//! Request routing, the per-connection context, and the tunnel implementations.

pub mod tcp;
pub mod udp;

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info, warn};

use crate::auth::Authenticator;
use crate::config::{Config, IpFamilyPreference};
use crate::h3api::{self, FieldValue, Fields, Method, Request, RespondError, Status, Stream};
use crate::policy::{self, Policy};

/// How a request should be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route<'a> {
    /// CONNECT with no `:protocol`: a TCP tunnel (RFC 9114 §4.4).
    Tcp,
    /// CONNECT with `:protocol = connect-udp`: a UDP tunnel (RFC 9298).
    ConnectUdp,
    /// CONNECT with a `:protocol` this proxy does not implement.
    ///
    /// Borrowed from the request, so the name logged and refused is the token
    /// the client actually sent rather than one of a fixed few.
    UnsupportedProtocol(&'a str),
    /// Not a CONNECT request at all. This server is a proxy, not an origin.
    NotConnect,
}

/// Classifies a request by method and `:protocol`.
///
/// The pseudo-header is read straight off the [`Request`], as the tunnels read
/// every other field of one (D78). It used to arrive through a classifier in
/// [`crate::h3api`], but that enum was this one's three variants under other
/// names and existed only to be translated into them on the next line.
pub fn route(req: &Request) -> Route<'_> {
    if req.method != Method::Connect {
        return Route::NotConnect;
    }

    match req.protocol.as_deref() {
        None => Route::Tcp,
        Some(udp::CONNECT_UDP) => Route::ConnectUdp,
        Some(protocol) => Route::UnsupportedProtocol(protocol),
    }
}

/// The field, if any, that makes `req` malformed under RFC 9114 §4.2.
///
/// RFC 9114 §4.2's rule -- quoted in full in `crate::h3::stream`, where the
/// `Connection` field itself is refused at decode time -- is that "any message
/// containing connection-specific fields MUST be treated as malformed". The
/// fields RFC 9110 §7.6.1 names as connection-specific beyond `Connection`
/// itself are judged here rather than in the codec so that the answer can be a
/// 400 instead of a reset: RFC 9114 §4.1.2 lets a server "send an HTTP response
/// indicating the error prior to closing or resetting the stream", and a client
/// is told more by a status than by `H3_MESSAGE_ERROR`.
///
/// Named one at a time so the log says which field was the problem.
pub(crate) fn connection_specific_field(req: &Request) -> Option<&'static str> {
    CONNECTION_SPECIFIC_FIELDS
        .iter()
        .copied()
        .find(|name| req.fields.contains(name))
}

/// RFC 9110 §7.6.1's connection-specific fields other than `Connection`.
///
/// Four of the five that section lists. The fifth is `TE`, which RFC 9114 §4.2
/// exempts when it says `trailers` and nothing else -- the sentence is quoted in
/// `crate::h3::stream`, where the value it carries is checked and where the
/// answer is the reset a malformed field section gets. So `TE` is not judged
/// here, and its absence from this list is the exemption rather than an
/// oversight.
const CONNECTION_SPECIFIC_FIELDS: [&str; 4] = [
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
];

/// Everything a request handler needs from the connection it arrived on.
///
/// Cloned per request — the cost is a handful of refcount bumps. The UDP-specific
/// members are here rather than in [`udp`] because a connection owns them
/// regardless of which tunnel type ends up using them: both are settled at the
/// handshake, before the first request arrives.
#[derive(Clone)]
pub struct Context {
    /// The QUIC connection, used directly for sending datagrams.
    ///
    /// Only the sending half: an inbound datagram is routed to the request
    /// stream it names by the HTTP/3 connection, and reaches a session through
    /// the [`h3api::DatagramReceiver`] that stream handed it (D79).
    pub datagrams: quinn::Connection,
    /// Whether the peer advertised `SETTINGS_H3_DATAGRAM = 1`.
    ///
    /// RFC 9297 §2.1.1 forbids sending QUIC datagrams when this is false; such
    /// sessions fall back to DATAGRAM capsules on the request stream. Shared
    /// with the HTTP/3 connection rather than copied from it, for the reason
    /// [`crate::h3::connection`] gives.
    pub peer_datagrams: Arc<AtomicBool>,
    /// The credentials every request is checked against.
    pub auth: Arc<Authenticator>,
    /// Authentication failures seen on this connection so far.
    ///
    /// Connection-scoped on purpose: no shared table across connections means no
    /// lock, no eviction policy and no memory that an attacker can grow.
    pub auth_failures: Arc<AtomicU32>,
    /// Failures tolerated before the connection is closed. Zero disables it.
    pub max_auth_failures: u32,
    /// Whether any request on this connection has passed the credentials check.
    ///
    /// Set once and never cleared. It is what lifts D76's bound on how long a
    /// connection may go without sending a request: a client that has proved
    /// who it is may hold an idle connection for as long as the transport's own
    /// idle timeout allows, which is what makes a proxy worth reconnecting to.
    /// A server with no users configured has nothing to check, so its first
    /// request sets this too -- the flag means "this peer got past the door",
    /// not "credentials were seen".
    ///
    /// Owned by [`crate::quic`] rather than allocated here, because it is read
    /// from outside the connection as well: the accept loop needs to know which
    /// of the connections it is holding has never got past the door, so that a
    /// full server can take that slot back rather than refuse a client that has
    /// credentials.
    pub authenticated: Arc<AtomicBool>,
    /// The peer's address, for logs that a fail2ban rule can act on.
    pub remote: std::net::SocketAddr,
    /// Which destinations this proxy may reach.
    pub policy: Arc<Policy>,
    /// How many tunnels this connection may hold open at once.
    pub quota: Arc<Quota>,
    /// How many tunnels this connection has been granted a slot for so far.
    ///
    /// Counted once per request that gets past [`Quota::acquire`], TCP and
    /// CONNECT-UDP alike, so this is slots taken rather than requests made: a
    /// request refused before the slot — 407, a malformed message, the tunnel
    /// limit itself — never reaches it. It is *not* tunnels that carried
    /// anything, though: the slot is taken before the target is judged, so a
    /// destination the policy rejects and a target that cannot be reached are
    /// both counted here. Owned by [`crate::quic`], which reads it once when
    /// the connection ends to report it on the closing line (D72); nothing here
    /// ever reads it back.
    pub tunnels: Arc<AtomicU64>,
    /// How long a UDP session may sit idle.
    pub idle_timeout: Duration,
    /// Budget for reaching a target, or `None` when it is disabled.
    ///
    /// Spent twice per request and separately — once on name resolution, once on
    /// the whole list of addresses it resolved to — so the worst case a tunnel
    /// slot is held before any byte flows is twice this.
    pub connect_timeout: Option<Duration>,
    /// Which address family a resolved target is tried on first.
    ///
    /// Snapshotted with the rest of the connection's `[limits]`, so a reload
    /// changes what connections accepted from then on do and leaves a running
    /// one alone.
    pub ip_family_preference: IpFamilyPreference,
    /// Packets a UDP session may send before its target has answered.
    pub unanswered_packet_budget: u32,
}

impl Context {
    /// Builds the context for one accepted connection.
    ///
    /// `peer_datagrams` comes from the HTTP/3 connection, which keeps writing
    /// to it; `tunnels` is the connection's tunnel counter and `authenticated`
    /// its door flag, both created by [`crate::quic`] so that they outlive this
    /// context — the first is read once the connection is over, the second
    /// while it runs.
    pub fn new(
        config: &Config,
        datagrams: quinn::Connection,
        peer_datagrams: Arc<AtomicBool>,
        tunnels: Arc<AtomicU64>,
        authenticated: Arc<AtomicBool>,
    ) -> Self {
        Self {
            remote: datagrams.remote_address(),
            auth_failures: Arc::new(AtomicU32::new(0)),
            max_auth_failures: config.security.max_auth_failures,
            authenticated,
            datagrams,
            peer_datagrams,
            auth: Arc::new(Authenticator::new(&config.auth)),
            policy: Arc::new(Policy::new(&config.security)),
            quota: Arc::new(Quota::new(config.limits.max_targets_per_conn)),
            tunnels,
            idle_timeout: config.limits.udp_session_timeout(),
            connect_timeout: config.limits.connect_timeout(),
            ip_family_preference: config.limits.ip_family_preference,
            unanswered_packet_budget: config.security.unanswered_packet_budget,
        }
    }

    /// Records an authentication failure, reporting whether that was one too many.
    ///
    /// Counts across the whole connection, so opening more streams does not reset
    /// the budget. A request that *succeeds* does — see [`Self::mark_authenticated`].
    pub(crate) fn record_auth_failure(&self) -> bool {
        let failures = self.auth_failures.fetch_add(1, Ordering::Relaxed) + 1;
        self.max_auth_failures > 0 && failures >= self.max_auth_failures
    }

    /// Whether QUIC datagrams may be sent to the peer right now.
    pub(crate) fn datagrams_allowed(&self) -> bool {
        self.peer_datagrams.load(Ordering::Relaxed)
    }

    /// Records that a request on this connection got past the credentials check,
    /// and clears the failures behind it.
    ///
    /// The counter is what makes guessing cost a handshake every
    /// `max_auth_failures` attempts, and a guesser never arrives here — so the
    /// reset takes nothing away from that. What it stops is the counter adding
    /// up over the life of a connection that *is* authenticated: a client whose
    /// password was rotated, or an app that omits the header on some request,
    /// spends the budget a failure at a time over hours and then loses every
    /// live tunnel to a cap meant for an attacker.
    pub(crate) fn mark_authenticated(&self) {
        self.authenticated.store(true, Ordering::Relaxed);
        self.auth_failures.store(0, Ordering::Relaxed);
    }

    /// Whether any request on this connection has (D76).
    pub(crate) fn is_authenticated(&self) -> bool {
        self.authenticated.load(Ordering::Relaxed)
    }
}

/// One connection's tunnel budget.
///
/// Every tunnel — TCP or UDP — costs a file descriptor on the target side, and a
/// single client multiplexes as many as it likes onto one QUIC connection. This
/// is the bound that keeps one client from exhausting the process fd limit, so
/// both tunnel types draw on the *same* budget rather than one each.
///
/// A semaphore rather than a counter, because it gives the M5 shutdown path the
/// other half for free: acquiring every permit at once is exactly "wait until all
/// tunnels have finished".
pub struct Quota {
    permits: Arc<Semaphore>,
    limit: u32,
}

/// One occupied tunnel slot, released when dropped.
///
/// Dropping is the *only* way a slot is returned, which is what makes every exit
/// path — response failure, idle timeout, reset, panic — leak-free by
/// construction, in the same spirit as the [`h3api::DatagramReceiver`] a UDP
/// session holds for as long as its Quarter Stream ID routes.
pub type Slot = OwnedSemaphorePermit;

impl Quota {
    /// Creates a quota allowing `limit` concurrent tunnels.
    pub fn new(limit: u32) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(limit as usize)),
            limit,
        }
    }

    /// Takes a slot, or `None` when the connection is at its limit.
    pub fn acquire(&self) -> Option<Slot> {
        Arc::clone(&self.permits).try_acquire_owned().ok()
    }

    /// How many tunnels are open right now.
    pub fn live(&self) -> u32 {
        self.limit - self.permits.available_permits() as u32
    }

    /// Resolves once every tunnel on this connection has finished.
    ///
    /// Used by the graceful shutdown path: all permits back means all slots
    /// dropped. The caller is responsible for bounding the wait — a tunnel that
    /// never ends would otherwise hold shutdown open forever.
    pub async fn wait_until_idle(&self) {
        // The semaphore is never closed, so this cannot fail.
        let _all = self.permits.acquire_many(self.limit).await;
    }
}

/// An RFC 9209 proxy error type, for the `Proxy-Status` field of a refusal.
///
/// Only registered types (RFC 9209 §2.3.2) appear here. There is no registered
/// type for "that port is closed by policy", so a denied port is reported as
/// `http_request_denied` — the registry's general "denied per policy" type —
/// rather than stretching `destination_ip_prohibited` to cover something that is
/// not about the address at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyError {
    /// The target name could not be resolved.
    DnsError,
    /// The resolver did not answer inside the `[limits] connect_timeout` budget.
    DnsTimeout,
    /// Every address the target resolved to is prohibited by policy.
    DestinationIpProhibited,
    /// The target is a legal destination but could not be reached.
    DestinationUnavailable,
    /// The target actively refused the connection.
    ConnectionRefused,
    /// The connection attempt timed out.
    ConnectionTimeout,
    /// This connection already holds as many tunnels as it may.
    ConnectionLimitReached,
    /// The request is refused by policy.
    HttpRequestDenied,
}

/// A target that could not be reached, and the address the attempt failed on.
///
/// The address is what RFC 9209 §2.1.2 calls the `next-hop`: "the intermediary or
/// origin server selected (and used, if contacted) to obtain this response".
/// Carried out of the connect helpers rather than recomputed, because with
/// several resolved addresses only they know which one was tried last.
pub(crate) struct Unreachable {
    /// The last address attempted, or `None` if there was nothing to attempt.
    pub(crate) next_hop: Option<std::net::SocketAddr>,
    /// Why that attempt failed.
    pub(crate) error: std::io::Error,
}

impl Unreachable {
    /// The failure of a target that offered nothing to attempt.
    ///
    /// Both tunnel types walk a list of addresses and keep the last failure, so
    /// both need an answer for a list that was empty. Neither can actually reach
    /// it — [`admit_target`] never hands back an empty list — so this is the
    /// empty-list arm written out rather than asserted, and there is no hop to
    /// name in it.
    pub(crate) fn no_addresses() -> Self {
        Self {
            next_hop: None,
            error: std::io::Error::new(std::io::ErrorKind::InvalidInput, "no addresses to try"),
        }
    }
}

/// A name that could not be turned into addresses, and why not.
///
/// The two cases are reported differently, so the callers have to be able to
/// tell them apart: a resolver that answered "no" is a 502, while one that did
/// not answer at all inside the `[limits] connect_timeout` budget is a 504.
#[derive(Debug)]
pub(crate) enum ResolveFailure {
    /// The resolver answered, unsuccessfully.
    Failed(std::io::Error),
    /// The budget expired before the resolver answered.
    TimedOut(Duration),
}

impl ResolveFailure {
    /// The RFC 9209 type this failure is reported as.
    pub(crate) fn proxy_error(&self) -> ProxyError {
        match self {
            Self::Failed(_) => ProxyError::DnsError,
            Self::TimedOut(_) => ProxyError::DnsTimeout,
        }
    }
}

impl std::fmt::Display for ResolveFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(error) => write!(f, "{error}"),
            Self::TimedOut(budget) => write!(f, "no answer within {budget:?}"),
        }
    }
}

/// Resolves `host`/`port`, giving the resolver at most `budget` and ordering the
/// answer by `family`.
///
/// Bounded because the tunnel slot and the file descriptor it stands for are
/// already held by the time this runs: a stub resolver whose nameserver has gone
/// away takes tens of seconds to give up, and every one of them is a slot the
/// client cannot use for anything else. `None` leaves the wait to the resolver,
/// which is what `connect_timeout = 0` asks for.
///
/// The address-family ordering happens here, once, rather than in each tunnel
/// (decision D58): this is the single point where a name becomes a list of
/// addresses, and it sits before the destination policy filters that list and
/// before either tunnel starts dialling it, so both kinds agree on which family
/// is tried first without either having to remember to ask.
pub(crate) async fn resolve_within(
    host: &str,
    port: u16,
    budget: Option<Duration>,
    family: IpFamilyPreference,
) -> Result<Vec<std::net::SocketAddr>, ResolveFailure> {
    let mut addresses = within_budget(crate::net::resolve(host, port), budget).await?;
    crate::net::prefer_family(&mut addresses, family);
    Ok(addresses)
}

/// Applies a resolution budget to `lookup`.
///
/// Split from [`resolve_within`] so the budget can be tested against a lookup
/// that never answers, which no real resolver can be made to do on demand.
async fn within_budget<F>(
    lookup: F,
    budget: Option<Duration>,
) -> Result<Vec<std::net::SocketAddr>, ResolveFailure>
where
    F: std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>>,
{
    let resolved = match budget {
        Some(budget) => match tokio::time::timeout(budget, lookup).await {
            Ok(resolved) => resolved,
            Err(_) => return Err(ResolveFailure::TimedOut(budget)),
        },
        None => lookup.await,
    };

    resolved.map_err(ResolveFailure::Failed)
}

/// Turns a request's target into the addresses it may be dialled on, answering
/// the request itself when there are none it may use.
///
/// `Some(addresses)` is a non-empty, policy-filtered, family-ordered list, ready
/// for the caller to dial. `None` means the request has **already been
/// answered** — with a 403, a 502, a 504, or the 200 that closes on the spot —
/// and the caller has nothing left to do but return.
///
/// Both tunnel types run exactly this preamble, which is why it is written once:
/// two copies drift, and a drift here is the two protocols disagreeing about
/// what a policy refusal looks like.
///
/// The order of the three steps is part of the design:
///
/// * The port rule needs no address, so it is applied before the resolver is
///   asked anything: a denied port cannot be used to make the proxy run lookups.
/// * Resolution is explicit, rather than left to the connect call, so the
///   addresses are visible to the policy below — and bounded, because the tunnel
///   slot and the file descriptor it stands for are already held. A resolver
///   failure is not the client's fault (decision D9), so it is a 502 with the
///   RFC 9209 reason rather than a 400, and a resolver that never answered is a
///   504 `dns_timeout` instead, because those are different things to an
///   operator reading the log. The list comes back ordered by `[limits]
///   ip_family_preference` (decision D58) and the callers dial it in that order,
///   so on a dual-stack target the non-preferred family is only reached after
///   the preferred one fails.
/// * A name resolving to a mix of public and private addresses keeps only the
///   public ones, so DNS rebinding onto loopback gains nothing.
///
/// Nothing left after that filter splits two ways (decision D49). A name whose
/// every address is the unspecified one was blocked by a filtering resolver
/// upstream, and that verdict is not this proxy's: answering 403 would make the
/// client attribute an ad blocker's decision to the proxy, and this is the only
/// protocol in the client's stable with an in-band channel to say anything at
/// all, so it is the only one that gets blamed. Such a request is accepted and
/// closed on the spot instead. Every other refusal — loopback, RFC 1918, a mix —
/// keeps its loud 403 with the RFC 9209 reason, because that is what an SSRF
/// probe looks like from here and the client really is being refused by this
/// proxy. The criterion belongs to [`policy::is_dns_blackhole`] and the response
/// mechanics to [`accept_then_close`]; only the choice between them is made
/// here.
///
/// `accepted_fields` supplies what an accepted response of the caller's tunnel
/// type has to carry — nothing for a TCP tunnel, the RFC 9297 `Capsule-Protocol`
/// field for CONNECT-UDP. Deferred, so only the one path that sends a 200 pays
/// for building it.
pub(crate) async fn admit_target(
    host: &str,
    port: u16,
    ctx: &Context,
    stream: &mut Stream,
    stream_id: u64,
    accepted_fields: impl FnOnce() -> Fields,
) -> Option<Vec<std::net::SocketAddr>> {
    if !ctx.policy.allows_port(port) {
        debug!(stream_id, host, port, "target port denied by policy");
        refuse_because(stream, ProxyError::HttpRequestDenied, stream_id).await;
        return None;
    }

    let resolved = resolve_within(host, port, ctx.connect_timeout, ctx.ip_family_preference).await;
    let addresses = match resolved {
        Ok(addresses) => addresses,
        Err(failure) => {
            let error = failure.proxy_error();
            debug!(stream_id, host, port, reason = %failure, "failed to resolve target");
            refuse_because(stream, error, stream_id).await;
            return None;
        }
    };

    let allowed = ctx.policy.allowed_addresses(&addresses);
    if allowed.is_empty() {
        if policy::is_dns_blackhole(&addresses) {
            info!(
                stream_id,
                host,
                port,
                ?addresses,
                "every address of the target is a DNS blackhole"
            );
            accept_then_close(stream, accepted_fields(), stream_id).await;
            return None;
        }

        warn!(
            stream_id,
            host,
            port,
            ?addresses,
            "every address of the target is prohibited by policy"
        );
        refuse_because(stream, ProxyError::DestinationIpProhibited, stream_id).await;
        return None;
    }

    Some(allowed)
}

impl ProxyError {
    /// The complete `Proxy-Status` field value.
    ///
    /// RFC 9209 §2 shape: an identifier for this proxy, then parameters. Kept as
    /// static strings so building a refusal cannot itself fail.
    fn field_value(self) -> &'static str {
        match self {
            Self::DnsError => "volto; error=dns_error",
            Self::DnsTimeout => "volto; error=dns_timeout",
            Self::DestinationIpProhibited => "volto; error=destination_ip_prohibited",
            Self::DestinationUnavailable => "volto; error=destination_unavailable",
            Self::ConnectionRefused => "volto; error=connection_refused",
            Self::ConnectionTimeout => "volto; error=connection_timeout",
            Self::ConnectionLimitReached => "volto; error=connection_limit_reached",
            Self::HttpRequestDenied => "volto; error=http_request_denied",
        }
    }

    /// This error as the field lines of a response.
    pub fn fields(self) -> Fields {
        let mut fields = Fields::new();
        fields.append(PROXY_STATUS, FieldValue::from_static(self.field_value()));
        fields
    }

    /// Whether this error may name the address it happened on.
    ///
    /// Only the three failures that are *about reaching a specific hop* qualify.
    /// RFC 9209 §2.1.2 allows the parameter anywhere, so this list is a privacy
    /// judgement rather than a syntactic one, and every exclusion is deliberate:
    ///
    /// * `dns_error` and `dns_timeout` — there is no hop to name. The lookup is
    ///   what failed, so any address in the response would be invented.
    /// * `destination_ip_prohibited` and `http_request_denied` — the request was
    ///   refused *by this proxy*, and echoing the resolved address would turn
    ///   every refusal into a lookup oracle: a client that cannot reach an
    ///   internal resolver could read this server's view of a name straight out
    ///   of the refusal. The policy exists to keep exactly that reachable-only-
    ///   from-here information in, so the refusal must not carry it out.
    /// * `connection_limit_reached`, and the 407 path, say nothing about a
    ///   target: they are verdicts on the client.
    fn discloses_next_hop(self) -> bool {
        matches!(
            self,
            Self::ConnectionRefused | Self::ConnectionTimeout | Self::DestinationUnavailable
        )
    }

    /// This error as the field lines of a response, naming the hop it happened on.
    ///
    /// The address is dropped unless `Self::discloses_next_hop` allows it, so a
    /// caller cannot leak one by passing it to the wrong error type.
    pub fn fields_with_next_hop(self, next_hop: Option<std::net::SocketAddr>) -> Fields {
        let Some(address) = next_hop.filter(|_| self.discloses_next_hop()) else {
            return self.fields();
        };

        // `<identifier>; error=<type>; next-hop="<address>"`. RFC 9209 §2.1.2
        // accepts a String or a Token; an IPv6 address needs its brackets, which
        // no Token may contain, so the String form is used for both families.
        let value = format!(
            "{}; next-hop={}",
            self.field_value(),
            sf_string(&address.to_string())
        );

        let mut fields = Fields::new();
        fields.append(
            PROXY_STATUS,
            // A rendered socket address is printable ASCII, so this cannot fail;
            // falling back to the parameterless value keeps that from being a
            // panic if it ever somehow did, which is the property the whole
            // refusal path is built on: refusing must never itself fail.
            FieldValue::parse(value.as_bytes())
                .unwrap_or_else(|| FieldValue::from_static(self.field_value())),
        );
        fields
    }

    /// The error type that best describes a failure to reach a target.
    pub fn from_connect_error(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            std::io::ErrorKind::TimedOut => Self::ConnectionTimeout,
            _ => Self::DestinationUnavailable,
        }
    }

    /// The HTTP status code RFC 9209 §2.3.2 recommends for this error type.
    ///
    /// The registry pairs each type with a status, and following it costs
    /// nothing while telling an operator reading a log which failure it was: a
    /// 504 is a target that never answered, a 503 is one that could not be
    /// reached at all, and a 502 is one that actively refused.
    ///
    /// One deliberate departure: `destination_ip_prohibited` is recommended as
    /// 502, and this server answers 403. Decision D11 made both policy refusals
    /// — denied port and denied address — a 403, because they are refusals by
    /// this proxy rather than reports about an upstream hop, and a client that
    /// sees 502 would reasonably retry.
    ///
    /// One address refusal never arrives here at all (decision D49, a carve-out
    /// from D11 rather than a revision of it): a target whose every resolved
    /// address is the unspecified one is a name the upstream resolver filtered,
    /// so it is answered with a 200 that closes on the spot — see
    /// `accept_then_close` — and carries no `Proxy-Status` field, because
    /// nothing about it is this proxy's verdict. Every refusal that is actually
    /// sent still follows the table below.
    pub fn recommended_status(self) -> Status {
        match self {
            Self::DnsError | Self::ConnectionRefused => Status::BAD_GATEWAY,
            Self::DnsTimeout | Self::ConnectionTimeout => Status::GATEWAY_TIMEOUT,
            Self::DestinationUnavailable | Self::ConnectionLimitReached => {
                Status::SERVICE_UNAVAILABLE
            }
            Self::DestinationIpProhibited | Self::HttpRequestDenied => Status::FORBIDDEN,
        }
    }
}

/// The field an RFC 9209 refusal explains itself in.
const PROXY_STATUS: &str = "proxy-status";

/// Renders `value` as a structured field String (RFC 8941 §3.3.3).
///
/// A String is DQUOTE-delimited, and inside it only DQUOTE and backslash are
/// escaped. A rendered socket address contains neither, so this never actually
/// escapes anything today — it exists so that the one field value this server
/// builds at runtime is correct by construction rather than by argument about its
/// inputs.
fn sf_string(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        if character == '"' || character == '\\' {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

/// Answers a request we will not serve, then closes the stream tidily.
///
/// Any request body is unwanted, so the client is told to stop sending before
/// the status goes out.
pub(crate) async fn refuse(stream: &mut Stream, status: Status, stream_id: u64) {
    refuse_with(stream, status, Fields::new(), stream_id).await;
}

/// Refuses a request, explaining why in an RFC 9209 `Proxy-Status` field.
///
/// The status is the error's own (`recommended_status`), so the table that
/// argues for each pairing — including D11's departure from the registry — is
/// the only thing that decides one.
pub(crate) async fn refuse_because(stream: &mut Stream, error: ProxyError, stream_id: u64) {
    refuse_with(
        stream,
        error.recommended_status(),
        error.fields(),
        stream_id,
    )
    .await;
}

/// Refuses a request whose target could not be reached, naming the failed hop.
///
/// Both tunnel types end up here from their connect step, so the mapping from an
/// `io::Error` to a status and an RFC 9209 field is written once: the type
/// decides the status (`recommended_status`) and whether the address may be
/// disclosed (`discloses_next_hop`).
pub(crate) async fn refuse_unreachable(stream: &mut Stream, failure: &Unreachable, stream_id: u64) {
    let error = ProxyError::from_connect_error(&failure.error);
    refuse_with(
        stream,
        error.recommended_status(),
        error.fields_with_next_hop(failure.next_hop),
        stream_id,
    )
    .await;
}

/// Refuses a request with an explicit set of response fields.
///
/// The write is bounded by one QUIC idle timeout and a lapsed one is abandoned
/// with a reset; [`h3api::Stream::respond_within`] carries the reasoning. It is
/// also why the count of authentication failures that is meant to cost a guesser
/// a handshake is recorded by the caller before this call rather than after it
/// (review H1/H2).
pub(crate) async fn refuse_with(
    stream: &mut Stream,
    status: Status,
    fields: Fields,
    stream_id: u64,
) {
    stream.stop_receiving(h3api::NO_ERROR);

    match stream.respond_within(status, fields).await {
        Ok(()) => {}
        Err(RespondError::Failed(error)) => {
            debug!(stream_id, %error, "failed to send error response");
            return;
        }
        Err(RespondError::Expired) => {
            debug!(
                stream_id,
                status = status.as_str(),
                "gave up on an error response the peer would not take"
            );
            return;
        }
    }

    if let Err(error) = stream.finish() {
        debug!(stream_id, %error, "failed to finish error response");
    }
}

/// Accepts a request with a 200 and closes the tunnel again immediately.
///
/// **Not a refusal, and deliberately not named like one.** The response carries
/// no `Proxy-Status` field and says nothing about a failure; `fields` is
/// whatever an accepted response of that tunnel type has to carry — nothing for
/// a TCP tunnel, the RFC 9297 `Capsule-Protocol` field for CONNECT-UDP.
///
/// Exactly one case uses it (decision D49): a target whose every resolved
/// address is the unspecified one, which is how a filtering resolver upstream
/// says "this name is blocked". That block is not this proxy's verdict, and an
/// error status makes the client attribute it here; a tunnel that opens and
/// closes at once is instead what every transport without an in-band refusal
/// channel shows for such a name, and what a target that accepts a connection
/// and hangs up immediately looks like on the wire.
///
/// Mechanically the close is the tidy one, and it is the same one an
/// established session ends with: STOP_SENDING with H3_NO_ERROR for anything
/// the client is still sending, then a FIN on the response stream. **Never a
/// reset** — RFC 9114 §4.4 reserves an abruptly terminated stream for a failure
/// of the target connection (H3_CONNECT_ERROR), which this is not, and a reset
/// would also be the one signal a client is entitled to read as "the proxy
/// broke". A clean FIN is what RFC 9297 §3.3 treats as the normal end of a
/// capsule stream, and on the CONNECT-UDP path it also settles RFC 9298 §3.1's
/// pairing of socket and request stream in the only way available here: there
/// is no socket, so no request stream is left open waiting for one.
///
/// The STOP_SENDING up front is the shape to keep. RFC 9114 §4.1 leaves the
/// choice open — a server may abort reading the request, or leave the client to
/// finish and close it — and the other shape was tried once (D59): 200 and FIN
/// only, then read and discard until the client closed, on the theory that a
/// stop landing on a client still writing its first bytes was what made one
/// client stack answer with a transport-level PROTOCOL_VIOLATION. A frame-level
/// A/B against that very stack showed the two shapes are indistinguishable to it
/// (it resets within a round trip either way) and production kept failing under
/// the drain, so the simpler shape came back. That fault is on the client's
/// side and does not depend on what this close sends.
pub(crate) async fn accept_then_close(stream: &mut Stream, fields: Fields, stream_id: u64) {
    stream.stop_receiving(h3api::NO_ERROR);

    // Bounded exactly as [`refuse_with`] is, and for the same reason: no tunnel
    // is opened here, so nothing but this write stands between the request task
    // and the end of its life.
    match stream.respond_within(Status::OK, fields).await {
        Ok(()) => {}
        Err(RespondError::Failed(error)) => {
            debug!(stream_id, %error, "failed to send 200 for a tunnel closed on the spot");
            return;
        }
        Err(RespondError::Expired) => {
            debug!(
                stream_id,
                "gave up on a 200 the peer would not take for a tunnel closed on the spot"
            );
            return;
        }
    }

    if let Err(error) = stream.finish() {
        debug!(stream_id, %error, "failed to close a tunnel after its 200");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect_with_protocol(protocol: Option<&str>) -> Request {
        let mut req = Request::new(Method::Connect);
        req.authority = Some("example.com".into());
        req.protocol = protocol.map(Into::into);
        req
    }

    #[test]
    fn the_protocol_pseudo_header_picks_the_tunnel() {
        assert_eq!(route(&connect_with_protocol(None)), Route::Tcp);
        assert_eq!(
            route(&connect_with_protocol(Some("connect-udp"))),
            Route::ConnectUdp
        );
        // The wire name survives, which is what makes a truthful 501 possible.
        assert_eq!(
            route(&connect_with_protocol(Some("connect-ip"))),
            Route::UnsupportedProtocol("connect-ip")
        );
        assert_eq!(
            route(&connect_with_protocol(Some("webtransport"))),
            Route::UnsupportedProtocol("webtransport")
        );
        // The method is judged first: this server proxies and does not serve.
        assert_eq!(
            route(&Request::new(Method::Other("GET".into()))),
            Route::NotConnect
        );
    }

    #[test]
    fn a_connection_specific_field_is_named_and_a_clean_request_is_not() {
        let mut clean = Request::new(Method::Connect);
        clean.authority = Some("example.com:443".into());
        clean
            .fields
            .append("te", FieldValue::from_static("trailers"));
        assert_eq!(connection_specific_field(&clean), None);

        for name in [
            "proxy-connection",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
        ] {
            let mut request = Request::new(Method::Connect);
            request.authority = Some("example.com:443".into());
            request
                .fields
                .append(name, FieldValue::from_static("anything"));
            assert_eq!(connection_specific_field(&request), Some(name), "{name}");
        }
    }

    #[test]
    fn proxy_status_values_are_rfc_9209_shaped() {
        for (error, expected) in [
            (ProxyError::DnsError, "dns_error"),
            (ProxyError::DnsTimeout, "dns_timeout"),
            (
                ProxyError::DestinationIpProhibited,
                "destination_ip_prohibited",
            ),
            (
                ProxyError::ConnectionLimitReached,
                "connection_limit_reached",
            ),
            (ProxyError::HttpRequestDenied, "http_request_denied"),
        ] {
            let value = error.field_value();
            // `<identifier>; error=<type>`: the identifier names this proxy, the
            // parameter names the failure.
            assert_eq!(value, format!("volto; error={expected}"));

            let fields = error.fields();
            assert_eq!(
                fields.get(PROXY_STATUS).and_then(FieldValue::to_str),
                Some(value)
            );
        }
    }

    /// RFC 9209 §2.3.2 pairs each registered type with a recommended status.
    /// Every pairing here is the registry's, except the documented D11 choice of
    /// 403 for a destination the policy refuses.
    #[test]
    fn every_error_type_carries_its_recommended_status() {
        for (error, expected) in [
            (ProxyError::DnsError, Status::BAD_GATEWAY),
            (ProxyError::DnsTimeout, Status::GATEWAY_TIMEOUT),
            (ProxyError::ConnectionRefused, Status::BAD_GATEWAY),
            (ProxyError::ConnectionTimeout, Status::GATEWAY_TIMEOUT),
            (
                ProxyError::DestinationUnavailable,
                Status::SERVICE_UNAVAILABLE,
            ),
            (
                ProxyError::ConnectionLimitReached,
                Status::SERVICE_UNAVAILABLE,
            ),
            (ProxyError::HttpRequestDenied, Status::FORBIDDEN),
            (ProxyError::DestinationIpProhibited, Status::FORBIDDEN),
        ] {
            assert_eq!(
                error.recommended_status(),
                expected,
                "{error:?} must answer {expected}"
            );
        }
    }

    /// The three failures `from_connect_error` distinguishes must stay
    /// distinguishable in the response, which is the point of computing them.
    #[test]
    fn connect_failures_do_not_collapse_onto_one_status() {
        use std::io::{Error, ErrorKind};

        let statuses: Vec<Status> = [
            ErrorKind::ConnectionRefused,
            ErrorKind::TimedOut,
            ErrorKind::PermissionDenied,
        ]
        .into_iter()
        .map(|kind| ProxyError::from_connect_error(&Error::from(kind)).recommended_status())
        .collect();

        assert_eq!(
            statuses,
            vec![
                Status::BAD_GATEWAY,
                Status::GATEWAY_TIMEOUT,
                Status::SERVICE_UNAVAILABLE
            ]
        );
    }

    #[test]
    fn connect_errors_map_onto_registered_types() {
        use std::io::{Error, ErrorKind};

        assert_eq!(
            ProxyError::from_connect_error(&Error::from(ErrorKind::ConnectionRefused)),
            ProxyError::ConnectionRefused
        );
        assert_eq!(
            ProxyError::from_connect_error(&Error::from(ErrorKind::TimedOut)),
            ProxyError::ConnectionTimeout
        );
        assert_eq!(
            ProxyError::from_connect_error(&Error::from(ErrorKind::PermissionDenied)),
            ProxyError::DestinationUnavailable
        );
    }

    /// Reads the `Proxy-Status` field out of a field list.
    fn proxy_status(fields: &Fields) -> String {
        fields
            .get(PROXY_STATUS)
            .and_then(FieldValue::to_str)
            .expect("every refusal carries a Proxy-Status field")
            .to_owned()
    }

    /// RFC 9209 §2.1.2's `next-hop` "identifies the intermediary or origin server
    /// selected (and used, if contacted) to obtain this response" — so it belongs
    /// on the failures that are about reaching one, and nowhere else.
    #[test]
    fn only_failures_to_reach_a_hop_name_it() {
        let hop: std::net::SocketAddr = "192.0.2.7:443".parse().expect("address");

        for error in [
            ProxyError::ConnectionRefused,
            ProxyError::ConnectionTimeout,
            ProxyError::DestinationUnavailable,
        ] {
            assert_eq!(
                proxy_status(&error.fields_with_next_hop(Some(hop))),
                format!("{}; next-hop=\"192.0.2.7:443\"", error.field_value())
            );
        }
    }

    /// The exclusions, and the reason for the middle two: a policy refusal that
    /// echoed the resolved address would hand the client this server's view of a
    /// name it is not allowed to reach — an internal DNS mapping, read straight
    /// out of the refusal. `dns_error` has no hop to name at all.
    #[test]
    fn refusals_that_are_not_about_a_hop_never_echo_an_address() {
        let hop: std::net::SocketAddr = "10.1.2.3:53".parse().expect("address");

        for error in [
            ProxyError::DnsError,
            ProxyError::DnsTimeout,
            ProxyError::DestinationIpProhibited,
            ProxyError::HttpRequestDenied,
            ProxyError::ConnectionLimitReached,
        ] {
            let value = proxy_status(&error.fields_with_next_hop(Some(hop)));
            assert_eq!(
                value,
                error.field_value(),
                "{error:?} must stay exactly as it is without a next-hop"
            );
            assert!(
                !value.contains("10.1.2.3") && !value.contains("next-hop"),
                "{error:?} leaked an address: {value}"
            );
        }
    }

    /// No address to report — an empty candidate list — leaves the field as the
    /// plain one, byte for byte.
    #[test]
    fn a_missing_address_leaves_the_field_untouched() {
        for error in [
            ProxyError::ConnectionRefused,
            ProxyError::ConnectionTimeout,
            ProxyError::DestinationUnavailable,
        ] {
            assert_eq!(
                error.fields_with_next_hop(None).get(PROXY_STATUS),
                error.fields().get(PROXY_STATUS)
            );
        }
    }

    /// RFC 9209 §2.1.2 accepts a String or a Token, and RFC 8941 §3.3.3 defines
    /// the String: DQUOTE-delimited, with DQUOTE and backslash escaped. An IPv6
    /// hop is the case that decides it — its brackets are not Token characters.
    #[test]
    fn a_next_hop_is_a_quoted_structured_field_string() {
        let ipv6: std::net::SocketAddr = "[2001:db8::1]:53".parse().expect("address");
        assert_eq!(
            proxy_status(&ProxyError::ConnectionRefused.fields_with_next_hop(Some(ipv6))),
            "volto; error=connection_refused; next-hop=\"[2001:db8::1]:53\""
        );

        // The escaping rule itself, on inputs a socket address cannot produce but
        // the encoder must still handle.
        assert_eq!(sf_string("192.0.2.7:443"), "\"192.0.2.7:443\"");
        assert_eq!(sf_string("[2001:db8::1]:53"), "\"[2001:db8::1]:53\"");
        assert_eq!(sf_string(r#"a"b"#), r#""a\"b""#);
        assert_eq!(sf_string(r"a\b"), r#""a\\b""#);
        assert_eq!(sf_string(""), "\"\"");
    }

    /// A resolver that never answers costs the request its budget and no more,
    /// and is reported as the timeout it is rather than as an ordinary lookup
    /// failure — the two carry different statuses.
    ///
    /// Real time rather than a paused clock, because tokio's `test-util` feature
    /// is not enabled in this tree; the budget is therefore small and the upper
    /// bound generous, so only a genuinely unbounded wait can fail it.
    #[tokio::test]
    async fn a_resolver_that_never_answers_costs_only_the_budget() {
        let budget = Duration::from_millis(50);
        let started = std::time::Instant::now();

        // The outer timeout is what turns a regression here into a failure
        // rather than a hung test run.
        let failure = tokio::time::timeout(
            Duration::from_secs(5),
            within_budget(std::future::pending(), Some(budget)),
        )
        .await
        .expect("the budget must bound the wait")
        .expect_err("a lookup that never answers must not succeed");
        let elapsed = started.elapsed();

        assert!(matches!(failure, ResolveFailure::TimedOut(_)), "{failure}");
        assert_eq!(failure.proxy_error(), ProxyError::DnsTimeout);
        assert_eq!(
            failure.proxy_error().recommended_status(),
            Status::GATEWAY_TIMEOUT
        );
        assert!(elapsed >= budget, "returned early, after {elapsed:?}");
    }

    /// A lookup that answers is passed straight through, budget or no budget.
    #[tokio::test]
    async fn a_lookup_that_answers_is_passed_through() {
        let addresses = vec!["192.0.2.1:443".parse().expect("address")];

        for budget in [None, Some(Duration::from_secs(10))] {
            let resolved = within_budget(std::future::ready(Ok(addresses.clone())), budget)
                .await
                .expect("a lookup that answers must succeed");
            assert_eq!(resolved, addresses);
        }

        // And a resolver that says no keeps saying no, as `dns_error`.
        let failure = within_budget(
            std::future::ready(Err(std::io::Error::from(std::io::ErrorKind::NotFound))),
            Some(Duration::from_secs(10)),
        )
        .await
        .expect_err("a lookup that fails must fail");
        assert_eq!(failure.proxy_error(), ProxyError::DnsError);
    }

    /// The mapping the two resolution failures are told apart by.
    #[test]
    fn a_resolver_timeout_is_a_different_type_from_a_resolver_failure() {
        use std::io::{Error, ErrorKind};

        let failed = ResolveFailure::Failed(Error::from(ErrorKind::NotFound));
        assert_eq!(failed.proxy_error(), ProxyError::DnsError);
        assert_eq!(
            failed.proxy_error().recommended_status(),
            Status::BAD_GATEWAY
        );

        let timed_out = ResolveFailure::TimedOut(Duration::from_secs(10));
        assert_eq!(timed_out.proxy_error(), ProxyError::DnsTimeout);
        assert_eq!(
            timed_out.proxy_error().recommended_status(),
            Status::GATEWAY_TIMEOUT
        );
    }

    #[tokio::test]
    async fn a_quota_hands_out_exactly_its_limit() {
        let quota = Quota::new(2);
        assert_eq!(quota.live(), 0);

        let first = quota.acquire().expect("first slot");
        let second = quota.acquire().expect("second slot");
        assert_eq!(quota.live(), 2);
        assert!(quota.acquire().is_none(), "the limit must be enforced");

        // Slots are returned by dropping them, on every path.
        drop(first);
        assert_eq!(quota.live(), 1);
        let third = quota.acquire().expect("a freed slot is reusable");
        assert!(quota.acquire().is_none());

        drop(second);
        drop(third);
        assert_eq!(quota.live(), 0);
    }

    #[tokio::test]
    async fn waiting_for_idle_resolves_when_the_last_slot_goes() {
        let quota = Arc::new(Quota::new(4));
        let slot = quota.acquire().expect("slot");

        // Still busy: the wait must not resolve yet.
        let idle = quota.clone();
        let waiter = tokio::spawn(async move { idle.wait_until_idle().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), async {})
                .await
                .is_ok(),
            "the timer works"
        );
        assert!(!waiter.is_finished());

        drop(slot);
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("idle within the timeout")
            .expect("waiter task");
    }
}
