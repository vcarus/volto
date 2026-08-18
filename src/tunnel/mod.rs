//! Request routing, the per-connection context, and the tunnel implementations.

pub mod tcp;
pub mod udp;

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::debug;

use crate::auth::Authenticator;
use crate::config::{Config, IpFamilyPreference};
use crate::h3api::{self, ConnectProtocol, Stream};
use crate::policy::Policy;

/// How a request should be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// CONNECT with no `:protocol`: a TCP tunnel (RFC 9114 §4.4).
    Tcp,
    /// CONNECT with `:protocol = connect-udp`: a UDP tunnel (RFC 9298).
    ConnectUdp,
    /// CONNECT with a `:protocol` this proxy does not implement.
    UnsupportedProtocol(&'static str),
    /// Not a CONNECT request at all. This server is a proxy, not an origin.
    NotConnect,
}

/// Classifies a request by method and `:protocol`.
pub fn route(req: &Request<()>) -> Route {
    if req.method() != Method::CONNECT {
        return Route::NotConnect;
    }

    match h3api::connect_protocol(req) {
        ConnectProtocol::Absent => Route::Tcp,
        ConnectProtocol::ConnectUdp => Route::ConnectUdp,
        ConnectProtocol::Unsupported(name) => Route::UnsupportedProtocol(name),
    }
}

/// Everything a request handler needs from the connection it arrived on.
///
/// Cloned per request — the cost is a handful of refcount bumps. The UDP-specific
/// members are here rather than in [`udp`] because a connection owns them
/// regardless of which tunnel type ends up using them: the datagram router is
/// started before the first request arrives.
#[derive(Clone)]
pub struct Context {
    /// The QUIC connection, used directly for datagram I/O.
    pub datagrams: quinn::Connection,
    /// Connection-wide Quarter Stream ID routing table.
    pub sessions: Arc<udp::SessionRegistry>,
    /// Whether the peer advertised `SETTINGS_H3_DATAGRAM = 1`.
    ///
    /// RFC 9297 §2.1.1 forbids sending QUIC datagrams when this is false; such
    /// sessions fall back to DATAGRAM capsules on the request stream. Shared with
    /// the connection so a late SETTINGS frame is still picked up.
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
    /// The peer's address, for logs that a fail2ban rule can act on.
    pub remote: std::net::SocketAddr,
    /// Which destinations this proxy may reach.
    pub policy: Arc<Policy>,
    /// How many tunnels this connection may hold open at once.
    pub quota: Arc<Quota>,
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
    pub fn new(config: &Config, datagrams: quinn::Connection) -> Self {
        Self {
            remote: datagrams.remote_address(),
            auth_failures: Arc::new(AtomicU32::new(0)),
            max_auth_failures: config.security.max_auth_failures,
            datagrams,
            sessions: Arc::new(udp::SessionRegistry::default()),
            peer_datagrams: Arc::new(AtomicBool::new(false)),
            auth: Arc::new(Authenticator::new(&config.auth)),
            policy: Arc::new(Policy::new(&config.security)),
            quota: Arc::new(Quota::new(config.limits.max_targets_per_conn)),
            idle_timeout: config.limits.udp_session_timeout(),
            connect_timeout: config.limits.connect_timeout(),
            ip_family_preference: config.limits.ip_family_preference,
            unanswered_packet_budget: config.security.unanswered_packet_budget,
        }
    }

    /// Records an authentication failure, reporting whether that was one too many.
    ///
    /// Counts across the whole connection, so opening more streams does not reset
    /// the budget.
    pub(crate) fn record_auth_failure(&self) -> bool {
        let failures = self.auth_failures.fetch_add(1, Ordering::Relaxed) + 1;
        self.max_auth_failures > 0 && failures >= self.max_auth_failures
    }

    /// Whether QUIC datagrams may be sent to the peer right now.
    pub(crate) fn datagrams_allowed(&self) -> bool {
        self.peer_datagrams.load(Ordering::Relaxed)
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
/// construction, in the same spirit as [`udp::SessionRegistry`]'s guard.
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

    /// The registered error type name, for logs.
    pub fn as_str(self) -> &'static str {
        // Everything after `error=`; the field value is the single source of truth
        // so the two cannot drift apart.
        self.field_value()
            .rsplit_once("error=")
            .expect("every field value carries an error parameter")
            .1
    }

    /// This error as a response header map.
    pub fn headers(self) -> HeaderMap {
        let mut headers = HeaderMap::with_capacity(1);
        headers.insert(
            HeaderName::from_static("proxy-status"),
            HeaderValue::from_static(self.field_value()),
        );
        headers
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

    /// This error as a response header map, naming the hop it happened on.
    ///
    /// The address is dropped unless `Self::discloses_next_hop` allows it, so a
    /// caller cannot leak one by passing it to the wrong error type.
    pub fn headers_with_next_hop(self, next_hop: Option<std::net::SocketAddr>) -> HeaderMap {
        let Some(address) = next_hop.filter(|_| self.discloses_next_hop()) else {
            return self.headers();
        };

        // `<identifier>; error=<type>; next-hop="<address>"`. RFC 9209 §2.1.2
        // accepts a String or a Token; an IPv6 address needs its brackets, which
        // no Token may contain, so the String form is used for both families.
        let value = format!(
            "{}; next-hop={}",
            self.field_value(),
            sf_string(&address.to_string())
        );

        let mut headers = HeaderMap::with_capacity(1);
        headers.insert(
            HeaderName::from_static("proxy-status"),
            // A rendered socket address is printable ASCII, so this cannot fail;
            // falling back to the parameterless value keeps that from being a
            // panic if it ever somehow did, which is the property the whole
            // refusal path is built on: refusing must never itself fail.
            HeaderValue::from_str(&value)
                .unwrap_or_else(|_| HeaderValue::from_static(self.field_value())),
        );
        headers
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
    pub fn recommended_status(self) -> StatusCode {
        match self {
            Self::DnsError | Self::ConnectionRefused => StatusCode::BAD_GATEWAY,
            Self::DnsTimeout | Self::ConnectionTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::DestinationUnavailable | Self::ConnectionLimitReached => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::DestinationIpProhibited | Self::HttpRequestDenied => StatusCode::FORBIDDEN,
        }
    }
}

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
pub(crate) async fn refuse(stream: &mut Stream, status: StatusCode, stream_id: u64) {
    refuse_with(stream, status, HeaderMap::new(), stream_id).await;
}

/// Refuses a request, explaining why in an RFC 9209 `Proxy-Status` field.
pub(crate) async fn refuse_because(
    stream: &mut Stream,
    status: StatusCode,
    error: ProxyError,
    stream_id: u64,
) {
    refuse_with(stream, status, error.headers(), stream_id).await;
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
        error.headers_with_next_hop(failure.next_hop),
        stream_id,
    )
    .await;
}

/// Refuses a request with an explicit set of response headers.
pub(crate) async fn refuse_with(
    stream: &mut Stream,
    status: StatusCode,
    headers: HeaderMap,
    stream_id: u64,
) {
    stream.stop_receiving(h3api::NO_ERROR);

    if let Err(error) = stream.respond_with(status, headers).await {
        debug!(stream_id, %error, "failed to send error response");
        return;
    }
    if let Err(error) = stream.finish().await {
        debug!(stream_id, %error, "failed to finish error response");
    }
}

/// Accepts a request with a 200 and closes the tunnel again immediately.
///
/// **Not a refusal, and deliberately not named like one.** The response carries
/// no `Proxy-Status` field and says nothing about a failure; `headers` is
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
/// Mechanically the close is the tidy one: a FIN on the response stream and
/// **never a reset** — RFC 9114 §4.4 reserves an abruptly terminated stream for
/// a failure of the target connection (H3_CONNECT_ERROR), which this is not, and
/// a reset would also be the one signal a client is entitled to read as "the
/// proxy broke". A clean FIN is what RFC 9297 §3.3 treats as the normal end of a
/// capsule stream, and on the CONNECT-UDP path it also settles RFC 9298 §3.1's
/// pairing of socket and request stream in the only way available here: there
/// is no socket, so no request stream is left open waiting for one.
///
/// What it deliberately does *not* do any more (decision D59) is abort the
/// request side first. RFC 9114 §4.1 offers both halves of the choice — a server
/// that does not need the rest of the request "MAY abort reading the request
/// stream", and if it does not, "clients SHOULD continue sending the content of
/// the request and close the stream normally" — and this path used to take the
/// first. Sending STOP_SENDING into a client that is still writing the first
/// bytes of its tunnel turned out to be the trigger for a rare transport-level
/// PROTOCOL_VIOLATION from one client stack, which costs the whole QUIC
/// connection and every other tunnel on it. So the response goes out, the
/// sending side closes, and the client's own close is then waited for — bounded,
/// see [`drain_until_peer_closes`].
pub(crate) async fn accept_then_close(stream: &mut Stream, headers: HeaderMap, stream_id: u64) {
    if let Err(error) = stream.respond_with(StatusCode::OK, headers).await {
        debug!(stream_id, %error, "failed to send 200 for a tunnel closed on the spot");
        return;
    }
    if let Err(error) = stream.finish().await {
        // Not a reason to skip the drain: what failed is the sending side, and
        // walking away from the receiving one is exactly the abrupt stop this
        // path exists to avoid. A stream that is broken in both directions ends
        // the drain on its first read anyway.
        debug!(stream_id, %error, "failed to close a tunnel after its 200");
    }

    drain_until_peer_closes(stream, stream_id).await;
}

/// How long [`accept_then_close`] waits for the client to close its own side.
///
/// A client that has read the 200 and the FIN behind it has nothing left to do
/// but close, so the ordinary wait is a round trip. The limit only has to cover
/// the client that had already started writing into the tunnel before the
/// response arrived — one flight, a TLS ClientHello — and three seconds is far
/// more than that takes on any path this server is deployed behind. Kept short
/// on purpose: the tunnel slot is held for the whole wait.
const DRAIN_TIME_LIMIT: Duration = Duration::from_secs(3);

/// How much [`accept_then_close`] reads and discards before it gives up waiting.
///
/// A well-behaved client sends at most that first flight here — a ClientHello is
/// a few kilobytes even with a post-quantum key share — so 64 KiB is a full
/// order of magnitude of headroom, and it bounds what a client that keeps
/// writing into a closed tunnel can make this server read. Nothing is buffered:
/// each chunk is counted and dropped.
const DRAIN_BYTE_LIMIT: usize = 64 * 1024;

/// How long the drain keeps reading after the time limit, to land its stop.
///
/// See [`drain_until_peer_closes`]: at the pinned `h3-quinn` revision a stop
/// asked for while a read is outstanding is only recorded, and applied when that
/// read next completes. This is how long that chance lasts. Short, because the
/// only client it can reach is one that is still writing, and such a client
/// writes often.
const DRAIN_STOP_GRACE: Duration = Duration::from_millis(500);

/// Which of the drain's two limits ran out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainLimit {
    /// The client neither closed nor reset within [`DRAIN_TIME_LIMIT`].
    Time,
    /// The client sent more than [`DRAIN_BYTE_LIMIT`] without closing.
    Bytes,
}

impl DrainLimit {
    /// The name this limit appears under in the fallback log line.
    fn as_str(self) -> &'static str {
        match self {
            Self::Time => "time",
            Self::Bytes => "bytes",
        }
    }
}

/// Reads and discards whatever the client is still sending, until it closes.
///
/// The point is the *absence* of a signal: a receive stream that simply goes out
/// of scope is not left alone, because quinn sends STOP_SENDING(0) for one
/// dropped with data still unread. Reaching end of stream — or the client's own
/// reset — is therefore the only way to let the client finish on its own terms,
/// and it is what [`h3api::Stream::recv_data`] is here for.
///
/// Bounded in both dimensions so a client that never closes cannot hold the
/// tunnel slot: past either limit this falls back to the old behaviour, a
/// STOP_SENDING with H3_NO_ERROR, since nothing went wrong and no other code
/// would be truthful. Runs in the request's own task, so the wait costs this request
/// and nothing else on the connection.
async fn drain_until_peer_closes(stream: &mut Stream, stream_id: u64) {
    let mut drained: usize = 0;

    let tripped = tokio::time::timeout(DRAIN_TIME_LIMIT, async {
        loop {
            match stream.recv_data().await {
                // The client closed its sending side, or reset it. Either way it
                // is done and there is nothing left to ask it to stop.
                Ok(None) | Err(_) => return None,
                Ok(Some(chunk)) => {
                    drained = drained.saturating_add(chunk.len());
                    if drained >= DRAIN_BYTE_LIMIT {
                        return Some(DrainLimit::Bytes);
                    }
                }
            }
        }
    })
    .await;

    let limit = match tripped {
        Ok(None) => return,
        Ok(Some(limit)) => limit,
        Err(_elapsed) => DrainLimit::Time,
    };

    // The signal to watch: a client that neither closes nor resets after being
    // told the tunnel is over. Expected to be rare enough that every line is
    // worth reading, which is why it names the limit that ran out.
    debug!(
        stream_id,
        drained,
        limit = limit.as_str(),
        "a client did not close a tunnel closed on the spot; stopping it"
    );
    stream.stop_receiving(h3api::NO_ERROR);

    // A quirk of the pinned `h3-quinn` revision, and the reason the time limit
    // needs a coda: while a read is outstanding the underlying receive stream
    // lives *inside* that read's future, so a stop asked for at that moment is
    // only recorded, to be applied when the read next completes. Reading once
    // more is what gets H3_NO_ERROR onto the wire rather than the bare 0 quinn
    // sends for a receive stream dropped unread — and a client still writing,
    // the only one that can tell the two apart, hits it on its next chunk. The
    // byte limit needs none of this: it is reached *by* a completed read, so the
    // stop goes out at once.
    if limit == DrainLimit::Time {
        let _ = tokio::time::timeout(DRAIN_STOP_GRACE, stream.recv_data()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assert_eq!(error.as_str(), expected);

            let value = error.field_value();
            // `<identifier>; error=<type>`: the identifier names this proxy, the
            // parameter names the failure.
            assert_eq!(value, format!("volto; error={expected}"));

            let headers = error.headers();
            assert_eq!(
                headers.get("proxy-status").and_then(|v| v.to_str().ok()),
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
            (ProxyError::DnsError, StatusCode::BAD_GATEWAY),
            (ProxyError::DnsTimeout, StatusCode::GATEWAY_TIMEOUT),
            (ProxyError::ConnectionRefused, StatusCode::BAD_GATEWAY),
            (ProxyError::ConnectionTimeout, StatusCode::GATEWAY_TIMEOUT),
            (
                ProxyError::DestinationUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                ProxyError::ConnectionLimitReached,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (ProxyError::HttpRequestDenied, StatusCode::FORBIDDEN),
            (ProxyError::DestinationIpProhibited, StatusCode::FORBIDDEN),
        ] {
            assert_eq!(
                error.recommended_status(),
                expected,
                "{} must answer {expected}",
                error.as_str()
            );
        }
    }

    /// The three failures `from_connect_error` distinguishes must stay
    /// distinguishable in the response, which is the point of computing them.
    #[test]
    fn connect_failures_do_not_collapse_onto_one_status() {
        use std::io::{Error, ErrorKind};

        let statuses: Vec<StatusCode> = [
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
                StatusCode::BAD_GATEWAY,
                StatusCode::GATEWAY_TIMEOUT,
                StatusCode::SERVICE_UNAVAILABLE
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

    /// Reads the `Proxy-Status` field out of a header map.
    fn proxy_status(headers: &HeaderMap) -> String {
        headers
            .get("proxy-status")
            .and_then(|value| value.to_str().ok())
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
                proxy_status(&error.headers_with_next_hop(Some(hop))),
                format!(
                    "volto; error={}; next-hop=\"192.0.2.7:443\"",
                    error.as_str()
                )
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
            let value = proxy_status(&error.headers_with_next_hop(Some(hop)));
            assert_eq!(
                value,
                error.field_value(),
                "{} must stay exactly as it is without a next-hop",
                error.as_str()
            );
            assert!(
                !value.contains("10.1.2.3") && !value.contains("next-hop"),
                "{} leaked an address: {value}",
                error.as_str()
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
                error.headers_with_next_hop(None).get("proxy-status"),
                error.headers().get("proxy-status")
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
            proxy_status(&ProxyError::ConnectionRefused.headers_with_next_hop(Some(ipv6))),
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
            StatusCode::GATEWAY_TIMEOUT
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
            StatusCode::BAD_GATEWAY
        );

        let timed_out = ResolveFailure::TimedOut(Duration::from_secs(10));
        assert_eq!(timed_out.proxy_error(), ProxyError::DnsTimeout);
        assert_eq!(
            timed_out.proxy_error().recommended_status(),
            StatusCode::GATEWAY_TIMEOUT
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
