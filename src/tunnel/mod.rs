//! Request routing, the per-connection context, and the tunnel implementations.
//!
//! Two concerns of this module's own are a file each, and are re-exported from
//! here so that `tunnel::refuse` and `tunnel::Quota` stay the paths the rest of
//! the crate uses:
//!
//! * `status`: refusals and the RFC 9209 vocabulary they are written in.
//! * `quota`: the per-connection tunnel budget and the guards that spend it.

mod quota;
mod status;
pub mod tcp;
pub mod udp;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tracing::{debug, info};

use crate::auth::Authenticator;
use crate::config::{Config, IpFamilyPreference};
use crate::h3api::{Fields, Method, Request, Stream};
use crate::policy::{self, Policy};
use crate::quic::{AuthGate, MarkOutcome};

pub use quota::{AuthFailures, Pending, Quota, Slot};
pub use status::ProxyError;
pub(crate) use status::{
    ResolveFailure, Unreachable, accept_then_close, refuse, refuse_because, refuse_unreachable,
    refuse_with, respond,
};

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
/// every other field of one (D78).
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
/// RFC 9114 §4.2's rule is that "any message containing connection-specific
/// fields MUST be treated as malformed". It is quoted in full in the HTTP/3
/// layer's request decoder (behind [`crate::h3api::Resolver::resolve`]), where
/// the `Connection` field itself is refused at decode time. The fields RFC 9110
/// §7.6.1 names as connection-specific beyond `Connection` itself are judged
/// here rather than in the codec so that the answer can be a 400 instead of a
/// reset: RFC 9114 §4.1.2 lets a server "send an HTTP response indicating the
/// error prior to closing or resetting the stream", and a client is told more
/// by a status than by `H3_MESSAGE_ERROR`.
///
/// Named one at a time so the log says which field was the problem.
///
/// Hidden, and public for the reason `gate::judgement` is (D83): the `request`
/// fuzz target is outside this crate and has to be able to hand every request
/// `build_request` accepts to the judgement a real one gets. It is not an entry
/// point of its own; the request path calls this same function.
#[doc(hidden)]
pub fn connection_specific_field(req: &Request) -> Option<&'static str> {
    CONNECTION_SPECIFIC_FIELDS
        .iter()
        .copied()
        .find(|name| req.fields.contains(name))
}

/// RFC 9110 §7.6.1's connection-specific fields other than `Connection`.
///
/// Four of the five that section lists. The fifth is `TE`, which RFC 9114 §4.2
/// exempts when it says `trailers` and nothing else. That sentence is quoted in
/// the HTTP/3 layer's request decoder, where the value is checked and where the
/// answer is the reset a malformed field section gets. So `TE` is not judged
/// here, and its absence from this list is the exemption rather than an
/// oversight.
const CONNECTION_SPECIFIC_FIELDS: [&str; 4] = [
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
];

/// Reads a port the way RFC 3986 §3.2.3 spells one, as the number it names.
///
/// That section: "The port subcomponent of authority is designated by an
/// optional port number in decimal following the host and delimited from it by a
/// single colon (":") character", with the grammar
///
/// ```text
/// port        = *DIGIT
/// ```
///
/// Stricter than `u16::from_str` and the grammar, so that a port has one
/// spelling, as RFC 9110 §9.3.6 asks a server to "reject a CONNECT request
/// that targets an empty or invalid port number". Two spellings are refused:
///
/// * A sign, which `u16::from_str` takes and the grammar does not.
///   Without the digit check `example.com:+443` and
///   `/.well-known/masque/udp/example.com/+443/` would be dialled as 443.
/// * A leading zero, which `*DIGIT` allows. `example.com:0443` and
///   `example.com:000443` would be dialled as 443. Refusing them is our rule,
///   not the grammar's.
///
/// The empty string and zero are refused as well, which is not what `*DIGIT`
/// says on its own. RFC 9298 §3 requires `target_port` to "represent an
/// integer between 1 and 65535 inclusive" and RFC 9110 §9.3.6 names an empty
/// port beside an invalid one. Zero alone is that refusal, not a leading zero.
pub(crate) fn parse_port(text: &str) -> Result<u16, &'static str> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid port");
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err("port has a leading zero");
    }
    match text.parse() {
        Ok(0) => Err("port must not be zero"),
        Ok(port) => Ok(port),
        Err(_) => Err("invalid port"),
    }
}

/// Judges a host the way both routes must, and gives back the host to dial.
///
/// `host` is what the route has cut out of its own syntax: the part of a
/// CONNECT authority before the port, brackets included, or the template's
/// `target_host` once its percent-encoding is decoded. Both routes call this
/// and nothing else on the host, so one host gets one answer whichever route
/// names it. `tunnel::tests::both_routes_give_one_host_shape_one_answer` holds
/// the two to that, shape by shape.
///
/// The grammar is RFC 3986 §3.2.2's for an authority:
///
/// ```text
/// host        = IP-literal / IPv4address / reg-name
///
/// IP-literal = "[" ( IPv6address / IPvFuture  ) "]"
///
/// reg-name    = *( unreserved / pct-encoded / sub-delims )
/// ```
///
/// and RFC 9298 §3's for the template, which drops the brackets and keeps the
/// other two: "target_host = IPv6address / IPv4address / reg-name". What
/// follows from the two:
///
/// * **Brackets hold an IPv6 address and nothing else.** RFC 3986 §3.2.2:
///   "This is the only place where square bracket characters are allowed in
///   the URI syntax." A bracketed reg-name or IPv4 address is in neither
///   grammar. IPvFuture is in the first, and the same section says what to do
///   with it: an application that does not know the version flag "should
///   return an appropriate error for "address mechanism not supported"". The
///   template has no brackets at all. The bracketed form is accepted there
///   around an IPv6 address all the same, as in an authority; that tolerance
///   is ours.
/// * **A colon is an IPv6 address.** The authority route has already refused
///   one outside brackets, where it cannot be told from the port's. The
///   template route writes an IPv6 literal bare: "if "target_host" contains an
///   IPv6 literal, the colons (":") MUST be percent-encoded" (RFC 9298 §3).
///   A decoded host with a colon that is not an IPv6 address, such as
///   `example.com:80`, is in none of the three rules.
/// * **No zone index.** RFC 9298 §3: "Note that IPv6 scoped addressing zone
///   identifiers are not supported." RFC 3986 §3.2.2 says the same of its
///   grammar: "This syntax does not support IPv6 scoped addressing zone
///   identifiers." A scope names an interface on the client's side, which
///   means nothing on the proxy's. `Ipv6Addr` parses no zone, and the rule
///   below refuses the "%" of one written outside the address.
/// * **A reg-name is ASCII from two sets**, RFC 3986 §2.3's
///   `unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"` and §2.2's
///   `sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="`.
///   That rule also covers an IPv4 address, whose digits and dots are in the
///   first set. The grammar's third member, `pct-encoded`, is refused: this is
///   our rule. The authority route does not decode, and the template route
///   decodes once, as RFC 9298 §3.1 asks ("decodes their percent-encoding").
///   Neither RFC says what a "%" still in the host after that stands for, so
///   both routes refuse it rather than guess.
///
/// A trailing dot is a reg-name character and stays: RFC 3986 §3.2.2 says the
/// rightmost label of a fully qualified name "may be followed by a single "."".
/// What the name resolves to, and whether that address may be reached, is
/// the resolver's and the destination policy's question, not this one.
///
/// The refusal is a reason for the debug line; each route answers it with the
/// 400 it gives every other malformed target.
pub(crate) fn parse_host(host: &str) -> Result<&str, &'static str> {
    let (literal, bracketed) = match host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(inside) => (inside, true),
        None => (host, false),
    };
    if literal.is_empty() {
        return Err("empty host");
    }

    if bracketed || literal.contains(':') {
        return match literal.parse::<std::net::Ipv6Addr>() {
            Ok(_) => Ok(literal),
            Err(_) if bracketed => Err("IP literal is not an IPv6 address"),
            Err(_) => Err("host with a colon is not an IPv6 address"),
        };
    }

    if literal.contains(['[', ']']) {
        return Err("stray bracket in host");
    }
    let reg_name = |byte: u8| byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&byte);
    if !literal.bytes().all(reg_name) {
        return Err("host is not a registered name or an IP address");
    }
    Ok(literal)
}

/// How many times over a connection may spend `unanswered_packet_budget` before
/// its sessions are closed instead of muted.
///
/// The per-session budget is the RFC 9298 §7 mitigation and it is the right unit
/// for one conversation: a handshake that legitimately needs several packets
/// before the first reply must not break, and the default of 64 is generous for
/// exactly that reason. What it does not bound is how many conversations a
/// connection may start, so this multiplier is what turns the mitigation into a
/// bound.
///
/// Eight, because a client with several targets that are slow or unreachable at
/// once is ordinary (a resolver that is down, a peer-to-peer application
/// probing a stale address list), and one that has spent eight full session
/// budgets without a single target ever answering is not doing that any more.
/// The product is what a connection can reflect at silent targets in its whole
/// life: 512 packets at the defaults, where the per-session budget alone sets no
/// limit. A client that wants another allowance pays for another handshake,
/// which is the price this server charges everywhere else.
///
/// Not a configuration key. `unanswered_packet_budget` already carries the
/// meaning "how much this proxy will send into silence", an operator who
/// changes it moves both halves together, and zero switches both off. A second
/// key would be a second thing to get wrong for a bound that is a multiple of
/// the first (D86 counts the configuration surface as a cost).
pub const CONNECTION_UNANSWERED_MULTIPLIER: u32 = 8;

// A multiplier of one would make the connection's allowance the session's, so
// a client could reflect its whole budget again at every new session and the
// bound this constant exists to add would not exist.
const _: () = assert!(CONNECTION_UNANSWERED_MULTIPLIER >= 2);

// The product is taken with `saturating_mul`, which is right for a value an
// operator chose but would be silent for the shipped one: a default that
// saturated would mean the connection budget is `u32::MAX` rather than eight
// session budgets, and the arithmetic in the constant's doc above would be
// wrong.
const _: () = assert!(
    crate::config::DEFAULT_UNANSWERED_PACKET_BUDGET
        .checked_mul(CONNECTION_UNANSWERED_MULTIPLIER)
        .is_some()
);

/// Everything a request handler needs from the connection it arrived on.
///
/// Built once per connection and held in an `Arc`, so sharing it with a request
/// costs one refcount bump rather than a copy of every field. Not [`Clone`]:
/// one `Arc` is the only sharing a connection's requests need.
///
/// Not every member is settled when the first request arrives. The peer's
/// SETTINGS, which `peer_settings` shows, are read on the control stream by a
/// task of its own, so a request can be routed before they have been read.
/// [`udp::run`] waits for them, within a bound, before it sets up a session
/// (D119). `unanswered`, `unanswered_closures` and `datagram_room` change for
/// the life of the connection.
pub struct Context {
    /// The QUIC connection this request arrived on.
    ///
    /// Most uses are a datagram being sent, and only the sending half: an
    /// inbound datagram is routed to the request stream it names by the HTTP/3
    /// connection, and reaches a session through the
    /// [`crate::h3api::DatagramReceiver`] that stream handed it (D79). The other
    /// use is a connection-wide decision a request can reach: raising the
    /// stream allowance once a request authenticates
    /// (`Context::mark_authenticated`).
    pub quic: quinn::Connection,
    /// What the peer's SETTINGS say about HTTP Datagrams, and whether they
    /// have been read.
    ///
    /// RFC 9297 §2.1.1 forbids sending QUIC datagrams until the peer has
    /// advertised `SETTINGS_H3_DATAGRAM = 1`; until then a session falls back
    /// to DATAGRAM capsules on the request stream. A view of the HTTP/3
    /// connection's own state rather than a copy of it, for the reason
    /// [`crate::h3api::Connection::peer_settings`] gives.
    pub peer_settings: crate::h3api::PeerSettings,
    /// The configuration generation this connection was accepted under, for
    /// the credentials every request is checked against and the destinations
    /// this proxy may reach.
    pub generation: Arc<Generation>,
    /// Authentication failures seen on this connection so far, bucketed by who
    /// they were aimed at.
    ///
    /// Connection-scoped on purpose: no shared table across connections means no
    /// eviction policy and no memory that an attacker can grow. The lock is a
    /// `std::sync::Mutex`, held for a bucket lookup and a sum and never across
    /// an await; it is here rather than an atomic because the buckets and the
    /// total taken from them have to move together.
    pub auth_failures: Mutex<AuthFailures>,
    /// Failures tolerated before the connection is closed. Zero disables it.
    pub max_auth_failures: u32,
    /// Whether any request on this connection has passed the credentials check.
    ///
    /// One cell with three states, and never cleared. It is what lifts D76's
    /// bound on how long a connection may go without sending a request: a
    /// client that has proved who it is may hold an idle connection for as long
    /// as the transport's own idle timeout allows, which is what makes a proxy
    /// worth reconnecting to. A server with no users configured has nothing to
    /// check, so its first request opens it too. The state means "this peer
    /// passed the credentials check", not "credentials were seen".
    ///
    /// The third state is the accept loop's: an eviction claims the cell with a
    /// compare-and-swap, so a request racing an eviction either opens the gate
    /// first (and the slot stays) or finds it taken and is refused. An evicted
    /// gate reads closed, so the connection stays under every
    /// pre-authentication bound for the moment it has left.
    ///
    /// Owned by [`crate::quic`] rather than allocated here, because it is read
    /// from outside the connection as well: the accept loop needs to know which
    /// of its connections has never passed the credentials check, so that a
    /// full server can take that slot back rather than refuse a client that has
    /// credentials.
    pub authenticated: AuthGate,
    /// The peer's address, for logs that a fail2ban rule can act on.
    pub remote: std::net::SocketAddr,
    /// How many tunnels this connection may hold open at once.
    pub quota: Quota,
    /// The bidirectional stream allowance this connection is granted once it
    /// has authenticated: `[limits] max_streams_bidi`, in full.
    ///
    /// It is not what the handshake advertised. A connection is accepted on the
    /// small allowance `quic::INITIAL_BIDI_STREAMS` describes and raised to this
    /// by `Context::mark_authenticated`, so the number is carried here for the
    /// one moment it is needed. It is snapshotted with the rest of this
    /// connection's `[limits]`, so a reload changes what connections accepted
    /// from then on are worth and leaves a running one alone.
    pub max_streams_bidi: u32,
    /// How many tunnels this connection has been granted a slot for so far.
    ///
    /// Counted once per request that gets past [`Quota::acquire`], TCP and
    /// CONNECT-UDP alike, so this is slots taken rather than requests made: a
    /// request refused before the slot (407, a malformed message, the tunnel
    /// limit itself) never reaches it. It is *not* tunnels that carried
    /// anything, though: the slot is taken before the target is judged, so a
    /// destination the policy rejects and a target that cannot be reached are
    /// both counted here. Owned by [`crate::quic`], which reads it once when
    /// the connection ends to report it on the closing line (D72); nothing here
    /// ever reads it back.
    pub tunnels: Arc<AtomicU64>,
    /// The setups on this connection that failed at the lookup or at the
    /// target; see [`FailedSetups`]. Owned by [`crate::quic`] as `tunnels` is.
    pub failed_setups: Arc<FailedSetups>,
    /// The longest one tunnel may make no progress before it is given up on.
    ///
    /// Both tunnel kinds spend it, which is why it is not named for either: a
    /// CONNECT-UDP session that goes this long without a packet in either
    /// direction is reclaimed, and once one direction of a TCP tunnel has ended
    /// cleanly, each write in the surviving direction has this long to complete
    /// (`tcp` module docs). Both come from `[limits] udp_session_timeout`,
    /// whose name covers only the CONNECT-UDP half for compatibility. This
    /// field documents the other half.
    pub stall_budget: Duration,
    /// Budget for reaching a target, or `None` when it is disabled.
    ///
    /// Spent twice per request and separately: once on name resolution, once on
    /// the whole list of addresses it resolved to. The slot is taken before
    /// either, and the 200 that follows them is written under
    /// [`crate::h3api::Stream::respond_within`]'s bound of one connection idle
    /// timeout. So the worst case a tunnel slot is held before any byte flows
    /// is twice this plus one idle timeout.
    pub connect_timeout: Option<Duration>,
    /// This connection's share of the blocking pool, spent on name resolution.
    ///
    /// Per connection rather than per request, because what it bounds is a
    /// connection: one reserved lookup slot nobody can take away plus a capped
    /// draw on the server-wide allowance, so a client whose targets never
    /// resolve can neither park the whole pool nor stop anyone else's names
    /// from resolving (D90).
    pub resolver: crate::net::ConnectionResolver,
    /// Which address family a resolved target is tried on first.
    ///
    /// Snapshotted with the rest of the connection's `[limits]`, so a reload
    /// changes what connections accepted from then on do and leaves a running
    /// one alone.
    pub ip_family_preference: IpFamilyPreference,
    /// Packets this connection's UDP sessions may send towards targets that
    /// have never answered, per session and in total (RFC 9298 §7, D84).
    pub(crate) unanswered: quota::Unanswered,
    /// How many sessions this connection has lost to the unanswered total, and
    /// when that is worth saying out loud again.
    ///
    /// One line per closed session would be one line per stream a peer opens,
    /// which is the flood [`crate::logfmt::Sampler`] exists to stop.
    pub unanswered_closures: crate::logfmt::Sampler,
    /// How many destinations this connection's policy has refused, and when
    /// that is worth saying out loud again.
    ///
    /// The line is INFO: the refusal is the intended answer, and a client
    /// inside the tunnel that tries a private address is not a fault of this
    /// host. It is still evidence, since a client probing loopback through the
    /// proxy is what SSRF looks like from here, and the shipped `volto=info`
    /// filter keeps it. It is also cheap for a peer to provoke: an IP literal
    /// takes no resolver slot, opens no socket, and holds its tunnel slot only
    /// for as long as the refusal takes. One line per request would let a peer
    /// decide how much of this host's journal is left for anybody else. See
    /// [`crate::logfmt::Sampler`] for the schedule and for why silencing the
    /// repeats was not the answer.
    pub policy_refusals: crate::logfmt::Sampler,
    /// The same, for requests refused because this connection is already
    /// holding every tunnel it may.
    ///
    /// Reaching the limit costs a peer `max_targets_per_conn` live tunnels.
    /// Staying there costs it nothing, and without sampling every further
    /// request would be a warning for as long as it kept asking.
    pub limit_refusals: crate::logfmt::Sampler,
    /// A lower bound of the room left in quinn's outgoing datagram queue,
    /// shared by the connection's sessions because they share the queue.
    datagram_room: quota::DatagramRoom,
}

/// One configuration generation as its connections use it: the configuration,
/// and the credentials and destination rules built from it.
///
/// Built once per generation by [`crate::quic`] and shared by every connection
/// accepted under it, so a server with many connections holds one copy of each
/// configured password and of the denied-port list, not one per connection.
pub struct Generation {
    /// The configuration.
    pub config: Arc<Config>,
    /// The credentials every request is checked against.
    pub auth: Authenticator,
    /// Which destinations this proxy may reach.
    pub policy: Policy,
}

impl Generation {
    /// The generation of `config`.
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            auth: Authenticator::new(&config.auth),
            policy: Policy::new(&config.security),
            config,
        }
    }
}

impl Context {
    /// Builds the context for one accepted connection.
    ///
    /// `peer_settings` comes from the HTTP/3 connection, whose control stream
    /// reader updates what it shows. `resolver` is this connection's own view
    /// of the server's blocking-pool allowance.
    pub fn new(
        generation: Arc<Generation>,
        quic: quinn::Connection,
        peer_settings: crate::h3api::PeerSettings,
        resolver: crate::net::ConnectionResolver,
        tunnels: Arc<AtomicU64>,
        failed_setups: Arc<FailedSetups>,
        authenticated: AuthGate,
    ) -> Self {
        let config = &generation.config;
        Self {
            remote: quic.remote_address(),
            auth_failures: Mutex::new(AuthFailures::default()),
            max_auth_failures: config.security.max_auth_failures,
            authenticated,
            quic,
            peer_settings,
            quota: Quota::new(config.limits.max_targets_per_conn),
            max_streams_bidi: config.limits.max_streams_bidi,
            tunnels,
            failed_setups,
            stall_budget: config.limits.udp_session_timeout(),
            connect_timeout: config.limits.connect_timeout(),
            resolver,
            ip_family_preference: config.limits.ip_family_preference,
            unanswered: quota::Unanswered::new(config.security.unanswered_packet_budget),
            policy_refusals: crate::logfmt::Sampler::new(),
            limit_refusals: crate::logfmt::Sampler::new(),
            unanswered_closures: crate::logfmt::Sampler::new(),
            datagram_room: quota::DatagramRoom::default(),
            generation,
        }
    }

    /// Records an authentication failure, reporting whether that was one too many.
    ///
    /// Counts across the whole connection, so opening more streams does not reset
    /// the budget, and the answer is about the *total* of every bucket. A request
    /// that succeeds *as `username`* clears one of them; see
    /// [`Self::mark_authenticated`] and [`AuthFailures::record`].
    pub(crate) fn record_auth_failure(&self, username: Option<&str>) -> bool {
        self.auth_failures()
            .record(&self.generation.auth, username, self.max_auth_failures)
    }

    /// Poisoning would mean a panic between the bucket writes in
    /// [`AuthFailures::record`]; every one of them is a plain counter with
    /// nothing to observe half-written, and the alternative is a panic on a
    /// path whose job is to answer 407.
    fn auth_failures(&self) -> MutexGuard<'_, AuthFailures> {
        self.auth_failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether QUIC datagrams may be sent to the peer right now.
    pub(crate) fn datagrams_allowed(&self) -> bool {
        self.peer_settings.datagrams()
    }

    /// Records that a request on this connection got past the credentials check,
    /// and clears the failures that success answers for.
    ///
    /// Returns whether the request may proceed. `false` means the accept loop
    /// claimed this connection for eviction first: the caller must return
    /// without routing the request or opening a target socket, because the
    /// connection is already being closed. The eviction signal, not a response
    /// written here, is what ends it.
    ///
    /// Clearing keeps an authenticated client's occasional failures from adding
    /// up to `max_auth_failures`; [`AuthFailures`] says which buckets a success
    /// clears and why.
    ///
    /// # The stream allowance
    ///
    /// This is also where a connection stops being worth
    /// `quic::INITIAL_BIDI_STREAMS` request streams and becomes worth
    /// `[limits] max_streams_bidi` of them. A compare-and-swap rather than a
    /// `store` because that raise must happen exactly once: every CONNECT on
    /// this connection carries credentials and so arrives here, and the request
    /// tasks run concurrently, so the transition to authenticated is the only
    /// thing that names one of them the first. Every later success takes the
    /// same path and grants nothing, which is what it means for the allowance
    /// to be a property of the connection rather than of the request. An
    /// evicted gate grants nothing and clears nothing, because the request it
    /// belongs to must not proceed.
    ///
    /// Done before the failure counters below rather than after, so this holds
    /// no lock of ours while it takes quinn's.
    pub(crate) fn mark_authenticated(&self, username: Option<&str>) -> bool {
        match self.authenticated.mark() {
            MarkOutcome::First => {
                crate::quic::admit_configured_streams(&self.quic, self.max_streams_bidi);
            }
            MarkOutcome::Already => {}
            MarkOutcome::Evicted => return false,
        }

        self.auth_failures().clear_for(username);
        true
    }

    /// Whether any request on this connection has passed the credentials check
    /// (D76).
    pub(crate) fn is_authenticated(&self) -> bool {
        self.authenticated.is_open()
    }
}

/// The tunnel setups of one connection that ended in a 502, a 503 or a 504
/// because the name did not resolve or the target could not be reached.
///
/// Such a setup prints at debug only, as every refusal does, because a peer
/// can provoke as many as it likes (D97). These counts are what the production
/// level keeps of them, and they cost one line: the connection's closing line
/// prints them once. A setup the policy refused, or one refused at the tunnel
/// limit, is not counted here.
#[derive(Debug, Default)]
pub struct FailedSetups {
    resolves: AtomicU64,
    connects: AtomicU64,
    millis: AtomicU64,
}

impl FailedSetups {
    /// Counts a lookup that failed or ran out of its budget after `waited`.
    pub(crate) fn resolve(&self, waited: Duration) {
        self.resolves.fetch_add(1, Ordering::Relaxed);
        self.wait(waited);
    }

    /// Counts a target none of whose addresses could be reached. `waited` is
    /// the lookup plus the walk over the addresses.
    pub(crate) fn connect(&self, waited: Duration) {
        self.connects.fetch_add(1, Ordering::Relaxed);
        self.wait(waited);
    }

    fn wait(&self, waited: Duration) {
        let millis = u64::try_from(waited.as_millis()).unwrap_or(u64::MAX);
        self.millis.fetch_add(millis, Ordering::Relaxed);
    }

    /// How many lookups failed, how many targets could not be reached, and
    /// how long those setups took in sum, in milliseconds.
    pub fn read(&self) -> (u64, u64, u64) {
        (
            self.resolves.load(Ordering::Relaxed),
            self.connects.load(Ordering::Relaxed),
            self.millis.load(Ordering::Relaxed),
        )
    }
}

/// Runs `work` and returns what it gave with the time it took.
///
/// On tokio's clock, like every budget in this module, so a test on a paused
/// clock reads the time exactly.
pub(crate) async fn timed<F: std::future::Future>(work: F) -> (F::Output, Duration) {
    let started = tokio::time::Instant::now();
    let output = work.await;
    (output, started.elapsed())
}

/// A target [`admit_target`] let through.
#[derive(Debug)]
pub(crate) struct Admitted {
    /// The addresses the tunnel may dial first, in the order to try them:
    /// those of the preferred family that passed the destination policy, or,
    /// when none did, those of the other family that passed it. Never empty.
    pub(crate) addresses: Vec<std::net::SocketAddr>,
    /// The other family's lookup, when its answer has not been read yet. A
    /// tunnel reads it only once every address above has failed, and its
    /// addresses still have to pass the destination policy
    /// ([`later_addresses`]). `None` for `system`, for an IP literal, and
    /// when `addresses` already are the other family's.
    pub(crate) later: Option<crate::net::OtherFamily>,
    /// When the resolution budget runs out, or `None` when there is none.
    pub(crate) deadline: Option<tokio::time::Instant>,
    /// How long the tunnel waited on lookups so far: the wait for a lookup
    /// slot plus the lookup ([`crate::net::ConnectionResolver::lookup`]), and
    /// the other family's lookup when the policy left none of the first
    /// family. An IP literal asks no resolver and reads zero. Each tunnel adds
    /// any later wait for the other family and prints the sum as
    /// `resolve_ms` on its established line.
    pub(crate) resolve: Duration,
}

/// What [`resolve_within`] found.
#[derive(Debug)]
pub(crate) struct Resolved {
    /// The preferred family's addresses, or the other family's when the
    /// preferred one gave none. Never empty.
    pub(crate) addresses: Vec<std::net::SocketAddr>,
    /// The other family's lookup, when `addresses` are the preferred family's.
    pub(crate) other: Option<crate::net::OtherFamily>,
    /// When the budget runs out, or `None` when there is none.
    pub(crate) deadline: Option<tokio::time::Instant>,
}

/// Resolves `host`/`port`, giving the resolver at most `budget` and asking for
/// the families in the order `family` gives.
///
/// Bounded because the tunnel slot and the file descriptor it stands for are
/// already held by the time this runs: a stub resolver whose nameserver has gone
/// away takes tens of seconds to give up, and every one of them is a slot the
/// client cannot use for anything else. `None` leaves the wait to the resolver,
/// which is what `connect_timeout = 0` asks for.
///
/// The address-family preference is applied here, once, rather than in each
/// tunnel (decision D58): this is the single point where a name becomes a list
/// of addresses, and it sits before the destination policy filters that list
/// and before either tunnel starts dialling it, so both kinds agree on which
/// family is tried first without either having to remember to ask.
///
/// With `ipv4` or `ipv6` the preferred family is asked alone, and the answer
/// is returned as soon as it has an address. The other family's lookup is
/// started beside it when the connection has a lookup slot to spare, and
/// otherwise only when a tunnel needs it (D123). RFC 8305 §3: "Implementations
/// SHOULD NOT wait for both families of answers to return before attempting
/// connection establishment." The slot rule and the lookup made only on demand
/// are this server's own. When the preferred family gives no address, for any
/// reason, the other family is asked before the name is refused, inside the
/// same budget. When both fail, the failure reported is the first of the two
/// that is not "no address in this family", the preferred family's first.
///
/// With `system` this is one lookup of both families, in the resolver's
/// order.
pub(crate) async fn resolve_within(
    host: &str,
    port: u16,
    resolver: &crate::net::ConnectionResolver,
    budget: Option<Duration>,
    family: IpFamilyPreference,
) -> Result<Resolved, ResolveFailure> {
    let limit = budget.map(|budget| (tokio::time::Instant::now() + budget, budget));
    let deadline = limit.map(|(deadline, _)| deadline);

    let Some(preferred) = crate::net::Family::preferred(family) else {
        let addresses = until_deadline(resolver.lookup(host, port), limit).await?;
        return Ok(Resolved {
            addresses,
            other: None,
            deadline,
        });
    };

    if let Some(address) = crate::net::literal(host, port) {
        return Ok(Resolved {
            addresses: vec![address],
            other: None,
            deadline,
        });
    }

    let mut other = crate::net::OtherFamily::new(host, port, preferred.other());
    let first = until_deadline(
        resolver.lookup_family(host, port, preferred, &mut other),
        limit,
    )
    .await;
    let first_failure = match first {
        Ok(addresses) => {
            return Ok(Resolved {
                addresses,
                other: Some(other),
                deadline,
            });
        }
        Err(failure) => failure,
    };

    match ask_other(&mut other, resolver, limit).await {
        Ok(addresses) => Ok(Resolved {
            addresses,
            other: None,
            deadline,
        }),
        Err(second_failure) => Err(reported(first_failure, second_failure)),
    }
}

/// The failure reported when both families failed: the first of the two that
/// is not "no address in this family", the preferred family's first.
fn reported(first: ResolveFailure, second: ResolveFailure) -> ResolveFailure {
    if first.is_no_data() && !second.is_no_data() {
        second
    } else {
        first
    }
}

/// The other family's answer, waited for until the deadline of `limit`.
///
/// A lookup that was never started is not started once the deadline has
/// passed, because nothing would wait for its answer.
async fn ask_other(
    other: &mut crate::net::OtherFamily,
    resolver: &crate::net::ConnectionResolver,
    limit: Option<(tokio::time::Instant, Duration)>,
) -> Result<Vec<std::net::SocketAddr>, ResolveFailure> {
    if let Some((deadline, budget)) = limit
        && !other.is_started()
        && tokio::time::Instant::now() >= deadline
    {
        return Err(ResolveFailure::TimedOut(budget));
    }
    until_deadline(other.addresses(resolver), limit).await
}

/// Waits for `lookup` until the deadline of `limit`, which also holds the
/// budget a timeout reports. `None` waits for as long as the lookup takes.
///
/// A deadline rather than a budget, so that two lookups can share one. Apart
/// from [`resolve_within`] so the budget can be tested against a lookup that
/// never answers, which no real resolver can be made to do on demand.
async fn until_deadline<F>(
    lookup: F,
    limit: Option<(tokio::time::Instant, Duration)>,
) -> Result<Vec<std::net::SocketAddr>, ResolveFailure>
where
    F: std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>>,
{
    let resolved = match limit {
        Some((deadline, budget)) => match tokio::time::timeout_at(deadline, lookup).await {
            Ok(resolved) => resolved,
            Err(_) => return Err(ResolveFailure::TimedOut(budget)),
        },
        None => lookup.await,
    };

    resolved.map_err(ResolveFailure::Failed)
}

/// The least time one connect attempt is given out of the budget, unless less
/// than this is left.
///
/// Our own rule, not a protocol number: three seconds is one SYN
/// retransmission at the one-second initial retransmission timeout plus the
/// handshake that follows it. A share below that ends an attempt before a lost
/// first SYN has been sent again, so a reachable target behind a slow path or a
/// long address list could time out on every address.
pub(crate) const MIN_CONNECT_SHARE: Duration = Duration::from_secs(3);

/// [`first_reachable_then`] with no other family behind `addresses`.
#[cfg(test)]
pub(crate) async fn first_reachable<T, D, F>(
    addresses: &[std::net::SocketAddr],
    budget: Option<Duration>,
    dial: D,
    failed: &'static str,
) -> Result<T, Unreachable>
where
    D: Fn(std::net::SocketAddr) -> F,
    F: std::future::Future<Output = std::io::Result<T>>,
{
    first_reachable_then(
        addresses.to_vec(),
        None::<Later<std::future::Ready<Vec<std::net::SocketAddr>>>>,
        budget,
        dial,
        failed,
    )
    .await
    .result
}

/// The other family's addresses, for a walk to go on to once the first
/// addresses have failed.
pub(crate) struct Later<L> {
    /// Whether the lookup behind `addresses` is already running, so that
    /// waiting for it beside an attempt starts nothing.
    pub(crate) started: bool,
    /// The addresses that passed the destination policy. Empty when the
    /// lookup failed.
    pub(crate) addresses: L,
}

/// What [`first_reachable_then`] did.
pub(crate) struct Walk<T> {
    /// The first address that answered, or the last failure.
    pub(crate) result: Result<T, Unreachable>,
    /// How long the walk waited for the other family's addresses with no
    /// attempt in flight. This is lookup time, which a tunnel reports as
    /// `resolve_ms` rather than as `connect_ms`.
    pub(crate) waited: Duration,
    /// Every address the walk knew of by the end, in the order it tries them.
    pub(crate) addresses: Vec<std::net::SocketAddr>,
}

/// Dials `first` in order, then the other family's addresses that `later`
/// gives, returning the first that answers or the last failure, with the
/// address it happened on.
///
/// Both tunnel types walk their resolved list this way, so the address an
/// RFC 9209 `next-hop` parameter names is chosen by one rule: the last one
/// attempted. `failed` is the caller's debug line for an address that did not
/// answer.
///
/// `budget` bounds the **whole** walk rather than each address, so a name
/// with several unreachable addresses cannot multiply the wait by their
/// number. Within it, each attempt gets an equal share of what is left for the
/// addresses not yet tried, so an address that never answers cannot spend the
/// time of the ones after it, and an address that fails early leaves the rest
/// of its share to them. The share is never less than [`MIN_CONNECT_SHARE`],
/// or what is left when that is less, so a long list or a small budget does not
/// cut every attempt shorter than a handshake takes. The shares never add up to
/// more than the budget, and the walk stops when nothing is left, so the floor
/// means fewer addresses are tried, not a longer wait. The attempts are still
/// made one at a time, in the order resolution gave (D58): this is not address
/// racing. `None` waits on each dial for as long as it takes.
///
/// The other family counts towards the shares as soon as its addresses are
/// known. While they are not, an attempt is given the share
/// that counts only the known ones, and the lookup is waited for beside it:
/// when it gives addresses, the attempt's share becomes what the rule gives
/// with them, counted from the moment the attempt started, and an attempt
/// already past that share ends at once. Beside an earlier attempt the lookup
/// is waited for only if it is already running. A lookup that never started,
/// because the connection had no slot to spare, is started beside the last
/// known address. Once every known address has failed, the walk waits for the
/// lookup alone, inside the same budget. A lookup that fails or runs out of
/// time adds no address, and the walk reports its last connect failure.
pub(crate) async fn first_reachable_then<T, D, F, L>(
    first: Vec<std::net::SocketAddr>,
    later: Option<Later<L>>,
    budget: Option<Duration>,
    dial: D,
    failed: &'static str,
) -> Walk<T>
where
    D: Fn(std::net::SocketAddr) -> F,
    F: std::future::Future<Output = std::io::Result<T>>,
    L: std::future::Future<Output = Vec<std::net::SocketAddr>>,
{
    // Taken once, before the first attempt: every address draws on the same
    // budget.
    let deadline = budget.map(|budget| tokio::time::Instant::now() + budget);
    let mut addresses = first;
    let (mut started, mut lookup) = match later {
        Some(later) => (later.started, Some(Box::pin(later.addresses))),
        None => (false, None),
    };
    let mut waited = Duration::ZERO;
    let mut last = None;
    let mut tried = 0;

    loop {
        if tried == addresses.len() {
            // Every known address has failed. What is left is the other
            // family, and nothing else is in flight while the walk waits.
            let Some(mut pending) = lookup.take() else {
                break;
            };
            let (found, took) = timed(async {
                match deadline {
                    Some(deadline) => tokio::time::timeout_at(deadline, pending.as_mut())
                        .await
                        .unwrap_or_default(),
                    None => pending.as_mut().await,
                }
            })
            .await;
            waited += took;
            addresses.extend(found);
            if tried == addresses.len()
                || deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
            {
                break;
            }
            continue;
        }

        let address = addresses[tried];
        let beside = lookup.is_some() && (started || tried + 1 == addresses.len());
        let mut attempt = std::pin::pin!(dial(address));
        let began = tokio::time::Instant::now();
        let share_end = |untried: usize| {
            deadline.map(|deadline| {
                let untried = u32::try_from(untried).unwrap_or(u32::MAX);
                let remaining = deadline.saturating_duration_since(began);
                began + (remaining / untried).max(MIN_CONNECT_SHARE).min(remaining)
            })
        };
        let mut ends = share_end(addresses.len() - tried);

        let result = loop {
            tokio::select! {
                biased;
                result = &mut attempt => break result,
                () = expiry(ends) => break Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the connect budget expired before the target answered",
                )),
                found = async {
                    match lookup.as_mut() {
                        Some(pending) => pending.as_mut().await,
                        None => std::future::pending().await,
                    }
                }, if beside && lookup.is_some() => {
                    lookup = None;
                    started = true;
                    addresses.extend(found);
                    ends = share_end(addresses.len() - tried);
                }
            }
        };
        tried += 1;

        match result {
            Ok(reached) => {
                return Walk {
                    result: Ok(reached),
                    waited,
                    addresses,
                };
            }
            Err(error) => {
                debug!(%address, %error, "{failed}");
                last = Some(Unreachable {
                    next_hop: Some(address),
                    error,
                });
            }
        }

        // Nothing left to share: the failure just recorded is the answer, and
        // no address is dialled on a budget that is already spent.
        if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            break;
        }
    }

    Walk {
        result: Err(last.unwrap_or_else(Unreachable::no_addresses)),
        waited,
        addresses,
    }
}

/// Waits until `at`, or for ever when it is `None`.
async fn expiry(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// The other family's addresses that pass the destination policy, for a
/// tunnel whose first addresses have all failed.
///
/// The lookup was started at resolution, or is started now if the connection
/// had no slot to spare then. A lookup that fails gives no address.
pub(crate) fn later_addresses<'a>(
    other: &'a mut crate::net::OtherFamily,
    resolver: &'a crate::net::ConnectionResolver,
    usable: impl Fn(&[std::net::SocketAddr]) -> Vec<std::net::SocketAddr> + 'a,
) -> Later<impl std::future::Future<Output = Vec<std::net::SocketAddr>> + 'a> {
    Later {
        started: other.is_started(),
        addresses: async move {
            match other.addresses(resolver).await {
                Ok(addresses) => usable(&addresses),
                Err(_) => Vec::new(),
            }
        },
    }
}

/// Whether a resolved address is one of this proxy's own.
///
/// RFC 9298 §7, on the software that trusts a request for having come from the
/// host it runs on: "This could lead to unauthorized access by UDP proxying
/// clients unless the UDP proxy disallows UDP proxying requests to vulnerable
/// targets, such as the UDP proxy's own addresses and localhost, link-local,
/// multicast, and broadcast addresses. UDP proxies can use the
/// destination_ip_prohibited Proxy Error Type from Section 2.3.5 of
/// [PROXY-STATUS] when rejecting such requests." Four of those five classes are
/// [`Policy`]'s two buckets. This is the fifth, and it is the one no address
/// range describes: which addresses are the proxy's own is a fact about the host
/// rather than about the address, so it is asked of the kernel
/// ([`crate::net::holds_address`]) rather than matched against a list.
///
/// The class is not lifted by `allow_private_networks`, because the reason is a
/// different one. That switch is the operator saying which *address space* this
/// proxy may reach; this rule is about the proxy itself, and a target that is
/// this host is the escalation the section describes whatever the address space
/// says.
///
/// **Loopback is deliberately not here.** The sentence above names "localhost"
/// as a class beside "the proxy's own addresses", and this crate implements that
/// class in the private bucket, where `allow_private_networks` decides it: off
/// by default, and reachable only where an operator has said in the
/// configuration file that local address space is a legitimate destination.
/// Folding loopback in here would overrule that decision, and it would do it for
/// every service on the host rather than for this proxy.
///
/// The question is asked of every form in which the host could hold the
/// target ([`own_address_probes`]), and the `SocketAddr` keeps the scope ID
/// that selects the interface for a link-local address.
///
/// The cost is one `bind(2)` per form per allowed address per tunnel opened,
/// and an address has at most two forms. That is per request and never per
/// packet, and it is paid only by addresses the policy has already let
/// through.
fn is_the_proxys_own(address: std::net::SocketAddr) -> bool {
    own_address_probes(address)
        .into_iter()
        .any(crate::net::holds_address)
}

/// The addresses [`is_the_proxys_own`] binds to ask whether `address` is this
/// host's, each at port 0.
///
/// A target can name this host in two forms, and both are probed:
///
/// * The address as written, in its [`policy::canonical`] form. A host that
///   runs a transition mechanism holds that IPv6 address on an interface: a
///   Teredo client on its tunnel interface, or a 6to4 host behind a 1:1 NAT,
///   which holds `2002:<public>::1` while no interface carries the public IPv4
///   address.
/// * The IPv4 address it carries. For NAT64, 6to4 and Teredo that is
///   [`policy::routed_form`], the address a host routing the prefix reaches.
///   For an IPv4-compatible `::a.b.c.d` it is the last 32 bits, which
///   `routed_form` leaves alone. A stack that still honours that deprecated
///   range reaches `a.b.c.d`, and on one that does not the target reaches
///   nothing, so refusing it costs no destination.
///
/// The IPv6 form keeps the scope ID, because a link-local address is selected
/// by it. An IPv4 form has no scope.
///
/// A loopback form is left out, because loopback is the private bucket's class
/// (see [`is_the_proxys_own`]). An IPv4-mapped address has one form, the IPv4
/// address it stands for, and the list holds no address twice.
///
/// Pure, so both forms and the scope are tested without a transition or
/// link-local address on the test host.
fn own_address_probes(address: std::net::SocketAddr) -> Vec<std::net::SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};

    let written = match (policy::canonical(address.ip()), address) {
        (IpAddr::V6(v6), SocketAddr::V6(original)) => SocketAddr::V6(SocketAddrV6::new(
            v6,
            0,
            original.flowinfo(),
            original.scope_id(),
        )),
        (ip, _) => SocketAddr::new(ip, 0),
    };

    let carried = match policy::routed_form(address.ip()) {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6)
            if v6.octets()[..12] == [0; 12] && !v6.is_unspecified() && !v6.is_loopback() =>
        {
            let [.., a, b, c, d] = v6.octets();
            Some(Ipv4Addr::new(a, b, c, d))
        }
        IpAddr::V6(_) => None,
    };

    let mut probes = Vec::with_capacity(2);
    for probe in [
        Some(written),
        carried.map(|v4| SocketAddr::new(v4.into(), 0)),
    ]
    .into_iter()
    .flatten()
    {
        if !probe.ip().is_loopback() && !probes.contains(&probe) {
            probes.push(probe);
        }
    }
    probes
}

/// Turns a request's target into the addresses it may be dialled on, answering
/// the request itself when there are none it may use.
///
/// `Some` carries a non-empty, policy-filtered, family-ordered list, ready for
/// the caller to dial, the other family's lookup when it is still to be read,
/// and the time the resolution took ([`Admitted`]). `None`
/// means the request has **already been answered** (with a 403, a 502, a 504,
/// or the 200 that closes on the spot), and the caller has nothing left to do
/// but return.
///
/// The order of the three steps is part of the design:
///
/// * The port rule needs no address, so it is applied before the resolver is
///   asked anything: a denied port cannot be used to make the proxy run lookups.
/// * Resolution is explicit, rather than left to the connect call, so the
///   addresses are visible to the policy below. [`resolve_within`] bounds it and
///   asks for the families in the preferred order. A resolver failure is not the client's fault
///   (decision D9), so it is a 502 with the RFC 9209 reason rather than a 400,
///   and a resolver that never answered is a 504 `dns_timeout` instead.
/// * A name resolving to a mix of public and private addresses keeps only the
///   public ones, so DNS rebinding onto loopback gains nothing. What survives
///   that filter is then asked [`is_the_proxys_own`]. When no address of the
///   preferred family survives, the other family is read and filtered before
///   anything is decided, so what follows is judged on both families together
///   ([`judge`]).
///
/// A target whose every address is the unspecified one is accepted and closed
/// on the spot ([`accept_then_close`], decision D49); every other refusal keeps
/// its 403 with the RFC 9209 reason.
///
/// `accepted_fields` supplies what an accepted response of the caller's tunnel
/// type has to carry: nothing for a TCP tunnel, the RFC 9297 `Capsule-Protocol`
/// field for CONNECT-UDP. Deferred, so only the one path that sends a 200 pays
/// for building it.
pub(crate) async fn admit_target(
    host: &str,
    port: u16,
    ctx: &Context,
    stream: &mut Stream,
    accepted_fields: impl FnOnce() -> Fields,
) -> Option<Admitted> {
    let stream_id = stream.id();

    if !ctx.generation.policy.allows_port(port) {
        debug!(stream_id, host, port, "target port denied by policy");
        refuse_because(stream, ProxyError::HttpRequestDenied).await;
        return None;
    }

    let judged = judge(
        host,
        port,
        &ctx.resolver,
        ctx.connect_timeout,
        ctx.ip_family_preference,
        |addresses| usable_addresses(ctx, stream_id, host, port, addresses),
    )
    .await;

    match judged {
        Judged::Admitted(admitted) => Some(admitted),
        Judged::Unresolved(failure, resolve) => {
            let error = failure.proxy_error();
            ctx.failed_setups.resolve(resolve);
            debug!(stream_id, host, port, reason = %failure, "failed to resolve target");
            refuse_because(stream, error).await;
            None
        }
        Judged::Blackhole(addresses) => {
            info!(
                log_id = "t9hu0cd2",
                stream_id,
                host,
                port,
                addresses = %crate::logfmt::addresses(&addresses),
                "every address of the target is a DNS blackhole"
            );
            accept_then_close(stream, accepted_fields()).await;
            None
        }
        Judged::Prohibited(addresses) => {
            // INFO on a doubling schedule rather than every time, for the
            // reason [`Context::policy_refusals`] gives.
            match ctx.policy_refusals.record() {
                Some(refusals) => info!(
                    log_id = "ucmaf4w6",
                    stream_id,
                    host,
                    port,
                    addresses = %crate::logfmt::addresses(&addresses),
                    refusals,
                    "every address of the target is prohibited by policy; further refusals on \
                     this connection are logged at debug level until the count doubles"
                ),
                None => debug!(
                    stream_id,
                    host,
                    port,
                    addresses = %crate::logfmt::addresses(&addresses),
                    "every address of the target is prohibited by policy"
                ),
            }
            refuse_because(stream, ProxyError::DestinationIpProhibited).await;
            None
        }
    }
}

/// The addresses of `addresses` the destination policy lets a tunnel dial,
/// in the same order: the ones [`Policy`] allows that are not
/// [`is_the_proxys_own`].
pub(crate) fn usable_addresses(
    ctx: &Context,
    stream_id: u64,
    host: &str,
    port: u16,
    addresses: &[std::net::SocketAddr],
) -> Vec<std::net::SocketAddr> {
    let mut allowed = ctx.generation.policy.allowed_addresses(addresses);
    let judged = allowed.len();
    allowed.retain(|address| !is_the_proxys_own(*address));
    if allowed.len() < judged {
        debug!(
            stream_id,
            host,
            port,
            refused = judged - allowed.len(),
            "refused an address this host holds as one of the proxy's own"
        );
    }
    allowed
}

/// What [`judge`] decided about a target.
#[derive(Debug)]
enum Judged {
    /// The tunnel may dial it.
    Admitted(Admitted),
    /// The name did not resolve, after this long.
    Unresolved(ResolveFailure, Duration),
    /// Every address, of both families, is the unspecified one.
    Blackhole(Vec<std::net::SocketAddr>),
    /// No address passed the policy. These are all of them, of both families.
    Prohibited(Vec<std::net::SocketAddr>),
}

/// Resolves a target and applies `usable`, the destination policy, to what
/// it resolved to.
///
/// The preferred family is judged first. When none of its addresses passes,
/// the other family is read before anything is decided, so the request is
/// answered as it would be with both families in one list: the other family's
/// usable addresses if it has any, and otherwise the blackhole or refusal
/// judged on both families together. The other family's lookup failing here
/// counts as no address, inside the resolution budget.
async fn judge(
    host: &str,
    port: u16,
    resolver: &crate::net::ConnectionResolver,
    budget: Option<Duration>,
    family: IpFamilyPreference,
    usable: impl Fn(&[std::net::SocketAddr]) -> Vec<std::net::SocketAddr>,
) -> Judged {
    let (resolved, mut resolve) = timed(resolve_within(host, port, resolver, budget, family)).await;
    let resolved = match resolved {
        Ok(resolved) => resolved,
        Err(failure) => return Judged::Unresolved(failure, resolve),
    };

    let allowed = usable(&resolved.addresses);
    if !allowed.is_empty() {
        return Judged::Admitted(Admitted {
            addresses: allowed,
            later: resolved.other,
            deadline: resolved.deadline,
            resolve,
        });
    }

    let mut addresses = resolved.addresses;
    let mut allowed = Vec::new();
    if let Some(mut other) = resolved.other {
        let limit = resolved.deadline.zip(budget);
        let (found, took) = timed(ask_other(&mut other, resolver, limit)).await;
        resolve += took;
        if let Ok(found) = found {
            allowed = usable(&found);
            addresses.extend(found);
        }
    }

    if !allowed.is_empty() {
        Judged::Admitted(Admitted {
            addresses: allowed,
            later: None,
            deadline: resolved.deadline,
            resolve,
        })
    } else if policy::is_dns_blackhole(&addresses) {
        Judged::Blackhole(addresses)
    } else {
        Judged::Prohibited(addresses)
    }
}

/// One poll on a no-op waker, for the tests of other modules.
#[cfg(test)]
pub(crate) use tests::poll_once;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h3api::{FieldValue, Status};
    use std::assert_matches;

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

    /// The RFC 9298 §7 class, in both directions.
    ///
    /// Loopback is the case worth pinning: it *is* an address this host holds,
    /// the kernel binds it happily, and it must still answer `false` here
    /// because "localhost" is the private bucket's class and
    /// `allow_private_networks` is what decides it. `::ffff:127.0.0.1` is the
    /// same address in an IPv6 hat and has to be canonicalised before the
    /// question is asked at all.
    #[test]
    fn only_a_non_loopback_address_of_this_host_is_the_proxys_own() {
        for literal in ["127.0.0.1:0", "[::1]:0", "[::ffff:127.0.0.1]:0"] {
            assert!(
                !is_the_proxys_own(literal.parse().expect("a socket address")),
                "{literal} is the localhost class, not this one"
            );
        }

        // RFC 5737 TEST-NET-1: on no interface anywhere.
        assert!(!is_the_proxys_own(
            "192.0.2.1:0".parse().expect("a socket address")
        ));

        // And the class itself, on a host that has an address to show it with.
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind a probe socket");
        if socket.connect("192.0.2.1:9").is_ok() {
            let own = socket.local_addr().expect("a local address");
            if !own.ip().is_loopback() && !own.ip().is_unspecified() {
                assert!(
                    is_the_proxys_own(own),
                    "{own} is an address this host holds"
                );
            }
        }
    }

    /// The scope ID of a link-local target reaches the bind.
    ///
    /// Binding `fe80::1` without the scope that selects its interface fails
    /// even on a host that holds it, so a probe that dropped the scope would
    /// call an own link-local address someone else's. A test host cannot be
    /// relied on to carry a link-local address, so the probe addresses are
    /// asserted instead of the bind.
    #[test]
    fn a_link_local_target_is_probed_with_its_scope() {
        for (target, scope) in [("[fe80::1%7]:443", 7), ("[fe80::1]:443", 0)] {
            let target: std::net::SocketAddr = target.parse().expect("a socket address");
            let probes = own_address_probes(target);
            assert_eq!(probes.len(), 1, "{target}: {probes:?}");
            let std::net::SocketAddr::V6(probe) = probes[0] else {
                panic!("{target} must be probed as IPv6");
            };
            assert_eq!(
                probe.ip(),
                &"fe80::1".parse::<std::net::Ipv6Addr>().unwrap()
            );
            assert_eq!(probe.scope_id(), scope, "{target}");
            assert_eq!(probe.port(), 0, "{target}");
        }
    }

    /// An IPv6 address that carries an IPv4 address is probed in both forms.
    ///
    /// The routed form is what a host that routes the prefix reaches, so a
    /// form of this host's own IPv4 address is the proxy's own. The address as
    /// written is what an interface carries on a host that runs the transition
    /// mechanism itself: a Teredo client holds its Teredo address on its tunnel
    /// interface, and a 6to4 host behind a 1:1 NAT holds `2002:<public>::1`
    /// while no interface carries the public IPv4 address. Each of those
    /// targets reaches this host, so the check asks about both forms.
    ///
    /// Every vector embeds 192.0.2.45. The Teredo one follows the RFC 4380 §4
    /// layout, with 192.0.2.1 (`c000:201`) as the server field and a client
    /// field, `3fff:fdd2`, that is 192.0.2.45 with every bit inverted. The scope ID on the Teredo literal is there to show
    /// that it is kept on the IPv6 probe, which is the form a scope belongs to.
    #[test]
    fn a_transition_address_is_probed_as_written_and_as_routed() {
        let carried: std::net::SocketAddr = "192.0.2.45:0".parse().unwrap();
        for written in [
            "[64:ff9b::c000:22d]:22",
            "[2002:c000:22d::1]:22",
            "[2001:0:c000:201:8000:63bf:3fff:fdd2]:22",
            "[::c000:22d]:22",
        ] {
            let target: std::net::SocketAddr = written.parse().expect("a socket address");
            let as_written = std::net::SocketAddr::new(target.ip(), 0);
            let probes = own_address_probes(target);
            assert!(
                probes.contains(&as_written),
                "{written} must be probed as written: {probes:?}"
            );
            assert!(
                probes.contains(&carried),
                "{written} must be probed as the {carried} it carries: {probes:?}"
            );
            assert_eq!(probes.len(), 2, "{written}: {probes:?}");
        }

        let scoped: std::net::SocketAddr = "[2001:0:c000:201:8000:63bf:3fff:fdd2%7]:22"
            .parse()
            .expect("a socket address");
        let probes = own_address_probes(scoped);
        assert!(
            probes.contains(&std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                "2001:0:c000:201:8000:63bf:3fff:fdd2".parse().unwrap(),
                0,
                0,
                7,
            ))),
            "the scope stays on the IPv6 probe: {probes:?}"
        );
        assert!(probes.contains(&carried), "{probes:?}");
    }

    /// Forms that carry no second address are probed once, and loopback is not
    /// probed at all.
    ///
    /// An IPv4-mapped address is the IPv4 address it stands for, so that is
    /// its one probe. Loopback is the private bucket's class, so neither `::1`
    /// nor a transition form of 127.0.0.1 is ever asked about as loopback. The
    /// NAT64 form of 127.0.0.1 is still probed as written, because an interface
    /// could carry that IPv6 address.
    #[test]
    fn single_forms_and_loopback_are_probed_as_they_route() {
        let probes = own_address_probes("[::ffff:192.0.2.45]:22".parse().unwrap());
        assert_eq!(probes, vec!["192.0.2.45:0".parse().unwrap()]);

        for loopback in ["127.0.0.1:22", "[::1]:22", "[::ffff:127.0.0.1]:22"] {
            assert!(
                own_address_probes(loopback.parse().unwrap()).is_empty(),
                "{loopback}"
            );
        }

        let probes = own_address_probes("[64:ff9b::7f00:1]:22".parse().unwrap());
        assert_eq!(probes, vec!["[64:ff9b::7f00:1]:0".parse().unwrap()]);
    }

    /// The same rule against this host's real address, where one can be found.
    ///
    /// The tests above pin the probe addresses on every host. This one checks
    /// that [`is_the_proxys_own`] asks the kernel about each of them, using the
    /// address the kernel picks as the source towards a documentation address.
    /// The three transition forms of that address are on no interface, so only
    /// their routed form can make the answer true.
    ///
    /// A host with no route to 192.0.2.1, or no non-loopback IPv4 source
    /// address, has nothing to build the forms from. Such a host skips with a
    /// line on stderr. When `CI` is set the skip is a failure instead, because
    /// every CI runner has an IPv4 route and a skip there means the discovery
    /// broke.
    #[test]
    fn transition_forms_of_this_hosts_own_address_are_refused() {
        let skip = |why: &str| {
            assert!(
                std::env::var_os("CI").is_none(),
                "{why}; a CI runner has an IPv4 route, so the transition forms would go \
                 untested"
            );
            eprintln!("skipping: {why}");
        };

        let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind a probe socket");
        if socket.connect("192.0.2.1:9").is_err() {
            skip("this host has no route towards 192.0.2.1 to discover its own IPv4 address");
            return;
        }

        let own = match socket.local_addr().expect("a local address").ip() {
            std::net::IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => v4,
            _ => {
                skip(
                    "this host has no non-loopback IPv4 address to build the transition forms from",
                );
                return;
            }
        };
        let octets = own.octets();

        // 64:ff9b::/96: the address is in the last 32 bits.
        let mut nat64 = [0u8; 16];
        nat64[..4].copy_from_slice(&[0x00, 0x64, 0xff, 0x9b]);
        nat64[12..].copy_from_slice(&octets);

        // 2002::/16: the address is at bits 16-47.
        let mut six_to_four = [0u8; 16];
        six_to_four[..2].copy_from_slice(&[0x20, 0x02]);
        six_to_four[2..6].copy_from_slice(&octets);

        // 2001::/32: the client's address is the last 32 bits, every bit
        // inverted.
        let mut teredo = [0u8; 16];
        teredo[..4].copy_from_slice(&[0x20, 0x01, 0x00, 0x00]);
        for (byte, own_byte) in teredo[12..].iter_mut().zip(octets) {
            *byte = own_byte ^ 0xff;
        }

        for (form, name) in [
            (std::net::IpAddr::V6(nat64.into()), "NAT64"),
            (std::net::IpAddr::V6(six_to_four.into()), "6to4"),
            (std::net::IpAddr::V6(teredo.into()), "Teredo"),
        ] {
            let address = std::net::SocketAddr::new(form, 0);
            assert!(
                is_the_proxys_own(address),
                "the {name} form {address} carries this host's own {own} and must be \
                 recognised as one of the proxy's own"
            );
        }
    }
    /// The time a tunnel line reports for a step is the time the step took, and
    /// nothing before or after it.
    #[tokio::test(start_paused = true)]
    async fn a_timed_step_reads_the_time_the_step_took() {
        tokio::time::advance(Duration::from_millis(7)).await;

        let (output, took) = timed(async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            "done"
        })
        .await;
        tokio::time::advance(Duration::from_millis(5)).await;

        assert_eq!(output, "done");
        assert_eq!(took, Duration::from_millis(30));
    }

    /// The deadline `budget` from now, with the budget a timeout reports.
    fn limit(budget: Duration) -> Option<(tokio::time::Instant, Duration)> {
        Some((tokio::time::Instant::now() + budget, budget))
    }

    /// A resolver that never answers costs the request its budget and no more,
    /// and is reported as the timeout it is rather than as an ordinary lookup
    /// failure: the two carry different statuses.
    ///
    /// On a paused clock, so the budget is the shipped default and both sides
    /// of the deadline are pinned exactly: nothing a millisecond short of it,
    /// the timeout on the millisecond itself.
    #[tokio::test(start_paused = true)]
    async fn a_resolver_that_never_answers_costs_only_the_budget() {
        let budget = Duration::from_secs(crate::config::DEFAULT_CONNECT_TIMEOUT);

        let mut waiting = Box::pin(until_deadline(std::future::pending(), limit(budget)));

        tokio::time::advance(budget - Duration::from_millis(1)).await;
        assert!(
            poll_once(waiting.as_mut()).is_none(),
            "the budget expired early"
        );

        tokio::time::advance(Duration::from_millis(1)).await;
        let failure = waiting
            .await
            .expect_err("a lookup that never answers must not succeed");

        assert_matches!(failure, ResolveFailure::TimedOut(_), "{failure}");
        assert_eq!(failure.proxy_error(), ProxyError::DnsTimeout);
        assert_eq!(
            failure.proxy_error().recommended_status(),
            Status::GATEWAY_TIMEOUT
        );
    }

    /// A clock that jumps clean past the budget reports the timeout, not the
    /// resolver's own failure.
    ///
    /// The resumed-VM shape: `Instant::now()` is hours past where the deadline
    /// was armed and every timer in the process fires in one instant. The
    /// budget must still resolve to `TimedOut`, the 504 with
    /// `error=dns_timeout`, rather than wrap, panic, or leave the request
    /// parked on a deadline the clock has already gone by. `TimedOut` carries
    /// the *budget*, not the time actually waited, so the answer the client
    /// gets says the same thing either way.
    #[tokio::test(start_paused = true)]
    async fn a_clock_that_jumps_hours_still_reports_the_budget() {
        let budget = Duration::from_secs(10);
        let mut waiting = Box::pin(until_deadline(std::future::pending(), limit(budget)));
        assert!(poll_once(waiting.as_mut()).is_none());

        tokio::time::advance(Duration::from_secs(3 * 60 * 60)).await;

        let failure = waiting.await.expect_err("the budget is long gone");
        assert_matches!(failure, ResolveFailure::TimedOut(reported) if reported == budget,
            "{failure}");
        assert_eq!(failure.proxy_error(), ProxyError::DnsTimeout);
    }

    /// Every host shape, spelled once for each route, gets one answer from both
    /// parsers: the same host to dial, or a refusal from each.
    ///
    /// The routes spell a host differently, so each row gives both spellings:
    /// a CONNECT authority writes an IPv6 literal in brackets (RFC 3986
    /// §3.2.2), and the template writes it bare with its colons escaped
    /// (RFC 9298 §3). The template's percent-encoding is its own syntax, so
    /// the template spelling of a shape is the CONNECT host encoded once.
    #[test]
    fn both_routes_give_one_host_shape_one_answer() {
        // (shape, CONNECT authority, template `target_host`, host dialled)
        let shapes: [(&str, &str, &str, Option<&str>); 22] = [
            (
                "reg-name",
                "example.com:443",
                "example.com",
                Some("example.com"),
            ),
            (
                "reg-name with a trailing dot",
                "example.com.:443",
                "example.com.",
                Some("example.com."),
            ),
            (
                "reg-name with every sub-delim",
                "a!$&'()*+,;=b:443",
                "a%21%24%26%27%28%29%2A%2B%2C%3B%3Db",
                Some("a!$&'()*+,;=b"),
            ),
            (
                "IPv4 literal",
                "192.0.2.1:443",
                "192.0.2.1",
                Some("192.0.2.1"),
            ),
            (
                "IPv6 literal",
                "[2001:db8::1]:443",
                "2001%3Adb8%3A%3A1",
                Some("2001:db8::1"),
            ),
            (
                "IPv6 literal ending in IPv4",
                "[::ffff:192.0.2.1]:443",
                "%3A%3Affff%3A192.0.2.1",
                Some("::ffff:192.0.2.1"),
            ),
            (
                "IPv6 literal, bracketed in the template too",
                "[2001:db8::1]:443",
                "%5B2001%3Adb8%3A%3A1%5D",
                Some("2001:db8::1"),
            ),
            (
                "bracketed reg-name",
                "[example.com]:443",
                "%5Bexample.com%5D",
                None,
            ),
            (
                "bracketed IPv4 literal",
                "[192.0.2.1]:443",
                "%5B192.0.2.1%5D",
                None,
            ),
            (
                "IPvFuture",
                "[v1.fe80::a+en1]:443",
                "%5Bv1.fe80%3A%3Aa%2Ben1%5D",
                None,
            ),
            (
                "zone index, raw",
                "[fe80::1%eth0]:443",
                "fe80%3A%3A1%25eth0",
                None,
            ),
            (
                "zone index, raw, bracketed",
                "[fe80::1%eth0]:443",
                "%5Bfe80%3A%3A1%25eth0%5D",
                None,
            ),
            (
                "zone index, percent-encoded (RFC 6874)",
                "[fe80::1%25eth0]:443",
                "fe80%3A%3A1%2525eth0",
                None,
            ),
            (
                "a colon that is not an IPv6 literal",
                "[example.com:80]:443",
                "example.com%3A80",
                None,
            ),
            ("empty", ":443", "", None),
            ("empty IP literal", "[]:443", "%5B%5D", None),
            (
                "a percent-encoded octet in the host",
                "ex%61mple.com:443",
                "ex%2561mple.com",
                None,
            ),
            (
                "non-ASCII",
                "b\u{fc}cher.example:443",
                "b%C3%BCcher.example",
                None,
            ),
            ("a space", "a b:443", "a%20b", None),
            ("a control character", "a\u{1}b:443", "a%01b", None),
            ("a slash", "a/b:443", "a%2Fb", None),
            (
                "a stray bracket",
                "example.com]:443",
                "example.com%5D",
                None,
            ),
        ];

        let mut disagreements = Vec::new();
        for (shape, authority, target_host, expected) in shapes {
            let connect = tcp::split_authority(authority)
                .ok()
                .map(|(host, port)| (host, port == 443));
            let template = udp::parse_target(
                &format!("{}{target_host}/443/", udp::WELL_KNOWN_PREFIX),
                None,
            )
            .ok()
            .map(|(host, port)| (host, port == 443));
            let expected = expected.map(|host| (host.to_owned(), true));
            if connect != expected || template != expected {
                disagreements.push(format!(
                    "{shape}: expected {expected:?}, CONNECT {authority:?} gave {connect:?}, \
                     template {target_host:?} gave {template:?}"
                ));
            }
        }
        assert!(
            disagreements.is_empty(),
            "{} shapes answered wrongly:\n{}",
            disagreements.len(),
            disagreements.join("\n")
        );
    }

    /// The value `future` has *without waiting*, or `None` if it would wait.
    ///
    /// The negative half of every deadline in this module and in
    /// [`super::tcp`]: a timer that has not fired is a future that is still
    /// pending, and one poll is the whole question. Polled through a bare waker
    /// rather than awaited, so a `None` is the future's own answer and not a
    /// race with the runtime: `tokio::time` advances only where a test says
    /// so, and nothing in either module wakes anything but a timer.
    pub(crate) fn poll_once<F: std::future::Future>(
        mut future: std::pin::Pin<&mut F>,
    ) -> Option<F::Output> {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(value) => Some(value),
            std::task::Poll::Pending => None,
        }
    }

    /// A lookup that answers is passed straight through, budget or no budget.
    #[tokio::test]
    async fn a_lookup_that_answers_is_passed_through() {
        let addresses = vec!["192.0.2.1:443".parse().expect("address")];

        for budget in [None, Some(Duration::from_secs(10))] {
            let resolved = until_deadline(
                std::future::ready(Ok(addresses.clone())),
                budget.and_then(limit),
            )
            .await
            .expect("a lookup that answers must succeed");
            assert_eq!(resolved, addresses);
        }

        // And a resolver that says no keeps saying no, as `dns_error`.
        let failure = until_deadline(
            std::future::ready(Err(std::io::Error::from(std::io::ErrorKind::NotFound))),
            limit(Duration::from_secs(10)),
        )
        .await
        .expect_err("a lookup that fails must fail");
        assert_eq!(failure.proxy_error(), ProxyError::DnsError);
    }

    /// The address family preference end to end below the stream: which
    /// lookups ran, when, and which addresses were dialled when (D123).
    ///
    /// A stand-in takes the place of `getaddrinfo` behind the real lookup
    /// budget, and answers each family after a delay on tokio's paused
    /// clock. The tunnels' own composition is used: [`judge`], then
    /// [`first_reachable_then`] with [`later_addresses`], as
    /// [`super::tcp`] calls them.
    pub(crate) mod family {
        use super::*;
        use crate::net::{ConnectionResolver, Family, ResolverBudget, StandIn};
        use std::cell::RefCell;
        use std::net::{IpAddr, SocketAddr};
        use std::rc::Rc;
        use tokio::time::Instant;

        /// What the stand-in answers for one family, and after how long.
        #[derive(Clone, Debug)]
        pub(crate) enum Answer {
            Addresses(Duration, Vec<&'static str>),
            /// The name exists and has no address of this family.
            NoData(Duration),
            /// A failure that is not "no data", such as NXDOMAIN.
            Fails(Duration, &'static str),
            Never,
        }

        /// What a dialled address does.
        #[derive(Clone, Copy, Debug)]
        pub(crate) enum Dial {
            Connects(Duration),
            Refuses(Duration),
            Silent,
        }

        pub(crate) fn ms(millis: u64) -> Duration {
            Duration::from_millis(millis)
        }

        pub(crate) fn at(address: &str) -> SocketAddr {
            SocketAddr::new(address.parse().expect("address"), 443)
        }

        type Asked = Arc<Mutex<Vec<(Option<Family>, Duration)>>>;

        /// One connection's resolver with a stand-in behind it.
        pub(crate) struct Lab {
            pub(crate) budget: ResolverBudget,
            pub(crate) resolver: ConnectionResolver,
            asked: Asked,
            start: Instant,
            dialled: Rc<RefCell<Vec<(SocketAddr, Duration)>>>,
        }

        impl Lab {
            /// A stand-in answering A with `v4`, AAAA with `v6` and an
            /// unhinted lookup with `both`.
            pub(crate) fn new(v4: Answer, v6: Answer, both: Answer) -> Self {
                let budget = ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS);
                let asked = Asked::default();
                let start = Instant::now();
                let record = asked.clone();
                let stand_in: StandIn = Arc::new(move |_host, family| {
                    record.lock().unwrap().push((family, start.elapsed()));
                    let answer = match family {
                        Some(Family::Ipv4) => v4.clone(),
                        Some(Family::Ipv6) => v6.clone(),
                        None => both.clone(),
                    };
                    Box::pin(async move {
                        match answer {
                            Answer::Addresses(after, addresses) => {
                                tokio::time::sleep(after).await;
                                Ok(addresses
                                    .iter()
                                    .map(|address| address.parse::<IpAddr>().unwrap())
                                    .collect())
                            }
                            // An answer with no address is what the lookup
                            // turns into "no data".
                            Answer::NoData(after) => {
                                tokio::time::sleep(after).await;
                                Ok(Vec::new())
                            }
                            Answer::Fails(after, text) => {
                                tokio::time::sleep(after).await;
                                Err(std::io::Error::other(text))
                            }
                            Answer::Never => std::future::pending().await,
                        }
                    })
                });
                Self {
                    resolver: budget.per_connection_with(stand_in),
                    budget,
                    asked,
                    start,
                    dialled: Rc::default(),
                }
            }

            /// The lookups the stand-in was asked for, with when.
            pub(crate) fn asked(&self) -> Vec<(Option<Family>, Duration)> {
                self.asked.lock().unwrap().clone()
            }

            /// The addresses dialled, with when.
            pub(crate) fn dialled(&self) -> Vec<(SocketAddr, Duration)> {
                self.dialled.borrow().clone()
            }

            pub(crate) fn now(&self) -> Duration {
                self.start.elapsed()
            }

            /// A dial step that records each address and then does what
            /// `plan` says for it. It yields the address it reached.
            pub(crate) fn dialler(
                &self,
                plan: impl Fn(SocketAddr) -> Dial,
            ) -> impl Fn(
                SocketAddr,
            ) -> std::pin::Pin<
                Box<dyn Future<Output = std::io::Result<SocketAddr>>>,
            > {
                let dialled = self.dialled.clone();
                let start = self.start;
                move |address| {
                    dialled.borrow_mut().push((address, start.elapsed()));
                    let dial = plan(address);
                    Box::pin(async move {
                        match dial {
                            Dial::Connects(after) => {
                                tokio::time::sleep(after).await;
                                Ok(address)
                            }
                            Dial::Refuses(after) => {
                                tokio::time::sleep(after).await;
                                Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
                            }
                            Dial::Silent => std::future::pending().await,
                        }
                    })
                }
            }

            /// [`judge`] for `example.test:443`, with a policy that allows
            /// every address `allowed` says it does.
            pub(crate) async fn judge(
                &self,
                preference: IpFamilyPreference,
                budget: Option<Duration>,
                allowed: fn(&SocketAddr) -> bool,
            ) -> Judged {
                judge(
                    "example.test",
                    443,
                    &self.resolver,
                    budget,
                    preference,
                    |addresses| addresses.iter().copied().filter(allowed).collect(),
                )
                .await
            }

            /// A TCP tunnel's setup: [`judge`] with every address allowed,
            /// then the walk with the other family behind it.
            pub(crate) async fn tcp(
                &self,
                preference: IpFamilyPreference,
                budget: Option<Duration>,
                plan: impl Fn(SocketAddr) -> Dial,
            ) -> (Walk<SocketAddr>, Duration) {
                let judged = self.judge(preference, budget, |_| true).await;
                let Judged::Admitted(Admitted {
                    addresses,
                    mut later,
                    resolve,
                    ..
                }) = judged
                else {
                    panic!("the target was not admitted: {judged:?}");
                };
                let later = later
                    .as_mut()
                    .map(|other| later_addresses(other, &self.resolver, <[SocketAddr]>::to_vec));
                let walk =
                    first_reachable_then(addresses, later, budget, self.dialler(&plan), "test")
                        .await;
                (walk, resolve)
            }
        }

        /// The address a walk reached, or a panic naming its failure.
        fn reached(walk: Walk<SocketAddr>) -> SocketAddr {
            match walk.result {
                Ok(address) => address,
                Err(failure) => panic!("nothing was reached: {}", failure.error),
            }
        }

        fn v4() -> Option<Family> {
            Some(Family::Ipv4)
        }

        fn v6() -> Option<Family> {
            Some(Family::Ipv6)
        }

        /// Row 1: a name with both families whose preferred address connects
        /// waits for the preferred answer and not for the other one.
        #[tokio::test(start_paused = true)]
        async fn both_families_the_preferred_one_connects_without_the_other_answer() {
            let lab = Lab::new(
                Answer::Addresses(ms(10), vec!["192.0.2.1"]),
                Answer::Addresses(ms(500), vec!["2001:db8::1"]),
                Answer::Never,
            );

            let (walk, resolve) = lab
                .tcp(IpFamilyPreference::Ipv4, Some(ms(10_000)), |_| {
                    Dial::Connects(ms(5))
                })
                .await;

            assert_eq!(reached(walk), at("192.0.2.1"));
            assert_eq!(lab.asked(), vec![(v4(), ms(0)), (v6(), ms(0))]);
            assert_eq!(lab.dialled(), vec![(at("192.0.2.1"), ms(10))]);
            assert_eq!(resolve, ms(10));
            assert_eq!(lab.now(), ms(15), "the tunnel waited for the AAAA answer");
        }

        /// Row 2: a name with the preferred family only waits for that
        /// family's answer, however long the other takes to say it has none.
        #[tokio::test(start_paused = true)]
        async fn the_preferred_family_only_waits_for_the_preferred_answer() {
            let lab = Lab::new(
                Answer::NoData(ms(300)),
                Answer::Addresses(ms(10), vec!["2001:db8::1"]),
                Answer::Never,
            );

            let (walk, resolve) = lab
                .tcp(IpFamilyPreference::Ipv6, Some(ms(10_000)), |_| {
                    Dial::Connects(ms(0))
                })
                .await;

            assert_eq!(reached(walk), at("2001:db8::1"));
            assert_eq!(lab.asked(), vec![(v6(), ms(0)), (v4(), ms(0))]);
            assert_eq!(lab.dialled(), vec![(at("2001:db8::1"), ms(10))]);
            assert_eq!(resolve, ms(10));
        }

        /// Row 3: a name with the other family only is dialled on that
        /// family once it answers. Both lookups ran at once, so the wait is
        /// the longer of the two and not their sum.
        #[tokio::test(start_paused = true)]
        async fn the_other_family_only_is_dialled_once_it_answers() {
            let lab = Lab::new(
                Answer::NoData(ms(20)),
                Answer::Addresses(ms(50), vec!["2001:db8::1"]),
                Answer::Never,
            );

            let (walk, resolve) = lab
                .tcp(IpFamilyPreference::Ipv4, Some(ms(10_000)), |_| {
                    Dial::Connects(ms(0))
                })
                .await;

            assert_eq!(reached(walk), at("2001:db8::1"));
            assert_eq!(lab.asked(), vec![(v4(), ms(0)), (v6(), ms(0))]);
            assert_eq!(lab.dialled(), vec![(at("2001:db8::1"), ms(50))]);
            assert_eq!(resolve, ms(50));
        }

        /// Added row: with the shared allowance used up the other family's
        /// lookup is not started beside the preferred one, and a name with
        /// only the other family still resolves, one lookup later.
        #[tokio::test(start_paused = true)]
        async fn without_a_spare_slot_a_name_with_only_the_other_family_still_resolves() {
            let lab = Lab::new(
                Answer::NoData(ms(20)),
                Answer::Addresses(ms(30), vec!["2001:db8::1"]),
                Answer::Never,
            );
            let _held = lab.budget.hold_shared();

            let (walk, resolve) = lab
                .tcp(IpFamilyPreference::Ipv4, Some(ms(10_000)), |_| {
                    Dial::Connects(ms(0))
                })
                .await;

            assert_eq!(reached(walk), at("2001:db8::1"));
            assert_eq!(lab.asked(), vec![(v4(), ms(0)), (v6(), ms(20))]);
            assert_eq!(lab.dialled(), vec![(at("2001:db8::1"), ms(50))]);
            assert_eq!(resolve, ms(50));
        }

        /// Row 4: when every preferred address fails, the walk goes on to the
        /// other family inside the same budget, and every attempt gives up
        /// when it would have with both families in one list.
        ///
        /// The reference is [`first_reachable`] over the four addresses known
        /// from the start, on the same paused clock.
        #[tokio::test(start_paused = true)]
        async fn every_preferred_address_failing_keeps_the_shares_of_one_list() {
            let budget = Some(ms(12_000));
            let reference = Lab::new(Answer::Never, Answer::Never, Answer::Never);
            let failure = first_reachable(
                &[
                    at("192.0.2.1"),
                    at("192.0.2.2"),
                    at("2001:db8::1"),
                    at("2001:db8::2"),
                ],
                budget,
                reference.dialler(|_| Dial::Silent),
                "test",
            )
            .await
            .expect_err("nothing answers");
            assert_eq!(failure.next_hop, Some(at("2001:db8::2")));

            let lab = Lab::new(
                Answer::Addresses(ms(0), vec!["192.0.2.1", "192.0.2.2"]),
                Answer::Addresses(ms(1_000), vec!["2001:db8::1", "2001:db8::2"]),
                Answer::Never,
            );
            let (walk, resolve) = lab
                .tcp(IpFamilyPreference::Ipv4, budget, |_| Dial::Silent)
                .await;

            assert_eq!(lab.dialled(), reference.dialled());
            assert_eq!(
                lab.dialled()
                    .iter()
                    .map(|(_, when)| *when)
                    .collect::<Vec<_>>(),
                vec![ms(0), ms(3_000), ms(6_000), ms(9_000)]
            );
            let failure = walk.result.expect_err("nothing answers");
            assert_eq!(failure.error.kind(), std::io::ErrorKind::TimedOut);
            assert_eq!(failure.next_hop, Some(at("2001:db8::2")));
            assert_eq!(lab.now(), ms(12_000));
            assert_eq!((resolve, walk.waited), (ms(0), ms(0)));
        }

        /// Row 4 without a spare slot: the other family's lookup is started
        /// beside the last preferred address, on a slot taken the normal
        /// way, and that attempt's share becomes what the rule gives with the
        /// addresses it brings.
        ///
        /// The first address had a share of half the budget, because the
        /// other family was not known yet. From the second address on, each
        /// share is the one-list rule's: six seconds left over three
        /// addresses is two, raised to the three-second floor.
        #[tokio::test(start_paused = true)]
        async fn a_lookup_never_started_is_asked_beside_the_last_preferred_address() {
            let lab = Lab::new(
                Answer::Addresses(ms(0), vec!["192.0.2.1", "192.0.2.2"]),
                Answer::Addresses(ms(1_000), vec!["2001:db8::1", "2001:db8::2"]),
                Answer::Never,
            );
            let _held = lab.budget.hold_shared();

            let (walk, _) = lab
                .tcp(IpFamilyPreference::Ipv4, Some(ms(12_000)), |_| Dial::Silent)
                .await;

            assert_eq!(lab.asked(), vec![(v4(), ms(0)), (v6(), ms(6_000))]);
            assert_eq!(
                lab.dialled(),
                vec![
                    (at("192.0.2.1"), ms(0)),
                    (at("192.0.2.2"), ms(6_000)),
                    (at("2001:db8::1"), ms(9_000)),
                ]
            );
            let failure = walk.result.expect_err("nothing answers");
            assert_eq!(failure.next_hop, Some(at("2001:db8::1")));
            assert_eq!(lab.now(), ms(12_000));
        }

        /// Row 4 when the other family gives nothing: a lookup that fails,
        /// or one that runs out of the budget, adds no address, and the
        /// tunnel reports its last connect failure. The time spent waiting
        /// for that lookup alone is lookup time.
        #[tokio::test(start_paused = true)]
        async fn a_second_lookup_that_gives_nothing_leaves_the_last_connect_failure() {
            for (v6_answer, waited) in [
                (Answer::Fails(ms(2_000), "Name does not resolve"), ms(1_900)),
                (Answer::Never, ms(9_900)),
            ] {
                let lab = Lab::new(
                    Answer::Addresses(ms(0), vec!["192.0.2.1"]),
                    v6_answer.clone(),
                    Answer::Never,
                );

                let (walk, _) = lab
                    .tcp(IpFamilyPreference::Ipv4, Some(ms(10_000)), |_| {
                        Dial::Refuses(ms(100))
                    })
                    .await;

                let failure = walk.result.expect_err("the only address refuses");
                assert_eq!(
                    failure.error.kind(),
                    std::io::ErrorKind::ConnectionRefused,
                    "{v6_answer:?}"
                );
                assert_eq!(failure.next_hop, Some(at("192.0.2.1")), "{v6_answer:?}");
                assert_eq!(walk.waited, waited, "{v6_answer:?}");
                assert_eq!(lab.dialled(), vec![(at("192.0.2.1"), ms(0))]);
            }
        }

        /// Row 6: an IP literal of either family asks no resolver under any
        /// preference, and has no other family behind it.
        #[tokio::test(start_paused = true)]
        async fn an_ip_literal_asks_no_resolver_whatever_its_family() {
            let lab = Lab::new(Answer::Never, Answer::Never, Answer::Never);
            for preference in [
                IpFamilyPreference::Ipv4,
                IpFamilyPreference::Ipv6,
                IpFamilyPreference::System,
            ] {
                for literal in ["192.0.2.1", "2001:db8::1"] {
                    let resolved =
                        resolve_within(literal, 443, &lab.resolver, Some(ms(10)), preference)
                            .await
                            .expect("a literal resolves");
                    assert_eq!(resolved.addresses, vec![at(literal)], "{preference:?}");
                    assert!(resolved.other.is_none(), "{preference:?} {literal}");
                }
            }
            assert!(lab.asked().is_empty(), "{:?}", lab.asked());
        }

        /// `system` is one lookup of both families, in the resolver's order.
        #[tokio::test(start_paused = true)]
        async fn the_system_preference_is_one_lookup_of_both_families() {
            let lab = Lab::new(
                Answer::Never,
                Answer::Never,
                Answer::Addresses(ms(10), vec!["2001:db8::1", "192.0.2.1"]),
            );

            let resolved = resolve_within(
                "example.test",
                443,
                &lab.resolver,
                Some(ms(10_000)),
                IpFamilyPreference::System,
            )
            .await
            .expect("the name resolves");

            assert_eq!(resolved.addresses, vec![at("2001:db8::1"), at("192.0.2.1")]);
            assert!(resolved.other.is_none());
            assert_eq!(lab.asked(), vec![(None, ms(0))]);
        }

        /// When both families fail, the failure reported is the first of the
        /// two that is not "no data", the preferred family's first, so the
        /// status is the one a single lookup of both families gives.
        #[tokio::test(start_paused = true)]
        async fn when_both_families_fail_the_first_failure_that_is_not_no_data_is_reported() {
            let budget = ms(5_000);
            for (v4_answer, v6_answer, expected) in [
                (
                    Answer::NoData(ms(10)),
                    Answer::Fails(ms(20), "the AAAA failure"),
                    Some("the AAAA failure"),
                ),
                (
                    Answer::Fails(ms(10), "the A failure"),
                    Answer::NoData(ms(20)),
                    Some("the A failure"),
                ),
                (
                    Answer::Fails(ms(10), "the A failure"),
                    Answer::Fails(ms(20), "the AAAA failure"),
                    Some("the A failure"),
                ),
                (Answer::NoData(ms(10)), Answer::NoData(ms(20)), Some("")),
                (Answer::Never, Answer::NoData(ms(20)), None),
                (Answer::NoData(ms(10)), Answer::Never, None),
            ] {
                let lab = Lab::new(v4_answer.clone(), v6_answer.clone(), Answer::Never);
                let failure = resolve_within(
                    "example.test",
                    443,
                    &lab.resolver,
                    Some(budget),
                    IpFamilyPreference::Ipv4,
                )
                .await
                .expect_err("neither family has an address");

                let case = format!("{v4_answer:?} then {v6_answer:?}: {failure}");
                match expected {
                    None => assert_matches!(failure, ResolveFailure::TimedOut(_), "{case}"),
                    // Both "no data": the preferred family's, which names
                    // the name and says it resolved to nothing.
                    Some("") => {
                        assert!(failure.is_no_data(), "{case}");
                        assert_eq!(failure.proxy_error(), ProxyError::DnsError, "{case}");
                    }
                    Some(text) => assert_eq!(failure.to_string(), text, "{case}"),
                }
            }
        }

        /// A preferred lookup that never answers within the budget does not
        /// refuse a name whose other family did answer.
        #[tokio::test(start_paused = true)]
        async fn a_preferred_lookup_that_times_out_is_served_by_the_other_family() {
            let lab = Lab::new(
                Answer::Never,
                Answer::Addresses(ms(10), vec!["2001:db8::1"]),
                Answer::Never,
            );

            let resolved = resolve_within(
                "example.test",
                443,
                &lab.resolver,
                Some(ms(5_000)),
                IpFamilyPreference::Ipv4,
            )
            .await
            .expect("the other family answered");

            assert_eq!(resolved.addresses, vec![at("2001:db8::1")]);
            assert_eq!(lab.now(), ms(5_000));
        }

        /// The destination policy sees both families before it refuses: an
        /// address of the other family that passes is admitted, and the
        /// blackhole check and the refusal are judged on both families
        /// together, as on one list.
        #[tokio::test(start_paused = true)]
        async fn the_blackhole_and_the_refusal_are_judged_on_both_families() {
            // Unspecified, loopback and RFC 1918 refused, the rest allowed.
            fn allowed(address: &SocketAddr) -> bool {
                let ip = address.ip();
                !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !matches!(ip, IpAddr::V4(v4) if v4.is_private())
            }

            let cases: [(Answer, Answer, &str, Vec<SocketAddr>); 5] = [
                (
                    Answer::Addresses(ms(10), vec!["0.0.0.0"]),
                    Answer::Addresses(ms(20), vec!["::"]),
                    "blackhole",
                    vec![at("0.0.0.0"), at("::")],
                ),
                (
                    Answer::Addresses(ms(10), vec!["0.0.0.0"]),
                    Answer::NoData(ms(20)),
                    "blackhole",
                    vec![at("0.0.0.0")],
                ),
                (
                    Answer::Addresses(ms(10), vec!["0.0.0.0"]),
                    Answer::Addresses(ms(20), vec!["::1"]),
                    "prohibited",
                    vec![at("0.0.0.0"), at("::1")],
                ),
                (
                    Answer::Addresses(ms(10), vec!["10.0.0.1"]),
                    Answer::Addresses(ms(20), vec!["2001:db8::1"]),
                    "admitted",
                    vec![at("2001:db8::1")],
                ),
                (
                    Answer::Addresses(ms(10), vec!["0.0.0.0", "192.0.2.1"]),
                    Answer::Addresses(ms(20), vec!["::"]),
                    "admitted",
                    vec![at("192.0.2.1")],
                ),
            ];

            for (v4_answer, v6_answer, expected, addresses) in cases {
                let lab = Lab::new(v4_answer.clone(), v6_answer.clone(), Answer::Never);
                let judged = lab
                    .judge(IpFamilyPreference::Ipv4, Some(ms(5_000)), allowed)
                    .await;

                let case = format!("{v4_answer:?} then {v6_answer:?}: {judged:?}");
                match (expected, judged) {
                    ("blackhole", Judged::Blackhole(seen))
                    | ("prohibited", Judged::Prohibited(seen)) => {
                        assert_eq!(seen, addresses, "{case}");
                    }
                    ("admitted", Judged::Admitted(admitted)) => {
                        assert_eq!(admitted.addresses, addresses, "{case}");
                    }
                    _ => panic!("expected {expected}, {case}"),
                }
            }
        }
    }
}
