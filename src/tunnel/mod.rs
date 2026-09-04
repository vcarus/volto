//! Request routing, the per-connection context, and the tunnel implementations.
//!
//! Two concerns of this module's own are a file each, and are re-exported from
//! here so that `tunnel::refuse` and `tunnel::Quota` stay the paths the rest of
//! the crate uses:
//!
//! * `status` — refusals and the RFC 9209 vocabulary they are written in.
//! * `quota` — the per-connection tunnel budget and the guards that spend it.

mod quota;
mod status;
pub mod tcp;
pub mod udp;

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::auth::Authenticator;
use crate::config::{Config, IpFamilyPreference};
use crate::h3api::{Fields, Method, Request, Stream};
use crate::policy::{self, Policy};
use crate::quic::AuthGate;

pub use quota::{Pending, Quota, Slot};
pub use status::ProxyError;
pub(crate) use status::{
    Responded, Unreachable, accept_then_close, refuse, refuse_because, refuse_unreachable,
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

/// Whether `text` is a port the way RFC 3986 §3.2.3 spells one.
///
/// That section: "The port subcomponent of authority is designated by an
/// optional port number in decimal following the host and delimited from it by a
/// single colon (":") character", with the grammar
///
/// ```text
/// port        = *DIGIT
/// ```
///
/// Asked by both parsers before `u16::from_str`, which is more generous than the
/// grammar: it takes a leading `+` or `-`, so `example.com:+443` was dialled as
/// 443 and `/.well-known/masque/udp/example.com/+443/` with it. Nothing was
/// bypassed, because `Policy::allows_port` judges the number that came out of
/// the parse and that is the number the socket is opened on. What it cost is
/// normalisation: one target had two spellings, the authority in the log and the
/// port on the wire disagreed, and RFC 9110 §9.3.6 asks a server to "reject a
/// CONNECT request that targets an empty or invalid port number".
///
/// The empty string is refused here as well, which is not what `*DIGIT` says on
/// its own. RFC 9298 §3 requires `target_port` to "represent an integer between
/// 1 and 65535 inclusive" and RFC 9110 §9.3.6 names an empty port beside an
/// invalid one; both callers already refused it by way of the parse that
/// follows, and saying so here keeps the two rules in one place.
///
/// Written once because it is one rule. Two copies of a spelling rule is how the
/// trailing-dot defect happened.
pub(crate) fn is_port(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
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
/// life: 512 packets at the defaults, against an unbounded number before this
/// existed. A client that wants another allowance pays for another handshake,
/// which is the price this server charges everywhere else.
///
/// Not a configuration key. `unanswered_packet_budget` already carries the
/// meaning "how much this proxy will send into silence", an operator who
/// changes it moves both halves together, and zero switches both off. A second
/// key would be a second thing to get wrong for a bound that is a multiple of
/// the first (D86 counts the configuration surface as a cost).
pub const CONNECTION_UNANSWERED_MULTIPLIER: u32 = 8;

/// The authentication failures one connection has run up, in buckets.
///
/// Which bucket a failure lands in is what makes clearing them on success
/// honest. `auth.users` is a list, so a peer can hold one valid credential and
/// guess at another user's password with it: with one counter cleared by any
/// success, it interleaves a good request between guesses and never reaches
/// `max_auth_failures`. One counter *per user-id guessed at* closes that, and
/// leaves the case the clearing exists for — one client, one credential, an app
/// that drops the header now and then — exactly as it was.
///
/// A single run charged to the first failure that named somebody was the earlier
/// answer and was not enough: the peer opens each cycle with a deliberate
/// failure as *itself*, which claims the run, and its success as itself then
/// clears the whole thing, guesses at everybody else included.
///
/// The cap is on the **total** across the buckets, not on any one of them. A
/// per-bucket cap would hand a guesser `max_auth_failures - 1` free guesses for
/// every configured user rather than that many for the whole connection.
///
/// One connection holds at most `|configured users| + 2` counters, and every key
/// is a copy of a name from the configuration file, so a peer cannot grow this
/// by inventing user-ids however many it invents.
#[derive(Default)]
pub struct AuthFailures {
    /// One counter per configured user-id a failure has named, created when
    /// that name is first guessed at.
    ///
    /// A success as that user clears its counter and nothing else. Keyed by a
    /// name that compared equal to a configured one, so the key's length comes
    /// from the configuration file rather than from the peer — a user-id too
    /// long to log is truncated by [`crate::auth::Denied::username`] (review
    /// H3) and therefore matches nothing here, which lands its guesses in
    /// `unconfigured` below.
    configured: std::collections::HashMap<String, u32>,
    /// Failures naming a user-id nobody has.
    ///
    /// One bucket for all of them, and no success ever clears it: succeeding as
    /// a user that does not exist is not a thing that can happen, so a success
    /// says nothing about these at all. This is where a scan lands.
    unconfigured: u32,
    /// Failures that named nobody.
    ///
    /// They carried no user-id this server could read — no credentials field at
    /// all, or one it could not parse — so they are the benign case: the app
    /// that dropped the header, not the peer that guessed. Any success clears
    /// this one, because any success is a client proving it is that client.
    ///
    /// It cannot be used to launder a guess: a guess names somebody and is
    /// charged to that name's bucket however many credential-less requests are
    /// sent around it.
    anonymous: u32,
}

impl AuthFailures {
    /// Failures across every bucket, which is what the cap is measured against.
    ///
    /// Saturating rather than wrapping: `max_auth_failures = 0` disables the cap
    /// and nothing then ever clears a bucket, so a connection left open long
    /// enough could otherwise overflow the sum. Saturated is the honest answer —
    /// a total that large is over any cap there could be.
    fn total(&self) -> u32 {
        self.configured
            .values()
            .copied()
            .chain([self.unconfigured, self.anonymous])
            .fold(0u32, u32::saturating_add)
    }
}

/// Everything a request handler needs from the connection it arrived on.
///
/// Built once per connection and held in an `Arc`, so sharing it with a request
/// costs one refcount bump rather than a copy of eighteen fields. Deliberately
/// not [`Clone`]: every member that could be copied is already behind an `Arc`
/// of its own, so a second whole `Context` would be a second view of the same
/// connection and nothing else.
///
/// The UDP-specific members are here rather than in [`udp`] because a connection
/// owns them regardless of which tunnel type ends up using them: both are
/// settled at the handshake, before the first request arrives.
pub struct Context {
    /// The QUIC connection this request arrived on.
    ///
    /// Most uses are a datagram being sent, and only the sending half: an
    /// inbound datagram is routed to the request stream it names by the HTTP/3
    /// connection, and reaches a session through the
    /// [`crate::h3api::DatagramReceiver`] that stream handed it (D79). The rest
    /// are connection-wide decisions a request can reach — closing after repeated
    /// authentication failures, and raising the stream allowance once one
    /// succeeds (`Context::mark_authenticated`) — which is why the handle is
    /// named for what it is rather than for what it mostly does.
    pub quic: quinn::Connection,
    /// Whether the peer advertised `SETTINGS_H3_DATAGRAM = 1`.
    ///
    /// RFC 9297 §2.1.1 forbids sending QUIC datagrams when this is false; such
    /// sessions fall back to DATAGRAM capsules on the request stream. Shared
    /// with the HTTP/3 connection rather than copied from it, for the reason
    /// [`crate::h3::connection`] gives.
    pub peer_datagrams: Arc<AtomicBool>,
    /// The credentials every request is checked against.
    pub auth: Arc<Authenticator>,
    /// Authentication failures seen on this connection so far, bucketed by who
    /// they were aimed at.
    ///
    /// Connection-scoped on purpose: no shared table across connections means no
    /// eviction policy and no memory that an attacker can grow. The lock is a
    /// `std::sync::Mutex`, held for a bucket lookup and a sum and never across
    /// an await; it is here rather than an atomic because the buckets and the
    /// total taken from them have to move together.
    pub auth_failures: Arc<Mutex<AuthFailures>>,
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
    /// Its transition is load-bearing as well as its value: the false-to-true
    /// edge is what raises this connection's bidirectional stream allowance to
    /// the configured one, exactly once — which is why it is an [`AuthGate`]
    /// and not the bare atomic it wraps. See `Context::mark_authenticated`.
    ///
    /// Owned by [`crate::quic`] rather than allocated here, because it is read
    /// from outside the connection as well: the accept loop needs to know which
    /// of the connections it is holding has never got past the door, so that a
    /// full server can take that slot back rather than refuse a client that has
    /// credentials.
    pub authenticated: AuthGate,
    /// The peer's address, for logs that a fail2ban rule can act on.
    pub remote: std::net::SocketAddr,
    /// Which destinations this proxy may reach.
    pub policy: Arc<Policy>,
    /// How many tunnels this connection may hold open at once.
    pub quota: Arc<Quota>,
    /// The bidirectional stream allowance this connection is granted once it
    /// has authenticated: `[limits] max_streams_bidi`, in full.
    ///
    /// It is not what the handshake advertised. A connection is accepted on the
    /// small allowance `quic::INITIAL_BIDI_STREAMS` describes and raised to this
    /// by `Context::mark_authenticated`, so the number is carried here for the
    /// one moment it is needed — snapshotted with the rest of this connection's
    /// `[limits]`, so a reload changes what connections accepted from then on
    /// are worth and leaves a running one alone.
    pub max_streams_bidi: u32,
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
    /// The longest one tunnel may make no progress before it is given up on.
    ///
    /// Both tunnel kinds spend it, which is why it is not named for either: a
    /// CONNECT-UDP session that goes this long without a packet in either
    /// direction is reclaimed, and once one direction of a TCP tunnel has ended
    /// cleanly, each write in the surviving direction has this long to complete
    /// (`tcp` module docs). Both come from `[limits] udp_session_timeout`,
    /// whose name is the CONNECT-UDP half alone for compatibility -- the field
    /// documents the other half.
    pub stall_budget: Duration,
    /// Budget for reaching a target, or `None` when it is disabled.
    ///
    /// Spent twice per request and separately — once on name resolution, once on
    /// the whole list of addresses it resolved to — so the worst case a tunnel
    /// slot is held before any byte flows is twice this.
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
    /// Packets a UDP session may send before its target has answered.
    pub unanswered_packet_budget: u32,
    /// Packets *this connection* may still send towards targets that have never
    /// answered, across every session it opens.
    ///
    /// The per-session budget above is what RFC 9298 §7 asks for and it is
    /// recreated by opening a session, which is free: a client that spends one
    /// session's allowance closes the stream and opens another, and the
    /// mitigation becomes a constant factor rather than a bound. Stream turnover
    /// is not bounded by anything (`max_streams_bidi` bounds how many are open
    /// at once and quinn issues fresh credit as streams complete), so this is
    /// the counter an attacker cannot recreate: it is created with the
    /// connection and it is only ever spent.
    ///
    /// **Nothing credits it back.** A target that answers lifts its own
    /// session's cap, as it always has, and pays nothing back here. Crediting on
    /// an answer would let a client keep one consenting target on the side and
    /// buy back, packet for packet, the allowance it is spending on a silent
    /// one, which is the churn this exists to stop. The allowance is therefore
    /// a total for the life of the connection, and a client that wants another
    /// one pays for another handshake.
    ///
    /// Zero means uncapped, the same way `unanswered_packet_budget = 0` does:
    /// the operator switched the mitigation off.
    pub unanswered_connection_budget: AtomicU32,
    /// How many sessions this connection has lost to that total, and when that
    /// is worth saying out loud again.
    ///
    /// One line per closed session would be one line per stream a peer opens,
    /// which is the flood [`crate::logfmt::Sampler`] exists to stop.
    pub unanswered_closures: Arc<crate::logfmt::Sampler>,
    /// How many destinations this connection's policy has refused, and when
    /// that is worth saying out loud again.
    ///
    /// The warning is deliberately loud (D44 left it at WARN while demoting the
    /// blackhole line beside it, because a client probing loopback through the
    /// proxy is what SSRF looks like from here) and deliberately cheap for a
    /// peer to provoke: an IP literal takes no resolver slot, opens no socket,
    /// and holds its tunnel slot only for as long as the refusal takes. One
    /// warning per request would let a peer decide how much of this host's
    /// journal is left for anybody else. See [`crate::logfmt::Sampler`] for the
    /// schedule and for why silencing the repeats was not the answer.
    pub policy_refusals: Arc<crate::logfmt::Sampler>,
    /// The same, for requests refused because this connection is already
    /// holding every tunnel it may.
    ///
    /// Reaching the limit costs a peer `max_targets_per_conn` live tunnels,
    /// which is real; staying there costs it nothing at all, and every further
    /// request was a warning for as long as it cared to keep asking.
    pub limit_refusals: Arc<crate::logfmt::Sampler>,
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
        quic: quinn::Connection,
        peer_datagrams: Arc<AtomicBool>,
        resolver: &crate::net::ResolverBudget,
        tunnels: Arc<AtomicU64>,
        authenticated: AuthGate,
    ) -> Self {
        Self {
            remote: quic.remote_address(),
            auth_failures: Arc::new(Mutex::new(AuthFailures::default())),
            max_auth_failures: config.security.max_auth_failures,
            authenticated,
            quic,
            peer_datagrams,
            auth: Arc::new(Authenticator::new(&config.auth)),
            policy: Arc::new(Policy::new(&config.security)),
            quota: Arc::new(Quota::new(config.limits.max_targets_per_conn)),
            max_streams_bidi: config.limits.max_streams_bidi,
            tunnels,
            stall_budget: config.limits.udp_session_timeout(),
            connect_timeout: config.limits.connect_timeout(),
            resolver: resolver.per_connection(),
            ip_family_preference: config.limits.ip_family_preference,
            unanswered_packet_budget: config.security.unanswered_packet_budget,
            unanswered_connection_budget: AtomicU32::new(
                config
                    .security
                    .unanswered_packet_budget
                    .saturating_mul(CONNECTION_UNANSWERED_MULTIPLIER),
            ),
            policy_refusals: Arc::new(crate::logfmt::Sampler::new()),
            limit_refusals: Arc::new(crate::logfmt::Sampler::new()),
            unanswered_closures: Arc::new(crate::logfmt::Sampler::new()),
        }
    }

    /// Spends one packet of the connection's unanswered allowance, reporting
    /// whether there was one to spend.
    ///
    /// `false` is the end of the session that asked, not of the packet: a
    /// session that finds this empty is closed rather than muted. Muting it
    /// would leave a socket, a routing entry and a stream in place until the
    /// idle timeout for a client that has already shown what it is doing with
    /// them, and it would let the next session pay nothing to be created.
    ///
    /// Charged only where the per-session budget is charged, so a session whose
    /// target has answered spends nothing here, and neither does a session whose
    /// own budget is already spent: a muted session sends no packet, and this
    /// counts packets that were sent.
    ///
    /// `Relaxed` throughout: the counter is ordered against nothing but itself,
    /// and `fetch_update`'s compare-and-swap is what makes two sessions racing
    /// for the last packet give it to exactly one of them.
    pub(crate) fn charge_unanswered(&self) -> bool {
        if self.unanswered_packet_budget == 0 {
            return true;
        }

        self.unanswered_connection_budget
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
    }

    /// Records an authentication failure, reporting whether that was one too many.
    ///
    /// Counts across the whole connection, so opening more streams does not reset
    /// the budget, and the answer is about the *total* of every bucket. A request
    /// that succeeds *as `username`* clears one of them — see
    /// [`Self::mark_authenticated`] and [`AuthFailures`].
    ///
    /// `username` is the user-id the failing request claimed, or `None` when it
    /// carried none this server could read. Which of the three kinds of bucket
    /// it lands in is decided here, by asking the connection's own
    /// [`Authenticator`] whether that name is one the operator configured.
    pub(crate) fn record_auth_failure(&self, username: Option<&str>) -> bool {
        let mut failures = self.auth_failures();

        match username {
            // A name that exists: its own bucket, which only a success as that
            // user clears.
            Some(username) if self.auth.is_configured(username) => {
                let bucket = failures.configured.entry(username.to_owned()).or_default();
                *bucket = bucket.saturating_add(1);
            }
            // A name nobody has, so nobody can ever succeed as it.
            Some(_) => failures.unconfigured = failures.unconfigured.saturating_add(1),
            // Nobody named at all: the benign case, cleared by any success.
            None => failures.anonymous = failures.anonymous.saturating_add(1),
        }

        self.max_auth_failures > 0 && failures.total() >= self.max_auth_failures
    }

    /// Poisoning would mean a panic between the bucket writes above; every one
    /// of them is a plain counter with nothing to observe half-written, and the
    /// alternative is a panic on a path whose job is to answer 407.
    fn auth_failures(&self) -> MutexGuard<'_, AuthFailures> {
        self.auth_failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether QUIC datagrams may be sent to the peer right now.
    pub(crate) fn datagrams_allowed(&self) -> bool {
        self.peer_datagrams.load(Ordering::Relaxed)
    }

    /// Records that a request on this connection got past the credentials check,
    /// and clears the failures that success answers for.
    ///
    /// The counters are what make guessing cost a handshake every
    /// `max_auth_failures` attempts, and clearing them is what stops them adding
    /// up over the life of a connection that *is* authenticated: a client whose
    /// password was rotated, or an app that omits the header on some request,
    /// would otherwise spend the budget a failure at a time over hours and then
    /// lose every live tunnel to a cap meant for an attacker.
    ///
    /// Exactly two buckets are answered for: `username`'s own, and the one for
    /// failures that named nobody. Nothing else, because a guesser *can* arrive
    /// here — `auth.users` is a list, and one valid credential is enough to
    /// interleave a success between guesses at a second user's password. See
    /// [`AuthFailures`]. `None` means there was nothing to check — no users are
    /// configured — so there is no user's bucket to clear, and no failure can
    /// have been recorded either.
    ///
    /// # The stream allowance
    ///
    /// This is also where a connection stops being worth
    /// `quic::INITIAL_BIDI_STREAMS` request streams and becomes worth
    /// `[limits] max_streams_bidi` of them. A `swap` rather than a `store`
    /// because that raise must happen exactly once: every CONNECT on this
    /// connection carries credentials and so arrives here, and the request
    /// tasks run concurrently, so the flag going from false to true is the only
    /// thing that names one of them the first. Every later success takes the
    /// same path and grants nothing, which is what it means for the allowance
    /// to be a property of the connection rather than of the request.
    ///
    /// Done before the failure counters below rather than after, so this holds
    /// no lock of ours while it takes quinn's.
    pub(crate) fn mark_authenticated(&self, username: Option<&str>) {
        if self.authenticated.mark() {
            crate::quic::admit_configured_streams(&self.quic, self.max_streams_bidi);
        }

        let mut failures = self.auth_failures();

        // The request that forgot its header rather than the one that guessed:
        // any success answers for those.
        failures.anonymous = 0;

        if let Some(username) = username {
            failures.configured.remove(username);
        }
    }

    /// Whether any request on this connection has (D76).
    pub(crate) fn is_authenticated(&self) -> bool {
        self.authenticated.is_open()
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
    resolver: &crate::net::ConnectionResolver,
    budget: Option<Duration>,
    family: IpFamilyPreference,
) -> Result<Vec<std::net::SocketAddr>, ResolveFailure> {
    let mut addresses = within_budget(resolver.lookup(host, port), budget).await?;
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
///   public ones, so DNS rebinding onto loopback gains nothing. What survives
///   that filter is then asked one more question, [`is_the_proxys_own`]: an
///   address this host holds is refused whatever the policy says about its
///   address space, because reaching it means borrowing the proxy's own source
///   address against the proxy's own services (RFC 9298 §7).
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
/// The cost is one `bind(2)` per allowed address per tunnel opened, which is per
/// request and never per packet, and it is paid only by addresses the policy has
/// already let through, and the loopback test above it is free.
fn is_the_proxys_own(ip: std::net::IpAddr) -> bool {
    // Canonical first: `::ffff:127.0.0.1` is loopback wearing an IPv6 hat, and
    // the kernel would bind it happily.
    let ip = policy::canonical(ip);
    !ip.is_loopback() && crate::net::holds_address(ip)
}

pub(crate) async fn admit_target(
    host: &str,
    port: u16,
    ctx: &Context,
    stream: &mut Stream,
    accepted_fields: impl FnOnce() -> Fields,
) -> Option<Vec<std::net::SocketAddr>> {
    let stream_id = stream.id();

    if !ctx.policy.allows_port(port) {
        debug!(stream_id, host, port, "target port denied by policy");
        refuse_because(stream, ProxyError::HttpRequestDenied).await;
        return None;
    }

    let resolved = resolve_within(
        host,
        port,
        &ctx.resolver,
        ctx.connect_timeout,
        ctx.ip_family_preference,
    )
    .await;
    let addresses = match resolved {
        Ok(addresses) => addresses,
        Err(failure) => {
            let error = failure.proxy_error();
            debug!(stream_id, host, port, reason = %failure, "failed to resolve target");
            refuse_because(stream, error).await;
            return None;
        }
    };

    let mut allowed = ctx.policy.allowed_addresses(&addresses);
    let judged = allowed.len();
    allowed.retain(|address| !is_the_proxys_own(address.ip()));
    if allowed.len() < judged {
        debug!(
            stream_id,
            host,
            port,
            refused = judged - allowed.len(),
            "refused an address this host holds as one of the proxy's own"
        );
    }

    if allowed.is_empty() {
        if policy::is_dns_blackhole(&addresses) {
            info!(
                stream_id,
                host,
                port,
                addresses = %crate::logfmt::addresses(&addresses),
                "every address of the target is a DNS blackhole"
            );
            accept_then_close(stream, accepted_fields()).await;
            return None;
        }

        // Loud on a doubling schedule rather than every time: this is the
        // evidence an operator has that somebody is probing the private side of
        // the host, and one line per request would let the peer decide how much
        // of the journal is left to record it in. The first refusal warns as
        // immediately as it ever did, and `refusals` is what a scan announces
        // itself by. See [`Context::policy_refusals`].
        match ctx.policy_refusals.record() {
            Some(refusals) => warn!(
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
        return None;
    }

    Some(allowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h3api::{FieldValue, Status};

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
        for literal in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            assert!(
                !is_the_proxys_own(literal.parse().expect("an address")),
                "{literal} is the localhost class, not this one"
            );
        }

        // RFC 5737 TEST-NET-1: on no interface anywhere.
        assert!(!is_the_proxys_own("192.0.2.1".parse().expect("an address")));

        // And the class itself, on a host that has an address to show it with.
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind a probe socket");
        if socket.connect("192.0.2.1:9").is_ok() {
            let own = socket.local_addr().expect("a local address").ip();
            if !own.is_loopback() && !own.is_unspecified() {
                assert!(
                    is_the_proxys_own(own),
                    "{own} is an address this host holds"
                );
            }
        }
    }

    /// One QUIC connection over the loopback.
    ///
    /// [`Context`] holds one and there is no way to make one without a
    /// handshake; nothing the failure counters do looks at it. The certificate
    /// is generated here rather than taken from `tests/common`, which the lib
    /// target cannot reach.
    async fn loopback_connection() -> quinn::Connection {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate a self-signed certificate");
        let certificate = issued.cert.der().clone();
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(issued.signing_key.serialize_der().into());

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .expect("certificate and key");
        server_crypto.alpn_protocols = vec![b"h3".to_vec()];
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).expect("quic tls"),
        ));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).expect("trust the certificate");
        let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];

        let bind = "127.0.0.1:0".parse().expect("bind address");
        let server = quinn::Endpoint::server(server_config, bind).expect("server endpoint");
        let addr = server.local_addr().expect("local address");
        let mut client = quinn::Endpoint::client(bind).expect("client endpoint");
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).expect("quic tls"),
        )));

        // Both sides have to be driven for either handshake to finish.
        let (connection, _accepted) = tokio::join!(
            client.connect(addr, "localhost").expect("start connecting"),
            async {
                server
                    .accept()
                    .await
                    .expect("an incoming connection")
                    .await
                    .expect("the server side of the handshake")
            }
        );

        connection.expect("the client side of the handshake")
    }

    /// A context whose authenticator knows exactly one user.
    ///
    /// Parsed rather than assembled so the `[auth]` section is the one the
    /// server itself would read. The certificate paths are never opened —
    /// nothing here binds a listener — and the cap is set well above what the
    /// test records, so every failure below answers "not yet" and the buckets
    /// are the only subject.
    async fn one_user_context() -> Context {
        let config: Config = toml::from_str(
            r#"
                [server]
                listen = "127.0.0.1:0"
                cert = "unused.pem"
                key = "unused.pem"

                [security]
                max_auth_failures = 100

                [[auth.users]]
                username = "user1"
                password = "s3cret"
            "#,
        )
        .expect("the test configuration must parse");

        Context::new(
            &config,
            loopback_connection().await,
            Arc::new(AtomicBool::new(false)),
            &crate::net::ResolverBudget::new(),
            Arc::new(AtomicU64::new(0)),
            AuthGate::closed(),
        )
    }

    /// A context whose `[security]` says how much silence this connection is
    /// worth, and nothing else worth reading.
    async fn context_with_budget(budget: u32) -> Context {
        let config: Config = toml::from_str(&format!(
            r#"
                [server]
                listen = "127.0.0.1:0"
                cert = "unused.pem"
                key = "unused.pem"

                [security]
                unanswered_packet_budget = {budget}
            "#
        ))
        .expect("the test configuration must parse");

        Context::new(
            &config,
            loopback_connection().await,
            Arc::new(AtomicBool::new(false)),
            &crate::net::ResolverBudget::new(),
            Arc::new(AtomicU64::new(0)),
            AuthGate::closed(),
        )
    }

    /// The connection's allowance is spent once and never given back, and the
    /// operator's off switch turns it off too.
    ///
    /// Charged one packet at a time because that is how a session spends it, and
    /// the number that has to be exact is the last one: the packet after the
    /// total is the one whose session is closed.
    #[tokio::test]
    async fn the_connections_unanswered_total_is_spent_exactly_once() {
        const BUDGET: u32 = 3;

        let context = context_with_budget(BUDGET).await;
        for packet in 0..BUDGET * CONNECTION_UNANSWERED_MULTIPLIER {
            assert!(
                context.charge_unanswered(),
                "packet {packet} is inside the connection's total"
            );
        }

        assert!(
            !context.charge_unanswered(),
            "the packet after the total must find nothing left"
        );
        assert!(
            !context.charge_unanswered(),
            "and nothing gives it back afterwards"
        );

        // Zero is the operator switching the mitigation off, which has to switch
        // off both halves of it: a session that is never capped must never be
        // closed for having reached a cap.
        let uncapped = context_with_budget(0).await;
        for _ in 0..1000 {
            assert!(uncapped.charge_unanswered());
        }
    }

    /// A guess at a user-id nobody has must not become a key.
    ///
    /// The buckets are what make clearing failures on success honest, and this
    /// is the half of them whose input a peer chooses: a failure naming a
    /// configured user gets that user's own counter, and every other name is
    /// charged to the one counter no success clears. One connection therefore
    /// holds at most `|configured users| + 2` counters however many names are
    /// tried against it.
    #[tokio::test]
    async fn a_guess_at_a_name_nobody_has_never_grows_the_buckets() {
        let context = one_user_context().await;

        // Near misses included: what decides the bucket is the comparison
        // `Authenticator` makes, not how close the name looks.
        for guess in ["admin", "root", "user1 ", "USER1", ""] {
            assert!(
                !context.record_auth_failure(Some(guess)),
                "{guess:?} must not reach the cap"
            );
        }

        {
            let failures = context.auth_failures();
            assert_eq!(failures.unconfigured, 5);
            assert!(
                failures.configured.is_empty(),
                "a name nobody has became a key: {:?}",
                failures.configured.keys().collect::<Vec<_>>()
            );
            assert_eq!(failures.anonymous, 0);
        }

        // The other two buckets, so the assertions above can only hold for the
        // right reason: a configured name does get a counter of its own, and a
        // failure that named nobody at all gets the third.
        assert!(!context.record_auth_failure(Some("user1")));
        assert!(!context.record_auth_failure(None));

        let failures = context.auth_failures();
        assert_eq!(failures.configured.len(), 1);
        assert_eq!(failures.configured.get("user1").copied(), Some(1));
        assert_eq!(failures.unconfigured, 5);
        assert_eq!(failures.anonymous, 1);
    }

    /// A resolver that never answers costs the request its budget and no more,
    /// and is reported as the timeout it is rather than as an ordinary lookup
    /// failure — the two carry different statuses.
    ///
    /// On a paused clock, so the budget is the shipped default and both sides
    /// of the deadline are pinned exactly: nothing a millisecond short of it,
    /// the timeout on the millisecond itself.
    #[tokio::test(start_paused = true)]
    async fn a_resolver_that_never_answers_costs_only_the_budget() {
        let budget = Duration::from_secs(crate::config::DEFAULT_CONNECT_TIMEOUT);

        let mut waiting = Box::pin(within_budget(std::future::pending(), Some(budget)));

        tokio::time::advance(budget - Duration::from_millis(1)).await;
        assert!(
            poll_once(waiting.as_mut()).is_none(),
            "the budget expired early"
        );

        tokio::time::advance(Duration::from_millis(1)).await;
        let failure = waiting
            .await
            .expect_err("a lookup that never answers must not succeed");

        assert!(matches!(failure, ResolveFailure::TimedOut(_)), "{failure}");
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
    /// budget must still resolve to `TimedOut` — the 504 with
    /// `error=dns_timeout` — rather than wrap, panic, or leave the request
    /// parked on a deadline the clock has already gone by. `TimedOut` carries
    /// the *budget*, not the time actually waited, so the answer the client
    /// gets says the same thing either way.
    #[tokio::test(start_paused = true)]
    async fn a_clock_that_jumps_hours_still_reports_the_budget() {
        let budget = Duration::from_secs(10);
        let mut waiting = Box::pin(within_budget(std::future::pending(), Some(budget)));
        assert!(poll_once(waiting.as_mut()).is_none());

        tokio::time::advance(Duration::from_secs(3 * 60 * 60)).await;

        let failure = waiting.await.expect_err("the budget is long gone");
        assert!(
            matches!(failure, ResolveFailure::TimedOut(reported) if reported == budget),
            "{failure}"
        );
        assert_eq!(failure.proxy_error(), ProxyError::DnsTimeout);
    }

    /// The value `future` has *without waiting*, or `None` if it would wait.
    ///
    /// The negative half of every deadline in this module and in
    /// [`super::tcp`]: a timer that has not fired is a future that is still
    /// pending, and one poll is the whole question. Polled through a bare waker
    /// rather than awaited, so a `None` is the future's own answer and not a
    /// race with the runtime -- `tokio::time` advances only where a test says
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
}
