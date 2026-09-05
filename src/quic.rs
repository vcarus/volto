//! The QUIC endpoint: transport parameters, the accept loop and peer metadata.

use std::collections::BTreeMap;
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
use quinn::{IdleTimeout, VarInt};
use socket2::SockRef;
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::config::{Config, CongestionControl};
use crate::gate::{Expected, Gate, Names};
use crate::shutdown::{self, Shutdown, Trigger};
use crate::{conn, h3api, tls};

/// What the handshake revealed about a peer, for logging.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The peer's address. Behind a UDP relay this is the relay's address.
    pub remote: SocketAddr,
    /// The negotiated ALPN identifier, lossily decoded for display.
    pub alpn: Option<String>,
    /// The SNI the client sent.
    pub server_name: Option<String>,
}

/// Extracts loggable handshake metadata from an established connection.
pub fn peer_info(conn: &quinn::Connection) -> PeerInfo {
    let handshake = conn
        .handshake_data()
        .and_then(|data| data.downcast::<HandshakeData>().ok());

    let (alpn, server_name) = match handshake {
        Some(data) => (
            data.protocol
                .as_deref()
                .map(|p| String::from_utf8_lossy(p).into_owned()),
            data.server_name.clone(),
        ),
        None => (None, None),
    };

    PeerInfo {
        remote: conn.remote_address(),
        alpn,
        server_name,
    }
}

/// Builds the quinn server configuration: TLS identity plus transport parameters.
///
/// Shared by [`Server::bind`] and [`ReloadHandle::reload`] so the two cannot drift
/// — a reload that quietly dropped the stream limit or the keep-alive would be a
/// miserable bug to find, since everything would work until the connection went
/// idle behind a relay. It is also what makes every value below reloadable: a
/// `SIGHUP` rebuilds this and hands it to `Endpoint::set_server_config`, so the new
/// numbers apply to connections accepted from then on. Connections already open
/// keep the transport parameters they negotiated at handshake time — QUIC has no
/// way to renegotiate them mid-connection, so this is a property of the protocol
/// rather than a shortcut.
fn server_config(config: &Config) -> Result<quinn::ServerConfig> {
    let crypto = tls::server_crypto(config)?;
    let quic_crypto = QuicServerConfig::try_from(crypto)
        .context("rustls configuration is not usable for QUIC (TLS 1.3 is required)")?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(Arc::new(transport_config(&config.limits)?));

    Ok(server_config)
}

/// The QUIC transport parameters, from `[limits]` plus the memory bounds.
///
/// Split out from [`server_config`] so it can be asserted on without a
/// certificate: these are the numbers that decide both what a legitimate client
/// gets and what an attacker can make this process hold.
fn transport_config(limits: &crate::config::Limits) -> Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();

    // Deliberately *not* `limits.max_streams_bidi`: that is what an
    // authenticated connection gets, and it is granted in one step by
    // [`admit_configured_streams`] the first time a request on the connection
    // passes the credentials check. What goes into the transport parameters is
    // the small allowance a peer that has proved nothing starts on; see
    // [`INITIAL_BIDI_STREAMS`].
    transport.max_concurrent_bidi_streams(VarInt::from_u32(initial_bidi_streams(limits)));

    // Stated rather than inherited: HTTP/3 needs three of these and quinn's
    // default allows a hundred; see [`MAX_PEER_UNI_STREAMS`].
    transport.max_concurrent_uni_streams(VarInt::from_u32(MAX_PEER_UNI_STREAMS));

    // The bound on what an unauthenticated peer can make this process hold,
    // where quinn's default is no aggregate bound at all; the arithmetic is in
    // [`CONNECTION_RECEIVE_WINDOW`].
    transport.receive_window(CONNECTION_RECEIVE_WINDOW);

    // A deliberate raise above quinn's own default, sized against the production
    // path's bandwidth-delay product; the case for the number, and why it is not
    // a memory decision, is in [`STREAM_RECEIVE_WINDOW`].
    transport.stream_receive_window(STREAM_RECEIVE_WINDOW);

    // Exactly what quinn already defaults to, set here rather than inherited so
    // the arithmetic quoted against it cannot go stale; see [`SEND_WINDOW`].
    transport.send_window(SEND_WINDOW);

    // The other two buffers an unauthenticated peer can fill, pinned at quinn's
    // own values for the same reason as the window above them; see
    // [`DATAGRAM_RECEIVE_BUFFER`] and [`CRYPTO_BUFFER_SIZE`].
    transport.datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER));
    transport.crypto_buffer_size(CRYPTO_BUFFER_SIZE);

    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(limits.max_idle_timeout())
            .context("limits.max_idle_timeout is out of range for QUIC")?,
    ));
    // `None` when the operator set 0, which switches keep-alives off entirely.
    transport.keep_alive_interval(limits.keep_alive_interval());

    // Seeds the loss-recovery timers until the first RTT sample arrives. At
    // quinn's 333 ms default a handshake packet lost on the way waits about a
    // second to be resent; an operator who has read `rtt_ms` off the connection
    // logs can cut that to the path's scale instead.
    transport.initial_rtt(limits.initial_rtt());

    // quinn clamps this up to 1200 silently; `Config::validate` rejects anything
    // below instead, so a typo is reported rather than quietly corrected.
    transport.initial_mtu(limits.initial_mtu);
    if limits.mtu_discovery {
        // Everything except the search ceiling stays at quinn's defaults; the
        // ceiling is the one discovery parameter safe to hand an operator,
        // because a size is only ever adopted by probing it — a bound above
        // what the path carries costs a handful of standalone PINGs whose loss
        // is not a congestion signal, nothing more. quinn clamps absurd values
        // itself, and `Config::validate` already rejected anything above the
        // 1472 bytes IPv4 leaves of an Ethernet frame.
        let mut mtud = quinn::MtuDiscoveryConfig::default();
        mtud.upper_bound(limits.mtu_upper_bound);
        transport.mtu_discovery_config(Some(mtud));
    } else {
        // Stops the upward search, so packets start at `initial_mtu` and are
        // never probed larger: spec §5.4's conservative setting for a path that
        // black-holes large packets, where a stable small MTU beats an
        // optimistic large one. Not a hard pin — quinn's black-hole detector
        // keeps running with discovery off, and if it fires the packet size
        // drops to the 1200-byte floor for the rest of the connection, since
        // nothing is left to probe it back up.
        transport.mtu_discovery_config(None);
    }

    // QUIC datagram support stays at quinn's default (enabled), which is
    // what makes `max_datagram_frame_size` appear in our transport
    // parameters. What a session does with the datagrams once they are
    // received is CONNECT-UDP's own bound, `INBOUND_QUEUE_DEPTH`; what the
    // transport holds before that is [`DATAGRAM_RECEIVE_BUFFER`] above.

    transport.congestion_controller_factory(congestion_factory(limits.congestion_control));

    Ok(transport)
}

/// The bidirectional stream allowance a connection is accepted with.
///
/// A `min` rather than a flat constant, so that an operator who configures fewer
/// than [`INITIAL_BIDI_STREAMS`] gets what they configured and not more —
/// before authentication as well as after it. Nothing here can raise the
/// configured value; the clamp only ever lowers it.
fn initial_bidi_streams(limits: &crate::config::Limits) -> u32 {
    limits.max_streams_bidi.min(INITIAL_BIDI_STREAMS)
}

/// Grants a connection the configured bidirectional stream allowance.
///
/// The other half of [`INITIAL_BIDI_STREAMS`], called once per connection by
/// [`crate::tunnel::Context::mark_authenticated`] — the one place both ways of
/// getting past the door meet. It lives here rather than there so that the two
/// values a connection's stream allowance can take are stated in the same file
/// as each other, next to the reasoning that pairs them.
///
/// quinn spells the two directions differently — `max_concurrent_bidi_streams`
/// on `TransportConfig`, `set_max_concurrent_bi_streams` on `Connection` — and
/// they are the same parameter. Raising it allocates the new stream slots and
/// queues a MAX_STREAMS frame, which reaches the peer on the next packet this
/// connection sends: in practice the one carrying the response to the request
/// that just authenticated.
pub(crate) fn admit_configured_streams(quic: &quinn::Connection, max_streams_bidi: u32) {
    quic.set_max_concurrent_bi_streams(VarInt::from_u32(max_streams_bidi));
}

/// Whether a connection has got past the door, shared by everything that asks.
///
/// One flag with three readers in three modules — the accept loop's eviction
/// candidacy (D80), the bound on how long a connection may say nothing (D76),
/// and the stream allowance above (D98) — and one of those is not a read at all
/// but a transition: the raise happens on the false-to-true edge and must
/// happen exactly once, however many requests authenticate at the same moment.
///
/// A newtype rather than the `Arc<AtomicBool>` it wraps, because that invariant
/// cannot survive as a convention across three modules: a plain `store(true)`
/// written anywhere in them compiles and silently skips the raise. There is no
/// way to open this gate without being told whether you were the one who opened
/// it.
#[derive(Clone, Debug, Default)]
pub struct AuthGate(Arc<AtomicBool>);

impl AuthGate {
    /// A gate nothing has passed yet.
    pub fn closed() -> Self {
        Self::default()
    }

    /// Records that a request got past the door; `true` if it was the first.
    ///
    /// `Relaxed` for the same reason the reads are: what is ordered against is
    /// the flag itself, and a `swap` names exactly one caller the first however
    /// many race.
    pub fn mark(&self) -> bool {
        !self.0.swap(true, Ordering::Relaxed)
    }

    /// Whether anything has.
    pub fn is_open(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// The quinn congestion controller factory named by `[limits] congestion_control`.
///
/// Split out from [`transport_config`] purely so it can be tested: `TransportConfig`
/// has no getter for the factory and its `Debug` skips it, so the mapping is
/// invisible to the assertions above — a `Bbr => CubicConfig` slip passes every one
/// of them. The failure it would cause is not subtle in production (the download
/// direction of a long international path collapsed to near-zero on 2026-08-13, and
/// it took a day to localise) but it is entirely silent here, so the unit test
/// builds the controller and downcasts it.
///
/// BBR by default. A loss-based controller (CUBIC, NewReno) reads the
/// non-congestive packet loss of a long international path as congestion and
/// collapses the window — the download direction stalls to near-zero while a
/// co-located Shadowsocks server on the same box sails through, because the Linux
/// kernel runs BBR for TCP. BBR models bandwidth and RTT instead, holding
/// throughput on exactly these paths. See `config::CongestionControl` for why this
/// is the default and stays configurable.
fn congestion_factory(
    cc: CongestionControl,
) -> Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> {
    match cc {
        CongestionControl::Bbr => Arc::new(quinn::congestion::BbrConfig::default()),
        CongestionControl::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
        CongestionControl::NewReno => Arc::new(quinn::congestion::NewRenoConfig::default()),
    }
}

/// The live configuration, swapped wholesale on reload.
///
/// A plain `RwLock` rather than anything fancier: it is read once per accepted
/// connection and written once per `SIGHUP`, and the guard is never held across an
/// await — only long enough to clone the `Arc`.
type LiveConfig = Arc<RwLock<Arc<Config>>>;

/// Serialises everything that decides what a new connection is accepted with.
///
/// Three writes make a reload, the SNI gate's list, the live [`Config`] and the
/// endpoint's `quinn::ServerConfig`, and a fourth closes the listener at the
/// start of the drain. Held apart, they are two check-then-act races on the
/// same state.
///
/// The first is [`ReloadHandle::reload`] against [`Server::drain`]: the reload
/// reads the shutdown latch and then re-opens the listener, so a `SIGTERM`
/// landing between the two puts the endpoint back to accepting handshakes the
/// drain has just refused, and quinn's unaccepted `Incoming` queue grows for the
/// whole grace period. D22 states that this must not happen. The second is the
/// reload against an accept: a connection taken off `endpoint.accept()` between
/// two of the three writes runs on one generation's transport parameters and
/// another's `Authenticator`, `Policy` and quotas for its whole life, which is
/// the half-applied state the same ADR says there is none of.
///
/// Three callers take it. `reload` holds it across the latch read and all three
/// writes, `drain` across its own `set_server_config(None)`, and
/// [`Server::accept_under_the_swap`] across the pair of reads that decide what
/// one new connection runs on. The third is what closes the second race rather
/// than narrowing it: both halves of a connection's configuration are now taken
/// on one side of a reload.
///
/// A `std::sync::Mutex<()>` because there is nothing to protect but the order:
/// the values themselves each have their own lock. It is never held across an
/// await, since `reload` is synchronous throughout, `drain` holds it for one
/// `set_server_config` call, and `accept_under_the_swap` for two synchronous
/// reads. The slow half of a reload, parsing the file and the certificate,
/// happens before it is taken.
#[derive(Clone)]
struct ConfigSwap(Arc<Mutex<()>>);

impl ConfigSwap {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(())))
    }

    /// Holds the swap for as long as the returned guard lives.
    ///
    /// Poisoning would mean a panic between two of the writes, which is a
    /// half-applied reload however the lock is treated; taking the guard anyway
    /// leaves the next reload able to finish the job, where refusing would
    /// freeze the configuration for the life of the process.
    fn hold(&self) -> MutexGuard<'_, ()> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One connection this endpoint is serving.
struct Slot {
    /// The peer's address, so the eviction can say whose slot was taken.
    remote: SocketAddr,
    /// Whether a request on this connection has passed the credentials check.
    ///
    /// The very gate [`crate::tunnel::Context`] opens (D76), created here and
    /// handed down, so that the accept loop can read it without reaching into
    /// a connection it does not own.
    authenticated: AuthGate,
    /// Ends this connection. `notify_one` leaves a permit behind, so a slot
    /// evicted before its task has run is still ended by it rather than
    /// missing the signal.
    evict: Arc<Notify>,
}

/// The connections this endpoint is serving, ordered by accept sequence.
///
/// What `max_connections` is decided against, and the reason it is a roster
/// rather than a count: at the cap the newcomer is not the only candidate for
/// refusal. Every bound an unauthenticated connection is under is a bound on
/// *one* connection — one idle timeout for the QUIC handshake, one for the
/// HTTP/3 handshake, then twice one for the first request to authenticate (D76)
/// — and none of them bounds how many slots such connections may hold between
/// them. A peer that completes a handshake about once a second and never sends
/// a credential holds all 256 of the default slots for as long as it likes,
/// each slot legitimately, while every client with credentials is refused
/// (audit 2026-08-23).
///
/// So at the cap the oldest connection that has never authenticated loses its
/// slot to the newcomer, and only a server whose every live connection *has*
/// authenticated refuses. A sub-quota for unauthenticated connections would not
/// do: a legitimate client is unauthenticated at accept time too, so it would be
/// squeezed by the same pool it is trying to join. An authenticated connection
/// is never a candidate, and below the cap none of this runs at all.
///
/// `max_connections` is a soft cap on tasks, and an exact one on slots. A victim
/// leaves the roster the moment it is chosen, while its task takes as long to
/// notice as one poll takes, so for that moment the process is running one more
/// connection than the cap names. That is harmless: what a slot rations is the
/// right to sit here unauthenticated, and a connection in that state holds no
/// tunnel, no target socket and no file descriptor beyond the endpoint's — the
/// resources worth rationing are behind [`crate::tunnel::Quota`], which counts
/// per connection and is not touched by any of this.
///
/// The lock is a `std::sync::Mutex` and is never held across an await — only
/// long enough to walk a map that has at most `max_connections` entries.
#[derive(Clone)]
struct Roster {
    /// Keyed by accept sequence, so the first entry is the oldest connection.
    slots: Arc<Mutex<BTreeMap<u64, Slot>>>,
    /// The sequence number the next registration takes.
    next: Arc<AtomicU64>,
}

impl Roster {
    fn new() -> Self {
        Self {
            slots: Arc::new(Mutex::new(BTreeMap::new())),
            next: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Poisoning would mean a panic while walking the map; every value in it is
    /// a handle whose own state lives elsewhere, so there is nothing to observe
    /// half-written.
    fn slots(&self) -> MutexGuard<'_, BTreeMap<u64, Slot>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many connections hold a slot right now.
    fn len(&self) -> usize {
        self.slots().len()
    }

    /// Enters a connection about to be served, returning its eviction signal
    /// and the guard that takes it off the roster again.
    fn register(&self, remote: SocketAddr, authenticated: AuthGate) -> (Arc<Notify>, Registration) {
        let evict = Arc::new(Notify::new());
        let sequence = self.next.fetch_add(1, Ordering::Relaxed);

        self.slots().insert(
            sequence,
            Slot {
                remote,
                authenticated,
                evict: evict.clone(),
            },
        );

        (
            evict,
            Registration {
                slots: self.slots.clone(),
                sequence,
            },
        )
    }

    /// Evicts until the roster is below `cap`, naming the victims in the order
    /// they were taken.
    ///
    /// A loop rather than a single eviction, because the cap it is measured
    /// against can move. One victim is all a server that has been sitting at a
    /// steady cap ever needs; a `SIGHUP` that lowers `max_connections` below the
    /// number of connections already live leaves the roster over the new cap,
    /// and only this brings it back down — otherwise the reload would be
    /// honoured for the newcomer and quietly ignored for everybody already in,
    /// for the lifetime of those connections.
    ///
    /// It stops when there is nothing left that may be taken, which is the same
    /// condition the caller's refusal tests: an answer that leaves the roster at
    /// the cap means every live connection has authenticated.
    ///
    /// A method rather than the loop written out at the accept path, so that
    /// what the unit tests run is what the server runs (audit follow-up
    /// 2026-08-24): the tests used to walk a copy of it, and changing the
    /// server's own loop back to a single eviction left every one of them green.
    ///
    /// One guard for the whole loop rather than two acquisitions per pass. With
    /// the lock taken and released between the length read and the eviction, a
    /// connection ending on another thread in that window left the roster below
    /// the cap and the next pass evicted somebody who no longer had to go: one
    /// extra unauthenticated connection dropped from a population that is
    /// already churning. Benign, and recorded as F2 of D96 with the instruction
    /// to fix it the next time this file changed.
    fn evict_until_below(&self, cap: usize) -> Vec<SocketAddr> {
        let mut victims = Vec::new();
        let mut slots = self.slots();

        while slots.len() >= cap {
            let Some(victim) = evict_oldest_from(&mut slots) else {
                break;
            };
            victims.push(victim);
        }

        victims
    }
}

/// Takes the oldest never-authenticated connection out of `slots` and ends it.
///
/// The victim is removed from the roster here rather than by its own task, so
/// that a burst of accepts at the cap evicts successive connections instead of
/// picking the same one over and over while it winds down. `None` means every
/// entry left has authenticated.
///
/// A free function over the guard rather than a method that takes its own, so
/// that [`Roster::evict_until_below`] can run it repeatedly under one guard and
/// the roster's own tests can run exactly what the server runs.
fn evict_oldest_from(slots: &mut BTreeMap<u64, Slot>) -> Option<SocketAddr> {
    let sequence = *slots
        .iter()
        .find(|(_, slot)| !slot.authenticated.is_open())
        .map(|(sequence, _)| sequence)?;

    let slot = slots.remove(&sequence)?;
    slot.evict.notify_one();

    Some(slot.remote)
}

/// A connection's place on the [`Roster`], given up when its task ends.
///
/// A guard rather than a call at the end of the task, because the task has
/// several endings — a refused handshake, an eviction, a panic — and a slot that
/// outlived any one of them would be a slot nothing can ever give back.
struct Registration {
    slots: Arc<Mutex<BTreeMap<u64, Slot>>>,
    sequence: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            // Already gone when an eviction took the entry out; sequence
            // numbers are never reused, so this can only ever remove this
            // connection's own slot.
            .remove(&self.sequence);
    }
}

/// A bound QUIC endpoint ready to accept connections.
pub struct Server {
    endpoint: quinn::Endpoint,
    /// What the kernel granted for the endpoint socket's buffers, for the
    /// startup line. Fixed at bind time: nothing reloadable can change it.
    socket_buffers: SocketBuffers,
    config: LiveConfig,
    /// The connections being served, in accept order, and what the accept loop
    /// decides `max_connections` against; see [`Roster`].
    roster: Roster,
    /// The blocking-pool allowance every connection's name lookups draw on.
    ///
    /// Server-wide because the pool is: what one connection may hold at once is
    /// bounded here so that a client whose targets never resolve cannot park
    /// every thread the process has and starve the rest (D90). Built at bind
    /// time and never reloaded -- it is sized against the runtime the process
    /// was started with, which a `SIGHUP` cannot resize.
    resolver: crate::net::ResolverBudget,
    /// The host names the SNI gate admits, shared with the socket wrapper.
    ///
    /// Held here so [`Server::reload_handle`] can hand it on: the gate lives
    /// under the endpoint, on a socket that a reload cannot rebind, so the list
    /// is the only part of it a `SIGHUP` can move (D106).
    expected: Expected,
    /// Orders a reload against the drain and against itself; see [`ConfigSwap`].
    swap: ConfigSwap,
    /// Fires the graceful shutdown. Handed to whoever watches for signals.
    trigger: Trigger,
    /// The other end of the same latch, cloned into every connection.
    shutdown: Shutdown,
    /// The `[server] listen` this endpoint was bound with.
    ///
    /// Kept beside the endpoint rather than read back off it, because the two
    /// are not the same answer: `local_addr()` reports the port the kernel
    /// chose, so a configured `:0` would never compare equal to itself. It is
    /// the *configured* address a reload has to be judged against, and it
    /// cannot come from the live configuration either -- a reload swaps that
    /// whole value in, so the second reload naming a new address would find
    /// the first one's already there and say nothing.
    listen: SocketAddr,
}

impl Server {
    /// Binds the UDP socket and prepares the QUIC server configuration.
    ///
    /// `quinn::Endpoint::server` is expanded by hand here, because the socket has
    /// to be reachable between the bind and the endpoint: quinn's own helper is a
    /// bare `std::net::UdpSocket::bind` and never touches `SO_RCVBUF`/`SO_SNDBUF`,
    /// so a server that does not ask keeps `net.core.rmem_default` — around
    /// 208 KiB — however high `net.core.rmem_max` is set, that sysctl being a
    /// ceiling on requests rather than an allocation (D56). Everything passed to
    /// [`quinn::Endpoint::new_with_abstract_socket`] below is what the helper
    /// passes internally; none of it may be dropped in the name of tidiness.
    ///
    /// The second reason for expanding it is [`Gate`], which wraps the socket
    /// the runtime hands back so that a datagram quinn would *answer* can be
    /// refused before quinn sees it (D106). The wrapper is installed whether or
    /// not `[security] expected_sni` is set, because the list is reloadable and
    /// the socket is not: with an empty list every datagram passes through
    /// untouched, and a `SIGHUP` can then turn the gate on without a restart.
    pub fn bind(config: Arc<Config>) -> Result<Self> {
        let quic_config = server_config(&config)?;
        // Taken before the configuration moves into the endpoint. The Initial
        // keys the gate needs are a function of the client's own Destination
        // Connection ID rather than of the certificate (RFC 9001 §5.2), so this
        // handle stays good across every reload.
        let crypto = quic_config.crypto.clone();

        let socket = std::net::UdpSocket::bind(config.server.listen)
            .with_context(|| format!("failed to bind UDP socket {}", config.server.listen))?;

        let socket_buffers = SocketBuffers::request(&socket, &config.limits);

        let runtime = quinn::default_runtime()
            .ok_or_else(|| anyhow!("no async runtime is available for the QUIC endpoint"))?;
        let socket = runtime
            .wrap_udp_socket(socket)
            .context("failed to hand the UDP socket to the async runtime")?;

        let expected = Expected::new(Names::new(&config.security.expected_sni));
        let socket = Arc::new(Gate::new(socket, expected.clone(), crypto));

        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(quic_config),
            socket,
            runtime,
        )
        .context("failed to build the QUIC endpoint over the gated socket")?;

        warn_if_fd_budget_is_tight(&config.limits);

        let (trigger, shutdown) = shutdown::channel();

        Ok(Self {
            endpoint,
            socket_buffers,
            listen: config.server.listen,
            config: Arc::new(RwLock::new(config)),
            roster: Roster::new(),
            resolver: crate::net::ResolverBudget::new(),
            expected,
            swap: ConfigSwap::new(),
            trigger,
            shutdown,
        })
    }

    /// A handle that starts the graceful shutdown.
    ///
    /// The binary hands this to its signal handler; tests fire it directly.
    pub fn shutdown_trigger(&self) -> Trigger {
        self.trigger.clone()
    }

    /// A handle that replaces the running configuration.
    ///
    /// The binary hands this to its `SIGHUP` handler; tests call it directly.
    pub fn reload_handle(&self) -> ReloadHandle {
        ReloadHandle {
            endpoint: self.endpoint.clone(),
            config: self.config.clone(),
            shutdown: self.shutdown.clone(),
            expected: self.expected.clone(),
            swap: self.swap.clone(),
            listen: self.listen,
        }
    }

    /// A snapshot of the configuration currently in force.
    fn config(&self) -> Arc<Config> {
        // Poisoning would mean a panic while swapping the config; the value itself
        // is an immutable `Arc`, so it cannot be observed half-written.
        self.config
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The address the endpoint is actually bound to.
    ///
    /// Useful when the configured port is 0.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("failed to read the local address of the QUIC endpoint")
    }

    /// Accepts connections until the endpoint closes or shutdown is triggered.
    ///
    /// Each connection is handled in its own task, so a failure only ever affects
    /// that connection. The tasks are tracked in a `JoinSet` rather than detached,
    /// because the shutdown path needs to know when they are finished — and
    /// because dropping the set is what finally cuts off anything still running
    /// once the grace period is over.
    pub async fn run(&self) {
        let config = self.config();
        info!(
            // The binary's own version, so a journal read after an upgrade
            // says which build produced the lines that follow without having
            // to be matched against the deploy log or a checksum.
            version = env!("CARGO_PKG_VERSION"),
            listen = %config.server.listen,
            alpn = ?config.server.alpn,
            // Empty when the SNI gate is off, which is the shipped default and
            // the behaviour of every release before it (D106).
            expected_sni = ?config.security.expected_sni,
            grace_secs = config.server.shutdown_grace,
            // The kernel's numbers, not the configured ones: these are what
            // `ss -uanpm` prints as `rb` and `tb`, so a log line and an `ss`
            // reading can be put side by side. Absent when the kernel would not
            // say, which is why they are `Option`s rather than a sentinel.
            so_rcvbuf = self.socket_buffers.recv,
            so_sndbuf = self.socket_buffers.send,
            "accepting QUIC connections"
        );

        let mut shutdown = self.shutdown.clone();
        let mut connections = JoinSet::new();

        loop {
            // Reap eagerly rather than only in the select below: with `biased`
            // ordering a steady stream of new connections would starve that
            // branch, and finished tasks would pile up in the set for as long as
            // the stream lasted. Nothing about the cap rides on this any more --
            // that is decided against the roster, in [`Self::admit`] -- so what
            // is at stake is the memory of the join handles and the length of
            // the walk `drain` does at shutdown.
            while connections.try_join_next().is_some() {}

            tokio::select! {
                // Shutdown wins any tie: no point starting work that is about to
                // be torn down.
                biased;

                () = shutdown.fired() => break,

                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        // The endpoint was closed from elsewhere.
                        break;
                    };

                    let Some(incoming) = self.admit(incoming) else {
                        continue;
                    };

                    connections.spawn(self.serve(incoming));
                }

                // Cancel-safe, so losing this race costs nothing; the eager drain
                // above is what actually keeps the set trimmed.
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }

        if shutdown.is_fired() {
            self.drain(&mut connections).await;
        }
    }

    /// Decides whether an arriving connection may have a slot, and answers
    /// it itself when it may not.
    ///
    /// `Some` is a connection the accept loop should go on and serve. `None`
    /// means this arrival has already been dealt with -- asked for a Retry,
    /// or refused -- and there is nothing left for the caller to do with it.
    ///
    /// Below the cap this is a configuration read and a length read and
    /// nothing else: every branch past the first belongs to a full server.
    fn admit(&self, mut incoming: quinn::Incoming) -> Option<quinn::Incoming> {
        // Read per accepted connection rather than snapshotted before the
        // loop: `docs/deployment.md#reloading` promises a reload applies to
        // connections accepted from then on, and lowering this cap during an
        // incident is exactly the sort of thing that promise is for. The cost
        // is an `Arc` load on a path that is already opening a QUIC
        // connection.
        let max_connections = self.config().limits.max_connections;

        // The roster rather than the `JoinSet`: a slot is entered before the
        // QUIC handshake starts and given up by a guard, so the roster counts
        // exactly the connections that hold one. The set is kept for draining,
        // and its length *leads* the roster rather than trailing it -- a task
        // that has finished but not been reaped has already dropped its
        // registration, and an evicted one leaves the roster before its task
        // ends, so the set holds everything the roster does and sometimes
        // more.
        if max_connections == 0 || self.roster.len() < max_connections as usize {
            return Some(incoming);
        }

        // Read before `retry()` or `refuse()` consumes the `Incoming`, so
        // either branch can still name the peer.
        let remote = incoming.remote_address();
        let live = self.roster.len();

        // Taking somebody else's slot is a privilege, and a source address
        // that has proved nothing does not have it: one spoofed Initial per
        // datagram, from addresses that never have to receive anything, would
        // otherwise walk the whole roster out of the door -- and every one of
        // those datagrams would start a TLS server flight, since `serve`
        // accepts the connection eagerly. So at the cap the unvalidated
        // newcomer is asked to come back with a token instead, which costs
        // this server no crypto and no slot, and is what QUIC provides for the
        // purpose.
        //
        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
        //# A server might wish to validate the client address
        //# before starting the cryptographic handshake.  QUIC
        //# uses a token in the Initial packet to provide
        //# address validation prior to completing the
        //# handshake.  This token is delivered to the client
        //# during connection establishment with a Retry packet
        //# (see Section 8.1.2) or in a previous connection
        //# using the NEW_TOKEN frame (see Section 8.1.3).
        //
        // The second of those is why the round trip is rarer than it looks.
        // quinn's `bloom` feature is on (see `Cargo.toml`), so this server
        // sends two NEW_TOKEN frames on every connection whose path it
        // validated, and a client that keeps them -- quinn's own default token
        // store does -- comes back already validated and evicts without a
        // Retry. What pays the extra round trip is an address this server
        // holds no token from: a first contact, a token past its two-week
        // lifetime, or one sealed by a key this process no longer has, since
        // `ServerConfig::with_crypto` draws a fresh one every time
        // `server_config` builds a config -- at startup and again on every
        // `SIGHUP`. And it is paid only while the server is full: below the
        // cap this branch is not entered at all, so an ordinary Surge
        // handshake is untouched.
        if !incoming.remote_address_validated() {
            if incoming.may_retry() {
                match incoming.retry() {
                    Ok(()) => {
                        // DEBUG for the same reason the refusal below is: a
                        // flood is exactly when this fires.
                        debug!(
                            %remote,
                            live,
                            max_connections,
                            "the server is full: asking an unvalidated address \
                             to prove itself before it may take a slot"
                        );
                        return None;
                    }
                    // Unreachable as quinn stands -- it documents
                    // `may_retry()` as guaranteed true whenever the address is
                    // unvalidated -- and handled rather than unwrapped because
                    // the fallback is the safe one either way.
                    //
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.2
                    //# In response to processing an Initial packet
                    //# containing a token that was provided in a Retry
                    //# packet, a server cannot send another Retry
                    //# packet; it can only refuse the connection or
                    //# permit it to proceed.
                    Err(error) => incoming = error.into_incoming(),
                }
            }

            debug!(
                %remote,
                live,
                max_connections,
                "refusing a connection: the server is full and this address \
                 cannot be asked to validate itself"
            );
            incoming.refuse();
            return None;
        }

        // A loop rather than a single eviction, because the cap this is
        // measured against can move; `evict_until_below` carries the whole of
        // that argument and is what the roster's own tests run. A connection
        // that has never had a request pass the credentials check is not owed
        // the slot it is sitting on, and a peer that completes a handshake a
        // second and never authenticates would otherwise hold every slot there
        // is for as long as it cared to -- each one bounded, all of them
        // replaced (audit 2026-08-23).
        for victim in self.roster.evict_until_below(max_connections as usize) {
            // DEBUG, not INFO: this fires once per arrival for as long as a
            // flood lasts, which is exactly the shape the refusal beside it is
            // DEBUG for. The victim's own closing line stays at INFO -- that
            // one is once per connection actually lost, and it is what an
            // operator is looking for.
            debug!(
                evicted = %victim,
                %remote,
                max_connections,
                "the server is full: evicting the oldest connection that has \
                 not authenticated"
            );
        }

        // Still full, so every live connection has authenticated and there is
        // nothing to take a slot from. Refused at the QUIC layer: the peer is
        // told immediately instead of timing out, and nothing per-connection
        // is built on our side. Logged at DEBUG because a flood is exactly
        // when this fires.
        if self.roster.len() >= max_connections as usize {
            debug!(
                %remote,
                live = self.roster.len(),
                max_connections,
                "refusing a connection: the server is at its connection limit"
            );
            incoming.refuse();
            return None;
        }
        Some(incoming)
    }

    /// The configuration one new connection runs on, and the handshake that
    /// runs it, taken as one step.
    ///
    /// Two reads decide what a connection gets, and they read two different
    /// generations unless something orders them. The first is the live
    /// `Config`, which carries the `Authenticator`, the `Policy`, the quotas
    /// and the timeouts. The second is quinn's endpoint server configuration,
    /// which carries the transport parameters: `IntoFuture` for
    /// `quinn::Incoming` is `Incoming::accept()` (quinn `incoming.rs`), and
    /// `proto::Endpoint::accept` reads `self.server_config` there and fixes the
    /// parameters for the life of the connection. Left to the first poll of the
    /// spawned task, that second read could land on the far side of a `SIGHUP`
    /// from the first, which is the half-applied state D22 says there is none
    /// of: one generation's transport parameters beside another's users.
    ///
    /// Both under [`ConfigSwap`], which `reload` holds across all three of its
    /// writes, so a connection accepted while a reload is applying waits for it
    /// and then runs wholly on one generation. The guard covers two synchronous
    /// reads and no await.
    ///
    /// Generic over what is being accepted so the regression test can attempt
    /// the snapshot with no peer on the other end; `serve` is the only caller
    /// that passes a `quinn::Incoming`.
    fn accept_under_the_swap<I: IntoFuture>(&self, incoming: I) -> (Arc<Config>, I::IntoFuture) {
        let _swapping = self.swap.hold();
        (self.config(), incoming.into_future())
    }

    /// Runs one accepted connection to completion.
    ///
    /// Split out of the accept loop so it can be a `'static` future for the
    /// `JoinSet`: everything it needs is cloned up front.
    ///
    /// # The handshake deadline
    ///
    /// The `max_connections` slot is taken by the roster registration below,
    /// before the QUIC and TLS handshake this starts with has happened — so the
    /// cap counts handshakes in progress as well as connections, and something
    /// has to bound the first of those. quinn has no handshake-specific timer: its idle
    /// timeout is reset by any authenticated packet in any packet number space,
    /// so a peer that sends an Initial-space PING every `max_idle_timeout` and
    /// never completes the handshake holds a slot for as long as it likes, and
    /// makes this endpoint retransmit its handshake flight on every PTO
    /// meanwhile (review M6). `Connection::handshake`'s deadline is no help
    /// either: it starts one layer later, once there is a connection at all.
    ///
    /// One idle timeout bounds it, for the same reason it bounds the HTTP/3
    /// handshake: a peer that cannot finish a handshake in the time it is
    /// allowed to say nothing at all is not going to finish it. Dropping the
    /// future ends the connection and frees the slot with it.
    ///
    /// What that drop is *not* is a refusal. The `Incoming` was turned into a
    /// future by [`Self::accept_under_the_swap`] before this task existed, and
    /// `IntoFuture` for `Incoming` is `Incoming::accept()`, so by the time
    /// either arm of the select below can run there is a `Connecting` rather
    /// than an `Incoming`: quinn has answered the client's Initial and the TLS
    /// server flight is already on its way.
    /// Dropping a `Connecting` closes the connection the way an application
    /// close does, and RFC 9000 §10.2.3 has an application close sent before the
    /// handshake completes go out as a transport one, so what the peer receives
    /// is `CONNECTION_CLOSE` with APPLICATION_ERROR and an empty reason — not
    /// the CONNECTION_REFUSED that `Incoming::refuse` sends, and not silence.
    ///
    /// # Eviction
    ///
    /// The same drop is what an eviction uses. A connection that has never
    /// authenticated may have its slot taken by a newcomer once the server is
    /// full ([`Roster`]), and the signal reaches it here: whichever stage it is
    /// in, its work is dropped. Before the handshake completes that is the
    /// `Connecting` close described above; after it, dropping `conn::handle`'s
    /// future drops the HTTP/3 connection, whose own `Drop` closes the QUIC
    /// connection with H3_NO_ERROR — nothing went wrong, the slot was simply
    /// owed to somebody else.
    fn serve(&self, incoming: quinn::Incoming) -> impl std::future::Future<Output = ()> + use<> {
        let remote = incoming.remote_address();

        // Snapshotted per connection, not read live: a reload changes what new
        // connections get, while a connection already running keeps the
        // credentials and policy it started with for its whole life. Anything else
        // would mean a tunnel's rules changing under it mid-transfer.
        let (config, accepted) = self.accept_under_the_swap(incoming);

        let shutdown = self.shutdown.clone();
        let resolver = self.resolver.clone();

        let handshake_deadline = config.limits.max_idle_timeout();

        // Entered here rather than inside the future: the accept loop decides
        // on the roster's length, and a slot that only appeared when the task
        // was first polled would let a burst of accepts all pass the same
        // check and overshoot the cap.
        let authenticated = AuthGate::closed();
        let (evicted, registration) = self.roster.register(remote, authenticated.clone());

        async move {
            // Held for the whole connection: dropping it takes the slot off the
            // roster, however this task ends.
            let _registration = registration;

            let quic = tokio::select! {
                () = evicted.notified() => {
                    // Dropping the half-built connection ends it, exactly as
                    // letting the deadline below lapse does -- with the
                    // `CONNECTION_CLOSE(APPLICATION_ERROR)` and empty reason
                    // this function's documentation describes, since the
                    // `Incoming` was accepted before either arm could run.
                    // DEBUG rather than the INFO the established case gets:
                    // there is no connection yet, so there is nothing to report
                    // about one.
                    debug!(
                        %remote,
                        "evicted before its QUIC handshake completed: the server is full"
                    );
                    return;
                }

                handshake = tokio::time::timeout(handshake_deadline, accepted) => match handshake {
                    Ok(Ok(quic)) => quic,
                    Ok(Err(error)) => {
                        // A failed handshake is routine on a public port: scanners,
                        // version negotiation, stale retries.
                        //
                        // Through `peer_error` because a peer that closes during
                        // the handshake writes the reason phrase inside this
                        // error, and `Display` escapes nothing: the connection
                        // that completed has the same door, and both call the
                        // one name.
                        debug!(
                            %remote,
                            error = %crate::logfmt::peer_error(error),
                            "QUIC handshake failed"
                        );
                        return;
                    }
                    // Equally routine, and logged at the same level for the same
                    // reason: a flood is exactly when this fires.
                    Err(_elapsed) => {
                        debug!(
                            %remote,
                            timeout_secs = handshake_deadline.as_secs(),
                            "QUIC handshake did not complete in time"
                        );
                        return;
                    }
                },
            };

            let peer = peer_info(&quic);
            info!(
                remote = %peer.remote,
                alpn = %crate::logfmt::or_dash(peer.alpn.as_deref()),
                server_name = %crate::logfmt::or_dash(peer.server_name.as_deref()),
                // At this point the estimate comes from the handshake samples
                // alone; the close logs below carry the lifetime smoothed value.
                rtt_ms = quic.rtt().as_millis(),
                "connection established"
            );

            // `conn::handle` consumes the connection; keep a handle so the close
            // logs can report what the connection learned about its path: the
            // RTT it measured, the address the peer ended on — `remote_now`
            // differing from `remote` is the only externally visible trace of a
            // migration or NAT rebind during the connection's life — and the
            // MTU.
            //
            // `mtu` is the packet size DPLPMTUD settled on in this direction —
            // a report, not a knob: it is here so an operator can see whether
            // discovery ever got past `initial_mtu` on their path. On a
            // connection that lived long enough to probe, a value still at the
            // floor means the probes went unanswered (the shape a path that
            // black-holes large packets has) or a black hole was detected later
            // and discovery fell back; anything above it is discovery having
            // done its job.
            //
            // `mtu_black_holes` counts how often quinn's black-hole detector
            // fired and pushed the packet size back to the floor for its
            // cooldown. It is what tells those two apart when `mtu` alone
            // cannot: discovery may have climbed back by the time the
            // connection ends, hiding a fall-back that a bulk transfer in the
            // middle paid for. quinn's detector is a heuristic over loss
            // bursts, and a burst of full-size packets lost to ordinary
            // congestion looks the same to it as a path that stopped carrying
            // them, so a non-zero count on a path that other connections probe
            // fine is the signature of a false positive rather than of the
            // path.
            //
            // `tunnels` is how many requests on this connection were granted a
            // tunnel slot — TCP CONNECT and CONNECT-UDP alike — so a connection
            // that only ever failed authentication reports zero.
            //
            // `dropped_datagrams` is how many inbound HTTP Datagrams the
            // connection's router dropped instead of delivering — an unknown
            // Context ID, a Quarter Stream ID no session claims, a session
            // whose inbound queue was full, or a datagram cut short of its
            // Context ID. Each drop is silent where it happens, because the
            // RFCs ask for exactly that, so this total is the only trace a
            // misdirected or over-fast sender leaves in production. Distinct
            // from `lost_packets`, which is the QUIC path losing what was
            // sent; these arrived fine and were dropped on purpose.
            //
            // `tx_bytes` and
            // `rx_bytes` are UDP-level byte counts: everything this endpoint put
            // on or took off the wire for this connection, QUIC and HTTP/3
            // framing, retransmissions, ACKs and padding included. They are
            // neither tunnel payload — always smaller — nor bytes the peer
            // acknowledged, since a packet is counted when it is sent whether or
            // not it arrived, so they answer "how much did this connection move
            // through this host" and nothing finer. `sent_packets` and
            // `lost_packets` are reported together because a loss rate needs
            // both: either number alone says nothing about the path (D72).
            let rtt_probe = quic.clone();

            // Created here rather than inside the connection so they survive
            // it: `conn::handle` hands the first to every request and the
            // second to the HTTP/3 datagram router, and both are read below,
            // once, after the connection is over.
            let tunnels = Arc::new(AtomicU64::new(0));
            let dropped_datagrams = Arc::new(AtomicU64::new(0));

            // Which of the two log levels this connection deserves is decided
            // from the error value `conn::handle` returned, and never from
            // `rtt_probe.close_reason()`. Returning from `conn::handle` drops
            // the HTTP/3 connection, whose `Drop` closes the QUIC connection with
            // H3_NO_ERROR; quinn's close path then unconditionally overwrites
            // the stored reason with `LocallyClosed`. So by the time control is
            // back here, `close_reason()` reports that drop rather than whatever
            // actually ended the connection — which is precisely how the idle
            // timeout ended up logged as an error for a whole release cycle.
            let closed = tokio::select! {
                // The newcomer that took this slot is already being served; all
                // that is left here is to stop. Graded with the idle endings
                // rather than as an error, because nothing about this
                // connection failed.
                () = evicted.notified() => Ok("evicted"),

                handled = conn::handle(quic, config, shutdown, &resolver, tunnels.clone(), dropped_datagrams.clone(), authenticated) =>
                    match handled {
                        // The accept loop ended on its own terms: the peer said it would
                        // send no further requests, or the GOAWAY drain completed.
                        Ok(()) => Ok("drained"),
                        Err(error) => match h3api::benign_close(&error) {
                            // Surge abandons connections without a CONNECTION_CLOSE
                            // (network switch, app exit), so letting one idle out is the
                            // everyday goodbye, not a failure.
                            Some(h3api::BenignClose::Idle) => Ok("idle"),
                            // A peer that closed cleanly is equally routine.
                            Some(h3api::BenignClose::PeerClosed) => Ok("peer_close"),
                            None => Err(error),
                        },
                    },
            };

            log_connection_closed(
                peer.remote,
                &rtt_probe,
                closed,
                tunnels.load(Ordering::Relaxed),
                dropped_datagrams.load(Ordering::Relaxed),
            );
        }
    }

    /// Winds the endpoint down: no new connections, then a bounded wait, then
    /// close regardless.
    ///
    /// The GOAWAY frames are not sent from here — every connection is watching the
    /// same signal and sends its own, which is what lets a connection start
    /// draining the instant the signal fires rather than waiting to be told.
    async fn drain(&self, connections: &mut JoinSet<()>) {
        // Stop new handshakes at the source. Packets for existing connections are
        // unaffected; a client that arrives now sees the port as closed and can
        // fail over immediately rather than after a timeout.
        //
        // Under the swap, because the latch this drain runs on is read by
        // `ReloadHandle::reload` as a plain predicate: without it a reload that
        // had already passed that read would install a server configuration
        // after this line and re-open the listener for the whole grace period.
        // Dropped explicitly and at once: it is a `std::sync::Mutex` guard and
        // the wait below is an await, so it must not still be alive there.
        let swapping = self.swap.hold();
        self.endpoint.set_server_config(None);
        drop(swapping);

        let grace = self.config().server.shutdown_grace();
        info!(
            open_connections = self.endpoint.open_connections(),
            grace_secs = grace.as_secs(),
            "shutting down: no new connections, letting existing tunnels finish"
        );

        let drained = tokio::time::timeout(grace, async {
            while connections.join_next().await.is_some() {}
        })
        .await
        .is_ok();

        if drained {
            info!("every connection finished within the grace period");
        } else {
            warn!(
                open_connections = self.endpoint.open_connections(),
                grace_secs = grace.as_secs(),
                "grace period expired, closing the remaining connections"
            );
        }

        // Unconditional: a tunnel that never ends must not keep the process alive.
        // `Endpoint::close` tells every peer why, rather than going silent and
        // leaving them to time out.
        self.endpoint
            .close(VarInt::from_u32(0), b"server shutting down");

        // Give the CONNECTION_CLOSE frames a moment to leave the socket. Bounded,
        // because this is the last thing standing between us and exiting.
        let _ = tokio::time::timeout(CLOSE_FLUSH_TIMEOUT, self.endpoint.wait_idle()).await;
    }
}

/// The line one connection ends on: INFO with the reason it stopped, WARN with
/// the error that stopped it.
///
/// Written here rather than at the end of [`Server::serve`] so the two field
/// lists cannot drift apart. They carry the same twelve fields and differ only
/// in `reason` against `error`, which is what makes an operator able to grep
/// one journal for both -- and what a second copy of a twelve-field list
/// invites losing, as D72's traffic counters would have been had they landed on
/// only one of them.
///
/// `closed` is graded from the error *value* rather than from
/// `Connection::close_reason()`, for the reason [`Server::serve`] gives where it
/// is decided.
fn log_connection_closed(
    remote: SocketAddr,
    quic: &quinn::Connection,
    closed: Result<&'static str, h3api::ConnectionError>,
    tunnels: u64,
    dropped_datagrams: u64,
) {
    // One snapshot for every transport field below, so they all describe the
    // same instant — and the only read of them there is, so the counters cost
    // nothing while the connection runs.
    let stats = quic.stats();
    let path = stats.path;

    match closed {
        Ok(reason) => {
            info!(
                remote = %remote,
                remote_now = %quic.remote_address(),
                reason,
                rtt_ms = quic.rtt().as_millis(),
                mtu = path.current_mtu,
                mtu_black_holes = path.black_holes_detected,
                tunnels,
                dropped_datagrams,
                tx_bytes = stats.udp_tx.bytes,
                rx_bytes = stats.udp_rx.bytes,
                sent_packets = path.sent_packets,
                lost_packets = path.lost_packets,
                "connection closed"
            );
        }
        Err(error) => {
            warn!(
                remote = %remote,
                remote_now = %quic.remote_address(),
                %error,
                rtt_ms = quic.rtt().as_millis(),
                mtu = path.current_mtu,
                mtu_black_holes = path.black_holes_detected,
                tunnels,
                dropped_datagrams,
                tx_bytes = stats.udp_tx.bytes,
                rx_bytes = stats.udp_rx.bytes,
                sent_packets = path.sent_packets,
                lost_packets = path.lost_packets,
                "connection closed with error"
            );
        }
    }
}

/// Replaces the configuration of a running server.
///
/// The point of this type is a guarantee: a `SIGHUP` with a broken configuration
/// file — a typo, a half-written certificate mid-renewal — must leave the server
/// running exactly as it was. A proxy that exits when handed a bad config would
/// turn a typo into an outage, and `certbot --deploy-hook` will send `SIGHUP` at
/// three in the morning with nobody watching.
///
/// So nothing is applied until everything has been parsed and validated: the file
/// is read, the new certificate and key are loaded, and only then is anything
/// swapped. There is no intermediate state where the endpoint has the new
/// certificate but the old users, or vice versa.
#[derive(Clone)]
pub struct ReloadHandle {
    endpoint: quinn::Endpoint,
    config: LiveConfig,
    shutdown: Shutdown,
    /// The SNI gate's list, which is swapped with the rest (D106).
    expected: Expected,
    /// The server's own, so a reload and the drain cannot interleave their
    /// writes; see [`ConfigSwap`].
    swap: ConfigSwap,
    /// The `[server] listen` the endpoint was bound with, for the one key a
    /// reload has to say it is ignoring.
    listen: SocketAddr,
}

impl ReloadHandle {
    /// Re-reads the configuration file and applies it, or changes nothing.
    ///
    /// Returns the newly applied configuration, or an error describing why the old
    /// one is still in force. Existing connections are deliberately unaffected —
    /// they keep the configuration they were accepted with (see `Server::serve`).
    pub fn reload(&self, path: &Path) -> Result<Arc<Config>> {
        // Parses, validates, and checks that the certificate files are readable.
        let config = Arc::new(Config::load(path)?);

        // Loads and parses the certificate and key, which is the step most likely
        // to fail during a renewal. Done before anything is swapped.
        let quic_config = server_config(&config)
            .context("the new configuration's certificate and key are not usable")?;

        // Everything from the latch read to the last write is one step, and the
        // drain takes the same lock around its own `set_server_config`. Held
        // here rather than only around the writes because the latch is a
        // check-then-act: reading it and then re-opening the listener is
        // precisely the race D22 forbids. The parsing above is deliberately
        // outside it, so a `SIGHUP` with a large certificate cannot delay a
        // drain that is waiting for this.
        let _swapping = self.swap.hold();

        // A reload during shutdown must not re-open the listener that `drain` just
        // closed. Refusing is safer than racing it.
        if self.shutdown.is_fired() {
            bail!("the server is shutting down; the configuration was not reloaded");
        }

        // Past this point nothing can fail, so the swaps cannot half-apply.
        //
        // The gate's list goes first, and deliberately: between it and the
        // endpoint's own configuration the socket admits the new set of names
        // while the endpoint still holds the old certificate, which is a
        // handshake that gets as far as the TLS layer and is refused there. The
        // other order would have the endpoint present the new certificate to a
        // name the socket still drops, which is the same refusal with the reply
        // removed -- and the gate's whole point is that a name it does not know
        // gets no reply at all.
        //
        // The live `Config` goes before `set_server_config` for a second
        // reason, now that `Server::accept_under_the_swap` takes this lock
        // across both of the reads a new connection makes: an accept can no
        // longer land between the two at all, so the order inside the guard is
        // what a reader of this function should be able to follow rather than
        // what a connection depends on. New users before new transport
        // parameters is the order the sentence above describes for the gate,
        // read the same way: the half that decides who gets in goes first.
        self.expected.set(Names::new(&config.security.expected_sni));
        *self.config.write().unwrap_or_else(PoisonError::into_inner) = config.clone();
        self.endpoint.set_server_config(Some(quic_config));

        info!(
            path = %path.display(),
            users = config.auth.users.len(),
            cert = %config.server.cert.display(),
            "configuration reloaded; new connections will use it"
        );

        // Said rather than done. A reload never rebinds -- `docs/configuration.md`
        // and `docs/deployment.md` both promise that, because the usual sender of
        // SIGHUP is a renewal hook that rewrites the whole file and a rebind
        // would take the proxy off the air over a key nobody meant to change.
        // What was missing was the operator being told: the rest of the file
        // applied, this one key silently did not, and until now the only way to
        // find out was to notice the socket had not moved.
        if config.server.listen != self.listen {
            warn!(
                bound = %self.listen,
                configured = %config.server.listen,
                "server.listen changed, but a reload cannot move the listening socket; \
                 the server is still bound where it started. Restart to apply it."
            );
        }

        for warning in config.warnings() {
            warn!("{warning}");
        }

        Ok(config)
    }
}

/// Warns when the fd limit leaves no room for the configured tunnel quota.
///
/// Every tunnel costs one descriptor, and the quota is per connection, so the
/// budget the process actually has to meet is
/// `max_connections * max_targets_per_conn` — not one connection's share of it.
/// The two keys are halves of one number and only their product can be compared
/// against `RLIMIT_NOFILE`; checking one connection's worth was checking a bound
/// no adversary is under, since a client holding credentials may open
/// `max_connections` of them (review M7).
///
/// fd exhaustion is not a graceful failure mode. It degrades rather than
/// crashes here — a `socket()` that fails becomes one refused tunnel — but it
/// does so for every connection at once and for anything else the process needs
/// a descriptor for, a certificate reload included (spec §5.2).
fn warn_if_fd_budget_is_tight(limits: &crate::config::Limits) {
    // `None` is `RLIM_INFINITY` rather than a failed read (the call cannot
    // fail): no ceiling means no budget to be tight against, so the check has
    // passed rather than been skipped.
    let Some(limit) = crate::net::fd_soft_limit() else {
        debug!("RLIMIT_NOFILE is unlimited; the fd budget cannot be exceeded");
        return;
    };

    if fd_budget_is_tight(limit, limits.max_connections, limits.max_targets_per_conn) {
        warn!(
            fd_soft_limit = limit,
            max_connections = limits.max_connections,
            max_targets_per_conn = limits.max_targets_per_conn,
            needed = fd_budget(limits.max_connections, limits.max_targets_per_conn),
            "RLIMIT_NOFILE leaves no room for limits.max_connections x \
             limits.max_targets_per_conn: clients at their quotas can exhaust the \
             process. Raise LimitNOFILE (systemd) or lower either limit."
        );
    }
}

/// Whether `limit` descriptors are too few for every connection at its full
/// quota.
///
/// Split out from the warning so the arithmetic is testable without changing the
/// process's actual limit.
fn fd_budget_is_tight(limit: u64, max_connections: u32, max_targets_per_conn: u32) -> bool {
    limit < fd_budget(max_connections, max_targets_per_conn)
}

/// Descriptors the configured limits allow to be open at once.
///
/// `max_connections = 0` means no cap on connections at all, which makes the
/// product meaningless; the check falls back to one connection's quota there,
/// which is the weakest claim that is still true. `Config::warnings` already
/// says what removing that cap costs, and this is not the place to say it twice.
fn fd_budget(max_connections: u32, max_targets_per_conn: u32) -> u64 {
    let connections = u64::from(max_connections.max(1));
    connections * u64::from(max_targets_per_conn) + FD_HEADROOM
}

/// One direction of the endpoint socket's buffer, with the names its messages
/// need.
///
/// The two directions differ only in which setsockopt they use and which sysctl
/// caps them, so they are one code path with this as the parameter rather than
/// two near-identical ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketBuffer {
    /// `SO_RCVBUF`: what the kernel holds for us until the endpoint reads it.
    Recv,
    /// `SO_SNDBUF`: what the kernel holds for us until the interface sends it.
    Send,
}

impl SocketBuffer {
    /// The `[limits]` key that asks for this buffer.
    fn key(self) -> &'static str {
        match self {
            Self::Recv => "limits.socket_recv_buffer",
            Self::Send => "limits.socket_send_buffer",
        }
    }

    /// The Linux sysctl that caps what may be asked for.
    fn ceiling_sysctl(self) -> &'static str {
        match self {
            Self::Recv => "net.core.rmem_max",
            Self::Send => "net.core.wmem_max",
        }
    }
}

/// What the kernel reports the endpoint socket's buffers are, after being asked.
///
/// Carried from [`Server::bind`] to [`Server::run`] for one reason: the startup
/// line prints them. They are also the only place the granted sizes are visible
/// at all, since neither quinn nor this module reads them again.
#[derive(Debug, Clone, Copy, Default)]
struct SocketBuffers {
    /// `SO_RCVBUF` as the kernel reports it, or `None` if it would not say.
    recv: Option<usize>,
    /// `SO_SNDBUF` as the kernel reports it, or `None` if it would not say.
    send: Option<usize>,
}

impl SocketBuffers {
    /// Asks for the configured sizes and reads back what the kernel granted.
    fn request(socket: &std::net::UdpSocket, limits: &crate::config::Limits) -> Self {
        let socket = SockRef::from(socket);

        Self {
            recv: request_socket_buffer(&socket, SocketBuffer::Recv, limits.socket_recv_buffer),
            send: request_socket_buffer(&socket, SocketBuffer::Send, limits.socket_send_buffer),
        }
    }
}

/// Asks the kernel for `requested` bytes of buffer and reports what it granted.
///
/// The socket half of the pair; [`socket_buffer_was_capped`] is the judgement,
/// kept separate so both of its answers can be tested without a socket.
///
/// Nothing here is fatal, and that is deliberate. A refused `setsockopt` leaves
/// the socket exactly where it was — on the operating system's default, which is
/// where every release before this one ran — so refusing to start over it would
/// trade a working server for a tuning preference.
///
/// Two ways a host can decline. It can clamp, which is what both hosts we build
/// for do: Linux at `net.core.rmem_max`, macOS at `kern.ipc.maxsockbuf` (8 MiB
/// by default, measured on Darwin 24). Or it can fail the call outright, which
/// older macOS releases are documented to do above the same ceiling and which
/// costs nothing to handle. Both endings are warned about and neither stops the
/// server; `0` asks for nothing at all, the escape hatch for a host whose
/// operator has already sized these elsewhere.
fn request_socket_buffer(
    socket: &SockRef<'_>,
    which: SocketBuffer,
    requested: usize,
) -> Option<usize> {
    let refused = if requested == 0 {
        false
    } else {
        let asked = match which {
            SocketBuffer::Recv => socket.set_recv_buffer_size(requested),
            SocketBuffer::Send => socket.set_send_buffer_size(requested),
        };

        match asked {
            Ok(()) => false,
            Err(error) => {
                warn!(
                    key = which.key(),
                    requested,
                    %error,
                    "the kernel refused the UDP socket buffer {} asks for, so the socket \
                     keeps the operating system default. Lower the value, or raise this \
                     host's ceiling ({} on Linux, kern.ipc.maxsockbuf on macOS).",
                    which.key(),
                    which.ceiling_sysctl(),
                );
                true
            }
        }
    };

    let granted = match which {
        SocketBuffer::Recv => socket.recv_buffer_size(),
        SocketBuffer::Send => socket.send_buffer_size(),
    };
    let granted = match granted {
        Ok(granted) => granted,
        Err(error) => {
            debug!(
                key = which.key(),
                %error,
                "could not read back the UDP socket buffer size"
            );
            return None;
        }
    };

    // Skipped after a refusal: that path has already said its piece, and the
    // read-back would only repeat it in different words.
    if requested > 0 && !refused && socket_buffer_was_capped(requested, granted) {
        warn!(
            key = which.key(),
            requested,
            actual = granted,
            "the kernel granted less UDP socket buffer than {} asks for: a burst that \
             outruns this socket is dropped there, silently, and has to be sent again. \
             Raise this host's ceiling (sysctl -w {}=<bytes> on Linux, \
             kern.ipc.maxsockbuf on macOS) or lower {} so it stops asking for more than \
             the host allows.",
            which.key(),
            which.ceiling_sysctl(),
            which.key(),
        );
    }

    Some(granted)
}

/// Whether the kernel granted less buffer than was asked for.
///
/// Split out from the socket I/O so both answers can be asserted on without one,
/// and written as `<` rather than `!=` deliberately: Linux reports back **twice**
/// the size it granted, because `SO_RCVBUF`'s accounting includes per-packet
/// overhead, while macOS reports the number unchanged. An equality check would
/// call every Linux host truncated — including the ones that got exactly what
/// they asked for.
fn socket_buffer_was_capped(requested: usize, granted: usize) -> bool {
    granted < requested
}

/// Aggregate flow-control window for one connection, in bytes.
///
/// The bound on what an *unauthenticated* peer can make this process hold.
/// quinn's own default is `VarInt::MAX` — no aggregate limit at all — and with
/// this server's raised stream limit that is 1024 x the 2 MiB
/// [`STREAM_RECEIVE_WINDOW`], so a single connection could pin 2 GiB of receive
/// buffer before we ever see a request to authenticate: open the streams, fill
/// each window, stop. On a 1 GB VPS one connection is enough to end the process.
///
/// The cap only constrains data that has arrived and not yet been read, and both
/// tunnel pumps read continuously, so it binds exactly when the target is slower
/// than the client — which is the case that should be bounded.
///
/// 16 MiB against the 2 MiB per-stream window: eight simultaneously saturated
/// tunnels still get their full stream windows, while the worst case stops being
/// a function of `max_streams_bidi`.
pub const CONNECTION_RECEIVE_WINDOW: VarInt = VarInt::from_u32(16 * 1024 * 1024);

/// Per-stream flow-control window, in bytes.
///
/// A deliberate raise above quinn's own default of 1,250,000, not inherited from
/// it and not a pin at it. No RFC constrains the value — RFC 9000 §4.2 leaves the
/// amount of credit to implementations outright, and §4.3 only observes the
/// consequence of getting it wrong: an endpoint that "cannot ensure that its peer
/// always has available flow control credit that is greater than the peer's
/// bandwidth-delay product" finds "its receive throughput will be limited by flow
/// control". That is advice, not a requirement, and it is the whole of the case.
/// The production path's BDP — a 100 Mbps client uplink over a 95 ms RTT — is
/// about 1.19 MB, so quinn's default sat at roughly 1.05x it: exactly one BDP,
/// with no margin for a window update still in flight. 2 MiB is about 1.75x.
/// Measured corroboration: the peer we interoperate with sizes its own side far
/// higher still, Surge's ClientHello advertising
/// `initial_max_stream_data_bidi_local` = 12 MiB per stream.
///
/// Not a memory decision. [`CONNECTION_RECEIVE_WINDOW`] is the real bound — the
/// invariant is that (the sum of the highest offsets received) minus (the bytes
/// read) stays within it — so a larger per-stream window cannot raise the
/// per-connection worst case, which is unchanged at 16 MiB. What this value
/// actually decides is how few simultaneously saturated tunnels it takes to spend
/// the whole connection's credit — 16 MiB / 2 MiB = 8 — which is a fairness
/// property rather than a memory one, and 8:1 is still far more conservative than
/// the 1.33:1 the peer itself runs (16 MiB of `initial_max_data` against 12 MiB
/// per stream). The per-tunnel ceiling in the download direction is whatever the
/// client advertises to us and is not settable here.
pub const STREAM_RECEIVE_WINDOW: VarInt = VarInt::from_u32(2 * 1024 * 1024);

/// quinn's own default per-stream receive window, in bytes.
///
/// Not a value this server uses — [`STREAM_RECEIVE_WINDOW`] is what reaches the
/// wire — but the number the reasoning there is written against, so it is stated
/// once and checked by `quinn_has_not_moved_the_defaults_we_quote` rather than
/// left as a claim in prose that a dependency bump could quietly falsify.
#[cfg(test)]
const QUINN_DEFAULT_STREAM_RECEIVE_WINDOW: u64 = 1_250_000;

/// Aggregate unacknowledged outbound stream data per connection, in bytes.
///
/// The mirror image of [`CONNECTION_RECEIVE_WINDOW`], and the only bound on what
/// this process buffers for a client that has stopped reading. 10 MB over the
/// ~90 ms path RTT is about 889 Mbps against a measured peak of 177 Mbps, so it
/// is nowhere near a throughput constraint.
///
/// Set to exactly what quinn already defaults to, so it changes not a byte on the
/// wire today. It is pinned rather than inherited because upstream derives that
/// default from `STREAM_RWND`, a private constant inside quinn's
/// `TransportConfig::default` with no stability guarantee, while the arithmetic
/// above is quoted against it. Dependabot proposes cargo bumps weekly; a patch
/// release that moved that constant would leave the documented numbers quietly
/// false. Setting the value here makes them true by construction instead of by
/// inheritance.
///
/// Note the asymmetry it leaves: 16 MiB of inbound credit granted against a
/// 10 MB outbound cap, on a proxy whose traffic is mostly outbound. That is an
/// accepted decision, not an oversight — lifting the outbound cap to match would
/// add roughly 1.6 GiB of theoretical worst case across `max_connections` (256 by
/// default) in exchange for throughput we cannot measure a need for.
pub const SEND_WINDOW: u64 = 10_000_000;

/// Inbound QUIC DATAGRAM bytes the transport buffers per connection.
///
/// Exactly what quinn already defaults to, and stated here for the reason D47
/// gives for [`SEND_WINDOW`]: upstream derives it from `STREAM_RWND`, a private
/// constant inside `TransportConfig::default` with no stability promise, and
/// Dependabot proposes cargo bumps weekly. A patch release that moved that
/// constant would move this buffer with it and change what an unauthenticated
/// peer can make this process hold, silently and without a line of this tree
/// changing.
///
/// It is 1.25 MB per connection, 320 MB across the default `max_connections`,
/// and every byte of it is reachable before a credential has been seen: quinn
/// buffers whatever the peer sends, `serve_peer` drains the queue, and before
/// authentication every datagram in it is routed to the `Unroutable` drop
/// because the session table is empty. Small next to the 16 MiB of
/// [`CONNECTION_RECEIVE_WINDOW`] beside it, which is why the value is kept
/// rather than lowered; what was missing was the pin, not a different number.
///
/// Not `None`, which would disable inbound datagrams altogether and with them
/// CONNECT-UDP, and not a `[limits]` key, for D47's reason: three coupled
/// numbers that operations can diagnose neither failure mode of.
const DATAGRAM_RECEIVE_BUFFER: usize = 1_250_000;

/// Out-of-order CRYPTO frame bytes the transport buffers per connection.
///
/// Pinned at quinn's own 16 KiB, on the same argument as
/// [`DATAGRAM_RECEIVE_BUFFER`]: it is held by a peer that has authenticated
/// nothing, so it belongs in the inventory of what an unauthenticated
/// connection costs, and an inventory that reads a dependency's private default
/// is not an inventory. 16 KiB is ample for the one client flight this server
/// ever reassembles, a ClientHello, which is 1.2 KB and up with a
/// post-quantum key share.
const CRYPTO_BUFFER_SIZE: usize = 16 * 1024;

/// Descriptors assumed to be needed beyond the tunnel quota: the endpoint
/// socket, the request streams, stdio, and the certificate reads a reload does.
pub const FD_HEADROOM: u64 = 64;

/// Unidirectional streams a peer may have open on one connection at a time.
///
/// HTTP/3 gives a client exactly three of them — the control stream and the
/// QPACK encoder/decoder pair (RFC 9114 §6.2, RFC 9204 §4.2) — and Surge opens
/// those three and nothing else. Everything past them is either an unknown type,
/// which RFC 9114 §6.2 has this server abort rather than reject, or a second
/// stream of a kind that may only be opened once, which is a connection error.
/// So no client that behaves needs a fourth, and a peer that opens them anyway
/// costs a task each while it says nothing.
///
/// Sixteen rather than three: this is a transport parameter, so exceeding it is
/// a QUIC-level failure with no application-level explanation attached, and the
/// margin means an ordinary client can only meet it by doing something the
/// HTTP/3 layer would refuse anyway. The number this replaces is quinn's own
/// default of 100, which this server had never taken a position on — the bidi
/// limit beside it has been a configuration key all along (review L3).
pub const MAX_PEER_UNI_STREAMS: u32 = 16;

/// Bidirectional streams a peer may have open before it has authenticated.
///
/// `[limits] max_streams_bidi` is what an authenticated connection is worth —
/// one stream per tunnel, 1024 of them by default — and it used to be what the
/// transport parameters advertised at the handshake, which handed it to every
/// peer that could complete one. So a client that had proved nothing could open
/// 1024 request streams at once and draw a 407 on each: 1024 parked request
/// tasks and 1024 refusals written for a peer with no credentials. Neither
/// bound that already applied there is a bound on *concurrency* — D77's 1 MiB
/// HEADERS budget bounds bytes buffered, D76's absolute deadline bounds time —
/// so nothing measured the one quantity that was free.
///
/// It is also work this process pays for at the wrong moment. quinn reserves a
/// stream slot for every unit of the allowance when the connection is
/// *created*, not when a stream is opened (see `docs/configuration.md`), so the
/// configured value was a per-handshake cost that a peer never had to
/// authenticate to impose. Clamping moves it to the first request that gets
/// past the door.
///
/// Sixteen, the same number as [`MAX_PEER_UNI_STREAMS`] and for the same kind
/// of reason: margin over what the protocol needs rather than the minimum,
/// because running into a transport parameter is a QUIC-level stall with no
/// application-level explanation attached. It happens to be exactly D77's
/// budget as well — sixteen field sections at the 64 KiB per-frame cap is the
/// 1 MiB a connection may buffer — so what an unauthenticated peer can hold in
/// HEADERS is now bounded twice over by the same number.
///
/// # Why it cannot stall a client that bursts
///
/// A client may fire several CONNECTs the moment the handshake completes,
/// before the first 200 comes back, and more than sixteen of them would find
/// the seventeenth blocked rather than refused — STREAMS_BLOCKED, which is
/// backpressure and not an error. What unblocks it is the first of the sixteen
/// to authenticate, and that is decided before any name is resolved and any
/// socket is opened (`conn::handle_request`), so the raise happens in the same
/// task that read the first HEADERS and its MAX_STREAMS rides the packet
/// carrying that request's response. The seventeenth tunnel therefore waits the
/// round trip the client was already waiting for its first answer, once per
/// connection, and only on a connection that opens more than sixteen tunnels
/// before any of them is answered. Below that this is never reached at all.
///
/// Closing streams returns credit before authentication too, which is what
/// keeps a well-behaved unauthenticated peer moving at all — RFC 9000 §4.6
/// leaves that to the receiver ("this document leaves implementations to decide
/// when and how many streams should be advertised to a peer via MAX_STREAMS.
/// Implementations might choose to increase limits as streams are closed"), and
/// quinn announces one only once an eighth of the window has come back, so three
/// closes rather than one. That is why the raise is what a burst waits on and
/// not the churn.
///
/// Which is also why the raise is not conditioned on hearing from the peer. The
/// same section: "An endpoint MUST NOT wait to receive this signal before
/// advertising additional credit, since doing so will mean that the peer will be
/// blocked for at least an entire round trip, and potentially indefinitely if
/// the peer chooses not to send STREAMS_BLOCKED frames."
pub const INITIAL_BIDI_STREAMS: u32 = 16;

/// How long to wait for `CONNECTION_CLOSE` frames to be flushed on shutdown.
///
/// `pub(crate)` for [`crate::shutdown::blocking_grace`], which adds it to the
/// grace period: the two together are the whole of what the async side of the
/// shutdown may spend, and the wait for the blocking pool is measured against
/// the same total.
pub(crate) const CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use proptest::prelude::*;

    /// How long a thread blocked on the swap is given to prove it is blocked.
    ///
    /// Nothing in the green direction depends on it: a reload waiting for the
    /// lock waits for as long as the test holds it. It is there for the red
    /// direction, where a reload that does not take the lock has to have
    /// finished before the assertions run, and parsing a configuration file and
    /// a certificate is milliseconds.
    const SETTLE: Duration = Duration::from_millis(300);

    /// A bound server, and the files it was built from so a reload has
    /// something new to read.
    struct Bound {
        server: Server,
        config_path: PathBuf,
        cert: PathBuf,
        key: PathBuf,
    }

    /// Writes a configuration file naming `cert` and `key`, with `extra` after
    /// the `[server]` keys.
    fn write_config(path: &Path, cert: &Path, key: &Path, extra: &str) {
        std::fs::write(
            path,
            format!(
                "[server]\nlisten = \"127.0.0.1:0\"\ncert = {:?}\nkey = {:?}\n{extra}",
                cert.display().to_string(),
                key.display().to_string(),
            ),
        )
        .expect("write the configuration file");
    }

    /// Binds a real endpoint on an ephemeral loopback port.
    ///
    /// The reload race is between [`Server::drain`] and
    /// [`ReloadHandle::reload`], and both of those are methods on the real
    /// thing, so the test drives the real thing: a certificate on disk, a
    /// configuration file `reload` can re-read, and an endpoint whose server
    /// configuration those two write.
    fn bound_server(extra: &str) -> Bound {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("a self-signed certificate");

        // Distinct per call, not per instant: two tests minting in the same
        // microsecond would otherwise share a directory.
        static MINTED: AtomicU64 = AtomicU64::new(0);
        let serial = MINTED.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("volto-quic-test-{}-{serial}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the directory");

        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, issued.cert.pem()).expect("write the certificate");
        std::fs::write(&key, issued.signing_key.serialize_pem()).expect("write the key");

        let config_path = dir.join("config.toml");
        write_config(&config_path, &cert, &key, extra);
        let config = Config::load(&config_path).expect("the test configuration loads");

        Bound {
            server: Server::bind(Arc::new(config)).expect("bind the test endpoint"),
            config_path,
            cert,
            key,
        }
    }

    /// Starts a reload on its own thread, and answers when it has begun.
    fn reload_on_another_thread(
        handle: ReloadHandle,
        path: PathBuf,
    ) -> std::thread::JoinHandle<Result<Arc<Config>>> {
        let (started, has_started) = std::sync::mpsc::channel();
        let reloading = std::thread::spawn(move || {
            started.send(()).expect("announce the reload");
            handle.reload(&path)
        });
        has_started.recv().expect("the reload thread started");
        std::thread::sleep(SETTLE);
        reloading
    }

    /// A reload that has not got the swap yet has applied none of its writes.
    ///
    /// The three are the SNI gate's list, the live `Config` and the endpoint's
    /// server configuration, and a connection accepted between any two of them
    /// runs on one generation's transport parameters beside another's
    /// credentials and policy for its whole life. Under the swap they are one
    /// step, which is what D22 means by no half-applied state.
    #[tokio::test]
    async fn a_reload_applies_none_of_its_writes_before_it_has_the_swap() {
        let bound = bound_server(
            "[limits]\nmax_streams_bidi = 64\n\
             [security]\nexpected_sni = [\"localhost\"]\n",
        );
        write_config(
            &bound.config_path,
            &bound.cert,
            &bound.key,
            "[limits]\nmax_streams_bidi = 32\n\
             [security]\nexpected_sni = [\"other.example\"]\n",
        );

        let swapping = bound.server.swap.hold();
        let reloading =
            reload_on_another_thread(bound.server.reload_handle(), bound.config_path.clone());

        assert_eq!(
            bound.server.config().limits.max_streams_bidi,
            64,
            "a reload waiting for the swap must not have replaced the live configuration"
        );
        assert!(
            bound.server.expected.current().accepts("localhost"),
            "nor the gate's list"
        );
        assert!(
            !bound.server.expected.current().accepts("other.example"),
            "nor the gate's list"
        );

        drop(swapping);
        reloading
            .join()
            .expect("the reload thread")
            .expect("the reload applies once the swap is free");

        assert_eq!(bound.server.config().limits.max_streams_bidi, 32);
        assert!(bound.server.expected.current().accepts("other.example"));
    }

    /// A connection is not accepted between two of a reload's writes.
    ///
    /// The mirror of the test above, from the accept side. `Server::serve`
    /// takes two reads that decide what one connection runs on, the live
    /// `Config` and, through `IntoFuture for quinn::Incoming`, the endpoint's
    /// server configuration, and until this batch it took neither under the
    /// swap. A reload landing between them gave that connection one
    /// generation's users beside another's transport parameters for its whole
    /// life, which is the tear D22's 2026-09-04 addendum recorded as narrowed
    /// rather than closed.
    ///
    /// Deterministic because the test holds the swap the reload holds, in place
    /// of racing one. The accept is stood in for by a future that needs no
    /// peer: what is under test is that the pair waits.
    #[tokio::test]
    async fn a_connection_is_not_accepted_between_two_of_a_reloads_writes() {
        let bound = bound_server("[limits]\nmax_streams_bidi = 64\n");
        write_config(
            &bound.config_path,
            &bound.cert,
            &bound.key,
            "[limits]\nmax_streams_bidi = 32\n",
        );

        let swapping = bound.server.swap.hold();
        let (snapshotted, has_snapshotted) = std::sync::mpsc::channel();

        std::thread::scope(|scope| {
            scope.spawn(|| {
                let (config, _accepted) =
                    bound.server.accept_under_the_swap(std::future::ready(()));
                snapshotted
                    .send(config.limits.max_streams_bidi)
                    .expect("report what the connection was accepted on");
            });

            assert!(
                has_snapshotted.recv_timeout(SETTLE).is_err(),
                "a connection accepted while a reload holds the swap must wait for it"
            );

            // The write the reload makes to the live configuration, while the
            // accept waits for the rest of them.
            *bound
                .server
                .config
                .write()
                .unwrap_or_else(PoisonError::into_inner) =
                Arc::new(Config::load(&bound.config_path).expect("the new configuration loads"));
            drop(swapping);

            assert_eq!(
                has_snapshotted
                    .recv_timeout(SETTLE)
                    .expect("the accept completes once the swap is free"),
                32,
                "a connection accepted after the reload runs on the new configuration"
            );
        });
    }

    /// A reload cannot re-open the listener the drain has just closed.
    ///
    /// D22: "a listener that `drain` has just closed must not be reopened".
    /// `reload` reads the shutdown latch and then writes, so before the swap a
    /// `SIGTERM` landing between the two put the endpoint back to accepting
    /// handshakes for the whole grace period, with quinn's unaccepted
    /// `Incoming` queue growing behind it. The sequential case is
    /// `it_reload::a_reload_during_the_shutdown_drain_is_refused`; this is the
    /// racing one, made deterministic by holding the swap the drain holds.
    #[tokio::test]
    async fn a_reload_racing_the_drain_cannot_reopen_the_listener() {
        let bound = bound_server("[limits]\nmax_streams_bidi = 64\n");
        write_config(
            &bound.config_path,
            &bound.cert,
            &bound.key,
            "[limits]\nmax_streams_bidi = 32\n",
        );

        let swapping = bound.server.swap.hold();
        let reloading =
            reload_on_another_thread(bound.server.reload_handle(), bound.config_path.clone());

        // What `Server::drain` does under this same guard, in its order.
        bound.server.endpoint.set_server_config(None);
        bound.server.trigger.fire();
        drop(swapping);

        let error = reloading
            .join()
            .expect("the reload thread")
            .expect_err("a reload that resumes after the drain must be refused");
        assert!(
            format!("{error:#}").contains("shutting down"),
            "the refusal must say why: {error:#}"
        );
        assert_eq!(
            bound.server.config().limits.max_streams_bidi,
            64,
            "a refused reload changes nothing"
        );
    }

    /// Renders the built transport parameters for inspection.
    ///
    /// `TransportConfig` has no getters, but its `Debug` prints every field, and
    /// asserting on that is enough to pin the values that matter.
    fn transport_debug(limits: &crate::config::Limits) -> String {
        format!("{:?}", transport_config(limits).expect("valid limits"))
    }

    /// The bound that stops one unauthenticated connection from exhausting the
    /// host's memory (audit 2026-08, finding 1.1a).
    ///
    /// quinn's default is `receive_window: VarInt::MAX` — no aggregate limit —
    /// which with 1024 streams of 2 MiB each is 2 GiB per connection, reachable
    /// before any request is authenticated.
    #[test]
    fn the_connection_receive_window_is_bounded() {
        let rendered = transport_debug(&crate::config::Limits::default());

        // Anchored on the separator: `stream_receive_window` ends in the same
        // characters, so the bare substring could pass on the wrong field should
        // the two ever hold the same value.
        assert!(
            rendered.contains(", receive_window: 16777216"),
            "the aggregate receive window must be capped at 16 MiB: {rendered}"
        );
        assert!(
            !rendered.contains(&format!("receive_window: {}", u64::from(VarInt::MAX))),
            "the unbounded quinn default must not survive: {rendered}"
        );
    }

    /// Both windows really reach the transport parameters, so an edit here cannot
    /// silently drop them.
    #[test]
    fn the_stream_and_send_windows_are_set() {
        let rendered = transport_debug(&crate::config::Limits::default());

        assert!(
            rendered.contains("stream_receive_window: 2097152"),
            "the per-stream receive window must stay at 2 MiB, the value the BDP and \
             fairness arithmetic in this module is quoted against: {rendered}"
        );
        assert!(
            rendered.contains("send_window: 10000000"),
            "the outbound send window must stay at 10 MB, the only bound on what we \
             buffer for a client that stops reading: {rendered}"
        );
    }

    /// The two buffers that used to be inherited really reach the wire.
    ///
    /// Both are held by a peer that has authenticated nothing, so what they are
    /// set to is part of what an unauthenticated connection costs; see
    /// [`DATAGRAM_RECEIVE_BUFFER`] and [`CRYPTO_BUFFER_SIZE`].
    #[test]
    fn the_datagram_and_crypto_buffers_are_stated_rather_than_inherited() {
        let rendered = transport_debug(&crate::config::Limits::default());

        assert!(
            rendered.contains(&format!(
                "datagram_receive_buffer_size: Some({DATAGRAM_RECEIVE_BUFFER})"
            )),
            "the inbound datagram buffer must be the pinned 1.25 MB: {rendered}"
        );
        assert!(
            rendered.contains(&format!("crypto_buffer_size: {CRYPTO_BUFFER_SIZE}")),
            "the out-of-order CRYPTO buffer must be the pinned 16 KiB: {rendered}"
        );
    }

    /// quinn's own defaults still agree with what this module says about them.
    ///
    /// The drift alarm covers two different claims, neither of which can change
    /// behaviour any more — both values reaching the wire are set explicitly —
    /// but either of which a cargo bump could turn into a false comment, and
    /// Dependabot proposes those weekly. [`SEND_WINDOW`] is genuinely pinned at
    /// quinn's default, so a moved default would invalidate the pin's own
    /// justification. [`STREAM_RECEIVE_WINDOW`] is no longer a pin — it is a
    /// deliberate raise — so quinn's value is not asserted against *ours*; what is
    /// asserted is [`QUINN_DEFAULT_STREAM_RECEIVE_WINDOW`], the number the BDP
    /// arithmetic there compares 2 MiB to.
    #[test]
    fn quinn_has_not_moved_the_defaults_we_quote() {
        let rendered = format!("{:?}", quinn::TransportConfig::default());

        assert!(
            rendered.contains(&format!("send_window: {SEND_WINDOW}")),
            "a quinn bump changed the default send window: our pin is unaffected, but \
             the comments in this module that call it quinn's default need \
             re-checking: {rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "stream_receive_window: {QUINN_DEFAULT_STREAM_RECEIVE_WINDOW}"
            )),
            "a quinn bump changed the default per-stream receive window: we no longer \
             use it, but STREAM_RECEIVE_WINDOW is justified as a raise above it, so \
             that arithmetic needs re-checking: {rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "datagram_receive_buffer_size: Some({DATAGRAM_RECEIVE_BUFFER})"
            )),
            "a quinn bump changed the default inbound datagram buffer: our pin is \
             unaffected, but it was chosen as a pin at that default, so the choice \
             needs re-making rather than inheriting silently: {rendered}"
        );
        assert!(
            rendered.contains(&format!("crypto_buffer_size: {CRYPTO_BUFFER_SIZE}")),
            "a quinn bump changed the default CRYPTO reassembly buffer: as above, \
             our pin holds and the reason for the number needs re-checking: {rendered}"
        );
    }

    /// What the handshake advertises is the clamp, not `max_streams_bidi`.
    ///
    /// The shipped default is 1024, and finding it here would mean every peer
    /// that can complete a handshake is handed a thousand request streams
    /// before it has proved anything; see [`INITIAL_BIDI_STREAMS`]. Asserted on
    /// the default limits rather than on a contrived pair, because the default
    /// is the configuration that ships.
    #[test]
    fn the_handshake_advertises_the_initial_stream_allowance() {
        let limits = crate::config::Limits::default();
        assert!(
            limits.max_streams_bidi > INITIAL_BIDI_STREAMS,
            "the default must be above the clamp for this to be measuring anything: {}",
            limits.max_streams_bidi
        );

        let rendered = transport_debug(&limits);
        assert!(
            rendered.contains(&format!(
                "max_concurrent_bidi_streams: {INITIAL_BIDI_STREAMS}"
            )),
            "an unauthenticated peer must be advertised the clamp: {rendered}"
        );
    }

    /// The clamp only ever lowers: an operator who wants fewer gets fewer.
    ///
    /// `min` rather than a flat constant, so a configuration below the clamp is
    /// honoured from the handshake onwards rather than being quietly raised to
    /// sixteen for as long as the connection went unauthenticated.
    #[test]
    fn a_configured_allowance_below_the_clamp_is_not_raised_to_it() {
        for configured in [1, 7, INITIAL_BIDI_STREAMS] {
            let limits = crate::config::Limits {
                max_streams_bidi: configured,
                ..Default::default()
            };
            assert_eq!(
                initial_bidi_streams(&limits),
                configured,
                "a configured allowance of {configured} must reach the wire as itself"
            );
        }

        assert_eq!(
            initial_bidi_streams(&crate::config::Limits {
                max_streams_bidi: INITIAL_BIDI_STREAMS + 1,
                ..Default::default()
            }),
            INITIAL_BIDI_STREAMS,
            "and one above it must not"
        );
    }

    /// The configured limits really reach the transport parameters.
    ///
    /// `max_streams_bidi` is the one that does not reach them as itself: 7 is
    /// below [`INITIAL_BIDI_STREAMS`], so it is what an unauthenticated peer is
    /// advertised, and the clamp's own two tests are above.
    #[test]
    fn configured_limits_reach_the_transport_config() {
        let limits = crate::config::Limits {
            max_streams_bidi: 7,
            initial_mtu: 1350,
            mtu_upper_bound: 1464,
            initial_rtt_ms: 150,
            ..Default::default()
        };

        let rendered = transport_debug(&limits);
        assert!(
            rendered.contains("max_concurrent_bidi_streams: 7"),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "max_concurrent_uni_streams: {MAX_PEER_UNI_STREAMS}"
            )),
            "the peer's unidirectional stream limit is ours to state, not quinn's \
             to default (review L3): {rendered}"
        );
        assert!(
            rendered.contains("1350"),
            "the initial MTU must apply: {rendered}"
        );
        assert!(
            rendered.contains("upper_bound: 1464"),
            "the discovery ceiling must apply: {rendered}"
        );
        assert!(
            rendered.contains("initial_rtt: 150ms"),
            "the initial RTT must apply: {rendered}"
        );
    }

    proptest::proptest! {
        /// Property 2: whatever validation accepts, this can be built from (D86).
        ///
        /// The other half of the invariant `crate::config`'s properties state:
        /// a value that passes validation must not be able to fail — or panic —
        /// on its way into a `quinn::TransportConfig`, which is where every
        /// `[limits]` key that reaches the transport ends up. The generator
        /// clamps into the accepted space rather than filtering, so it stacks
        /// cases on the boundaries; that its output really is accepted is
        /// asserted here rather than assumed, so the two statements of the
        /// ranges cannot drift apart silently. Run in a debug build, where
        /// arithmetic overflow is a panic rather than a wrap.
        #[test]
        fn every_accepted_limits_builds_a_transport_config(
            limits in crate::config::tests::valid_limits()
        ) {
            let config = crate::config::tests::config_with(limits.clone());
            prop_assert!(
                crate::config::tests::valid_apart_from_certs(&config),
                "the generator produced limits validation rejects: {:?}",
                config.validate().err()
            );

            prop_assert!(transport_config(&limits).is_ok());
        }
    }

    /// The check has to fire on the configuration that actually bites: a macOS
    /// default limit of 256 with the default quota of 256, where one connection
    /// at its quota consumes every descriptor the process has.
    ///
    /// And on the shipped quotas under a 65536-descriptor limit, which is the
    /// case that made the old single-connection arithmetic wrong (review M7):
    /// 256 connections x 256 tunnels is that limit exactly, so the defaults
    /// leave not one descriptor of headroom and the check said nothing. That
    /// pairing is synthetic now that the shipped unit sets 131072, and is kept
    /// because the product landing on the limit is the tightest case there is.
    #[test]
    fn a_tight_fd_budget_is_recognised() {
        assert!(fd_budget_is_tight(256, 1, 256), "the macOS default pairing");
        assert!(fd_budget_is_tight(1024, 1, 1024));
        assert!(fd_budget_is_tight(64, 1, 1));

        let defaults = crate::config::Limits::default();
        assert!(
            fd_budget_is_tight(
                65536,
                defaults.max_connections,
                defaults.max_targets_per_conn
            ),
            "the shipped quotas against a limit their product meets exactly: {} \
             x {} leaves nothing over",
            defaults.max_connections,
            defaults.max_targets_per_conn
        );
    }

    /// `max_connections = 0` is "no cap", which has no product to check, so the
    /// budget falls back to one connection's quota rather than to zero.
    #[test]
    fn an_uncapped_connection_count_falls_back_to_one_connection() {
        assert_eq!(fd_budget(0, 256), fd_budget(1, 256));
        assert!(!fd_budget_is_tight(1024, 0, 256));
        assert!(fd_budget_is_tight(256, 0, 256));
    }

    /// The read-back convention differs by platform, so the judgement is written
    /// as `<` and has to stay that way.
    ///
    /// Linux reports twice what it granted; macOS reports it unchanged. The two
    /// middle cases below are the ones an equality check would get wrong.
    #[test]
    fn a_capped_socket_buffer_is_recognised() {
        // Linux, request satisfied: doubled on the way back.
        assert!(!socket_buffer_was_capped(2 * 1024 * 1024, 4 * 1024 * 1024));
        // macOS, request satisfied: reported unchanged.
        assert!(!socket_buffer_was_capped(2 * 1024 * 1024, 2 * 1024 * 1024));
        // Linux, clamped at a stock `net.core.rmem_max` of 212992.
        assert!(socket_buffer_was_capped(2 * 1024 * 1024, 425_984));
        // The socket left on an untouched default while a size was asked for.
        assert!(socket_buffer_was_capped(2 * 1024 * 1024, 212_992));
    }

    /// A size every host allows is granted, in both directions.
    ///
    /// 128 KiB, not the 2 MiB default, and the difference is the whole point:
    /// GitHub's runners ship `net.core.rmem_max` = 212992, so asserting that the
    /// default is obtained would fail on CI while saying nothing about this code.
    /// What is under test is that a request the host *can* satisfy comes back
    /// classified as satisfied — on either platform's read-back convention.
    #[test]
    fn a_modest_socket_buffer_request_is_granted() {
        const MODEST: usize = 128 * 1024;

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a UDP socket");
        let socket = SockRef::from(&socket);

        for which in [SocketBuffer::Recv, SocketBuffer::Send] {
            let granted =
                request_socket_buffer(&socket, which, MODEST).expect("the kernel reports the size");
            assert!(
                !socket_buffer_was_capped(MODEST, granted),
                "{which:?}: 128 KiB is below every stock ceiling, but the kernel \
                 reported {granted}"
            );
        }
    }

    /// A size no host allows is reported as not granted, however it was declined.
    ///
    /// A host may clamp the request (Linux at `net.core.rmem_max`, macOS at
    /// `kern.ipc.maxsockbuf`) or fail the `setsockopt` outright and leave the
    /// default in place, and the assertion deliberately does not say which — that
    /// is a property of the host, not of this code. Both endings must arrive at
    /// "we did not get what we asked for", because that is the one condition the
    /// startup warning is built on.
    #[test]
    fn an_absurd_socket_buffer_request_is_seen_as_capped() {
        const ABSURD: usize = 1024 * 1024 * 1024;

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a UDP socket");
        let socket = SockRef::from(&socket);

        for which in [SocketBuffer::Recv, SocketBuffer::Send] {
            let granted =
                request_socket_buffer(&socket, which, ABSURD).expect("the kernel reports the size");
            assert!(
                socket_buffer_was_capped(ABSURD, granted),
                "{which:?}: 1 GiB cannot have been granted, but the kernel reported \
                 {granted}"
            );
        }
    }

    /// `0` is the escape hatch: the socket is left exactly as the OS made it.
    ///
    /// Measured against a second, untouched socket rather than a constant,
    /// because the default is a host property (and a doubled one on Linux).
    #[test]
    fn a_zero_socket_buffer_request_leaves_the_socket_alone() {
        let asked = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a UDP socket");
        let untouched = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a UDP socket");
        let asked = SockRef::from(&asked);
        let untouched = SockRef::from(&untouched);

        assert_eq!(
            request_socket_buffer(&asked, SocketBuffer::Recv, 0),
            untouched.recv_buffer_size().ok(),
            "a zero receive buffer request must not touch the socket"
        );
        assert_eq!(
            request_socket_buffer(&asked, SocketBuffer::Send, 0),
            untouched.send_buffer_size().ok(),
            "a zero send buffer request must not touch the socket"
        );
    }

    /// Builds the controller a `[limits] congestion_control` value selects and
    /// names its concrete type.
    ///
    /// `TransportConfig` keeps the factory behind a private field that its `Debug`
    /// does not print, so [`transport_debug`] — which pins every other transport
    /// parameter — cannot see this one at all. `Controller::into_any` exists for
    /// exactly this downcast.
    fn controller_type_of(cc: crate::config::CongestionControl) -> &'static str {
        let built = congestion_factory(cc).build(std::time::Instant::now(), 1200);
        let any = built.into_any();

        if any.is::<quinn::congestion::Bbr>() {
            "bbr"
        } else if any.is::<quinn::congestion::Cubic>() {
            "cubic"
        } else if any.is::<quinn::congestion::NewReno>() {
            "newreno"
        } else {
            "unknown"
        }
    }

    /// Every `congestion_control` value selects the controller it names.
    #[test]
    fn each_congestion_control_value_selects_its_controller() {
        use crate::config::CongestionControl;

        for (value, expected) in [
            (CongestionControl::Bbr, "bbr"),
            (CongestionControl::Cubic, "cubic"),
            (CongestionControl::NewReno, "newreno"),
        ] {
            assert_eq!(controller_type_of(value), expected, "{value:?}");
        }
    }

    /// The default really is BBR, all the way to the built controller.
    ///
    /// The one assertion in this module with a production incident behind it. quinn
    /// defaults to CUBIC, so losing this mapping — a mis-edited match arm, a
    /// default that stops being BBR — lands on a loss-based controller, and a
    /// loss-based controller collapses the download direction of the production
    /// path to near-zero while leaving upload, CPU and every log line looking
    /// normal. Nothing else in the suite can tell the two apart. (What this cannot
    /// see is `transport_config` ceasing to call `congestion_factory` at all; that
    /// call is one line away and reviewed with it.)
    #[test]
    fn the_default_congestion_controller_is_bbr() {
        let limits = crate::config::Limits::default();

        assert_eq!(
            limits.congestion_control,
            crate::config::CongestionControl::Bbr,
            "the default must stay BBR"
        );
        assert_eq!(
            controller_type_of(limits.congestion_control),
            "bbr",
            "the default limits must build a BBR controller, not quinn's CUBIC"
        );
    }

    // -----------------------------------------------------------------------
    // The roster
    // -----------------------------------------------------------------------

    /// A documentation address (RFC 5737 §3) with `n` in its last octet.
    fn peer(n: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, n], 443))
    }

    /// A gate a request has already passed, for the rosters that are about what
    /// an authenticated connection is owed.
    fn authenticated_gate() -> AuthGate {
        let gate = AuthGate::closed();
        assert!(gate.mark(), "the first pass through a gate is the first");
        gate
    }

    /// Registers `count` connections that have never authenticated, keeping the
    /// registrations alive: dropping one gives its slot straight back.
    fn park(roster: &Roster, count: u8) -> Vec<Registration> {
        (0..count)
            .map(|n| {
                let (_evict, registration) = roster.register(peer(n), AuthGate::closed());
                registration
            })
            .collect()
    }

    /// A cap that has just been lowered is caught up with, not lived over.
    ///
    /// One eviction per arrival is all a server sitting at a steady cap needs.
    /// A `SIGHUP` that lowers `max_connections` below the number of connections
    /// already live is the case that is not steady: `serve_forever` reads the cap
    /// per accepted connection, so the newcomer is judged against the new value
    /// while everybody already in was admitted under the old one, and without
    /// the loop inside `evict_until_below` -- the accept path's own, called here
    /// rather than copied -- the roster would sit above the new cap for as long
    /// as those connections lasted.
    ///
    /// Five live and a cap of two leaves room for the newcomer, so four go: the
    /// loop stops at one, and the arrival that runs it makes two.
    #[test]
    fn a_lowered_cap_evicts_until_there_is_room() {
        let roster = Roster::new();
        let _parked = park(&roster, 5);

        assert_eq!(
            roster.evict_until_below(2),
            vec![peer(0), peer(1), peer(2), peer(3)],
            "the victims must be the oldest four, oldest first"
        );
        assert_eq!(roster.len(), 1, "one slot is left for the newcomer");
    }

    /// The loop stops when there is nothing left it may take.
    ///
    /// An authenticated connection is never a candidate, so a roster of them is
    /// what makes the accept loop refuse rather than spin.
    #[test]
    fn eviction_stops_when_every_connection_has_authenticated() {
        let roster = Roster::new();

        let mut held = Vec::new();
        for n in 0..3 {
            let (_evict, registration) = roster.register(peer(n), authenticated_gate());
            held.push(registration);
        }

        assert!(
            roster.evict_until_below(1).is_empty(),
            "an authenticated connection must never lose its slot"
        );
        assert_eq!(roster.len(), 3, "and must still be on the roster");
    }

    /// Why the accept loop asks whether there is a cap before applying one.
    ///
    /// `max_connections = 0` means "no limit", and the guard in `serve_forever`
    /// is the whole of that meaning. Handed to this arithmetic as a number, zero
    /// is the harshest cap there could be -- every roster is at or above it -- so
    /// each arrival would empty the roster and then be refused for finding it
    /// still full. The configuration would mean the opposite of what it says.
    #[test]
    fn a_cap_of_zero_would_empty_the_roster_if_it_were_ever_applied() {
        let roster = Roster::new();
        let _parked = park(&roster, 3);

        assert_eq!(roster.evict_until_below(0), vec![peer(0), peer(1), peer(2)]);
        assert_eq!(
            roster.len(),
            0,
            "and then there would be nobody left to refuse"
        );
    }

    /// A signal sent before the victim is listening must not be lost.
    ///
    /// A slot is taken in `serve` before the connection's task has polled
    /// anything, so an eviction can arrive between the registration and the
    /// `select!` that waits on it. `Notify::notify_one` leaves a permit behind
    /// for exactly that, and the whole pre-handshake eviction path rests on it:
    /// with a plain channel send, or a `Notify` whose permit did not persist,
    /// the victim would wait out its handshake deadline instead.
    #[tokio::test]
    async fn an_eviction_that_arrives_first_is_still_delivered() {
        let roster = Roster::new();
        let (evict, _registration) = roster.register(peer(0), AuthGate::closed());

        assert_eq!(evict_oldest_from(&mut roster.slots()), Some(peer(0)));

        // Nothing was awaiting the signal when it was sent, and it is still
        // there to be collected.
        tokio::time::timeout(std::time::Duration::from_secs(5), evict.notified())
            .await
            .expect("the permit `notify_one` stored must outlive the send");
    }

    /// An eviction a lost `select!` race consumed is still delivered to the
    /// next wait.
    ///
    /// `serve` waits on this signal *twice* — once beside the QUIC handshake,
    /// once beside the whole connection — and the two waits are separate
    /// futures. So there is a window nothing else in this file covers: the
    /// eviction lands while the first wait is parked, `Notify` hands the
    /// notification to that waiter, and then the handshake completes in the
    /// same wake-up and wins the race. The first wait is dropped holding a
    /// notification it never returned.
    ///
    /// If that were lost, the victim would keep running until its own idle
    /// timeout rather than "as long as one poll takes", which is what the
    /// [`Roster`] documentation promises and what an operator reading
    /// `max_connections` is owed. `Notify` puts an unclaimed notification back
    /// as a permit when its waiter is dropped, and this pins that: the whole
    /// two-wait design rests on it and nothing said so.
    ///
    /// Polled through a bare waker rather than awaited, so the assertion is
    /// about the permit being there and not about a runtime getting round to
    /// it.
    #[tokio::test]
    async fn an_eviction_a_lost_race_consumed_is_still_delivered() {
        use std::task::{Context as TaskContext, Poll, Waker};

        let roster = Roster::new();
        let (evict, _registration) = roster.register(peer(0), AuthGate::closed());

        let mut cx = TaskContext::from_waker(Waker::noop());

        // The wait beside the handshake, parked.
        let mut first = Box::pin(evict.notified());
        assert_eq!(first.as_mut().poll(&mut cx), Poll::Pending);

        // The eviction arrives while it is parked, and is handed to it.
        assert_eq!(evict_oldest_from(&mut roster.slots()), Some(peer(0)));

        // The other arm of that `select!` wins the wake-up: this one is dropped
        // without ever being polled again.
        drop(first);

        // The wait beside the connection must still find it.
        let mut second = Box::pin(evict.notified());
        assert_eq!(
            second.as_mut().poll(&mut cx),
            Poll::Ready(()),
            "an eviction was swallowed by the wait that lost the race"
        );
    }

    /// A dropped registration gives the slot back, and takes nobody else's.
    ///
    /// The guard is what makes the cap survive the several ways a connection
    /// task can end, and sequence numbers are never reused, so a late drop can
    /// only ever remove its own entry — including after an eviction has already
    /// removed it.
    #[test]
    fn a_registration_gives_back_only_its_own_slot() {
        let roster = Roster::new();
        let mut parked = park(&roster, 3);

        // The middle one leaves of its own accord.
        let middle = parked.remove(1);
        drop(middle);
        assert_eq!(roster.len(), 2);

        // The oldest is evicted, and its guard is dropped afterwards: the entry
        // is already gone, and the drop must not reach the third connection's.
        assert_eq!(evict_oldest_from(&mut roster.slots()), Some(peer(0)));
        drop(parked.remove(0));
        assert_eq!(roster.len(), 1);
        assert_eq!(
            evict_oldest_from(&mut roster.slots()),
            Some(peer(2)),
            "the survivor must be the one nobody gave up"
        );
    }

    #[test]
    fn a_roomy_fd_budget_is_left_alone() {
        // The Ubuntu default, and the dev host, against a single connection.
        assert!(!fd_budget_is_tight(1024, 1, 256));
        assert!(!fd_budget_is_tight(1_048_576, 1, 256));
        // Exactly the headroom, and one better.
        assert!(!fd_budget_is_tight(FD_HEADROOM + 8, 1, 8));
        assert!(fd_budget_is_tight(FD_HEADROOM + 7, 1, 8));
        // The product is what the limit is compared against: eight connections
        // of eight tunnels need eight times as many descriptors as one does.
        assert!(!fd_budget_is_tight(FD_HEADROOM + 64, 8, 8));
        assert!(fd_budget_is_tight(FD_HEADROOM + 63, 8, 8));
        // The shipped defaults, with the headroom the docs ask an operator for.
        assert!(!fd_budget_is_tight(131_072, 256, 256));
    }
}
