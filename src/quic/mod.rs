//! The QUIC endpoint: transport parameters, the accept loop and peer metadata.

mod reload;
mod roster;
mod socket;
mod transport;

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::task::Poll;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use quinn::VarInt;
use quinn::crypto::rustls::HandshakeData;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::gate::{Expected, Gate, Names};
use crate::shutdown::{self, Shutdown, Trigger};
use crate::{conn, h3api};

pub use reload::ReloadHandle;
pub use socket::FD_HEADROOM;
pub(crate) use transport::admit_configured_streams;
pub use transport::{
    AuthGate, CONNECTION_RECEIVE_WINDOW, INITIAL_BIDI_STREAMS, MAX_PEER_UNI_STREAMS, SEND_WINDOW,
    STREAM_RECEIVE_WINDOW,
};

use reload::{ConfigSwap, LiveConfig, LiveQuicConfig, server_config};
use roster::Roster;
use socket::{RequestedBuffers, SocketBuffers, warn_if_fd_budget_is_tight};

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
            // Moved rather than cloned: the first element has finished
            // borrowing `data` by the time this one is evaluated, and this is
            // one `String` per accepted connection.
            data.server_name,
        ),
        None => (None, None),
    };

    PeerInfo {
        remote: conn.remote_address(),
        alpn,
        server_name,
    }
}

/// Starting one arriving connection's handshake on a stated configuration.
///
/// One method, so that [`Server::accept_under_the_swap`] can be exercised with
/// no peer on the other end. It was `IntoFuture` until the server configuration
/// became something this process chooses rather than something quinn reads for
/// itself. What the regression test has to observe now is the argument, and
/// `IntoFuture::into_future` takes none.
trait AcceptWith {
    /// The handshake, once started.
    type Accepted;

    /// Answers the peer's Initial and starts the handshake on `server_config`.
    fn accept_with(self, server_config: Arc<quinn::ServerConfig>) -> Self::Accepted;
}

impl AcceptWith for quinn::Incoming {
    type Accepted = Handshake;

    fn accept_with(self, server_config: Arc<quinn::ServerConfig>) -> Handshake {
        // quinn's own inherent method of the same name, which a path call
        // reaches ahead of this trait's.
        Handshake(quinn::Incoming::accept_with(self, server_config))
    }
}

/// A handshake `quinn::Incoming::accept_with` has started, awaited like a
/// `Connecting`.
///
/// quinn's `IncomingFuture` is exactly this and cannot be built from outside:
/// its field is private and `IntoFuture for Incoming` is the only way to reach
/// it, which is the call this replaces. The `Result` is resolved before the
/// future exists, and that is what keeps the accept eager: by the time anything
/// polls this, quinn has answered the client's Initial and the TLS server flight
/// is on its way. [`Server::serve`] depends on that and says so.
struct Handshake(Result<quinn::Connecting, quinn::ConnectionError>);

impl std::future::Future for Handshake {
    type Output = Result<quinn::Connection, quinn::ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        match &mut self.0 {
            // `Connecting` is `Unpin`, which is how quinn polls it inside
            // `IncomingFuture` as well.
            Ok(connecting) => Pin::new(connecting).poll(cx),
            // Cloned rather than taken, so that a second poll answers the same
            // error instead of panicking. Nothing here polls twice; this is the
            // shape quinn's own adapter has.
            Err(error) => Poll::Ready(Err(error.clone())),
        }
    }
}

/// A bound QUIC endpoint ready to accept connections.
pub struct Server {
    endpoint: quinn::Endpoint,
    /// What the kernel granted for the endpoint socket's buffers, for the
    /// startup line. Fixed at bind time: nothing reloadable can change it.
    socket_buffers: SocketBuffers,
    /// The socket buffer sizes `[limits]` asked for at bind, for the one thing
    /// a reload has to say about them; see [`RequestedBuffers`].
    requested_buffers: RequestedBuffers,
    config: LiveConfig,
    /// The `quinn::ServerConfig` an accept runs a connection on; see
    /// [`LiveQuicConfig`].
    ///
    /// Written beside `config` and under the same guard, so the two halves of
    /// what one connection gets cannot come from two generations.
    quic_config: LiveQuicConfig,
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
        // The other copy, the one every accept runs a connection on. Taken here
        // so the slot and the endpoint start on the same generation, which is
        // the invariant `reload` then maintains. `quinn::ServerConfig` is a set
        // of `Arc`s, so this is a few reference counts and the two copies share
        // the transport parameters, the certificate and the token key.
        let accepted_with = Arc::new(quic_config.clone());

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
            requested_buffers: RequestedBuffers {
                recv: config.limits.socket_recv_buffer,
                send: config.limits.socket_send_buffer,
            },
            listen: config.server.listen,
            config: Arc::new(RwLock::new(config)),
            quic_config: Arc::new(RwLock::new(accepted_with)),
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

    /// The `server.shutdown_grace` in force now, which a reload may have moved.
    ///
    /// Read from the live configuration rather than from a copy taken at bind,
    /// because `server.shutdown_grace` is a reloadable key and both readers have
    /// to see the same value: `Server::drain` bounds the drain with it, and
    /// `main` bounds the blocking pool with it after the runtime has stopped.
    /// [`crate::shutdown::blocking_grace`] states that as an invariant.
    pub fn shutdown_grace(&self) -> Duration {
        self.config().server.shutdown_grace()
    }

    /// A handle that replaces the running configuration.
    ///
    /// The binary hands this to its `SIGHUP` handler; tests call it directly.
    pub fn reload_handle(&self) -> ReloadHandle {
        ReloadHandle {
            endpoint: self.endpoint.clone(),
            config: self.config.clone(),
            quic_config: self.quic_config.clone(),
            shutdown: self.shutdown.clone(),
            expected: self.expected.clone(),
            swap: self.swap.clone(),
            requested_buffers: self.requested_buffers,
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

    /// A snapshot of the `quinn::ServerConfig` currently in force.
    ///
    /// The other half of [`Self::config`], and read in the same breath as it by
    /// [`Self::accept_under_the_swap`]; poisoning is treated the same way and
    /// for the same reason.
    fn quic_config(&self) -> Arc<quinn::ServerConfig> {
        self.quic_config
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
            log_id = "77jqt7xj",
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
        /// `limits.max_connections` as the roster counts, which is a `usize`.
        ///
        /// Saturating rather than truncating, though neither is reachable: a
        /// `u32` is always a `usize` on both supported targets, and a cap that
        /// did not fit would be a cap no roster could ever reach.
        fn live_ceiling(max_connections: u32) -> usize {
            usize::try_from(max_connections).unwrap_or(usize::MAX)
        }

        // Read per accepted connection rather than snapshotted before the
        // loop: `docs/deployment.md#reloading` promises a reload applies to
        // connections accepted from then on, and lowering this cap during an
        // incident is exactly the sort of thing that promise is for. The cost
        // is an `Arc` load on a path that is already opening a QUIC
        // connection.
        let max_connections = self.config().limits.max_connections;

        // Zero is no cap at all, so nothing below is measured and the roster is
        // not even asked for its length.
        if max_connections == 0 {
            return Some(incoming);
        }
        let ceiling = live_ceiling(max_connections);

        // The roster rather than the `JoinSet`: a slot is entered before the
        // QUIC handshake starts and given up by a guard, so the roster counts
        // exactly the connections that hold one. The set is kept for draining,
        // and its length *leads* the roster rather than trailing it -- a task
        // that has finished but not been reaped has already dropped its
        // registration, and an evicted one leaves the roster before its task
        // ends, so the set holds everything the roster does and sometimes
        // more.
        //
        // Read once and reused by the two log lines below, which takes one
        // mutex acquisition off every arrival at the cap, the path a flood
        // takes.
        let live = self.roster.len();
        if live < ceiling {
            return Some(incoming);
        }

        // Read before `retry()` or `refuse()` consumes the `Incoming`, so
        // either branch can still name the peer.
        let remote = incoming.remote_address();

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
        //
        // Deliberately not given the slot `accept_under_the_swap` reads, because
        // quinn has no `retry_with`. quinn-proto seals the Retry token with the
        // `token_key` of the configuration it pinned to this `Incoming` when the
        // Initial arrived, and validates the returning token against the
        // configuration the endpoint holds when that token arrives. Neither read
        // can be reached from here.
        //
        // The two keys differ when a `SIGHUP` lands between the Retry and the
        // returning Initial, because `server_config` builds every configuration
        // with `ServerConfig::with_crypto`, which draws a fresh `token_key`
        // each time (quinn-proto 0.11.x `src/config/mod.rs`,
        // `ServerConfig::with_crypto`). A Retry token that crosses a `SIGHUP`
        // then fails to decode under the new key, and quinn-proto treats the
        // returning Initial as carrying no token. That connection attempt
        // fails; it does not cost one more round trip the way a NEW_TOKEN token
        // does in the paragraph above. If the server is still full, `admit`
        // sends a second Retry, and the client discards it:
        //
        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
        //# A client MUST accept and process at most one Retry packet for each
        //# connection attempt.
        //
        // The client keeps resending its Initial, each one draws another
        // Retry, and the attempt ends at the client's idle timeout. If the
        // server is no longer full, the connection is accepted with the Retry's
        // source connection ID as its original destination connection ID and
        // with no retry source connection ID, and the client closes it with
        // TRANSPORT_PARAMETER_ERROR. Either way the client has to start a new
        // attempt. This needs the server to be full and a reload to land inside
        // one round trip. Keeping one key across reloads would remove it: a key
        // drawn once and set with `ServerConfig::token_key` (quinn-proto 0.11.x
        // `src/config/mod.rs`) on every build, with one `ValidationTokenConfig`
        // shared across builds so that its log of used NEW_TOKEN tokens
        // survives too. That is not done, because D31 records key rotation on
        // reload as the current behaviour.
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
        for victim in self.roster.evict_until_below(ceiling) {
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
        if self.roster.len() >= ceiling {
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
    /// and the timeouts. The second is [`LiveQuicConfig`], which carries the
    /// transport parameters and the certificate. Both are read here, under
    /// [`ConfigSwap`], and the second is handed straight to
    /// `Incoming::accept_with`, so the pair cannot straddle a `SIGHUP`. A
    /// connection accepted while a reload is applying waits for it and then runs
    /// wholly on one generation.
    ///
    /// Reading the second one here is the whole point of the slot. What quinn
    /// would otherwise use is the copy quinn-proto 0.11.x took from the
    /// endpoint when this connection's first Initial arrived, which a `SIGHUP`
    /// in between makes a generation old: `Incoming::accept()`, which
    /// `IntoFuture for Incoming` calls, passes no configuration, and
    /// `proto::Endpoint::accept` then falls back to
    /// `incoming_buffer.server_config` (quinn-proto 0.11.x `src/endpoint.rs`,
    /// `Endpoint::accept`, `server_config.unwrap_or_else(..)`). That window
    /// opens in the endpoint driver, where no lock in this file reaches, so it
    /// is closed by stating the value rather than by ordering the read (D22,
    /// addendum of 2026-09-17).
    ///
    /// The guard covers two synchronous reads and the synchronous half of the
    /// accept, and no await. `Incoming::accept_with` answers the client's
    /// Initial before it returns, which [`Self::serve`] depends on.
    ///
    /// Generic over [`AcceptWith`] rather than over `quinn::Incoming` so the
    /// regression test can attempt the pair with no peer on the other end and
    /// read back what the accept was handed; `serve` is the only caller that
    /// passes a `quinn::Incoming`.
    fn accept_under_the_swap<I: AcceptWith>(&self, incoming: I) -> (Arc<Config>, I::Accepted) {
        let _swapping = self.swap.hold();
        (self.config(), incoming.accept_with(self.quic_config()))
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
    /// What that drop is *not* is a refusal. The `Incoming` was accepted by
    /// [`Self::accept_under_the_swap`] before this task existed, and
    /// `Incoming::accept_with` returns a `Connecting`, so by the time either arm
    /// of the select below can run there is a `Connecting` rather than an
    /// `Incoming`: quinn has answered the client's Initial and the TLS server
    /// flight is already on its way. [`Handshake`] is the wrapper that carries
    /// it here, and it starts nothing of its own.
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
                log_id = "7l4svyo3",
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
        // "New" counts from the first Initial. A handshake quinn had already
        // queued as an `Incoming` keeps the server configuration it arrived
        // under (quinn-proto 0.11.x), so this call neither completes nor
        // refuses it. Nothing here ever accepts one: the accept loop has left by
        // the time this runs, and a queued `Incoming` goes away with the
        // endpoint.
        //
        // Deliberately not paired with a write to `self.quic_config`. That slot
        // exists for `accept_under_the_swap`, which is the only thing that reads
        // it, and by the time this runs the accept loop it belongs to has
        // returned. Emptying it would mean making it an `Option` and giving that
        // method a branch nothing can take.
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

        let grace = self.shutdown_grace();
        info!(
            log_id = "7x7xt92f",
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
            info!(
                log_id = "85kda9tt",
                "every connection finished within the grace period"
            );
        } else {
            warn!(
                log_id = "89143be4",
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
/// lists cannot drift apart. They carry the same eleven fields and differ in
/// two, `log_id` and `reason` against `error`, which is what makes an operator
/// able to grep one journal for both -- and what a second copy of a list this
/// long invites losing, as D72's traffic counters would have been had they
/// landed on only one of them.
///
/// `closed` is graded from the error *value* rather than from
/// `Connection::close_reason()`, for the reason [`Server::serve`] gives where it
/// is decided.
///
/// # What the fields report
///
/// `mtu` is the packet size DPLPMTUD settled on in this direction — a report,
/// not a knob: it is here so an operator can see whether discovery ever got
/// past `initial_mtu` on their path. On a connection that lived long enough to
/// probe, a value still at the floor means the probes went unanswered (the
/// shape a path that black-holes large packets has) or a black hole was
/// detected later and discovery fell back; anything above it is discovery
/// having done its job.
///
/// `mtu_black_holes` counts how often quinn's black-hole detector fired and
/// pushed the packet size back to the floor for its cooldown. It is what tells
/// those two apart when `mtu` alone cannot: discovery may have climbed back by
/// the time the connection ends, hiding a fall-back that a bulk transfer in the
/// middle paid for. quinn's detector is a heuristic over loss bursts, and a
/// burst of full-size packets lost to ordinary congestion looks the same to it
/// as a path that stopped carrying them, so a non-zero count on a path that
/// other connections probe fine is the signature of a false positive rather
/// than of the path.
///
/// `tunnels` is how many requests on this connection were granted a tunnel slot
/// — TCP CONNECT and CONNECT-UDP alike — so a connection that only ever failed
/// authentication reports zero.
///
/// `dropped_datagrams` is how many inbound HTTP Datagrams the connection's
/// router dropped instead of delivering — an unknown Context ID, a Quarter
/// Stream ID no session claims, a session whose inbound queue was full, or a
/// datagram cut short of its Context ID. Each drop is silent where it happens,
/// because the RFCs ask for exactly that, so this total is the only trace a
/// misdirected or over-fast sender leaves in production. Distinct from
/// `lost_packets`, which is the QUIC path losing what was sent; these arrived
/// fine and were dropped on purpose.
///
/// `tx_bytes` and `rx_bytes` are UDP-level byte counts: everything this
/// endpoint put on or took off the wire for this connection, QUIC and HTTP/3
/// framing, retransmissions, ACKs and padding included. They are neither tunnel
/// payload — always smaller — nor bytes the peer acknowledged, since a packet
/// is counted when it is sent whether or not it arrived, so they answer "how
/// much did this connection move through this host" and nothing finer.
/// `sent_packets` and `lost_packets` are reported together because a loss rate
/// needs both: either number alone says nothing about the path (D72).
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
                log_id = "8ro19wv6",
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
                log_id = "9pds6tk6",
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

/// How long to wait for `CONNECTION_CLOSE` frames to be flushed on shutdown.
///
/// `pub(crate)` for [`crate::shutdown::blocking_grace`], which adds it to the
/// grace period: the two together are the whole of what the async side of the
/// shutdown may spend, and the wait for the blocking pool is measured against
/// the same total.
pub(crate) const CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

// `shutdown::blocking_grace` adds this to a grace period an operator may set to
// zero, and the drain that precedes it may equally have nothing to wait for. At
// zero here a shutdown would leave the endpoint no time at all to put the
// CONNECTION_CLOSE it just wrote on the wire.
const _: () = assert!(!CLOSE_FLUSH_TIMEOUT.is_zero());

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use quinn::crypto::rustls::QuicServerConfig;

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

    /// The grace a reload raises is the grace the exit bound gets.
    ///
    /// `Server::drain` and `main` both ask for it, and `shutdown::blocking_grace`
    /// states that the blocking pool gets the whole allowance the connections
    /// got. That is only true while both read the live configuration: `main`
    /// read the startup value until 2026-09-07, so a `SIGHUP` that raised the
    /// key raised the drain and not the exit bound.
    #[tokio::test]
    async fn a_reload_moves_the_grace_the_exit_is_bounded_by() {
        let bound = bound_server("");
        assert_eq!(
            bound.server.shutdown_grace(),
            Duration::from_secs(crate::config::DEFAULT_SHUTDOWN_GRACE),
            "the grace the process started on"
        );

        write_config(
            &bound.config_path,
            &bound.cert,
            &bound.key,
            "shutdown_grace = 300\n",
        );
        bound
            .server
            .reload_handle()
            .reload(&bound.config_path)
            .expect("the raised grace reloads");

        assert_eq!(
            bound.server.shutdown_grace(),
            Duration::from_secs(300),
            "the grace in force after the reload"
        );
    }

    /// A reload that has not got the swap yet has applied none of its writes.
    ///
    /// The four are the SNI gate's list, the live `Config`, the
    /// `quinn::ServerConfig` slot an accept reads and the endpoint's own copy,
    /// and a connection accepted between any two of them runs on one
    /// generation's transport parameters beside another's credentials and
    /// policy for its whole life. Under the swap they are one step, which is
    /// what D22 means by no half-applied state. The endpoint's copy has no
    /// getter, so the test reads the other three.
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
        let before = bound.server.quic_config();

        let swapping = bound.server.swap.hold();
        let reloading =
            reload_on_another_thread(bound.server.reload_handle(), bound.config_path.clone());

        assert_eq!(
            bound.server.config().limits.max_streams_bidi,
            64,
            "a reload waiting for the swap must not have replaced the live configuration"
        );
        assert!(
            Arc::ptr_eq(&bound.server.quic_config(), &before),
            "nor the server configuration an accept reads"
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
        assert!(
            !Arc::ptr_eq(&bound.server.quic_config(), &before),
            "the reload replaces the server configuration an accept reads"
        );
    }

    /// A `quinn::Incoming` stand-in that needs no peer on the other end.
    ///
    /// Records the `quinn::ServerConfig` it was accepted with, which is the
    /// half of `accept_under_the_swap` that `std::future::ready(())` could not
    /// observe: until the accept took a configuration of its own there was no
    /// argument to look at.
    struct Arriving(Arc<Mutex<Option<Arc<quinn::ServerConfig>>>>);

    impl Arriving {
        /// A stand-in, and the slot it writes what it was handed into.
        fn new() -> (Self, Arc<Mutex<Option<Arc<quinn::ServerConfig>>>>) {
            let recorded = Arc::new(Mutex::new(None));
            (Self(recorded.clone()), recorded)
        }
    }

    impl AcceptWith for Arriving {
        type Accepted = std::future::Ready<()>;

        fn accept_with(self, server_config: Arc<quinn::ServerConfig>) -> Self::Accepted {
            *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(server_config);
            std::future::ready(())
        }
    }

    /// A connection is not accepted between two of a reload's writes, and it is
    /// accepted with the server configuration the reload installed.
    ///
    /// The mirror of the test above, from the accept side. `Server::serve` takes
    /// two reads that decide what one connection runs on, the live `Config` and
    /// the `quinn::ServerConfig`, and until the 2026-09-05 batch it took neither
    /// under the swap. A reload landing between them gave that connection one
    /// generation's users beside another's transport parameters for its whole
    /// life, which is the tear D22's 2026-09-04 addendum recorded as narrowed
    /// rather than closed.
    ///
    /// The `Arc::ptr_eq` pair at the end is the 2026-09-17 half. The swap
    /// orders the two reads, and that alone stopped deciding the transport
    /// parameters when quinn-proto 0.11.18 began pinning a pending `Incoming`
    /// to the configuration the endpoint held as its first Initial arrived. So
    /// the accept states the configuration rather than letting quinn pick one,
    /// and what this pins is that the value stated is the one the reload wrote
    /// and not the one it replaced.
    ///
    /// Deterministic because the test holds the swap the reload holds, in place
    /// of racing one. The accept is stood in for by [`Arriving`]: what is under
    /// test is that the pair waits, and what it is handed when it stops waiting.
    #[tokio::test]
    async fn a_connection_is_not_accepted_between_two_of_a_reloads_writes() {
        let bound = bound_server("[limits]\nmax_streams_bidi = 64\n");
        write_config(
            &bound.config_path,
            &bound.cert,
            &bound.key,
            "[limits]\nmax_streams_bidi = 32\n",
        );

        // What `bind` put in the slot, so the last assertion can say the accept
        // did not take it.
        let before = bound.server.quic_config();

        let swapping = bound.server.swap.hold();
        let (snapshotted, has_snapshotted) = std::sync::mpsc::channel();
        let (arriving, accepted_with) = Arriving::new();

        std::thread::scope(|scope| {
            scope.spawn(|| {
                let (config, _accepted) = bound.server.accept_under_the_swap(arriving);
                snapshotted
                    .send(config.limits.max_streams_bidi)
                    .expect("report what the connection was accepted on");
            });

            assert!(
                has_snapshotted.recv_timeout(SETTLE).is_err(),
                "a connection accepted while a reload holds the swap must wait for it"
            );

            // The two writes the reload makes to what an accept reads, while the
            // accept waits for the rest of them.
            let reloaded = Config::load(&bound.config_path).expect("the new configuration loads");
            let reloaded_quic =
                Arc::new(server_config(&reloaded).expect("the new certificate is usable"));
            *bound
                .server
                .config
                .write()
                .unwrap_or_else(PoisonError::into_inner) = Arc::new(reloaded);
            *bound
                .server
                .quic_config
                .write()
                .unwrap_or_else(PoisonError::into_inner) = reloaded_quic.clone();
            drop(swapping);

            assert_eq!(
                has_snapshotted
                    .recv_timeout(SETTLE)
                    .expect("the accept completes once the swap is free"),
                32,
                "a connection accepted after the reload runs on the new configuration"
            );

            let handed = accepted_with
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
                .expect("the accept states a server configuration");
            assert!(
                Arc::ptr_eq(&handed, &reloaded_quic),
                "a connection accepted after the reload must be accepted with the \
                 server configuration the reload installed"
            );
            assert!(
                !Arc::ptr_eq(&handed, &before),
                "and not with the one that was in force before it"
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
        let before = bound.server.quic_config();

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
        assert!(
            Arc::ptr_eq(&bound.server.quic_config(), &before),
            "nor the server configuration an accept reads"
        );
    }

    /// A QUIC connection over the loopback whose server side uses `transport`,
    /// returned as the client's side and the server's.
    ///
    /// For the tests here and in `congestion` and `tunnel` that need a real
    /// connection. The certificate is generated here rather than taken from
    /// `tests/common`, which the lib target cannot reach.
    pub(crate) async fn loopback_pair(
        transport: quinn::TransportConfig,
    ) -> (quinn::Connection, quinn::Connection) {
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
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto).expect("quic tls"),
        ));
        server_config.transport_config(Arc::new(transport));

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
        let (connection, accepted) = tokio::join!(
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
        (
            connection.expect("the client side of the handshake"),
            accepted,
        )
    }
}
