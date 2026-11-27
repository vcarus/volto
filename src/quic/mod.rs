//! The QUIC endpoint: transport parameters, the accept loop and peer metadata.

mod cid;
mod reload;
mod roster;
mod socket;
mod transport;

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError, RwLock};
use std::task::Poll;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use quinn::VarInt;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::gate::{Expected, Gate};
use crate::shutdown::{self, Shutdown, Trigger};
use crate::tls::HandshakeData;
use crate::{conn, h3api, tunnel};

pub use reload::ReloadHandle;
pub use socket::FD_HEADROOM;
pub(crate) use transport::admit_configured_streams;
pub use transport::{
    AuthGate, CONNECTION_RECEIVE_WINDOW, INITIAL_BIDI_STREAMS, INITIAL_CONNECTION_RECEIVE_WINDOW,
    MAX_PEER_UNI_STREAMS, MarkOutcome, SEND_WINDOW, STREAM_RECEIVE_WINDOW,
};

use reload::{ConfigSwap, Live, LiveSlot, server_config};
use roster::Roster;
use socket::{RequestedBuffers, SocketBuffers, warn_if_fd_budget_is_tight};

/// What the handshake revealed about a peer, for logging.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The peer's address. Behind a UDP relay this is the relay's address.
    pub remote: SocketAddr,
    /// The negotiated ALPN identifier, lossily decoded for display.
    pub alpn: Option<String>,
    /// The SNI the client sent. The inner name when ECH was accepted.
    pub server_name: Option<String>,
    /// Whether the handshake ran on an accepted ECH extension.
    pub ech: bool,
}

/// Extracts loggable handshake metadata from an established connection.
pub fn peer_info(conn: &quinn::Connection) -> PeerInfo {
    let handshake = conn
        .handshake_data()
        .and_then(|data| data.downcast::<HandshakeData>().ok());

    let (alpn, server_name, ech) = match handshake {
        Some(data) => (
            data.protocol
                .as_deref()
                .map(|p| String::from_utf8_lossy(p).into_owned()),
            // Moved rather than cloned: the first element has finished
            // borrowing `data` by the time this one is evaluated, and this is
            // one `String` per accepted connection.
            data.server_name,
            data.ech_accepted,
        ),
        None => (None, None, false),
    };

    PeerInfo {
        remote: conn.remote_address(),
        alpn,
        server_name,
        ech,
    }
}

/// Starting one arriving connection's handshake on a stated configuration.
///
/// One method, so that [`Server::accept_on_one_generation`] can be exercised with
/// no peer on the other end. What the regression test has to observe is the
/// server configuration argument, and `IntoFuture::into_future` takes none.
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
/// its field is private and `IntoFuture for Incoming`, which takes no server
/// configuration, is the only way to reach it. The `Result` is resolved before the
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

/// How [`Server::run`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "an endpoint that stopped on its own is a failure the caller has to report"]
pub enum Stopped {
    /// The shutdown trigger fired, and the drain ran.
    Shutdown,
    /// `quinn::Endpoint::accept` returned `None` while the trigger had not fired.
    ///
    /// quinn's endpoint driver ends when the socket's receive call returns any
    /// error but `ConnectionReset`, and from then on `accept` returns `None`
    /// (quinn 0.11 `src/endpoint.rs`: `State::drive_recv`, `Drop for
    /// EndpointDriver`, `Accept::poll`). No connection can be accepted or
    /// served after that, and the tasks of the ones still open have been
    /// dropped without a drain. The caller has to end the process with an
    /// error, so that the service manager starts it again (D124).
    EndpointLost,
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
    /// The configuration generation an accept runs a connection on, both
    /// halves in one value; see [`Live`].
    live: LiveSlot,
    /// The connections being served, in accept order, and what the accept loop
    /// decides `max_connections` against; see [`Roster`].
    roster: Roster,
    /// The blocking-pool allowance every connection's name lookups draw on.
    ///
    /// Server-wide because the pool is: what one connection may hold at once is
    /// bounded here so that a client whose targets never resolve cannot park
    /// every thread the process has and starve the rest (D90). Built at bind
    /// time and never reloaded, because it is sized against the runtime the
    /// process was started with, which a `SIGHUP` cannot resize.
    resolver: crate::net::ResolverBudget,
    /// The host names the SNI gate admits, shared with the socket wrapper.
    ///
    /// Held here so [`Server::reload_handle`] can hand it on: the gate lives
    /// under the endpoint, on a socket that a reload cannot rebind, so the list
    /// is the only part of it a `SIGHUP` can move (D106).
    expected: Expected,
    /// Orders a reload against the drain; see [`ConfigSwap`].
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
    /// cannot come from the live configuration either. A reload swaps that
    /// whole value in, so the second reload naming a new address would find
    /// the first one's already there and say nothing.
    listen: SocketAddr,
    /// The `[log].level` the tracing subscriber was built with.
    ///
    /// Kept from bind for the same reason `listen` is: a reload swaps the whole
    /// live configuration in, so a comparison against it would find the
    /// reloaded value already there and say nothing. The subscriber itself is
    /// installed once, in `main`, before this type exists; see [`ReloadHandle`].
    startup_log_level: String,
    /// The ECH keys the server was bound with, for the startup line. A reload
    /// reports its own in the reload line.
    ech: Option<Arc<crate::tls::EchKeySet>>,
}

impl Server {
    /// Binds the UDP socket and prepares the QUIC server configuration.
    ///
    /// `quinn::Endpoint::server` is expanded by hand here, because the socket has
    /// to be reachable between the bind and the endpoint: quinn's own helper is a
    /// bare `std::net::UdpSocket::bind` and never touches `SO_RCVBUF`/`SO_SNDBUF`,
    /// so the socket would keep the kernel's default (D56; see
    /// [`crate::config::DEFAULT_SOCKET_RECV_BUFFER`]). Everything passed to
    /// [`quinn::Endpoint::new_with_abstract_socket`] below is what the helper
    /// passes internally, and none of it may be dropped. The one difference is
    /// the endpoint configuration, which is quinn's default with the connection
    /// ID generator of `cid`, so that the endpoint never sends a Stateless
    /// Reset.
    ///
    /// The second reason for expanding it is [`Gate`], which wraps the socket
    /// the runtime hands back so that a datagram quinn would *answer* can be
    /// refused before quinn sees it (D106). The wrapper is installed whether or
    /// not `[security] expected_sni` is set, because the list is reloadable and
    /// the socket is not: with an empty list every datagram passes through
    /// untouched, and a `SIGHUP` can then turn the gate on without a restart.
    pub fn bind(config: Arc<Config>) -> Result<Self> {
        let (quic_config, ech, policy) = server_config(&config)?;
        // The other copy, the one every accept runs a connection on. Taken here
        // so the slot and the endpoint start on the same generation, which is
        // the invariant `reload` then maintains. `quinn::ServerConfig` is a set
        // of `Arc`s, so this is a few reference counts and the two copies share
        // the transport parameters, the certificate and the token key.
        let live = Arc::new(Live {
            generation: Arc::new(tunnel::Generation::new(config.clone())),
            quic: Arc::new(quic_config.clone()),
        });

        let socket = std::net::UdpSocket::bind(config.server.listen)
            .with_context(|| format!("failed to bind UDP socket {}", config.server.listen))?;

        let socket_buffers = SocketBuffers::request(&socket, &config.limits);

        let runtime = quinn::default_runtime()
            .ok_or_else(|| anyhow!("no async runtime is available for the QUIC endpoint"))?;
        let socket = runtime
            .wrap_udp_socket(socket)
            .context("failed to hand the UDP socket to the async runtime")?;

        let expected = Expected::new(policy);
        let socket = Arc::new(Gate::new(socket, expected.clone()));

        // quinn's default endpoint configuration, with the one change that
        // the endpoint never sends a Stateless Reset; `cid` says why and how.
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            cid::endpoint_config(),
            Some(quic_config),
            socket,
            runtime,
        )
        .context("failed to build the QUIC endpoint over the gated socket")?;

        warn_if_fd_budget_is_tight(&config.limits);

        let (trigger, shutdown) = shutdown::channel();

        // Sized from the same number `main` sized the blocking pool from,
        // before the configuration moves into its lock.
        let resolver = crate::net::ResolverBudget::new(config.limits.max_connections);

        Ok(Self {
            endpoint,
            socket_buffers,
            requested_buffers: RequestedBuffers {
                recv: config.limits.socket_recv_buffer,
                send: config.limits.socket_send_buffer,
            },
            listen: config.server.listen,
            startup_log_level: config.log.level.clone(),
            ech,
            live: Arc::new(RwLock::new(live)),
            roster: Roster::new(),
            resolver,
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
            live: self.live.clone(),
            shutdown: self.shutdown.clone(),
            expected: self.expected.clone(),
            swap: self.swap.clone(),
            requested_buffers: self.requested_buffers,
            listen: self.listen,
            startup_log_level: self.startup_log_level.clone(),
        }
    }

    /// A snapshot of the generation currently in force.
    fn live(&self) -> Arc<Live> {
        // Poisoning would mean a panic while swapping the generation; the value
        // itself is an immutable `Arc`, so it cannot be observed half-written.
        self.live
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// A snapshot of the configuration currently in force.
    fn config(&self) -> Arc<Config> {
        self.live().generation.config.clone()
    }

    /// The address the endpoint is actually bound to.
    ///
    /// Useful when the configured port is 0.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("failed to read the local address of the QUIC endpoint")
    }

    /// A reader of how many connections the endpoint still holds, for the
    /// tests.
    ///
    /// This is quinn's `Endpoint::open_connections`: a connection counts from
    /// its first packet until quinn has drained it and removed its connection
    /// IDs from the endpoint's index. So a count of zero says that a packet of
    /// a finished connection no longer reaches it. The reader holds a clone of
    /// the endpoint, so it can be taken before the server moves into its task.
    /// Nothing in the crate calls it.
    #[doc(hidden)]
    pub fn open_connections(&self) -> impl Fn() -> usize + Send + Sync + 'static {
        let endpoint = self.endpoint.clone();
        move || endpoint.open_connections()
    }

    /// Accepts connections until the endpoint closes or shutdown is triggered,
    /// and says which of the two ended it.
    ///
    /// Each connection is handled in its own task, so a failure only ever affects
    /// that connection. The tasks are tracked in a `JoinSet` rather than detached,
    /// because the shutdown path needs to know when they are finished, and
    /// because dropping the set is what cuts off anything still running once
    /// the grace period is over.
    pub async fn run(&self) -> Stopped {
        let config = self.config();
        info!(
            log_id = "77jqt7xj",
            // The binary's own version, so a journal read after an upgrade
            // says which build produced the lines that follow without having
            // to be matched against the deploy log or a checksum.
            version = env!("CARGO_PKG_VERSION"),
            listen = %config.server.listen,
            alpn = ?config.server.alpn,
            // Empty when the SNI gate is off, which is the shipped default
            // (D106).
            expected_sni = ?config.security.expected_sni,
            grace_secs = config.server.shutdown_grace,
            // The kernel's numbers, not the configured ones: these are what
            // `ss -uanpm` prints as `rb` and `tb`, so a log line and an `ss`
            // reading can be put side by side. Absent when the kernel would not
            // say, which is why they are `Option`s rather than a sentinel.
            so_rcvbuf = self.socket_buffers.recv,
            so_sndbuf = self.socket_buffers.send,
            // Whether ECH is on, under which config_id and public name, and
            // the config_id of the previous key a rotation still accepts.
            // Nothing secret: each is in the ECHConfigList a client holds and
            // in every ClientHello it sends. The public name passed the key
            // file's LDH check, so `Display` is safe.
            ech = self.ech.is_some(),
            ech_config_id = %crate::logfmt::or_dash(self.ech.as_ref().map(|e| e.current().config_id())),
            ech_previous_config_id = %crate::logfmt::or_dash(
                self.ech.as_ref().and_then(|e| e.previous()).map(|e| e.config_id())
            ),
            ech_public_name = %crate::logfmt::or_dash(self.ech.as_ref().map(|e| e.current().public_name())),
            // Whether the gate drops every handshake without ECH (D115).
            require_ech = config.security.require_ech,
            "accepting QUIC connections"
        );

        let mut shutdown = self.shutdown.clone();
        let mut connections = JoinSet::new();

        loop {
            // Reap eagerly rather than only in the select below: with `biased`
            // ordering a steady stream of new connections would starve that
            // branch, and finished tasks would pile up in the set for as long as
            // the stream lasted. The cap does not depend on this (it is decided
            // against the roster, in [`Self::admit`]), so what is at stake is
            // the memory of the join handles and the length of the walk `drain`
            // does at shutdown.
            while connections.try_join_next().is_some() {}

            tokio::select! {
                // Shutdown wins any tie: no point starting work that is about to
                // be torn down.
                biased;

                () = shutdown.fired() => break,

                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        // The endpoint stopped without the trigger; see
                        // `Stopped::EndpointLost` for how.
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
            Stopped::Shutdown
        } else {
            Stopped::EndpointLost
        }
    }

    /// Decides whether an arriving connection may have a slot, and answers
    /// it itself when it may not.
    ///
    /// `Some` is a connection the accept loop should go on and serve. `None`
    /// means this arrival has already been dealt with (asked for a Retry, or
    /// refused), and there is nothing left for the caller to do with it.
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

        // Zero is no cap at all, so nothing below is measured and the roster is
        // not even asked for its length.
        if max_connections == 0 {
            return Some(incoming);
        }
        // The roster counts in `usize`. A `u32` always fits on the supported
        // targets, so the saturation is never reached.
        let ceiling = usize::try_from(max_connections).unwrap_or(usize::MAX);

        // The roster rather than the `JoinSet`: a slot is entered before the
        // QUIC handshake starts and given up by a guard, so the roster counts
        // exactly the connections that hold one. The set is kept for draining,
        // and its length *leads* the roster rather than trailing it. A task
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
        // that has proved nothing does not have it. Otherwise one spoofed
        // Initial per datagram, from addresses that never have to receive
        // anything, could evict every connection on the roster, and every one
        // of those datagrams would start a TLS server flight, since `serve`
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
        // validated, and a client that keeps them (quinn's own default token
        // store does) comes back already validated and evicts without a
        // Retry. The extra round trip falls on an address this server holds
        // no token from: a first contact, a token past its two-week lifetime,
        // or one sealed by a key this process no longer has, since
        // `ServerConfig::with_crypto` draws a fresh one every time
        // `server_config` builds a config, at startup and again on every
        // `SIGHUP`. And it is paid only while the server is full: below the
        // cap this branch is not entered at all, so an ordinary Surge
        // handshake is untouched.
        //
        // quinn has no `retry_with`, so the Retry token is sealed with the
        // `token_key` of the configuration quinn-proto pinned to this
        // `Incoming`, and `with_crypto` draws a fresh key on every `SIGHUP`. A
        // Retry that crosses a reload therefore fails to decode, and if the
        // server is still full the second Retry is discarded by the client:
        //
        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
        //# A client MUST accept and process at most one Retry packet for each
        //# connection attempt.
        //
        // That attempt fails and the client starts a new one. It needs a full
        // server and a reload inside one round trip, and D31 records key
        // rotation on reload as the current behaviour.
        if !incoming.remote_address_validated() {
            match incoming.retry() {
                Ok(()) => {
                    // DEBUG for the same reason the refusal below is: a flood
                    // is exactly when this fires.
                    debug!(
                        %remote,
                        live,
                        max_connections,
                        "the server is full: asking an unvalidated address \
                         to prove itself before it may take a slot"
                    );
                    return None;
                }
                // Unreachable as quinn stands: `retry` fails only when
                // `may_retry()` is false, and quinn documents `may_retry()` as
                // true whenever the address is unvalidated. Handled rather
                // than unwrapped because the fallback is the safe one either
                // way.
                //
                //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.2
                //# In response to processing an Initial packet
                //# containing a token that was provided in a Retry
                //# packet, a server cannot send another Retry
                //# packet; it can only refuse the connection or
                //# permit it to proceed.
                Err(error) => incoming = error.into_incoming(),
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
        // is for as long as it wanted. Each one is bounded, but each one that
        // ends is replaced.
        let (victims, remaining) = self.roster.evict_until_below(ceiling);
        for victim in victims {
            // DEBUG, not INFO: this fires once per arrival for as long as a
            // flood lasts, which is exactly the shape the refusal beside it is
            // DEBUG for. The victim's own closing line stays at INFO: that one
            // is once per connection actually lost, and it is what an operator
            // is looking for.
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
        if remaining >= ceiling {
            debug!(
                %remote,
                live = remaining,
                max_connections,
                "refusing a connection: the server is at its connection limit"
            );
            incoming.refuse();
            return None;
        }
        Some(incoming)
    }

    /// The generation one new connection runs on, and the handshake that runs
    /// it, from one read of [`Live`], so the pair cannot straddle a `SIGHUP`
    /// (D22).
    ///
    /// The quinn half is handed to `Incoming::accept_with` rather than left to
    /// quinn, because quinn would otherwise use the copy quinn-proto 0.11.x
    /// took from the endpoint when this connection's first Initial arrived,
    /// which a `SIGHUP` in between makes a generation old: `Incoming::accept()`
    /// passes no configuration, and `proto::Endpoint::accept` then falls back
    /// to `incoming_buffer.server_config` (`src/endpoint.rs`,
    /// `Endpoint::accept`, `server_config.unwrap_or_else(..)`).
    ///
    /// Synchronous and lock-free apart from the slot's read lock:
    /// `Incoming::accept_with` answers the client's Initial before it returns,
    /// which [`Self::serve`] depends on. Generic over [`AcceptWith`] so a test
    /// can read back what the accept was handed with no peer on the other end.
    fn accept_on_one_generation<I: AcceptWith>(
        &self,
        incoming: I,
    ) -> (Arc<tunnel::Generation>, I::Accepted) {
        let live = self.live();
        (
            live.generation.clone(),
            incoming.accept_with(live.quic.clone()),
        )
    }

    /// Runs one accepted connection to completion.
    ///
    /// Split out of the accept loop so it can be a `'static` future for the
    /// `JoinSet`: everything it needs is cloned up front.
    ///
    /// # The handshake deadline
    ///
    /// The `max_connections` slot is taken by the roster registration below,
    /// before the QUIC and TLS handshake this starts with has happened. So the
    /// cap counts handshakes in progress as well as connections, and something
    /// has to bound the first of those. quinn has no handshake-specific timer: its idle
    /// timeout is reset by any authenticated packet in any packet number space,
    /// so a peer that sends an Initial-space PING every `max_idle_timeout` and
    /// never completes the handshake holds a slot for as long as it likes, and
    /// makes this endpoint retransmit its handshake flight on every PTO
    /// meanwhile. `Connection::handshake`'s deadline does not help either: it
    /// starts one layer later, once there is a connection at all.
    ///
    /// One idle timeout bounds it, for the same reason it bounds the HTTP/3
    /// handshake: a peer that cannot finish a handshake in the time it is
    /// allowed to say nothing at all is not going to finish it. Dropping the
    /// future ends the connection and frees the slot with it.
    ///
    /// What that drop is *not* is a refusal. The `Incoming` was accepted by
    /// [`Self::accept_on_one_generation`] before this task existed, and
    /// `Incoming::accept_with` returns a `Connecting`, so by the time either arm
    /// of the select below can run there is a `Connecting` rather than an
    /// `Incoming`: quinn has answered the client's Initial and the TLS server
    /// flight is already on its way. [`Handshake`] is the wrapper that carries
    /// it here, and it starts nothing of its own.
    /// Dropping a `Connecting` closes the connection the way an application
    /// close does, and RFC 9000 §10.2.3 has an application close sent before the
    /// handshake completes go out as a transport one, so what the peer receives
    /// is `CONNECTION_CLOSE` with APPLICATION_ERROR and an empty reason. That is
    /// not the CONNECTION_REFUSED that `Incoming::refuse` sends, and not silence.
    ///
    /// # Eviction
    ///
    /// The same drop is what an eviction uses. A connection that has never
    /// authenticated may have its slot taken by a newcomer once the server is
    /// full ([`Roster`]), and the signal reaches it here: whichever stage it is
    /// in, its work is dropped. Before the handshake completes that is the
    /// `Connecting` close described above; after it, dropping `conn::handle`'s
    /// future drops the HTTP/3 connection, whose own `Drop` closes the QUIC
    /// connection with H3_NO_ERROR. Nothing went wrong; the slot was owed to
    /// somebody else.
    fn serve(&self, incoming: quinn::Incoming) -> impl std::future::Future<Output = ()> + use<> {
        let remote = incoming.remote_address();

        // Snapshotted per connection, not read live: a reload changes what new
        // connections get, while a connection already running keeps the
        // credentials and policy it started with for its whole life. Anything else
        // would mean a tunnel's rules changing under it mid-transfer.
        let (generation, accepted) = self.accept_on_one_generation(incoming);

        let shutdown = self.shutdown.clone();
        let resolver = self.resolver.per_connection();

        let handshake_deadline = generation.config.limits.max_idle_timeout();

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

            // Created here rather than inside the connection so they survive
            // it: `conn::handle` hands them to the requests and to the HTTP/3
            // datagram router, and they are read below, once, after the
            // connection is over.
            let counts = conn::Counts::default();

            // Written once the handshake completes, so the closing line can tell
            // an eviction during the handshake from one after it. `conn::handle`
            // consumes the connection; the handle kept here lets the close logs
            // report what the connection learned about its path: the RTT it
            // measured, the address the peer ended on, and the MTU.
            // `remote_now` differing from `remote` is the only externally
            // visible trace of a migration or NAT rebind during the
            // connection's life.
            let mut established: Option<(SocketAddr, quinn::Connection)> = None;

            // One wait on the eviction for the whole connection, handshake and
            // all. `select!` drops the connection's future before it runs the
            // eviction arm, so the borrow of `established` has ended there.
            let closed = tokio::select! {
                // The newcomer that took this slot is already being served; all
                // that is left here is to stop. Before the handshake completes,
                // dropping the half-built connection ends it with the
                // `CONNECTION_CLOSE(APPLICATION_ERROR)` this function's
                // documentation describes. After it, the close is graded with
                // the idle endings rather than as an error, because nothing
                // about this connection failed.
                () = evicted.notified() => Some(Ok(CloseReason::Evicted)),

                closed = async {
                    let quic = match tokio::time::timeout(handshake_deadline, accepted).await {
                        Ok(Ok(quic)) => quic,
                        Ok(Err(error)) => {
                            // A failed handshake is routine on a public port:
                            // scanners, version negotiation, stale retries.
                            //
                            // Through `peer_error` because a peer that closes
                            // during the handshake writes the reason phrase
                            // inside this error, and `Display` escapes nothing.
                            // An established connection has the same exposure,
                            // and both use the same function.
                            debug!(
                                %remote,
                                error = %crate::logfmt::peer_error(error),
                                "QUIC handshake failed"
                            );
                            return None;
                        }
                        // Equally routine, and logged at the same level for the
                        // same reason: a flood is exactly when this fires.
                        Err(_elapsed) => {
                            debug!(
                                %remote,
                                timeout_secs = handshake_deadline.as_secs(),
                                "QUIC handshake did not complete in time"
                            );
                            return None;
                        }
                    };

                    let peer = peer_info(&quic);
                    info!(
                        log_id = "7l4svyo3",
                        remote = %peer.remote,
                        alpn = %crate::logfmt::or_dash(peer.alpn.as_deref()),
                        server_name = %crate::logfmt::or_dash(peer.server_name.as_deref()),
                        // Whether this handshake used ECH. The startup line's
                        // `ech=` says whether a key is loaded.
                        ech = peer.ech,
                        // At this point the estimate comes from the handshake
                        // samples alone; the close logs below carry the lifetime
                        // smoothed value.
                        rtt_ms = quic.rtt().as_millis(),
                        "connection established"
                    );
                    established = Some((peer.remote, quic.clone()));

                    let handled = conn::handle(
                        quic,
                        generation,
                        shutdown,
                        resolver,
                        counts.clone(),
                        authenticated,
                    )
                    .await;
                    Some(match handled {
                        // The accept loop ended on its own terms: the GOAWAY
                        // drain completed.
                        Ok(()) => Ok(CloseReason::Drained),
                        Err(error) => graded(error),
                    })
                } => closed,
            };

            // `None` is a handshake that failed or lapsed, already logged where
            // it was decided.
            let Some(closed) = closed else { return };
            match established {
                // Only an eviction ends a connection before its handshake has
                // completed. DEBUG rather than the INFO the established case
                // gets: there is no connection yet, so there is nothing to
                // report about one.
                None => debug!(
                    %remote,
                    "evicted before its QUIC handshake completed: the server is full"
                ),
                Some((remote, rtt_probe)) => log_connection_closed(
                    remote,
                    &rtt_probe,
                    closed,
                    counts.tunnels.load(Ordering::Relaxed),
                    counts.failed_setups.read(),
                    counts.dropped_datagrams.load(Ordering::Relaxed),
                ),
            }
        }
    }

    /// Winds the endpoint down: no new connections, then a bounded wait, then
    /// close regardless.
    ///
    /// The GOAWAY frames are not sent from here. Every connection watches the
    /// same signal and sends its own, so a connection starts draining the
    /// instant the signal fires rather than waiting to be told.
    async fn drain(&self, connections: &mut JoinSet<()>) {
        // Stop new handshakes at the source. Packets for existing connections are
        // unaffected. A client that arrives now hears nothing and gives up at
        // its own handshake timeout: the gate is closed first, so the Stateless
        // Reset quinn would send an Initial once the server configuration is
        // gone is never drawn (D106 addendum 2026-11-20, user ruling). The
        // order of the two calls is load-bearing and `Expected::close` says
        // why.
        //
        // "New" counts from the first Initial. A handshake quinn had already
        // queued as an `Incoming` keeps the server configuration it arrived
        // under (quinn-proto 0.11.x), so this call neither completes nor
        // refuses it. Nothing here ever accepts one: the accept loop has left by
        // the time this runs, and a queued `Incoming` goes away with the
        // endpoint.
        //
        // Deliberately not paired with a write to `self.live`. Its quinn half
        // exists for `accept_on_one_generation`, and by the time this runs the
        // accept loop that calls it has returned. Emptying it would mean making
        // it an `Option` and giving that method a branch nothing can take.
        //
        // Under the swap, because the latch this drain runs on is read by
        // `ReloadHandle::reload` as a plain predicate: without it a reload that
        // had already passed that read would install a server configuration
        // after this line and re-open the listener for the whole grace period.
        // Dropped explicitly and at once: it is a `std::sync::Mutex` guard and
        // the wait below is an await, so it must not still be alive there.
        let swapping = self.swap.hold();
        self.expected.close();
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
        let _ =
            tokio::time::timeout(shutdown::CLOSE_FLUSH_TIMEOUT, self.endpoint.wait_idle()).await;
    }
}

/// Why a connection ended without an error, as the closing line reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseReason {
    /// A newcomer took this connection's slot on a full roster.
    Evicted,
    /// The accept loop ended on its own terms: the GOAWAY drain completed.
    Drained,
    /// The peer went silent and the idle timeout expired.
    Idle,
    /// The peer closed the connection cleanly, without an error code.
    PeerClosed,
}

/// How a connection that `conn::handle` ended with `error` is reported: an
/// ordinary goodbye as the [`CloseReason`] the INFO line names, anything else
/// as the error the WARN line carries.
///
/// The judgement is made on the error *value* on purpose. Asking
/// `quinn::Connection::close_reason()` afterwards cannot work: returning from
/// `conn::handle` drops the HTTP/3 connection, whose `Drop` closes the QUIC
/// connection with H3_NO_ERROR, and quinn's close path unconditionally
/// overwrites whatever reason was stored with `LocallyClosed`. An idle timeout
/// would then be logged as an error. An error value is immutable and
/// independent of drop order.
fn graded(error: h3api::ConnectionError) -> Result<CloseReason, h3api::ConnectionError> {
    use h3api::{Code, ConnectionError};
    match error {
        // The QUIC idle timeout, and nothing else. Clients that abandon a
        // connection without a CONNECTION_CLOSE, as Surge does on a network
        // switch or app exit, all end up here.
        ConnectionError::Timeout => Ok(CloseReason::Idle),

        // 0x0 is the application error code Surge actually sends when it closes
        // a connection cleanly; H3_NO_ERROR (0x100) is what RFC 9114 §8.1
        // defines for the same intent. Both mean the peer simply left. Any other
        // code is the peer reporting a problem and stays a warning.
        ConnectionError::ApplicationClose { code }
            if code.value() == 0 || code == Code::H3_NO_ERROR =>
        {
            Ok(CloseReason::PeerClosed)
        }

        // This endpoint closed the connection with nothing to report, which is
        // what `Connection::close_quietly` does when a peer that never
        // authenticated has gone silent for too long (D76). The peer was idle;
        // that an application timer rather than the transport's own noticed it
        // does not make it a fault.
        ConnectionError::Local(ref violation) if violation.code() == Code::H3_NO_ERROR => {
            Ok(CloseReason::Idle)
        }

        error => Err(error),
    }
}

impl CloseReason {
    /// The value of the `reason` field on log line `8ro19wv6`.
    ///
    /// Tests and operations scripts match these strings, so each one stays
    /// exactly as it is.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Evicted => "evicted",
            Self::Drained => "drained",
            Self::Idle => "idle",
            Self::PeerClosed => "peer_close",
        }
    }
}

/// The line one connection ends on: INFO with the reason it stopped, WARN with
/// the error that stopped it.
///
/// The two lines share 23 fields: 11 transport and count fields, 9 controller
/// readings ([`crate::congestion::Record`]) and 3 failed-setup counts
/// ([`tunnel::FailedSetups`]). They differ in the value of `log_id` and in
/// `reason` against `error`, so an operator can grep one journal for both.
/// Each statement spells its field list out, because `it_log_lines` reads log
/// statements out of the source text and does not see through a wrapper. So a
/// field added to one list has to be added to the other by hand. `it_close_log`
/// requires every field on the INFO line.
///
/// `closed` is graded from the error *value* rather than from
/// `Connection::close_reason()`, for the reason [`graded`] gives.
///
/// Each field is described for operators in `docs/configuration.md`.
fn log_connection_closed(
    remote: SocketAddr,
    quic: &quinn::Connection,
    closed: Result<CloseReason, h3api::ConnectionError>,
    tunnels: u64,
    (failed_resolves, failed_connects, failed_setup_ms): (u64, u64, u64),
    dropped_datagrams: u64,
) {
    // One snapshot for every transport field below, so they all describe the
    // same instant. It is also the only read of them, so the counters cost
    // nothing while the connection runs.
    let stats = quic.stats();
    let path = stats.path;
    let record = quic
        .congestion_state()
        .into_any()
        .downcast::<crate::congestion::Bbr>()
        .ok()
        .map(|controller| controller.record());
    let window_limited_ms = crate::logfmt::or_dash(record.map(|r| r.window_limited.as_millis()));
    let window_floor_ms = crate::logfmt::or_dash(record.map(|r| r.floor.as_millis()));
    let window_floor_lossless_ms =
        crate::logfmt::or_dash(record.map(|r| r.floor_lossless.as_millis()));
    let peak_bytes_per_sec = crate::logfmt::or_dash(record.map(|r| r.peak));
    let window_turnover_permille =
        crate::logfmt::or_dash(record.and_then(|r| r.turnover_permille()));
    let flight_over_min_rtt_permille =
        crate::logfmt::or_dash(record.and_then(|r| r.flight_permille()));
    let base_loss_mean_ppm = crate::logfmt::or_dash(record.and_then(|r| r.base_loss_mean()));
    let base_loss_peak_ppm = crate::logfmt::or_dash(record.and_then(|r| r.base_loss_highest()));
    let gain_mean_permille = crate::logfmt::or_dash(record.and_then(|r| r.gain_mean()));

    match closed {
        Ok(reason) => {
            info!(
                log_id = "8ro19wv6",
                remote = %remote,
                remote_now = %quic.remote_address(),
                reason = reason.as_str(),
                rtt_ms = quic.rtt().as_millis(),
                mtu = path.current_mtu,
                mtu_black_holes = path.black_holes_detected,
                tunnels,
                dropped_datagrams,
                tx_bytes = stats.udp_tx.bytes,
                rx_bytes = stats.udp_rx.bytes,
                sent_packets = path.sent_packets,
                lost_packets = path.lost_packets,
                %window_limited_ms,
                %window_floor_ms,
                %window_floor_lossless_ms,
                %peak_bytes_per_sec,
                %window_turnover_permille,
                %flight_over_min_rtt_permille,
                %base_loss_mean_ppm,
                %base_loss_peak_ppm,
                %gain_mean_permille,
                failed_resolves,
                failed_connects,
                failed_setup_ms,
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
                %window_limited_ms,
                %window_floor_ms,
                %window_floor_lossless_ms,
                %peak_bytes_per_sec,
                %window_turnover_permille,
                %flight_over_min_rtt_permille,
                %base_loss_mean_ppm,
                %base_loss_peak_ppm,
                %gain_mean_permille,
                failed_resolves,
                failed_connects,
                failed_setup_ms,
                "connection closed with error"
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

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
        /// Removes the files above when the test ends.
        _dir: ScratchDir,
    }

    /// A directory that is removed with everything in it when dropped.
    ///
    /// A field of its own rather than `Drop for Bound`, so a test may still
    /// move the server out of a [`Bound`].
    struct ScratchDir(PathBuf);

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            // A failure leaves a directory behind and nothing else, so it is
            // not worth failing a test over.
            let _ = std::fs::remove_dir_all(&self.0);
        }
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
        let dir = ScratchDir(dir);

        let cert = dir.0.join("cert.pem");
        let key = dir.0.join("key.pem");
        std::fs::write(&cert, issued.cert.pem()).expect("write the certificate");
        std::fs::write(&key, issued.signing_key.serialize_pem()).expect("write the key");

        let config_path = dir.0.join("config.toml");
        write_config(&config_path, &cert, &key, extra);
        let config = Config::load(&config_path).expect("the test configuration loads");

        Bound {
            server: Server::bind(Arc::new(config)).expect("bind the test endpoint"),
            config_path,
            cert,
            key,
            _dir: dir,
        }
    }

    /// A test server leaves no files behind once it is dropped.
    #[tokio::test]
    async fn a_bound_server_removes_its_files_when_dropped() {
        let bound = bound_server("");
        let dir = bound
            .config_path
            .parent()
            .expect("the configuration file has a directory")
            .to_owned();
        assert!(dir.exists(), "{} holds the test files", dir.display());
        drop(bound);
        assert!(
            !dir.exists(),
            "{} is left behind after the test",
            dir.display()
        );
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

    /// The grading the closing line logs by: three endings are routine, the
    /// rest warn.
    #[test]
    fn routine_endings_are_graded_as_such() {
        use h3api::{Code, ConnectionError, Violation};
        assert_eq!(
            graded(ConnectionError::Timeout).ok(),
            Some(CloseReason::Idle)
        );
        for code in [Code::new(0), Code::H3_NO_ERROR] {
            assert_eq!(
                graded(ConnectionError::ApplicationClose { code }).ok(),
                Some(CloseReason::PeerClosed),
                "{code}"
            );
        }
        // A close this endpoint makes with nothing to report is graded with
        // the idle timeout it stands in for, not with the violations (D76).
        let quiet = Violation::connection(Code::H3_NO_ERROR, "no request within the timeout");
        assert_eq!(
            graded(ConnectionError::Local(quiet)).ok(),
            Some(CloseReason::Idle)
        );
    }

    #[test]
    fn a_reported_problem_still_warns() {
        use h3api::{Code, ConnectionError, Violation};
        assert!(
            graded(ConnectionError::ApplicationClose {
                code: Code::new(42)
            })
            .is_err()
        );
        // A violation is still a violation, whatever its code says about us.
        let violation = Violation::connection(
            Code::H3_FRAME_UNEXPECTED,
            "a frame that may not appear here",
        );
        assert!(graded(ConnectionError::Local(violation)).is_err());
        assert!(
            graded(ConnectionError::Transport(
                quinn::ConnectionError::LocallyClosed
            ))
            .is_err()
        );
    }

    /// Connections accepted under one configuration generation share its
    /// credentials and destination rules, and a reload's generation gets its
    /// own.
    #[tokio::test]
    async fn a_generation_is_built_once_and_a_reload_builds_the_next() {
        let bound = bound_server("");
        let first = bound.server.live().generation.clone();
        let again = bound.server.live().generation.clone();
        assert!(Arc::ptr_eq(&first, &again), "one generation, one value");

        bound
            .server
            .reload_handle()
            .reload(&bound.config_path)
            .expect("the reload succeeds");
        let next = bound.server.live().generation.clone();
        assert!(!Arc::ptr_eq(&first, &next), "a reload builds the next one");
    }

    /// The grace a reload raises is the grace the exit bound gets.
    ///
    /// `Server::drain` and `main` both ask for it, and `shutdown::blocking_grace`
    /// states that the blocking pool gets the whole allowance the connections
    /// got. That is only true while both read the live configuration, so that a
    /// `SIGHUP` raising the key raises the exit bound as well as the drain.
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
    /// The three are the SNI gate's list, the [`Live`] slot an accept reads and
    /// the endpoint's own copy. Under the swap they are one step against the
    /// drain, and the slot is one value, which is what D22 means by no
    /// half-applied state. The endpoint's copy has no getter, so the test reads
    /// the other two.
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
        let before = bound.server.live();

        let swapping = bound.server.swap.hold();
        let reloading =
            reload_on_another_thread(bound.server.reload_handle(), bound.config_path.clone());

        assert_eq!(
            bound.server.config().limits.max_streams_bidi,
            64,
            "a reload waiting for the swap must not have replaced the live configuration"
        );
        assert!(
            Arc::ptr_eq(&bound.server.live(), &before),
            "nor the generation an accept reads"
        );
        assert!(
            bound.server.expected.current().names().accepts("localhost"),
            "nor the gate's list"
        );
        assert!(
            !bound
                .server
                .expected
                .current()
                .names()
                .accepts("other.example"),
            "nor the gate's list"
        );

        drop(swapping);
        reloading
            .join()
            .expect("the reload thread")
            .expect("the reload applies once the swap is free");

        assert_eq!(bound.server.config().limits.max_streams_bidi, 32);
        assert!(
            bound
                .server
                .expected
                .current()
                .names()
                .accepts("other.example")
        );
        assert!(
            !Arc::ptr_eq(&bound.server.live().quic, &before.quic),
            "the reload replaces the server configuration an accept reads"
        );
    }

    /// A `quinn::Incoming` stand-in that needs no peer on the other end.
    ///
    /// Records the `quinn::ServerConfig` it was accepted with, the argument
    /// `accept_on_one_generation` states.
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

    /// An accept takes both halves of what a connection runs on from one
    /// generation, the one a reload installed, and does not wait on the swap.
    ///
    /// The `Arc::ptr_eq` pair pins that the configuration the accept states is
    /// the one in the slot, not the one quinn-proto pinned to the `Incoming`
    /// (D22). The swap is held throughout: only a reload and the drain take it.
    #[tokio::test]
    async fn an_accept_takes_both_halves_from_one_generation() {
        let bound = bound_server("[limits]\nmax_streams_bidi = 64\n");
        write_config(
            &bound.config_path,
            &bound.cert,
            &bound.key,
            "[limits]\nmax_streams_bidi = 32\n",
        );
        bound
            .server
            .reload_handle()
            .reload(&bound.config_path)
            .expect("the reload succeeds");
        let live = bound.server.live();

        let _swapping = bound.server.swap.hold();
        let (arriving, accepted_with) = Arriving::new();
        let (generation, _accepted) = bound.server.accept_on_one_generation(arriving);

        assert_eq!(generation.config.limits.max_streams_bidi, 32);
        assert!(Arc::ptr_eq(&generation, &live.generation));
        let handed = accepted_with
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .expect("the accept states a server configuration");
        assert!(
            Arc::ptr_eq(&handed, &live.quic),
            "the accept must state the server configuration of the same generation"
        );
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
        let before = bound.server.live();

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
            Arc::ptr_eq(&bound.server.live(), &before),
            "nor the generation an accept reads"
        );
    }

    /// A socket whose every receive fails with an error other than
    /// `ConnectionReset`, the one error quinn's endpoint driver does not end on.
    #[derive(Debug)]
    struct FailingSocket(SocketAddr);

    /// The poller [`FailingSocket`] hands out: the socket is always writable.
    #[derive(Debug)]
    struct AlwaysWritable;

    impl quinn::UdpPoller for AlwaysWritable {
        fn poll_writable(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl quinn::AsyncUdpSocket for FailingSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
            Box::pin(AlwaysWritable)
        }

        fn try_send(&self, _transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
            Ok(())
        }

        fn poll_recv(
            &self,
            _cx: &mut std::task::Context<'_>,
            _bufs: &mut [std::io::IoSliceMut<'_>],
            _meta: &mut [quinn::udp::RecvMeta],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::other("an injected receive failure")))
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.0)
        }
    }

    /// An endpoint whose driver ends on a receive error stops the accept loop,
    /// and `run` says so rather than reporting a shutdown.
    ///
    /// The receive error is the real one: the endpoint is moved onto a socket
    /// whose receive fails, so quinn's driver returns the error, its `Drop`
    /// marks the driver lost and `accept` returns `None`. The trigger is never
    /// fired. Before D124 `run` returned the same `()` for this as for a
    /// shutdown, and the process exited with status 0.
    #[tokio::test]
    async fn a_lost_endpoint_ends_the_accept_loop_as_a_failure() {
        let bound = bound_server("");
        let server = Arc::new(bound.server);
        let addr = server.local_addr().expect("the bound address");

        let running = tokio::spawn({
            let server = server.clone();
            async move { server.run().await }
        });
        server
            .endpoint
            .rebind_abstract(Arc::new(FailingSocket(addr)))
            .expect("the endpoint takes the failing socket");

        let stopped = tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("the accept loop must end once the driver is lost")
            .expect("the accept loop task");
        assert_eq!(stopped, Stopped::EndpointLost);
        assert!(
            !server.shutdown.is_fired(),
            "nothing fired the trigger, so this was not a shutdown"
        );
    }

    /// A fired trigger still ends the loop as a shutdown.
    #[tokio::test]
    async fn a_fired_trigger_ends_the_accept_loop_as_a_shutdown() {
        let bound = bound_server("shutdown_grace = 0\n");
        let server = Arc::new(bound.server);
        let running = tokio::spawn({
            let server = server.clone();
            async move { server.run().await }
        });
        server.trigger.fire();
        let stopped = tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("the drain must end")
            .expect("the accept loop task");
        assert_eq!(stopped, Stopped::Shutdown);
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
