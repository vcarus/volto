//! The QUIC endpoint: transport parameters, the accept loop and peer metadata.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
use quinn::{IdleTimeout, VarInt};
use socket2::SockRef;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::config::{Config, CongestionControl};
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
    transport.max_concurrent_bidi_streams(VarInt::from_u32(limits.max_streams_bidi));

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
    if !limits.mtu_discovery {
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
    // parameters. CONNECT-UDP sizes the datagram buffers explicitly.

    transport.congestion_controller_factory(congestion_factory(limits.congestion_control));

    Ok(transport)
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

/// A bound QUIC endpoint ready to accept connections.
pub struct Server {
    endpoint: quinn::Endpoint,
    /// What the kernel granted for the endpoint socket's buffers, for the
    /// startup line. Fixed at bind time: nothing reloadable can change it.
    socket_buffers: SocketBuffers,
    config: LiveConfig,
    /// Fires the graceful shutdown. Handed to whoever watches for signals.
    trigger: Trigger,
    /// The other end of the same latch, cloned into every connection.
    shutdown: Shutdown,
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
    /// [`quinn::Endpoint::new`] below is what the helper passes internally; none
    /// of it may be dropped in the name of tidiness.
    pub fn bind(config: Arc<Config>) -> Result<Self> {
        let quic_config = server_config(&config)?;

        let socket = std::net::UdpSocket::bind(config.server.listen)
            .with_context(|| format!("failed to bind UDP socket {}", config.server.listen))?;

        let socket_buffers = SocketBuffers::request(&socket, &config.limits);

        let runtime = quinn::default_runtime()
            .ok_or_else(|| anyhow!("no async runtime is available for the QUIC endpoint"))?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(quic_config),
            socket,
            runtime,
        )
        .with_context(|| format!("failed to bind UDP socket {}", config.server.listen))?;

        warn_if_fd_budget_is_tight(config.limits.max_targets_per_conn);

        let (trigger, shutdown) = shutdown::channel();

        Ok(Self {
            endpoint,
            socket_buffers,
            config: Arc::new(RwLock::new(config)),
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
        }
    }

    /// A snapshot of the configuration currently in force.
    fn config(&self) -> Arc<Config> {
        // Poisoning would mean a panic while swapping the config; the value itself
        // is an immutable `Arc`, so it cannot be observed half-written.
        self.config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
            // branch, leaving finished tasks in the set and making the count
            // below refuse connections that are no longer there.
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

                    // Read per accepted connection rather than snapshotted
                    // before the loop: `docs/deployment.md#reloading` promises a
                    // reload applies to connections accepted from then on, and
                    // lowering this cap during an incident is exactly the sort of
                    // thing that promise is for. The cost is an `Arc` load on a
                    // path that is already opening a QUIC connection.
                    let max_connections = self.config().limits.max_connections;

                    if max_connections > 0 && connections.len() >= max_connections as usize {
                        // Refused at the QUIC layer: the peer is told immediately
                        // instead of timing out, and nothing per-connection is
                        // built on our side. Logged at DEBUG because a flood is
                        // exactly when this fires.
                        debug!(
                            remote = %incoming.remote_address(),
                            live = connections.len(),
                            max_connections,
                            "refusing a connection: the server is at its connection limit"
                        );
                        incoming.refuse();
                        continue;
                    }

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

    /// Runs one accepted connection to completion.
    ///
    /// Split out of the accept loop so it can be a `'static` future for the
    /// `JoinSet`: everything it needs is cloned up front.
    fn serve(&self, incoming: quinn::Incoming) -> impl std::future::Future<Output = ()> {
        // Snapshotted per connection, not read live: a reload changes what new
        // connections get, while a connection already running keeps the
        // credentials and policy it started with for its whole life. Anything else
        // would mean a tunnel's rules changing under it mid-transfer.
        let config = self.config();
        let shutdown = self.shutdown.clone();
        let remote = incoming.remote_address();

        async move {
            let quic = match incoming.await {
                Ok(quic) => quic,
                Err(error) => {
                    // A failed handshake is routine on a public port: scanners,
                    // version negotiation, stale retries.
                    debug!(%remote, %error, "QUIC handshake failed");
                    return;
                }
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
            // that only ever failed authentication reports zero. `tx_bytes` and
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

            // Created here rather than inside the connection so it survives it:
            // `conn::handle` hands it to every request, and it is read below,
            // once, after the connection is over.
            let tunnels = Arc::new(AtomicU64::new(0));

            // Which of the two log levels this connection deserves is decided
            // from the error value `conn::handle` returned, and never from
            // `rtt_probe.close_reason()`. Returning from `conn::handle` drops
            // the HTTP/3 connection, whose `Drop` closes the QUIC connection with
            // H3_NO_ERROR; quinn's close path then unconditionally overwrites
            // the stored reason with `LocallyClosed`. So by the time control is
            // back here, `close_reason()` reports that drop rather than whatever
            // actually ended the connection — which is precisely how the idle
            // timeout ended up logged as an error for a whole release cycle.
            let closed = match conn::handle(quic, config, shutdown, tunnels.clone()).await {
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
            };

            // One snapshot for every transport field below, so they all
            // describe the same instant — and the only read of them there is, so
            // the counters cost nothing while the connection runs.
            let stats = rtt_probe.stats();
            let path = stats.path;
            let tunnels = tunnels.load(Ordering::Relaxed);

            match closed {
                Ok(reason) => {
                    info!(
                        remote = %peer.remote,
                        remote_now = %rtt_probe.remote_address(),
                        reason,
                        rtt_ms = rtt_probe.rtt().as_millis(),
                        mtu = path.current_mtu,
                        mtu_black_holes = path.black_holes_detected,
                        tunnels,
                        tx_bytes = stats.udp_tx.bytes,
                        rx_bytes = stats.udp_rx.bytes,
                        sent_packets = path.sent_packets,
                        lost_packets = path.lost_packets,
                        "connection closed"
                    );
                }
                Err(error) => {
                    warn!(
                        remote = %peer.remote,
                        remote_now = %rtt_probe.remote_address(),
                        %error,
                        rtt_ms = rtt_probe.rtt().as_millis(),
                        mtu = path.current_mtu,
                        mtu_black_holes = path.black_holes_detected,
                        tunnels,
                        tx_bytes = stats.udp_tx.bytes,
                        rx_bytes = stats.udp_rx.bytes,
                        sent_packets = path.sent_packets,
                        lost_packets = path.lost_packets,
                        "connection closed with error"
                    );
                }
            }
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
        self.endpoint.set_server_config(None);

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

        // A reload during shutdown must not re-open the listener that `drain` just
        // closed. Refusing is safer than racing it.
        if self.shutdown.is_fired() {
            bail!("the server is shutting down; the configuration was not reloaded");
        }

        // Past this point nothing can fail, so the two swaps cannot half-apply.
        self.endpoint.set_server_config(Some(quic_config));
        *self
            .config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = config.clone();

        info!(
            path = %path.display(),
            users = config.auth.users.len(),
            cert = %config.server.cert.display(),
            "configuration reloaded; new connections will use it"
        );
        for warning in config.warnings() {
            warn!("{warning}");
        }

        Ok(config)
    }
}

/// Warns when the fd limit leaves no room for the configured tunnel quota.
///
/// One connection at its quota needs `max_targets_per_conn` descriptors, plus the
/// endpoint's own socket and the request streams. If the soft limit is not
/// comfortably above the quota, a single busy client can exhaust the process —
/// and fd exhaustion is not a graceful failure mode, it breaks everything at once
/// (spec §5.2).
fn warn_if_fd_budget_is_tight(max_targets_per_conn: u32) {
    let Some(limit) = crate::net::fd_soft_limit() else {
        debug!("could not read RLIMIT_NOFILE; skipping the fd budget check");
        return;
    };

    if fd_budget_is_tight(limit, max_targets_per_conn) {
        warn!(
            fd_soft_limit = limit,
            max_targets_per_conn,
            "RLIMIT_NOFILE leaves no room for limits.max_targets_per_conn: one busy \
             connection can exhaust the process. Raise LimitNOFILE (systemd) or lower \
             the quota."
        );
    }
}

/// Whether `limit` descriptors are too few for a connection at its full quota.
///
/// Split out from the warning so the arithmetic is testable without changing the
/// process's actual limit.
fn fd_budget_is_tight(limit: u64, max_targets_per_conn: u32) -> bool {
    limit < u64::from(max_targets_per_conn) + FD_HEADROOM
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
const CONNECTION_RECEIVE_WINDOW: VarInt = VarInt::from_u32(16 * 1024 * 1024);

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
const STREAM_RECEIVE_WINDOW: VarInt = VarInt::from_u32(2 * 1024 * 1024);

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
const SEND_WINDOW: u64 = 10_000_000;

/// Descriptors assumed to be needed beyond one connection's full tunnel quota:
/// the endpoint socket, the request streams, stdio, and the start of a second
/// connection.
const FD_HEADROOM: u64 = 64;

/// How long to wait for `CONNECTION_CLOSE` frames to be flushed on shutdown.
const CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    /// The configured limits really reach the transport parameters.
    #[test]
    fn configured_limits_reach_the_transport_config() {
        let limits = crate::config::Limits {
            max_streams_bidi: 7,
            initial_mtu: 1350,
            initial_rtt_ms: 150,
            ..Default::default()
        };

        let rendered = transport_debug(&limits);
        assert!(
            rendered.contains("max_concurrent_bidi_streams: 7"),
            "{rendered}"
        );
        assert!(
            rendered.contains("1350"),
            "the initial MTU must apply: {rendered}"
        );
        assert!(
            rendered.contains("initial_rtt: 150ms"),
            "the initial RTT must apply: {rendered}"
        );
    }

    /// The check has to fire on the configuration that actually bites: a macOS
    /// default limit of 256 with the default quota of 256, where one connection
    /// at its quota consumes every descriptor the process has.
    #[test]
    fn a_tight_fd_budget_is_recognised() {
        assert!(fd_budget_is_tight(256, 256), "the macOS default pairing");
        assert!(fd_budget_is_tight(1024, 1024));
        assert!(fd_budget_is_tight(64, 1));
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

    #[test]
    fn a_roomy_fd_budget_is_left_alone() {
        // The Ubuntu default, and the dev host.
        assert!(!fd_budget_is_tight(1024, 256));
        assert!(!fd_budget_is_tight(1_048_576, 256));
        // Exactly the headroom, and one better.
        assert!(!fd_budget_is_tight(FD_HEADROOM + 8, 8));
        assert!(fd_budget_is_tight(FD_HEADROOM + 7, 8));
    }
}
