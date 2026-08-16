//! The QUIC endpoint: transport parameters, the accept loop and peer metadata.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
use quinn::{IdleTimeout, VarInt};
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

    // The bound on what an *unauthenticated* peer can make this process hold.
    //
    // quinn's default is `VarInt::MAX` — no aggregate limit at all — and the
    // per-stream window is 2 MiB (ours, set just below). With our raised stream
    // limit that is 1024 x 2 MiB, so a single connection could pin 2 GiB of
    // receive buffer before we ever see a request to authenticate: open the
    // streams, fill each window, stop. On a 1 GB VPS one connection is enough to
    // end the process.
    //
    // The cap only constrains data that has arrived and not yet been read, and
    // both tunnel pumps read continuously, so it binds exactly when the target is
    // slower than the client — which is the case that should be bounded.
    transport.receive_window(CONNECTION_RECEIVE_WINDOW);

    // Raised above quinn's own default of 1,250,000, not inherited from it and no
    // longer a pin at it. No RFC constrains the value — RFC 9000 §4.2 leaves the
    // amount of credit to implementations outright, and §4.3 only observes the
    // consequence of getting it wrong: an endpoint that "cannot ensure that its
    // peer always has available flow control credit that is greater than the
    // peer's bandwidth-delay product" finds "its receive throughput will be
    // limited by flow control". That is advice, not a requirement, and it is the
    // whole of the case. The production path's BDP — a 100 Mbps client uplink over
    // a 95 ms RTT — is about 1.19 MB, so quinn's default sat at roughly 1.05x it:
    // exactly one BDP, with no margin for a window update still in flight. 2 MiB
    // is about 1.75x. The peer we
    // interoperate with sizes its own side far higher still: Surge's ClientHello
    // advertises `initial_max_stream_data_bidi_local` = 12 MiB per stream.
    //
    // Not a memory decision. `receive_window` above is the real bound — the
    // invariant is that (the sum of the highest offsets received) minus (the bytes
    // read) stays within it — so a larger per-stream window cannot raise the
    // per-connection worst case, which is unchanged at 16 MiB. What this value
    // actually decides is how few simultaneously saturated tunnels it takes to
    // spend the whole connection's credit — 16 MiB / 2 MiB = 8 — which is a
    // fairness property rather than a memory one, and 8:1 is still far more
    // conservative than the 1.33:1 the peer itself runs (16 MiB of
    // `initial_max_data` against 12 MiB per stream). The per-tunnel ceiling in the
    // download direction is whatever the client advertises to us and is not
    // settable here.
    transport.stream_receive_window(STREAM_RECEIVE_WINDOW);

    // This one *is* set to exactly what quinn already defaults to, so it changes
    // not a byte on the wire today. It is pinned because upstream derives it from
    // `STREAM_RWND`, a private constant inside `TransportConfig::default` with no
    // stability guarantee, while the throughput arithmetic below is quoted against
    // it. Dependabot proposes cargo bumps weekly; a patch release that moved that
    // constant would leave the documented numbers quietly false. Setting the value
    // here makes them true by construction instead of by inheritance.
    //
    // The mirror image of `receive_window`, and the only bound on what this
    // process buffers for a client that stops reading: a per-connection aggregate
    // cap on unacknowledged outbound stream data. 10 MB over the ~90 ms path RTT
    // is about 889 Mbps against a measured peak of 177 Mbps, so it is nowhere near
    // a throughput constraint.
    //
    // Note the asymmetry it leaves: 16 MiB of inbound credit granted against a
    // 10 MB outbound cap, on a proxy whose traffic is mostly outbound. That is an
    // accepted decision, not an oversight — lifting the outbound cap to match
    // would add roughly 1.6 GiB of theoretical worst case across `max_connections`
    // (256 by default) in exchange for throughput we cannot measure a need for.
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
        // Pins the packet size at `initial_mtu` for the life of the connection:
        // spec §5.4's conservative setting for a path that black-holes large
        // packets, where a stable small MTU beats an optimistic large one.
        transport.mtu_discovery_config(None);
    }

    // QUIC datagram support stays at quinn's default (enabled), which is
    // what makes `max_datagram_frame_size` appear in our transport
    // parameters. CONNECT-UDP sizes the datagram buffers explicitly.

    // Congestion controller, BBR by default. A loss-based controller (CUBIC,
    // NewReno) reads the non-congestive packet loss of a long international path
    // as congestion and collapses the window — the download direction stalls to
    // near-zero while a co-located Shadowsocks server on the same box sails
    // through, because the Linux kernel runs BBR for TCP. BBR models bandwidth
    // and RTT instead, holding throughput on exactly these paths. See
    // `config::CongestionControl` for why this is the default and stays
    // configurable.
    let controller: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
        match limits.congestion_control {
            CongestionControl::Bbr => Arc::new(quinn::congestion::BbrConfig::default()),
            CongestionControl::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
            CongestionControl::NewReno => Arc::new(quinn::congestion::NewRenoConfig::default()),
        };
    transport.congestion_controller_factory(controller);

    Ok(transport)
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
    config: LiveConfig,
    /// Fires the graceful shutdown. Handed to whoever watches for signals.
    trigger: Trigger,
    /// The other end of the same latch, cloned into every connection.
    shutdown: Shutdown,
}

impl Server {
    /// Binds the UDP socket and prepares the QUIC server configuration.
    pub fn bind(config: Arc<Config>) -> Result<Self> {
        let quic_config = server_config(&config)?;

        let endpoint = quinn::Endpoint::server(quic_config, config.server.listen)
            .with_context(|| format!("failed to bind UDP socket {}", config.server.listen))?;

        warn_if_fd_budget_is_tight(config.limits.max_targets_per_conn);

        let (trigger, shutdown) = shutdown::channel();

        Ok(Self {
            endpoint,
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

    /// The underlying quinn endpoint.
    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
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
            listen = %config.server.listen,
            alpn = ?config.server.alpn,
            grace_secs = config.server.shutdown_grace,
            "accepting QUIC connections"
        );

        let mut shutdown = self.shutdown.clone();
        let mut connections = JoinSet::new();

        let max_connections = config.limits.max_connections;

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
                alpn = ?peer.alpn,
                server_name = ?peer.server_name,
                // At this point the estimate comes from the handshake samples
                // alone; the close logs below carry the lifetime smoothed value.
                rtt_ms = quic.rtt().as_millis(),
                "connection established"
            );

            // `conn::handle` consumes the connection; keep a handle so the close
            // logs can report the path RTT the connection actually measured and
            // the address the peer ended on — `remote_now` differing from
            // `remote` is the only externally visible trace of a migration or
            // NAT rebind during the connection's life.
            let rtt_probe = quic.clone();

            // Which of the two log levels this connection deserves is decided
            // from the error value `conn::handle` returned, and never from
            // `rtt_probe.close_reason()`. Returning from `conn::handle` drops
            // the `h3` connection, whose `Drop` closes the QUIC connection with
            // H3_NO_ERROR; quinn's close path then unconditionally overwrites
            // the stored reason with `LocallyClosed`. So by the time control is
            // back here, `close_reason()` reports that drop rather than whatever
            // actually ended the connection — which is precisely how the idle
            // timeout ended up logged as an error for a whole release cycle.
            let closed = match conn::handle(quic, config, shutdown).await {
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

            match closed {
                Ok(reason) => {
                    info!(
                        remote = %peer.remote,
                        remote_now = %rtt_probe.remote_address(),
                        reason,
                        rtt_ms = rtt_probe.rtt().as_millis(),
                        "connection closed"
                    );
                }
                Err(error) => {
                    warn!(
                        remote = %peer.remote,
                        remote_now = %rtt_probe.remote_address(),
                        %error,
                        rtt_ms = rtt_probe.rtt().as_millis(),
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
    /// they keep the configuration they were accepted with (see [`Server::serve`]).
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

/// Aggregate flow-control window for one connection, in bytes.
///
/// 16 MiB against the 2 MiB [`STREAM_RECEIVE_WINDOW`]: eight simultaneously
/// saturated tunnels still get their full stream windows, while the worst case
/// stops being a function of `max_streams_bidi`.
const CONNECTION_RECEIVE_WINDOW: VarInt = VarInt::from_u32(16 * 1024 * 1024);

/// Per-stream flow-control window, in bytes.
///
/// A deliberate raise above quinn's own default of 1,250,000, not a pin at it.
/// No RFC constrains the value; RFC 9000 §4.3 only observes that credit below the
/// peer's bandwidth-delay product caps receive throughput. At the production
/// path's BDP of about 1.19 MB (100 Mbps over 95 ms) quinn's default was roughly
/// 1.05x — one BDP with no margin — where this is about 1.75x. Measured
/// corroboration: Surge advertises 12 MiB per stream to us.
///
/// Not a memory bound — [`CONNECTION_RECEIVE_WINDOW`] is, and it caps the
/// aggregate whatever this value is, so the per-connection worst case does not
/// move. This only sets how few saturated tunnels can spend a connection's whole
/// credit: 16 MiB / 2 MiB = 8.
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
/// quinn's own default, restated for the same reason, and the only bound on what
/// this process buffers for a client that has stopped reading. 10 MB is about
/// 889 Mbps at the production path's RTT, so the cap costs no measurable
/// throughput.
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
