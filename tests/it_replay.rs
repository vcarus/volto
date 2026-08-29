//! Replays the *shape* of production traffic against a lab server.
//!
//! # The gap this closes
//!
//! Every other binary in this suite drives the server the way a script drives
//! it: open a tunnel, use it, close it, assert. Production drives it the way an
//! application does -- dozens of connections at once, hundreds of tunnels on
//! each, targets that repeat, a client that vanishes mid-transfer and comes back
//! with a new connection a second later, and a link with 80-95 ms of round trip
//! under all of it. A whole class of question has therefore only ever been
//! askable of production, and the standing example is a protocol-violation
//! investigation that was closed as "not reproducible in the lab" when the lab
//! was never shaped like the thing it was trying to reproduce.
//!
//! This binary takes a shape profile -- what `tests/replay/shape_extract.py`
//! distils out of the server's own log -- and drives a lab server with it:
//! connections arriving on the measured interarrival distribution, living for
//! measured lifetimes, carrying measured numbers of tunnels at measured
//! spacings, split between TCP and UDP in the measured proportion, going to a
//! target set with the measured fan-out, ending in the measured mix of idle
//! timeouts, clean closes and protocol violations, and restarting in bursts
//! that abort whatever was in flight.
//!
//! # What the run is worth, and what it is not
//!
//! What it reproduces:
//!
//! * **Arrival and departure structure.** Interarrival, lifetime, concurrency
//!   and the close-reason mix all come from the capture.
//! * **Tunnel structure.** Count per connection, spacing, TCP/UDP split,
//!   address-literal share (which decides whether a request costs a name
//!   lookup at all -- D90), blackholed share, and fan-out over distinct
//!   targets.
//! * **Asynchrony.** Tunnels overlap, connections overlap, and restart bursts
//!   kill live connections with transfers still running.
//! * **The server's own accounting.** The lab server writes the same log lines
//!   production does, so the same extractor reads both and the two profiles are
//!   comparable field by field.
//!
//! What it cannot reproduce, and no amount of tuning here will:
//!
//! * **The path.** Everything is loopback: sub-millisecond RTT against
//!   production's 80-95 ms, and no loss at all against a link whose p90
//!   connection loses 13% of its packets. Congestion control, MTU discovery and
//!   the loss-driven half of the server's behaviour are therefore *not* under
//!   test here. `initial_rtt_ms` is set to the production value so the server's
//!   own timers start where production's do, which is as close as loopback gets.
//! * **Payload sizes.** The log records transport bytes per connection, not
//!   payload per tunnel, so a tunnel's transfer size is derived from
//!   `tx_bytes + rx_bytes` divided by the connection's tunnel count. That
//!   over-counts (it includes QUIC framing, ACKs, retransmissions) and it
//!   flattens the variation between tunnels on one connection.
//! * **Tunnel lifetime.** Nothing at INFO level records when a tunnel *ends*,
//!   so a replayed tunnel lives exactly as long as its transfer takes.
//! * **Time.** Wall-clock hours are compressed by a configurable factor. What
//!   compression preserves is every *ratio* -- concurrency, tunnels per
//!   connection, the arrival-to-lifetime relationship -- because arrivals,
//!   lifetimes and spacings are all divided by the same number. What it
//!   distorts is anything with an absolute floor, and there is one that
//!   matters: the server's idle timeout, which the configuration will not take
//!   below one second however far time is compressed. Four in five production
//!   connections end on that timer, so at a compression of 1000 an
//!   idle-ended connection holds its slot for the equivalent of 2000
//!   production-seconds instead of 30 -- and **measured lifetime and
//!   concurrency read high by roughly that factor**. The *working* part of a
//!   connection's life is right, because the production idle wait is subtracted
//!   before compression; it is only the tail that is long. A run whose subject
//!   is lifetime or concurrency should use a compression near 30 and accept the
//!   smaller sample; a run whose subject is volume, fan-out or the violation
//!   rate should compress hard and read those two rows as inflated.
//!
//! # Running it
//!
//! ```sh
//! cargo test --release --test it_replay -- --ignored --nocapture
//! ```
//!
//! Every knob is an environment variable, so a heavier run needs no rebuild:
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `VOLTO_REPLAY_PROFILE` | `tests/replay/profiles/host-b.json` | the shape to replay |
//! | `VOLTO_REPLAY_SECONDS` | `30` | wall-clock seconds of load |
//! | `VOLTO_REPLAY_COMPRESSION` | `1000` | production seconds per wall second |
//! | `VOLTO_REPLAY_SEED` | `24061` | the whole run is a function of this |
//! | `VOLTO_REPLAY_IDLE_SECS` | `2` | the lab server's idle timeout |
//! | `VOLTO_REPLAY_MAX_TRANSFER` | `65536` | ceiling on one tunnel's transfer |
//! | `VOLTO_REPLAY_MAX_TUNNELS` | `512` | ceiling on one connection's tunnels |
//! | `VOLTO_REPLAY_TARGETS` | `64` | distinct lab targets to spread over |
//! | `VOLTO_REPLAY_LOG` | a temp file | where the server's own log is written |
//!
//! The run prints the log's path. Feeding that file back through
//! `shape_extract.py` produces a lab profile in the same schema as the
//! production one, which is what makes the comparison a comparison rather than
//! two lists of numbers.
//!
//! # What is asserted
//!
//! Almost nothing, on purpose: this is a measurement, and a measurement that
//! fails the build when production shifts is worse than no measurement. The
//! three assertions that are here are the ones a replay is uniquely able to
//! make, and none of them is about a rate:
//!
//! * **No protocol violation the run did not inject.** The plan closes some
//!   connections with H3_GENERAL_PROTOCOL_ERROR on purpose, because production
//!   does; any *other* error close is the server having produced one under
//!   load, which is exactly the signal this harness exists to catch.
//! * **No dropped datagrams.** Every UDP session's datagrams must reach it. A
//!   Quarter-Stream-ID mix-up under this much concurrency shows up here.
//! * **No cross-talk.** Every tunnel's echo carries that tunnel's own tag.

mod common;

#[path = "replay/shape.rs"]
mod shape;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use common::{
    basic_credentials, spawn_echo_target, spawn_udp_echo_target, ClientStream, H3Client,
    SharedBuffer, TestServer, CONNECT_UDP,
};
use tokio::sync::mpsc;
use tokio::time::{sleep_until, timeout, Instant};
use volto::datagram;
use volto::h3api::{Method, Request, Status};

use shape::{Ending, Json, TunnelKind};

/// The credentials the replayed client presents on every request.
///
/// Production authenticates every CONNECT, so a replay that skipped it would
/// leave out a field decode and a constant-time comparison per tunnel.
const USER: &str = "replay";
const PASSWORD: &str = "replay-password";

/// How long one request may take to be answered before the tunnel is written
/// off. Generous: this is loopback, and the interesting case is a request that
/// is never answered at all.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a transfer may take.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(20);

/// Bytes written to a tunnel in one go.
const CHUNK: usize = 4096;

// --------------------------------------------------------------------------
// Settings
// --------------------------------------------------------------------------

struct Settings {
    profile: String,
    seed: u64,
    wall_seconds: u64,
    compression: f64,
    idle_seconds: u64,
    max_transfer: u32,
    max_tunnels: u64,
    targets: usize,
    log_path: std::path::PathBuf,
}

fn env_or<T: std::str::FromStr>(name: &str, fallback: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(fallback)
}

impl Settings {
    fn from_env() -> Self {
        let default_profile = format!(
            "{}/tests/replay/profiles/host-b.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let default_log = std::env::temp_dir().join(format!(
            "volto-replay-{}-{}.log",
            std::process::id(),
            "server"
        ));

        Self {
            profile: std::env::var("VOLTO_REPLAY_PROFILE").unwrap_or(default_profile),
            seed: env_or("VOLTO_REPLAY_SEED", 24_061u64),
            wall_seconds: env_or("VOLTO_REPLAY_SECONDS", 30u64),
            compression: env_or("VOLTO_REPLAY_COMPRESSION", 1000.0f64),
            idle_seconds: env_or("VOLTO_REPLAY_IDLE_SECS", 2u64),
            max_transfer: env_or("VOLTO_REPLAY_MAX_TRANSFER", 65_536u32),
            max_tunnels: env_or("VOLTO_REPLAY_MAX_TUNNELS", 512u64),
            targets: env_or("VOLTO_REPLAY_TARGETS", 64usize),
            log_path: std::env::var("VOLTO_REPLAY_LOG")
                .map(std::path::PathBuf::from)
                .unwrap_or(default_log),
        }
    }

    /// The lab server's configuration.
    ///
    /// The MTU and initial-RTT keys are the values the shipped
    /// `script/config.example.toml` recommends and the captured hosts run with,
    /// so the server's own timers and packet sizes start where production's do.
    /// Everything else is the program default, which is what those hosts use.
    fn config(&self) -> String {
        format!(
            "[auth]\n\
             users = [{{ username = \"{USER}\", password = \"{PASSWORD}\" }}]\n\
             [limits]\n\
             max_idle_timeout = {idle}\n\
             keep_alive_interval = 0\n\
             udp_session_timeout = {udp}\n\
             initial_mtu = 1242\n\
             mtu_upper_bound = 1464\n\
             initial_rtt_ms = 150\n\
             [security]\n\
             allow_private_networks = true\n",
            idle = self.idle_seconds,
            // The production 180s scaled the same way everything else is, with
            // the config's own floor of one second under it.
            udp = ((180.0 / self.compression).round() as u64).max(1),
        )
    }
}

// --------------------------------------------------------------------------
// Counters
// --------------------------------------------------------------------------

#[derive(Default)]
struct Tally {
    connections_started: AtomicU64,
    handshakes_failed: AtomicU64,
    ended_idle: AtomicU64,
    ended_peer_close: AtomicU64,
    ended_violation: AtomicU64,
    ended_outlive: AtomicU64,
    aborted_by_burst: AtomicU64,

    tunnels_requested: AtomicU64,
    tunnels_opened: AtomicU64,
    tunnels_refused: AtomicU64,
    tunnels_failed: AtomicU64,
    tunnels_aborted: AtomicU64,
    tunnels_transferred: AtomicU64,
    blackholes_closed_empty: AtomicU64,
    blackholes_unexpected: AtomicU64,
    udp_sessions: AtomicU64,
    udp_round_trips: AtomicU64,
    udp_lost: AtomicU64,
    crosstalk: AtomicU64,
    bytes_echoed: AtomicU64,
}

impl Tally {
    fn bump(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

// --------------------------------------------------------------------------
// Per-connection datagram routing
// --------------------------------------------------------------------------

/// Demultiplexes one connection's inbound HTTP Datagrams by Quarter Stream ID.
///
/// A connection may hold several CONNECT-UDP sessions at once, and
/// `quinn::Connection::read_datagram` is one queue for all of them: sessions
/// reading it directly would steal each other's packets and every answer would
/// look like cross-talk. So each replayed connection runs one reader that routes
/// by Quarter Stream ID, exactly as the server's own `serve_peer` does.
#[derive(Clone)]
struct Router {
    sessions: Arc<Mutex<HashMap<u64, mpsc::Sender<Bytes>>>>,
}

impl Router {
    fn spawn(quic: quinn::Connection, tally: Arc<Tally>) -> Self {
        let router = Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        };
        let sessions = router.sessions.clone();

        tokio::spawn(async move {
            while let Ok(raw) = quic.read_datagram().await {
                let Ok(decoded) = datagram::decode(raw) else {
                    tally.bump(&tally.udp_lost);
                    continue;
                };
                if decoded.context_id != datagram::CONTEXT_ID_UDP_PAYLOAD {
                    continue;
                }
                let sender = sessions
                    .lock()
                    .expect("router lock")
                    .get(&decoded.quarter_stream_id)
                    .cloned();
                // A session that has already closed gets no delivery: its
                // answer arriving late is normal, and is not the cross-talk
                // this run looks for.
                if let Some(sender) = sender {
                    let _ = sender.try_send(decoded.payload);
                }
            }
        });

        router
    }

    fn claim(&self, quarter_stream_id: u64) -> mpsc::Receiver<Bytes> {
        let (sender, receiver) = mpsc::channel(16);
        self.sessions
            .lock()
            .expect("router lock")
            .insert(quarter_stream_id, sender);
        receiver
    }

    fn release(&self, quarter_stream_id: u64) {
        self.sessions
            .lock()
            .expect("router lock")
            .remove(&quarter_stream_id);
    }
}

// --------------------------------------------------------------------------
// Targets
// --------------------------------------------------------------------------

/// The lab's stand-ins for the targets production reached.
///
/// Names rather than addresses wherever the profile says production used a
/// name: `getaddrinfo` runs for a name and not for a literal, so a replay whose
/// targets were all literals would leave the resolver budget (D90) untouched.
/// `localhost` is the only name a dev host is guaranteed to resolve without
/// touching its DNS, so the distinct-target axis is carried by the port instead
/// -- distinct authorities, one lookup each, which is what the budget counts.
struct Targets {
    echo: Vec<SocketAddr>,
    udp: Vec<SocketAddr>,
}

impl Targets {
    async fn spawn(count: usize) -> Self {
        let mut echo = Vec::with_capacity(count);
        for _ in 0..count {
            echo.push(spawn_echo_target().await);
        }

        // Fewer UDP targets: they carry under one percent of production's
        // tunnels, so a wide pool would only cost sockets.
        let mut udp = Vec::with_capacity(count.div_ceil(8).max(1));
        for _ in 0..count.div_ceil(8).max(1) {
            udp.push(spawn_udp_echo_target().await);
        }

        Self { echo, udp }
    }

    /// The authority a planned tunnel asks for.
    fn authority(&self, kind: TunnelKind, index: usize) -> String {
        match kind {
            TunnelKind::Tcp => {
                format!("localhost:{}", self.echo[index % self.echo.len()].port())
            }
            TunnelKind::TcpLiteral => self.echo[index % self.echo.len()].to_string(),
            // Every address of the unspecified target is the unspecified one,
            // which is the shape a resolver that blackholed a name returns
            // (D49). The port is carried along so the request is otherwise
            // ordinary.
            TunnelKind::Blackhole => {
                format!("0.0.0.0:{}", self.echo[index % self.echo.len()].port())
            }
            TunnelKind::Udp => self.udp[index % self.udp.len()].to_string(),
        }
    }
}

// --------------------------------------------------------------------------
// Driving one tunnel
// --------------------------------------------------------------------------

fn credentials() -> String {
    basic_credentials(USER, PASSWORD)
}

fn connect_request(authority: &str) -> Request {
    let mut request = Request::new(Method::Connect);
    request.authority = Some(authority.into());
    request.fields.append(
        "proxy-authorization",
        volto::h3api::FieldValue::parse(credentials().as_bytes()).expect("a valid field value"),
    );
    request
}

fn connect_udp_request(proxy: SocketAddr, target: SocketAddr) -> Request {
    let mut request = Request::new(Method::Connect);
    request.scheme = Some("https".into());
    request.authority = Some(proxy.to_string().into());
    request.path =
        Some(format!("/.well-known/masque/udp/{}/{}/", target.ip(), target.port()).into());
    request.protocol = Some(CONNECT_UDP.into());
    request.fields.append(
        "proxy-authorization",
        volto::h3api::FieldValue::parse(credentials().as_bytes()).expect("a valid field value"),
    );
    request
}

/// How a transfer through a TCP tunnel ended.
///
/// The two failures are kept apart deliberately. A connection torn down under a
/// transfer is a *result* of this run -- restart bursts do exactly that, several
/// times a run, on purpose -- while a tunnel handed the wrong bytes is a fault
/// of the server, and the only one of the two worth failing the run over. An
/// earlier version of this file counted them as one thing and reported six
/// abortions as six mix-ups.
enum Transferred {
    /// The echo came back, all of it this tunnel's own bytes.
    Echoed(u64),
    /// The tunnel or the connection under it went away.
    Aborted,
    /// The echo carried some other tunnel's bytes.
    CrossTalk,
}

/// Pushes `bytes` through an accepted TCP tunnel and checks what comes back.
///
/// The first eight bytes of the payload are this tunnel's own tag, and the echo
/// has to start with them. That is the whole cross-talk check: a tunnel handed
/// another tunnel's data fails it, whatever else is true of the run.
async fn run_transfer(stream: &mut ClientStream, bytes: u32, tag: u64) -> Transferred {
    use bytes::Buf;

    let payload: Vec<u8> = {
        let mut buffer = vec![0u8; bytes as usize];
        let tag = tag.to_be_bytes();
        for (slot, byte) in buffer.iter_mut().zip(tag.iter().cycle()) {
            *slot = *byte;
        }
        buffer
    };

    for chunk in payload.chunks(CHUNK) {
        if stream
            .send_data(Bytes::copy_from_slice(chunk))
            .await
            .is_err()
        {
            return Transferred::Aborted;
        }
    }
    if stream.finish().is_err() {
        return Transferred::Aborted;
    }

    let mut echoed = Vec::with_capacity(payload.len());
    let mut ended_early = false;
    while echoed.len() < payload.len() {
        match stream.recv_data().await {
            Ok(Some(mut chunk)) => {
                echoed.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref())
            }
            // The target hung up early, or the connection went away underneath.
            Ok(None) | Err(_) => {
                ended_early = true;
                break;
            }
        }
    }

    // Checked on whatever arrived, aborted or not: bytes that reached this
    // tunnel from somewhere else are wrong however the tunnel then ended.
    if echoed.len() >= 8 && echoed[..8] != tag.to_be_bytes() {
        return Transferred::CrossTalk;
    }
    if ended_early {
        return Transferred::Aborted;
    }
    Transferred::Echoed(echoed.len() as u64)
}

/// Drives one planned tunnel to whatever end it reaches.
///
/// Nothing here panics on a failure of the tunnel: a connection aborted
/// mid-transfer by a restart burst is a *result* of this run, not a fault of it,
/// and the whole point of the harness is that those happen.
async fn run_tunnel(
    mut stream: ClientStream,
    plan: shape::TunnelPlan,
    tag: u64,
    tally: Arc<Tally>,
    router: Option<(Router, quinn::Connection)>,
) {
    let response = match timeout(RESPONSE_TIMEOUT, stream.recv_response()).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) | Err(_) => {
            tally.bump(&tally.tunnels_failed);
            return;
        }
    };

    if response.status != Status::OK {
        tally.bump(&tally.tunnels_refused);
        return;
    }
    tally.bump(&tally.tunnels_opened);

    match plan.kind {
        TunnelKind::Blackhole => {
            // D49: accepted, then closed at once with nothing sent. Reading must
            // reach end of stream rather than fail.
            let mut seen = 0usize;
            loop {
                match timeout(RESPONSE_TIMEOUT, stream.recv_data()).await {
                    Ok(Ok(Some(chunk))) => seen += chunk.len(),
                    Ok(Ok(None)) => break,
                    Ok(Err(_)) | Err(_) => {
                        tally.bump(&tally.tunnels_failed);
                        return;
                    }
                }
            }
            if seen == 0 {
                tally.bump(&tally.blackholes_closed_empty);
            } else {
                tally.bump(&tally.blackholes_unexpected);
            }
        }

        TunnelKind::Udp => {
            let Some((router, quic)) = router else {
                tally.bump(&tally.tunnels_failed);
                return;
            };
            tally.bump(&tally.udp_sessions);

            let quarter = datagram::quarter_stream_id(stream.id());
            let mut inbound = router.claim(quarter);

            // A packet per kilobyte the plan asked for, capped: a UDP session in
            // this data is a handful of DNS-sized exchanges, not a transfer.
            let packets = (plan.bytes / 1024).clamp(1, 8);
            for index in 0..packets {
                let payload = [&tag.to_be_bytes()[..], &index.to_be_bytes()[..]].concat();
                if quic
                    .send_datagram(datagram::encode_udp_payload(quarter, &payload))
                    .is_err()
                {
                    break;
                }
                match timeout(Duration::from_secs(5), inbound.recv()).await {
                    Ok(Some(answer)) => {
                        if answer.len() >= 8 && answer[..8] != tag.to_be_bytes() {
                            tally.bump(&tally.crosstalk);
                        } else {
                            tally.bump(&tally.udp_round_trips);
                        }
                    }
                    Ok(None) | Err(_) => {
                        tally.bump(&tally.udp_lost);
                        break;
                    }
                }
            }

            router.release(quarter);
            let _ = stream.finish();
        }

        TunnelKind::Tcp | TunnelKind::TcpLiteral => {
            match timeout(TRANSFER_TIMEOUT, run_transfer(&mut stream, plan.bytes, tag)).await {
                Ok(Transferred::Echoed(echoed)) => {
                    tally.bump(&tally.tunnels_transferred);
                    tally.bytes_echoed.fetch_add(echoed, Ordering::Relaxed);
                }
                Ok(Transferred::Aborted) => tally.bump(&tally.tunnels_aborted),
                Ok(Transferred::CrossTalk) => tally.bump(&tally.crosstalk),
                Err(_) => tally.bump(&tally.tunnels_failed),
            }
        }
    }
}

// --------------------------------------------------------------------------
// Driving one connection
// --------------------------------------------------------------------------

/// Connections still open, so a restart burst has something to abort.
type Live = Arc<Mutex<Vec<quinn::Connection>>>;

#[allow(clippy::too_many_arguments)]
async fn run_connection(
    server: Arc<TestServer>,
    targets: Arc<Targets>,
    plan: shape::ConnectionPlan,
    tally: Arc<Tally>,
    live: Live,
    idle_release: Instant,
    outlive_release: Instant,
    connection_tag: u64,
) {
    // A restart burst is a client that came back: whatever it was holding is
    // gone. Aborting a predecessor here rather than at plan time is what puts a
    // transfer genuinely in flight when the abort lands.
    if plan.in_burst {
        let victim = live.lock().expect("live lock").pop();
        if let Some(victim) = victim {
            victim.close(quinn::VarInt::from_u32(0), b"");
            tally.bump(&tally.aborted_by_burst);
        }
    }

    let client = match timeout(RESPONSE_TIMEOUT, H3Client::connect(&server)).await {
        Ok(client) => client,
        Err(_) => {
            tally.bump(&tally.handshakes_failed);
            return;
        }
    };
    let mut client = client;
    tally.bump(&tally.connections_started);

    let quic = client.quic.clone();
    live.lock().expect("live lock").push(quic.clone());
    let router = Router::spawn(quic.clone(), tally.clone());

    let mut bodies = Vec::new();
    let started = Instant::now();

    for (index, tunnel) in plan.tunnels.iter().enumerate() {
        sleep_until(started + Duration::from_millis(tunnel.at_ms)).await;

        // A connection's target slot maps straight onto the pool, without a
        // per-connection offset. Offsetting would spread the load evenly and
        // that is the wrong shape: the capture is one device's traffic, so its
        // popular targets are popular on *every* connection -- one target takes
        // a seventh of all tunnels and ten take two thirds. Spreading would
        // turn that into a flat scan and lose the per-target socket pressure
        // that goes with concentration.
        let slot = tunnel.target;
        let request = match tunnel.kind {
            TunnelKind::Udp => {
                connect_udp_request(server.addr, targets.udp[slot % targets.udp.len()])
            }
            other => connect_request(&targets.authority(other, slot)),
        };

        tally.bump(&tally.tunnels_requested);
        let stream = match client.send.send_request(request).await {
            Ok(stream) => stream,
            // The connection is gone -- aborted by a burst, or closed under us.
            Err(_) => {
                tally.bump(&tally.tunnels_failed);
                break;
            }
        };

        let tag = connection_tag
            .wrapping_mul(1_000_003)
            .wrapping_add(index as u64);
        bodies.push(tokio::spawn(run_tunnel(
            stream,
            tunnel.clone(),
            tag,
            tally.clone(),
            Some((router.clone(), quic.clone())),
        )));
    }

    // Let the transfers finish, but no longer than the connection was planned
    // to be active: a connection that ends mid-transfer is exactly what a
    // restart looks like from the server's side.
    let deadline = started + Duration::from_millis(plan.active_ms);
    let _ = timeout(
        deadline.saturating_duration_since(Instant::now()),
        futures_join(bodies),
    )
    .await;

    // The connection is no longer a candidate for a burst to abort.
    {
        let mut held = live.lock().expect("live lock");
        if let Some(position) = held
            .iter()
            .position(|other| other.stable_id() == quic.stable_id())
        {
            held.remove(position);
        }
    }

    match plan.ending {
        Ending::PeerClose => {
            quic.close(quinn::VarInt::from_u32(0), b"");
            tally.bump(&tally.ended_peer_close);
        }
        Ending::ProtocolViolation => {
            // H3_GENERAL_PROTOCOL_ERROR: what a client sends when it decides the
            // server broke the protocol. The reason is left empty, so the
            // server's log line names the code and nothing this test invented.
            quic.close(quinn::VarInt::from_u32(0x101), b"");
            tally.bump(&tally.ended_violation);
        }
        Ending::Idle => {
            // Say nothing at all and hold the connection open: the server's idle
            // timer is what ends it, which is how a client that switched
            // networks or exited leaves.
            tally.bump(&tally.ended_idle);
            sleep_until(idle_release).await;
        }
        Ending::Outlive => {
            tally.bump(&tally.ended_outlive);
            sleep_until(outlive_release).await;
        }
    }

    drop(client);
}

/// Awaits every handle, ignoring what they returned.
///
/// `futures::future::join_all` without the dependency: the handles are awaited
/// in order, which is enough because the point is only that all of them are
/// finished before the caller moves on.
async fn futures_join(handles: Vec<tokio::task::JoinHandle<()>>) {
    for handle in handles {
        let _ = handle.await;
    }
}

// --------------------------------------------------------------------------
// Reading the lab's own log
// --------------------------------------------------------------------------

/// What the server said about itself, read back off its own log lines.
///
/// The same lines production writes, read the same way: this is a Rust-side
/// summary for the assertions, and the log is written out whole so
/// `shape_extract.py` can build a full profile from it and put that beside the
/// production one.
#[derive(Default, Debug)]
struct LabLog {
    established: u64,
    closed: u64,
    by_reason: HashMap<String, u64>,
    error_closes: Vec<String>,
    violations: u64,
    tunnels: u64,
    dropped_datagrams: u64,
    lost_packets: u64,
    sent_packets: u64,
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!(" {key}=");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    Some(rest.split(' ').next().unwrap_or(rest))
}

fn number(line: &str, key: &str) -> u64 {
    field(line, key)
        .and_then(|value| value.trim_matches('"').parse().ok())
        .unwrap_or(0)
}

fn read_log(text: &str) -> LabLog {
    let mut log = LabLog::default();

    for line in text.lines() {
        if line.contains("connection established") {
            log.established += 1;
        } else if line.contains("connection closed with error") {
            log.closed += 1;
            log.tunnels += number(line, "tunnels");
            log.dropped_datagrams += number(line, "dropped_datagrams");
            log.lost_packets += number(line, "lost_packets");
            log.sent_packets += number(line, "sent_packets");

            let error = line
                .split(" error=")
                .nth(1)
                .map(|rest| rest.split(" rtt_ms=").next().unwrap_or(rest).to_owned())
                .unwrap_or_default();
            if error.contains("H3_GENERAL_PROTOCOL_ERROR") || error.contains("protocol compliance")
            {
                log.violations += 1;
            } else {
                log.error_closes.push(error);
            }
        } else if line.contains("connection closed") {
            log.closed += 1;
            log.tunnels += number(line, "tunnels");
            log.dropped_datagrams += number(line, "dropped_datagrams");
            log.lost_packets += number(line, "lost_packets");
            log.sent_packets += number(line, "sent_packets");
            let reason = field(line, "reason")
                .unwrap_or("?")
                .trim_matches('"')
                .to_owned();
            *log.by_reason.entry(reason).or_default() += 1;
        }
    }

    log
}

// --------------------------------------------------------------------------
// The run
// --------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "replay: minutes of shaped load; run it with --release --nocapture"]
async fn production_shapes_are_replayed() {
    let settings = Settings::from_env();

    let text = std::fs::read_to_string(&settings.profile).unwrap_or_else(|error| {
        panic!(
            "the shape profile {} must be readable: {error}",
            settings.profile
        )
    });
    let profile = Json::parse(&text).expect("the shape profile must be valid JSON");

    let scaling = shape::Scaling {
        wall_seconds: settings.wall_seconds,
        compression: settings.compression,
        idle_seconds: settings.idle_seconds,
        // The idle timeout that was in force when the capture was taken. The
        // server configures 60 seconds and both captured hosts run that
        // default, but RFC 9000 §10.1 makes the effective value the smaller of
        // the two advertisements and the client advertises 30 -- so 30 is what
        // an idle-ended connection in the capture actually waited out. See
        // `DEFAULT_MAX_IDLE_TIMEOUT` in `src/config.rs`.
        production_idle_seconds: 30,
        max_transfer: settings.max_transfer,
        max_tunnels: settings.max_tunnels,
    };
    let plan = shape::plan(&profile, scaling, settings.seed);

    let buffer = SharedBuffer::install("info");
    let server = Arc::new(TestServer::start_with(&settings.config()).await);
    let targets = Arc::new(Targets::spawn(settings.targets).await);
    let tally = Arc::new(Tally::default());
    let live: Live = Arc::new(Mutex::new(Vec::new()));

    let planned_tunnels: usize = plan.connections.iter().map(|c| c.tunnels.len()).sum();
    println!(
        "\n--- replay plan ---\n\
         profile               {}\n\
         seed                  {}\n\
         wall seconds          {}\n\
         compression           {:.0}x  ({:.2} production hours in {} seconds)\n\
         lab idle timeout      {}s = {:.0} production-seconds against production's {}s,\n\
         \x20                     so an idle-ended connection holds its slot {:.0}x too long\n\
         \x20                     and measured lifetime and concurrency read high by about that\n\
         connections planned   {}\n\
         tunnels planned       {}\n\
         lab targets           {} TCP, {} UDP\n\
         from joint table      {} of {} connections\n\
         capped tunnel counts  {}\n\
         capped transfers      {}\n\
         collapsed spacings    {}\n\
         tunnels past window   {}\n",
        settings.profile,
        settings.seed,
        settings.wall_seconds,
        settings.compression,
        settings.wall_seconds as f64 * settings.compression / 3600.0,
        settings.wall_seconds,
        settings.idle_seconds,
        settings.idle_seconds as f64 * settings.compression,
        scaling.production_idle_seconds,
        settings.idle_seconds as f64 * settings.compression
            / scaling.production_idle_seconds as f64,
        plan.connections.len(),
        planned_tunnels,
        targets.echo.len(),
        targets.udp.len(),
        plan.compromises.from_joint_table,
        plan.connections.len(),
        plan.compromises.tunnel_counts_capped,
        plan.compromises.transfers_capped,
        plan.compromises.spacings_collapsed,
        plan.compromises.tunnels_past_window,
    );

    let start = Instant::now();
    let run_end = start + Duration::from_secs(settings.wall_seconds);
    let idle_release = run_end + Duration::from_secs(settings.idle_seconds + 3);
    let outlive_release = idle_release + Duration::from_secs(5);

    let mut drivers = Vec::with_capacity(plan.connections.len());
    for (index, connection) in plan.connections.into_iter().enumerate() {
        sleep_until(start + Duration::from_millis(connection.start_ms)).await;
        drivers.push(tokio::spawn(run_connection(
            server.clone(),
            targets.clone(),
            connection,
            tally.clone(),
            live.clone(),
            idle_release,
            outlive_release,
            index as u64,
        )));
    }

    // Every driver returns once its connection has ended the way its plan said,
    // which for an idle ending is after the server's timer has had time to fire.
    futures_join(drivers).await;

    // Nothing is left driving; give the last closing lines time to be written,
    // then take the server down so anything still open is logged as drained.
    sleep_until(outlive_release).await;
    let mut server =
        Arc::try_unwrap(server).unwrap_or_else(|_| panic!("the server outlived every driver"));
    server.shutdown();
    server.wait_until_stopped(Duration::from_secs(30)).await;

    let log = buffer.contents();
    std::fs::write(&settings.log_path, &log).expect("write the server log");
    let summary = read_log(&log);

    let elapsed = start.elapsed();
    println!(
        "--- client side ---\n\
         wall clock            {:.1}s\n\
         connections started   {} ({} handshakes failed)\n\
         endings driven        idle {}, peer_close {}, protocol_violation {}, outlive {}\n\
         burst aborts          {}\n\
         tunnels requested     {}\n\
         tunnels opened (200)  {}\n\
         tunnels refused       {}\n\
         tunnels failed        {}\n\
         transfers aborted     {}  (a restart burst tearing one down mid-flight)\n\
         transfers completed   {} ({} bytes echoed)\n\
         blackholes            {} closed empty, {} carried data\n\
         udp sessions          {} ({} round trips, {} lost)\n\
         cross-talk            {}\n",
        elapsed.as_secs_f64(),
        tally.connections_started.load(Ordering::Relaxed),
        tally.handshakes_failed.load(Ordering::Relaxed),
        tally.ended_idle.load(Ordering::Relaxed),
        tally.ended_peer_close.load(Ordering::Relaxed),
        tally.ended_violation.load(Ordering::Relaxed),
        tally.ended_outlive.load(Ordering::Relaxed),
        tally.aborted_by_burst.load(Ordering::Relaxed),
        tally.tunnels_requested.load(Ordering::Relaxed),
        tally.tunnels_opened.load(Ordering::Relaxed),
        tally.tunnels_refused.load(Ordering::Relaxed),
        tally.tunnels_failed.load(Ordering::Relaxed),
        tally.tunnels_aborted.load(Ordering::Relaxed),
        tally.tunnels_transferred.load(Ordering::Relaxed),
        tally.bytes_echoed.load(Ordering::Relaxed),
        tally.blackholes_closed_empty.load(Ordering::Relaxed),
        tally.blackholes_unexpected.load(Ordering::Relaxed),
        tally.udp_sessions.load(Ordering::Relaxed),
        tally.udp_round_trips.load(Ordering::Relaxed),
        tally.udp_lost.load(Ordering::Relaxed),
        tally.crosstalk.load(Ordering::Relaxed),
    );

    let mut reasons: Vec<_> = summary.by_reason.iter().collect();
    reasons.sort();
    println!(
        "--- server side, off its own log ---\n\
         established           {}\n\
         closed                {}\n\
         close reasons         {:?}\n\
         protocol violations   {}  ({:.4} per 1000 connections, {:.4} per 1000 tunnels)\n\
         other error closes    {} {:?}\n\
         tunnels reported      {}\n\
         dropped datagrams     {}\n\
         packets               {} sent, {} lost\n\
         log written to        {}\n",
        summary.established,
        summary.closed,
        reasons,
        summary.violations,
        1000.0 * summary.violations as f64 / summary.established.max(1) as f64,
        1000.0 * summary.violations as f64 / summary.tunnels.max(1) as f64,
        summary.error_closes.len(),
        summary.error_closes,
        summary.tunnels,
        summary.dropped_datagrams,
        summary.sent_packets,
        summary.lost_packets,
        settings.log_path.display(),
    );

    // The three assertions a replay is uniquely able to make. Everything above
    // is a measurement and is printed rather than asserted; these are about the
    // server having done something wrong under a load nothing else produces.
    assert_eq!(
        summary.error_closes,
        Vec::<String>::new(),
        "the server ended connections with errors this run did not inject"
    );
    assert_eq!(
        summary.dropped_datagrams, 0,
        "the server dropped inbound datagrams instead of delivering them"
    );
    assert_eq!(
        tally.crosstalk.load(Ordering::Relaxed),
        0,
        "a tunnel was handed another tunnel's data"
    );
}
