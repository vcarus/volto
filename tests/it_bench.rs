//! Loopback performance baseline: throughput, packet rates and churn.
//!
//! Every test here is `#[ignore]`d, and the binary itself is behind the
//! `operator-runs` feature, so `cargo test` neither builds, runs nor is slowed
//! by them. Naming the target without the feature is an error rather than an
//! empty pass — see the feature's comment in `Cargo.toml`. Run the set with
//!
//! ```sh
//! cargo test --release --features operator-runs --test it_bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! # What the numbers mean, and what they do not
//!
//! The test harness runs the client, the proxy and the target **in one
//! process**, which is what makes these benchmarks dependency-free and hermetic
//! — and what makes every CPU figure here the sum of all three. They are
//! comparable against each other and against a later run of the same harness;
//! they are not a statement about what the proxy alone costs. Splitting the
//! three apart is a profiler's job (`/usr/bin/sample` on macOS), not this
//! harness's.
//!
//! Two more caveats worth carrying into any conclusion:
//!
//! * On macOS `quinn-udp` runs with a batch size of one and no GSO/GRO, while
//!   the Linux deployment has both. Absolute UDP packet rates measured here are
//!   therefore a floor, not a prediction; what does carry over is the *relative*
//!   cost of the work inside this crate — encode, route, channel, allocate —
//!   against the syscall and crypto around it.
//! * Loopback has no loss, no reordering and a sub-millisecond RTT, so the
//!   congestion controller and the loss recovery timers barely participate.
//!
//! # Knobs
//!
//! All optional, all read from the environment:
//!
//! | variable | default | meaning |
//! |---|---|---|
//! | `VOLTO_BENCH_MB` | 128 | payload per TCP throughput repetition, MiB |
//! | `VOLTO_BENCH_PACKETS` | 100000 | datagrams per UDP repetition, per direction |
//! | `VOLTO_BENCH_CYCLES` | 2000 | open/close cycles per churn repetition |
//! | `VOLTO_BENCH_CONCURRENT` | 500 | tunnels opened at once |
//! | `VOLTO_BENCH_REPS` | 3 | measured repetitions after the warm-up |
//! | `VOLTO_BENCH_SECONDS` | 0 | if set, UDP repetitions run for this long instead of a packet count (for profiling) |

// An argued exception to the package's `unsafe_code = "deny"`: `getrusage` is
// raw libc FFI because rustix wraps no equivalent, and it only fills a struct
// the two call sites read once.
#![allow(unsafe_code)]

mod common;

#[path = "common/alloc.rs"]
mod alloc;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use common::{
    ALLOW_PRIVATE, H3Client, TestServer, close_and_drain, open_tcp_tunnel, open_udp_session,
    read_to_end,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Semaphore, mpsc};
use volto::datagram;

// ---------------------------------------------------------------------------
// Counting allocator
// ---------------------------------------------------------------------------

/// A pass-through allocator that counts what goes through it.
///
/// The point is ADR D29: the UDP outbound path allocates one `BytesMut` per
/// packet, and the question that shelved it was how much that costs. A global
/// counter answers "how many allocations per packet does the whole pipeline
/// make", which bounds the answer from above no matter where they come from.
///
/// Reallocation counts as one allocation of the growth, which is what makes a
/// `Vec` that doubles look like the several allocations it really is.
struct Counting;

static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

impl alloc::Record for Counting {
    fn allocated(size: usize) {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(size as u64, Ordering::Relaxed);
    }

    fn reallocated(old: usize, new: usize) {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new.saturating_sub(old) as u64, Ordering::Relaxed);
    }
}

#[global_allocator]
static GLOBAL: alloc::PassThrough<Counting> = alloc::PassThrough::new();

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// Process CPU time, user + system, from `getrusage(RUSAGE_SELF)`.
///
/// Process-wide on purpose: the work under measurement is spread over the tokio
/// worker threads, the quinn endpoint driver and the target tasks, and no
/// per-thread accounting would add them up correctly.
fn cpu_time() -> Duration {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: `getrusage` fills the `rusage` it is handed; the pointer is valid
    // and correctly aligned, and the value is only read after a success return.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    assert_eq!(rc, 0, "getrusage failed");
    // SAFETY: `getrusage` returned 0, so the struct is initialised.
    let usage = unsafe { usage.assume_init() };

    fn to_duration(tv: libc::timeval) -> Duration {
        Duration::new(tv.tv_sec as u64, (tv.tv_usec as u32).saturating_mul(1_000))
    }

    to_duration(usage.ru_utime) + to_duration(usage.ru_stime)
}

/// Peak resident set size in bytes.
///
/// `ru_maxrss` is bytes on macOS and kibibytes on Linux, and it is a high-water
/// mark rather than a current reading — a difference between two samples is
/// "how much further the peak moved", never a decrease.
fn max_rss_bytes() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: as in `cpu_time`.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    assert_eq!(rc, 0, "getrusage failed");
    // SAFETY: as in `cpu_time`.
    let usage = unsafe { usage.assume_init() };

    let raw = usage.ru_maxrss.max(0) as u64;
    if cfg!(target_os = "macos") {
        raw
    } else {
        raw * 1024
    }
}

/// An open measurement window: wall clock, CPU time and allocations.
struct Window {
    wall: Instant,
    cpu: Duration,
    rss: u64,
}

impl Window {
    fn open() -> Self {
        ALLOC_COUNT.store(0, Ordering::Relaxed);
        ALLOC_BYTES.store(0, Ordering::Relaxed);
        Self {
            wall: Instant::now(),
            cpu: cpu_time(),
            rss: max_rss_bytes(),
        }
    }

    fn close(self) -> Totals {
        self.close_at(Instant::now())
    }

    /// Closes the window with an explicit end instant.
    ///
    /// Used where the last useful event and the moment the test notices it are
    /// not the same thing — a drain loop polling for the final packets, say.
    fn close_at(self, end: Instant) -> Totals {
        Totals {
            wall: end.saturating_duration_since(self.wall),
            cpu: cpu_time().saturating_sub(self.cpu),
            allocs: ALLOC_COUNT.load(Ordering::Relaxed),
            alloc_bytes: ALLOC_BYTES.load(Ordering::Relaxed),
            rss_delta: max_rss_bytes().saturating_sub(self.rss),
        }
    }
}

/// What one repetition cost.
struct Totals {
    wall: Duration,
    cpu: Duration,
    allocs: u64,
    alloc_bytes: u64,
    rss_delta: u64,
}

/// One repetition's raw counts, from which every reported metric is derived.
#[derive(Clone, Copy)]
struct Rep {
    wall_s: f64,
    cpu_s: f64,
    allocs: f64,
    alloc_bytes: f64,
    rss_delta: f64,
    /// Whatever the scenario counts: bytes, packets or cycles.
    units: f64,
    /// Payload bytes moved, for the scenarios where that is not `units`.
    payload_bytes: f64,
    /// Units offered and units that arrived, for loss.
    sent: f64,
    delivered: f64,
}

impl Rep {
    fn new(totals: Totals, units: f64, payload_bytes: f64, sent: f64, delivered: f64) -> Self {
        Self {
            wall_s: totals.wall.as_secs_f64(),
            cpu_s: totals.cpu.as_secs_f64(),
            allocs: totals.allocs as f64,
            alloc_bytes: totals.alloc_bytes as f64,
            rss_delta: totals.rss_delta as f64,
            units,
            payload_bytes,
            sent,
            delivered,
        }
    }
}

/// How a scenario's counts should be phrased.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `units` are bytes: report MB/s, CPU-seconds per GB, allocations per MiB.
    Bytes,
    /// `units` are datagrams: report packets/s, CPU µs per packet, allocations
    /// per packet, and loss.
    Packets,
    /// `units` are open/close cycles: report cycles/s and allocations per cycle.
    Cycles,
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in a measurement"));
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

/// Prints one line per repetition and one for the median of each metric.
fn report(name: &str, kind: Kind, reps: &[Rep]) {
    for (i, rep) in reps.iter().enumerate() {
        println!("bench {name} rep{}: {}", i + 1, line(kind, rep));
    }
    if reps.len() > 1 {
        println!("bench {name} median: {}", medians(kind, reps));
    }
}

fn line(kind: Kind, rep: &Rep) -> String {
    match kind {
        Kind::Bytes => format!(
            "{:.1} MiB in {:.3} s -> {:.1} MB/s, cpu {:.3} s ({:.1}% of wall), {:.2} cpu-s/GB, \
             {:.0} allocs/MiB, {:.2} alloc-KiB/MiB",
            rep.units / (1024.0 * 1024.0),
            rep.wall_s,
            rep.units / 1e6 / rep.wall_s,
            rep.cpu_s,
            100.0 * rep.cpu_s / rep.wall_s,
            rep.cpu_s / (rep.units / 1e9),
            rep.allocs / (rep.units / (1024.0 * 1024.0)),
            rep.alloc_bytes / 1024.0 / (rep.units / (1024.0 * 1024.0)),
        ),
        Kind::Packets => format!(
            "{:.0} pkt in {:.3} s -> {:.0} pkt/s, {:.1} MB/s payload, cpu {:.3} s, \
             {:.2} cpu-us/pkt, {:.2} allocs/pkt, {:.0} alloc-B/pkt, loss {:.2}%",
            rep.units,
            rep.wall_s,
            rep.units / rep.wall_s,
            rep.payload_bytes / 1e6 / rep.wall_s,
            rep.cpu_s,
            rep.cpu_s * 1e6 / rep.units,
            rep.allocs / rep.units,
            rep.alloc_bytes / rep.units,
            100.0 * (rep.sent - rep.delivered) / rep.sent.max(1.0),
        ),
        Kind::Cycles => format!(
            "{:.0} cycles in {:.3} s -> {:.0} cycles/s, cpu {:.3} s, {:.0} cpu-us/cycle, \
             {:.0} allocs/cycle, {:.1} alloc-KiB/cycle, peak rss +{:.1} MiB",
            rep.units,
            rep.wall_s,
            rep.units / rep.wall_s,
            rep.cpu_s,
            rep.cpu_s * 1e6 / rep.units,
            rep.allocs / rep.units,
            rep.alloc_bytes / 1024.0 / rep.units,
            rep.rss_delta / (1024.0 * 1024.0),
        ),
    }
}

/// The median of each metric taken independently.
///
/// Independently rather than "the median repetition": with three repetitions of
/// a loopback benchmark the interesting failure is one metric drifting, and a
/// per-metric median makes that visible instead of hiding it behind whichever
/// repetition won on throughput.
fn medians(kind: Kind, reps: &[Rep]) -> String {
    let pick = |f: fn(&Rep) -> f64| median(reps.iter().map(f).collect());

    match kind {
        Kind::Bytes => format!(
            "{:.1} MB/s, {:.2} cpu-s/GB, {:.0} allocs/MiB",
            pick(|r| r.units / 1e6 / r.wall_s),
            pick(|r| r.cpu_s / (r.units / 1e9)),
            pick(|r| r.allocs / (r.units / (1024.0 * 1024.0))),
        ),
        Kind::Packets => format!(
            "{:.0} pkt/s, {:.1} MB/s payload, {:.2} cpu-us/pkt, {:.2} allocs/pkt, loss {:.2}%",
            pick(|r| r.units / r.wall_s),
            pick(|r| r.payload_bytes / 1e6 / r.wall_s),
            pick(|r| r.cpu_s * 1e6 / r.units),
            pick(|r| r.allocs / r.units),
            pick(|r| 100.0 * (r.sent - r.delivered) / r.sent.max(1.0)),
        ),
        Kind::Cycles => format!(
            "{:.0} cycles/s, {:.0} cpu-us/cycle, {:.0} allocs/cycle",
            pick(|r| r.units / r.wall_s),
            pick(|r| r.cpu_s * 1e6 / r.units),
            pick(|r| r.allocs / r.units),
        ),
    }
}

// ---------------------------------------------------------------------------
// Knobs
// ---------------------------------------------------------------------------

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn megabytes() -> usize {
    env_u64("VOLTO_BENCH_MB", 128) as usize * 1024 * 1024
}

fn packets() -> u64 {
    env_u64("VOLTO_BENCH_PACKETS", 100_000)
}

fn cycles() -> u64 {
    env_u64("VOLTO_BENCH_CYCLES", 2_000)
}

fn concurrent() -> usize {
    env_u64("VOLTO_BENCH_CONCURRENT", 500) as usize
}

fn reps() -> usize {
    env_u64("VOLTO_BENCH_REPS", 3).max(1) as usize
}

/// A wall-clock budget per repetition, replacing the packet count when set.
///
/// The profiling mode: `/usr/bin/sample` needs a steady state to sample, which a
/// repetition that finishes in two seconds does not provide.
fn seconds() -> Option<Duration> {
    match env_u64("VOLTO_BENCH_SECONDS", 0) {
        0 => None,
        secs => Some(Duration::from_secs(secs)),
    }
}

/// Prints the caveats once per process, so a captured log explains itself.
fn header() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        println!(
            "bench header: client, proxy and target share this process; every cpu figure is the \
             sum of all three."
        );
        // The platform caveat is the one line a captured log is read against
        // later, so it must describe the host it ran on rather than the host
        // it was written on.
        match std::env::consts::OS {
            "linux" => println!(
                "bench header: loopback on linux, where quinn-udp batches with GSO/GRO as the \
                 deployment does; absolute udp rates are still loopback rates, not a path's."
            ),
            os => println!(
                "bench header: loopback on {os}, where quinn-udp has no GSO/GRO and a batch size \
                 of one; absolute udp rates do not carry to linux, the cost breakdown does."
            ),
        }
        println!(
            "bench header: threads={}, mb={}, packets={}, cycles={}, concurrent={}, reps={}, \
             seconds={:?}",
            std::thread::available_parallelism().map_or(0, |n| n.get()),
            megabytes() / (1024 * 1024),
            packets(),
            cycles(),
            concurrent(),
            reps(),
            seconds(),
        );
    });
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

/// A TCP target that writes `total` bytes as fast as the socket takes them.
async fn spawn_tcp_source(total: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind source");
    let addr = listener.local_addr().expect("source address");

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let chunk = vec![0x5au8; 64 * 1024];
                let mut left = total;
                while left > 0 {
                    let take = left.min(chunk.len());
                    if socket.write_all(&chunk[..take]).await.is_err() {
                        return;
                    }
                    left -= take;
                }
                // Dropping the socket is the EOF the proxy turns into a stream
                // FIN, which is what ends the client's read loop.
            });
        }
    });

    addr
}

/// A TCP target that reads to EOF and reports how many bytes it swallowed.
async fn spawn_tcp_sink() -> (SocketAddr, mpsc::Receiver<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind sink");
    let addr = listener.local_addr().expect("sink address");
    let (tx, rx) = mpsc::channel(4);

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 256 * 1024];
                let mut total = 0usize;
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => total += n,
                    }
                }
                let _ = tx.send(total).await;
            });
        }
    });

    (addr, rx)
}

/// A UDP target that counts what arrives and answers nothing.
///
/// Each packet returns a permit to `window`, which is what keeps the client from
/// outrunning the pipeline: the two together bound the packets in flight without
/// needing a reply path that would make the measurement bidirectional.
async fn spawn_udp_sink(window: Arc<Semaphore>) -> (SocketAddr, Arc<AtomicU64>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp sink");
    let addr = socket.local_addr().expect("udp sink address");
    let received = Arc::new(AtomicU64::new(0));

    let counter = received.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok(_) => {
                    counter.fetch_add(1, Ordering::Relaxed);
                    window.add_permits(1);
                }
                Err(_) => return,
            }
        }
    });

    (addr, received)
}

/// A UDP target that answers each packet with a burst of `burst` replies.
///
/// The client meters the bursts, so the packets in flight towards it stay
/// bounded while the target still gets to send back to back — which is the shape
/// of the download direction the proxy actually has to survive.
async fn spawn_udp_burst_target(size: usize, burst: usize) -> (SocketAddr, Arc<AtomicU64>) {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp burst");
    let addr = socket.local_addr().expect("udp burst address");
    let sent = Arc::new(AtomicU64::new(0));

    let counter = sent.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let reply = vec![0x5au8; size];
        loop {
            let from = match socket.recv_from(&mut buf).await {
                Ok((_, from)) => from,
                Err(_) => return,
            };
            for i in 0..burst {
                // A loopback socket can refuse a packet under pressure; that is a
                // drop before the proxy ever sees it, so it must not be counted
                // as one the proxy lost.
                if socket.send_to(&reply, from).await.is_ok() {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                if i % 32 == 31 {
                    tokio::task::yield_now().await;
                }
            }
        }
    });

    (addr, sent)
}

/// Allows loopback targets and turns the RFC 9298 §7 amplification cap off.
///
/// The cap exists to stop a session whose target never answers; the uplink
/// benchmark is exactly such a session by construction, so leaving the cap on
/// would measure the cap rather than the path.
const UNMETERED: &str = "[security]\nallow_private_networks = true\nunanswered_packet_budget = 0\n";

// ---------------------------------------------------------------------------
// Scenario 1: TCP throughput
// ---------------------------------------------------------------------------

async fn tcp_download(total: usize) -> Rep {
    let server = TestServer::start().await;
    let target = spawn_tcp_source(total).await;
    let mut client = H3Client::connect(&server).await;
    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    // The clock starts after the 200: setting a tunnel up is scenario 4's
    // subject, not this one's.
    let window = Window::open();
    let received = tokio::time::timeout(Duration::from_secs(300), async {
        let mut received = 0usize;
        while let Some(chunk) = stream.recv_data().await.expect("read the tunnel") {
            received += chunk.remaining();
        }
        received
    })
    .await
    .expect("the download finished inside the budget");
    let totals = window.close();

    assert_eq!(received, total, "the download was truncated");
    Rep::new(totals, total as f64, total as f64, 0.0, 0.0)
}

async fn tcp_upload(total: usize) -> Rep {
    let server = TestServer::start().await;
    let (target, mut done) = spawn_tcp_sink().await;
    let mut client = H3Client::connect(&server).await;
    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    // One buffer, sliced per write: `Bytes::slice` shares it, so the send loop
    // itself allocates nothing and the allocations counted are the pipeline's.
    let source = Bytes::from(vec![0x5au8; 64 * 1024]);

    let window = Window::open();
    let mut left = total;
    while left > 0 {
        let take = left.min(source.len());
        stream
            .send_data(source.slice(..take))
            .await
            .expect("write into the tunnel");
        left -= take;
    }
    stream.finish().expect("finish the request stream");

    // The transfer is over when the *target* has it, not when the client handed
    // it to quinn: everything still in flight is work this process has not done.
    let sunk = tokio::time::timeout(Duration::from_secs(300), done.recv())
        .await
        .expect("the upload finished inside the budget")
        .expect("the sink reported");
    let totals = window.close();

    assert_eq!(sunk, total, "the upload was truncated");
    Rep::new(totals, total as f64, total as f64, 0.0, 0.0)
}

// ---------------------------------------------------------------------------
// Scenarios 2 and 3: UDP, client to target
// ---------------------------------------------------------------------------

/// Datagrams in flight from the target towards the client.
///
/// Loopback's RTT is tens of microseconds, so a few hundred packets is already
/// far more than the pipeline needs to stay busy; the window is here to stop the
/// queues from being the experiment.
const IN_FLIGHT: usize = 256;

/// Datagrams in flight from the client towards the target.
///
/// Deliberately below `h3::connection::INBOUND_QUEUE_DEPTH` (64), the
/// per-session channel the connection's datagram router `try_send`s into. That queue is the real
/// bound on this direction: the router drops rather than blocks, by design, so
/// letting more than 64 packets pile up in front of one session measures the
/// drop policy instead of the forwarding cost. Measured at a 256-packet window,
/// this path loses about 4% of its packets for exactly that reason.
const UPLINK_IN_FLIGHT: usize = 48;

async fn udp_uplink(size: usize, count: u64, budget: Option<Duration>) -> Rep {
    let server = TestServer::start_with(UNMETERED).await;
    let permits = Arc::new(Semaphore::new(UPLINK_IN_FLIGHT));
    let (target, delivered) = spawn_udp_sink(permits.clone()).await;
    let mut client = H3Client::connect(&server).await;
    let (qsid, _stream) = open_udp_session(&mut client, &server, target).await;

    // Encoded once and cloned per send: cloning `Bytes` is a refcount bump, so
    // the client contributes no per-packet allocation and what the counter sees
    // is the proxy's own.
    let payload = vec![0x5au8; size];
    let encoded = datagram::encode_udp_payload(qsid, &payload);
    assert!(
        encoded.len() <= client.quic.max_datagram_size().unwrap_or(0),
        "a {size}-byte payload does not fit this connection's datagrams"
    );

    let sent = Arc::new(AtomicU64::new(0));
    let counted = sent.clone();
    let window = Window::open();
    let started = window.wall;

    let send_budget = budget.unwrap_or(Duration::from_secs(120)) + Duration::from_secs(30);
    let _ = tokio::time::timeout(send_budget, async {
        let mut n = 0u64;
        while n < count {
            let permit = permits.acquire().await.expect("the window stays open");
            // The target hands permits back explicitly, one per packet it sees.
            permit.forget();

            if client.quic.send_datagram(encoded.clone()).is_err() {
                break;
            }
            n += 1;
            counted.store(n, Ordering::Relaxed);

            if n.is_multiple_of(64)
                && let Some(budget) = budget
                && started.elapsed() >= budget
            {
                break;
            }
        }
    })
    .await;

    let sent = sent.load(Ordering::Relaxed);

    // Drain: the last `IN_FLIGHT` packets are still in the pipeline. The end
    // instant is when the target stopped making progress, so a lossy run is not
    // charged for the time it spent waiting for packets that will never arrive.
    let mut seen = delivered.load(Ordering::Relaxed);
    let mut progressed = Instant::now();
    let end = loop {
        let now = delivered.load(Ordering::Relaxed);
        if now >= sent {
            break Instant::now();
        }
        if now != seen {
            seen = now;
            progressed = Instant::now();
        } else if progressed.elapsed() > Duration::from_millis(300) {
            break progressed;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    };
    let totals = window.close_at(end);
    let arrived = delivered.load(Ordering::Relaxed).min(sent);

    Rep::new(
        totals,
        arrived as f64,
        (arrived as usize * size) as f64,
        sent as f64,
        arrived as f64,
    )
}

// ---------------------------------------------------------------------------
// Scenarios 2 and 3: UDP, target to client
// ---------------------------------------------------------------------------

/// Replies a single request draws from the burst target.
const BURST: usize = 64;

async fn udp_downlink(size: usize, count: u64, budget: Option<Duration>) -> Rep {
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let (target, target_sent) = spawn_udp_burst_target(size, BURST).await;
    let mut client = H3Client::connect(&server).await;
    let (qsid, _stream) = open_udp_session(&mut client, &server, target).await;

    let request = datagram::encode_udp_payload(qsid, b"go");
    let limit = client.quic.max_datagram_size().unwrap_or(0);
    assert!(
        datagram::encoded_len(qsid, datagram::CONTEXT_ID_UDP_PAYLOAD, size) <= limit,
        "a {size}-byte reply does not fit this connection's datagrams"
    );

    let requests = count.div_ceil(BURST as u64);
    let mut requested = 0u64;
    let mut received = 0u64;
    let mut payload_bytes = 0u64;

    // A single timer for the whole loop, reset in batches: a per-packet timeout
    // would allocate once per packet and land in the number this whole harness
    // exists to measure.
    let idle = tokio::time::sleep(Duration::from_millis(400));
    tokio::pin!(idle);

    let window = Window::open();
    let started = window.wall;
    let mut last_seen = started;

    // Prime the pipe.
    while requested < requests && requested * BURST as u64 <= received + IN_FLIGHT as u64 {
        client
            .quic
            .send_datagram(request.clone())
            .expect("send a request");
        requested += 1;
    }

    let end = loop {
        tokio::select! {
            biased;
            raw = client.quic.read_datagram() => {
                let Ok(raw) = raw else { break last_seen };
                let decoded = datagram::decode(raw).expect("the proxy encodes valid datagrams");
                if received == 0 {
                    assert_eq!(decoded.quarter_stream_id, qsid, "datagram misrouted");
                }
                received += 1;
                payload_bytes += decoded.payload.len() as u64;

                while requested < requests
                    && requested * BURST as u64 <= received + IN_FLIGHT as u64
                {
                    if client.quic.send_datagram(request.clone()).is_err() {
                        break;
                    }
                    requested += 1;
                }

                if received.is_multiple_of(64) {
                    last_seen = Instant::now();
                    idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_millis(400));
                    if let Some(budget) = budget
                        && started.elapsed() >= budget
                    {
                        break last_seen;
                    }
                }
                if requested == requests && received >= requests * BURST as u64 {
                    break Instant::now();
                }
            }
            _ = &mut idle => break last_seen,
        }
    };
    let totals = window.close_at(end);

    // What the target managed to put on the wire is the honest denominator: a
    // packet loopback refused at the target was never the proxy's to lose.
    let offered = target_sent.load(Ordering::Relaxed).max(received);

    Rep::new(
        totals,
        received as f64,
        payload_bytes as f64,
        offered as f64,
        received as f64,
    )
}

// ---------------------------------------------------------------------------
// Scenario 4: churn
// ---------------------------------------------------------------------------

async fn tcp_churn(count: u64) -> Rep {
    let server = TestServer::start_with(&format!(
        "[limits]\nmax_targets_per_conn = 64\n{ALLOW_PRIVATE}"
    ))
    .await;
    let target = common::spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;
    let authority = target.to_string();

    let window = Window::open();
    for _ in 0..count {
        let mut stream = open_tcp_tunnel(&mut client, &authority).await;
        // Closing without a round trip would measure a tunnel that may never
        // have reached its target; a FIN answered by the target's EOF proves the
        // whole path was built and torn down.
        close_and_drain(&mut stream).await;
    }
    let totals = window.close();

    Rep::new(totals, count as f64, 0.0, 0.0, 0.0)
}

async fn udp_churn(count: u64) -> Rep {
    let server = TestServer::start_with(&format!(
        "[limits]\nmax_targets_per_conn = 64\n{ALLOW_PRIVATE}"
    ))
    .await;
    let target = common::spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let window = Window::open();
    for _ in 0..count {
        let (_qsid, mut stream) = open_udp_session(&mut client, &server, target).await;
        close_and_drain(&mut stream).await;
    }
    let totals = window.close();

    Rep::new(totals, count as f64, 0.0, 0.0, 0.0)
}

/// Opens `count` tunnels on one connection, then closes them all.
async fn concurrent_tunnels(count: usize) -> (Rep, Rep) {
    let server = TestServer::start_with(&format!(
        "[limits]\nmax_targets_per_conn = {}\n{ALLOW_PRIVATE}",
        count + 8
    ))
    .await;
    let target = common::spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;
    let authority = target.to_string();

    let opening = Window::open();
    let mut streams = Vec::with_capacity(count);
    for _ in 0..count {
        streams.push(open_tcp_tunnel(&mut client, &authority).await);
    }
    let open_totals = opening.close();

    let closing = Window::open();
    for stream in &mut streams {
        stream.finish().expect("finish the request stream");
    }
    for stream in &mut streams {
        read_to_end(stream).await;
    }
    let close_totals = closing.close();

    (
        Rep::new(open_totals, count as f64, 0.0, 0.0, 0.0),
        Rep::new(close_totals, count as f64, 0.0, 0.0, 0.0),
    )
}

// ---------------------------------------------------------------------------
// The benchmarks
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark: run it deliberately, with --release --nocapture"]
async fn bench_tcp_download() {
    header();
    let total = megabytes();
    // Warm-up: the first run pays for lazily initialised crypto, thread spawns
    // and a cold allocator, none of which the steady state pays again.
    tcp_download(total / 8).await;

    let mut results = Vec::new();
    for _ in 0..reps() {
        results.push(tcp_download(total).await);
    }
    report("tcp_download", Kind::Bytes, &results);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark: run it deliberately, with --release --nocapture"]
async fn bench_tcp_upload() {
    header();
    let total = megabytes();
    tcp_upload(total / 8).await;

    let mut results = Vec::new();
    for _ in 0..reps() {
        results.push(tcp_upload(total).await);
    }
    report("tcp_upload", Kind::Bytes, &results);
}

/// Warms one UDP direction up, then measures it.
///
/// The phase marker is for the profiler rather than the reader: sampling has to
/// be aimed at a steady state, and a line appearing on stdout is something a
/// script outside the process can wait for. It is printed only in the timed
/// mode, which is the only mode long enough to sample.
async fn udp_direction<F, Fut>(
    name: &str,
    size: usize,
    count: u64,
    budget: Option<Duration>,
    direction: F,
) where
    F: Fn(usize, u64, Option<Duration>) -> Fut,
    Fut: std::future::Future<Output = Rep>,
{
    // The warm-up pays for lazily initialised crypto, thread spawns and a cold
    // allocator; a fraction of the budget is enough for that.
    direction(size, count / 8, budget.map(|budget| budget / 8)).await;

    if budget.is_some() {
        println!("bench phase: {name} measuring");
    }

    let mut results = Vec::new();
    for _ in 0..reps() {
        results.push(direction(size, count, budget).await);
    }
    report(name, Kind::Packets, &results);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark: run it deliberately, with --release --nocapture"]
async fn bench_udp_large_datagrams() {
    header();
    let count = packets();
    let budget = seconds();

    udp_direction("udp_1200_client_to_target", 1200, count, budget, udp_uplink).await;
    udp_direction(
        "udp_1200_target_to_client",
        1200,
        count,
        budget,
        udp_downlink,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark: run it deliberately, with --release --nocapture"]
async fn bench_udp_small_datagrams() {
    header();
    let count = packets();
    let budget = seconds();

    udp_direction("udp_64_client_to_target", 64, count, budget, udp_uplink).await;
    // The D29 direction: one `BytesMut` per outbound datagram, at the packet
    // size where per-packet cost matters most.
    udp_direction("udp_64_target_to_client", 64, count, budget, udp_downlink).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark: run it deliberately, with --release --nocapture"]
async fn bench_tunnel_churn() {
    header();
    let count = cycles();

    tcp_churn(count / 8).await;
    let mut tcp = Vec::new();
    for _ in 0..reps() {
        tcp.push(tcp_churn(count).await);
    }
    report("tcp_churn", Kind::Cycles, &tcp);

    udp_churn(count / 8).await;
    let mut udp = Vec::new();
    for _ in 0..reps() {
        udp.push(udp_churn(count).await);
    }
    report("udp_churn", Kind::Cycles, &udp);
}

/// Separate from the churn benchmark so the resident-set figures mean something.
///
/// `ru_maxrss` is a high-water mark: once another benchmark in the same process
/// has pushed the peak up, a later delta reads as zero however much memory the
/// tunnels really take. Run this one on its own —
/// `--features operator-runs --test it_bench -- --ignored bench_concurrent_tunnels`
/// — and the peak it reports is its own.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark: run it deliberately, with --release --nocapture"]
async fn bench_concurrent_tunnels() {
    header();
    let at_once = concurrent();
    let baseline = max_rss_bytes();

    let mut opens = Vec::new();
    let mut closes = Vec::new();
    for _ in 0..reps() {
        let (open, close) = concurrent_tunnels(at_once).await;
        opens.push(open);
        closes.push(close);
    }
    report("tcp_concurrent_open", Kind::Cycles, &opens);
    report("tcp_concurrent_close", Kind::Cycles, &closes);
    println!(
        "bench tcp_concurrent rss: peak {:.1} MiB after {at_once} tunnels, {:.1} MiB above the \
         pre-benchmark peak ({:.1} KiB per tunnel, client and proxy together)",
        max_rss_bytes() as f64 / (1024.0 * 1024.0),
        max_rss_bytes().saturating_sub(baseline) as f64 / (1024.0 * 1024.0),
        max_rss_bytes().saturating_sub(baseline) as f64 / 1024.0 / at_once as f64,
    );
}

/// The allocation ADR D29 is about, timed on its own.
///
/// `forward_to_client` calls `datagram::encode_udp_payload` once per packet,
/// which allocates a `BytesMut` and copies the payload into it behind the two
/// varints. This measures that call against the same copy into a buffer that is
/// already there — the difference is the whole of what an amortised buffer could
/// save, before any of the plumbing such a change would need.
///
/// Single-threaded and allocator-warm, so it is an optimistic bound on the
/// saving rather than a pessimistic one.
#[test]
#[ignore = "benchmark: run it deliberately, with --release --nocapture"]
fn bench_datagram_encode() {
    header();
    const ITERATIONS: u64 = 2_000_000;

    for size in [64usize, 1200] {
        let payload = vec![0x5au8; size];

        // Warm-up, and a check that the optimiser cannot delete the call.
        let mut checksum = 0u64;
        for _ in 0..ITERATIONS / 10 {
            let encoded = datagram::encode_udp_payload(4242, std::hint::black_box(&payload));
            checksum += encoded.len() as u64;
        }

        let window = Window::open();
        for _ in 0..ITERATIONS {
            let encoded = datagram::encode_udp_payload(4242, std::hint::black_box(&payload));
            checksum += encoded.len() as u64;
        }
        let encode = window.close();

        // The same work with the allocation taken out: the copy stays, the
        // malloc/free pair goes.
        let mut scratch = vec![0u8; size + 16];
        let window = Window::open();
        for _ in 0..ITERATIONS {
            let payload = std::hint::black_box(&payload);
            scratch[0] = 0x50;
            scratch[1] = 0x92;
            scratch[2] = 0x00;
            scratch[3..3 + size].copy_from_slice(payload);
            checksum += std::hint::black_box(scratch[3] as u64);
        }
        let copy = window.close();

        std::hint::black_box(checksum);
        let per_encode = encode.wall.as_secs_f64() * 1e9 / ITERATIONS as f64;
        let per_copy = copy.wall.as_secs_f64() * 1e9 / ITERATIONS as f64;
        println!(
            "bench datagram_encode_{size}: {per_encode:.1} ns/call ({:.2} allocs/call), \
             copy-only {per_copy:.1} ns/call, allocation costs {:.1} ns/packet",
            encode.allocs as f64 / ITERATIONS as f64,
            per_encode - per_copy,
        );
    }
}
