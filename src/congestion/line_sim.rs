//! A deterministic simulator that drives the real [`Bbr`] against a modelled
//! path, for tests only.
//!
//! The path drops a share of packets at random, which can change at given
//! times, can drop packets in episodes or all of them for a span, or as a
//! recorded sequence of packet fates says, can limit
//! the rate with a token-bucket policer or a queue, and delays each packet by
//! a fixed time each way. The sender is a bulk sender that behaves as
//! quinn-proto 0.11.19 does under this crate's transport settings. It is never
//! short of data, except in a handshake when a scenario models one. It sends
//! while in-flight data is under [`Controller::window`] and its pacer allows
//! it. It calls the controller in quinn's order and declares a loss by quinn's
//! rule.
//!
//! What of quinn is left out is listed on [`Sim`]. The random numbers come from
//! a seeded xorshift generator, so a run depends only on its [`Scenario`].

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerFactory};

use super::base_loss::{Closed, READINGS};
use super::{Bbr, BbrConfig, INITIAL_WINDOW, Record};
use crate::quic::LOSS_TIME_THRESHOLD;

/// quinn's `TIMER_GRANULARITY` in quinn-proto `src/lib.rs`: the shortest loss
/// delay.
const TIMER_GRANULARITY: Duration = Duration::from_millis(1);

/// quinn's pacer, copied from quinn-proto `src/connection/pacing.rs`
/// (`Pacer::new`, `Pacer::on_transmit`, `Pacer::delay` and
/// `optimal_capacity`). It adds 1.25 windows of tokens per smoothed RTT, only
/// when it is asked for more tokens than it holds.
struct Pacer {
    capacity: u64,
    last_window: u64,
    last_mtu: u16,
    tokens: u64,
    prev: Instant,
}

/// quinn's `BURST_INTERVAL_NANOS` in `src/connection/pacing.rs`.
const BURST_INTERVAL_NANOS: u128 = 2_000_000;
/// quinn's `MIN_BURST_SIZE` in `src/connection/pacing.rs`.
const MIN_BURST_SIZE: u64 = 10;
/// quinn's `MAX_BURST_SIZE` in `src/connection/pacing.rs`.
const MAX_BURST_SIZE: u64 = 256;

/// quinn's `optimal_capacity`, with its `as` conversion.
#[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
fn optimal_capacity(smoothed_rtt: Duration, window: u64, mtu: u16) -> u64 {
    let rtt = smoothed_rtt.as_nanos().max(1);
    let capacity = ((u128::from(window) * BURST_INTERVAL_NANOS) / rtt) as u64;
    capacity.clamp(
        MIN_BURST_SIZE * u64::from(mtu),
        MAX_BURST_SIZE * u64::from(mtu),
    )
}

impl Pacer {
    fn new(smoothed_rtt: Duration, window: u64, mtu: u16, now: Instant) -> Self {
        let capacity = optimal_capacity(smoothed_rtt, window, mtu);
        Self {
            capacity,
            last_window: window,
            last_mtu: mtu,
            tokens: capacity,
            prev: now,
        }
    }

    fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into());
    }

    /// quinn's `Pacer::delay`, with its `as` conversions, so that it
    /// truncates as quinn does.
    #[allow(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn delay(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        mtu: u16,
        window: u64,
        now: Instant,
    ) -> Option<Instant> {
        if window != self.last_window || mtu != self.last_mtu {
            self.capacity = optimal_capacity(smoothed_rtt, window, mtu);
            self.tokens = self.capacity.min(self.tokens);
            self.last_window = window;
            self.last_mtu = mtu;
        }
        if self.tokens >= bytes_to_send {
            return None;
        }
        if window > u64::from(u32::MAX) {
            return None;
        }
        let window = window as u32;
        let time_elapsed = now.checked_duration_since(self.prev).unwrap_or_default();
        if smoothed_rtt.as_nanos() == 0 {
            return None;
        }
        let elapsed_rtts = time_elapsed.as_secs_f64() / smoothed_rtt.as_secs_f64();
        let new_tokens = f64::from(window) * 1.25 * elapsed_rtts;
        self.tokens = self
            .tokens
            .saturating_add(new_tokens as u64)
            .min(self.capacity);
        self.prev = now;
        if self.tokens >= bytes_to_send {
            return None;
        }
        let unscaled_delay = smoothed_rtt
            .checked_mul((bytes_to_send.max(self.capacity) - self.tokens) as u32)
            .unwrap_or(Duration::MAX)
            / window;
        Some(self.prev + (unscaled_delay / 5) * 4)
    }
}

/// quinn's RTT estimator, copied from `RttEstimator::new`, `get`,
/// `conservative` and `update` in quinn-proto `src/connection/paths.rs`.
/// quinn's own type has no public constructor.
struct Rtt {
    latest: Duration,
    smoothed: Option<Duration>,
    var: Duration,
    min: Duration,
}

impl Rtt {
    fn get(&self) -> Duration {
        self.smoothed.unwrap_or(self.latest)
    }

    fn conservative(&self) -> Duration {
        self.get().max(self.latest)
    }

    fn update(&mut self, ack_delay: Duration, rtt: Duration) {
        self.latest = rtt;
        self.min = self.min.min(self.latest);
        if let Some(smoothed) = self.smoothed {
            let adjusted_rtt = if self.min + ack_delay <= self.latest {
                self.latest - ack_delay
            } else {
                self.latest
            };
            let var_sample = smoothed.abs_diff(adjusted_rtt);
            self.var = (3 * self.var + var_sample) / 4;
            self.smoothed = Some((7 * smoothed + adjusted_rtt) / 8);
        } else {
            self.smoothed = Some(self.latest);
            self.var = self.latest / 2;
            self.min = self.latest;
        }
    }
}

/// The rule by which the sender declares a packet lost, as quinn's
/// `Connection::detect_lost_packets` in `src/connection/mod.rs` applies it to
/// a packet numbered below the largest acknowledged one.
#[derive(Debug, Clone, Copy)]
enum LossRule {
    /// This crate's settings (D116): no packet threshold, and a packet is lost
    /// once its age is `LOSS_TIME_THRESHOLD` times the larger of the smoothed
    /// and the latest RTT. See `LOSS_PACKET_THRESHOLD` and
    /// `LOSS_TIME_THRESHOLD` in `src/quic/transport.rs`.
    Ours,
    /// quinn's defaults, which release 1.8.1 ran: a packet is lost once a
    /// packet numbered 3 or more above it has been acknowledged, or once its
    /// age is 9/8 of the larger of the smoothed and the latest RTT.
    QuinnDefault,
}

impl LossRule {
    /// The packet threshold and the time threshold.
    fn thresholds(self) -> (Option<u64>, f32) {
        match self {
            Self::Ours => (None, LOSS_TIME_THRESHOLD),
            Self::QuinnDefault => (Some(3), 9.0 / 8.0),
        }
    }
}

/// A token bucket without a queue: a packet that finds too few tokens is
/// dropped.
#[derive(Debug, Clone, Copy)]
struct Policer {
    /// Bytes per second.
    rate: f64,
    /// The bucket depth in bytes.
    depth: f64,
}

/// A first-in first-out queue drained at a fixed rate, which drops a packet
/// that does not fit.
#[derive(Debug, Clone, Copy)]
struct Queue {
    /// Bytes per second.
    rate: f64,
    /// The most bytes the queue holds.
    limit: f64,
}

/// Loss in episodes: the path is quiet or lossy, each for a time drawn from an
/// exponential distribution with the given mean, and in the lossy state it
/// drops each packet with the given share.
#[derive(Debug, Clone, Copy)]
struct Episodes {
    quiet: Duration,
    lossy: Duration,
    share: f64,
}

/// A handshake: `flights` flights of `packets` packets, and nothing more
/// until `bulk`, when the bulk data begins. The first flight goes at the
/// start; each further one goes when an ACK of a packet of the one before it
/// arrives, as the server's flights follow the client's. The sender is
/// app-limited in between. With one flight, every ACK of the handshake
/// arrives in one batch and no sample interval closes before the bulk data.
#[derive(Debug, Clone, Copy)]
struct Handshake {
    packets: u64,
    flights: u64,
    bulk: Duration,
}

/// A span in which the path drops every packet.
#[derive(Debug, Clone, Copy)]
struct Outage {
    /// When it starts, or with `in_probe` the earliest time it may start.
    at: Duration,
    length: Duration,
    /// Whether it starts at the first moment from `at` on at which a probe
    /// holds its window, so that it falls into a base-loss reading.
    in_probe: bool,
}

/// quinn's default `max_ack_delay` of the peer, 25 ms, which the probe
/// timeout adds (quinn-proto `src/transport_parameters.rs`).
const PEER_MAX_ACK_DELAY: Duration = Duration::from_millis(25);

/// quinn's `MAX_BACKOFF_EXPONENT` in `src/connection/mod.rs`.
const MAX_BACKOFF_EXPONENT: u32 = 16;

/// One simulated run.
#[derive(Debug, Clone, Copy)]
struct Scenario {
    /// The round-trip time without any queue, half of it each way.
    rtt: Duration,
    /// The share of packets the path drops at random, after the policer and
    /// the queue.
    drop_share: f64,
    /// Changes of `drop_share`: from each second given, the share given.
    drop_steps: &'static [(u64, f64)],
    episodes: Option<Episodes>,
    outage: Option<Outage>,
    policer: Option<Policer>,
    queue: Option<Queue>,
    /// Simulated seconds.
    seconds: u64,
    /// Seconds at the start that the means leave out.
    warmup: u64,
    /// Bytes per packet, which is also the MTU the controller is built with.
    packet: u16,
    /// ACKs reach the sender at multiples of this time.
    ack_batch: Duration,
    /// Each ACK batch arrives up to this much after its multiple of
    /// `ack_batch`, by an amount fixed per batch and seed. Without it every
    /// RTT sample of a path without a queue is a multiple of `ack_batch`, a
    /// sample equal to the minimum comes every few batches, the minimum never
    /// expires and no probe starts. On a real path the samples differ by
    /// microseconds and the probe starts every 10 s.
    ack_jitter: Duration,
    loss_rule: LossRule,
    /// A steady gain in per mille that the test sets again after every ACK
    /// batch, or `None` to leave the gain to the controller.
    pinned_gain: Option<u64>,
    /// Prints the controller's state after every ACK batch and every
    /// congestion event before this time, to read a start packet by packet.
    trace_until: Duration,
    /// Runs the controller as it was before it read the base loss: the bound
    /// of `BaseLoss` at zero, so the base loss is always zero, no early probe,
    /// and the startup's one-interval exit from its first packet.
    before: bool,
    /// Sets `BaseLoss::bound` when `before` is not set. Without it the
    /// environment variable `LINE_SIM_BOUND_PPM` can set it.
    bound_ppm: Option<u64>,
    /// Ends the run once the window reaches this many bytes.
    stop_window: Option<u64>,
    /// Ends the run once this many bytes have arrived at the receiver, as a
    /// transfer of a file of that size ends.
    transfer: Option<u64>,
    /// The peer's flow control in its simplest form: no packet goes out while
    /// in-flight data plus the packet would be above this many bytes, and the
    /// sender is then app-limited, as quinn reports a sender blocked by flow
    /// control.
    client_window: Option<u64>,
    /// A handshake in its simplest form; see [`Handshake`].
    handshake: Option<Handshake>,
    /// The packets with these numbers are dropped on the path whatever else
    /// happens to them.
    drop_packets: &'static [u64],
    /// A recorded sequence of fates, one byte per packet, `b'0'` for a packet
    /// the path dropped: the n-th packet that passes the policer and the queue
    /// meets the n-th byte from `trace_start` on, and the sequence starts again
    /// at its end.
    trace: Option<&'static [u8]>,
    trace_start: usize,
    /// How many packets in a row meet each byte of `trace`: with 2 or more,
    /// the recorded runs are that many times longer, as loss that follows
    /// time and not packets would be at that many times the recorded rate.
    trace_stretch: usize,
    seed: u64,
}

impl Scenario {
    /// A path of `rtt_ms` that drops `drop_share` of the packets, with no rate
    /// limit, run for 60 s and measured from 10 s.
    fn new(rtt_ms: u64, drop_share: f64, seed: u64) -> Self {
        Self {
            rtt: Duration::from_millis(rtt_ms),
            drop_share,
            drop_steps: &[],
            episodes: None,
            outage: None,
            policer: None,
            queue: None,
            seconds: 60,
            warmup: 10,
            packet: 1436,
            ack_batch: Duration::from_millis(2),
            ack_jitter: Duration::from_micros(100),
            loss_rule: LossRule::Ours,
            pinned_gain: None,
            trace_until: Duration::ZERO,
            before: false,
            bound_ppm: None,
            stop_window: None,
            transfer: None,
            client_window: None,
            handshake: None,
            drop_packets: &[],
            trace: None,
            trace_start: 0,
            trace_stretch: 1,
            seed,
        }
    }

    /// Adds a policer of `mbps` megabits per second and `depth` bytes.
    fn policer(mut self, mbps: f64, depth: f64) -> Self {
        self.policer = Some(Policer {
            rate: mbps * 1e6 / 8.0,
            depth,
        });
        self
    }

    /// Adds a queue drained at `mbps` megabits per second that holds `limit`
    /// bytes.
    fn queue(mut self, mbps: f64, limit: f64) -> Self {
        self.queue = Some(Queue {
            rate: mbps * 1e6 / 8.0,
            limit,
        });
        self
    }

    /// Whether the recorded sequence drops the `n`-th packet that reaches it,
    /// counted from zero; `false` without a sequence. The sequence is read
    /// from `trace_start`, each of its bytes holds for `trace_stretch` packets
    /// in a row, and it starts again at its end.
    fn traced_drop(&self, n: usize) -> bool {
        self.trace.is_some_and(|trace| {
            let at = self.trace_start + n / self.trace_stretch.max(1);
            trace[at % trace.len()] == b'0'
        })
    }

    /// The same scenario on the controller as it was before it read the base
    /// loss.
    fn before(mut self) -> Self {
        self.before = true;
        self
    }
}

/// xorshift64*, seeded.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    /// A number in [0, 1).
    #[allow(clippy::as_conversions, clippy::cast_precision_loss)]
    fn unit(&mut self) -> f64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        let x = self.0.wrapping_mul(0x2545_F491_4F6C_DD1D);
        (x >> 11) as f64 / (1u64 << 53) as f64
    }

    /// A time drawn from an exponential distribution with mean `mean`, in
    /// nanoseconds, and at least one.
    fn exponential(&mut self, mean: Duration) -> u64 {
        to_u64(-(1.0 - self.unit()).ln() * to_f64(nanos(mean))).max(1)
    }
}

/// splitmix64: a number fixed by `x`, for the arrival offset of an ACK batch.
fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// A packet that is in flight.
#[derive(Debug, Clone, Copy)]
struct Packet {
    number: u64,
    sent: u64,
    size: u64,
}

/// The sums of one simulated second.
#[derive(Debug, Clone, Copy, Default)]
struct Second {
    sent: u64,
    delivered: u64,
    lost: u64,
    /// Integrals over time, in the unit times nanoseconds.
    window: f64,
    estimate: f64,
    in_flight_share: f64,
    floor: f64,
    gain: f64,
    recovery_binding: f64,
    base: f64,
    probe: f64,
    nanos: f64,
}

/// What a run measured. Rates are megabits per second of packet bytes.
#[derive(Debug, Clone)]
struct Report {
    send: f64,
    delivered: f64,
    /// Packets declared lost over packets sent.
    lost_share: f64,
    /// The mean of [`Controller::window`] in kilobytes.
    window_kb: f64,
    /// The mean bandwidth estimate.
    estimate: f64,
    /// The lowest and the highest per-second mean of the estimate.
    estimate_range: (f64, f64),
    in_flight_over_window: f64,
    /// The share of the time the cap is [`INITIAL_WINDOW`].
    floor_share: f64,
    /// The mean steady gain in per mille.
    gain: f64,
    /// The share of the time the recovery window is below the window the cap
    /// would give, after the startup has ended.
    recovery_binding: f64,
    /// The mean base loss the controller uses.
    base: f64,
    /// The share of the time a probe is in progress.
    probe_share: f64,
    /// The delivered rate over the last 10 s.
    delivered_end: f64,
    /// The delivered rate over the first 5 s.
    delivered_first: f64,
    /// Bytes declared lost before the first startup ended.
    startup_lost: u64,
    /// When the first startup ended, in seconds.
    startup_end: Option<f64>,
    /// The estimate when the first startup ended, in Mbit/s.
    startup_end_estimate: f64,
    /// Each base-loss reading the controller kept: when, in seconds, and the
    /// share.
    readings: Vec<(f64, f64)>,
    /// When each probe started, in seconds.
    probes: Vec<f64>,
    /// How many packets were sent while each probe held its window, which
    /// are the packets its reading counts.
    probe_packets: Vec<u64>,
    /// The estimate in Mbit/s when each probe started, and the share of the
    /// packets sent in the round trip before it that had been acknowledged
    /// before it was entered, which its reading cannot count.
    probe_starts: Vec<(f64, f64)>,
    /// When each reading closed, in seconds, and what became of it.
    closes: Vec<(f64, String)>,
    /// Each change of the minimum RTT: when, in seconds, the new value in
    /// milliseconds, and whether it was lowered rather than renewed by an
    /// equal sample or taken by a probe.
    min_rtt_changes: Vec<(f64, f64, bool)>,
    /// Whether the run stopped before the measurement span.
    span_empty: bool,
    /// When the window reached `Scenario::stop_window`, in seconds.
    stopped: Option<f64>,
    /// When `Scenario::transfer` bytes had arrived, in seconds.
    transferred: Option<f64>,
    /// How many times the probe timeout fired.
    timeouts: u32,
    /// The share of 100 ms spans with packets sent in which the path's drop
    /// stages dropped none, and the mean packets an episode dropped.
    clean_spans: f64,
    per_episode: f64,
    /// Packets sent and packets the drop stages dropped, per 100 ms.
    spans: Vec<(u32, u32)>,
    seconds: Vec<Second>,
    /// What the controller counted for the close line, over the whole run.
    record: Record,
}

/// The sender, the path and the controller.
///
/// The sender is quinn-proto 0.11.19 reduced to what moves the controller.
/// Left out: the handshake unless [`Scenario::handshake`] models it (the run
/// starts with the RTT estimator holding one sample of the path's RTT, as
/// after a handshake), flow control (the peer's
/// windows and `send_window` never bind), ACK-only packets, persistent
/// congestion (which [`Bbr`] ignores), ECN, MTU discovery, the peer's ACK
/// delay (reported as zero), and loss or reordering of ACKs. Timers fire at
/// their exact time. The probe timeout is quinn's in its simplest form: when
/// no loss timer is set, it fires the smoothed RTT plus four RTT variations
/// plus the peer's 25 ms ACK delay after the last packet sent, doubled per
/// timeout in a row, and lets two packets out above the window.
struct Sim {
    sc: Scenario,
    c: Bbr,
    rng: Rng,
    episode_rng: Rng,
    t0: Instant,
    pacer: Pacer,
    rtt: Rtt,
    /// Delivered packets not yet acknowledged, in packet-number order, with
    /// the time their ACK reaches the sender.
    pending: VecDeque<(Packet, u64)>,
    /// Dropped packets not yet declared lost, in packet-number order.
    holes: VecDeque<Packet>,
    in_flight: u64,
    next_number: u64,
    /// The largest acknowledged packet number.
    largest_acked: Option<u64>,
    loss_time: Option<u64>,
    pacing_at: Option<u64>,
    /// Probe timeouts in a row, and packets they let out above the window.
    pto_count: u32,
    timeouts: u32,
    pto_packets: u32,
    last_sent: u64,
    /// The policer's tokens and when they were last added.
    policer_tokens: f64,
    policer_at: u64,
    /// When the queue has sent everything it holds.
    queue_free_at: u64,
    /// Whether the path is in a lossy episode, and until when the state
    /// lasts.
    lossy: bool,
    state_until: u64,
    episodes: u64,
    episode_drops: u64,
    /// How many packets have met the recorded sequence.
    trace_at: usize,
    outage_from: Option<u64>,
    startup_end: Option<u64>,
    startup_end_estimate: u64,
    startup_lost: u64,
    /// The base-loss ring as last seen, to find each new reading.
    seen: (usize, usize, [u64; READINGS]),
    readings: Vec<(u64, u64)>,
    /// When each probe started.
    probes: Vec<u64>,
    /// The packets sent while each probe held its window.
    probe_packets: Vec<u64>,
    probe_starts: Vec<(f64, f64)>,
    /// The share missed at the latest probe entry, until `observe` takes it.
    entry_missed: Option<f64>,
    /// The send times of the packets acknowledged in the last two seconds.
    recent_acks: VecDeque<u64>,
    /// Whether the last transmit stopped at the client window.
    app_limited: bool,
    /// The latest reading's close as last seen, and the closes.
    closed_seen: Option<(Instant, Closed)>,
    closes: Vec<(u64, String)>,
    /// The minimum RTT as last seen, and its changes.
    min_rtt_seen: Option<(Duration, Instant)>,
    min_rtt_changes: Vec<(u64, Duration, bool)>,
    /// The latest time no probe was in progress.
    probe_seen: u64,
    stopped: Option<u64>,
    /// Bytes that have arrived at the receiver, and when they first reached
    /// `Scenario::transfer`.
    arrived: u64,
    transferred: Option<u64>,
    /// Packets sent and packets the drop stages dropped, per 100 ms.
    spans: Vec<(u32, u32)>,
    clock: u64,
    seconds: Vec<Second>,
}

/// The loss the drop stages caused, as the production captures were read:
/// the mean, the lowest and highest mean of 8 s stages, the share of 200 ms
/// windows (two 100 ms bins) that lost 5, 10 and 17 percent or more, and the
/// share of pairs of windows 0.6 s apart whose lower one lost 5 and 10
/// percent or more. Bins in which nothing was sent are left out.
fn window_stats(spans: &[(u32, u32)]) -> String {
    let share = |(sent, dropped): (u32, u32)| f64::from(dropped) / f64::from(sent.max(1));
    let windows: Vec<f64> = spans
        .as_chunks::<2>()
        .0
        .iter()
        .filter(|w| w[0].0 > 0 && w[1].0 > 0)
        .map(|w| share((w[0].0 + w[1].0, w[0].1 + w[1].1)))
        .collect();
    let stages: Vec<f64> = spans
        .as_chunks::<80>()
        .0
        .iter()
        .map(|stage| {
            let (sent, dropped) = stage.iter().fold((0, 0), |(a, b), &(s, d)| (a + s, b + d));
            share((sent, dropped))
        })
        .collect();
    let at = |list: &[f64], level: f64| {
        to_f64(u64::try_from(list.iter().filter(|&&w| w >= level).count()).unwrap_or(0))
            / to_f64(u64::try_from(list.len()).unwrap_or(0)).max(1.0)
    };
    let lower: Vec<f64> = windows.windows(4).map(|w| w[0].min(w[3])).collect();
    let (sent, dropped) = spans.iter().fold((0u64, 0u64), |(a, b), &(s, d)| {
        (a + u64::from(s), b + u64::from(d))
    });
    let lo = stages.iter().copied().fold(f64::MAX, f64::min);
    let hi = stages.iter().copied().fold(0.0, f64::max);
    format!(
        "mean {:.3}, stages {lo:.3} to {hi:.3}, windows at 5/10/17 percent {:.3}/{:.3}/{:.3}, \
         lower of two 0.6 s apart at 5/10 percent {:.3}/{:.3}",
        to_f64(dropped) / to_f64(sent.max(1)),
        at(&windows, 0.05),
        at(&windows, 0.10),
        at(&windows, 0.17),
        at(&lower, 0.05),
        at(&lower, 0.10),
    )
}

/// A reading's close in words, with its ratio of arrival rates.
fn describe(closed: Closed) -> String {
    let ratio = |ppm: u64| to_f64(ppm) / 1e6;
    match closed {
        Closed::No => "no close".to_owned(),
        Closed::Kept { ratio_ppm } => format!("kept, ratio {:.3}", ratio(ratio_ppm)),
        Closed::Short {
            ratio_ppm, cleared, ..
        } => format!(
            "short, ratio {:.3}{}",
            ratio(ratio_ppm),
            if cleared { ", cleared" } else { "" }
        ),
        Closed::Unverified {
            ratio_ppm,
            sent_ppm,
        } => match (ratio_ppm, sent_ppm) {
            (Some(ppm), Some(sent)) => format!(
                "unverified, ratio {:.3}, sent {:.3}",
                ratio(ppm),
                ratio(sent)
            ),
            (Some(ppm), None) => format!("unverified, ratio {:.3}", ratio(ppm)),
            _ => "unverified, nothing before".to_owned(),
        },
        Closed::Cleared {
            ratio_ppm,
            sent_ppm,
        } => format!(
            "cleared, ratio {:.3}, sent {:.3}",
            ratio(ratio_ppm),
            ratio(sent_ppm)
        ),
        Closed::Dropped { cleared } => {
            format!(
                "dropped as an outage{}",
                if cleared { ", cleared" } else { "" }
            )
        }
    }
}

/// Nanoseconds as a [`Duration`] since the start of the run.
fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).expect("a run is shorter than 584 years")
}

#[allow(clippy::as_conversions, clippy::cast_precision_loss)]
fn to_f64(x: u64) -> f64 {
    x as f64
}

#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn to_u64(x: f64) -> u64 {
    x as u64
}

fn seconds_of(ns: u64) -> f64 {
    to_f64(ns) / 1e9
}

impl Sim {
    fn new(sc: Scenario) -> Self {
        let t0 = Instant::now();
        let mut c = *Arc::new(BbrConfig)
            .build(t0, sc.packet)
            .into_any()
            .downcast::<Bbr>()
            .expect("the factory builds a Bbr");
        if sc.before {
            c.base.bound = 0;
            c.base.early = u64::MAX;
            c.exit_packets = 0;
        } else {
            let env = |name: &str| std::env::var(name).ok().and_then(|v| v.parse().ok());
            c.base.bound = sc
                .bound_ppm
                .or_else(|| env("LINE_SIM_BOUND_PPM"))
                .unwrap_or(c.base.bound);
        }
        let rtt = Rtt {
            latest: sc.rtt,
            smoothed: Some(sc.rtt),
            var: sc.rtt / 2,
            min: sc.rtt,
        };
        let pacer = Pacer::new(rtt.get(), c.window(), sc.packet, t0);
        let seconds = vec![Second::default(); usize::try_from(sc.seconds).unwrap_or(0)];
        let mut episode_rng = Rng::new(sc.seed ^ 0x5EED_E915_0DE5);
        let state_until = sc
            .episodes
            .map_or(u64::MAX, |e| episode_rng.exponential(e.quiet));
        Self {
            policer_tokens: sc.policer.map_or(0.0, |p| p.depth),
            sc,
            seen: c.base.readings(),
            c,
            rng: Rng::new(sc.seed),
            episode_rng,
            t0,
            pacer,
            rtt,
            pending: VecDeque::new(),
            holes: VecDeque::new(),
            in_flight: 0,
            next_number: 0,
            largest_acked: None,
            loss_time: None,
            pacing_at: None,
            pto_count: 0,
            timeouts: 0,
            pto_packets: 0,
            last_sent: 0,
            policer_at: 0,
            queue_free_at: 0,
            lossy: false,
            state_until,
            episodes: 0,
            episode_drops: 0,
            trace_at: 0,
            outage_from: None,
            startup_end: None,
            startup_end_estimate: 0,
            startup_lost: 0,
            readings: Vec::new(),
            probes: Vec::new(),
            probe_packets: Vec::new(),
            probe_starts: Vec::new(),
            entry_missed: None,
            recent_acks: VecDeque::new(),
            app_limited: false,
            closed_seen: None,
            closes: Vec::new(),
            min_rtt_seen: None,
            min_rtt_changes: Vec::new(),
            probe_seen: 0,
            stopped: None,
            arrived: 0,
            transferred: None,
            spans: vec![(0, 0); usize::try_from(sc.seconds * 10).unwrap_or(0)],
            clock: 0,
            seconds,
        }
    }

    fn at(&self, ns: u64) -> Instant {
        self.t0 + Duration::from_nanos(ns)
    }

    fn second(&mut self, ns: u64) -> Option<&mut Second> {
        self.seconds
            .get_mut(usize::try_from(ns / 1_000_000_000).unwrap_or(usize::MAX))
    }

    fn span(&mut self, ns: u64) -> Option<&mut (u32, u32)> {
        self.spans
            .get_mut(usize::try_from(ns / 100_000_000).unwrap_or(usize::MAX))
    }

    /// Adds the controller's state from the clock to `to` to the per-second
    /// integrals.
    fn advance(&mut self, to: u64) {
        let window = self.c.window();
        let estimate = to_f64(self.c.rate.max().unwrap_or(0)) * 8.0 / 1e6;
        let floor = if self.c.cap == Some(INITIAL_WINDOW) {
            1.0
        } else {
            0.0
        };
        let share = to_f64(self.in_flight) / to_f64(window.max(1));
        let gain = to_f64(self.c.gain.permille);
        let cap_window = self.c.cap.unwrap_or(INITIAL_WINDOW);
        let binding = match self.c.recovery {
            Some(r) if self.c.startup.ended && r.window < cap_window => 1.0,
            _ => 0.0,
        };
        let base = to_f64(self.c.base.ppm()) / 1e6;
        let probe = if self.c.probe.is_some() { 1.0 } else { 0.0 };
        while self.clock < to {
            let end = to.min((self.clock / 1_000_000_000 + 1) * 1_000_000_000);
            let dt = to_f64(end - self.clock);
            if let Some(s) = self.second(self.clock) {
                s.window += to_f64(window) * dt;
                s.estimate += estimate * dt;
                s.in_flight_share += share * dt;
                s.floor += floor * dt;
                s.gain += gain * dt;
                s.recovery_binding += binding * dt;
                s.base += base * dt;
                s.probe += probe * dt;
                s.nanos += dt;
            }
            self.clock = end;
        }
    }

    /// The random drop share at `now`.
    fn drop_share(&self, now: u64) -> f64 {
        self.sc
            .drop_steps
            .iter()
            .rev()
            .find(|&&(from, _)| now >= from * 1_000_000_000)
            .map_or(self.sc.drop_share, |&(_, share)| share)
    }

    /// Passes one packet sent at `now` through the policer, the queue, the
    /// random drop, the episodes, the outage and the delay. Returns when it
    /// reaches the receiver, or `None` when the path drops it.
    fn carry(&mut self, now: u64, size: u64, number: u64) -> Option<u64> {
        let dropped =
            self.rng.unit() < self.drop_share(now) || self.sc.drop_packets.contains(&number);
        let mut in_episode = false;
        if let Some(e) = self.sc.episodes {
            while now >= self.state_until {
                self.lossy = !self.lossy;
                let mean = if self.lossy { e.lossy } else { e.quiet };
                self.episodes += u64::from(self.lossy);
                self.state_until += self.episode_rng.exponential(mean);
            }
            in_episode = self.lossy && self.episode_rng.unit() < e.share;
        }
        if let Some(p) = self.sc.policer {
            let elapsed = to_f64(now - self.policer_at) / 1e9;
            self.policer_tokens = (self.policer_tokens + elapsed * p.rate).min(p.depth);
            self.policer_at = now;
            if self.policer_tokens < to_f64(size) {
                return None;
            }
            self.policer_tokens -= to_f64(size);
        }
        let mut left = now;
        if let Some(q) = self.sc.queue {
            let backlog = to_f64(self.queue_free_at.saturating_sub(now)) / 1e9 * q.rate;
            if backlog + to_f64(size) > q.limit {
                return None;
            }
            left = self.queue_free_at.max(now) + to_u64(to_f64(size) / q.rate * 1e9);
            self.queue_free_at = left;
        }
        let outage = match (self.sc.outage, self.outage_from) {
            (Some(o), Some(from)) => now >= from && now < from + nanos(o.length),
            _ => false,
        };
        let traced = self.sc.traced_drop(self.trace_at);
        if self.sc.trace.is_some() {
            self.trace_at += 1;
        }
        if dropped || traced || in_episode || outage {
            self.episode_drops += u64::from(in_episode);
            if let Some(span) = self.span(now) {
                span.1 += 1;
            }
            return None;
        }
        Some(left + nanos(self.sc.rtt) / 2)
    }

    /// When the ACK of a packet that reaches the sender at `back` is handled:
    /// at the next multiple of the batch time, plus that batch's offset.
    fn batch_time(&self, back: u64) -> u64 {
        let batch = nanos(self.sc.ack_batch);
        let index = back.div_ceil(batch);
        let jitter = nanos(self.sc.ack_jitter).min(batch - 1);
        let offset = if jitter == 0 {
            0
        } else {
            mix(self.sc.seed ^ index.wrapping_mul(0x2545_F491_4F6C_DD1D)) % jitter
        };
        index * batch + offset
    }

    /// quinn's `Connection::poll_transmit` for a sender that always has data:
    /// a packet goes out while in-flight data plus the packet is under the
    /// window and the pacer does not ask for a delay. A packet the probe
    /// timeout lets out skips the window check but not the pacer.
    fn transmit(&mut self, now: u64) {
        self.pacing_at = None;
        let size = u64::from(self.sc.packet);
        loop {
            let window = self.c.window();
            let probe = self.pto_packets > 0;
            // quinn finds no stream data to send before it checks the window,
            // and reports that as app-limited.
            if let Some(h) = self.sc.handshake
                && now < nanos(h.bulk)
            {
                let flight = self.next_number / h.packets;
                let previous_acked = flight == 0
                    || self
                        .largest_acked
                        .is_some_and(|n| n >= (flight - 1) * h.packets);
                if flight >= h.flights || !previous_acked {
                    // An ACK or the start of the bulk data sends again.
                    self.app_limited = true;
                    self.pacing_at = Some(nanos(h.bulk));
                    return;
                }
            }
            if self
                .sc
                .client_window
                .is_some_and(|w| self.in_flight + size > w)
            {
                self.app_limited = true;
                return;
            }
            self.app_limited = false;
            if !probe && self.in_flight + size >= window {
                return;
            }
            let at = self.at(now);
            if let Some(wake) = self
                .pacer
                .delay(self.rtt.get(), size, self.sc.packet, window, at)
            {
                let wake = nanos(wake.saturating_duration_since(self.t0));
                self.pacing_at = Some(wake.max(now + 1));
                return;
            }
            if probe {
                self.pto_packets -= 1;
            }
            self.pacer.on_transmit(self.sc.packet);
            let packet = Packet {
                number: self.next_number,
                sent: now,
                size,
            };
            self.next_number += 1;
            if self.c.probe.as_ref().is_some_and(|p| p.ends.is_some())
                && let Some(count) = self.probe_packets.last_mut()
            {
                *count += 1;
            }
            self.in_flight += size;
            self.last_sent = now;
            if let Some(s) = self.second(now) {
                s.sent += size;
            }
            if let Some(span) = self.span(now) {
                span.0 += 1;
            }
            match self.carry(now, size, packet.number) {
                Some(arrived) => {
                    if let Some(s) = self.second(arrived) {
                        s.delivered += size;
                    }
                    self.arrived += size;
                    if self.transferred.is_none()
                        && self.sc.transfer.is_some_and(|bytes| self.arrived >= bytes)
                    {
                        self.transferred = Some(arrived);
                    }
                    let back = self.batch_time(arrived + nanos(self.sc.rtt) / 2);
                    self.pending.push_back((packet, back));
                }
                None => self.holes.push_back(packet),
            }
        }
    }

    /// The share of the delivered packets sent in the minimum RTT before `now`
    /// that were acknowledged before `now`, when a probe is entered at `now`.
    fn missed_at_entry(&self, now: u64) -> f64 {
        let span = self.c.min_rtt.map_or(0, |(min, _)| nanos(min));
        let from = now.saturating_sub(span);
        let inside = |sent: u64| sent >= from && sent < now;
        let acked = self
            .recent_acks
            .iter()
            .filter(|&&sent| inside(sent))
            .count();
        let waiting = self.pending.iter().filter(|(p, _)| inside(p.sent)).count();
        to_f64(u64::try_from(acked).unwrap_or(0))
            / to_f64(u64::try_from(acked + waiting).unwrap_or(0)).max(1.0)
    }

    /// quinn's `Connection::on_ack_received` for the ACKs that have reached
    /// the sender by `now`. `on_packet_acked` calls `Controller::on_ack` per
    /// packet with the RTT estimator as it was before the frame. Then come
    /// `Controller::on_end_acks`, with in-flight data after the acknowledged
    /// packets and before the lost ones, the RTT update, and
    /// `detect_lost_packets`.
    fn ack_batch(&mut self, now: u64) {
        let at = self.at(now);
        let srtt = self.rtt.get();
        let mut largest = None;
        while let Some(&(packet, back)) = self.pending.front() {
            if back > now {
                break;
            }
            self.pending.pop_front();
            self.in_flight -= packet.size;
            let sent = self.at(packet.sent);
            let entered = self.c.probe.is_none();
            self.c
                .record_ack(at, sent, packet.size, self.app_limited, srtt);
            if entered && self.c.probe.is_some() {
                self.entry_missed = Some(self.missed_at_entry(now));
            }
            self.recent_acks.push_back(packet.sent);
            while self
                .recent_acks
                .front()
                .is_some_and(|&at| at + 2_000_000_000 < now)
            {
                self.recent_acks.pop_front();
            }
            largest = Some(packet);
        }
        let Some(largest) = largest else {
            return;
        };
        self.pto_count = 0;
        self.largest_acked = Some(largest.number);
        self.c
            .on_end_acks(at, self.in_flight, self.app_limited, self.largest_acked);
        if let Some(permille) = self.sc.pinned_gain {
            self.c.gain.permille = permille;
            self.c.refresh();
        }
        self.trace_state(now, "acks", largest.number);
        self.rtt
            .update(Duration::ZERO, Duration::from_nanos(now - largest.sent));
        self.detect_lost(now);
    }

    /// One line of [`Scenario::trace_until`].
    fn trace_state(&self, now: u64, what: &str, number: u64) {
        if now >= nanos(self.sc.trace_until) {
            return;
        }
        eprintln!(
            "trace {:.3} s {what} {number}: startup ended {} {:?} estimate {} window {} in flight {} app-limited {} probe {} due {} repeat {}",
            to_f64(now) / 1e9,
            self.c.startup.ended,
            self.c.startup,
            self.c.rate.max().unwrap_or(0),
            self.c.window,
            self.in_flight,
            self.app_limited,
            self.c.probe.is_some(),
            self.c.probe_due,
            self.c.repeat,
        );
    }

    /// quinn's `Connection::detect_lost_packets`: a packet numbered below the
    /// largest acknowledged one is lost when it is old enough or, under a
    /// packet threshold, far enough behind. All lost bytes of one pass go to
    /// one `Controller::on_congestion_event`, with the send time of the newest
    /// lost packet. The oldest packet that is not lost yet sets the loss
    /// timer, which quinn's `on_loss_detection_timeout` serves with another
    /// pass.
    fn detect_lost(&mut self, now: u64) {
        let Some(largest) = self.largest_acked else {
            return;
        };
        let (packets, time) = self.sc.loss_rule.thresholds();
        let delay = nanos(self.rtt.conservative().mul_f32(time).max(TIMER_GRANULARITY));
        self.loss_time = None;
        let mut lost = 0;
        let mut last_sent = 0;
        while let Some(&p) = self.holes.front() {
            if p.number >= largest {
                break;
            }
            let old = now.saturating_sub(p.sent) >= delay;
            let behind = packets.is_some_and(|n| largest >= p.number + n);
            if !old && !behind {
                self.loss_time = Some(p.sent + delay);
                break;
            }
            self.holes.pop_front();
            self.in_flight -= p.size;
            lost += p.size;
            last_sent = p.sent;
        }
        if lost > 0 {
            if let Some(s) = self.second(now) {
                s.lost += lost;
            }
            if self.startup_end.is_none() {
                self.startup_lost += lost;
            }
            self.c
                .on_congestion_event(self.at(now), self.at(last_sent), false, lost);
            self.trace_state(now, "lost bytes", lost);
        }
    }

    /// quinn's probe timeout in its simplest form; see [`Sim`].
    fn pto_at(&self) -> Option<u64> {
        if self.loss_time.is_some() || self.in_flight == 0 {
            return None;
        }
        let base = self.rtt.get() + (4 * self.rtt.var).max(TIMER_GRANULARITY) + PEER_MAX_ACK_DELAY;
        Some(self.last_sent + (nanos(base) << self.pto_count.min(MAX_BACKOFF_EXPONENT)))
    }

    /// Notes what changed in the controller at `now`: the end of the first
    /// startup, a new base-loss reading, and the start of an outage.
    fn observe(&mut self, now: u64) {
        if self.startup_end.is_none() && self.c.startup.ended {
            self.startup_end = Some(now);
            self.startup_end_estimate = self.c.rate.max().unwrap_or(0);
        }
        let ring = self.c.base.readings();
        if ring != self.seen {
            let (len, next, readings) = ring;
            // A ring emptied after empty probes holds no new reading.
            if len > 0 {
                let newest = readings[(next + READINGS - 1) % READINGS];
                self.readings.push((now, newest));
            }
            self.seen = ring;
        }
        if self.c.min_rtt != self.min_rtt_seen {
            if let Some((value, _)) = self.c.min_rtt {
                let lower = self.min_rtt_seen.is_some_and(|(old, _)| value < old);
                self.min_rtt_changes.push((now, value, lower));
            }
            self.min_rtt_seen = self.c.min_rtt;
        }
        if self.c.last_closed != self.closed_seen {
            self.closed_seen = self.c.last_closed;
            if let Some((_, closed)) = self.c.last_closed {
                self.closes.push((now, describe(closed)));
            }
        }
        let probing = self.c.probe.is_some();
        if probing && self.probes.last().is_none_or(|&at| at < self.probe_seen) {
            self.probes.push(now);
            self.probe_packets.push(0);
            let estimate = to_f64(self.c.rate.max().unwrap_or(0)) * 8.0 / 1e6;
            let missed = self.entry_missed.take().unwrap_or(0.0);
            self.probe_starts.push((estimate, missed));
        }
        if !probing {
            self.probe_seen = now;
        }
        if let Some(o) = self.sc.outage
            && self.outage_from.is_none()
            && now >= nanos(o.at)
            && (!o.in_probe || self.c.probe.as_ref().is_some_and(|p| p.ends.is_some()))
        {
            self.outage_from = Some(now);
        }
    }

    fn run(mut self) -> Report {
        let end = self.sc.seconds * 1_000_000_000;
        self.transmit(0);
        loop {
            let next = [
                self.pending.front().map(|&(_, back)| back),
                self.loss_time,
                self.pacing_at,
                self.pto_at(),
            ]
            .into_iter()
            .flatten()
            .min()
            .expect("the sender has a packet in flight or a timer");
            if next >= end {
                self.advance(end);
                break;
            }
            self.advance(next);
            if self.pending.front().is_some_and(|&(_, back)| back <= next) {
                self.ack_batch(next);
            }
            if self.loss_time.is_some_and(|t| t <= next) {
                self.detect_lost(next);
            }
            if self.pto_at().is_some_and(|t| t <= next) {
                self.pto_count += 1;
                self.timeouts += 1;
                self.pto_packets += 2;
            }
            self.observe(next);
            self.transmit(next);
            if self
                .sc
                .stop_window
                .is_some_and(|stop| self.c.window() >= stop)
            {
                self.stopped = Some(next);
                break;
            }
            if self.transferred.is_some_and(|at| next >= at) {
                break;
            }
        }
        self.report()
    }

    fn report(&self) -> Report {
        let filled = self
            .seconds
            .iter()
            .rposition(|s| s.nanos > 0.0)
            .map_or(0, |i| i + 1);
        let seconds = &self.seconds[..filled];
        let span = &seconds[usize::try_from(self.sc.warmup).unwrap_or(0).min(filled)..];
        let n = to_f64(u64::try_from(span.len()).unwrap_or(0)).max(1.0);
        let mbps = |bytes: u64| to_f64(bytes) * 8.0 / 1e6;
        let sum = |f: &dyn Fn(&Second) -> f64| span.iter().map(f).sum::<f64>();
        let time = sum(&|s| s.nanos).max(1.0);
        let sent: u64 = span.iter().map(|s| s.sent).sum();
        let lost: u64 = span.iter().map(|s| s.lost).sum();
        let estimate_range = span
            .iter()
            .map(|s| s.estimate / s.nanos.max(1.0))
            .fold((f64::MAX, f64::MIN), |(lo, hi), x| (lo.min(x), hi.max(x)));
        let mean_of = |part: &[Second]| {
            part.iter().map(|s| mbps(s.delivered)).sum::<f64>()
                / to_f64(u64::try_from(part.len()).unwrap_or(0)).max(1.0)
        };
        let used: Vec<&(u32, u32)> = self.spans.iter().filter(|s| s.0 > 0).collect();
        let clean = used.iter().filter(|s| s.1 == 0).count();
        Report {
            send: mbps(sent) / n,
            delivered: sum(&|s| mbps(s.delivered)) / n,
            lost_share: to_f64(lost) / to_f64(sent.max(1)),
            window_kb: sum(&|s| s.window) / time / 1e3,
            estimate: sum(&|s| s.estimate) / time,
            estimate_range,
            in_flight_over_window: sum(&|s| s.in_flight_share) / time,
            floor_share: sum(&|s| s.floor) / time,
            gain: sum(&|s| s.gain) / time,
            recovery_binding: sum(&|s| s.recovery_binding) / time,
            base: sum(&|s| s.base) / time,
            probe_share: sum(&|s| s.probe) / time,
            delivered_end: mean_of(&seconds[filled.saturating_sub(10)..]),
            delivered_first: mean_of(&seconds[..filled.min(5)]),
            startup_lost: self.startup_lost,
            startup_end: self.startup_end.map(seconds_of),
            startup_end_estimate: to_f64(self.startup_end_estimate) * 8.0 / 1e6,
            readings: self
                .readings
                .iter()
                .map(|&(at, ppm)| (seconds_of(at), to_f64(ppm) / 1e6))
                .collect(),
            probes: self.probes.iter().copied().map(seconds_of).collect(),
            probe_packets: self.probe_packets.clone(),
            probe_starts: self.probe_starts.clone(),
            closes: self
                .closes
                .iter()
                .map(|(at, what)| (seconds_of(*at), what.clone()))
                .collect(),
            min_rtt_changes: self
                .min_rtt_changes
                .iter()
                .map(|&(at, value, lower)| (seconds_of(at), value.as_secs_f64() * 1e3, lower))
                .collect(),
            span_empty: span.is_empty(),
            stopped: self.stopped.map(seconds_of),
            transferred: self.transferred.map(seconds_of),
            timeouts: self.timeouts,
            clean_spans: to_f64(u64::try_from(clean).unwrap_or(0))
                / to_f64(u64::try_from(used.len()).unwrap_or(0)).max(1.0),
            per_episode: to_f64(self.episode_drops) / to_f64(self.episodes.max(1)),
            spans: self.spans.clone(),
            seconds: seconds.to_vec(),
            record: self.c.record(),
        }
    }
}

/// Runs `sc` and prints its summary, and its per-second series when
/// `series` is set.
fn run(name: &str, sc: Scenario, series: bool) -> Report {
    let r = Sim::new(sc).run();
    let mode = if sc.before { "before" } else { "after" };
    // A run that stopped before the measurement span has no means.
    let f = |x: f64, places: usize| {
        if r.span_empty {
            "none".to_owned()
        } else {
            format!("{x:.places$}")
        }
    };
    println!(
        "{name} {mode} seed {}: send {} delivered {} sent/delivered {} lost {} \
         window {} kB estimate {} ({} to {}) in-flight/window {} \
         floor {} gain {} recovery {} base {} probe {} \
         first 5 s {:.1} last 10 s {:.1} startup lost {:.0} kB ends {} stopped {} \
         timeouts {} first reading {} first probe {}",
        sc.seed,
        f(r.send, 1),
        f(r.delivered, 1),
        f(r.send / r.delivered.max(1e-9), 3),
        f(r.lost_share, 3),
        f(r.window_kb, 0),
        f(r.estimate, 1),
        f(r.estimate_range.0, 1),
        f(r.estimate_range.1, 1),
        f(r.in_flight_over_window, 3),
        f(r.floor_share, 2),
        f(r.gain, 0),
        f(r.recovery_binding, 2),
        f(r.base, 3),
        f(r.probe_share, 3),
        r.delivered_first,
        r.delivered_end,
        to_f64(r.startup_lost) / 1e3,
        r.startup_end
            .map_or_else(|| "never".to_owned(), |t| format!("{t:.2} s")),
        r.stopped
            .map_or_else(|| "no".to_owned(), |t| format!("at {t:.2} s")),
        r.timeouts,
        r.readings
            .first()
            .map_or_else(|| "none".to_owned(), |(t, p)| format!("{p:.3} at {t:.2} s")),
        r.probes
            .first()
            .map_or_else(|| "none".to_owned(), |t| format!("at {t:.2} s")),
    );
    if series {
        let readings: Vec<String> = r
            .readings
            .iter()
            .map(|(t, p)| format!("{t:.2} s: {p:.3}"))
            .collect();
        println!("  {name} {mode} readings: {}", readings.join(", "));
        println!(
            "  {name} {mode} startup end estimate: {:.2} Mbit/s",
            r.startup_end_estimate
        );
        println!(
            "  {name} {mode} transferred: {}",
            r.transferred
                .map_or_else(|| "no".to_owned(), |t| format!("at {t:.2} s"))
        );
        let probes: Vec<String> = r
            .probes
            .iter()
            .zip(&r.probe_packets)
            .zip(&r.probe_starts)
            .map(|((t, n), (e, missed))| {
                format!("{t:.2} s: {n} packets, estimate {e:.1}, missed {missed:.3}")
            })
            .collect();
        println!("  {name} {mode} probes: {}", probes.join("; "));
        let closes: Vec<String> = r
            .closes
            .iter()
            .map(|(t, what)| format!("{t:.2} s: {what}"))
            .collect();
        println!("  {name} {mode} closes: {}", closes.join("; "));
        println!("  {name} {mode} windows: {}", window_stats(&r.spans));
        let lowered = r.min_rtt_changes.iter().filter(|c| c.2).count();
        let renewed = r.min_rtt_changes.len() - lowered;
        let last = r.min_rtt_changes.last().map_or_else(
            || "none".to_owned(),
            |(t, v, _)| format!("{v:.3} ms at {t:.2} s"),
        );
        let gap = r
            .min_rtt_changes
            .windows(2)
            .map(|w| w[1].0 - w[0].0)
            .fold(0.0_f64, f64::max);
        println!(
            "  {name} {mode} min rtt: {lowered} lowered, {renewed} renewed or taken by a probe, \
             last {last}, longest gap {gap:.2} s"
        );
        let changes: Vec<String> = r
            .min_rtt_changes
            .iter()
            .map(|(t, v, lower)| {
                format!("{t:.2} s {v:.3} ms{}", if *lower { " lower" } else { "" })
            })
            .collect();
        println!("  {name} {mode} min rtt changes: {}", changes.join(", "));
        for (i, s) in r.seconds.iter().enumerate() {
            let t = s.nanos.max(1.0);
            println!(
                "  {name} {mode} t={i:>3} send {:>6.1} delivered {:>6.1} lost {:>6.1} \
                 window {:>6.0} kB estimate {:>6.1} in-flight/window {:.3} floor {:.2} \
                 gain {:.0} recovery {:.2} base {:.3} probe {:.2}",
                to_f64(s.sent) * 8.0 / 1e6,
                to_f64(s.delivered) * 8.0 / 1e6,
                to_f64(s.lost) * 8.0 / 1e6,
                s.window / t / 1e3,
                s.estimate / t,
                s.in_flight_share / t,
                s.floor / t,
                s.gain / t,
                s.recovery_binding / t,
                s.base / t,
                s.probe / t,
            );
        }
    }
    r
}

/// Runs `sc` before and after the base loss, in that order.
fn both(name: &str, sc: Scenario, series: bool) -> (Report, Report) {
    (run(name, sc.before(), series), run(name, sc, series))
}

/// Whether the series is printed: set `LINE_SIM_SERIES=1` with `--nocapture`.
fn series() -> bool {
    std::env::var_os("LINE_SIM_SERIES").is_some()
}

const SEEDS: [u64; 3] = [1, 2, 3];

/// The connection window Surge advertises, 16 MiB. A sender without a rate
/// limit is held by it, which the simulator does not model, so a run without
/// a limit ends when the window reaches it.
const CLIENT_WINDOW: u64 = 16 * 1024 * 1024;

/// S1 to S3 (V2): paths that drop a quarter to a third of the packets, with no
/// rate limit, for 20 s.
///
/// Before, the first congestion event ends the startup, the cap is at its
/// floor for most of the run, and the send rate is within 10 percent of the
/// recorded one. After, the startup ends at the same event, and having lost
/// more than 5 percent it starts the first probe at once. A run whose reading
/// is kept within 2 s reaches [`CLIENT_WINDOW`] within 20 s. A probe at the
/// floor on a path with a long RTT counts under 100 packets and gives no
/// reading, and such a run stays at the floor; it is printed and not asserted.
#[test]
fn paths_that_drop_a_quarter_to_a_third_without_a_limit() {
    for (name, rtt_ms, drop_share, recorded) in [
        ("S1", 64, 0.33, 28.2),
        ("S2", 151, 0.24, 11.7),
        ("S3", 90, 0.23, 20.0),
    ] {
        for seed in SEEDS {
            let mut sc = Scenario::new(rtt_ms, drop_share, seed);
            sc.seconds = 20;
            sc.stop_window = Some(CLIENT_WINDOW);
            let (before, after) = both(name, sc, series());
            assert!(
                (before.send - recorded).abs() <= recorded * 0.1,
                "{name} seed {seed}: before sends {:.1}, recorded {recorded}",
                before.send
            );
            assert!(before.stopped.is_none(), "{name} seed {seed}: before");
            assert!(
                before.floor_share > 0.5,
                "{name} seed {seed}: before, the cap was at the floor {:.2} of the time",
                before.floor_share
            );
            if after.readings.first().is_some_and(|&(at, _)| at <= 2.0) {
                assert!(
                    after.stopped.is_some(),
                    "{name} seed {seed}: after, the window did not reach 16 MiB in 20 s"
                );
            }
        }
    }
}

/// P1: a handshake of four flights of three packets that loses the last
/// packet of each of its first two flights, on a path that drops 0.24 at
/// 151 ms (the lab trace), 0.23 at 85 ms or 0.30 at 250 ms. Two congestion
/// events in a row, the second in an interval without growth, end the
/// startup before any bulk data is acknowledged, on a dozen packets; one
/// lost packet does not, because the first interval that runs the test
/// always grows from zero.
///
/// Before, the startup ends in the handshake. After, it runs until it has
/// counted 100 packets, past the handshake, and the base loss acts within
/// 5 s. Before's bound is zero, so its base loss never acts.
#[test]
fn a_handshake_that_loses_packets_does_not_end_the_startup() {
    for (name, rtt_ms, drop_share) in [("P1a", 151, 0.24), ("P1b", 85, 0.23), ("P1c", 250, 0.30)] {
        let rtt = Duration::from_millis(rtt_ms);
        let mut sc = Scenario::new(rtt_ms, drop_share, 1);
        sc.seconds = 6;
        sc.handshake = Some(Handshake {
            packets: 3,
            flights: 4,
            bulk: rtt * 4,
        });
        sc.drop_packets = &[2, 5];
        let (before, after) = both(name, sc, series());
        let handshake = (rtt * 5).as_secs_f64();
        assert!(
            before.startup_end.is_some_and(|t| t <= handshake),
            "{name}: before, the startup ends in the handshake, not at {:?}",
            before.startup_end
        );
        assert!(
            after.startup_end.is_some_and(|t| t > handshake),
            "{name}: after, the startup ends past the handshake, not at {:?}",
            after.startup_end
        );
        let acts = after.readings.iter().find(|&&(_, p)| p > 0.0);
        assert!(
            acts.is_some_and(|&(at, _)| at <= 5.0),
            "{name}: after, the base loss acts at {acts:?}"
        );
    }
}

/// V1: the drop share from 0 to 0.40 at 85 ms behind a policer of 200 Mbit/s
/// and 1 MB, under both loss rules, before and after. Prints only.
#[test]
#[ignore = "a sweep for a report"]
fn a_sweep_of_the_drop_share_behind_a_policer_at_85_ms() {
    let shares: Vec<u32> = (0..=8)
        .map(|i| i * 5)
        .chain([16, 17, 18, 19, 21, 22])
        .collect();
    for rule in [LossRule::Ours, LossRule::QuinnDefault] {
        for &percent in &shares {
            let p = f64::from(percent) / 100.0;
            for seed in SEEDS {
                let mut sc = Scenario::new(85, p, seed).policer(200.0, 1e6);
                sc.loss_rule = rule;
                both(&format!("V1 {rule:?} p {p:.2}"), sc, false);
            }
        }
    }
}

/// V3: a policer of 191.5 Mbit/s at 55 ms with a bucket of 0.25, 1 and 4 MB
/// and no other loss. Both deliver at least 98 percent of the policer's rate.
/// Without random drop the seed changes nothing.
#[test]
fn a_policer_at_191_mbit_s_and_55_ms() {
    for depth in [0.25e6, 1e6, 4e6] {
        let name = format!("V3 depth {:.2} MB", depth / 1e6);
        let sc = Scenario::new(55, 0.0, 1).policer(191.5, depth);
        let (before, after) = both(&name, sc, series());
        for r in [before, after] {
            assert!(r.delivered >= 0.98 * 191.5, "{name}: {:.1}", r.delivered);
        }
    }
}

/// The episodes of V4: everything dropped for 7 ms on average, about once
/// every 147 ms, which is about 5 percent of the time.
const V4_EPISODES: Episodes = Episodes {
    quiet: Duration::from_millis(140),
    lossy: Duration::from_millis(7),
    share: 1.0,
};

/// V4: the policer of V3 with loss in episodes. Prints only.
#[test]
#[ignore = "a scenario for a report"]
fn a_policer_with_loss_in_episodes() {
    for depth in [0.25e6, 1e6, 4e6] {
        for seed in SEEDS {
            let mut sc = Scenario::new(55, 0.0, seed).policer(191.5, depth);
            sc.episodes = Some(V4_EPISODES);
            let name = format!("V4 depth {:.2} MB", depth / 1e6);
            let (_, after) = both(&name, sc, series());
            println!(
                "  {name} seed {seed}: clean 100 ms spans {:.2}, packets per episode {:.0}",
                after.clean_spans, after.per_episode
            );
        }
    }
}

/// V5: a policer of 96 Mbit/s at 85 ms with 12 and 20 percent dropped.
/// Prints only.
#[test]
#[ignore = "a scenario for a report"]
fn a_policer_at_96_mbit_s_with_random_loss() {
    for p in [0.12, 0.20] {
        for seed in SEEDS {
            let sc = Scenario::new(85, p, seed).policer(96.0, 1e6);
            both(&format!("V5 p {p:.2}"), sc, series());
        }
    }
}

/// V6: a queue of 150 Mbit/s and 50 kB at 60 ms, without loss (S6) and with
/// 2 percent dropped (S8). Prints only.
#[test]
#[ignore = "a scenario for a report"]
fn a_short_queue_with_and_without_random_loss() {
    for p in [0.0, 0.02] {
        for seed in SEEDS {
            let sc = Scenario::new(60, p, seed).queue(150.0, 50e3);
            both(&format!("V6 p {p:.2}"), sc, series());
        }
    }
}

/// S8 with the steady gain pinned at 1.05 and at 1.25, on the controller as
/// it was before the base loss. Asserts per seed that 1.05 delivers under 60
/// percent of what 1.25 does.
#[test]
fn a_short_queue_with_2_percent_dropped_at_a_pinned_gain() {
    for seed in SEEDS {
        let mut delivered = [0.0; 2];
        for (i, pinned) in [1050, 1250].into_iter().enumerate() {
            let mut sc = Scenario::new(60, 0.02, seed).queue(150.0, 50e3).before();
            sc.pinned_gain = Some(pinned);
            delivered[i] = run(&format!("S8 pinned {pinned}"), sc, series()).delivered;
        }
        assert!(
            delivered[0] < 0.6 * delivered[1],
            "S8 seed {seed}: {delivered:?}"
        );
    }
}

/// V7: 20 percent dropped at 85 ms behind a policer of 200 Mbit/s, 40 s with
/// the per-second series. Prints only.
#[test]
#[ignore = "a scenario for a report"]
fn twenty_percent_dropped_behind_a_policer_second_by_second() {
    for seed in SEEDS {
        let mut sc = Scenario::new(85, 0.20, seed).policer(200.0, 1e6);
        sc.seconds = 40;
        let (_, after) = both("V7", sc, seed == 1);
        let target = 0.9 * 0.8 * 200.0;
        let reached = after
            .seconds
            .iter()
            .position(|s| to_f64(s.delivered) * 8.0 / 1e6 >= target);
        println!("  V7 seed {seed}: first second at 90 percent: {reached:?}");
    }
}

/// V8: the drop share steps from 0.10 to 0.25 at 20 s and back at 40 s,
/// behind a policer of 200 Mbit/s at 85 ms. Prints only.
#[test]
#[ignore = "a scenario for a report"]
fn a_drop_share_that_steps_up_and_back() {
    for seed in SEEDS {
        let mut sc = Scenario::new(85, 0.10, seed).policer(200.0, 1e6);
        sc.drop_steps = &[(20, 0.25), (40, 0.10)];
        sc.seconds = 70;
        both("V8", sc, seed == 1);
    }
}

/// V9: everything dropped for 150 ms at 25 s, once outside a probe and once
/// during one, behind a policer of 191.5 Mbit/s at 55 ms. Prints only.
#[test]
#[ignore = "a scenario for a report"]
fn an_outage_of_150_ms() {
    for in_probe in [false, true] {
        for seed in SEEDS {
            let mut sc = Scenario::new(55, 0.0, seed).policer(191.5, 1e6);
            sc.outage = Some(Outage {
                at: Duration::from_secs(25),
                length: Duration::from_millis(150),
                in_probe,
            });
            let name = if in_probe { "V9 in a probe" } else { "V9" };
            both(name, sc, seed == 1);
        }
    }
}

/// V10: transfers of 15 s at 85 ms behind a policer of 200 Mbit/s and 1 MB,
/// with 15 and 23 percent dropped, measured over the whole 15 s. Prints only.
#[test]
#[ignore = "a scenario for a report"]
fn short_transfers_behind_a_policer_with_random_loss() {
    for p in [0.15, 0.23] {
        for seed in SEEDS {
            let mut sc = Scenario::new(85, p, seed).policer(200.0, 1e6);
            sc.seconds = 15;
            sc.warmup = 0;
            both(&format!("V10 p {p:.2}"), sc, false);
        }
    }
}

/// Behind a slow policer on a path that drops nothing, the first sample of the
/// startup already loses, because the initial window is paced above the
/// path's rate. Asserts that the base loss stays zero and that sent over
/// delivered is within 0.02 of the controller before the base loss, over
/// 30 s from the start.
#[test]
fn slow_policers_on_paths_without_base_loss_read_none() {
    for (name, rtt_ms, mbps) in [
        ("30 Mbit/s at 60 ms", 60, 30.0),
        ("10 Mbit/s at 200 ms", 200, 10.0),
    ] {
        for seed in SEEDS {
            let mut sc = Scenario::new(rtt_ms, 0.0, seed).policer(mbps, 20e3);
            sc.seconds = 30;
            sc.warmup = 0;
            let (before, after) = both(name, sc, series());
            assert!(
                after.base == 0.0,
                "{name} seed {seed}: base loss {}",
                after.base
            );
            let ratio = |r: &Report| r.send / r.delivered;
            assert!(
                (ratio(&after) - ratio(&before)).abs() <= 0.02,
                "{name} seed {seed}: sent over delivered {:.3} after, {:.3} before",
                ratio(&after),
                ratio(&before)
            );
        }
    }
}

/// On a clean policer the base loss is zero during the first startup, so the
/// startup ends as it did before the base loss was read. Asserts that its lost
/// bytes and the time it ends are the same as before, exactly.
#[test]
fn a_clean_policer_ends_the_first_startup_as_before() {
    for (rtt_ms, mbps, depth) in [(55, 191.5, 1e6), (60, 30.0, 20e3), (200, 10.0, 20e3)] {
        for seed in SEEDS {
            let mut sc = Scenario::new(rtt_ms, 0.0, seed).policer(mbps, depth);
            sc.seconds = 5;
            sc.warmup = 0;
            let name = format!("{mbps} Mbit/s at {rtt_ms} ms");
            let (before, after) = both(&name, sc, false);
            assert_eq!(
                (before.startup_lost, before.startup_end),
                (after.startup_lost, after.startup_end),
                "{name} seed {seed}"
            );
        }
    }
}

/// Behind a policer whose burst allowance is several times what it passes in a
/// round trip, the startup measures several times the token rate, and the
/// estimate keeps that sample for ten intervals. A probe at half of such an
/// estimate is above the path's rate and reads its own loss. Asserts, over 30
/// s from the start, that every reading is under 0.02.
///
/// Sent over delivered is not asserted. Each probe behind such a policer lets
/// the bucket fill while it holds half the window, and the window overshoots
/// when it opens again, before the base loss as after. The early probe adds
/// one such episode, which in `line_sim` raised sent over delivered over 30 s
/// by up to 0.03 behind 30 Mbit/s and once by 0.09 behind 60 Mbit/s.
#[test]
fn a_policer_with_a_large_burst_allowance_reads_no_base_loss() {
    for mbps in [30.0, 60.0] {
        for seed in SEEDS {
            let mut sc = Scenario::new(60, 0.0, seed).policer(mbps, 4e6);
            sc.seconds = 30;
            sc.warmup = 0;
            let name = format!("{mbps} Mbit/s with 4 MB");
            let (_, after) = both(&name, sc, series());
            for &(at, share) in &after.readings {
                assert!(
                    share < 0.02,
                    "{name} seed {seed}: read {share:.3} at {at:.2} s"
                );
            }
        }
    }
}

/// A slow path with base loss: 85 ms, a policer of 40 Mbit/s and 1 MB, a fifth
/// of the packets dropped. Prints only.
#[test]
#[ignore = "a scenario for a report"]
fn a_slow_policer_with_a_fifth_dropped() {
    for seed in SEEDS {
        let sc = Scenario::new(85, 0.20, seed).policer(40.0, 1e6);
        both("slow lossy", sc, series());
    }
}

/// An outage of 150 ms in the first probe from 5 s on, behind a policer of
/// 60 Mbit/s and 20 kB at 60 ms. The probe that the startup's loss brings
/// forward has already given a reading at about 0.7 s, so the outage's reading
/// is not the only one; it reads near 1 and is dropped. Prints only.
#[test]
#[ignore = "a scenario for a report"]
fn an_outage_in_a_probe_behind_60_mbit_s() {
    for seed in SEEDS {
        let mut sc = Scenario::new(60, 0.0, seed).policer(60.0, 20e3);
        sc.seconds = 40;
        sc.warmup = 0;
        sc.outage = Some(Outage {
            at: Duration::from_secs(5),
            length: Duration::from_millis(150),
            in_probe: true,
        });
        both("outage in a probe", sc, seed == 1);
    }
}

/// Three seconds at 90 percent dropped, from 25 s, on a path that drops a
/// fifth of the packets behind a policer of 200 Mbit/s at 85 ms. The episode
/// lowers the estimate under half of its highest value, and the climb back
/// brings the startup back. A total outage does not: without ACKs no sample
/// interval closes and the estimate stays. Prints only.
#[test]
#[ignore = "a scenario for a report"]
fn a_loss_episode_that_brings_the_startup_back() {
    for seed in SEEDS {
        let mut sc = Scenario::new(85, 0.20, seed).policer(200.0, 1e6);
        sc.seconds = 45;
        sc.drop_steps = &[(25, 0.90), (28, 0.20)];
        both("loss episode", sc, seed == 1);
    }
}

/// Loss in episodes calibrated to a production rate-limit line in a typical
/// evening: 0.5 s quiet and 0.05 s lossy on average, 30 percent lost in the
/// lossy state. The capture read, in stages of 8 s, a mean loss of 1.5 to 4.0
/// percent, 200 ms windows at 5, 10 and 17 percent or more in 8 to 24, 1 to 13
/// and 0 to 8 percent of the windows, and the lower of two windows 0.6 s apart
/// at 5 and 10 percent or more in 0 to 14 and 0 to 6 percent. On a sender held
/// at about 41 Mbit/s for 240 s, three seeds, this setting read a mean of
/// 0.023 to 0.024, stages of 0.7 to 4.3 percent, windows in 18 to 19, 9 and 2
/// to 3 percent, and the lower of two in 3 to 4 and 1 percent.
const TYPICAL_EPISODES: Episodes = Episodes {
    quiet: Duration::from_millis(500),
    lossy: Duration::from_millis(50),
    share: 0.30,
};

/// Loss in episodes calibrated to the same line in a bad evening: 0.3 s quiet
/// and 0.2 s lossy on average, 20 percent lost in the lossy state. The capture
/// read a mean of 6.5 to 10.3 percent per stage, windows at 5, 10 and 17
/// percent or more in 44 to 74, 21 to 45 and 12 to 21 percent, and the lower
/// of two in 15 to 58 and 3 to 26 percent. This setting read a mean of 0.078
/// to 0.081, stages of 3.9 to 11.1 percent, windows in 53 to 55, 38 to 39 and
/// 21 to 22 percent, and the lower of two in 28 to 31 and 14 to 16 percent:
/// within the capture except windows at 17 percent, at or just above its top,
/// and stages that spread wider than its own.
const DENSE_EPISODES: Episodes = Episodes {
    quiet: Duration::from_millis(300),
    lossy: Duration::from_millis(200),
    share: 0.20,
};

/// The calibrated episodes behind the policer of 191.5 Mbit/s and 1 MB at
/// 55 ms, 120 s, three seeds, with the window statistics. Prints only.
#[test]
#[ignore = "a scenario for a report"]
fn a_policer_with_loss_in_episodes_calibrated_to_production() {
    for (name, episodes) in [("typical", TYPICAL_EPISODES), ("dense", DENSE_EPISODES)] {
        for seed in SEEDS {
            let mut sc = Scenario::new(55, 0.0, seed).policer(191.5, 1e6);
            sc.episodes = Some(episodes);
            sc.seconds = 120;
            both(&format!("{name} episodes"), sc, true);
        }
    }
}

/// A recorded sequence is read from its starting point, each byte holds for
/// the stretch, and the sequence starts again at its end.
#[test]
fn a_recorded_sequence_is_read_in_order_and_starts_again() {
    let fates = |sc: Scenario, count: usize| -> Vec<bool> {
        (0..count).map(|n| sc.traced_drop(n)).collect()
    };
    let mut sc = Scenario::new(60, 0.0, 1);
    assert_eq!(fates(sc, 3), [false; 3], "no sequence drops nothing");
    sc.trace = Some(b"1101");
    assert_eq!(
        fates(sc, 8),
        [false, false, true, false, false, false, true, false],
        "the third of every four"
    );
    sc.trace_start = 2;
    assert_eq!(
        fates(sc, 6),
        [true, false, false, false, true, false],
        "from the third byte on"
    );
    sc.trace_start = 0;
    sc.trace_stretch = 2;
    assert_eq!(
        fates(sc, 10),
        [
            false, false, false, false, true, true, false, false, false, false
        ],
        "each byte for two packets in a row"
    );
}

/// A sender that a client window holds under the path's rate loses exactly
/// what the recorded sequence drops: a quarter of its packets when the
/// sequence drops every fourth, whatever the stretch.
#[test]
fn a_held_sender_loses_what_the_recorded_sequence_drops() {
    for stretch in [1, 3] {
        let mut sc = Scenario::new(60, 0.0, 1);
        sc.seconds = 12;
        sc.warmup = 2;
        sc.client_window = Some(600_000);
        sc.trace = Some(b"1110");
        sc.trace_stretch = stretch;
        let report = run(&format!("sequence stretch {stretch}"), sc, false);
        assert!(
            (report.lost_share - 0.25).abs() < 0.01,
            "stretch {stretch}: lost {:.3}",
            report.lost_share
        );
    }
}

/// Recorded loss sequences in place of the random share, for a report. Every
/// file of the directory `LINE_SIM_TRACE_DIR` whose name starts with
/// `LINE_SIM_TRACE_PREFIX` is one sequence, a `0` per dropped packet and a `1`
/// per delivered one. Each runs from three starting points behind a policer
/// of each rate in `LINE_SIM_TRACE_MBPS` (megabits per second, separated by
/// commas) with 1 MB, at `LINE_SIM_TRACE_RTT_MS`. With `LINE_SIM_TRACE_STRETCH`
/// each recorded packet's fate is met by that many packets in a row. Prints
/// only.
#[test]
#[ignore = "a scenario for a report"]
fn recorded_loss_sequences() {
    let Ok(dir) = std::env::var("LINE_SIM_TRACE_DIR") else {
        return;
    };
    let prefix = std::env::var("LINE_SIM_TRACE_PREFIX").unwrap_or_default();
    let limits: Vec<f64> = std::env::var("LINE_SIM_TRACE_MBPS")
        .unwrap_or_else(|_| "90,150".to_owned())
        .split(',')
        .filter_map(|v| v.parse().ok())
        .collect();
    let rtt_ms: u64 = std::env::var("LINE_SIM_TRACE_RTT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(90);
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .expect("the directory of sequences")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&prefix))
        })
        .collect();
    files.sort();
    for path in files {
        let bytes: Vec<u8> = std::fs::read(&path)
            .expect("a sequence")
            .into_iter()
            .filter(|b| *b == b'0' || *b == b'1')
            .collect();
        let trace: &'static [u8] = Box::leak(bytes.into_boxed_slice());
        let dropped = trace.iter().filter(|&&b| b == b'0').count();
        let share = to_f64(u64::try_from(dropped).unwrap_or(u64::MAX))
            / to_f64(u64::try_from(trace.len()).unwrap_or(u64::MAX));
        let label = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("sequence")
            .to_owned();
        for &mbps in &limits {
            for third in 0..3 {
                let mut sc = Scenario::new(rtt_ms, 0.0, 1).policer(mbps, 1e6);
                sc.trace = Some(trace);
                sc.trace_start = trace.len() / 3 * third;
                sc.trace_stretch = std::env::var("LINE_SIM_TRACE_STRETCH")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1);
                let name = format!("T {label} {mbps:.0} start{third}");
                let (before, after) = both(&name, sc, series());
                let own: Vec<String> = after
                    .readings
                    .iter()
                    .map(|(at, p)| format!("{p:.3}@{at:.0}"))
                    .collect();
                println!(
                    "  TRACE {label} limit {mbps:.0} start {third}: recorded {share:.3} | \
                     delivered after {:.1} before {:.1} ratio {:.2} | after floor {:.2} base {:.3} \
                     sent/delivered {:.3} | before floor {:.2} | readings {}",
                    after.delivered,
                    before.delivered,
                    after.delivered / before.delivered.max(1e-9),
                    after.floor_share,
                    after.base,
                    after.send / after.delivered.max(1e-9),
                    before.floor_share,
                    own.join(" ")
                );
            }
        }
    }
}

/// A clean path whose acknowledgements reach the sender in clumps, here 50 ms
/// apart on a round trip of 65 ms, holds the sender at its floor, and the
/// record for the close line shows it: most of the time the window held the
/// sender was spent at the floor without loss, on a connection that had
/// delivered several times what the floor carries. With acknowledgements
/// every 2 ms the same path spends no time at the floor.
///
/// The first half asserts what the controller does today, which is a fault
/// and not a rule: the window is sized by the minimum RTT, and a packet stays
/// in it for as long as it is in flight. When that is repaired, the first half
/// changes.
#[test]
fn acknowledgements_in_clumps_hold_the_sender_at_the_floor_and_the_record_shows_it() {
    // What the floor sends on this path when a window turns over once per
    // round trip, in bytes per second.
    let floor_rate = INITIAL_WINDOW * 1000 / 65;
    for seed in SEEDS {
        let mut sc = Scenario::new(65, 0.0, seed).policer(150.0, 1e6);
        sc.ack_batch = Duration::from_millis(50);
        let r = run("clumps of 50 ms", sc, false);
        let held = r.record.window_limited.as_secs_f64();
        assert!(
            held >= 40.0,
            "seed {seed}: the window held the sender for {held} s of 60"
        );
        assert!(
            r.record.floor_lossless.as_secs_f64() >= 0.6 * held,
            "seed {seed}: {:?}",
            r.record
        );
        assert!(
            r.record.peak >= 4 * floor_rate,
            "seed {seed}: {:?}",
            r.record
        );
        assert!(
            r.delivered <= 40.0,
            "seed {seed}: delivered {}",
            r.delivered
        );

        let r = run(
            "no clumps",
            Scenario::new(65, 0.0, seed).policer(150.0, 1e6),
            false,
        );
        assert!(r.record.window_limited.as_secs_f64() >= 40.0, "seed {seed}");
        assert_eq!(
            r.record.floor,
            Duration::ZERO,
            "seed {seed}: {:?}",
            r.record
        );
        assert!(
            r.delivered >= 140.0,
            "seed {seed}: delivered {}",
            r.delivered
        );
    }
}

/// The same run twice gives the same numbers.
#[test]
fn a_run_depends_only_on_its_scenario() {
    let mut sc = Scenario::new(64, 0.33, 7).policer(100.0, 1e6);
    sc.episodes = Some(V4_EPISODES);
    let a = Sim::new(sc).run();
    let b = Sim::new(sc).run();
    assert_eq!(
        a.seconds
            .iter()
            .map(|s| (s.sent, s.delivered, s.lost))
            .collect::<Vec<_>>(),
        b.seconds
            .iter()
            .map(|s| (s.sent, s.delivered, s.lost))
            .collect::<Vec<_>>()
    );
}

/// One scenario from environment variables, with its series: `LINE_SIM_RTT_MS`
/// (85), `LINE_SIM_DROP` (0), `LINE_SIM_POLICER_MBPS` and `LINE_SIM_DEPTH`
/// (none, 1 MB), `LINE_SIM_QUEUE_MBPS` and `LINE_SIM_QUEUE_BYTES` (none,
/// 50 kB), `LINE_SIM_SECONDS` (60), `LINE_SIM_WARMUP` (10),
/// `LINE_SIM_STOP_BYTES` (a window that ends the run; none),
/// `LINE_SIM_TRANSFER_BYTES` (bytes whose arrival ends the run; none),
/// `LINE_SIM_STEP_AT` and `LINE_SIM_STEP_DROP` (a drop share from that second
/// on; none), `LINE_SIM_CLIENT_WINDOW` (none), `LINE_SIM_HANDSHAKE`
/// (`packets,flights,bulk_ms`; none), `LINE_SIM_DROP_PACKETS` (none),
/// `LINE_SIM_TRACE_MS` (none), `LINE_SIM_JITTER_US` (100), `LINE_SIM_EPISODES`
/// (the episodes of V4, or `quiet_ms,lossy_ms,share`), `LINE_SIM_OUTAGE_AT_MS`,
/// `LINE_SIM_OUTAGE_LEN_MS` (150) and `LINE_SIM_OUTAGE_IN_PROBE`,
/// `LINE_SIM_SEED` (1) and `LINE_SIM_QUINN_RULE` for quinn's default loss rule.
/// Runs the controller before the base loss and as it is. Prints only.
#[test]
#[ignore = "a scenario for exploring"]
fn a_scenario_from_the_environment() {
    fn env<T: std::str::FromStr>(name: &str, default: T) -> T {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }
    let mut sc = Scenario::new(
        env("LINE_SIM_RTT_MS", 85),
        env("LINE_SIM_DROP", 0.0),
        env("LINE_SIM_SEED", 1),
    );
    let policer: f64 = env("LINE_SIM_POLICER_MBPS", 0.0);
    if policer > 0.0 {
        sc = sc.policer(policer, env("LINE_SIM_DEPTH", 1e6));
    }
    let queue: f64 = env("LINE_SIM_QUEUE_MBPS", 0.0);
    if queue > 0.0 {
        sc = sc.queue(queue, env("LINE_SIM_QUEUE_BYTES", 50e3));
    }
    sc.seconds = env("LINE_SIM_SECONDS", 60);
    sc.warmup = env("LINE_SIM_WARMUP", 10);
    let stop: u64 = env("LINE_SIM_STOP_BYTES", 0);
    if stop > 0 {
        sc.stop_window = Some(stop);
    }
    let transfer: u64 = env("LINE_SIM_TRANSFER_BYTES", 0);
    if transfer > 0 {
        sc.transfer = Some(transfer);
    }
    if std::env::var_os("LINE_SIM_QUINN_RULE").is_some() {
        sc.loss_rule = LossRule::QuinnDefault;
    }
    if let Some(value) = std::env::var_os("LINE_SIM_HANDSHAKE") {
        let parts: Vec<u64> = value
            .to_string_lossy()
            .split(',')
            .filter_map(|v| v.parse().ok())
            .collect();
        if let [packets, flights, bulk_ms] = parts[..] {
            sc.handshake = Some(Handshake {
                packets,
                flights,
                bulk: Duration::from_millis(bulk_ms),
            });
        }
    }
    if let Some(value) = std::env::var_os("LINE_SIM_DROP_PACKETS") {
        let numbers: Vec<u64> = value
            .to_string_lossy()
            .split(',')
            .filter_map(|v| v.parse().ok())
            .collect();
        sc.drop_packets = Box::leak(numbers.into_boxed_slice());
    }
    let window: u64 = env("LINE_SIM_CLIENT_WINDOW", 0);
    if window > 0 {
        sc.client_window = Some(window);
    }
    sc.ack_jitter = Duration::from_micros(env("LINE_SIM_JITTER_US", 100));
    sc.trace_until = Duration::from_millis(env("LINE_SIM_TRACE_MS", 0));
    if let Some(value) = std::env::var_os("LINE_SIM_EPISODES") {
        let parts: Vec<f64> = value
            .to_string_lossy()
            .split(',')
            .filter_map(|v| v.parse().ok())
            .collect();
        sc.episodes = Some(match parts[..] {
            [quiet, lossy, share] => Episodes {
                quiet: Duration::from_secs_f64(quiet / 1e3),
                lossy: Duration::from_secs_f64(lossy / 1e3),
                share,
            },
            _ => V4_EPISODES,
        });
    }
    let outage_at: u64 = env("LINE_SIM_OUTAGE_AT_MS", 0);
    if outage_at > 0 {
        sc.outage = Some(Outage {
            at: Duration::from_millis(outage_at),
            length: Duration::from_millis(env("LINE_SIM_OUTAGE_LEN_MS", 150)),
            in_probe: std::env::var_os("LINE_SIM_OUTAGE_IN_PROBE").is_some(),
        });
    }
    let step_at: u64 = env("LINE_SIM_STEP_AT", 0);
    if step_at > 0 {
        let step: &'static [(u64, f64)] =
            Box::leak(vec![(step_at, env("LINE_SIM_STEP_DROP", 0.0))].into_boxed_slice());
        sc.drop_steps = step;
    }
    run("env", sc.before(), true);
    run("env", sc, true);
}
