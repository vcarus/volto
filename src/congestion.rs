//! The `bbr` congestion controller: a window of at most 1.25 times the
//! bandwidth-delay product it measures.
//!
//! It is the default (D108). The type is named [`BbrCapped`], for the name it
//! had when it was a wrapper around quinn's BBR.
//!
//! quinn-proto 0.11's BBR estimates the bottleneck bandwidth several times too
//! high, so its window never limits in-flight data, and a bulk download loses
//! what the bottleneck queue cannot hold. This controller uses no part of
//! quinn's BBR. It measures its own delivery rate and minimum RTT, and its
//! window is computed from them alone (D108).
//!
//! The window is a gain times the delivery rate measured once per round trip
//! (see `DeliveryRate`) times the minimum RTT. The gain is 1.25 unless the
//! path's loss has lowered it, as described below. Outside a recovery and a
//! probe the window is never below the initial window, 240 kB: 200 packets of
//! 1200 bytes, the default initial window of the BBR in quinn-proto 0.11
//! (`BbrConfig`). So on a path whose bandwidth-delay product is under 192 kB,
//! the window can be 240 kB. Until there is a delivery-rate sample and a
//! minimum RTT, the window is the initial window.
//!
//! quinn paces from the window (quinn-proto `src/connection/pacing.rs`,
//! `Pacer::delay`, which adds 1.25 windows of tokens per smoothed RTT), so the
//! window also sets the pacing rate. In-flight data sits at the window, and at
//! 1.25 a quarter of a bandwidth-delay product stands in the bottleneck queue
//! when the queue can hold it. 1.25 is
//! the highest pacing gain of BBR's ProbeBW cycle. BBR's window gain of two is a
//! ceiling above a sender that paces at the estimated rate. In quinn the window
//! is what the sender sends, so a gain of two keeps a whole bandwidth-delay
//! product queued and loses packets wherever the queue is shorter than that.
//!
//! The gain follows the path between 1.05 and 1.25. With the window at a gain
//! g, in-flight data is g times what the path carries in transit, and what the
//! bottleneck queue cannot hold of the rest is lost. In the lab a queue of
//! 0.04 bandwidth-delay products lost 19 percent of the packets at 1.25 and
//! 0.9 percent at 1.05. A path that loses packets at random needs the higher gain:
//! with 2 percent of them lost, a fixed 1.05 carried a third of what 1.25
//! carried, because each loss holds in-flight data for a round trip and at
//! 1.05 the window has no room to bring the delivery rate back. The two kinds
//! of loss differ in one thing the sender can see. A lower gain removes the
//! loss of a queue and leaves random loss as it is. The rule below is ours.
//!
//! The controller counts the bytes acknowledged and the bytes lost over loss
//! windows of at least four sample intervals and 2000 packets. When the last
//! four windows at the present gain each lost something and the mean of their
//! loss shares is one percent or more, a trial of a lower gain starts: the gain
//! times the share delivered, which is the in-flight data the path carried, and never under
//! the floor. Windows that lost so much that the path carried under 0.9
//! bandwidth-delay products start no trial, because a queue loses at most what
//! the window holds above one. If the loss was the queue's, the loss at the
//! lower gain is the part of the same in-flight data that the lower window
//! still exceeds, often none.
//!
//! The first two windows of a trial are left out. The lower gain is kept when
//! each of the next four lost less than the lowest of the four before the
//! trial, and their mean is at or under the middle between the loss before and
//! that prediction. The first of them that does not lose less ends the trial:
//! the old gain returns, and the wait before the next trial doubles, from 16
//! windows up to 256. This is a rank test. Eight windows whose loss does not
//! depend on the gain come in any order with the same chance, and the four
//! after the change are all below the four before it in 1 of 70 orders. The
//! chance here is higher than that, because a trial starts only after four
//! windows that all lost something, and windows without loss pass: loss series
//! recorded in the lab at a fixed gain passed in 2 to 3 of 100 places. Through
//! 1.8.0 one window of eight at or under the middle kept the gain, and after a
//! burst of loss the next window is at or under it at any gain. On a path with
//! loss in bursts every trial was kept, the gain stayed near the floor, and the
//! path carried 4 to 5 percent less than at 1.25. Under random loss a trial
//! lowers the gain by the loss share, 1.25 to 1.225 at 2 percent.
//!
//! A lowered gain is tried one step of 0.05 higher after 16 windows. The
//! middle alone judges it, in one window: when the loss is at or past the middle
//! between the loss before and the loss predicted for the higher gain, the
//! queue is still that short, the lowered gain returns and the wait doubles.
//! A gain that has come down after a loss burst or on a path that has changed
//! goes back up this way.
//!
//! A lowered gain is given up for 1.25 when the bandwidth estimate falls
//! under three quarters of the highest one since the gain was last 1.25. The
//! wait before the next trial of a lower gain doubles as after a refusal, and
//! that trial does not go as low as the gain given up: the floor is 0.05 above
//! it, and comes down by 0.05 every 256 windows. This guards a path with a
//! short queue and random loss, where a low gain passes the loss test and then
//! does not hold the rate.
//!
//! A window in which more than half of the intervals were app-limited did not
//! fill the queue. It counts for lowering the gain, because behind a short
//! queue the retransmissions stall the sender on flow control in nearly half
//! of all intervals. It does not count towards the 16 windows, and it can
//! refuse a higher gain on trial and cannot keep one. Otherwise a stream that
//! sends less than the path carries would take a lowered gain back to 1.25
//! step by step, and the next download would lose to the queue again.
//!
//! A connection that sends too little for a loss window within 32 intervals
//! has its trial dropped and its gain set back to 1.25, and the gain starts
//! again when the startup gain returns. Probe intervals and the two intervals
//! after a probe or a change of gain are left out of the loss windows, and so
//! are the interval that ends a startup and the seven after it. A startup ends
//! with more in flight than the path holds, and that loss is not the steady
//! gain's.
//!
//! A new connection also starts as slow start does. Until its first startup has
//! ended, the window is at most the initial window plus the bytes acknowledged
//! so far, so it doubles per round trip at most. The startup gain alone would
//! let the first samples open the window to 2.89 times a bandwidth-delay
//! product at once. The controller had this limit through the window of
//! quinn's BBR while it was built around it, and keeps it as a rule of its
//! own. The limit does not come back when the startup gain does.
//!
//! A new connection uses a higher gain until its estimate stops growing. With
//! the window at 1.25 times the estimate, each sample can only show the rate
//! that window allows, so the estimate grows by at most 1.25 times per sample.
//! The startup gain is BBR's Startup gain, 2/ln 2, about 2.89. The estimate has
//! stopped growing when three samples in a row from intervals that were not
//! app-limited have not raised it by 25 percent since it last did. This is
//! BBR's full-bandwidth test. A congestion event also ends the startup when the
//! sample interval it falls in does not raise the estimate by 25 percent,
//! whether or not that interval was app-limited. quinn reports a sender blocked
//! by the peer's flow control as app-limited. Behind a flow-control window
//! smaller than the startup window the full-bandwidth test therefore never
//! runs, and without the congestion exit the startup gain would stay.
//!
//! The startup gain returns when the estimate climbs back after a fall. The
//! estimate keeps a sample for ten intervals, so a loss episode longer than that
//! leaves only samples from the episode in it, and the window starts again from
//! its floor. At 1.25 the estimate then grows by about 12 percent per sample,
//! not 25, because a raised window shows in the sample about two round trips
//! later. So three samples in a row from intervals that were not app-limited,
//! each raising the estimate from below half of the highest estimate the
//! connection has had, bring the startup gain back, and the two rules above end
//! it again. Any rise counts, so a climb at 1.25 meets the rule within a few
//! samples. The rule is ours. The highest estimate does not expire, so on a
//! path whose rate has fallen for good, a later climb from below half of the
//! old rate also uses the startup gain, until the same two rules end it.
//!
//! A loss holds in-flight data for one round trip, by BBR's packet
//! conservation. The form here is ours, and it has the effect of the recovery
//! window of quinn's BBR. quinn reports a loss after the ACK batch that found
//! it, so the rule acts at the next batch. That batch sets a recovery window
//! of in-flight data plus the bytes it acknowledged, and never less than four
//! packets. Each later batch takes the bytes lost since the previous one off
//! the recovery window. Once a packet sent after the recovery began has been
//! acknowledged, each batch also adds the bytes it acknowledged. In-flight data
//! plus the bytes the batch acknowledged stays the recovery window's lower
//! bound. The recovery ends at the first batch without a loss that
//! acknowledges a packet sent after the last batch with one. The recovery
//! window limits the window only after the startup has ended, as quinn's BBR
//! applies its own only outside its Startup. An ECN mark loses no bytes and
//! starts no recovery.
//!
//! The minimum RTT expires. quinn's `RttEstimator::min` never does within a
//! path, so with it a lasting RTT rise would leave the window below the new
//! bandwidth-delay product, each delivery-rate sample would come out lower than
//! the last, and the window would fall to its floor. Expiry alone would not fix
//! that. A minimum measured again with the standing queue in it would raise the
//! window, and with it the queue, each time. So the controller empties the
//! queue before it measures, the way BBR's ProbeRTT does.
//!
//! A sample is the `now - sent` of an acknowledged packet. The peer's ACK
//! delay is part of it, which can only make it larger. The `now` can make it
//! smaller: quinn reads the clock once per endpoint poll and hands every ACK
//! of that poll the same value, so a poll that is held up between the clock
//! read and the socket read gives samples that are too short by the delay. One
//! such sample taken as the minimum holds the window under the
//! bandwidth-delay product for the 10 s it lasts, each delivery-rate sample
//! then comes out lower than the last, and nothing raises the estimate again:
//! in the lab a 60 ms path read as 37 ms once every 7 s carried 50 to 81
//! Mbit/s of 144. So the samples of one `now` count once. A sample under the
//! minimum lowers it when three values of `now` within a second have given
//! one, and the new minimum is the highest of the three lowest. A fall in the
//! path's RTT meets this with the third socket poll that reads an ACK. A
//! connection whose ACKs arrive less often than three polls in a second keeps
//! its minimum through such a fall; it sends too little for the window to
//! limit it, and the first bulk transfer confirms the lower minimum at once.
//! The rule is ours; BBR takes the
//! plain minimum, under a window gain of two that a short sample does not
//! bring under the bandwidth-delay product.
//!
//! A sample equal to the minimum restarts its 10 s lifetime, BBR's
//! MinRTTFilterLen. The first ACK after the lifetime ends that does not find
//! the sender app-limited starts a probe: the window is held at half the
//! estimated bandwidth-delay product, the target of BBRv2's ProbeRTT, and at
//! least four packets. Once in-flight data has fallen to that window, the probe
//! lasts 200 ms or one smoothed RTT, whichever is longer. The new minimum is
//! then taken from the samples since the probe started: the highest of the
//! lowest samples of the three values of `now` that gave the lowest ones,
//! without the limit of a second, or the lowest sample when the probe saw
//! fewer than three values of `now`. While the sender
//! is app-limited the probe does not start, because the window does not limit
//! an app-limited sender. ACKs that arrive during a probe count as app-limited
//! for the delivery rate, so the probe's own low samples do not lower the
//! estimate. Linux BBR does the same during ProbeRTT (`bbr_update_min_rtt` in
//! `net/ipv4/tcp_bbr.c`).
//!
//! A lasting RTT rise therefore lowers throughput until the next probe, which
//! starts 10 s after the minimum was last taken, or later while the sender is
//! app-limited. By then the estimate has fallen to what the floor carries, so
//! once the probe has taken the new minimum, the climb back to the new
//! bandwidth-delay product brings the startup gain back. A fall in RTT takes
//! effect with the third arrival that shows it. Each probe holds the window low for
//! about a quarter of a second.
//!
//! A delivery-rate sample is bounded by the send interval of its packets as
//! well as by its ACK interval (see `DeliveryRate`), because ACKs that arrive
//! together, as they do after a fall in RTT, would otherwise give a sample far
//! above what the path carries, and quinn's app-limited report for a
//! flow-control-blocked sender would keep the lower samples that follow out of
//! the estimate. One limit remains: quinn's app-limited flag is the
//! connection's state when the ACK arrives, not when the packet was sent, so
//! the first sample stored after ten or more unstored intervals, which replaces
//! the whole estimate, can measure packets sent while the sender was
//! app-limited and put the window about one round trip low until the next
//! sample.
//!
//! The window is computed when one of its inputs changes and stored, because
//! quinn reads it before every packet it sends. The inputs are the estimate,
//! the minimum RTT, the probe, the startup with its slow-start limit, the
//! steady gain, the recovery window and the MTU.
//!
//! Lab measurements are in `docs/configuration.md`.

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;

/// After how many sample intervals a stored delivery-rate sample can leave the
/// bandwidth estimate: the length of BBR's own bandwidth filter in round trips.
/// A sample interval lasts about one round trip. Every closed interval counts,
/// including one whose sample is not stored, and a sample leaves at the first
/// stored sample above zero that comes this many intervals or more after it.
/// While nothing is stored, the estimate does not change.
const SAMPLES: usize = 10;

/// The window a connection starts with, and the floor of the window outside a
/// probe: 200 packets of 1200 bytes, the default initial window of the BBR in
/// quinn-proto 0.11 (`BbrConfig::default()`), which this controller replaced.
const INITIAL_WINDOW: u64 = 200 * 1200;

/// The window as a multiple of the estimated bandwidth-delay product, in per
/// mille, once the startup has ended: the steady gain a connection starts with
/// and the highest one it uses.
const CWND_GAIN_PERMILLE: u64 = 1_250;

/// The lowest steady gain, in per mille. It is the lowest one measured: in the
/// lab a fixed 1.05 lost 0.9 percent through a queue of 0.04 bandwidth-delay
/// products where 1.25 lost 19 percent.
const GAIN_FLOOR_PERMILLE: u64 = 1_050;

/// How much a trial raises a lowered gain, in per mille.
const GAIN_STEP_UP_PERMILLE: u64 = 50;

/// The smallest step a trial lowers the gain by, in per mille.
const GAIN_MIN_STEP_PERMILLE: u64 = 10;

/// The share of bytes lost in a loss window, in parts per million, from which
/// a lower gain is tried: one percent.
const LOSS_TRIGGER_PPM: u64 = 10_000;

/// The least a path must have carried, as a gain in per mille, for a lower gain
/// to be tried. A queue loses at most what the window holds above one
/// bandwidth-delay product, 20 percent at 1.25. Loss windows after which the
/// gain times the mean share delivered is under 0.9 lost more than a queue explains. In the lab a 3 s burst of 90
/// percent loss would otherwise lower the gain to the floor for the climb back.
const LEAST_CARRIED_PERMILLE: u64 = 900;

/// The fewest sample intervals in a loss window.
const WINDOW_INTERVALS: u8 = 4;

/// The fewest packets of the current MTU in a loss window, so that a loss of
/// one percent is twenty packets.
const WINDOW_PACKETS: u64 = 2_000;

/// After this many sample intervals a loss window that has not covered
/// [`WINDOW_PACKETS`] is dropped with any trial, and a lowered gain goes back
/// to 1.25: without loss windows the guard does not run and no trial is judged.
const WINDOW_MAX_INTERVALS: u8 = 32;

/// How many sample intervals after a change of gain or a probe are left out of
/// the loss windows. The packets acknowledged and lost in them were sent
/// before it.
const SETTLE_INTERVALS: u8 = 2;

/// How many sample intervals are left out of the loss windows at the end of a
/// startup: the interval that ends it and the seven after it. The startup ends
/// with more in flight than the path and its queue hold, and what is lost of
/// that says nothing about the steady gain. In the lab a loss window that began
/// two intervals after the end of a startup still lost 16 percent to it.
const STARTUP_SETTLE_INTERVALS: u8 = 8;

/// How many loss windows at the present gain a lower gain is measured against,
/// and how many windows at the lower gain are judged. Eight windows whose loss
/// does not depend on the gain come in any order with the same chance, and all
/// of the later four are below all of the earlier four in 1 of 70 orders. A
/// trial starts only after four windows that all lost something, which raises
/// that chance: in the lab, loss series recorded at a fixed gain passed in 2 to
/// 3 of 100 places.
const TRIAL_WINDOWS: usize = 4;

/// [`TRIAL_WINDOWS`] as the divisor of a sum of loss shares.
const TRIAL_WINDOWS_U64: u64 = 4;

/// How many loss windows at a lower gain on trial are left out before the
/// judged ones. The receiver first has to take the retransmissions of what was
/// lost before, and until then the sender stalls on flow control and refills in
/// bursts, which lose more.
const TRIAL_SKIPPED_WINDOWS: u8 = 2;

/// How many loss windows pass after a lower gain was refused before one is
/// tried again. Doubles with each refusal up to [`MAX_WAIT`], and starts again
/// here when one is kept. A trial runs at a gain under the one the path needs,
/// so under loss that is not the queue's the trials themselves cost rate: in
/// the lab a wait of 4 put a third of a 60 s transfer on trial.
const FIRST_BACKOFF: u16 = 16;

/// How many loss windows a lowered gain is held before a higher one is tried.
/// Doubles each time the higher one is refused, up to [`MAX_WAIT`], and starts
/// again here when the gain is back at 1.25.
const FIRST_HOLD: u16 = 16;

/// The longest wait between two trials, in loss windows.
const MAX_WAIT: u16 = 256;

/// A lowered gain is given up when the bandwidth estimate is below this many
/// percent of the highest one since the gain was last 1.25.
const GUARD_PERCENT: u128 = 75;

/// The probe window as a multiple of the estimated bandwidth-delay product, in
/// per mille: half, the target of BBRv2's ProbeRTT.
const PROBE_GAIN_PERMILLE: u128 = 500;

/// The window until the estimate stops growing, in per mille: BBR's Startup
/// gain, 2/ln 2, to three decimals.
const STARTUP_GAIN_PERMILLE: u128 = 2_885;

/// How much the estimate has to rise, in percent of its value when it last
/// rose, to count as growth: BBR's full-bandwidth test.
const GROWTH_PERCENT: u128 = 125;

/// How many samples in a row without growth end the startup: BBR's
/// full-bandwidth test.
const SAMPLES_WITHOUT_GROWTH: u8 = 3;

/// How far the estimate has to be below its highest value, in percent of it,
/// for a rise to count towards bringing the startup back. Our own value.
const FALLEN_PERCENT: u128 = 50;

/// How many samples in a row, each raising the estimate from below
/// [`FALLEN_PERCENT`] of its highest value, bring the startup back. The same
/// count as [`SAMPLES_WITHOUT_GROWTH`]; the rule is ours. Any rise counts, not
/// only one of [`GROWTH_PERCENT`]: with the window at 1.25 times the estimate,
/// a raised window shows in the sample about two round trips later, so the
/// estimate grows by about 12 percent per sample.
const RISES_TO_RESTART: u8 = 3;

/// How many ACK batches with different arrival times have to give an RTT sample
/// under the minimum before the minimum comes down, to the highest of their
/// lowest samples.
const MIN_RTT_CONFIRMATIONS: usize = 3;

/// How long a sample under the minimum waits for the others that confirm it.
const LOW_SAMPLE_LIFETIME: Duration = Duration::from_secs(1);

/// How long a minimum RTT holds without a sample equal to it or a confirmed
/// lower one before a probe measures it again: BBR's MinRTTFilterLen.
const MIN_RTT_LIFETIME: Duration = Duration::from_secs(10);

/// The shortest time a probe holds its window once in-flight data has fallen
/// to it: BBR's ProbeRTTDuration.
const PROBE_TIME: Duration = Duration::from_millis(200);

/// The smallest probe window and the smallest recovery window, in packets:
/// BBR's minimum congestion window.
const MIN_WINDOW_PACKETS: u64 = 4;

/// Builds [`BbrCapped`] controllers.
#[derive(Debug, Clone, Default)]
pub struct BbrCappedConfig;

impl ControllerFactory for BbrCappedConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(BbrCapped {
            rate: DeliveryRate::default(),
            startup: Startup::default(),
            min_rtt: None,
            low: LowSamples::default(),
            probe: None,
            srtt: Duration::ZERO,
            mtu: current_mtu.into(),
            acked: 0,
            lost: 0,
            recovery: None,
            slow_start: Some(INITIAL_WINDOW),
            gain: Gain::default(),
            cap: None,
            window: INITIAL_WINDOW,
        })
    }
}

/// A controller whose window is at most 1.25 times the measured
/// bandwidth-delay product. See the [module documentation](self).
#[derive(Debug, Clone)]
pub struct BbrCapped {
    rate: DeliveryRate,
    startup: Startup,
    /// The minimum RTT and when it was taken or last renewed; `None` before
    /// the first ACK.
    min_rtt: Option<(Duration, Instant)>,
    /// The samples under the minimum that are not confirmed yet, and during a
    /// probe the lowest samples of the probe.
    low: LowSamples,
    /// The probe in progress, if any.
    probe: Option<Probe>,
    /// quinn's smoothed RTT as it was before the latest ACK frame, since quinn
    /// updates it after `on_ack` and `on_end_acks`: how long a sample interval
    /// lasts.
    srtt: Duration,
    mtu: u64,
    /// Bytes acknowledged since the last ACK batch ended.
    acked: u64,
    /// Bytes lost since the last ACK batch ended.
    lost: u64,
    /// The recovery in progress, if any.
    recovery: Option<Recovery>,
    /// The slow-start limit of a new connection: the initial window plus the
    /// bytes acknowledged so far. `None` once the first startup has ended.
    slow_start: Option<u64>,
    /// The steady gain and the loss windows that move it.
    gain: Gain,
    /// What [`BbrCapped::compute_cap`] returned when an input last changed.
    cap: Option<u64>,
    /// What [`Controller::window`] returns: the cap, or the initial window
    /// while there is none, lowered to the slow-start limit during the first
    /// startup and to the recovery window after the startup.
    window: u64,
}

/// The state of BBR's full-bandwidth test, which ends the startup gain, and
/// of the rule that brings it back after the estimate has fallen.
#[derive(Debug, Clone, Copy, Default)]
struct Startup {
    /// Whether the startup has ended. Cleared when the startup comes back.
    ended: bool,
    /// The estimate when it last grew by [`GROWTH_PERCENT`].
    grown_to: u64,
    /// Samples since then that did not grow it.
    flat: u8,
    /// Whether a congestion event came in the current sample interval.
    congested: bool,
    /// The highest estimate so far.
    peak: u64,
    /// The estimate after the last sample interval that was not app-limited.
    last: u64,
    /// Samples in a row, not counting app-limited ones, that raised the
    /// estimate from below [`FALLEN_PERCENT`] of `peak` after the startup had
    /// ended.
    rises: u8,
}

impl Startup {
    /// Applies the test to the sample interval that has just closed, with the
    /// estimate after it.
    fn on_interval(&mut self, estimate: u64, app_limited: bool) {
        let congested = std::mem::take(&mut self.congested);
        self.peak = self.peak.max(estimate);
        if self.ended {
            if !app_limited {
                self.count_rise(estimate);
            }
            return;
        }
        if !app_limited {
            self.last = estimate;
        }
        if app_limited && !congested {
            return;
        }
        if u128::from(estimate) * 100 >= u128::from(self.grown_to) * GROWTH_PERCENT {
            self.grown_to = estimate;
            self.flat = 0;
        } else if congested {
            // The Startup loss exit of BBRv2 and BBRv3, in a form of our own:
            // one congestion event in an interval without growth is enough.
            self.ended = true;
        } else {
            self.flat += 1;
            self.ended = self.flat >= SAMPLES_WITHOUT_GROWTH;
        }
    }

    /// Brings the startup back once [`RISES_TO_RESTART`] samples in a row,
    /// each from an estimate below [`FALLEN_PERCENT`] of the highest one, have
    /// raised it. The test that ends it then starts again from the current
    /// estimate.
    fn count_rise(&mut self, estimate: u64) {
        let last = std::mem::replace(&mut self.last, estimate);
        let fallen = u128::from(last) * 100 < u128::from(self.peak) * FALLEN_PERCENT;
        let rose = estimate > last;
        self.rises = if fallen && rose { self.rises + 1 } else { 0 };
        if self.rises >= RISES_TO_RESTART {
            *self = Self {
                grown_to: estimate,
                peak: self.peak,
                last: estimate,
                ..Self::default()
            };
        }
    }
}

/// The lowest RTT samples of up to [`MIN_RTT_CONFIRMATIONS`] arrival times.
///
/// quinn reads the clock once per endpoint poll and hands every ACK of that
/// poll the same `now` (quinn `EndpointDriver::poll`). A poll that is held up
/// between the clock read and the socket read, by the scheduler or by the host
/// of a virtual machine, gives samples that are too short by the delay, all
/// under one `now`. So one `now` counts once, and a minimum needs
/// [`MIN_RTT_CONFIRMATIONS`] of them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LowSamples([Option<(Instant, Duration)>; MIN_RTT_CONFIRMATIONS]);

impl LowSamples {
    /// Takes a sample that arrived at `now`. Entries older than `lifetime` are
    /// dropped first. The lowest sample per `now` is kept, for the
    /// [`MIN_RTT_CONFIRMATIONS`] values of `now` whose lowest sample is lowest.
    fn add(&mut self, now: Instant, rtt: Duration, lifetime: Option<Duration>) {
        if let Some(lifetime) = lifetime {
            for entry in &mut self.0 {
                if entry.is_some_and(|(at, _)| now.saturating_duration_since(at) > lifetime) {
                    *entry = None;
                }
            }
        }
        if let Some((_, lowest)) = self.0.iter_mut().flatten().find(|(at, _)| *at == now) {
            *lowest = (*lowest).min(rtt);
        } else if let Some(free) = self.0.iter_mut().find(|entry| entry.is_none()) {
            *free = Some((now, rtt));
        } else if let Some(highest) = self.0.iter_mut().flatten().max_by_key(|(_, rtt)| *rtt)
            && rtt < highest.1
        {
            *highest = (now, rtt);
        }
    }

    /// The highest of the kept samples once every slot is filled: the
    /// [`MIN_RTT_CONFIRMATIONS`]-th lowest of the arrival times seen.
    fn confirmed(&self) -> Option<Duration> {
        let mut highest = Duration::ZERO;
        for entry in &self.0 {
            highest = highest.max(entry.as_ref()?.1);
        }
        Some(highest)
    }
}

/// A probe that holds the window low to measure the minimum RTT again.
#[derive(Debug, Clone)]
struct Probe {
    /// The lowest RTT sample since the probe started.
    min: Duration,
    /// When the probe ends; `None` until in-flight data has fallen to the
    /// probe window.
    ends: Option<Instant>,
}

/// A recovery after a loss; see the module documentation.
#[derive(Debug, Clone, Copy)]
struct Recovery {
    /// The most in-flight data the recovery allows.
    window: u64,
    /// The end of the ACK batch that began the recovery. Once a packet sent
    /// after it has been acknowledged, the window grows by the bytes
    /// acknowledged.
    began: Instant,
    /// The end of the last ACK batch that had a loss.
    last_loss: Instant,
}

impl BbrCapped {
    /// The part of [`Controller::on_ack`] that is ours, split out because
    /// [`RttEstimator`] has no public constructor and the tests cannot make one.
    fn record_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        srtt: Duration,
    ) {
        self.srtt = srtt;
        self.acked = self.acked.saturating_add(bytes);
        self.gain.acked = self.gain.acked.saturating_add(bytes);
        if let Some(limit) = &mut self.slow_start {
            *limit = limit.saturating_add(bytes);
        }
        // A probe holds the window below the path's rate on purpose, so its ACKs
        // count as app-limited and its low samples do not lower the estimate.
        let probing = self.probe.is_some();
        self.rate.on_ack(sent, bytes, app_limited || probing);
        let rtt = now.saturating_duration_since(sent);
        if let Some(probe) = &mut self.probe {
            probe.min = probe.min.min(rtt);
            self.low.add(now, rtt, None);
            return;
        }
        match self.min_rtt {
            Some((min, at)) if rtt > min => {
                if !app_limited && now.saturating_duration_since(at) > MIN_RTT_LIFETIME {
                    self.probe = Some(Probe {
                        min: rtt,
                        ends: None,
                    });
                    self.low = LowSamples::default();
                    self.low.add(now, rtt, None);
                    self.refresh();
                }
            }
            // An equal sample only restarts the lifetime.
            Some((min, _)) if rtt == min => self.min_rtt = Some((rtt, now)),
            // A lower sample waits for two more arrival times that confirm it.
            Some(_) => {
                self.low.add(now, rtt, Some(LOW_SAMPLE_LIFETIME));
                if let Some(confirmed) = self.low.confirmed() {
                    self.min_rtt = Some((confirmed, now));
                    self.low = LowSamples::default();
                    self.refresh();
                }
            }
            None => {
                self.min_rtt = Some((rtt, now));
                self.refresh();
            }
        }
    }

    /// Starts the probe's clock once in-flight data has fallen to the probe
    /// window, and ends the probe when that time is up. Returns whether the
    /// probe ended.
    fn update_probe(&mut self, now: Instant, in_flight: u64) -> bool {
        let cap = self.cap;
        let Some(probe) = &mut self.probe else {
            return false;
        };
        match probe.ends {
            None if cap.is_none_or(|cap| in_flight <= cap) => {
                probe.ends = Some(now + PROBE_TIME.max(self.srtt));
            }
            Some(ends) if now >= ends => {
                // A probe too short for the confirmations takes its lowest sample.
                let min = self.low.confirmed().unwrap_or(probe.min);
                self.min_rtt = Some((min, now));
                self.low = LowSamples::default();
                self.probe = None;
                return true;
            }
            _ => {}
        }
        false
    }

    /// Applies the losses and acknowledgements of the ACK batch that has just
    /// ended to the recovery window. Returns whether the recovery changed.
    fn update_recovery(&mut self, now: Instant, in_flight: u64) -> bool {
        let lost = std::mem::take(&mut self.lost);
        let acked = std::mem::take(&mut self.acked);
        let held = in_flight
            .saturating_add(acked)
            .max(MIN_WINDOW_PACKETS * self.mtu);
        let acked_after = |at: Instant| self.rate.sent.is_some_and(|sent| sent > at);
        match self.recovery {
            None if lost == 0 => return false,
            None => {
                self.recovery = Some(Recovery {
                    window: held,
                    began: now,
                    last_loss: now,
                });
            }
            Some(r) if lost == 0 && acked_after(r.last_loss) => self.recovery = None,
            Some(r) => {
                let grown = if acked_after(r.began) { acked } else { 0 };
                self.recovery = Some(Recovery {
                    window: r
                        .window
                        .saturating_sub(lost)
                        .saturating_add(grown)
                        .max(held),
                    last_loss: if lost > 0 { now } else { r.last_loss },
                    ..r
                });
            }
        }
        true
    }

    /// Stores the cap and the window after a change to one of their inputs.
    fn refresh(&mut self) {
        self.cap = self.compute_cap();
        let window = self.cap.unwrap_or(INITIAL_WINDOW);
        let window = self.slow_start.map_or(window, |limit| window.min(limit));
        self.window = match self.recovery {
            Some(recovery) if self.startup.ended => window.min(recovery.window),
            _ => window,
        };
    }

    /// One debug line per delivery-rate sample, with the terms that limit the
    /// window after the ACK batch that closed it. Off under the shipped
    /// `volto=info` filter.
    fn trace(&self, sample: &Sample, in_flight: u64) {
        tracing::debug!(
            sample_bytes_per_sec = sample.rate,
            estimate_bytes_per_sec = self.rate.max().unwrap_or(0),
            cap_bytes = self.cap.unwrap_or(0),
            recovery_bytes = self.recovery.map_or(0, |r| r.window),
            window_bytes = self.window,
            in_flight_bytes = in_flight,
            min_rtt_us = self.min_rtt.map_or_default(|(min, _)| min.as_micros()),
            srtt_us = self.srtt.as_micros(),
            ack_interval_us = sample.ack_elapsed.as_micros(),
            send_interval_us = sample.send_elapsed.as_micros(),
            gain_permille = self.gain.permille,
            startup = !self.startup.ended,
            app_limited = sample.app_limited,
            stored = sample.stored,
            probing = self.probe.is_some(),
            "bbr-capped sample"
        );
    }

    /// The window limit, once there is a delivery-rate sample to compute it
    /// from: the steady gain times the bandwidth-delay product, the startup
    /// gain times it until the startup has ended, or half of it during a probe.
    ///
    /// Outside a probe the limit is never below [`INITIAL_WINDOW`], so a
    /// connection that has measured a low rate is never slower to send than a
    /// fresh one.
    fn compute_cap(&self) -> Option<u64> {
        let bandwidth = self.rate.max()?;
        let (min_rtt, _) = self.min_rtt?;
        let (gain_permille, floor) = match self.probe {
            None if self.startup.ended => (u128::from(self.gain.permille), INITIAL_WINDOW),
            None => (STARTUP_GAIN_PERMILLE, INITIAL_WINDOW),
            Some(_) => (PROBE_GAIN_PERMILLE, MIN_WINDOW_PACKETS * self.mtu),
        };
        // Bytes per second times microseconds times per mille.
        let bytes = u128::from(bandwidth) * min_rtt.as_micros() * gain_permille / 1_000_000_000;
        Some(u64::try_from(bytes).unwrap_or(u64::MAX).max(floor))
    }
}

/// The steady gain and the rule that moves it; see the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Gain {
    /// The steady gain in per mille, from [`GAIN_FLOOR_PERMILLE`] to
    /// [`CWND_GAIN_PERMILLE`].
    permille: u64,
    /// The lowest gain a trial may set. Raised when the guard gives up a gain,
    /// and lowered again a step at a time.
    floor: u64,
    /// Bytes acknowledged in the current loss window.
    acked: u64,
    /// Bytes lost in the current loss window.
    lost: u64,
    /// Sample intervals in the current loss window.
    intervals: u8,
    /// How many of them were app-limited.
    limited: u8,
    /// Sample intervals still to leave out.
    settle: u8,
    /// The trial in progress, if any.
    trial: Option<Trial>,
    /// The highest bandwidth estimate at the end of a loss window since the
    /// gain was last [`CWND_GAIN_PERMILLE`], in bytes per second.
    reference: u64,
    /// Loss windows to pass before a lower gain is tried.
    down_wait: u16,
    /// The wait the next refused lower gain sets.
    backoff: u16,
    /// Loss windows to pass before a higher gain is tried.
    up_wait: u16,
    /// The wait a refused higher gain sets.
    hold: u16,
    /// Loss windows to pass before a floor the guard raised comes down a step.
    floor_wait: u16,
    /// The loss shares of the latest windows at the present gain outside a
    /// trial, in parts per million, newest last.
    recent: [u64; TRIAL_WINDOWS],
    /// How many of them there are.
    recent_len: usize,
}

/// A gain on trial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Trial {
    /// The gain before the trial.
    from: u64,
    /// The loss share at that gain, in parts per million: for a lower gain the
    /// mean of the [`TRIAL_WINDOWS`] windows before the trial, for a higher
    /// gain the window before it.
    loss_ppm: u64,
    /// The lowest loss share of the windows before a trial of a lower gain.
    lowest_ppm: u64,
    /// Loss windows since the trial started.
    windows: u8,
    /// The sum of the loss shares of the judged windows of a lower gain.
    judged_ppm: u64,
}

impl Default for Gain {
    fn default() -> Self {
        Self {
            permille: CWND_GAIN_PERMILLE,
            floor: GAIN_FLOOR_PERMILLE,
            acked: 0,
            lost: 0,
            intervals: 0,
            limited: 0,
            settle: STARTUP_SETTLE_INTERVALS,
            trial: None,
            reference: 0,
            down_wait: 0,
            backoff: FIRST_BACKOFF,
            up_wait: FIRST_HOLD,
            hold: FIRST_HOLD,
            floor_wait: 0,
            recent: [0; TRIAL_WINDOWS],
            recent_len: 0,
        }
    }
}

impl Gain {
    /// The gain at which in-flight data is what the path carried at gain
    /// `permille` with `loss_ppm` lost: the gain times the share delivered.
    fn carried(permille: u64, loss_ppm: u64) -> u64 {
        permille * (1_000_000 - loss_ppm.min(1_000_000)) / 1_000_000
    }

    /// The loss share at gain `to`, in parts per million, if what the path
    /// lost at gain `from` was what its queue could not hold. The in-flight
    /// data the path carries is then the same at both gains.
    fn predicted_loss_ppm(from: u64, loss_ppm: u64, to: u64) -> u64 {
        let carried = from * (1_000_000 - loss_ppm.min(1_000_000));
        1_000_000u64.saturating_sub(carried / to.max(1))
    }

    fn restart(&mut self) {
        self.acked = 0;
        self.lost = 0;
        self.intervals = 0;
        self.limited = 0;
    }

    /// Counts the sample interval that has just closed, and judges the loss
    /// window when the interval completes one. `probing` is whether a probe is
    /// in progress, `app_limited` whether the interval was app-limited,
    /// `estimate` is the bandwidth estimate, and `packets` is
    /// [`WINDOW_PACKETS`] in bytes.
    fn on_interval(&mut self, probing: bool, app_limited: bool, estimate: u64, packets: u64) {
        if probing {
            self.settle = self.settle.max(SETTLE_INTERVALS);
            self.restart();
            return;
        }
        if self.settle > 0 {
            self.settle -= 1;
            self.restart();
            return;
        }
        self.intervals += 1;
        self.limited += u8::from(app_limited);
        let bytes = self.acked.saturating_add(self.lost);
        if self.intervals >= WINDOW_INTERVALS && bytes >= packets {
            let loss_ppm = u128::from(self.lost) * 1_000_000 / u128::from(bytes.max(1));
            let limited = self.limited * 2 > self.intervals;
            self.restart();
            let loss_ppm = u64::try_from(loss_ppm).unwrap_or(u64::MAX);
            self.on_window(loss_ppm, estimate, limited);
        } else if self.intervals >= WINDOW_MAX_INTERVALS {
            // A trial cannot be judged, and a later window would not measure
            // what it started from.
            self.restart();
            self.trial = None;
            self.recent_len = 0;
            self.hold = FIRST_HOLD;
            if self.permille < CWND_GAIN_PERMILLE {
                self.set(
                    CWND_GAIN_PERMILLE,
                    "too slow for a loss window",
                    0,
                    estimate,
                );
            }
        }
    }

    /// Sets the gain and writes one debug line. Off under the shipped
    /// `volto=info` filter.
    fn set(&mut self, permille: u64, why: &'static str, loss_ppm: u64, estimate: u64) {
        tracing::debug!(
            from_permille = self.permille,
            to_permille = permille,
            floor_permille = self.floor,
            loss_ppm,
            estimate_bytes_per_sec = estimate,
            reference_bytes_per_sec = self.reference,
            why,
            "bbr-capped gain"
        );
        if permille != self.permille {
            self.permille = permille;
            self.settle = SETTLE_INTERVALS;
            self.recent_len = 0;
        }
    }

    /// Judges the loss window that has just closed, with its loss share, the
    /// bandwidth estimate at its end, and whether more than half of its
    /// intervals were app-limited.
    fn on_window(&mut self, loss_ppm: u64, estimate: u64, limited: bool) {
        self.down_wait = self.down_wait.saturating_sub(1);
        if self.floor > GAIN_FLOOR_PERMILLE {
            self.floor_wait = self.floor_wait.saturating_sub(1);
            if self.floor_wait == 0 {
                self.floor = (self.floor - GAIN_STEP_UP_PERMILLE).max(GAIN_FLOOR_PERMILLE);
                self.floor_wait = MAX_WAIT;
            }
        }
        if self.permille < CWND_GAIN_PERMILLE {
            // The guard.
            if u128::from(estimate) * 100 < u128::from(self.reference) * GUARD_PERCENT {
                self.floor = (self.permille + GAIN_STEP_UP_PERMILLE).min(CWND_GAIN_PERMILLE);
                self.floor_wait = MAX_WAIT;
                self.trial = None;
                self.hold = FIRST_HOLD;
                self.refuse_lower();
                self.set(CWND_GAIN_PERMILLE, "the estimate fell", loss_ppm, estimate);
                return;
            }
            self.reference = self.reference.max(estimate);
        }
        if let Some(trial) = self.trial.take() {
            self.judge(trial, loss_ppm, estimate, limited);
            return;
        }
        self.recent.rotate_left(1);
        self.recent[TRIAL_WINDOWS - 1] = loss_ppm;
        self.recent_len = (self.recent_len + 1).min(TRIAL_WINDOWS);
        if !self.try_lower(estimate) && self.permille < CWND_GAIN_PERMILLE && !limited {
            self.up_wait = self.up_wait.saturating_sub(1);
            if self.up_wait == 0 {
                self.trial = Some(Trial {
                    from: self.permille,
                    loss_ppm,
                    lowest_ppm: 0,
                    windows: 0,
                    judged_ppm: 0,
                });
                let higher = (self.permille + GAIN_STEP_UP_PERMILLE).min(CWND_GAIN_PERMILLE);
                self.set(higher, "higher tried", loss_ppm, estimate);
            }
        }
    }

    /// Starts the wait after a refused lower gain and doubles the next one.
    fn refuse_lower(&mut self) {
        self.down_wait = self.backoff;
        self.backoff = (self.backoff * 2).min(MAX_WAIT);
    }

    /// Starts a trial of the gain the path carried, when the last
    /// [`TRIAL_WINDOWS`] windows at the present gain each lost something and
    /// together lost [`LOSS_TRIGGER_PPM`] or more, no wait is running, the path
    /// carried [`LEAST_CARRIED_PERMILLE`] or more and that gain is at least
    /// [`GAIN_MIN_STEP_PERMILLE`] lower. A window without loss cannot be
    /// beaten, so with one among them there is nothing to measure against.
    /// Returns whether it did.
    fn try_lower(&mut self, estimate: u64) -> bool {
        if self.down_wait > 0 || self.recent_len < TRIAL_WINDOWS {
            return false;
        }
        let lowest_ppm = self.recent.iter().copied().min().unwrap_or(0);
        let loss_ppm = self.recent.iter().sum::<u64>() / TRIAL_WINDOWS_U64;
        if lowest_ppm == 0 || loss_ppm < LOSS_TRIGGER_PPM {
            return false;
        }
        let carried = Self::carried(self.permille, loss_ppm);
        let target = carried.max(self.floor);
        if carried < LEAST_CARRIED_PERMILLE || target + GAIN_MIN_STEP_PERMILLE > self.permille {
            return false;
        }
        if self.permille == CWND_GAIN_PERMILLE {
            self.reference = estimate;
        }
        self.trial = Some(Trial {
            from: self.permille,
            loss_ppm,
            lowest_ppm,
            windows: 0,
            judged_ppm: 0,
        });
        self.set(target, "lower tried", loss_ppm, estimate);
        true
    }

    /// Judges a trial by the loss of one more window at the gain on trial.
    ///
    /// A lower gain is kept when, after [`TRIAL_SKIPPED_WINDOWS`] windows,
    /// each of the next [`TRIAL_WINDOWS`] lost less than the lowest of the
    /// windows before the trial, and their mean is at or under the middle
    /// between the loss before the trial and the loss the queue rule predicts.
    /// The first judged window that does not lose less ends the trial.
    ///
    /// A higher gain is judged in one window: the loss is on the queue's side
    /// when it is at or past that middle. A window that was mostly app-limited
    /// did not fill the queue, so it can refuse a higher gain and cannot keep
    /// one.
    fn judge(&mut self, trial: Trial, loss_ppm: u64, estimate: u64, limited: bool) {
        let predicted = Self::predicted_loss_ppm(trial.from, trial.loss_ppm, self.permille);
        let middle = (trial.loss_ppm + predicted) / 2;
        let windows = trial.windows + 1;
        if self.permille < trial.from {
            let judged = usize::from(windows.saturating_sub(TRIAL_SKIPPED_WINDOWS));
            let judged_ppm = trial.judged_ppm + loss_ppm;
            if judged == 0 {
                self.trial = Some(Trial { windows, ..trial });
            } else if loss_ppm >= trial.lowest_ppm
                || (judged == TRIAL_WINDOWS && judged_ppm > middle * TRIAL_WINDOWS_U64)
            {
                self.refuse_lower();
                self.set(trial.from, "lower refused", loss_ppm, estimate);
            } else if judged < TRIAL_WINDOWS {
                self.trial = Some(Trial {
                    windows,
                    judged_ppm,
                    ..trial
                });
            } else {
                self.backoff = FIRST_BACKOFF;
                self.up_wait = self.hold;
                self.set(self.permille, "lower kept", loss_ppm, estimate);
            }
        } else if loss_ppm >= middle {
            self.hold = (self.hold * 2).min(MAX_WAIT);
            self.up_wait = self.hold;
            self.set(trial.from, "higher refused", loss_ppm, estimate);
        } else if limited {
            self.trial = Some(trial);
        } else {
            self.up_wait = self.hold;
            self.set(self.permille, "higher kept", loss_ppm, estimate);
        }
        if self.permille == CWND_GAIN_PERMILLE && self.trial.is_none() {
            self.hold = FIRST_HOLD;
        }
    }
}

impl Controller for BbrCapped {
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.record_ack(now, sent, bytes, app_limited, rtt.get());
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        let sample = self.rate.on_end_acks(now, app_limited, self.srtt);
        if let Some(sample) = &sample {
            self.startup
                .on_interval(self.rate.max().unwrap_or(0), sample.app_limited);
            if self.startup.ended {
                self.slow_start = None;
                let estimate = self.rate.max().unwrap_or(0);
                let packets = WINDOW_PACKETS * self.mtu;
                let probing = self.probe.is_some();
                self.gain
                    .on_interval(probing, sample.app_limited, estimate, packets);
            } else {
                self.gain = Gain::default();
            }
            self.refresh();
        }
        if self.update_probe(now, in_flight) {
            self.refresh();
        }
        // The slow-start limit moved with the bytes this batch acknowledged.
        if self.update_recovery(now, in_flight) || self.slow_start.is_some() {
            self.refresh();
        }
        if let Some(sample) = &sample {
            self.trace(sample, in_flight);
        }
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.startup.congested = true;
        self.lost = self.lost.saturating_add(lost_bytes);
        self.gain.lost = self.gain.lost.saturating_add(lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu.into();
        self.refresh();
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        INITIAL_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// The delivery rate, measured once per round trip, and the largest of the
/// stored samples, each kept until a newer one is stored [`SAMPLES`] intervals
/// or more after it.
///
/// An interval starts at the end of one ACK batch and ends at the end of the
/// first batch at least one smoothed RTT later. One smoothed RTT rather than
/// the minimum, so that with a queue standing the interval still covers a whole
/// window of acknowledgements and averages out how the peer bunches them.
///
/// The sample is the bytes acknowledged in between, over the longer of two
/// times: the interval itself, and the send interval of the packets those bytes
/// belong to. The send interval runs from the earliest send time among the
/// packets acknowledged in the interval and the latest send time acknowledged
/// before it, to the latest send time acknowledged when it ends. The latest
/// send time only moves forward, so a packet acknowledged out of order does not
/// shorten the send interval. The earliest one moves back when a packet was
/// sent before the interval started, as it is when a peer acknowledges the
/// newest packet first and older ones later, so the send interval always covers
/// the bytes measured. ACKs that arrive bunched shorten the ACK interval but not
/// the send interval, so a sample is not higher than the rate at which its
/// packets were sent. The rule is ours, a simplified form of the one in the
/// delivery-rate estimation draft
/// (draft-cheng-iccrg-delivery-rate-estimation), which keeps these times per
/// packet. If nothing had been acknowledged before the interval started, the
/// send interval starts at the first packet acknowledged in it.
#[derive(Debug, Clone, Default)]
struct DeliveryRate {
    /// When the current interval started; `None` until the first ACK batch.
    started: Option<Instant>,
    /// Bytes acknowledged since `started`.
    bytes: u64,
    /// Whether any ACK in the current interval found the sender app-limited.
    app_limited: bool,
    /// The latest send time of any packet acknowledged so far.
    sent: Option<Instant>,
    /// The earliest send time among the packets acknowledged since the current
    /// interval started, or the latest send time acknowledged before it,
    /// whichever is earlier.
    earliest: Option<Instant>,
    /// Stored samples in bytes per second, oldest overwritten first; a slot
    /// holds zero where expiry cleared it.
    samples: [u64; SAMPLES],
    /// The interval count when each sample was stored.
    stored_at: [usize; SAMPLES],
    next: usize,
    /// How many intervals have closed.
    intervals: usize,
}

impl DeliveryRate {
    fn on_ack(&mut self, sent: Instant, bytes: u64, app_limited: bool) {
        self.bytes = self.bytes.saturating_add(bytes);
        self.app_limited |= app_limited;
        // The two send times of the type's doc.
        self.sent = self.sent.max(Some(sent));
        self.earliest = Some(self.earliest.map_or(sent, |earliest| earliest.min(sent)));
    }

    /// Ends the current interval if it has lasted `round`, and then returns
    /// its sample.
    fn on_end_acks(&mut self, now: Instant, app_limited: bool, round: Duration) -> Option<Sample> {
        self.app_limited |= app_limited;
        let Some(started) = self.started else {
            self.restart(now);
            return None;
        };
        let elapsed = now.saturating_duration_since(started);
        if elapsed.is_zero() || elapsed < round {
            return None;
        }
        // From the earliest packet acknowledged in the interval, or the latest
        // one acknowledged before it when that is earlier, to the latest one
        // acknowledged when the interval ends. Zero when none was acknowledged.
        let send_elapsed = match (self.earliest, self.sent) {
            (Some(first), Some(last)) => last.saturating_duration_since(first),
            _ => Duration::ZERO,
        };
        let ack_elapsed = elapsed;
        let elapsed = elapsed.max(send_elapsed);
        let rate = u128::from(self.bytes) * 1_000_000 / elapsed.as_micros().max(1);
        let sample = u64::try_from(rate).unwrap_or(u64::MAX);
        // An app-limited interval measures the application, not the path, so it
        // only counts when it is above the estimate. The rule is the one in the
        // BBR draft (draft-cardwell-iccrg-bbr-congestion-control) and in Linux
        // (`bbr_update_bw` in `net/ipv4/tcp_bbr.c`), which also take a sample
        // equal to the estimate. quinn's BBR never takes an app-limited sample.
        let stored = !self.app_limited || sample > self.max().unwrap_or(0);
        if stored {
            // A sample at least SAMPLES intervals old leaves the filter when a
            // newer one is stored, so the estimate holds while nothing is
            // stored. Linux's windowed max filter also expires samples only when
            // it is given a new one (`minmax_running_max` in
            // `lib/win_minmax.c`). A zero sample expires nothing, so expiry
            // alone never empties the estimate; ten stored zero samples still
            // do, through the ring.
            if sample > 0 {
                for (slot, &at) in self.samples.iter_mut().zip(&self.stored_at) {
                    if self.intervals.wrapping_sub(at) >= SAMPLES {
                        *slot = 0;
                    }
                }
            }
            self.samples[self.next] = sample;
            self.stored_at[self.next] = self.intervals;
            self.next = (self.next + 1) % SAMPLES;
        }
        self.intervals = self.intervals.wrapping_add(1);
        let sample = Sample {
            rate: sample,
            app_limited: self.app_limited,
            stored,
            ack_elapsed,
            send_elapsed,
        };
        self.restart(now);
        Some(sample)
    }

    fn restart(&mut self, now: Instant) {
        self.started = Some(now);
        self.earliest = self.sent;
        self.bytes = 0;
        self.app_limited = false;
    }

    /// The bandwidth estimate in bytes per second; `None` before any sample
    /// above zero.
    fn max(&self) -> Option<u64> {
        self.samples.iter().copied().max().filter(|&max| max > 0)
    }
}

/// One closed sample interval of [`DeliveryRate`].
#[derive(Debug, Clone, Copy)]
struct Sample {
    /// The delivery rate in bytes per second.
    rate: u64,
    /// Whether any ACK in the interval found the sender app-limited.
    app_limited: bool,
    /// Whether the sample went into the filter; an app-limited one below the
    /// estimate does not.
    stored: bool,
    /// The ACK interval.
    ack_elapsed: Duration,
    /// The send span of the acknowledged packets; zero when none was
    /// acknowledged or they were all sent at one time.
    send_elapsed: Duration,
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    const MIN_RTT: Duration = Duration::from_millis(60);
    /// The sample interval in these tests: one smoothed RTT.
    const SRTT: Duration = Duration::from_millis(100);
    /// [`INITIAL_WINDOW`], 200 packets of 1200 bytes, which is the floor of the
    /// cap outside a probe.
    const FLOOR: u64 = 240_000;
    /// The bandwidth estimate of [`estimated`], 120 Mbit/s.
    const BANDWIDTH: u64 = 15_000_000;

    impl BbrCapped {
        /// The stored window limit; `None` before there is a delivery-rate
        /// sample and a minimum RTT to compute it from.
        fn cap(&self) -> Option<u64> {
            self.cap
        }
    }

    /// The controller the default factory builds at `mtu`.
    fn build(mtu: u16) -> BbrCapped {
        *Arc::new(BbrCappedConfig)
            .build(Instant::now(), mtu)
            .into_any()
            .downcast::<BbrCapped>()
            .expect("the factory builds a BbrCapped")
    }

    /// A controller as the default factory builds it, still in its startup.
    fn starting() -> BbrCapped {
        build(1200)
    }

    /// [`starting`] with the startup ended, so that the cap is 1.25 times the
    /// bandwidth-delay product.
    fn capped() -> BbrCapped {
        let mut c = starting();
        c.startup.ended = true;
        c.slow_start = None;
        c
    }

    /// A controller whose bandwidth estimate is [`BANDWIDTH`] in every slot, so
    /// that the empty samples a test's batch ends add do not lower it, and
    /// whose minimum RTT is [`MIN_RTT`], taken at `t0`. Its cap is 1.125 MB.
    fn estimated(t0: Instant) -> BbrCapped {
        let mut c = capped();
        c.rate.samples = [BANDWIDTH; SAMPLES];
        ack(&mut c, t0, MIN_RTT, 0, false);
        c
    }

    /// An ACK at `at` of `bytes` sent `rtt` before it.
    fn ack(c: &mut BbrCapped, at: Instant, rtt: Duration, bytes: u64, app_limited: bool) {
        c.record_ack(at, at - rtt, bytes, app_limited, SRTT);
    }

    fn end_acks(c: &mut BbrCapped, at: Instant, app_limited: bool) {
        c.on_end_acks(at, 0, app_limited, None);
    }

    /// Runs one sample interval of `SRTT`, starting where the previous one
    /// ended, whose sample is `rate` bytes per second, and returns when it
    /// ended. `SRTT` is a tenth of a second, so the interval acknowledges a
    /// tenth of `rate`.
    fn interval(c: &mut BbrCapped, start: Instant, rate: u64, app_limited: bool) -> Instant {
        let end = start + SRTT;
        ack(c, end, MIN_RTT, rate / 10, app_limited);
        end_acks(c, end, app_limited);
        end
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// The estimate the gain tests use: 18 MB/s.
    const ESTIMATE: u64 = 18_000_000;

    /// [`WINDOW_PACKETS`] at an MTU of 1200, in bytes.
    const PACKETS: u64 = 2_400_000;

    /// A gain as a connection has it once its first intervals have settled.
    fn settled() -> Gain {
        Gain {
            settle: 0,
            ..Gain::default()
        }
    }

    /// A settled gain that has been lowered to `permille` and kept.
    fn lowered(permille: u64) -> Gain {
        Gain {
            permille,
            reference: ESTIMATE,
            ..settled()
        }
    }

    /// One sample interval that acknowledged and lost these bytes.
    fn gain_interval(g: &mut Gain, acked: u64, lost: u64) {
        g.acked += acked;
        g.lost += lost;
        g.on_interval(false, false, ESTIMATE, PACKETS);
    }

    #[test]
    fn the_divisor_of_the_trial_windows_is_their_count() {
        assert_eq!(u64::try_from(TRIAL_WINDOWS), Ok(TRIAL_WINDOWS_U64));
    }

    /// `n` loss windows that each lost `loss_ppm`.
    fn windows(g: &mut Gain, n: usize, loss_ppm: u64) {
        for _ in 0..n {
            g.on_window(loss_ppm, ESTIMATE, false);
        }
    }

    #[test]
    fn four_windows_that_lost_under_one_percent_leave_the_gain() {
        let mut g = settled();
        windows(&mut g, 4, 9_999);
        assert_eq!((g.permille, g.trial), (1250, None));
        windows(&mut g, 40, 9_999);
        assert_eq!((g.permille, g.trial), (1250, None));
    }

    #[test]
    fn four_windows_that_lost_one_percent_start_a_trial_of_the_gain_the_path_carried() {
        let mut g = settled();
        windows(&mut g, 3, 10_000);
        assert_eq!((g.permille, g.trial), (1250, None), "three are too few");
        windows(&mut g, 1, 10_000);
        assert_eq!(g.permille, 1237, "1250 x 0.99");

        let mut g = settled();
        for loss_ppm in [60_000, 100_000, 80_000, 80_000] {
            g.on_window(loss_ppm, ESTIMATE, false);
        }
        assert_eq!(g.permille, 1150, "1250 x 0.92, by the mean of the four");
        assert_eq!(
            g.trial,
            Some(Trial {
                from: 1250,
                loss_ppm: 80_000,
                lowest_ppm: 60_000,
                windows: 0,
                judged_ppm: 0
            })
        );
        assert_eq!(g.reference, ESTIMATE, "the guard's reference");
        assert_eq!(g.settle, SETTLE_INTERVALS, "a change of gain settles");
    }

    #[test]
    fn a_window_without_loss_among_the_four_starts_no_trial() {
        let mut g = settled();
        for loss_ppm in [80_000, 0, 80_000, 80_000] {
            g.on_window(loss_ppm, ESTIMATE, false);
        }
        assert_eq!((g.permille, g.trial), (1250, None), "6 percent together");
        windows(&mut g, 1, 80_000);
        assert_eq!(
            g.permille, 1250,
            "the window without loss is still one of the four"
        );
        windows(&mut g, 1, 80_000);
        assert_eq!(g.permille, 1150);
    }

    #[test]
    fn a_trial_never_goes_under_the_floor_and_never_moves_the_gain_by_under_a_hundredth() {
        let mut g = settled();
        windows(&mut g, 4, 200_000);
        assert_eq!(g.permille, 1050, "1250 x 0.8 is 1000, under the floor");

        let mut g = lowered(1060);
        windows(&mut g, 4, 50_000);
        assert_eq!(g.permille, 1050, "a step of 10 is tried");

        let mut g = lowered(1059);
        windows(&mut g, 4, 50_000);
        assert_eq!(g.permille, 1059, "a step of 9 is not");
        assert_eq!(g.trial, None);
        assert_eq!(
            g.up_wait,
            FIRST_HOLD - 4,
            "the windows count towards the hold"
        );

        let mut g = Gain {
            floor: 1200,
            floor_wait: MAX_WAIT,
            ..settled()
        };
        windows(&mut g, 4, 80_000);
        assert_eq!(g.permille, 1200, "a raised floor holds the trial up");
    }

    #[test]
    fn windows_that_lost_more_than_a_queue_can_start_no_trial() {
        let mut g = settled();
        windows(&mut g, 4, 280_001);
        assert_eq!(
            (g.permille, g.trial),
            (1250, None),
            "1250 x 0.719999 is 899"
        );
        windows(&mut g, 1, 280_000);
        assert_eq!(
            g.permille, 1050,
            "the mean, cut to a whole part per million, is 28 percent: 900, tried, at the floor"
        );

        let mut g = lowered(1100);
        windows(&mut g, 4, 190_000);
        assert_eq!((g.permille, g.trial), (1100, None), "1100 x 0.81 is 891");
    }

    #[test]
    fn a_lower_gain_is_kept_when_four_windows_lose_less_than_any_before_and_no_more_than_the_middle()
     {
        // 1250 at 8 percent carried 1150, so at 1150 the queue rule predicts no
        // loss and the middle is 4 percent.
        let mut g = settled();
        g.backoff = 64;
        windows(&mut g, 4, 80_000);
        windows(&mut g, 2, 300_000);
        assert_eq!(
            (g.permille, g.trial.map(|t| (t.windows, t.judged_ppm))),
            (1150, Some((2, 0))),
            "the first two windows are left out"
        );
        windows(&mut g, 3, 40_000);
        assert_eq!(g.trial.map(|t| t.windows), Some(5), "still on trial");
        windows(&mut g, 1, 40_000);
        assert_eq!(g.trial, None);
        assert_eq!(g.permille, 1150, "kept");
        assert_eq!(
            g.backoff, FIRST_BACKOFF,
            "a kept gain starts the backoff again"
        );
        assert_eq!(g.up_wait, FIRST_HOLD);
        assert_eq!(
            g.settle, SETTLE_INTERVALS,
            "set by the change, not by keeping it"
        );

        // The sum of the four one part per million above four times the middle.
        let mut g = settled();
        windows(&mut g, 4, 80_000);
        windows(&mut g, 5, 40_000);
        windows(&mut g, 1, 40_001);
        assert_eq!((g.permille, g.trial), (1250, None), "refused");

        // 1250 at 20 percent carried 1000. At the floor, 1050, the rule predicts
        // 1 - 1000/1050, 4.762 percent, and the middle is 12.381 percent.
        let mut g = settled();
        windows(&mut g, 4, 200_000);
        windows(&mut g, 6, 123_810);
        assert_eq!((g.trial, g.permille), (None, 1050));
    }

    #[test]
    fn a_lower_gain_is_refused_by_the_first_judged_window_that_does_not_lose_less() {
        let before = [50_000, 110_000, 80_000, 80_000];
        let tried = || {
            let mut g = settled();
            for loss_ppm in before {
                g.on_window(loss_ppm, ESTIMATE, false);
            }
            assert_eq!(g.permille, 1150);
            windows(&mut g, 2, 0);
            g
        };
        let mut g = tried();
        windows(&mut g, 1, 49_999);
        assert_eq!(g.permille, 1150, "under the lowest of the four: on trial");
        let mut g = tried();
        windows(&mut g, 1, 50_000);
        assert_eq!(
            (g.permille, g.trial),
            (1250, None),
            "the lowest of the four again: refused at once"
        );
        let mut g = tried();
        windows(&mut g, 3, 0);
        windows(&mut g, 1, 50_000);
        assert_eq!(
            (g.permille, g.trial),
            (1250, None),
            "the last one decides too"
        );
    }

    #[test]
    fn a_refused_lower_gain_waits_sixteen_windows_and_the_wait_doubles() {
        let mut g = settled();
        windows(&mut g, 4, 20_000);
        assert_eq!(g.permille, 1225, "1250 x 0.98");
        windows(&mut g, 2, 20_000);
        assert_eq!(g.permille, 1225, "left out");
        windows(&mut g, 1, 20_000);
        assert_eq!((g.permille, g.trial), (1250, None), "random loss: refused");
        assert_eq!((g.down_wait, g.backoff), (16, 32));
        assert_eq!(g.settle, SETTLE_INTERVALS);

        for _ in 0..15 {
            windows(&mut g, 1, 20_000);
            assert_eq!(g.permille, 1250, "no trial during the wait");
        }
        windows(&mut g, 1, 20_000);
        assert_eq!(g.permille, 1225, "the sixteenth window after the refusal");
        windows(&mut g, 3, 20_000);
        assert_eq!((g.permille, g.down_wait, g.backoff), (1250, 32, 64));

        g.backoff = MAX_WAIT;
        g.down_wait = 0;
        windows(&mut g, 4, 20_000);
        assert_eq!(g.permille, 1225, "the four windows since the refusal");
        windows(&mut g, 3, 20_000);
        assert_eq!((g.down_wait, g.backoff), (MAX_WAIT, MAX_WAIT));
    }

    #[test]
    fn a_lowered_gain_is_tried_one_step_higher_after_the_hold() {
        let mut g = lowered(1100);
        for _ in 0..15 {
            g.on_window(0, ESTIMATE, false);
            assert_eq!((g.permille, g.trial), (1100, None));
        }
        g.on_window(5_000, ESTIMATE, false);
        assert_eq!(g.permille, 1150);
        assert_eq!(
            g.trial,
            Some(Trial {
                from: 1100,
                loss_ppm: 5_000,
                lowest_ppm: 0,
                windows: 0,
                judged_ppm: 0
            })
        );

        let mut g = lowered(1225);
        g.up_wait = 1;
        g.on_window(0, ESTIMATE, false);
        assert_eq!(g.permille, 1250, "never above 1.25");

        let mut g = settled();
        for _ in 0..40 {
            g.on_window(0, ESTIMATE, false);
        }
        assert_eq!(
            (g.permille, g.trial, g.up_wait),
            (1250, None, FIRST_HOLD),
            "nothing to raise at 1.25"
        );
    }

    #[test]
    fn a_higher_gain_is_refused_when_the_loss_reaches_the_middle_and_the_hold_doubles() {
        // 1100 without loss carried 1100. At 1150 the rule predicts
        // 1 - 1100/1150, 4.3479 percent, and the middle is 2.1739 percent.
        let tried = || {
            let mut g = lowered(1100);
            g.up_wait = 1;
            g.on_window(0, ESTIMATE, false);
            g
        };
        let mut g = tried();
        g.on_window(21_739, ESTIMATE, false);
        assert_eq!(
            (g.permille, g.trial),
            (1100, None),
            "the queue is still short"
        );
        assert_eq!((g.hold, g.up_wait), (32, 32));

        let mut g = tried();
        g.on_window(21_738, ESTIMATE, false);
        assert_eq!((g.permille, g.trial), (1150, None), "kept");
        assert_eq!((g.hold, g.up_wait), (16, 16));

        let mut g = tried();
        g.hold = MAX_WAIT;
        g.on_window(21_739, ESTIMATE, false);
        assert_eq!((g.hold, g.up_wait), (MAX_WAIT, MAX_WAIT));
    }

    #[test]
    fn a_gain_back_at_the_top_starts_the_hold_again() {
        let mut g = lowered(1225);
        g.hold = 64;
        g.up_wait = 1;
        g.on_window(0, ESTIMATE, false);
        assert_eq!(g.permille, 1250);
        g.on_window(0, ESTIMATE, false);
        assert_eq!((g.trial, g.hold), (None, FIRST_HOLD));
    }

    #[test]
    fn a_lowered_gain_is_given_up_when_the_estimate_falls_under_three_quarters() {
        let mut g = lowered(1100);
        g.on_window(0, ESTIMATE + 4, false);
        assert_eq!(g.reference, ESTIMATE + 4, "the reference is the highest");
        g.on_window(0, 13_500_003, false);
        assert_eq!(g.permille, 1100, "exactly three quarters holds");
        g.on_window(0, 13_500_002, false);
        assert_eq!(g.permille, 1250, "given up");
        assert_eq!(g.floor, 1150, "no later trial goes that low");
        assert_eq!((g.down_wait, g.backoff), (16, 32));
        assert_eq!(g.hold, FIRST_HOLD);

        // The guard also ends a trial, and its floor never passes 1.25.
        let mut g = settled();
        windows(&mut g, 4, 20_000);
        g.on_window(0, ESTIMATE / 2, false);
        assert_eq!((g.permille, g.trial, g.floor), (1250, None, 1250));
        g.down_wait = 0;
        windows(&mut g, 4, 200_000);
        assert_eq!(g.permille, 1250, "with the floor at 1.25 nothing is tried");

        // At 1.25 there is no guard: the reference is taken when a trial starts.
        let mut g = Gain {
            reference: ESTIMATE,
            ..settled()
        };
        g.on_window(0, 1, false);
        assert_eq!((g.permille, g.floor), (1250, 1050));
        for _ in 0..4 {
            g.on_window(80_000, 1_000, false);
        }
        assert_eq!((g.permille, g.reference), (1150, 1_000));
    }

    #[test]
    fn a_loss_window_is_four_settled_intervals_and_2000_packets() {
        let mut g = Gain::default();
        for _ in 0..8 {
            gain_interval(&mut g, 0, 9_000_000);
            assert_eq!(g.permille, 1250, "eight intervals after a startup");
        }
        assert_eq!((g.acked, g.lost, g.intervals, g.settle), (0, 0, 0, 0));
        for _ in 0..3 {
            gain_interval(&mut g, 588_000, 12_000);
        }
        assert_eq!((g.permille, g.intervals), (1250, 3), "three intervals");
        gain_interval(&mut g, 588_000, 12_000);
        assert_eq!((g.acked, g.lost, g.intervals), (0, 0, 0), "a new window");
        assert_eq!(
            (g.recent_len, g.recent[TRIAL_WINDOWS - 1]),
            (1, 20_000),
            "2 percent of 2.4 MB lost"
        );
        for _ in 0..12 {
            gain_interval(&mut g, 588_000, 12_000);
        }
        assert_eq!(g.permille, 1225, "four such windows");

        let mut g = settled();
        for _ in 0..4 {
            gain_interval(&mut g, 480_000, 100_000);
        }
        assert_eq!(
            (g.permille, g.intervals),
            (1250, 4),
            "2.32 MB is under 2000 packets"
        );
        gain_interval(&mut g, 79_999, 0);
        assert_eq!(g.recent_len, 0, "one byte short");
        gain_interval(&mut g, 1, 0);
        assert_eq!(
            (g.recent_len, g.recent[TRIAL_WINDOWS - 1]),
            (1, 166_666),
            "0.4 MB of 2.4 MB lost"
        );
    }

    #[test]
    fn a_probe_leaves_its_intervals_and_the_two_after_it_out_of_the_loss_window() {
        let mut g = settled();
        for _ in 0..3 {
            gain_interval(&mut g, 600_000, 200_000);
        }
        g.acked += 600_000;
        g.lost += 200_000;
        g.on_interval(true, false, ESTIMATE, PACKETS);
        assert_eq!((g.permille, g.intervals, g.acked, g.lost), (1250, 0, 0, 0));
        assert_eq!(g.settle, SETTLE_INTERVALS);
        for _ in 0..5 {
            gain_interval(&mut g, 600_000, 200_000);
        }
        assert_eq!(g.recent_len, 0, "two settle intervals and three counted");
        gain_interval(&mut g, 600_000, 200_000);
        assert_eq!((g.recent_len, g.recent[TRIAL_WINDOWS - 1]), (1, 250_000));
    }

    #[test]
    fn a_connection_too_slow_for_a_loss_window_goes_back_to_the_top() {
        let mut g = lowered(1100);
        g.trial = Some(Trial {
            from: 1150,
            loss_ppm: 50_000,
            lowest_ppm: 40_000,
            windows: 3,
            judged_ppm: 0,
        });
        for _ in 0..31 {
            gain_interval(&mut g, 1_000, 1_000);
        }
        assert_eq!((g.permille, g.intervals), (1100, 31));
        gain_interval(&mut g, 1_000, 1_000);
        assert_eq!((g.permille, g.trial, g.intervals), (1250, None, 0));
        assert_eq!((g.acked, g.lost), (0, 0));

        let mut g = settled();
        for _ in 0..32 {
            gain_interval(&mut g, 1_000, 1_000);
        }
        assert_eq!(g, settled(), "at 1.25 the window is only dropped");

        // The windows before it are dropped as well: a later one would be
        // measured against a transfer that has ended.
        let mut g = settled();
        windows(&mut g, 3, 80_000);
        assert_eq!(g.recent_len, 3);
        for _ in 0..32 {
            gain_interval(&mut g, 1_000, 1_000);
        }
        assert_eq!((g.permille, g.recent_len), (1250, 0));
        windows(&mut g, 1, 80_000);
        assert_eq!((g.permille, g.trial), (1250, None));
    }

    /// A refused trial of 1.25 itself doubles the hold like any other.
    #[test]
    fn a_refused_trial_of_the_top_gain_doubles_the_hold() {
        let mut g = lowered(1225);
        g.hold = 64;
        g.up_wait = 1;
        g.on_window(0, ESTIMATE, false);
        assert_eq!(
            (g.permille, g.hold),
            (1250, 64),
            "on trial: the hold stands"
        );
        g.on_window(30_000, ESTIMATE, false);
        assert_eq!((g.permille, g.hold, g.up_wait), (1225, 128, 128));
    }

    #[test]
    fn a_connection_too_slow_for_a_loss_window_drops_a_trial_of_the_top_gain() {
        let mut g = lowered(1200);
        g.hold = 64;
        g.up_wait = 1;
        g.on_window(0, ESTIMATE, false);
        assert!(g.trial.is_some() && g.permille == 1250);
        g.settle = 0;
        for _ in 0..32 {
            gain_interval(&mut g, 1_000, 0);
        }
        assert_eq!((g.permille, g.trial, g.hold), (1250, None, FIRST_HOLD));
    }

    #[test]
    fn a_floor_the_guard_raised_comes_down_a_step_every_256_windows() {
        let mut g = lowered(1100);
        g.on_window(0, ESTIMATE / 2, false);
        assert_eq!((g.floor, g.floor_wait), (1150, MAX_WAIT));
        for _ in 0..255 {
            g.on_window(0, ESTIMATE, false);
        }
        assert_eq!(g.floor, 1150);
        g.on_window(0, ESTIMATE, false);
        assert_eq!((g.floor, g.floor_wait), (1100, MAX_WAIT));
        for _ in 0..256 {
            g.on_window(0, ESTIMATE, false);
        }
        assert_eq!(g.floor, 1050, "back at the lowest gain");
        for _ in 0..600 {
            g.on_window(0, ESTIMATE, false);
        }
        assert_eq!(g.floor, 1050, "and never under it");
        assert_eq!(g.permille, 1250);
    }

    #[test]
    fn a_mostly_app_limited_window_can_refuse_a_higher_gain_and_cannot_keep_one() {
        let mut g = lowered(1100);
        for _ in 0..40 {
            g.on_window(0, ESTIMATE, true);
        }
        assert_eq!(
            (g.permille, g.up_wait),
            (1100, FIRST_HOLD),
            "no count towards the hold"
        );

        g.up_wait = 1;
        g.on_window(0, ESTIMATE, false);
        assert_eq!(g.permille, 1150, "on trial");
        g.on_window(0, ESTIMATE, true);
        assert_eq!(g.permille, 1150);
        assert!(
            g.trial.is_some(),
            "not kept on a window that did not fill the queue"
        );
        g.on_window(21_739, ESTIMATE, true);
        assert_eq!((g.permille, g.trial), (1100, None), "refused all the same");

        // Lowering does not wait for a window that is not app-limited: behind
        // a short queue nearly half of all intervals are app-limited.
        let mut g = settled();
        for _ in 0..4 {
            g.on_window(80_000, ESTIMATE, true);
        }
        assert_eq!(g.permille, 1150);
        for _ in 0..6 {
            g.on_window(0, ESTIMATE, true);
        }
        assert_eq!((g.permille, g.trial), (1150, None), "kept");
    }

    #[test]
    fn a_loss_window_is_mostly_app_limited_when_over_half_of_its_intervals_are() {
        let run = |limited: u8| {
            let mut g = lowered(1100);
            g.up_wait = 1;
            for i in 0..4 {
                g.acked += 600_000;
                g.on_interval(false, i < limited, ESTIMATE, PACKETS);
            }
            g.permille
        };
        assert_eq!(run(2), 1150, "half: the window counts towards the hold");
        assert_eq!(run(3), 1100, "three of four: it does not");

        // A window that needs eight intervals for its packets.
        let long = |limited: u8| {
            let mut g = lowered(1100);
            g.up_wait = 1;
            for i in 0..8 {
                g.acked += 300_000;
                g.on_interval(false, i < limited, ESTIMATE, PACKETS);
            }
            g.permille
        };
        assert_eq!(long(4), 1150, "half of eight");
        assert_eq!(long(5), 1100, "five of eight");
    }

    #[test]
    fn a_probe_does_not_shorten_the_intervals_left_out_after_a_startup() {
        let mut g = Gain::default();
        gain_interval(&mut g, 0, 0);
        g.on_interval(true, false, ESTIMATE, PACKETS);
        assert_eq!(g.settle, 7);
        let mut g = settled();
        g.on_interval(true, false, ESTIMATE, PACKETS);
        assert_eq!(g.settle, SETTLE_INTERVALS);
    }

    /// The loss window's 2000 packets are packets of the current MTU.
    #[test]
    fn the_loss_window_counts_packets_of_the_current_mtu() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        c.mtu = 1400;
        c.gain = settled();
        end_acks(&mut c, t0, false);
        let mut t = t0;
        // 2000 packets of 1400 bytes are 2.8 MB. Each interval acknowledges
        // 0.65 MB and loses 0.05 MB, so the window closes with the fourth.
        for _ in 0..3 {
            c.on_congestion_event(t, t - MIN_RTT, false, 50_000);
            t = interval(&mut c, t, 6_500_000, false);
        }
        assert_eq!((c.gain.permille, c.gain.intervals), (1250, 3));
        c.on_congestion_event(t, t - MIN_RTT, false, 50_000);
        t = interval(&mut c, t, 6_500_000, false);
        assert_eq!(c.gain.recent_len, 1, "a window");
        for _ in 0..12 {
            c.on_congestion_event(t, t - MIN_RTT, false, 50_000);
            t = interval(&mut c, t, 6_500_000, false);
        }
        assert_eq!(c.gain.permille, 1160, "1250 x (1 - 0.2 / 2.8)");

        let mut c = estimated(t0);
        c.mtu = 1500;
        c.gain = settled();
        end_acks(&mut c, t, false);
        for _ in 0..4 {
            c.on_congestion_event(t, t - MIN_RTT, false, 50_000);
            t = interval(&mut c, t, 6_500_000, false);
        }
        assert_eq!(
            (c.gain.recent_len, c.gain.intervals),
            (0, 4),
            "2.8 MB is under 2000 packets of 1500"
        );
    }

    /// The controller feeds the loss windows from its ACKs and losses, and its
    /// cap follows the gain.
    #[test]
    fn the_stored_window_follows_the_steady_gain() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        c.mtu = 1200;
        c.gain = settled();
        end_acks(&mut c, t0, false);
        let mut t = t0;
        // Three loss windows of four intervals and three intervals of the
        // fourth.
        for _ in 0..15 {
            c.on_congestion_event(t, t - MIN_RTT, false, 125_000);
            t = interval(&mut c, t, BANDWIDTH, false);
            assert_eq!(c.cap(), Some(1_125_000), "1.25 x 15 MB/s x 60 ms");
        }
        c.on_congestion_event(t, t - MIN_RTT, false, 125_000);
        interval(&mut c, t, BANDWIDTH, false);
        // 125 kB lost for 1.5 MB acknowledged is 7.6923 percent.
        assert_eq!(c.gain.permille, 1153, "1250 x 0.923077");
        assert_eq!(c.cap(), Some(1_037_700), "1.153 x 15 MB/s x 60 ms");
    }

    #[test]
    fn the_gain_starts_again_when_the_startup_gain_returns() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        end_acks(&mut c, t0, false);
        c.gain = lowered(1100);
        c.gain.floor = 1150;
        let t = interval(&mut c, t0, BANDWIDTH, false);
        assert_eq!(c.gain.permille, 1100, "kept while the startup has ended");
        c.startup.ended = false;
        interval(&mut c, t, BANDWIDTH, false);
        assert_eq!(c.gain, Gain::default());
    }

    /// A probe's intervals count as probing for the gain as well.
    #[test]
    fn a_probe_restarts_the_controllers_loss_window() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        end_acks(&mut c, t0, false);
        c.gain.settle = 0;
        let t = interval(&mut c, t0, BANDWIDTH, false);
        assert_eq!(c.gain.intervals, 1);
        c.probe = Some(Probe {
            min: MIN_RTT,
            ends: None,
        });
        interval(&mut c, t, BANDWIDTH, false);
        assert_eq!((c.gain.intervals, c.gain.settle), (0, SETTLE_INTERVALS));
    }

    #[test]
    fn the_factory_starts_a_connection_in_its_startup_at_quinns_mtu() {
        let c = build(1300);
        assert_eq!(c.initial_window(), FLOOR);
        assert_eq!(c.window(), FLOOR);
        assert_eq!(c.mtu, 1300);
        assert!(!c.startup.ended, "a new connection starts in its startup");
        assert!(c.min_rtt.is_none() && c.probe.is_none() && c.rate.max().is_none());
        assert!(c.recovery.is_none());
    }

    /// The window is the cap, and outside a probe the cap is
    /// `max(gain x bandwidth-delay product, initial window)`.
    #[test]
    fn the_window_is_the_cap_and_the_cap_never_goes_below_the_initial_window() {
        // The bytes acknowledged and how long after the interval started, then
        // the cap and the window.
        for (bytes, after, cap, window, case) in [
            (
                1_500_000,
                SRTT - ms(1),
                None,
                FLOOR,
                "no sample yet, so no cap",
            ),
            (
                10_000,
                SRTT,
                Some(FLOOR),
                FLOOR,
                "1.25 x 100 kB/s x 60 ms is below the floor",
            ),
            (
                1_500_000,
                SRTT,
                Some(1_125_000),
                1_125_000,
                "1.25 x 15 MB/s x 60 ms",
            ),
        ] {
            let mut c = capped();
            let t0 = Instant::now();
            end_acks(&mut c, t0, false);
            ack(&mut c, t0 + after, MIN_RTT, bytes, false);
            end_acks(&mut c, t0 + after, false);

            assert_eq!(c.cap(), cap, "{case}");
            assert_eq!(c.window(), window, "{case}");
            let metrics = c.metrics();
            assert_eq!(metrics.congestion_window, window, "{case}");
            assert_eq!(
                metrics.pacing_rate, None,
                "{case}: quinn paces from the window"
            );
        }
    }

    /// Before the first sample there is no cap, and the window is the initial
    /// window however many bytes are acknowledged: it does not grow by them,
    /// and a loss during the startup does not lower it.
    #[test]
    fn before_the_first_sample_the_window_is_the_initial_window() {
        let mut c = starting();
        let t0 = Instant::now();
        end_acks(&mut c, t0, false);
        for n in 1..=9 {
            let at = t0 + ms(10 * n);
            ack(&mut c, at, MIN_RTT, 200_000, false);
            c.on_congestion_event(at, at - MIN_RTT, false, 1200);
            c.on_end_acks(at, 500_000, false, None);
            assert_eq!(c.cap(), None, "no interval has closed at {n}0 ms");
            assert_eq!(c.window(), FLOOR, "at {n}0 ms");
        }
        assert_eq!(c.min_rtt.map(|(min, _)| min), Some(MIN_RTT));

        ack(&mut c, t0 + SRTT, MIN_RTT, 200_000, false);
        end_acks(&mut c, t0 + SRTT, false);
        assert_eq!(c.cap(), Some(3_462_000), "2.885 x 20 MB/s x 60 ms");
        assert_eq!(
            c.window(),
            2_240_000,
            "the slow-start limit: 240 kB plus the 2 MB acknowledged"
        );
    }

    /// During the first startup the window follows the bytes acknowledged
    /// batch by batch, and the limit ends with that startup for good.
    #[test]
    fn the_slow_start_limit_moves_with_each_batch_and_ends_with_the_first_startup() {
        let t0 = Instant::now();
        let mut c = starting();
        c.rate.samples = [BANDWIDTH; SAMPLES];
        ack(&mut c, t0, MIN_RTT, 0, false);
        end_acks(&mut c, t0, false);
        assert_eq!(c.cap(), Some(2_596_500), "2.885 x 15 MB/s x 60 ms");
        assert_eq!(c.window(), FLOOR, "nothing acknowledged yet");

        // A batch that closes no sample interval still moves the limit.
        ack(&mut c, t0 + ms(10), MIN_RTT, 50_000, false);
        end_acks(&mut c, t0 + ms(10), false);
        assert_eq!(c.window(), FLOOR + 50_000);

        let mut t = t0 + ms(10);
        while !c.startup.ended {
            t = interval(&mut c, t, BANDWIDTH, false);
        }
        assert_eq!(c.slow_start, None);
        assert_eq!(Some(c.window()), c.cap(), "the cap alone after the startup");

        // The startup gain comes back; the limit does not.
        c.startup = Startup::default();
        c.refresh();
        assert_eq!(c.cap(), Some(2_596_500));
        assert_eq!(c.window(), 2_596_500);
    }

    #[test]
    fn a_sample_is_the_bytes_acked_over_one_round_trip_and_sets_the_cap() {
        let mut c = capped();
        let t0 = Instant::now();
        // Bytes acknowledged by the batch that opens the interval were delivered
        // before it, so they are not part of the sample.
        ack(&mut c, t0, MIN_RTT, 999_999, false);
        end_acks(&mut c, t0, false);
        ack(&mut c, t0 + ms(40), MIN_RTT, 1_000_000, false);
        end_acks(&mut c, t0 + ms(40), false);
        ack(&mut c, t0 + SRTT, MIN_RTT, 500_000, false);
        end_acks(&mut c, t0 + SRTT, false);

        assert_eq!(c.rate.max(), Some(15_000_000), "1.5 MB over 100 ms");
        assert_eq!(c.cap(), Some(1_125_000), "1.25 x 15 MB/s x 60 ms");
    }

    #[test]
    fn an_app_limited_round_can_raise_the_estimate_but_not_lower_it() {
        let mut c = capped();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 10_000_000, true);
        assert_eq!(
            c.rate.max(),
            Some(10_000_000),
            "the first sample raises it from none"
        );
        // Fill the other nine slots, so that one more sample would push the
        // 10 MB/s one out.
        for _ in 1..SAMPLES {
            t = interval(&mut c, t, 5_000_000, false);
        }

        // Either flag marks the round: one app-limited ACK, or the batch end.
        t += SRTT;
        ack(&mut c, t, MIN_RTT, 100_000, true);
        end_acks(&mut c, t, false);
        t += SRTT;
        ack(&mut c, t, MIN_RTT, 100_000, false);
        end_acks(&mut c, t, true);
        for _ in 0..SAMPLES {
            t = interval(&mut c, t, 1_000_000, true);
        }
        assert_eq!(
            c.rate.max(),
            Some(10_000_000),
            "lower app-limited samples are skipped, so they push nothing out"
        );

        interval(&mut c, t, 19_000_000, true);
        assert_eq!(c.rate.max(), Some(19_000_000), "a higher one counts");
    }

    #[test]
    fn an_ack_compressed_round_is_measured_over_the_time_its_packets_were_sent() {
        let mut c = capped();
        let t0 = Instant::now();
        // The path RTT has just fallen from 140 to 60 ms, so the ACKs for 1.8 MB
        // sent over 180 ms, from t0 - 140 ms to t0 + 40 ms, arrive within one
        // 100 ms round. Each packet's send time is its ACK time minus its RTT.
        ack(&mut c, t0, ms(140), 1_000_000, false);
        end_acks(&mut c, t0, false);
        ack(&mut c, t0 + ms(10), ms(110), 1_000_000, false);
        ack(&mut c, t0 + SRTT, ms(60), 700_000, false);
        // Acknowledged out of order: sent at t0 - 120 ms, before the latest
        // packet.
        ack(&mut c, t0 + SRTT, ms(220), 100_000, false);
        end_acks(&mut c, t0 + SRTT, false);
        assert_eq!(
            c.rate.max(),
            Some(10_000_000),
            "1.8 MB over the 180 ms they were sent in, not the 100 ms of ACKs"
        );

        // The next round's send time starts at the latest packet of this one,
        // t0 + 40 ms, and ends at t0 + 140 ms.
        ack(&mut c, t0 + ms(200), ms(60), 1_200_000, false);
        end_acks(&mut c, t0 + ms(200), false);
        assert_eq!(c.rate.max(), Some(12_000_000), "1.2 MB over 100 ms");

        // Sent in 100 ms, up to t0 + 240 ms, and acknowledged over 150 ms: the
        // ACK interval counts.
        ack(&mut c, t0 + ms(350), ms(110), 2_250_000, false);
        end_acks(&mut c, t0 + ms(350), false);
        assert_eq!(c.rate.max(), Some(15_000_000), "2.25 MB over 150 ms");
    }

    #[test]
    fn a_round_that_acknowledges_older_packets_is_measured_over_their_send_span() {
        let mut rate = DeliveryRate::default();
        let t0 = Instant::now();
        // The peer acknowledges only the newest packet, sent at t0 + 90 ms, in
        // the first interval, which closes at t0 + 100 ms.
        rate.on_end_acks(t0, false, SRTT);
        rate.on_ack(t0 + ms(90), 1_000_000, false);
        let first = rate
            .on_end_acks(t0 + SRTT, false, SRTT)
            .expect("the first interval closes");
        assert_eq!(first.rate, 10_000_000, "1 MB over the 100 ms ACK interval");

        // A smoothed RTT later the peer acknowledges older packets, sent at
        // t0 - 60 ms and t0 + 60 ms, so before the newest one. Their send span
        // is longer than the 100 ms ACK interval.
        rate.on_ack(t0 - ms(60), 1_000_000, false);
        rate.on_ack(t0 + ms(60), 1_000_000, false);
        let second = rate
            .on_end_acks(t0 + 2 * SRTT, false, SRTT)
            .expect("the second interval closes");

        assert_eq!(
            second.send_elapsed,
            ms(150),
            "from the earliest older packet to the latest send time seen"
        );
        assert_eq!(
            second.rate, 13_333_333,
            "2 MB over the 150 ms send span, not the 100 ms ACK interval"
        );
    }

    #[test]
    fn the_estimate_forgets_a_sample_after_ten_newer_ones() {
        let mut c = capped();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 30_000_000, false);
        for _ in 1..SAMPLES {
            t = interval(&mut c, t, 10_000_000, false);
        }
        assert_eq!(c.rate.max(), Some(30_000_000), "still within the last ten");

        interval(&mut c, t, 10_000_000, false);
        assert_eq!(c.rate.max(), Some(10_000_000));
        assert_eq!(c.cap(), Some(750_000), "1.25 x 10 MB/s x 60 ms");
    }

    #[test]
    fn a_sample_expires_ten_intervals_later_even_when_they_stored_nothing() {
        let mut c = capped();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 30_000_000, false);
        t = interval(&mut c, t, 12_000_000, false);
        for _ in 2..SAMPLES {
            t = interval(&mut c, t, 1_000_000, true);
        }
        assert_eq!(
            c.rate.max(),
            Some(30_000_000),
            "nothing was stored, so the estimate holds"
        );

        t = interval(&mut c, t, 10_000_000, false);
        assert_eq!(
            c.rate.max(),
            Some(12_000_000),
            "the next stored sample expires the one ten intervals old"
        );
        interval(&mut c, t, 10_000_000, false);
        assert_eq!(c.rate.max(), Some(10_000_000));
    }

    #[test]
    fn a_zero_sample_expires_nothing() {
        let mut c = capped();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 30_000_000, false);
        for _ in 1..SAMPLES {
            t = interval(&mut c, t, 1_000_000, true);
        }
        interval(&mut c, t, 0, false);
        assert_eq!(
            c.rate.max(),
            Some(30_000_000),
            "a zero sample ten intervals later keeps the estimate"
        );
        assert!(c.cap().is_some(), "the cap stays while the estimate holds");
    }

    #[test]
    fn a_cap_too_large_for_u64_saturates_instead_of_wrapping() {
        let mut c = capped();
        c.rate.samples[0] = u64::MAX;
        c.min_rtt = Some((Duration::from_secs(1), Instant::now()));
        c.refresh();

        assert_eq!(c.cap(), Some(u64::MAX));
        assert_eq!(c.window(), u64::MAX);
    }

    #[test]
    fn the_minimum_rtt_is_renewed_by_a_sample_at_or_below_it_and_expires_after_10_s() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        ack(&mut c, t0 + ms(1_000), ms(70), 0, false);
        assert_eq!(c.cap(), Some(1_125_000), "a higher sample leaves it");
        ack(&mut c, t0 + ms(4_998), ms(55), 0, false);
        ack(&mut c, t0 + ms(4_999), ms(55), 0, false);
        assert_eq!(c.cap(), Some(1_125_000), "two lower arrivals leave it");
        ack(&mut c, t0 + ms(5_000), ms(55), 0, false);
        assert_eq!(c.cap(), Some(1_031_250), "the third replaces it");
        ack(&mut c, t0 + ms(9_000), ms(55), 0, false);

        // The equal sample at 9 s renewed it, so 10 s after that it still holds.
        ack(&mut c, t0 + ms(19_000), ms(70), 0, false);
        assert!(c.probe.is_none());
        assert_eq!(c.cap(), Some(1_031_250));

        ack(&mut c, t0 + ms(19_001), ms(70), 0, false);
        assert!(
            c.probe.is_some(),
            "expired, so a higher sample starts a probe"
        );
        assert_eq!(
            c.min_rtt.map(|(min, _)| min),
            Some(ms(55)),
            "and is not taken"
        );
    }

    #[test]
    fn an_app_limited_ack_does_not_start_a_probe() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        ack(&mut c, t0 + ms(11_000), ms(90), 0, true);
        assert!(c.probe.is_none());
        assert_eq!(c.cap(), Some(1_125_000));

        ack(&mut c, t0 + ms(12_000), ms(90), 0, false);
        assert!(c.probe.is_some());
    }

    #[test]
    fn a_probe_holds_the_window_at_half_the_bdp_and_at_least_four_packets() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        ack(&mut c, t0 + ms(10_001), ms(120), 0, false);

        assert_eq!(c.cap(), Some(450_000), "15 MB/s x 60 ms / 2");

        c.rate.samples = [10_000; SAMPLES];
        c.refresh();
        assert_eq!(c.window(), 4 * 1200, "half of 600 bytes is less");
        c.on_mtu_update(1452);
        assert_eq!(c.window(), 4 * 1452);
    }

    #[test]
    fn a_probe_ends_200_ms_or_one_srtt_after_in_flight_falls_to_its_window() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        let t1 = t0 + ms(10_001);
        ack(&mut c, t1, ms(120), 0, false);

        c.on_end_acks(t1 + ms(5_000), 450_001, false, None);
        assert!(
            c.probe.as_ref().is_some_and(|p| p.ends.is_none()),
            "not drained yet"
        );
        let drained = t1 + ms(5_001);
        c.on_end_acks(drained, 450_000, false, None);
        c.on_end_acks(drained + ms(199), 0, false, None);
        assert_eq!(c.cap(), Some(450_000), "200 ms, since SRTT is 100 ms");
        c.on_end_acks(drained + ms(200), 0, false, None);
        assert!(c.probe.is_none());
        assert_eq!(c.cap(), Some(2_250_000), "1.25 x 15 MB/s x 120 ms");

        // With a smoothed RTT of 300 ms the probe lasts 300 ms.
        let mut c = estimated(t0);
        c.record_ack(t1, t1 - ms(120), 0, false, ms(300));
        c.on_end_acks(drained, 0, false, None);
        c.on_end_acks(drained + ms(299), 0, false, None);
        assert!(c.probe.is_some());
        c.on_end_acks(drained + ms(300), 0, false, None);
        assert!(c.probe.is_none());
    }

    #[test]
    fn the_new_minimum_is_the_third_lowest_arrival_of_the_probe_even_above_the_old_one() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        // The path RTT has risen from 60 to 150 ms.
        let t1 = t0 + ms(10_001);
        ack(&mut c, t1, ms(160), 0, false);
        ack(&mut c, t1 + ms(10), ms(150), 0, false);
        ack(&mut c, t1 + ms(20), ms(155), 0, false);
        end_acks(&mut c, t1 + ms(20), false);
        ack(&mut c, t1 + ms(100), ms(152), 0, false);
        assert_eq!(
            c.cap(),
            Some(450_000),
            "the probe window uses the old minimum"
        );
        end_acks(&mut c, t1 + ms(220), false);

        assert!(c.probe.is_none());
        assert_eq!(
            c.min_rtt,
            Some((ms(155), t1 + ms(220))),
            "of 160, 150, 155 and 152"
        );
        assert_eq!(c.cap(), Some(2_906_250), "1.25 x 15 MB/s x 155 ms");
    }

    #[test]
    fn a_probe_with_under_three_arrivals_takes_its_lowest_sample() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        let t1 = t0 + ms(10_001);
        ack(&mut c, t1, ms(160), 0, false);
        ack(&mut c, t1 + ms(10), ms(150), 0, false);
        end_acks(&mut c, t1 + ms(10), false);
        end_acks(&mut c, t1 + ms(210), false);
        assert!(c.probe.is_none());
        assert_eq!(c.min_rtt, Some((ms(150), t1 + ms(210))));
    }

    /// quinn hands every ACK of one endpoint poll the same `now`. A poll that
    /// was held up gives samples that are too short, all under that `now`.
    #[test]
    fn the_samples_of_one_arrival_time_do_not_lower_the_minimum() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        let held = t0 + ms(1_000);
        for rtt in [37, 38, 37, 39] {
            ack(&mut c, held, ms(rtt), 0, false);
        }
        assert_eq!(c.min_rtt, Some((MIN_RTT, t0)));
        assert_eq!(c.cap(), Some(1_125_000));
        // A second held-up poll within the second does not confirm it either.
        ack(&mut c, held + ms(500), ms(37), 0, false);
        assert_eq!(c.min_rtt, Some((MIN_RTT, t0)));
        // A sample at the minimum renews it and leaves the two waiting.
        ack(&mut c, held + ms(600), MIN_RTT, 0, false);
        assert_eq!(c.min_rtt, Some((MIN_RTT, held + ms(600))));
        assert_eq!(c.low.0.iter().flatten().count(), 2);
        // A third arrival exactly a second after the first confirms them.
        ack(&mut c, held + ms(1_000), ms(39), 0, false);
        assert_eq!(c.min_rtt, Some((ms(39), held + ms(1_000))));
    }

    #[test]
    fn a_lower_minimum_is_the_highest_of_three_arrivals_within_a_second() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        let t1 = t0 + ms(1_000);
        ack(&mut c, t1, ms(40), 0, false);
        ack(&mut c, t1, ms(38), 0, false);
        ack(&mut c, t1 + ms(5), ms(50), 0, false);
        assert_eq!(c.min_rtt, Some((MIN_RTT, t0)));
        ack(&mut c, t1 + ms(9), ms(45), 0, false);
        assert_eq!(
            c.min_rtt,
            Some((ms(50), t1 + ms(9))),
            "of 38, 50 and 45, each the lowest of its arrival"
        );
        assert_eq!(c.cap(), Some(937_500), "1.25 x 15 MB/s x 50 ms");
        assert_eq!(c.low, LowSamples::default(), "the next one starts again");

        // An arrival more than a second old no longer counts.
        let mut c = estimated(t0);
        ack(&mut c, t1, ms(40), 0, false);
        ack(&mut c, t1 + ms(500), ms(40), 0, false);
        ack(&mut c, t1 + ms(1_001), ms(40), 0, false);
        assert_eq!(c.min_rtt, Some((MIN_RTT, t0)));
        ack(&mut c, t1 + ms(1_400), ms(40), 0, false);
        assert_eq!(c.min_rtt, Some((ms(40), t1 + ms(1_400))));
    }

    #[test]
    fn samples_taken_during_a_probe_do_not_lower_the_estimate() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        let mut t = t0 + ms(10_001);
        ack(&mut c, t, ms(120), 0, false);
        assert!(c.probe.is_some());

        // In-flight data stays above the probe window, so the probe goes on,
        // and every interval delivers a tenth of the estimated rate without
        // finding the sender app-limited.
        for _ in 0..2 * SAMPLES {
            t += SRTT;
            ack(&mut c, t, MIN_RTT, 150_000, false);
            c.on_end_acks(t, 10_000_000, false, None);
        }
        assert!(
            c.probe.as_ref().is_some_and(|p| p.ends.is_none()),
            "still probing"
        );
        assert_eq!(c.rate.max(), Some(BANDWIDTH));

        // After the probe the same samples count.
        c.on_end_acks(t, 0, false, None);
        t += ms(200);
        c.on_end_acks(t, 0, false, None);
        assert!(c.probe.is_none());
        for _ in 0..SAMPLES {
            t = interval(&mut c, t, 1_500_000, false);
        }
        assert_eq!(c.rate.max(), Some(1_500_000));
    }

    #[test]
    fn a_new_connection_uses_the_startup_gain_until_three_samples_have_not_grown_by_a_quarter() {
        let mut c = starting();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 1_000_000, false);
        assert_eq!(c.cap(), Some(FLOOR), "2.885 x 60 kB is below the floor");
        for rate in [10_000_000, 20_000_000, 40_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert_eq!(c.cap(), Some(6_924_000), "2.885 x 40 MB/s x 60 ms");

        // Two samples below 1.25 x 40 MB/s, then one exactly at it.
        t = interval(&mut c, t, 49_000_000, false);
        t = interval(&mut c, t, 49_000_000, false);
        t = interval(&mut c, t, 50_000_000, false);
        assert!(!c.startup.ended, "a rise of exactly a quarter is growth");
        assert_eq!(c.cap(), Some(8_655_000), "2.885 x 50 MB/s x 60 ms");

        t = interval(&mut c, t, 62_000_000, false);
        t = interval(&mut c, t, 62_000_000, false);
        for _ in 0..SAMPLES {
            t = interval(&mut c, t, 1_000_000, true);
        }
        assert!(
            !c.startup.ended,
            "app-limited samples are not part of the test"
        );
        t = interval(&mut c, t, 62_000_000, false);
        assert!(c.startup.ended, "the third sample below 62.5 MB/s");
        assert_eq!(c.cap(), Some(4_650_000), "1.25 x 62 MB/s x 60 ms");

        interval(&mut c, t, 200_000_000, false);
        assert_eq!(
            c.cap(),
            Some(15_000_000),
            "growth does not bring the startup back"
        );
    }

    #[test]
    fn a_congestion_event_without_growth_ends_the_startup_even_when_app_limited() {
        let mut c = starting();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 10_000_000, false);

        c.on_congestion_event(t, t - MIN_RTT, false, 1200);
        t = interval(&mut c, t, 20_000_000, true);
        assert!(
            !c.startup.ended,
            "loss while the estimate grows by a quarter"
        );

        t = interval(&mut c, t, 20_000_000, false);
        assert!(
            !c.startup.ended,
            "the event belonged to the previous interval"
        );

        // An ECN mark arrives as a congestion event with no lost bytes.
        c.on_congestion_event(t, t - MIN_RTT, false, 0);
        interval(&mut c, t, 20_000_000, true);
        assert!(c.startup.ended);
        assert_eq!(c.cap(), Some(1_500_000), "1.25 x 20 MB/s x 60 ms");
    }

    /// A controller whose startup ended at 15 MB/s by three samples without
    /// growth, and whose estimate has since fallen to `rate` through ten
    /// intervals at that rate. Returns it and when its last interval ended.
    fn fallen_to(rate: u64) -> (BbrCapped, Instant) {
        let mut c = starting();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        for _ in 0..4 {
            t = interval(&mut c, t, BANDWIDTH, false);
        }
        assert!(c.startup.ended, "three samples without growth");
        for _ in 0..SAMPLES {
            t = interval(&mut c, t, rate, false);
        }
        assert_eq!(c.rate.max(), Some(rate));
        (c, t)
    }

    #[test]
    fn the_startup_gain_returns_after_three_rises_from_below_half_the_peak() {
        let (mut c, mut t) = fallen_to(2_000_000);
        t = interval(&mut c, t, 2_200_000, false);
        // An app-limited sample in the run neither counts nor breaks it.
        t = interval(&mut c, t, 1_000_000, true);
        t = interval(&mut c, t, 2_400_000, false);
        assert!(c.startup.ended, "two rises");
        assert_eq!(
            c.cap(),
            Some(240_000),
            "1.25 x 2.4 MB/s x 60 ms is below the floor"
        );

        t = interval(&mut c, t, 4_000_000, false);
        assert!(!c.startup.ended, "the third rise");
        assert_eq!(c.cap(), Some(692_400), "2.885 x 4 MB/s x 60 ms");

        // It ends by the rules of the first startup: three samples in a row
        // without a rise of a quarter since the estimate last grew.
        t = interval(&mut c, t, 10_000_000, false);
        for _ in 0..2 {
            t = interval(&mut c, t, 12_000_000, false);
        }
        assert!(!c.startup.ended, "10 MB/s grew, 12 MB/s twice did not");
        t = interval(&mut c, t, 12_000_000, false);
        assert!(c.startup.ended);
        assert_eq!(c.cap(), Some(900_000), "1.25 x 12 MB/s x 60 ms");

        // And it can return again after the next fall.
        for _ in 0..SAMPLES {
            t = interval(&mut c, t, 1_000_000, false);
        }
        for rate in [1_100_000, 1_200_000, 1_300_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(!c.startup.ended, "15 MB/s is still the peak");
    }

    #[test]
    fn the_startup_gain_does_not_return_without_a_fall_below_half_or_three_rises_in_a_row() {
        // From 8 MB/s, above half of the 15 MB/s peak, three rises.
        let (mut c, mut t) = fallen_to(8_000_000);
        for rate in [10_000_000, 12_500_000, 16_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(c.startup.ended, "the estimate had not fallen to half");

        // From 2 MB/s, a run of rises broken by a sample that does not raise
        // the estimate.
        let (mut c, mut t) = fallen_to(2_000_000);
        for rate in [3_000_000, 4_000_000, 3_900_000, 5_000_000, 6_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(c.startup.ended, "3.9 MB/s leaves the estimate at 4 MB/s");
        interval(&mut c, t, 7_000_000, false);
        assert!(
            !c.startup.ended,
            "5, 6 and 7 MB/s are three rises from below 7.5 MB/s"
        );

        // The rise has to start below half the peak, not at it.
        let (mut c, mut t) = fallen_to(6_000_000);
        for rate in [7_000_000, 7_500_000, 8_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(c.startup.ended, "the third rise starts at 7.5 MB/s");

        // App-limited samples alone never bring it back.
        let (mut c, mut t) = fallen_to(2_000_000);
        for rate in [3_000_000, 4_000_000, 5_000_000, 7_000_000] {
            t = interval(&mut c, t, rate, true);
        }
        assert!(c.startup.ended);
    }

    #[test]
    fn a_returned_startup_keeps_the_peak_and_the_last_estimate() {
        // The peak stays at 15 MB/s: after the returned startup has ended at
        // 5 MB/s, three rises below 7.5 MB/s bring it back again.
        let (mut c, mut t) = fallen_to(2_000_000);
        for rate in [3_000_000, 4_000_000, 5_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(!c.startup.ended);
        for _ in 0..3 {
            t = interval(&mut c, t, 5_000_000, false);
        }
        assert!(c.startup.ended, "three samples without growth");
        for rate in [5_500_000, 6_000_000, 6_500_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(!c.startup.ended, "15 MB/s is still the peak");

        // The last estimate is the one the startup returned at: when only an
        // app-limited interval follows before it ends, a sample that leaves
        // the estimate at 5 MB/s is not a rise.
        let (mut c, mut t) = fallen_to(2_000_000);
        for rate in [3_000_000, 4_000_000, 5_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        c.on_congestion_event(t, t - MIN_RTT, false, 1200);
        t = interval(&mut c, t, 5_000_000, true);
        assert!(c.startup.ended);
        for rate in [5_000_000, 5_500_000, 6_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(c.startup.ended, "two rises, not three");
    }

    #[test]
    fn a_congestion_event_without_growth_ends_a_returned_startup() {
        let (mut c, mut t) = fallen_to(2_000_000);
        for rate in [3_000_000, 4_000_000, 5_000_000] {
            t = interval(&mut c, t, rate, false);
        }
        assert!(!c.startup.ended);
        c.on_congestion_event(t, t - MIN_RTT, false, 1200);
        interval(&mut c, t, 5_500_000, true);
        assert!(c.startup.ended);
    }

    // The stored cap and window are refreshed at each change of an input. Each
    // test below changes one input and reads the stored window at once.

    #[test]
    fn the_stored_window_follows_each_new_estimate() {
        let mut c = capped();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        t = interval(&mut c, t, 10_000_000, false);
        assert_eq!(c.window(), 750_000, "1.25 x 10 MB/s x 60 ms");
        interval(&mut c, t, 20_000_000, false);
        assert_eq!(c.window(), 1_500_000, "1.25 x 20 MB/s x 60 ms");
    }

    #[test]
    fn the_stored_window_follows_the_end_of_the_startup() {
        let mut c = starting();
        let mut t = Instant::now();
        end_acks(&mut c, t, false);
        for _ in 0..3 {
            t = interval(&mut c, t, BANDWIDTH, false);
        }
        assert_eq!(c.window(), 2_596_500, "2.885 x 15 MB/s x 60 ms");
        interval(&mut c, t, BANDWIDTH, false);
        assert!(c.startup.ended, "the third sample without growth");
        assert_eq!(
            c.window(),
            1_125_000,
            "the same estimate at 1.25: 1.25 x 15 MB/s x 60 ms"
        );
    }

    #[test]
    fn the_stored_window_follows_a_lower_minimum_rtt() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        assert_eq!(c.window(), 1_125_000);
        for after in [10, 11, 12] {
            ack(&mut c, t0 + ms(after), ms(30), 0, false);
        }
        assert_eq!(c.window(), 562_500, "1.25 x 15 MB/s x 30 ms");
    }

    #[test]
    fn the_stored_window_follows_the_start_and_the_end_of_a_probe() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        let t1 = t0 + ms(10_001);
        ack(&mut c, t1, ms(120), 0, false);
        assert_eq!(c.window(), 450_000, "the probe starts: 15 MB/s x 60 ms / 2");

        c.on_end_acks(t1, 0, false, None);
        assert_eq!(c.window(), 450_000, "in-flight data has fallen to it");
        c.on_end_acks(t1 + ms(200), 0, false, None);
        assert!(c.probe.is_none());
        assert_eq!(
            c.window(),
            2_250_000,
            "the probe ends: 1.25 x 15 MB/s x 120 ms"
        );
    }

    #[test]
    fn the_stored_window_follows_the_mtu() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        c.rate.samples = [10_000; SAMPLES];
        ack(&mut c, t0 + ms(10_001), ms(120), 0, false);
        assert_eq!(c.window(), 4 * 1200, "a probe window of four packets");
        c.on_mtu_update(1452);
        assert_eq!(c.window(), 4 * 1452);
    }

    /// The recovery rule of the module documentation, batch by batch. The
    /// recovery begins at t1 + 5 ms, and the last loss is reported to the batch
    /// at t1 + 20 ms.
    #[test]
    fn a_loss_holds_in_flight_data_for_a_round_trip_and_then_lets_it_grow() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        let t1 = t0 + ms(1_000);
        // An ACK of `bytes` at t1 + `at` ms, of packets sent at t1 + `sent` ms,
        // then the end of the batch with `in_flight` bytes still in flight.
        let batch = |c: &mut BbrCapped, at: u64, sent: i64, bytes: u64, in_flight: u64| {
            let now = t1 + ms(at);
            let sent = if sent < 0 {
                t1 - ms(sent.unsigned_abs())
            } else {
                t1 + ms(sent.unsigned_abs())
            };
            c.record_ack(now, sent, bytes, false, SRTT);
            c.on_end_acks(now, in_flight, false, None);
        };

        c.on_congestion_event(t1, t1 - MIN_RTT, false, 100_000);
        assert_eq!(c.window(), 1_125_000, "a loss acts at the next batch");
        batch(&mut c, 5, -55, 50_000, 600_000);
        assert_eq!(c.window(), 650_000, "in-flight data plus the bytes acked");

        batch(&mut c, 10, -50, 50_000, 550_000);
        assert_eq!(
            c.window(),
            650_000,
            "acknowledged packets were sent before the recovery: no growth"
        );

        c.on_congestion_event(t1 + ms(15), t1 - ms(45), false, 30_000);
        batch(&mut c, 20, -40, 20_000, 500_000);
        assert_eq!(c.window(), 620_000, "a later loss takes its bytes off");

        batch(&mut c, 70, 10, 40_000, 500_000);
        assert_eq!(
            c.window(),
            660_000,
            "a packet sent after the recovery began: the bytes acked are added"
        );

        batch(&mut c, 80, 15, 10_000, 700_000);
        assert_eq!(
            c.window(),
            710_000,
            "the window never falls below in-flight data plus the bytes acked"
        );

        batch(&mut c, 85, 25, 10_000, 500_000);
        assert!(c.recovery.is_none(), "a packet sent after the last loss");
        assert_eq!(c.window(), 1_125_000, "back at the cap");
    }

    #[test]
    fn a_recovery_never_holds_the_window_below_four_packets() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        c.on_congestion_event(t0, t0 - MIN_RTT, false, 100_000);
        c.on_end_acks(t0 + ms(5), 0, false, None);
        assert_eq!(c.window(), 4 * 1200);
    }

    #[test]
    fn an_ecn_mark_starts_no_recovery() {
        let t0 = Instant::now();
        let mut c = estimated(t0);
        c.on_congestion_event(t0, t0 - MIN_RTT, false, 0);
        c.on_end_acks(t0 + ms(5), 100_000, false, None);
        assert!(c.recovery.is_none());
        assert_eq!(c.window(), 1_125_000);
    }

    /// A recovery that begins during the startup does not lower the window
    /// until the startup has ended, and then it does at once.
    #[test]
    fn a_recovery_limits_the_window_only_after_the_startup() {
        let t0 = Instant::now();
        let mut c = starting();
        c.rate.samples = [BANDWIDTH; SAMPLES];
        ack(&mut c, t0, MIN_RTT, 0, false);
        c.on_congestion_event(t0, t0 - MIN_RTT, false, 1200);
        let mut t = t0 + ms(5);
        ack(&mut c, t, MIN_RTT, 10_000, false);
        c.on_end_acks(t, 100_000, false, None);
        assert_eq!(c.recovery.map(|r| r.window), Some(110_000));
        assert_eq!(
            c.window(),
            250_000,
            "the slow-start limit, 240 kB plus 10 kB acknowledged, not the recovery window"
        );

        // The first interval grows the estimate from nothing; the second has a
        // congestion event and no growth, so it ends the startup.
        for _ in 0..2 {
            c.on_congestion_event(t, t - MIN_RTT, false, 1200);
            t += SRTT;
            ack(&mut c, t, MIN_RTT, 10_000, false);
            c.on_end_acks(t, 100_000, false, None);
        }
        assert!(c.startup.ended);
        assert_eq!(
            c.window(),
            127_600,
            "110 kB, then twice 1200 bytes lost and 10 kB acked"
        );
    }

    /// What a [`Shadowed`] controller saw on a real connection.
    #[derive(Debug, Default)]
    struct Shadow {
        acks: u64,
        /// Every point where the stored cap or window differed from a fresh
        /// computation, or the controller did not hold quinn's smoothed RTT.
        mismatches: Vec<String>,
        min_rtt: Option<Duration>,
        estimate: Option<u64>,
    }

    /// A [`BbrCapped`] that quinn drives, which is the one way to call
    /// [`Controller::on_ack`] with a real [`RttEstimator`], checked after every
    /// callback.
    #[derive(Debug, Clone)]
    struct Shadowed {
        capped: BbrCapped,
        shadow: Arc<Mutex<Shadow>>,
    }

    impl Shadowed {
        fn compare(&self, after: &str, srtt: Option<Duration>) {
            let mut shadow = self.shadow.lock().expect("the shadow lock");
            let mut fresh = self.capped.clone();
            fresh.refresh();
            let stored = (self.capped.cap, self.capped.window);
            // During the first startup the slow-start limit moves with each
            // ACK and the window is stored once per ACK batch, which is when
            // quinn reads it next.
            let between_batches = after == "on_ack" && self.capped.slow_start.is_some();
            if (fresh.cap, fresh.window) != stored && !between_batches {
                let computed = (fresh.cap, fresh.window);
                shadow.mismatches.push(format!(
                    "after {after}: stored {stored:?}, computed {computed:?}"
                ));
            }
            if let Some(srtt) = srtt
                && self.capped.srtt != srtt
            {
                let held = self.capped.srtt;
                shadow
                    .mismatches
                    .push(format!("after {after}: srtt {held:?}, quinn {srtt:?}"));
            }
            shadow.min_rtt = self.capped.min_rtt.map(|(min, _)| min);
            shadow.estimate = self.capped.rate.max();
        }
    }

    impl Controller for Shadowed {
        fn on_ack(
            &mut self,
            now: Instant,
            sent: Instant,
            bytes: u64,
            app_limited: bool,
            rtt: &RttEstimator,
        ) {
            self.capped.on_ack(now, sent, bytes, app_limited, rtt);
            self.shadow.lock().expect("the shadow lock").acks += 1;
            self.compare("on_ack", Some(rtt.get()));
        }

        fn on_end_acks(
            &mut self,
            now: Instant,
            in_flight: u64,
            app_limited: bool,
            largest_packet_num_acked: Option<u64>,
        ) {
            self.capped
                .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
            self.compare("on_end_acks", None);
        }

        fn on_congestion_event(
            &mut self,
            now: Instant,
            sent: Instant,
            is_persistent_congestion: bool,
            lost_bytes: u64,
        ) {
            self.capped
                .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
            self.compare("on_congestion_event", None);
        }

        fn on_mtu_update(&mut self, new_mtu: u16) {
            self.capped.on_mtu_update(new_mtu);
            self.compare("on_mtu_update", None);
        }

        fn window(&self) -> u64 {
            self.capped.window()
        }

        fn clone_box(&self) -> Box<dyn Controller> {
            Box::new(self.clone())
        }

        fn initial_window(&self) -> u64 {
            self.capped.initial_window()
        }

        fn into_any(self: Box<Self>) -> Box<dyn Any> {
            self
        }
    }

    #[derive(Debug)]
    struct ShadowedConfig(Arc<Mutex<Shadow>>);

    impl ControllerFactory for ShadowedConfig {
        fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
            Box::new(Shadowed {
                capped: build(current_mtu),
                shadow: self.0.clone(),
            })
        }
    }

    /// `on_ack` hands `record_ack` quinn's smoothed RTT, and the stored cap and
    /// window match a fresh computation after every callback: the server sends
    /// 8 MB over a real connection.
    #[tokio::test]
    async fn on_ack_records_quinns_smoothed_rtt_and_the_stored_window_stays_current() {
        const BYTES: usize = 8_000_000;
        let shadow = Arc::new(Mutex::new(Shadow::default()));
        let mut transport = quinn::TransportConfig::default();
        transport.congestion_controller_factory(Arc::new(ShadowedConfig(shadow.clone())));
        let (client, server) = crate::quic::tests::loopback_pair(transport).await;

        let write = async {
            let mut stream = server.open_uni().await.expect("open a stream");
            stream.write_all(&vec![0; BYTES]).await.expect("write");
            stream.finish().expect("finish");
            stream.stopped().await.expect("the peer reads to the end");
        };
        let read = async {
            let mut stream = client.accept_uni().await.expect("accept the stream");
            stream.read_to_end(BYTES).await.expect("read").len()
        };
        let ((), received) = tokio::join!(write, read);
        assert_eq!(received, BYTES);

        let shadow = shadow.lock().expect("the shadow lock");
        assert!(
            shadow.acks > 100,
            "only {} ACKs reached the controller",
            shadow.acks
        );
        assert_eq!(shadow.mismatches, Vec::<String>::new());
        assert!(
            shadow.min_rtt.is_some_and(|min| !min.is_zero()),
            "the RTT sample is now - sent: {:?}",
            shadow.min_rtt
        );
        assert!(shadow.estimate.is_some(), "on_ack fed the delivery rate");
    }
}
