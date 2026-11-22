//! The `bbr` congestion controller: a window of 1.25 times the bandwidth-delay
//! product it measures.
//!
//! It is the default (D108). quinn's BBR as it ships is the value
//! `bbr-uncapped`. The type is named [`BbrCapped`], for the name it had when it
//! was a wrapper around quinn's BBR.
//!
//! quinn-proto 0.11's BBR estimates the bottleneck bandwidth several times too
//! high, so its window never limits in-flight data, and a bulk download loses
//! what the bottleneck queue cannot hold. This controller uses no part of
//! quinn's BBR. It measures its own delivery rate and minimum RTT, and its
//! window is computed from them alone (D108).
//!
//! The window is 1.25 times the delivery rate measured once per round trip
//! (see `DeliveryRate`) times the minimum RTT. It is never below the initial
//! window, 240 kB: 200 packets of 1200 bytes, the default initial window of
//! quinn's BBR (`BbrConfig`). So on a path whose bandwidth-delay product is
//! under 192 kB, the window can be 240 kB. Until there is a delivery-rate sample
//! and a minimum RTT, the window is the initial window.
//!
//! quinn paces from the window (quinn-proto `src/connection/pacing.rs`,
//! `Pacer::delay`, which adds 1.25 windows of tokens per smoothed RTT), so the
//! window also sets the pacing rate. In-flight data sits at the window, and a
//! quarter of a bandwidth-delay product stands in the bottleneck queue. 1.25 is
//! the highest pacing gain of BBR's ProbeBW cycle. BBR's window gain of two is a
//! ceiling above a sender that paces at the estimated rate. In quinn the window
//! is what the sender sends, so a gain of two keeps a whole bandwidth-delay
//! product queued and loses packets wherever the queue is shorter than that.
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
//! The minimum is the lowest `now - sent` of any acknowledged packet. The
//! peer's ACK delay is part of it, which can only make it larger. A sample at
//! or below the minimum replaces it and restarts its 10 s lifetime, BBR's
//! MinRTTFilterLen. The first ACK after the lifetime ends that does not find
//! the sender app-limited starts a probe: the window is held at half the
//! estimated bandwidth-delay product, the target of BBRv2's ProbeRTT, and at
//! least four packets. Once in-flight data has fallen to that window, the probe
//! lasts 200 ms or one smoothed RTT, whichever is longer. The lowest sample
//! seen since the probe started then becomes the new minimum. While the sender
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
//! effect with the first lower sample. Each probe holds the window low for
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
//! the minimum RTT, the probe, the startup, the recovery window and the MTU.
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
/// probe: 200 packets of 1200 bytes, the default initial window of quinn's BBR.
/// Held here so that the controller does not depend on quinn's BBR; a test
/// checks that the two still agree.
const INITIAL_WINDOW: u64 = 200 * 1200;

/// The window as a multiple of the estimated bandwidth-delay product, in per
/// mille, once the startup has ended.
const CWND_GAIN_PERMILLE: u128 = 1_250;

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

/// How long a minimum RTT holds without a sample at or below it before a probe
/// measures it again: BBR's MinRTTFilterLen.
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
            probe: None,
            srtt: Duration::ZERO,
            mtu: current_mtu.into(),
            acked: 0,
            lost: 0,
            recovery: None,
            cap: None,
            window: INITIAL_WINDOW,
        })
    }
}

/// A controller whose window is 1.25 times the measured bandwidth-delay
/// product. See the [module documentation](self).
#[derive(Debug, Clone)]
pub struct BbrCapped {
    rate: DeliveryRate,
    startup: Startup,
    /// The lowest RTT sample and when it was taken; `None` before the first ACK.
    min_rtt: Option<(Duration, Instant)>,
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
    /// What [`BbrCapped::compute_cap`] returned when an input last changed.
    cap: Option<u64>,
    /// What [`Controller::window`] returns: the cap, or the initial window
    /// while there is none, lowered to the recovery window after the startup.
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
        // A probe holds the window below the path's rate on purpose, so its ACKs
        // count as app-limited and its low samples do not lower the estimate.
        let probing = self.probe.is_some();
        self.rate.on_ack(sent, bytes, app_limited || probing);
        let rtt = now.saturating_duration_since(sent);
        if let Some(probe) = &mut self.probe {
            probe.min = probe.min.min(rtt);
            return;
        }
        match self.min_rtt {
            Some((min, at)) if rtt > min => {
                if !app_limited && now.saturating_duration_since(at) > MIN_RTT_LIFETIME {
                    self.probe = Some(Probe {
                        min: rtt,
                        ends: None,
                    });
                    self.refresh();
                }
            }
            // An equal sample only restarts the lifetime.
            Some((min, _)) if rtt == min => self.min_rtt = Some((rtt, now)),
            _ => {
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
                self.min_rtt = Some((probe.min, now));
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
            startup = !self.startup.ended,
            app_limited = sample.app_limited,
            stored = sample.stored,
            probing = self.probe.is_some(),
            "bbr-capped sample"
        );
    }

    /// The window limit, once there is a delivery-rate sample to compute it
    /// from: 1.25 times the bandwidth-delay product, the startup gain times it
    /// until the startup has ended, or half of it during a probe.
    ///
    /// Outside a probe the limit is never below [`INITIAL_WINDOW`], so a
    /// connection that has measured a low rate is never slower to send than a
    /// fresh one.
    fn compute_cap(&self) -> Option<u64> {
        let bandwidth = self.rate.max()?;
        let (min_rtt, _) = self.min_rtt?;
        let (gain_permille, floor) = match self.probe {
            None if self.startup.ended => (CWND_GAIN_PERMILLE, INITIAL_WINDOW),
            None => (STARTUP_GAIN_PERMILLE, INITIAL_WINDOW),
            Some(_) => (PROBE_GAIN_PERMILLE, MIN_WINDOW_PACKETS * self.mtu),
        };
        // Bytes per second times microseconds times per mille.
        let bytes = u128::from(bandwidth) * min_rtt.as_micros() * gain_permille / 1_000_000_000;
        Some(u64::try_from(bytes).unwrap_or(u64::MAX).max(floor))
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
            self.refresh();
        }
        if self.update_probe(now, in_flight) {
            self.refresh();
        }
        if self.update_recovery(now, in_flight) {
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

    /// The initial window is held here and not read from quinn's BBR, so this
    /// test is the one place that sees a change of quinn's default. It is the
    /// only use of `quinn::congestion::Bbr` in this module.
    #[test]
    fn the_initial_window_is_the_default_of_quinns_bbr() {
        let bbr =
            quinn::congestion::Bbr::new(Arc::new(quinn::congestion::BbrConfig::default()), 1200);
        assert_eq!(INITIAL_WINDOW, bbr.initial_window());
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
        assert_eq!(
            c.window(),
            3_462_000,
            "the first sample, 2 MB over 100 ms, sets 2.885 x 20 MB/s x 60 ms"
        );
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
        ack(&mut c, t0 + ms(5_000), ms(55), 0, false);
        assert_eq!(c.cap(), Some(1_031_250), "a lower one replaces it");
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
    fn the_new_minimum_is_the_lowest_sample_of_the_probe_even_above_the_old_one() {
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
        assert_eq!(c.min_rtt, Some((ms(150), t1 + ms(220))));
        assert_eq!(c.cap(), Some(2_812_500), "1.25 x 15 MB/s x 150 ms");
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
        ack(&mut c, t0 + ms(10), ms(30), 0, false);
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
        assert_eq!(c.window(), 2_596_500, "2.885 x 15 MB/s x 60 ms");

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
            if (fresh.cap, fresh.window) != stored {
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
