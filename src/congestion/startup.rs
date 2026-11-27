//! BBR's full-bandwidth test, which ends the startup gain, the congestion
//! exit, and the rule that brings the startup back.
//!
//! A new connection uses a higher gain until its estimate stops growing. With
//! the window at 1.25 times the estimate, each sample can only show the rate
//! that window allows, so the estimate grows by at most 1.25 times per sample.
//! The startup gain is BBR's Startup gain, 2/ln 2, about 2.89. The estimate
//! has stopped growing when [`SAMPLES_WITHOUT_GROWTH`] samples in a row from
//! intervals that were not app-limited have not raised it by
//! [`GROWTH_PERCENT`] since it last did. This is BBR's full-bandwidth test.
//!
//! A new connection also starts as slow start does. Until its first startup
//! has ended, the window is at most the initial window plus the bytes
//! acknowledged so far, so it doubles per round trip at most. The startup gain
//! alone would let the first samples open the window to 2.89 times a
//! bandwidth-delay product at once. The rule is ours. The limit does not come
//! back when the startup gain does.
//!
//! # The congestion exit
//!
//! A congestion event also ends the startup when the sample interval it falls
//! in does not raise the estimate by [`GROWTH_PERCENT`] and lost a share of its
//! bytes above 1.5 times the base loss, whether or not that interval was
//! app-limited. An ECN mark ends it in such an interval at any loss. With a
//! base loss of zero that is any lost byte. Either applies only once the
//! startup has counted [`super::base_loss::READING_PACKETS`] packets of the current MTU,
//! acknowledged and lost (D117). Before that count the startup has measured
//! nothing of the path: a handshake is a few packets per round trip,
//! app-limited, and one that lost a packet in each of two round trips ended the
//! startup on a dozen packets, so the connection never ran one. On a path that
//! drops a quarter of its packets such a start is common, and the connection
//! then sent at its floor until a regular probe. The count cannot let a first
//! startup overshoot: 100 packets are at most 147 kB, under the initial window,
//! and until the first startup has ended the window is at most the initial
//! window plus the bytes acknowledged, so within those packets the startup gain
//! sets nothing. A startup that returns counts again from zero, but its window
//! is never below the initial window and no recovery limits it, so it counts
//! 100 packets within its first sample interval unless the sender is held
//! under 100 packets in flight.
//!
//! Beyond the count, a first startup, which comes before the first probe, and
//! every startup on a path without base loss end on any lost byte in an
//! interval without growth. On a path with base loss, a startup that returns
//! would otherwise end at its first interval without growth, far below the
//! path's rate. quinn reports a sender blocked by the peer's flow control as
//! app-limited. Behind a flow-control window smaller than the startup window
//! the full-bandwidth test therefore never runs, and without the congestion
//! exit the startup gain would stay. On a path with base loss such a sender
//! keeps the startup gain until an interval loses more than 1.5 times the base
//! loss.
//!
//! # The startup's return
//!
//! The startup gain returns when the estimate climbs back after a fall. The
//! estimate keeps a sample for ten intervals, so a loss episode longer than
//! that leaves only samples from the episode in it, and the window starts
//! again from its floor. At 1.25 the estimate then grows by about 12 percent
//! per sample, not 25, because a raised window shows in the sample about two
//! round trips later. So [`RISES_TO_RESTART`] samples in a row from intervals
//! that were not app-limited, each raising the estimate from below
//! [`FALLEN_PERCENT`] of the highest estimate the connection has had, bring the
//! startup gain back, and the two rules above end it again. Any rise counts,
//! so a climb at 1.25 meets the rule within a few samples. The rule is ours.
//! The highest estimate does not expire, so on a path whose rate has fallen
//! for good, a later climb from below half of the old rate also uses the
//! startup gain, until the same two rules end it.

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
/// count as [`SAMPLES_WITHOUT_GROWTH`]; the rule is ours. Any rise counts; the
/// module documentation says why.
const RISES_TO_RESTART: u8 = 3;

/// The state of BBR's full-bandwidth test, which ends the startup gain, and
/// of the rule that brings it back after the estimate has fallen.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Startup {
    /// Whether the startup has ended. Cleared when the startup comes back.
    pub(super) ended: bool,
    /// The estimate when it last grew by [`GROWTH_PERCENT`].
    grown_to: u64,
    /// Samples since then that did not grow it.
    flat: u8,
    /// Whether a congestion event came in the current sample interval.
    congested: bool,
    /// Whether a congestion event that lost no bytes, an ECN mark, came in
    /// the current sample interval.
    marked: bool,
    /// Bytes acknowledged in the current sample interval.
    acked: u64,
    /// Bytes lost in the current sample interval.
    lost: u64,
    /// Bytes acknowledged and lost since the startup began, also after it has
    /// ended.
    total: (u64, u64),
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
    /// Counts acknowledged bytes in the current sample interval.
    pub(super) fn on_ack(&mut self, bytes: u64) {
        self.acked = self.acked.saturating_add(bytes);
    }

    /// Counts a congestion event and its lost bytes in the current sample
    /// interval. An event that lost no bytes is an ECN mark.
    pub(super) fn on_loss(&mut self, bytes: u64) {
        self.congested = true;
        self.marked |= bytes == 0;
        self.lost = self.lost.saturating_add(bytes);
    }

    /// Whether the current sample interval has lost no bytes so far. An ECN
    /// mark loses none.
    pub(super) fn lossless(&self) -> bool {
        self.lost == 0
    }

    /// Applies the test to the sample interval that has just closed, with the
    /// estimate after it. A congestion event in an interval without growth
    /// ends the startup when the interval lost more than `exit_above_ppm` of
    /// its bytes, or when it was an ECN mark, provided the startup has counted
    /// `least` bytes, acknowledged and lost, this interval's included.
    pub(super) fn on_interval(
        &mut self,
        estimate: u64,
        app_limited: bool,
        exit_above_ppm: u64,
        least: u64,
    ) {
        let congested = std::mem::take(&mut self.congested);
        let marked = std::mem::take(&mut self.marked);
        let acked = std::mem::take(&mut self.acked);
        let lost = std::mem::take(&mut self.lost);
        self.total = (
            self.total.0.saturating_add(acked),
            self.total.1.saturating_add(lost),
        );
        // Compared without rounding, so that with `exit_above_ppm` at zero any
        // lost byte is above it.
        let above = u128::from(lost) * 1_000_000
            > u128::from(exit_above_ppm) * u128::from(acked.saturating_add(lost));
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
        } else if (marked || (congested && above))
            && self.total.0.saturating_add(self.total.1) >= least
        {
            // The Startup loss exit of BBRv2 and BBRv3, in a form of our own:
            // one interval without growth that lost more than the base loss
            // explains is enough, once the startup has counted enough packets
            // to have measured something of the path.
            self.ended = true;
        } else if app_limited {
            // An app-limited interval is not part of the full-bandwidth test.
        } else {
            self.flat += 1;
            self.ended = self.flat >= SAMPLES_WITHOUT_GROWTH;
        }
    }

    /// The share of its bytes the startup has lost so far, in parts per
    /// million: lost over acknowledged plus lost.
    pub(super) fn lost_ppm(&self) -> u64 {
        let bytes = u128::from(self.total.0.saturating_add(self.total.1));
        u64::try_from(u128::from(self.total.1) * 1_000_000 / bytes.max(1)).unwrap_or(u64::MAX)
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
