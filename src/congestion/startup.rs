//! BBR's full-bandwidth test, which ends the startup gain, the congestion
//! exit, and the rule that brings the startup back.

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
