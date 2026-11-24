//! The steady gain between 1.05 and 1.25, and the loss windows that move it.

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
pub(super) const WINDOW_PACKETS: u64 = 2_000;

/// After this many sample intervals a loss window that has not covered
/// [`WINDOW_PACKETS`] is dropped with any trial, and a lowered gain goes back
/// to 1.25: without loss windows the guard does not run and no trial is judged.
const WINDOW_MAX_INTERVALS: u8 = 32;

/// How many sample intervals after a change of gain or a probe are left out of
/// the loss windows. The packets acknowledged and lost in them were sent
/// before it.
pub(super) const SETTLE_INTERVALS: u8 = 2;

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

/// The steady gain and the rule that moves it; see the [module
/// documentation](super).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Gain {
    /// The steady gain in per mille, from [`GAIN_FLOOR_PERMILLE`] to
    /// [`CWND_GAIN_PERMILLE`].
    pub(super) permille: u64,
    /// The lowest gain a trial may set. Raised when the guard gives up a gain,
    /// and lowered again a step at a time.
    pub(super) floor: u64,
    /// Bytes acknowledged in the current loss window.
    pub(super) acked: u64,
    /// Bytes lost in the current loss window.
    pub(super) lost: u64,
    /// Sample intervals in the current loss window.
    pub(super) intervals: u8,
    /// How many of them were app-limited.
    limited: u8,
    /// Sample intervals still to leave out.
    pub(super) settle: u8,
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
    pub(super) recent_len: usize,
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
    pub(super) fn on_interval(
        &mut self,
        probing: bool,
        app_limited: bool,
        estimate: u64,
        packets: u64,
    ) {
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
            "bbr gain"
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

/// The estimate the gain tests use: 18 MB/s.
#[cfg(test)]
const ESTIMATE: u64 = 18_000_000;

/// A gain as a connection has it once its first intervals have settled.
#[cfg(test)]
pub(super) fn settled() -> Gain {
    Gain {
        settle: 0,
        ..Gain::default()
    }
}

/// A settled gain that has been lowered to `permille` and kept.
#[cfg(test)]
pub(super) fn lowered(permille: u64) -> Gain {
    Gain {
        permille,
        reference: ESTIMATE,
        ..settled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`WINDOW_PACKETS`] at an MTU of 1200, in bytes.
    const PACKETS: u64 = 2_400_000;

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
}
