//! What a connection's close line reports of its controller.

use std::time::Duration;

/// What [`Bbr`](super::Bbr) has counted for the connection's close line.
///
/// A sender whose window is at its floor sends one floor window per round
/// trip, whatever the path carries. On a slow path that is right. It is wrong
/// on a path that carries more, and the controller can be held there: its
/// window is the estimate times the minimum RTT, and a packet stays in the
/// window for as long as it is in flight. When that is more than 1.25 minimum
/// RTTs, because the round trip has risen or because acknowledgements arrive
/// in clumps, the window carries less than the estimate, the estimate falls,
/// and at the floor the same condition keeps it there. In `line_sim` a clean
/// path that carries 150 Mbit/s delivers 17 to 26 when acknowledgements reach
/// the sender half a round trip apart or more, and loses nothing.
///
/// The two cases look alike from the sender, so these counts do not tell them
/// apart. They say how long a connection sat at the floor without loss while
/// it had more to send, and how fast it had been at its best, which is what a
/// reader needs to find the connections worth a closer look.
///
/// Four more readings come from the same intervals, each a mean over them.
/// The window's turnover is the quantity the fault above turns on: how many
/// minimum RTTs the window took to deliver its own size. The steady gain
/// allows 1.25 of them on a path without loss, and a window that takes more
/// delivers less than the estimate it was sized from. The time in flight of
/// the acknowledged bytes, also in minimum RTTs, is the part of the turnover
/// that is delay; the rest is a window that was not full. The base loss in
/// force and the steady gain say how much of the time the controller's two
/// adjustments of the window were at work.
///
/// Counted per sample interval, by its ACK interval. An interval counts when
/// no startup was in progress before it and no ACK in it found the sender
/// app-limited, which leaves out an interval with a probe in it, since a
/// probe's ACKs count as app-limited. quinn builds a new controller when the
/// peer's address changes, and the counts start again with it; after a change
/// of IPv4 port alone it keeps a copy of this one, and the counts go on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Record {
    /// The time in counted intervals: the window, and nothing before it, held
    /// the sender.
    pub window_limited: Duration,
    /// The part of `window_limited` in intervals that closed with the window's
    /// limit at its floor.
    pub floor: Duration,
    /// The part of `floor` in intervals that lost nothing.
    pub floor_lossless: Duration,
    /// The highest delivery rate of a counted interval, in bytes per second.
    pub peak: u64,
    /// The highest base loss in force when a counted interval closed, in
    /// parts per million.
    pub base_loss_peak: u64,
    /// The bytes acknowledged in counted intervals, and the sum over those
    /// bytes of their time in flight in per mille of the minimum RTT in force
    /// when their interval closed.
    pub(super) flight: (u64, u128),
    /// The sum over the same intervals of the window in bytes times the
    /// interval in per mille of the minimum RTT.
    pub(super) window_time: u128,
    /// The sum over counted intervals of the base loss in force, in parts per
    /// million, times the interval in microseconds.
    pub(super) base_loss: u128,
    /// The sum over counted intervals of the steady gain in per mille times
    /// the interval in microseconds.
    pub(super) gain: u128,
}

/// One sample interval that [`Record`]'s rule lets in.
#[derive(Debug, Clone, Copy)]
pub(super) struct Counted {
    /// The ACK interval.
    pub(super) length: Duration,
    /// The delivery rate in bytes per second.
    pub(super) rate: u64,
    /// Whether the window's limit was at its floor when the interval closed.
    pub(super) at_floor: bool,
    /// Whether nothing was lost in it.
    pub(super) lossless: bool,
    /// The window in force when it closed, in bytes.
    pub(super) window: u64,
    /// The bytes acknowledged in it and the sum of their times in flight, in
    /// byte-microseconds.
    pub(super) flight: (u64, u128),
    /// The minimum RTT in force when it closed.
    pub(super) min_rtt: Duration,
    /// The base loss in force when it closed, in parts per million.
    pub(super) base_loss_ppm: u64,
    /// The steady gain when it closed, in per mille.
    pub(super) gain_permille: u64,
}

impl Record {
    /// Counts one interval.
    pub(super) fn count(&mut self, interval: Counted) {
        self.window_limited = self.window_limited.saturating_add(interval.length);
        if interval.at_floor {
            self.floor = self.floor.saturating_add(interval.length);
            if interval.lossless {
                self.floor_lossless = self.floor_lossless.saturating_add(interval.length);
            }
        }
        self.peak = self.peak.max(interval.rate);
        self.base_loss_peak = self.base_loss_peak.max(interval.base_loss_ppm);
        let micros = interval.length.as_micros();
        self.base_loss = self
            .base_loss
            .saturating_add(u128::from(interval.base_loss_ppm) * micros);
        self.gain = self
            .gain
            .saturating_add(u128::from(interval.gain_permille) * micros);
        // Byte-microseconds over the minimum RTT's microseconds, in per mille:
        // the bytes times their mean time in flight in minimum RTTs.
        let (bytes, byte_micros) = interval.flight;
        let min_rtt = interval.min_rtt.as_micros();
        if let Some(in_min_rtts) = (byte_micros * 1000).checked_div(min_rtt) {
            self.flight.0 = self.flight.0.saturating_add(bytes);
            self.flight.1 = self.flight.1.saturating_add(in_min_rtts);
            self.window_time = self
                .window_time
                .saturating_add(u128::from(interval.window) * micros * 1000 / min_rtt);
        }
    }

    /// The mean time in flight of the bytes acknowledged in counted intervals,
    /// in per mille of the minimum RTT; `None` when none was acknowledged.
    pub fn flight_permille(&self) -> Option<u64> {
        let (bytes, sum) = self.flight;
        u64::try_from(sum.checked_div(u128::from(bytes))?).ok()
    }

    /// How many minimum RTTs the window took to deliver its own size over the
    /// counted intervals, in per mille: the window times the time, over the
    /// bytes acknowledged. `None` when none was acknowledged.
    pub fn turnover_permille(&self) -> Option<u64> {
        u64::try_from(self.window_time.checked_div(u128::from(self.flight.0))?).ok()
    }

    /// The mean base loss in force over the counted time, in parts per
    /// million; `None` when no interval was counted.
    pub fn base_loss_mean(&self) -> Option<u64> {
        u64::try_from(
            self.base_loss
                .checked_div(self.window_limited.as_micros())?,
        )
        .ok()
    }

    /// The highest base loss in force in a counted interval, in parts per
    /// million; `None` when no interval was counted.
    pub fn base_loss_highest(&self) -> Option<u64> {
        (!self.window_limited.is_zero()).then_some(self.base_loss_peak)
    }

    /// The mean steady gain over the counted time, in per mille; `None` when
    /// no interval was counted.
    pub fn gain_mean(&self) -> Option<u64> {
        u64::try_from(self.gain.checked_div(self.window_limited.as_micros())?).ok()
    }
}
