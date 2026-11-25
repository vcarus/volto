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
/// Counted per sample interval, by its ACK interval. An interval counts when
/// no startup was in progress before it and no ACK in it found the sender
/// app-limited, which leaves out an interval with a probe in it, since a
/// probe's ACKs count as app-limited. quinn builds a new controller for a new
/// path, and the counts start again with it.
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
}

impl Record {
    /// Counts one interval that the type's rule lets in: it lasted `interval`,
    /// delivered `rate` bytes per second, closed with the window's limit at
    /// its floor or not, and lost nothing or something.
    pub(super) fn count(&mut self, interval: Duration, rate: u64, at_floor: bool, lossless: bool) {
        self.window_limited = self.window_limited.saturating_add(interval);
        if at_floor {
            self.floor = self.floor.saturating_add(interval);
            if lossless {
                self.floor_lossless = self.floor_lossless.saturating_add(interval);
            }
        }
        self.peak = self.peak.max(rate);
    }
}
