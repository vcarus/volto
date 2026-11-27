//! The confirmation of a lower minimum RTT, and the probe that measures it
//! again. [`Bbr`](super::Bbr) applies the rules below.
//!
//! The minimum RTT expires. quinn's `RttEstimator::min` never does within a
//! path, so with it a lasting RTT rise would leave the window below the new
//! bandwidth-delay product, each delivery-rate sample would come out lower
//! than the last, and the window would fall to its floor. Expiry alone would
//! not fix that. A minimum measured again with the standing queue in it would
//! raise the window, and with it the queue, each time. So the controller
//! empties the queue before it measures, the way BBR's ProbeRTT does.
//!
//! # A lower minimum
//!
//! A sample is the `now - sent` of an acknowledged packet. The peer's ACK
//! delay is part of it, which can only make it larger. The `now` can make it
//! smaller: quinn reads the clock once per endpoint poll and hands every ACK of
//! that poll the same value (quinn `EndpointDriver::poll`), so a poll that is
//! held up between the clock read and the socket read, by the scheduler or by
//! the host of a virtual machine, gives samples that are too short by the
//! delay. One such sample taken as the minimum holds the window under the
//! bandwidth-delay product for the 10 s it lasts, each delivery-rate sample
//! then comes out lower than the last, and nothing raises the estimate again
//! (D108). So the samples of one `now` count once. A sample under the minimum
//! lowers it when [`MIN_RTT_CONFIRMATIONS`] values of `now` within a second
//! have given one, and the new minimum is the highest of their lowest samples.
//! A fall in the path's RTT meets this with the third socket poll that reads
//! an ACK. A connection whose ACKs arrive less often than three polls in a
//! second keeps its minimum through such a fall; it sends too little for the
//! window to limit it, and the first bulk transfer confirms the lower minimum
//! at once. The rule is ours; BBR takes the plain minimum, under a window gain
//! of two that a short sample does not bring under the bandwidth-delay
//! product.
//!
//! # The probe
//!
//! A sample equal to the minimum restarts its 10 s lifetime, BBR's
//! MinRTTFilterLen. The first ACK after the lifetime ends that does not find
//! the sender app-limited starts a probe: the window is held at half the
//! estimated bandwidth-delay product, the target of BBRv2's ProbeRTT, and at
//! least four packets. Once in-flight data has fallen to that window, the
//! probe lasts 200 ms or one smoothed RTT, whichever is longer. The new
//! minimum is then taken from the samples since the probe started: the
//! highest of the lowest samples of the three values of `now` that gave the
//! lowest ones, without the limit of a second, or the lowest sample when the
//! probe saw fewer than three values of `now`. While the sender is app-limited
//! the probe does not start, because the window does not limit an app-limited
//! sender. Nor does it start while the base-loss reading of the previous probe
//! is still open. ACKs that arrive during a probe count as app-limited for the
//! delivery rate, so the probe's own low samples do not lower the estimate.
//! Linux BBR does the same during ProbeRTT (`bbr_update_min_rtt` in
//! `net/ipv4/tcp_bbr.c`).
//!
//! A lasting RTT rise therefore lowers throughput until the next probe, which
//! starts 10 s after the minimum was last taken, or later while the sender is
//! app-limited. By then the estimate has fallen to what the floor carries, so
//! once the probe has taken the new minimum, the climb back to the new
//! bandwidth-delay product brings the startup gain back. A fall in RTT takes
//! effect with the third arrival that shows it. Each probe holds the window
//! low for about a quarter of a second.

use std::time::{Duration, Instant};

/// How many ACK batches with different arrival times have to give an RTT sample
/// under the minimum before the minimum comes down, to the highest of their
/// lowest samples.
const MIN_RTT_CONFIRMATIONS: usize = 3;

/// The lowest RTT samples of up to [`MIN_RTT_CONFIRMATIONS`] arrival times.
/// One `now` counts once; the module documentation says why.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct LowSamples(pub(super) [Option<(Instant, Duration)>; MIN_RTT_CONFIRMATIONS]);

impl LowSamples {
    /// Takes a sample that arrived at `now`. Entries older than `lifetime` are
    /// dropped first. The lowest sample per `now` is kept, for the
    /// [`MIN_RTT_CONFIRMATIONS`] values of `now` whose lowest sample is lowest.
    pub(super) fn add(&mut self, now: Instant, rtt: Duration, lifetime: Option<Duration>) {
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
    pub(super) fn confirmed(&self) -> Option<Duration> {
        let mut highest = Duration::ZERO;
        for entry in &self.0 {
            highest = highest.max(entry.as_ref()?.1);
        }
        Some(highest)
    }
}

/// A probe that holds the window low to measure the minimum RTT again.
#[derive(Debug, Clone)]
pub(super) struct Probe {
    /// The lowest RTT sample since the probe started.
    pub(super) min: Duration,
    /// When the probe ends; `None` until in-flight data has fallen to the
    /// probe window.
    pub(super) ends: Option<Instant>,
}
