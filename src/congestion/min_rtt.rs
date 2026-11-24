//! The confirmation of a lower minimum RTT, and the probe that measures it
//! again.

use std::time::{Duration, Instant};

/// How many ACK batches with different arrival times have to give an RTT sample
/// under the minimum before the minimum comes down, to the highest of their
/// lowest samples.
const MIN_RTT_CONFIRMATIONS: usize = 3;

/// The lowest RTT samples of up to [`MIN_RTT_CONFIRMATIONS`] arrival times.
///
/// quinn reads the clock once per endpoint poll and hands every ACK of that
/// poll the same `now` (quinn `EndpointDriver::poll`). A poll that is held up
/// between the clock read and the socket read, by the scheduler or by the host
/// of a virtual machine, gives samples that are too short by the delay, all
/// under one `now`. So one `now` counts once, and a minimum needs
/// [`MIN_RTT_CONFIRMATIONS`] of them.
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
