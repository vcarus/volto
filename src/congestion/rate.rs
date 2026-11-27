//! The delivery rate, measured once per round trip, and its max filter.

use std::time::{Duration, Instant};

/// After how many sample intervals a stored delivery-rate sample can leave the
/// bandwidth estimate: the length of BBR's own bandwidth filter in round trips.
/// A sample interval lasts about one round trip. Every closed interval counts,
/// including one whose sample is not stored, and a sample leaves at the first
/// stored sample above zero that comes this many intervals or more after it.
/// While nothing is stored, the estimate does not change.
pub(super) const SAMPLES: usize = 10;

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
/// send interval starts at the earliest packet acknowledged in it.
#[derive(Debug, Clone, Default)]
pub(super) struct DeliveryRate {
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
    pub(super) samples: [u64; SAMPLES],
    /// The interval count when each sample was stored.
    stored_at: [usize; SAMPLES],
    next: usize,
    /// How many intervals have closed.
    intervals: usize,
}

impl DeliveryRate {
    pub(super) fn on_ack(&mut self, sent: Instant, bytes: u64, app_limited: bool) {
        self.bytes = self.bytes.saturating_add(bytes);
        self.app_limited |= app_limited;
        // The two send times of the type's doc.
        self.sent = self.sent.max(Some(sent));
        self.earliest = Some(self.earliest.map_or(sent, |earliest| earliest.min(sent)));
    }

    /// Ends the current interval if it has lasted `round`, and then returns
    /// its sample.
    pub(super) fn on_end_acks(
        &mut self,
        now: Instant,
        app_limited: bool,
        round: Duration,
    ) -> Option<Sample> {
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
    pub(super) fn max(&self) -> Option<u64> {
        self.samples.iter().copied().max().filter(|&max| max > 0)
    }

    /// Whether a packet sent after `at` has been acknowledged.
    pub(super) fn acked_sent_after(&self, at: Instant) -> bool {
        self.sent.is_some_and(|sent| sent > at)
    }
}

/// One closed sample interval of [`DeliveryRate`].
#[derive(Debug, Clone, Copy)]
pub(super) struct Sample {
    /// The delivery rate in bytes per second.
    pub(super) rate: u64,
    /// Whether any ACK in the interval found the sender app-limited.
    pub(super) app_limited: bool,
    /// Whether the sample went into the filter; an app-limited one below the
    /// estimate does not.
    pub(super) stored: bool,
    /// The ACK interval.
    pub(super) ack_elapsed: Duration,
    /// The send span of the acknowledged packets; zero when none was
    /// acknowledged or they were all sent at one time.
    pub(super) send_elapsed: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::congestion::test_support::{SRTT, ms};

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
}
