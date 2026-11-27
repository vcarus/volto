//! The path's base loss: the share of packets it drops whatever the sender
//! sends, and the factor by which the window covers it. The reasoning and the
//! measurements behind every rule here are in D117. The rules are ours.
//!
//! quinn takes an acknowledged packet out of in-flight data one round trip
//! after it was sent, and a lost one only when it declares it lost, 1.25
//! round trips after it was sent ([`super::LOSS_TIME_THRESHOLD`], D116). With
//! a base loss p, a window of 1.25 times the bandwidth-delay product therefore
//! delivers 1.25 (1 - p) / (1 + 0.25 p) times the estimate. Above about one
//! sixth lost that is under one, each sample is lower than the estimate, and
//! the window falls to its floor however much the path carries. So outside the
//! startup and a probe the window is multiplied by (1 + t p) / (1 - p), where
//! t is the time threshold minus one and p is the base loss, at most
//! [`BOUND_PPM`].
//!
//! # Where the base loss is read
//!
//! Loss the sender causes by sending above a rate limit or a queue is not base
//! loss, and the window does not cover it. A window that grew with that loss
//! would grow without end at a limiter, because what it adds is lost and
//! covered again. So the base loss is read only where the sender's rate cannot
//! cause it: during a probe, whose window is half the estimated
//! bandwidth-delay product. The startup is no such place. It sends above the
//! path by design. Behind a buffer of under ten packets the probe's own
//! sending causes loss too, because quinn's pacer sends at least ten packets
//! at once and those bursts overflow such a buffer at any rate. This is a
//! known limit.
//!
//! A reading counts the bytes acknowledged and the bytes lost of the packets
//! sent from the moment in-flight data has fallen to the probe window until
//! the probe ends. quinn reports a loss detection pass as one congestion event
//! with the send time of the newest packet it found lost, so a pass counts
//! whole when that packet was sent in the span. The reading closes
//! [`CLOSE_RTTS`] smoothed RTTs after the probe ended, and the next probe waits
//! for it to close. [`Closed`] lists what a closed reading can come to.
//!
//! A probe that counted fewer than [`READING_PACKETS`] is not dropped: its
//! bytes are carried into the next probe's, and the reading completes at the
//! probe where the sum reaches them. A probe at half the window counts about
//! the estimate times 200 ms or one smoothed RTT, whichever is longer, over
//! 2 (1 + p / 4), so a sender at the 240 kB floor on an RTT of 200 ms or more
//! counts under 100 packets in one probe. A probe or a completed reading that
//! lost [`OUTAGE_PPM`] or more fell mostly into an outage and is dropped. A
//! partial outage in the only reading can still raise the base loss until the
//! next probe, and a probe can read the loss of an episode; that tail is
//! accepted. A probe during a change of path can read too much loss, because
//! quinn does not call `Controller::on_ack` while it validates a new path
//! (quinn-proto `src/connection/mod.rs`, `Connection::on_packet_acked`) and
//! still reports the losses. This is a known limit.
//!
//! The base loss is the lowest of the last [`READINGS`] readings. Loss that
//! comes in episodes is missing from some probes, and loss that is steady
//! shows in all of them. So a rise in the path's loss takes effect once every
//! kept reading has risen, which is up to four probes. A single reading acts:
//! waiting for a second one cost more than it saved. [`EMPTY_PROBES`] probes in
//! a row that complete no kept reading clear the kept readings and the carry.
//!
//! # A reading tests its own premise
//!
//! A probe is under the path's rate only if half the estimate is, and right
//! after a startup behind a policer with a large burst allowance it is not:
//! the allowance lets the startup measure several times the token rate. On a
//! path that delivers 1 - p of what is sent up to a limit, sending less makes
//! less arrive only under the limit. So the reading compares the arrival rate
//! of the packets sent while the probe held its window with the arrival rate
//! of the packets sent in the round trip before the probe was entered, counted
//! the same way by send time over the minimum RTT before entry, and is kept
//! only when the ratio is at most [`VERIFY_PPM`]. The minimum RTT is the
//! highest of three low arrivals within a second, so a single round trip can
//! be shorter than it by up to the spread of those arrivals, and a packet of
//! that round trip that was acknowledged before entry is missed. That lowers
//! the arrival rate before entry by the share missed and raises the ratio.
//!
//! A reading that fails is judged by what was sent in the two spans,
//! acknowledged and lost, counted the same way. When the probe did not lower
//! the sending to [`VERIFY_PPM`] of the round trip before it either, as when a
//! client holds the sender, it says nothing about the path
//! ([`Closed::Unverified`]). When it did lower the sending and the arrivals
//! stayed, the sender was above the path's rate even at the probe's, and a
//! base loss in force is what put it there or keeps it there
//! ([`Closed::Cleared`]). That inference is wrong in two cases, where a base
//! loss that was right is cleared until the next kept reading: a lossy path
//! behind a policer whose burst allowance is half a second to two seconds of
//! its rate, where the confirming probe falls above the limit; and an episode
//! or a partial outage in the round trip before a probe, which lowers the
//! arrivals before it. The two rules are kept for what they prevent at a
//! limit. A probe whose rate stays above a limit while the allowance that fed
//! the arrivals before it runs out inside it could pass; `line_sim` did not
//! reproduce that case.
//!
//! # The probes a reading needs
//!
//! [`Bbr`](super::Bbr) brings probes forward for the readings. The first
//! regular probe would come when the minimum RTT expires, 10 s after it was
//! last taken. So when a startup ends having lost [`EARLY_PROBE_PPM`] or more
//! of its bytes, and no reading is kept, the minimum RTT's lifetime is treated
//! as over, and the probe starts at the next ACK that does not find the sender
//! app-limited. Nothing else about the probe changes. After a startup that
//! lost that much, the path either drops a share of everything or the startup
//! overshot a limit, and only a reading below the path's rate tells the two
//! apart. Under that share the factor is under 1.07, and waiting costs little.
//!
//! While no reading is kept after such a startup, a probe whose reading closes
//! short makes the next one due at once, provided it counted at least a
//! quarter of [`READING_PACKETS`] and the bytes carried so far, its own
//! included, lost [`EARLY_PROBE_PPM`] or more. Four such probes complete a
//! reading, so the early probes are at most four. Under a quarter four probes
//! cannot complete a reading, and a short probe that lost less has shown that
//! the startup's loss was its own; either ends the repeat, and the bytes stay
//! carried for the regular probes. An unverified or a cleared reading ends it
//! too, because arrivals that did not fall mean that the startup's loss was a
//! limit's. On a path with a clean limit the rule therefore costs one probe
//! about a second into the connection: half the window for 200 ms or one
//! smoothed RTT.
//!
//! The first reading can be an episode's or an outage's. So a reading that
//! brings the base loss from zero to [`EARLY_PROBE_PPM`] or more acts at once
//! and is confirmed: a further probe is due ten sample intervals later, the
//! estimate's window, and its reading enters the lowest of four like any
//! other, or clears the base loss. This happens each time a reading takes the
//! base loss up from zero, so again after a clearing. A reading taken in an
//! outage or an episode then acts until that probe has closed, about thirteen
//! round trips, not until the next regular probe 10 s or more later. It costs
//! one probe and the lower of two readings.

use std::time::{Duration, Instant};

/// How many readings the base loss is the lowest of. Our own value.
pub(super) const READINGS: usize = 4;

/// The fewest packets of the current MTU a reading must have counted to be
/// kept. Our own value. A reading of 100 packets at a quarter lost has a
/// standard error of about 0.04.
pub(super) const READING_PACKETS: u64 = 100;

/// How many smoothed RTTs after the probe ended a reading closes. Our own
/// value. A packet sent just before the end is acknowledged one round trip
/// later or declared lost [`super::LOSS_DELAY_EXTRA_PERMILLE`] of a round
/// trip after that, and the second round trip leaves room for a queue.
const CLOSE_RTTS: u32 = 2;

/// After this many probes in a row that completed no kept reading, the kept
/// readings and the carried bytes are cleared and the base loss is zero until a
/// new reading. Our own value. On a path where four probes together count
/// under [`READING_PACKETS`], a base loss once read would otherwise last for
/// the whole connection.
const EMPTY_PROBES: u8 = 4;

/// The highest base loss the window covers, in parts per million: 40
/// percent, where the window is 1.83 times what it is without loss. Our own
/// value.
const BOUND_PPM: u64 = 400_000;

/// A reading of this share or more is dropped, in parts per million: 75
/// percent. Most of such a probe fell into an outage. Our own value. A reading
/// between [`BOUND_PPM`] and this is kept, and the base loss is held at the
/// bound where it is used: dropping every reading above the bound left a path
/// that drops 40 percent without any reading in one of three runs of
/// `line_sim`.
const OUTAGE_PPM: u64 = 750_000;

/// The highest ratio, in parts per million, of the probe's arrival rate to
/// the arrival rate of the round trip before it at which a reading is kept:
/// 0.75. Our own value. A probe at half the window that is under the path's
/// rate delivers about half of what the round trip before it delivered. A probe
/// still above a rate limit delivers as much, a ratio near 1, and its loss is
/// the sender's own.
const VERIFY_PPM: u64 = 750_000;

/// The share of its bytes a startup must have lost, in parts per million, for
/// the first probe to start when it ends rather than when the minimum RTT
/// expires: 5 percent. Our own value. Under it the factor the window would
/// take is under 1.07.
pub(super) const EARLY_PROBE_PPM: u64 = 50_000;

/// The loss share of `lost` bytes among `acked + lost`, in parts per million;
/// `None` when the two are fewer than `least` bytes.
fn share_ppm(acked: u64, lost: u64, least: u64) -> Option<u64> {
    let bytes = acked.saturating_add(lost);
    if bytes == 0 || bytes < least {
        return None;
    }
    u64::try_from(u128::from(lost) * 1_000_000 / u128::from(bytes)).ok()
}

/// The readings of the base loss and the one in progress; see the [module
/// documentation](super).
#[derive(Debug, Clone, Copy)]
pub(super) struct BaseLoss {
    /// The latest readings in parts per million, oldest overwritten first.
    readings: [u64; READINGS],
    /// How many of them there are.
    len: usize,
    next: usize,
    /// The reading in progress, if any.
    reading: Option<Reading>,
    /// The round trip before the probe of the reading in progress was
    /// entered, whose arrivals the probe's are compared with.
    before: Option<Reading>,
    /// Probes in a row that completed no kept reading.
    empty: u8,
    /// The bytes acknowledged and lost of the probes since the last completed
    /// reading that counted too few bytes, carried into the next one.
    carry: (u64, u64),
    /// [`BOUND_PPM`] in tests. With it at zero and `early` at `u64::MAX`,
    /// `line_sim` runs the controller as it was before the base loss was read.
    /// A build that is not a test has neither field and uses the constants.
    #[cfg(test)]
    pub(super) bound: u64,
    /// [`EARLY_PROBE_PPM`] in tests.
    #[cfg(test)]
    pub(super) early: u64,
}

impl Default for BaseLoss {
    fn default() -> Self {
        Self {
            readings: [0; READINGS],
            len: 0,
            next: 0,
            reading: None,
            before: None,
            empty: 0,
            carry: (0, 0),
            #[cfg(test)]
            bound: BOUND_PPM,
            #[cfg(test)]
            early: EARLY_PROBE_PPM,
        }
    }
}

/// What [`BaseLoss::close`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Closed {
    /// No reading was due to close.
    No,
    /// A reading completed and was kept. `ratio_ppm` is the probe's arrival
    /// rate over the arrival rate of the round trip before it. `share_ppm` is
    /// the loss share the reading itself read, with what was carried into it,
    /// which is not the base loss in force: that is the lowest of the kept
    /// readings.
    Kept { ratio_ppm: u64, share_ppm: u64 },
    /// The probe's bytes, `own` of them, are carried, because with the carry
    /// they are still too few for a reading. `lost_ppm` is the loss share of
    /// the carried bytes including this probe's. `cleared` when this was the
    /// [`EMPTY_PROBES`]-th probe in a row without a kept reading, which
    /// emptied the carry.
    Short {
        own: u64,
        lost_ppm: u64,
        ratio_ppm: u64,
        cleared: bool,
    },
    /// What arrived in the probe did not fall below [`VERIFY_PPM`] of what
    /// arrived in the round trip before it, or nothing arrived in that round
    /// trip, and neither did what was sent, so the probe was not under the
    /// path's rate and says nothing about it. Its bytes are dropped, not
    /// carried, and it does not count as a probe without a reading.
    /// `ratio_ppm` is `None` when nothing arrived before it, and `sent_ppm`
    /// is the same ratio of what was sent.
    Unverified {
        ratio_ppm: Option<u64>,
        sent_ppm: Option<u64>,
    },
    /// What was sent in the probe fell to [`VERIFY_PPM`] of what was sent in
    /// the round trip before it or less, and what arrived did not: the sender
    /// was above the path's rate even at the probe's. The kept readings and
    /// the carry are cleared, and the base loss is zero until a new reading.
    Cleared { ratio_ppm: u64, sent_ppm: u64 },
    /// The probe or the completed reading lost [`OUTAGE_PPM`] or more and was
    /// dropped. `cleared` as for `Short`.
    Dropped { cleared: bool },
}

/// The packets sent while a probe held its window.
#[derive(Debug, Clone, Copy)]
struct Reading {
    /// When in-flight data had fallen to the probe window.
    from: Instant,
    /// When the probe ended; `None` while it lasts.
    until: Option<Instant>,
    /// Bytes acknowledged of the packets sent in between.
    acked: u64,
    /// Bytes lost of the packets sent in between.
    lost: u64,
}

impl Reading {
    fn covers(&self, sent: Instant) -> bool {
        sent >= self.from && self.until.is_none_or(|until| sent < until)
    }
}

impl BaseLoss {
    /// The highest base loss the window covers: [`BOUND_PPM`].
    #[cfg(not(test))]
    pub(super) fn bound_ppm(&self) -> u64 {
        BOUND_PPM
    }

    /// The highest base loss the window covers: [`BOUND_PPM`] unless a test
    /// has set another value.
    #[cfg(test)]
    pub(super) fn bound_ppm(&self) -> u64 {
        self.bound
    }

    /// The startup loss from which the first probe starts early:
    /// [`EARLY_PROBE_PPM`].
    #[cfg(not(test))]
    pub(super) fn early_probe_ppm(&self) -> u64 {
        EARLY_PROBE_PPM
    }

    /// The startup loss from which the first probe starts early:
    /// [`EARLY_PROBE_PPM`] unless a test has set another value.
    #[cfg(test)]
    pub(super) fn early_probe_ppm(&self) -> u64 {
        self.early
    }

    /// Whether a reading is kept.
    pub(super) fn has_reading(&self) -> bool {
        self.len > 0
    }

    /// Whether the reading of the last probe has not closed yet. A new probe
    /// waits for it, since entering replaces the round trip it is compared
    /// with and beginning replaces the reading.
    pub(super) fn open(&self) -> bool {
        self.reading.is_some()
    }

    /// The base loss in parts per million: the lowest of the kept readings,
    /// at most [`BaseLoss::bound_ppm`], and zero before the first reading.
    pub(super) fn ppm(&self) -> u64 {
        self.readings[..self.len]
            .iter()
            .copied()
            .min()
            .unwrap_or(0)
            .min(self.bound_ppm())
    }

    /// Keeps a reading, in place of the oldest when there are
    /// [`READINGS`] already.
    ///
    /// A reading of [`OUTAGE_PPM`] or more is dropped. Returns whether the
    /// reading was kept.
    pub(super) fn push(&mut self, ppm: u64) -> bool {
        if ppm >= OUTAGE_PPM {
            return false;
        }
        self.readings[self.next] = ppm;
        self.next = (self.next + 1) % READINGS;
        self.len = (self.len + 1).min(READINGS);
        self.empty = 0;
        true
    }

    /// Opens, at `now` when a probe is entered, the span of the round trip
    /// before it, `span` long, whose packets are counted by send time as the
    /// reading's are. `span` is the minimum RTT, so that no packet sent in it
    /// can have been acknowledged before `now`.
    pub(super) fn enter(&mut self, now: Instant, span: Duration) {
        self.before = Some(Reading {
            from: now.checked_sub(span).unwrap_or(now),
            until: Some(now),
            acked: 0,
            lost: 0,
        });
    }

    /// Starts a reading at `now`, when in-flight data has fallen to the probe
    /// window.
    pub(super) fn begin(&mut self, now: Instant) {
        self.reading = Some(Reading {
            from: now,
            until: None,
            acked: 0,
            lost: 0,
        });
    }

    /// Stops counting packets sent from `now` on, when the probe ends.
    pub(super) fn end(&mut self, now: Instant) {
        if let Some(reading) = &mut self.reading {
            reading.until.get_or_insert(now);
        }
    }

    /// Counts an acknowledged packet sent at `sent`.
    pub(super) fn on_ack(&mut self, sent: Instant, bytes: u64) {
        if let Some(reading) = &mut self.reading
            && reading.covers(sent)
        {
            reading.acked = reading.acked.saturating_add(bytes);
        }
        if let Some(before) = &mut self.before
            && before.covers(sent)
        {
            before.acked = before.acked.saturating_add(bytes);
        }
    }

    /// Counts the bytes of a loss detection pass whose newest lost packet was
    /// sent at `sent`. quinn reports one pass as one congestion event with
    /// the send time of that packet alone (quinn-proto
    /// `src/connection/mod.rs`, `Connection::detect_lost_packets`), so the
    /// whole pass counts when that packet was sent while the probe held its
    /// window, or in the round trip before it.
    pub(super) fn on_loss(&mut self, sent: Instant, bytes: u64) {
        if let Some(reading) = &mut self.reading
            && reading.covers(sent)
        {
            reading.lost = reading.lost.saturating_add(bytes);
        }
        if let Some(before) = &mut self.before
            && before.covers(sent)
        {
            before.lost = before.lost.saturating_add(bytes);
        }
    }

    /// Closes the reading [`CLOSE_RTTS`] smoothed RTTs after the probe ended.
    /// A reading completes at `least` bytes. [`Closed`] lists the outcomes.
    pub(super) fn close(&mut self, now: Instant, srtt: Duration, least: u64) -> Closed {
        let Some(reading) = self.reading else {
            return Closed::No;
        };
        let Some(until) = reading.until else {
            return Closed::No;
        };
        if now < until + srtt * CLOSE_RTTS {
            return Closed::No;
        }
        self.reading = None;
        let before = self.before.take();
        let own = reading.acked.saturating_add(reading.lost);
        let outage = share_ppm(reading.acked, reading.lost, 1).is_some_and(|ppm| ppm >= OUTAGE_PPM);
        // What arrived of the packets sent in the probe, per time, over what
        // arrived of the packets sent in the round trip before it, per time;
        // and the same of what was sent, acknowledged and lost.
        let rate_ratio = |probe: u64, earlier: u64| {
            let before = before?;
            let before_len = before
                .until?
                .saturating_duration_since(before.from)
                .as_nanos();
            let probe_len = until.saturating_duration_since(reading.from).as_nanos();
            if earlier == 0 || probe_len == 0 {
                return None;
            }
            let ratio =
                u128::from(probe) * before_len * 1_000_000 / (probe_len * u128::from(earlier));
            u64::try_from(ratio).ok()
        };
        let ratio_ppm = rate_ratio(reading.acked, before.map_or(0, |b| b.acked));
        let sent_ppm = rate_ratio(own, before.map_or(0, |b| b.acked.saturating_add(b.lost)));
        let verified = ratio_ppm.is_some_and(|ratio| ratio <= VERIFY_PPM);
        if !outage && !verified {
            if let (Some(ratio_ppm), Some(sent_ppm)) = (ratio_ppm, sent_ppm)
                && sent_ppm <= VERIFY_PPM
            {
                self.len = 0;
                self.next = 0;
                self.empty = 0;
                self.carry = (0, 0);
                return Closed::Cleared {
                    ratio_ppm,
                    sent_ppm,
                };
            }
            return Closed::Unverified {
                ratio_ppm,
                sent_ppm,
            };
        }
        let ratio_ppm = ratio_ppm.unwrap_or(0);
        // The loss share of the carry when the probe is short.
        let short = if outage {
            None
        } else {
            let acked = self.carry.0.saturating_add(reading.acked);
            let lost = self.carry.1.saturating_add(reading.lost);
            match share_ppm(acked, lost, least) {
                Some(ppm) => {
                    self.carry = (0, 0);
                    if self.push(ppm) {
                        return Closed::Kept {
                            ratio_ppm,
                            share_ppm: ppm,
                        };
                    }
                    None
                }
                None => {
                    self.carry = (acked, lost);
                    Some(share_ppm(acked, lost, 1).unwrap_or(0))
                }
            }
        };
        self.empty = self.empty.saturating_add(1);
        let cleared = self.empty >= EMPTY_PROBES;
        if cleared {
            self.empty = 0;
            self.len = 0;
            self.next = 0;
            self.carry = (0, 0);
        }
        match short {
            Some(lost_ppm) => Closed::Short {
                own,
                lost_ppm,
                ratio_ppm,
                cleared,
            },
            None => Closed::Dropped { cleared },
        }
    }
}

#[cfg(test)]
impl BaseLoss {
    /// How many readings there are, where the next one goes, and the ring.
    pub(super) fn readings(&self) -> (usize, usize, [u64; READINGS]) {
        (self.len, self.next, self.readings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::congestion::test_support::{SRTT, ms};

    #[test]
    fn the_base_loss_is_the_lowest_of_the_last_four_readings() {
        let mut b = BaseLoss::default();
        assert_eq!(b.ppm(), 0, "no reading");
        for ppm in [200_000, 300_000, 250_000, 220_000] {
            b.push(ppm);
        }
        assert_eq!(b.ppm(), 200_000);
        b.push(260_000);
        assert_eq!(b.ppm(), 220_000, "the reading of 200 000 is the oldest");
        for _ in 0..READINGS {
            b.push(600_000);
        }
        assert_eq!(b.ppm(), BOUND_PPM, "kept, and held at the bound");
    }

    #[test]
    fn a_reading_counts_the_packets_sent_while_the_probe_held_its_window() {
        let t0 = Instant::now();
        let mut b = BaseLoss::default();
        // The round trip before the probe, from 110 to 10 ms before it.
        b.enter(t0 - ms(10), ms(100));
        b.on_ack(t0 - ms(50), 400_000);
        b.begin(t0);
        b.on_ack(t0 - ms(1), 1_000_000);
        b.on_loss(t0 - ms(1), 1_000_000);
        b.on_ack(t0, 150_000);
        b.on_loss(t0 + ms(10), 50_000);
        b.end(t0 + ms(200));
        b.on_ack(t0 + ms(199), 50_000);
        b.on_loss(t0 + ms(200), 1_000_000);
        assert_eq!(
            b.close(t0 + ms(399), SRTT, 120_000),
            Closed::No,
            "not two SRTT yet"
        );
        assert_eq!(
            b.close(t0 + ms(400), SRTT, 120_000),
            Closed::Kept {
                ratio_ppm: 250_000,
                share_ppm: 200_000
            },
            "1 MB/s arrived in the probe, 4 MB/s before it"
        );
        assert_eq!(b.ppm(), 200_000, "50 kB lost of 250 kB");
        b.on_loss(t0 + ms(100), 1_000_000);
        assert_eq!(b.ppm(), 200_000, "the reading is closed");
    }

    /// One probe entered at `t` after a round trip of 100 ms in which
    /// `before` bytes arrived, and held for 200 ms from 10 ms after it, in
    /// which `acked` bytes arrived and `lost` were lost; closed two smoothed
    /// RTTs after it ended, with readings of 120 kB. Returns what `close` did.
    fn probe_after(b: &mut BaseLoss, t: Instant, before: u64, acked: u64, lost: u64) -> Closed {
        b.enter(t, ms(100));
        b.on_ack(t - ms(50), before);
        b.begin(t + ms(10));
        b.on_ack(t + ms(10), acked);
        b.on_loss(t + ms(10), lost);
        b.end(t + ms(210));
        b.close(t + ms(410), SRTT, 120_000)
    }

    /// [`probe_after`] with as much arriving before the probe as in it, which
    /// is half the rate: a ratio of 0.5.
    fn probe(b: &mut BaseLoss, t: Instant, acked: u64, lost: u64) -> Closed {
        probe_after(b, t, acked, acked, lost)
    }

    #[test]
    fn a_reading_is_kept_only_when_what_arrived_fell_with_what_was_sent() {
        let t0 = Instant::now();
        let mut b = BaseLoss::default();
        assert_eq!(
            probe_after(&mut b, t0, 100_000, 150_000, 30_000),
            Closed::Kept {
                ratio_ppm: 750_000,
                share_ppm: 166_666
            },
            "0.75 MB/s arrived in the probe, 1 MB/s before it"
        );
        assert_eq!(b.ppm(), 166_666);
        let mut b = BaseLoss::default();
        assert_eq!(
            probe_after(&mut b, t0, 98_000, 150_000, 30_000),
            Closed::Unverified {
                ratio_ppm: Some(765_306),
                sent_ppm: Some(918_367)
            },
            "above 0.75: the probe was not under the path's rate"
        );
        assert!(!b.has_reading());
        assert_eq!(
            probe_after(&mut b, t0 + ms(1_000), 0, 150_000, 30_000),
            Closed::Unverified {
                ratio_ppm: None,
                sent_ppm: None
            },
            "nothing arrived before the probe"
        );
    }

    /// One probe as in [`probe_after`], with `before_lost` bytes lost of the
    /// round trip before it as well.
    fn probe_sent(
        b: &mut BaseLoss,
        t: Instant,
        before: (u64, u64),
        acked: u64,
        lost: u64,
    ) -> Closed {
        b.enter(t, ms(100));
        b.on_ack(t - ms(50), before.0);
        b.on_loss(t - ms(50), before.1);
        b.begin(t + ms(10));
        b.on_ack(t + ms(10), acked);
        b.on_loss(t + ms(10), lost);
        b.end(t + ms(210));
        b.close(t + ms(410), SRTT, 120_000)
    }

    #[test]
    fn a_probe_that_lowered_the_sending_but_not_the_arrivals_clears_the_base_loss() {
        let t0 = Instant::now();
        let mut b = BaseLoss::default();
        assert!(b.push(200_000));
        b.carry = (30_000, 3_000);
        // Before: 1 MB/s arrived of 1.25 MB/s sent. In the probe: 0.95 MB/s
        // arrived of 1 MB/s sent, a sending ratio of 0.8.
        assert_eq!(
            probe_sent(&mut b, t0, (100_000, 25_000), 190_000, 10_000),
            Closed::Unverified {
                ratio_ppm: Some(950_000),
                sent_ppm: Some(800_000)
            },
            "the sending did not fall to 0.75: it says nothing"
        );
        assert_eq!(b.ppm(), 200_000);
        assert_eq!(b.carry, (30_000, 3_000));
        // 0.9 MB/s arrived of 0.9 MB/s sent: a sending ratio of 0.72.
        assert_eq!(
            probe_sent(&mut b, t0 + ms(10_000), (100_000, 25_000), 180_000, 0),
            Closed::Cleared {
                ratio_ppm: 900_000,
                sent_ppm: 720_000
            },
            "the sending fell and the arrivals did not"
        );
        assert_eq!(b.ppm(), 0, "the readings are cleared");
        assert!(!b.has_reading());
        assert_eq!(b.carry, (0, 0), "and the carry");
        // Both fell: verified as before.
        assert!(matches!(
            probe_sent(&mut b, t0 + ms(20_000), (100_000, 25_000), 100_000, 50_000),
            Closed::Kept { .. }
        ));
    }

    #[test]
    fn an_unverified_reading_does_not_count_as_empty_and_is_not_carried() {
        let t0 = Instant::now();
        let mut b = BaseLoss::default();
        assert!(b.push(200_000));
        for i in 0..3 {
            probe(&mut b, t0 + ms(10_000 * i), 20_000, 0);
        }
        assert_eq!(b.carry, (60_000, 0));
        assert!(matches!(
            probe_after(&mut b, t0 + ms(30_000), 10_000, 20_000, 5_000),
            Closed::Unverified { .. }
        ));
        assert_eq!(b.carry, (60_000, 0), "not carried");
        assert_eq!(b.ppm(), 200_000, "not the fourth empty probe");
        assert!(matches!(
            probe(&mut b, t0 + ms(40_000), 20_000, 0),
            Closed::Short { cleared: true, .. }
        ));
        assert_eq!(b.ppm(), 0, "this one is");
    }

    #[test]
    fn a_reading_of_three_quarters_or_more_is_dropped_and_one_above_the_bound_is_held_at_it() {
        let t0 = Instant::now();
        let mut b = BaseLoss::default();
        assert_eq!(
            probe(&mut b, t0, 10_000, 990_000),
            Closed::Dropped { cleared: false },
            "an outage reads 0.99"
        );
        assert_eq!(b.ppm(), 0, "the base loss does not move");
        assert!(!b.push(750_000));
        assert!(b.push(749_999));
        assert_eq!(b.ppm(), BOUND_PPM, "a reading of 0.75 is used as 0.40");
        assert!(b.push(300_000));
        assert_eq!(b.ppm(), 300_000);
    }

    #[test]
    fn a_short_reading_is_carried_and_completes_at_the_next_probe() {
        let t0 = Instant::now();
        let mut b = BaseLoss::default();
        assert_eq!(
            probe(&mut b, t0, 100_000, 19_999),
            Closed::Short {
                own: 119_999,
                lost_ppm: 166_659,
                ratio_ppm: 500_000,
                cleared: false
            }
        );
        assert_eq!(b.ppm(), 0, "nothing kept yet");
        assert_eq!(
            probe(&mut b, t0 + ms(1_000), 50_000, 30_001),
            Closed::Kept {
                ratio_ppm: 500_000,
                share_ppm: 250_000
            }
        );
        assert_eq!(b.ppm(), 250_000, "50 kB lost of 200 kB over both probes");
        assert_eq!(b.carry, (0, 0), "the carry starts again");
    }

    /// The debug line of a reading prints its outcome, so this is what tells a
    /// reader what one probe read when an earlier, lower reading is in force.
    #[test]
    fn a_kept_reading_reports_its_own_share_and_not_the_base_loss_in_force() {
        let t0 = Instant::now();
        let mut b = BaseLoss::default();
        probe(&mut b, t0, 900_000, 100_000);
        assert_eq!(
            probe(&mut b, t0 + ms(10_000), 750_000, 250_000),
            Closed::Kept {
                ratio_ppm: 500_000,
                share_ppm: 250_000
            }
        );
        assert_eq!(b.ppm(), 100_000, "the lower of the two readings");
    }

    #[test]
    fn a_short_probe_that_lost_three_quarters_is_not_carried() {
        let t0 = Instant::now();
        let mut b = BaseLoss::default();
        assert!(matches!(probe(&mut b, t0, 60_000, 0), Closed::Short { .. }));
        assert_eq!(
            probe(&mut b, t0 + ms(1_000), 10_000, 40_000),
            Closed::Dropped { cleared: false },
            "80 percent of its own bytes"
        );
        assert_eq!(b.carry, (60_000, 0), "the carry is what it was");
        assert_eq!(
            probe(&mut b, t0 + ms(2_000), 60_000, 20_000),
            Closed::Kept {
                ratio_ppm: 500_000,
                share_ppm: 142_857
            }
        );
        assert_eq!(b.ppm(), 142_857, "20 kB lost of 140 kB, without the outage");
    }

    #[test]
    fn four_probes_in_a_row_without_a_kept_reading_clear_the_base_loss_and_the_carry() {
        let t0 = Instant::now();
        let mut b = BaseLoss::default();
        assert_eq!(
            probe(&mut b, t0, 800_000, 200_000),
            Closed::Kept {
                ratio_ppm: 500_000,
                share_ppm: 200_000
            }
        );
        assert_eq!(b.ppm(), 200_000);
        for i in 1..4 {
            assert!(matches!(
                probe(&mut b, t0 + ms(10_000 * i), 20_000, 0),
                Closed::Short { cleared: false, .. }
            ));
            assert_eq!(b.ppm(), 200_000, "after {i} short probes");
        }
        assert_eq!(
            probe(&mut b, t0 + ms(40_000), 20_000, 0),
            Closed::Short {
                own: 20_000,
                lost_ppm: 0,
                ratio_ppm: 500_000,
                cleared: true
            },
            "the fourth clears"
        );
        assert_eq!((b.ppm(), b.carry), (0, (0, 0)));
        assert!(
            matches!(
                probe(&mut b, t0 + ms(50_000), 100_000, 0),
                Closed::Short { .. }
            ),
            "100 kB alone, the 80 kB before it are gone"
        );

        // A kept reading starts the count again.
        let mut b = BaseLoss::default();
        assert!(b.push(200_000));
        for i in 0..3 {
            probe(&mut b, t0 + ms(10_000 * i), 20_000, 0);
        }
        assert_eq!(
            probe(&mut b, t0 + ms(30_000), 800_000, 200_000),
            // 200 kB lost of 1060 kB: the three short probes carried 60 kB.
            Closed::Kept {
                ratio_ppm: 500_000,
                share_ppm: 188_679
            }
        );
        for i in 4..7 {
            probe(&mut b, t0 + ms(10_000 * i), 20_000, 0);
        }
        assert_eq!(
            b.ppm(),
            188_679,
            "the kept reading took the 60 kB carried before it, 200 kB lost of 1.06 MB, \
             and three short probes since then clear nothing"
        );
    }
}
