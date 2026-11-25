//! The QUIC datagram path of a UDP session: sending each target packet as a
//! QUIC datagram, and grading the two per-packet conditions it can meet.

use tracing::{debug, info};

use super::block::PacketBlock;
use crate::tunnel::Context;

/// The QUIC datagram half of a session's target -> client direction.
///
/// Holds what sending a packet as a QUIC datagram needs to remember between
/// packets, so that a packet that fits takes one acquisition of the
/// connection's lock, the one inside `send_datagram`. Asking for the size limit
/// and for the room in the send queue on every packet would take two more.
pub(super) struct DatagramPath {
    stream_id: u64,
    quarter_stream_id: u64,
    /// The largest datagram quinn allowed when it was last asked.
    ///
    /// It moves with the path MTU: discovery raises it and black-hole
    /// detection lowers it. A packet over this reading is held against a fresh
    /// one before it is dropped. A packet under it that meets a lower limit
    /// inside quinn comes back as `SendDatagramError::TooLarge`, the same
    /// `len > limit` comparison, and is dropped and reported the same way.
    limit: usize,
    /// How many oversized drops this session has had, on a doubling schedule.
    ///
    /// The drops themselves are per packet and can arrive at line rate, so a
    /// line each would be the flood [`crate::logfmt::Sampler`] exists to stop;
    /// see [`grade`]. One sampler per session, so a session cannot
    /// spend a quiet neighbour's allowance.
    oversize_drops: crate::logfmt::Sampler,
    /// How many send-buffer evictions this session has had, likewise.
    ///
    /// The same shape and the same reason as `oversize_drops`: see
    /// [`grade`].
    evictions: crate::logfmt::Sampler,
}

impl DatagramPath {
    pub(super) fn new(stream_id: u64, quarter_stream_id: u64, limit: usize) -> Self {
        Self {
            stream_id,
            quarter_stream_id,
            limit,
            oversize_drops: crate::logfmt::Sampler::new(),
            evictions: crate::logfmt::Sampler::new(),
        }
    }

    /// Sends the packet in `packets` as a QUIC datagram, or drops it if it is
    /// too large for one.
    ///
    /// The two readings are taken only when the cached answer does not cover
    /// the packet. A packet over the last limit read is checked against a
    /// fresh limit, and dropped if it is over that too. A packet for which
    /// [`super::super::quota::DatagramRoom::claim`] shows no room has the room read and
    /// graded. A packet under the limit with room goes straight to
    /// `send_datagram`, and a limit that has fallen since the last reading is
    /// caught there, as `TooLarge`.
    pub(super) fn send(&mut self, ctx: &Context, packets: &mut PacketBlock) {
        let encoded_len = packets.encoded_len();

        if encoded_len > self.limit {
            // The QUIC datagram path. If the packet does not fit, it is dropped.
            // RFC 9298 §6.1: "the UDP proxy SHOULD NOT send the UDP payload in
            // a DATAGRAM capsule, as that defeats the end-to-end unreliability
            // characteristic that methods such as Datagram Packetization Layer
            // PMTU Discovery (DPLPMTUD) depend on". The same paragraph goes on:
            // "the UDP proxy SHOULD drop the UDP payload and send an ICMP Packet
            // Too Big message to the target". The drop is done. The ICMP
            // message is not sent, because sending one needs a raw socket, so
            // that half of the SHOULD is unmet by our choice. An oversized
            // packet is lost the way a UDP packet on a too-small link would be.
            // What is negotiable is how loudly it is said; see
            // [`Self::report_oversize`].
            self.refresh_limit(ctx);
            let graded = grade(encoded_len, self.limit, &self.oversize_drops);
            if graded != Graded::Clear {
                // Dropped before it is cut off the block, so its bytes go to
                // the next packet.
                self.report_oversize(ctx, graded, encoded_len);
                return;
            }
        }

        if !ctx.datagram_room.claim(encoded_len) {
            // quinn's `send_datagram` is `send(data, drop = true)`: when the
            // outgoing queue would grow past `datagram_send_buffer_size` it
            // silently drops the *oldest* queued datagrams to make room, saying
            // so only in its own `trace!`. The `Blocked` error that would
            // otherwise report it is `unreachable!()` on this path, so the
            // `debug!` below can never see this loss. The remaining space,
            // read before the send, is the only way to detect it (D72).
            //
            // The packet still goes out unchanged: the eviction was decided by
            // how far behind the queue already is, and holding this packet back
            // would only trade a fresh datagram for a stale one. The reading
            // only decides what is logged.
            //
            // The reading is taken only here, when the connection's lower bound
            // of the room ([`super::quota::DatagramRoom::claim`]) does not
            // cover the packet.
            //
            // Exactly-enough space is room, not an eviction:
            // `datagram_send_buffer_space()` already has one datagram's own
            // overhead taken off, so `len <= space` is quinn's own "this one
            // fits" predicate. A larger datagram puts the queue over its limit,
            // and quinn discards from the front, on this send or the next. The
            // loss is decided before anything here could react, which is why
            // only how loudly to say so is graded.
            let space = ctx.quic.datagram_send_buffer_space();
            ctx.datagram_room.reset(space, encoded_len);
            let len = encoded_len;
            match grade(len, space, &self.evictions) {
                Graded::Clear => {}
                Graded::Report(evictions) => info!(
                    log_id = "zh8bm6bi",
                    stream_id = self.stream_id,
                    quarter_stream_id = self.quarter_stream_id,
                    space,
                    len,
                    evictions,
                    "QUIC datagram send buffer full, older datagrams evicted; further \
                     evictions on this session are logged at debug level until the count \
                     doubles"
                ),
                Graded::Quiet => debug!(
                    stream_id = self.stream_id,
                    quarter_stream_id = self.quarter_stream_id,
                    space,
                    len,
                    "QUIC datagram send buffer full, older datagrams evicted"
                ),
            }
        }

        match ctx.quic.send_datagram(packets.take()) {
            Ok(()) => {}
            // The limit fell below the last reading, and quinn compared the
            // packet with the new one. The packet was already cut off the
            // block, which only this case does to a packet that is not sent.
            Err(quinn::SendDatagramError::TooLarge) => {
                self.refresh_limit(ctx);
                self.report_oversize(ctx, occurrence(&self.oversize_drops), encoded_len);
            }
            Err(error) => debug!(%error, "failed to send a QUIC datagram"),
        }
    }

    /// Reads the size limit again.
    ///
    /// The transport parameter a `None` would come from does not change, so
    /// after the `Some` this path was built from, quinn does not answer `None`.
    fn refresh_limit(&mut self, ctx: &Context) {
        self.limit = ctx.quic.max_datagram_size().unwrap_or(0);
    }

    /// Says that a packet of `encoded_len` bytes was dropped as too large, as
    /// loudly as `graded` says.
    ///
    /// A drop logged only at `debug!` is invisible in production, and the
    /// condition is not hypothetical: a large EDNS0 or DNSSEC answer and any
    /// QUIC-in-QUIC flow through the tunnel exceed the limit routinely. So the
    /// drops the schedule picks are raised to `info!`, one line naming the
    /// length, the limit, the path MTU and how many drops there have been. The
    /// rest stay at `debug!`, because these arrive per packet and a flood of
    /// one benign message hides the warnings that matter.
    ///
    /// The MTU is on the line because the limit is the smaller of two things:
    /// what the peer's `max_datagram_frame_size` allows and what one packet at
    /// the current path MTU holds. A Surge that advertises 1300 gives a limit
    /// of 1291 once the path MTU has reached 1329, and one that advertises 1500
    /// gives 1398 at an MTU of 1436. Below those MTUs the MTU sets the limit for
    /// both: 1204 at 1242 (D48 addendum 2026-11-13). Without the MTU
    /// a low limit cannot be told from a path that shrank (D81). It is read
    /// from the connection statistics on a reported drop only, never per
    /// packet.
    fn report_oversize(&self, ctx: &Context, graded: Graded, encoded_len: usize) {
        let limit = self.limit;
        match graded {
            Graded::Clear => {}
            Graded::Report(drops) => info!(
                log_id = "ybux2nd9",
                quarter_stream_id = self.quarter_stream_id,
                encoded_len,
                limit,
                mtu = ctx.quic.stats().path.current_mtu,
                drops,
                "target packet too large for a QUIC datagram, dropping; further \
                 drops on this session are logged at debug level until the count \
                 doubles"
            ),
            Graded::Quiet => debug!(
                quarter_stream_id = self.quarter_stream_id,
                encoded_len, limit, "target packet too large for a QUIC datagram, dropping"
            ),
        }
    }
}

/// How loudly one occurrence of a per-packet condition is worth saying.
///
/// Shared by the two conditions the outbound path grades, a packet too large
/// for a QUIC datagram and a send queue with no room left. Neither condition is
/// decided here and neither is negotiable; what this carries is only how loudly
/// to say it, which is the same question with the same answer for both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Graded {
    /// The condition did not arise. The sampler is left untouched, so the
    /// schedule counts real occurrences and nothing else.
    Clear,
    /// It did, and the schedule reports this one: worth an `info!`, carrying
    /// how many this session has had.
    Report(u64),
    /// It did, and this one falls between reports: `debug!` only.
    Quiet,
}

/// Grades `value` against `limit` on `sampler`'s doubling schedule.
///
/// Both conditions are the same comparison: `value <= limit` is
/// [`Graded::Clear`] and anything past it is the condition. Exactly the limit is
/// clear, in both cases and for the same reason, which is why the comparison is
/// here rather than at the call sites. What the two numbers *are*, and why the
/// condition is worth a production line at all, stays with the caller: the two
/// call sites carry an argument each and they are different arguments.
///
/// [`crate::logfmt::Sampler`] is the doubling schedule this crate bounds every
/// peer-repeatable line with: the first occurrence of a session is reported at
/// once, and the reports after it are 2, 4, 8 and so on rather than silence.
/// `sampler` is the session's own, so one session cannot quieten another. It is
/// advanced only where the condition arose, and that is the whole cost: no
/// allocation, no lock, one atomic increment on the forwarding path.
fn grade(value: usize, limit: usize, sampler: &crate::logfmt::Sampler) -> Graded {
    if value <= limit {
        return Graded::Clear;
    }

    occurrence(sampler)
}

/// Records one occurrence on `sampler` and says how loudly to report it.
///
/// [`grade`] without the comparison, for a caller that already knows the
/// condition arose: quinn refusing a datagram as too large is that verdict
/// made under its own lock.
fn occurrence(sampler: &crate::logfmt::Sampler) -> Graded {
    sampler.record().map_or(Graded::Quiet, Graded::Report)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::datagram;
    use crate::tunnel::quota::QUEUED_DATAGRAM_COST;
    use crate::tunnel::udp::block::landed;

    // -----------------------------------------------------------------------
    // The QUIC datagram path
    // -----------------------------------------------------------------------
    //
    // A real loopback connection, because what is asserted is what quinn's
    // own answers make of each packet. The tests run on the current-thread
    // runtime and do not yield inside a loop of sends, so quinn's driver
    // transmits nothing until a test lets it, and its queue grows exactly by
    // what the test sends.

    /// A context on a loopback connection whose peer accepts QUIC datagrams,
    /// and the peer's end of it, kept open.
    async fn datagram_context() -> (Context, quinn::Connection) {
        let config: crate::config::Config = toml::from_str(
            r#"
                [server]
                listen = "127.0.0.1:0"
                cert = "unused.pem"
                key = "unused.pem"
            "#,
        )
        .expect("the test configuration must parse");
        let (peer, ours) =
            crate::quic::tests::loopback_pair(quinn::TransportConfig::default()).await;

        let ctx = Context::new(
            std::sync::Arc::new(crate::tunnel::Generation::new(std::sync::Arc::new(config))),
            ours,
            crate::h3api::PeerSettings::for_tests(true),
            crate::net::ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS)
                .per_connection(),
            std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            crate::quic::AuthGate::closed(),
        );
        (ctx, peer)
    }

    /// A packet under a limit that has since fallen is refused by quinn as too
    /// large, and that refusal is a drop like any other: counted on the
    /// session's schedule, with the limit read again for the line.
    #[tokio::test]
    async fn a_packet_quinn_refuses_as_too_large_is_a_counted_drop() {
        let (ctx, _peer) = datagram_context().await;
        let limit = ctx
            .quic
            .max_datagram_size()
            .expect("the peer accepts datagrams");
        let mut path = DatagramPath::new(4, 1, limit);
        let mut packets = PacketBlock::new(1);

        // One packet that fits, so the room bound covers the next one and the
        // next one goes straight to quinn.
        landed(&mut packets, &[1; 100]);
        path.send(&ctx, &mut packets);
        assert!(ctx.datagram_room.get() > limit);

        // The reading as it stood before the path MTU fell.
        path.limit = usize::MAX;
        landed(&mut packets, &vec![2; limit - 1]);
        assert_eq!(packets.encoded_len(), limit + 1);
        path.send(&ctx, &mut packets);

        assert_eq!(path.oversize_drops.seen(), 1, "quinn's TooLarge is a drop");
        assert_eq!(path.limit, limit, "the limit is read again for the line");
        assert_eq!(path.evictions.seen(), 0, "a refused packet evicts nothing");
    }

    /// A packet over a limit that has since risen is held against a fresh
    /// reading, and sent.
    #[tokio::test]
    async fn a_packet_over_an_old_limit_is_held_against_a_fresh_one() {
        let (ctx, _peer) = datagram_context().await;
        let limit = ctx
            .quic
            .max_datagram_size()
            .expect("the peer accepts datagrams");
        let mut path = DatagramPath::new(4, 1, 0);
        let mut packets = PacketBlock::new(1);

        landed(&mut packets, &vec![3; limit - 2]);
        assert_eq!(packets.encoded_len(), limit);
        path.send(&ctx, &mut packets);

        assert_eq!(path.oversize_drops.seen(), 0, "a packet that fits is sent");
        assert_eq!(path.limit, limit);
        assert!(!packets.prepared(), "the packet was cut off the block");
    }

    /// Evictions are graded exactly as a reading before every send grades
    /// them, which is what the session did before the room bound existed.
    ///
    /// Enough packets to fill quinn's 1 MiB queue and evict past it. Before
    /// each send the test reads the room itself and works out what the old
    /// code would have said; after it, the bound must still be below the room.
    #[tokio::test]
    async fn evictions_are_graded_as_a_reading_before_every_send_grades_them() {
        let (ctx, _peer) = datagram_context().await;
        let limit = ctx
            .quic
            .max_datagram_size()
            .expect("the peer accepts datagrams");
        let mut path = DatagramPath::new(4, 1, limit);
        let mut packets = PacketBlock::new(1);
        let payload = vec![4; 1000];
        let mut expected = 0;

        for nth in 0..1200 {
            landed(&mut packets, &payload);
            let space = ctx.quic.datagram_send_buffer_space();
            if packets.encoded_len() > space {
                expected += 1;
            }

            path.send(&ctx, &mut packets);

            assert_eq!(
                path.evictions.seen(),
                expected,
                "packet {nth}: graded differently from a reading of {space}"
            );
            assert!(
                ctx.datagram_room.get() <= ctx.quic.datagram_send_buffer_space(),
                "packet {nth}: the bound passed the room it bounds"
            );
        }

        assert!(
            expected > 100,
            "the queue never filled, so nothing was tested"
        );
    }

    /// A packet the bound covers takes no reading: once quinn has sent what
    /// was queued, the bound still counts it, until a packet it does not cover
    /// reads the room again.
    #[tokio::test]
    async fn a_packet_the_room_bound_covers_takes_no_reading() {
        let (ctx, _peer) = datagram_context().await;
        let limit = ctx
            .quic
            .max_datagram_size()
            .expect("the peer accepts datagrams");
        let mut path = DatagramPath::new(4, 1, limit);
        let mut packets = PacketBlock::new(1);
        let payload = vec![5; 1000];
        let cost = 2 + payload.len() + QUEUED_DATAGRAM_COST;

        landed(&mut packets, &payload);
        path.send(&ctx, &mut packets);
        let after_first = ctx.datagram_room.get();

        // Long enough for quinn to send the one queued datagram.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            ctx.quic.datagram_send_buffer_space() > after_first,
            "quinn did not send the first datagram, so nothing tells a reading apart"
        );

        landed(&mut packets, &payload);
        path.send(&ctx, &mut packets);
        assert_eq!(
            ctx.datagram_room.get(),
            after_first - cost,
            "the second packet read the room although the bound covered it"
        );
    }

    /// The `max_datagram_frame_size` an older Surge advertises (D48).
    const SURGE_MAX_DATAGRAM_FRAME_SIZE: usize = 1300;

    /// An `info!` on the doubling schedule, and the running total in it, for
    /// both conditions the outbound path grades.
    ///
    /// RFC 9298 §6.1 fixes what happens to an oversized packet (it is dropped,
    /// never downgraded to a capsule), and quinn decides an eviction, so only
    /// their visibility is in question here. At `debug!` alone neither could be
    /// seen in production, and a line per packet would be the flood D44
    /// removed elsewhere.
    ///
    /// Eight occurrences, because the schedule is the assertion: reports land
    /// on the 1st, 2nd, 4th and 8th and on none of the others, and each says
    /// how many there have been. Asserting the whole sequence at once rather
    /// than "the first one only" is what tells the schedule apart from the two
    /// mutations next to it: reporting always, and reporting on everything but
    /// the first.
    ///
    /// Pure arithmetic and a sampler: a live session would need a QUIC
    /// connection whose path is too small, or whose send queue is a megabyte
    /// behind, while the decision being asserted lives entirely in [`grade`].
    #[test]
    fn a_per_packet_condition_is_reported_on_a_doubling_schedule() {
        // A 4 KiB answer, which an EDNS0/DNSSEC response routinely is, against
        // an older Surge's limit; and a datagram against a queue with no room.
        let oversize = datagram::encoded_len(9, datagram::CONTEXT_ID_UDP_PAYLOAD, 4096);
        assert!(oversize > SURGE_MAX_DATAGRAM_FRAME_SIZE);

        for (value, limit) in [(oversize, SURGE_MAX_DATAGRAM_FRAME_SIZE), (1200, 0)] {
            let sampler = crate::logfmt::Sampler::new();
            let verdicts: Vec<Graded> = (0..8).map(|_| grade(value, limit, &sampler)).collect();

            assert_eq!(
                verdicts,
                vec![
                    Graded::Report(1),
                    Graded::Report(2),
                    Graded::Quiet,
                    Graded::Report(4),
                    Graded::Quiet,
                    Graded::Quiet,
                    Graded::Quiet,
                    Graded::Report(8),
                ],
                "{value} over {limit}: an operator must be told at once that this is \
                 happening, and then how far it has got, without a line per packet"
            );
        }
    }

    /// The other half: an ordinary packet is sent untouched and does not advance
    /// the session's schedule.
    #[test]
    fn a_packet_within_the_limit_is_sent_and_costs_no_report() {
        let fits = datagram::encoded_len(9, datagram::CONTEXT_ID_UDP_PAYLOAD, 512);
        assert!(fits <= SURGE_MAX_DATAGRAM_FRAME_SIZE);

        let drops = crate::logfmt::Sampler::new();
        for _ in 0..3 {
            assert_eq!(
                grade(fits, SURGE_MAX_DATAGRAM_FRAME_SIZE, &drops),
                Graded::Clear
            );
        }
        assert_eq!(drops.seen(), 0, "a packet that fits is not a drop");

        // Exactly the limit still fits; one byte past it does not, and that is the
        // first drop of the session, so it is the first thing reported.
        assert_eq!(
            grade(
                SURGE_MAX_DATAGRAM_FRAME_SIZE,
                SURGE_MAX_DATAGRAM_FRAME_SIZE,
                &drops
            ),
            Graded::Clear
        );
        assert_eq!(
            grade(
                SURGE_MAX_DATAGRAM_FRAME_SIZE + 1,
                SURGE_MAX_DATAGRAM_FRAME_SIZE,
                &drops
            ),
            Graded::Report(1)
        );
    }

    /// The other half: room is room, and exactly enough of it is still room.
    #[test]
    fn a_datagram_the_queue_has_room_for_costs_no_report() {
        let evictions = crate::logfmt::Sampler::new();
        for _ in 0..3 {
            assert_eq!(grade(1200, 1_048_576, &evictions), Graded::Clear);
        }
        assert_eq!(
            evictions.seen(),
            0,
            "a datagram that fits displaces nothing"
        );

        // The boundary quinn itself draws: `datagram_send_buffer_space()` has the
        // per-datagram overhead subtracted already, so a datagram of exactly that
        // many bytes is the last one that fits.
        assert_eq!(grade(1200, 1200, &evictions), Graded::Clear);
        assert_eq!(grade(1201, 1200, &evictions), Graded::Report(1));
    }
}
