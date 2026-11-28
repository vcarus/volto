//! The state the gate keeps while an ECH key is configured: first flights held
//! until their ClientHello is whole, and the record of every ECH flight a key
//! opened.
//!
//! Everything here is fed by datagrams nobody has authenticated, so every part
//! of it is bounded by a constant below, and each constant says why it has the
//! value it has. The parent module's documentation says what the hold is for
//! and how a held datagram reaches quinn; this module is the bookkeeping.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::ConnectionId;
use quinn::udp::RecvMeta;

use crate::hello::{self, Ech, Message};

use super::initial::{Refused, Stream};
use super::{Policy, Screened, by_name};

/// How long a first flight is held for its ClientHello to complete.
///
/// The packets of one first flight leave the client in one burst, so on any
/// path they arrive within milliseconds of each other. The rest of the window
/// is for loss. The hold sends nothing back, so a client learns of no loss
/// and sends at most two datagrams at each probe timeout, filled from its
/// oldest packets that still carry data (RFC 9002 §6.2.4: "An endpoint MAY
/// send up to two full-sized datagrams containing ack-eliciting packets to
/// avoid an expensive consecutive PTO expiration due to a single lost
/// datagram or to transmit data from multiple packet number spaces."). From
/// the 333 ms initial RTT quinn and this server default to, the probe
/// timeouts fall at about 1 s, 3 s and 7 s. A flight of three
/// datagrams that loses its third gets the lost bytes back only at the
/// second of them, 3 s after it began, and a flight of five or six, or a
/// flight whose retransmission is lost once more, only at the third, 7 s
/// after it began. So the window ends after the third probe timeout.
/// `it_gate_shapes` drives the three-datagram case with a quinn client. A
/// flight that is still incomplete after this is dropped without a reply.
/// Our own value.
///
/// The lifetime is not a bound on what a flood can hold: [`HOLD_FLIGHTS`]
/// and [`HOLD_TOTAL_BYTES`] are, and a new flight evicts the oldest whatever
/// its age.
pub const HOLD_LIFETIME: Duration = Duration::from_secs(8);

/// How many first flights may be held at once.
///
/// One flight per handshake in progress, and a handshake is in this table only
/// for the milliseconds between its first and last Initial packet, so even a
/// burst of reconnects after a network change holds a handful. When the table
/// is full, a new flight evicts the oldest one, which is dropped without a
/// reply. Evicting the oldest rather than refusing the newest is what keeps a
/// flood of incomplete flights from shutting out a client: to push a client's
/// flight out between its first and its last packet, a flood has to start this
/// many new flights inside that gap, where refusing the newest would let it
/// hold the table with this many packets every [`HOLD_LIFETIME`]. Our own value.
pub const HOLD_FLIGHTS: usize = 64;

/// The most CRYPTO stream bytes the hold reassembles for one flight:
/// libssl's limit for the Initial level, [`hello::MAX_INITIAL_FLIGHT`], since
/// no ClientHello libssl reads is longer. A flight whose CRYPTO bytes reach
/// past it, or whose ClientHello says it is longer, is dropped.
pub const HOLD_HELLO_BYTES: usize = hello::MAX_INITIAL_FLIGHT;

/// The most bytes one held flight may count: its datagrams as received, plus
/// the buffer its CRYPTO stream is reassembled in and that buffer's bitmap,
/// each by its length.
///
/// The largest ClientHello the hold reassembles ([`HOLD_HELLO_BYTES`]) takes
/// about fifteen Initial packets of 1200 bytes, which with its reassembly
/// buffer is about 40 KiB; this leaves room above that for duplicates. A
/// ClientHello of a client this server serves is under 2 KiB in two packets.
/// A flight that would grow past it is dropped. Our own value. The heap behind
/// a flight is more than its count; [`HOLD_TOTAL_BYTES`] says how much more.
pub const HOLD_FLIGHT_BYTES: usize = 64 * 1024;

/// The most bytes the hold counts in all: every held flight as
/// [`HOLD_FLIGHT_BYTES`] counts it, and the released datagrams waiting for the
/// next receive call.
///
/// [`HOLD_FLIGHTS`] flights at [`HOLD_FLIGHT_BYTES`] each, 4 MiB. A datagram
/// that would push the count past it evicts the oldest flights first, as a
/// full table does.
///
/// The count is of lengths, so the heap the hold takes at worst is larger:
/// about 6 MiB, before the allocator's own rounding. std's vector grows by
/// doubling, so a stream buffer's capacity is under twice its length, which
/// is under 16 KiB more per flight for the bytes and 2 KiB for the bitmap.
/// Each held datagram has a record of 96 bytes beside its bytes (its receive
/// metadata and its vector), and a flight's list of records has room for at
/// most 64, because a held datagram is at least 1200 bytes and a flight
/// counts at most 64 KiB: 6 KiB. That is under 24 KiB per flight, 1.5 MiB for
/// [`HOLD_FLIGHTS`] flights. The released queue holds at most 3495 datagrams
/// of 1200 bytes inside the 4 MiB, and its records take at most 4096 times
/// 96 bytes, 384 KiB.
pub const HOLD_TOTAL_BYTES: usize = HOLD_FLIGHTS * HOLD_FLIGHT_BYTES;

/// How many admitted ECH flights the replay record remembers.
///
/// The record does not expire by time, because an entry that expired would let
/// a copy of that flight, sent from another address, draw a ServerHello. It is
/// bounded by count instead, at 2^20 entries. At the limit the oldest entry
/// goes, so a copy of a flight older than the last 2^20 admitted ones is no
/// longer recognised. One record serves the current and the previous key
/// together, so this bound is the whole record's with one key or two. Our own
/// value.
///
/// An entry is two 64-bit tags in the map and one in the order queue. A full
/// record is a map of 2^21 buckets of 17 bytes (the two tags and a control
/// byte) and a queue of 2^20 tags of 8 bytes, 42 MiB, and evicting the oldest
/// entry for each new one keeps the map at that size. While the map grows past
/// 917,504 entries, its old table of 2^20 buckets is held as well, 59 MiB for
/// that moment.
pub const REPLAY_ENTRIES: usize = 1 << 20;

/// One received datagram the hold keeps, as quinn would have received it.
pub(super) struct HeldDatagram {
    /// The receive metadata of the batch entry it came in: the source address,
    /// the ECN bits and the local address. Its `len` and `stride` are set to
    /// this one datagram when it is handed over.
    pub(super) meta: RecvMeta,
    /// The datagram's bytes, as they arrived.
    pub(super) bytes: Vec<u8>,
}

/// Why a held first flight was dropped.
///
/// Hidden and public for the same reason the gate's `Refusal` is: the fuzz
/// target and the tests behind `Screening` say which drop they expected.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dropped {
    /// The first handshake message is not a ClientHello.
    NotClientHello,
    /// A whole ClientHello with no extension block, or one whose block libssl
    /// would refuse: it does not end where the ClientHello ends, or an
    /// extension in it does not fit. Only the framing is checked; the other
    /// things libssl refuses in a ClientHello are left to libssl.
    UnreadableExtensions,
    /// CRYPTO bytes, or a ClientHello length, past [`HOLD_HELLO_BYTES`].
    TooLong,
    /// Two packets of the flight carried different bytes at one offset.
    Conflict,
    /// A packet of the flight carried frames that do not parse, or a frame no
    /// Initial packet may carry.
    Frames,
    /// An ECH extension that names neither key's config_id, or that the key it
    /// names does not open.
    EchNotOpened,
    /// An ECH extension a key opened, already admitted from another address.
    Replayed,
    /// No ECH extension, with `security.require_ech` on.
    EchRequired,
    /// No ECH extension and no `server_name`, with the name list on.
    Anonymous,
    /// No ECH extension and a name off the list, carried as it arrived.
    OtherName(Vec<u8>),
    /// The ClientHello did not complete within [`HOLD_LIFETIME`].
    Expired,
    /// The table was full, or the hold out of bytes, and this was the oldest
    /// flight.
    Evicted,
    /// The flight would have grown past [`HOLD_FLIGHT_BYTES`].
    TooBig,
}

/// A first flight being held.
struct Flight {
    dcid: ConnectionId,
    from: SocketAddr,
    started: Instant,
    datagrams: Vec<HeldDatagram>,
    /// The sum of the datagrams' lengths.
    datagram_bytes: usize,
    stream: Stream,
}

impl Flight {
    /// Every byte this flight holds, as [`HOLD_FLIGHT_BYTES`] counts it.
    fn bytes(&self) -> usize {
        self.datagram_bytes + self.stream.footprint()
    }
}

/// The record of every ECH flight a key opened: its HPKE `enc` and the
/// address it came from, both as keyed 64-bit tags.
///
/// Tags rather than the values: an X25519 `enc` is 32 bytes and an address up
/// to 28, and [`REPLAY_ENTRIES`] of them would be several times the memory.
/// The tags are SipHash under a key drawn when the record is made, so a peer
/// cannot aim two values at one tag. Two of this server's own flights colliding
/// on a tag, which is what a tag costs, is a chance of about one in 2^24 over a
/// full record, and costs that client one retry.
pub(super) struct Replay {
    keys: RandomState,
    /// `enc` tag to address tag.
    seen: HashMap<u64, u64>,
    /// `enc` tags, oldest first, for the eviction at [`REPLAY_ENTRIES`].
    order: VecDeque<u64>,
}

impl Replay {
    fn new() -> Self {
        Self {
            keys: RandomState::new(),
            seen: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Whether a flight whose ECH opened with `enc`, from `from`, is admitted,
    /// recording it if it is new.
    ///
    /// The same `enc` from the same address is admitted: that is a client
    /// sending its first flight again, after a loss or after a Retry, which
    /// keeps the ClientHello and so its `enc`. The same `enc` from another
    /// address is a copy of somebody else's flight. Our own rule.
    ///
    /// It protects against a copy that arrives after the original, not one
    /// that overtakes it; the gate's module documentation says so under
    /// *Limits*.
    fn admit(&mut self, enc: &[u8], from: SocketAddr) -> bool {
        let tag = self.keys.hash_one(enc);
        let place = self.keys.hash_one(from);
        if let Some(seen) = self.seen.get(&tag) {
            return *seen == place;
        }
        if self.order.len() >= REPLAY_ENTRIES
            && let Some(oldest) = self.order.pop_front()
        {
            self.seen.remove(&oldest);
        }
        self.seen.insert(tag, place);
        self.order.push_back(tag);
        true
    }

    pub(super) fn len(&self) -> usize {
        self.order.len()
    }
}

/// Every flight held, and the datagrams of the flights already released.
pub(super) struct Hold {
    /// Oldest first, which is the order both expiry and eviction take them in.
    flights: VecDeque<Flight>,
    /// Datagrams of admitted flights, in arrival order, for the next receive
    /// call to hand quinn.
    pub(super) released: VecDeque<HeldDatagram>,
    /// Every byte in `flights` and `released`, as [`HOLD_TOTAL_BYTES`] counts.
    bytes: usize,
}

/// One opened first Initial, as the gate hands it to the hold.
pub(super) struct Arrival<'a> {
    /// When the receive call that read it began.
    pub(super) now: Instant,
    /// The receive metadata it came with.
    pub(super) meta: RecvMeta,
    /// The whole datagram, as received.
    pub(super) datagram: &'a [u8],
    /// The Destination Connection ID of its first packet, which with the
    /// source address keys its flight.
    pub(super) dcid: ConnectionId,
}

impl Hold {
    fn new() -> Self {
        Self {
            flights: VecDeque::new(),
            released: VecDeque::new(),
            bytes: 0,
        }
    }

    pub(super) fn flights(&self) -> usize {
        self.flights.len()
    }

    /// Every byte the hold counts against [`HOLD_TOTAL_BYTES`].
    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Every byte the hold counts, summed from what it holds rather than
    /// read from the running count: each flight's datagrams and its stream's
    /// buffer and bitmap, and every released datagram.
    ///
    /// The fuzz target and the tests compare it with [`Hold::bytes`] after
    /// every datagram, because a bound checked against the count alone cannot
    /// see a count that has drifted below what is held.
    pub(super) fn recount(&self) -> usize {
        let flights: usize = self
            .flights
            .iter()
            .map(|flight| {
                let datagrams: usize = flight.datagrams.iter().map(|d| d.bytes.len()).sum();
                datagrams + flight.stream.footprint()
            })
            .sum();
        let released: usize = self.released.iter().map(|d| d.bytes.len()).sum();
        flights + released
    }

    /// Drops every held flight, reporting none: for a reload that removed the
    /// key, after which nothing would ever judge them.
    pub(super) fn clear(&mut self) {
        let released: usize = self.released.iter().map(|d| d.bytes.len()).sum();
        self.flights.clear();
        self.bytes = released;
    }

    /// Takes the next released datagram, keeping the byte count.
    pub(super) fn pop_released(&mut self) -> Option<HeldDatagram> {
        let datagram = self.released.pop_front()?;
        self.bytes -= datagram.bytes.len();
        Some(datagram)
    }

    /// Removes the flight at `index`, releasing its accounting.
    fn remove(&mut self, index: usize) -> Option<Flight> {
        let flight = self.flights.remove(index)?;
        self.bytes -= flight.bytes();
        Some(flight)
    }

    /// Drops every flight that has outlived [`HOLD_LIFETIME`] at `now`.
    fn expire(&mut self, now: Instant, report: &mut dyn FnMut(SocketAddr, Dropped)) {
        while let Some(front) = self.flights.front() {
            if now.saturating_duration_since(front.started) < HOLD_LIFETIME {
                break;
            }
            if let Some(flight) = self.remove(0) {
                report(flight.from, Dropped::Expired);
            }
        }
    }

    /// Where the flight of `dcid` from `from` is, if it is held.
    fn find(&self, dcid: &ConnectionId, from: SocketAddr) -> Option<usize> {
        self.flights
            .iter()
            .position(|flight| flight.dcid == *dcid && flight.from == from)
    }

    /// What the flight at `found`, or a new one when it is `None`, would count
    /// with a datagram of `datagram` bytes in it and its stream grown to
    /// `end`.
    ///
    /// The sum cannot overflow: a held flight counts at most
    /// [`HOLD_FLIGHT_BYTES`], a datagram is a slice and so at most `isize::MAX`
    /// bytes, and a stream with its bitmap is at most [`HOLD_HELLO_BYTES`] and
    /// an eighth more.
    fn bytes_after(&self, found: Option<usize>, datagram: usize, end: usize) -> usize {
        match found.and_then(|index| self.flights.get(index)) {
            Some(flight) => flight.datagram_bytes + datagram + flight.stream.footprint_at(end),
            None => datagram + Stream::default().footprint_at(end),
        }
    }

    /// Starts an empty flight for `arrival`, evicting the oldest one when the
    /// table is full, and says where it is: last, since it is the newest.
    fn open(
        &mut self,
        arrival: &Arrival<'_>,
        report: &mut dyn FnMut(SocketAddr, Dropped),
    ) -> usize {
        if self.flights.len() >= HOLD_FLIGHTS
            && let Some(oldest) = self.remove(0)
        {
            report(oldest.from, Dropped::Evicted);
        }
        self.flights.push_back(Flight {
            dcid: arrival.dcid,
            from: arrival.meta.addr,
            started: arrival.now,
            datagrams: Vec::new(),
            datagram_bytes: 0,
            stream: Stream::default(),
        });
        // Not empty after the push, so the subtraction cannot underflow.
        self.flights.len() - 1
    }

    /// Evicts the oldest flights ahead of the one at `index` until the hold
    /// has room for `growth` more bytes, as a full table does, and says where
    /// that flight is now: `Ok` with room, `Err` when evicting every flight
    /// ahead of it still leaves none.
    ///
    /// `index` falls by one for each flight removed ahead of it, and the loop
    /// stops at 0, so it cannot underflow.
    fn make_room(
        &mut self,
        mut index: usize,
        growth: usize,
        report: &mut dyn FnMut(SocketAddr, Dropped),
    ) -> Result<usize, usize> {
        while self.bytes + growth > HOLD_TOTAL_BYTES && index > 0 {
            if let Some(oldest) = self.remove(0) {
                report(oldest.from, Dropped::Evicted);
            }
            index -= 1;
        }
        if self.bytes + growth > HOLD_TOTAL_BYTES {
            Err(index)
        } else {
            Ok(index)
        }
    }

    /// Writes `fragments` into the stream of the flight at `index` and, if
    /// every one joins, keeps `arrival`'s datagram in it.
    ///
    /// The only place a held flight's contents change. The count is raised by
    /// what the flight counts after the writes less what it counted before
    /// them, on the path that keeps the datagram and on the one that refuses
    /// it, so it is always the sum of what is held. A fragment can be refused
    /// after the fragments ahead of it in the same datagram have grown the
    /// stream, and the caller then removes the flight with that growth in it,
    /// which [`Hold::remove`] takes off the count again. The growth
    /// [`Hold::make_room`] made room for is the most this can add: exactly it
    /// when every fragment joins, less when one is refused. The subtraction
    /// cannot underflow, because a stream and a flight's datagrams only grow.
    fn write(
        &mut self,
        index: usize,
        arrival: &Arrival<'_>,
        fragments: &[(u64, &[u8])],
    ) -> Result<(), Dropped> {
        let flight = &mut self.flights[index];
        let before = flight.bytes();
        let written = fragments
            .iter()
            .try_for_each(|(offset, bytes)| flight.stream.insert(*offset, bytes));
        if written.is_ok() {
            flight.datagrams.push(HeldDatagram {
                meta: arrival.meta,
                bytes: arrival.datagram.to_vec(),
            });
            flight.datagram_bytes += arrival.datagram.len();
        }
        self.bytes += flight.bytes() - before;
        written.map_err(|refused| match refused {
            Refused::TooLong => Dropped::TooLong,
            Refused::Conflict => Dropped::Conflict,
        })
    }
}

/// Where the CRYPTO stream of a flight ends once `fragments` have joined it,
/// or `None` when one of them reaches past [`HOLD_HELLO_BYTES`].
///
/// The limit test is [`Stream::insert`]'s own, applied to every fragment,
/// empty ones included, so a datagram `insert` would refuse as too long is
/// found here, before the hold makes room for it. An empty fragment does not
/// move the end, because it does not grow the buffer.
fn crypto_end(fragments: &[(u64, &[u8])]) -> Option<usize> {
    let mut end = 0usize;
    for (offset, bytes) in fragments {
        let stop = usize::try_from(*offset).ok()?.checked_add(bytes.len())?;
        if stop > HOLD_HELLO_BYTES {
            return None;
        }
        if !bytes.is_empty() {
            end = end.max(stop);
        }
    }
    Some(end)
}

/// The policy in force, the hold and the replay record, behind one lock in
/// the gate, so that whatever reads the policy holds the lock that guards the
/// hold.
pub(super) struct Memory {
    pub(super) policy: Arc<Policy>,
    pub(super) hold: Hold,
    pub(super) replay: Replay,
}

impl Memory {
    pub(super) fn new(policy: Arc<Policy>) -> Self {
        Self {
            policy,
            hold: Hold::new(),
            replay: Replay::new(),
        }
    }

    /// Holds one opened first Initial and, if it completes its flight, judges
    /// the flight under [`Memory::policy`].
    ///
    /// `fragments` are the CRYPTO frames of every Initial packet of the flight
    /// in the datagram, the first one and those coalesced behind it, or `None`
    /// when the frames of one of them do not parse or include a type no
    /// Initial packet may carry. Every flight dropped on the way, this one or
    /// another, is reported once through `report`.
    ///
    /// The phases run in this order: expiry; the checks that need only the
    /// datagram and the flight it joins (frames that do not parse, CRYPTO
    /// bytes past [`HOLD_HELLO_BYTES`], a flight past [`HOLD_FLIGHT_BYTES`]);
    /// a new flight, and room in the hold, both of which may evict the oldest
    /// flights; the write; the judgement. So a datagram dropped by one of
    /// those checks evicts no other flight.
    pub(super) fn take(
        &mut self,
        arrival: &Arrival<'_>,
        fragments: Option<&[(u64, &[u8])]>,
        report: &mut dyn FnMut(SocketAddr, Dropped),
    ) -> Screened {
        let from = arrival.meta.addr;
        self.hold.expire(arrival.now, report);
        let found = self.hold.find(&arrival.dcid, from);

        let Some(fragments) = fragments else {
            return self.drop_found(found, from, Dropped::Frames, report);
        };
        let Some(end) = crypto_end(fragments) else {
            return self.drop_found(found, from, Dropped::TooLong, report);
        };
        let after = self.hold.bytes_after(found, arrival.datagram.len(), end);
        if after > HOLD_FLIGHT_BYTES {
            return self.drop_found(found, from, Dropped::TooBig, report);
        }

        let index = match found {
            Some(index) => index,
            None => self.hold.open(arrival, report),
        };
        // `bytes_after` is at least what the flight counts now, because
        // `footprint_at` is at least `footprint` and the datagram is added,
        // so the subtraction cannot underflow.
        let growth = after - self.hold.flights[index].bytes();
        let index = match self.hold.make_room(index, growth, report) {
            Ok(index) => index,
            Err(index) => return self.drop_flight(index, Dropped::Evicted, report),
        };
        if let Err(why) = self.hold.write(index, arrival, fragments) {
            return self.drop_flight(index, why, report);
        }

        match judge(
            self.hold.flights[index].stream.contiguous(),
            &self.policy,
            from,
            &mut self.replay,
        ) {
            None => Screened::Held,
            Some(Err(why)) => self.drop_flight(index, why, report),
            Some(Ok(())) => self.release(index),
        }
    }

    /// Drops the flight at `index` and reports why.
    fn drop_flight(
        &mut self,
        index: usize,
        why: Dropped,
        report: &mut dyn FnMut(SocketAddr, Dropped),
    ) -> Screened {
        if let Some(flight) = self.hold.remove(index) {
            report(flight.from, why);
        }
        Screened::Dropped
    }

    /// Drops the datagram from `from`, and with it the flight at `found` if
    /// one is held, and reports why once, whether or not a flight was held.
    fn drop_found(
        &mut self,
        found: Option<usize>,
        from: SocketAddr,
        why: Dropped,
        report: &mut dyn FnMut(SocketAddr, Dropped),
    ) -> Screened {
        if let Some(index) = found {
            self.hold.remove(index);
        }
        report(from, why);
        Screened::Dropped
    }

    /// Moves every datagram of the admitted flight at `index` to `released`,
    /// in the order they arrived, keeping the byte count.
    fn release(&mut self, index: usize) -> Screened {
        let Some(flight) = self.hold.remove(index) else {
            return Screened::Dropped;
        };
        for datagram in flight.datagrams {
            self.hold.bytes += datagram.bytes.len();
            self.hold.released.push_back(datagram);
        }
        Screened::Released
    }
}

/// The verdict on a flight whose CRYPTO stream starts with `contiguous`:
/// `None` while the ClientHello is not whole, `Ok` to admit it.
///
/// D115's rule table, in the order a ClientHello answers it:
///
/// 1. An ECH extension that opens under the key its config_id names is
///    admitted, unless the replay record holds its `enc` from another address.
///    The outer name is not consulted: the name a client asks for is the
///    inner one, and the TLS layer judges that one against `expected_sni`.
/// 2. An ECH extension that names neither key's config_id, that the named key
///    does not open, or that is not a well-formed outer one, is dropped,
///    whether or not `require_ech` is on. Our own rule and a
///    deviation from RFC 9849 §7.1, which has the server go on with the outer
///    ClientHello: "Otherwise, if all candidate ECHConfig values fail to
///    decrypt the extension, the client-facing server MUST ignore the extension
///    and proceed with the connection using ClientHelloOuter". Going on would
///    send this server's ECHConfigList as `retry_configs` to a peer without
///    the key (D115).
/// 3. No ECH extension is dropped under `require_ech`, and otherwise judged by
///    its name by [`by_name`], the stateless gate's rule, with an empty list
///    admitting every name.
///
/// A whole ClientHello whose extension block libssl would refuse to parse is
/// dropped before any of that, because this gate cannot then say whether it
/// carries an ECH extension, and libssl, which would read it differently or
/// not at all, is the parser the rule protects. A ClientHello with no
/// extension block is dropped there too: libssl reads it as one without
/// extensions, and it cannot complete a QUIC handshake, since it carries no
/// transport parameters. Only the block's framing is checked: a ClientHello
/// libssl refuses for another reason (a session ID over 32 bytes, an odd
/// cipher suite list, a duplicated extension, bytes after the message) is
/// judged like any other, and libssl refuses it.
fn judge(
    contiguous: &[u8],
    policy: &Policy,
    from: SocketAddr,
    replay: &mut Replay,
) -> Option<Result<(), Dropped>> {
    let mut header = hello::Reader::new(contiguous);
    if let (Some(hello::CLIENT_HELLO), Some(length)) = (header.u8(), header.u24())
        && length.saturating_add(4) > HOLD_HELLO_BYTES
    {
        return Some(Err(Dropped::TooLong));
    }
    let body = match hello::client_hello(contiguous) {
        Message::Incomplete => return None,
        Message::NotAClientHello => return Some(Err(Dropped::NotClientHello)),
        Message::ClientHello(body) => body,
    };
    let Some(ech) = hello::ech(body) else {
        return Some(Err(Dropped::UnreadableExtensions));
    };
    Some(match ech {
        Ech::Outer(outer) => match policy
            .ech
            .as_deref()
            .and_then(|keys| keys.by_config_id(outer.config_id))
        {
            Some(key) if key.opens(body, &outer) => {
                if replay.admit(&body[outer.enc], from) {
                    Ok(())
                } else {
                    Err(Dropped::Replayed)
                }
            }
            _ => Err(Dropped::EchNotOpened),
        },
        Ech::Malformed => Err(Dropped::EchNotOpened),
        Ech::Absent if policy.require_ech => Err(Dropped::EchRequired),
        Ech::Absent if policy.names.is_empty() => Ok(()),
        Ech::Absent => by_name(&policy.names, hello::server_name(body)).map_err(Dropped::from),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], port))
    }

    /// The same `enc` is admitted again from its own address and refused from
    /// any other.
    #[test]
    fn a_replay_is_an_enc_seen_from_another_address() {
        let mut replay = Replay::new();
        assert!(replay.admit(b"enc-one", addr(1)));
        assert!(replay.admit(b"enc-one", addr(1)));
        assert!(!replay.admit(b"enc-one", addr(2)));
        assert!(replay.admit(b"enc-two", addr(2)));
        assert_eq!(replay.len(), 2);
    }

    /// At the limit the oldest entry goes and the newest stays.
    #[test]
    fn a_full_replay_record_forgets_its_oldest_entry() {
        let mut replay = Replay::new();
        for i in 0..REPLAY_ENTRIES {
            assert!(replay.admit(&i.to_be_bytes(), addr(1)));
        }
        assert_eq!(replay.len(), REPLAY_ENTRIES);
        assert!(replay.admit(b"one more", addr(1)));
        assert_eq!(replay.len(), REPLAY_ENTRIES);
        // The first entry is gone, so its copy from elsewhere is not caught;
        // the second is still there.
        assert!(replay.admit(&0usize.to_be_bytes(), addr(2)));
        assert!(!replay.admit(&2usize.to_be_bytes(), addr(2)));
    }

    /// Hands `memory` one datagram from `from`, addressed to `dcid`, and says
    /// whether the hold kept it and which flights it dropped on the way.
    fn take_one(
        memory: &mut Memory,
        from: SocketAddr,
        dcid: u8,
        datagram: &[u8],
        fragments: Option<&[(u64, &[u8])]>,
    ) -> (bool, Vec<(SocketAddr, Dropped)>) {
        let mut drops = Vec::new();
        let arrival = Arrival {
            now: Instant::now(),
            meta: RecvMeta {
                addr: from,
                ..RecvMeta::default()
            },
            datagram,
            dcid: ConnectionId::new(&[dcid; 8]),
        };
        let screened = memory.take(&arrival, fragments, &mut |from, why| {
            drops.push((from, why));
        });
        (screened != Screened::Dropped, drops)
    }

    /// A datagram that starts a new flight and is dropped for what it carries
    /// evicts no other flight, even with the table full: the drop is found
    /// before the table makes room.
    #[test]
    fn a_new_flight_the_hold_drops_evicts_nothing() {
        let mut memory = Memory::new(Arc::new(Policy::new(
            super::super::Names::new(&[]),
            None,
            false,
        )));
        let datagram = vec![0u8; 1200];
        // The start of a ClientHello whose declared length has not arrived.
        let start: &[(u64, &[u8])] = &[(0, &[1, 0, 0, 10])];
        for index in 0..HOLD_FLIGHTS {
            let port = u16::try_from(index).expect("small");
            let (kept, drops) = take_one(&mut memory, addr(port), 1, &datagram, Some(start));
            assert!(kept && drops.is_empty(), "flight {index} is held");
        }
        assert_eq!(memory.hold.flights(), HOLD_FLIGHTS);

        let past: &[(u64, &[u8])] = &[(u64::try_from(HOLD_HELLO_BYTES).expect("small"), b"x")];
        let large = vec![0u8; HOLD_FLIGHT_BYTES + 1];
        for (what, datagram, fragments, why) in [
            ("frames that do not parse", &datagram, None, Dropped::Frames),
            (
                "CRYPTO past the limit",
                &datagram,
                Some(past),
                Dropped::TooLong,
            ),
            (
                "a datagram past the flight bound",
                &large,
                Some(start),
                Dropped::TooBig,
            ),
        ] {
            let (kept, drops) = take_one(&mut memory, addr(9999), 2, datagram, fragments);
            assert!(!kept, "{what}: dropped");
            assert_eq!(
                drops,
                vec![(addr(9999), why)],
                "{what}: only its own flight"
            );
            assert_eq!(
                memory.hold.flights(),
                HOLD_FLIGHTS,
                "{what}: nothing evicted"
            );
            assert_eq!(memory.hold.bytes(), memory.hold.recount(), "{what}");
        }
    }
}
