//! The state the gate keeps while an ECH key is configured: first flights held
//! until their ClientHello is whole, and the record of every ECH flight the key
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
use std::time::{Duration, Instant};

use quinn::ConnectionId;
use quinn::udp::RecvMeta;

use crate::hello::{self, Ech, Message};

use super::Policy;

/// How long a first flight is held for its ClientHello to complete.
///
/// The packets of one first flight leave the client in one burst, so on any
/// path they arrive within milliseconds of each other. The rest of the window
/// is for loss: a client that hears nothing sends its flight again after one
/// probe timeout, about one second for a client that starts from the 333 ms
/// initial RTT quinn and this server default to, and two seconds lets that
/// retransmission join the packets of the first attempt that did arrive. A
/// flight that is still incomplete after this is dropped without a reply. Our
/// own value.
pub const HOLD_LIFETIME: Duration = Duration::from_secs(2);

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

/// The most CRYPTO stream bytes the hold reassembles for one flight.
///
/// libssl's own limit for the Initial level (`SSL_quic_max_handshake_flight_len`
/// at `ssl_encryption_initial`): `SSL_provide_quic_data` refuses a longer
/// flight, so no ClientHello libssl reads is longer. A flight whose CRYPTO
/// bytes reach past it, or whose ClientHello says it is longer, is dropped.
pub const HOLD_HELLO_BYTES: usize = 16 * 1024;

/// The most bytes one held flight may occupy: its datagrams as received, plus
/// the buffer its CRYPTO stream is reassembled in.
///
/// The largest ClientHello the hold reassembles ([`HOLD_HELLO_BYTES`]) takes
/// about fifteen Initial packets of 1500 bytes, which with its reassembly
/// buffer is about 40 KiB; this leaves room above that for duplicates. A
/// ClientHello of a client this server serves is under 2 KiB in two packets.
/// A flight that would grow past it is dropped. Our own value.
pub const HOLD_FLIGHT_BYTES: usize = 64 * 1024;

/// The most bytes the hold occupies in all: every held flight, and the
/// released datagrams waiting for the next receive call.
///
/// [`HOLD_FLIGHTS`] flights at [`HOLD_FLIGHT_BYTES`] each, 4 MiB. A datagram
/// that would push the hold past it evicts the oldest flights first, as a full
/// table does.
pub const HOLD_TOTAL_BYTES: usize = HOLD_FLIGHTS * HOLD_FLIGHT_BYTES;

/// How many admitted ECH flights the replay record remembers.
///
/// The record does not expire by time, because an entry that expired would let
/// a copy of that flight, sent from another address, draw a ServerHello. It is
/// bounded by count instead, at 2^20 entries: about 800 connections a day on
/// the busier of the two hosts fill it in three and a half years. At the limit
/// the oldest entry goes, so a copy of a flight older than the last 2^20
/// admitted ones is no longer recognised. An entry is two 64-bit tags in the
/// map and one in the order queue, so a full record is about 44 MiB with the
/// map's spare capacity. Only a flight the key opened adds an entry. Our own
/// value.
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
    /// A whole ClientHello that libssl would refuse to parse.
    Unreadable,
    /// CRYPTO bytes, or a ClientHello length, past [`HOLD_HELLO_BYTES`].
    TooLong,
    /// Two packets of the flight carried different bytes at one offset.
    Conflict,
    /// A packet of the flight carried frames that do not parse, or a frame no
    /// Initial packet may carry.
    Frames,
    /// An ECH extension this server's key does not open.
    EchNotOpened,
    /// An ECH extension the key opened, already admitted from another address.
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

/// A CRYPTO stream reassembled from offset 0, up to [`HOLD_HELLO_BYTES`].
///
/// The buffer grows to the highest offset seen and a bitmap records which of
/// its bytes have arrived, so inserting a fragment costs its own length and no
/// arrangement of fragments costs more: no fragment list to sort, no interval
/// list to merge.
#[derive(Default)]
struct Stream {
    data: Vec<u8>,
    /// One bit per byte of `data`: set once the byte has arrived.
    have: Vec<u64>,
    /// How many bytes from offset 0 have all arrived.
    prefix: usize,
}

/// A fragment that cannot join the stream.
enum Refused {
    /// It reaches past [`HOLD_HELLO_BYTES`].
    TooLong,
    /// It disagrees with bytes already there.
    Conflict,
}

impl Stream {
    /// What the buffer and the bitmap occupy.
    fn footprint(&self) -> usize {
        self.data.len() + self.have.len() * 8
    }

    /// What [`Stream::footprint`] would be once the buffer reaches `end`.
    fn footprint_at(&self, end: usize) -> usize {
        let end = end.max(self.data.len());
        end + end.div_ceil(64) * 8
    }

    fn has(&self, at: usize) -> bool {
        self.have[at / 64] & (1 << (at % 64)) != 0
    }

    /// Adds `bytes` at `offset`.
    ///
    /// A byte that is already there must be the same byte again. RFC 9000
    /// §2.2: "The data at a given offset MUST NOT change if it is sent
    /// multiple times; an endpoint MAY treat receipt of different data at the
    /// same offset within a stream as a connection error of type
    /// PROTOCOL_VIOLATION." and §19.6: "CRYPTO frames are functionally
    /// identical to STREAM frames, except that they do not bear a stream
    /// identifier". Refusing the difference is what makes the ClientHello
    /// judged here the one quinn hands libssl, whatever order quinn's own
    /// reassembly takes the overlapping fragments in.
    fn insert(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Refused> {
        let start = usize::try_from(offset).map_err(|_| Refused::TooLong)?;
        let end = start.checked_add(bytes.len()).ok_or(Refused::TooLong)?;
        if end > HOLD_HELLO_BYTES {
            return Err(Refused::TooLong);
        }
        // An empty fragment carries nothing, and must not grow the buffer to
        // its offset.
        if bytes.is_empty() {
            return Ok(());
        }
        // Checked whole before anything is written, so a refused fragment
        // leaves the stream as it was.
        for (index, byte) in bytes.iter().enumerate() {
            let at = start + index;
            if at < self.data.len() && self.has(at) && self.data[at] != *byte {
                return Err(Refused::Conflict);
            }
        }
        if end > self.data.len() {
            self.data.resize(end, 0);
            self.have.resize(end.div_ceil(64), 0);
        }
        self.data[start..end].copy_from_slice(bytes);
        for at in start..end {
            self.have[at / 64] |= 1 << (at % 64);
        }
        while self.prefix < self.data.len() && self.has(self.prefix) {
            self.prefix += 1;
        }
        Ok(())
    }

    /// The bytes from offset 0 that have all arrived.
    fn contiguous(&self) -> &[u8] {
        &self.data[..self.prefix]
    }
}

/// The record of every ECH flight the key opened: its HPKE `enc` and the
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
    /// address is a copy of somebody else's flight. Our own rule; RFC 9849
    /// leaves replay of a ClientHelloOuter to the TLS layer, which answers it.
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

    /// Forgets every entry, for a reload that changed the key.
    pub(super) fn clear(&mut self) {
        self.seen = HashMap::new();
        self.order = VecDeque::new();
    }

    /// How many entries there are.
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

/// What became of one datagram the hold was given.
pub(super) enum Taken {
    /// It is held.
    Held,
    /// It completed its flight, which was admitted: every datagram of it is in
    /// `released`.
    Released,
}

impl Hold {
    fn new() -> Self {
        Self {
            flights: VecDeque::new(),
            released: VecDeque::new(),
            bytes: 0,
        }
    }

    /// How many flights are held.
    pub(super) fn flights(&self) -> usize {
        self.flights.len()
    }

    /// Every byte the hold occupies.
    pub(super) fn bytes(&self) -> usize {
        self.bytes
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
}

/// The hold and the replay record, behind one lock in the gate.
pub(super) struct Memory {
    pub(super) hold: Hold,
    pub(super) replay: Replay,
}

impl Memory {
    pub(super) fn new() -> Self {
        Self {
            hold: Hold::new(),
            replay: Replay::new(),
        }
    }

    /// Holds one opened first Initial and, if it completes its flight, judges
    /// the flight.
    ///
    /// `fragments` are the CRYPTO frames of the datagram's first packet, or
    /// `None` when its frames do not parse. Every flight dropped on the way,
    /// this one or another, is reported once through `report`, and `None` is
    /// this datagram's own flight dropped.
    pub(super) fn take(
        &mut self,
        arrival: Arrival<'_>,
        fragments: Option<&[(u64, &[u8])]>,
        policy: &Policy,
        report: &mut dyn FnMut(SocketAddr, Dropped),
    ) -> Option<Taken> {
        let Arrival {
            now,
            meta,
            datagram,
            dcid,
        } = arrival;
        let from = meta.addr;
        self.hold.expire(now, report);

        let index = match self
            .hold
            .flights
            .iter()
            .position(|f| f.dcid == dcid && f.from == from)
        {
            Some(index) => index,
            None => {
                if self.hold.flights.len() >= HOLD_FLIGHTS
                    && let Some(oldest) = self.hold.remove(0)
                {
                    report(oldest.from, Dropped::Evicted);
                }
                self.hold.flights.push_back(Flight {
                    dcid,
                    from,
                    started: now,
                    datagrams: Vec::new(),
                    datagram_bytes: 0,
                    stream: Stream::default(),
                });
                self.hold.flights.len() - 1
            }
        };

        let Some(fragments) = fragments else {
            return self.drop_flight(index, Dropped::Frames, report);
        };

        // What the flight would occupy with this datagram in it.
        let mut end = 0usize;
        for (offset, bytes) in fragments.iter().filter(|(_, bytes)| !bytes.is_empty()) {
            let Some(stop) = usize::try_from(*offset)
                .ok()
                .and_then(|start| start.checked_add(bytes.len()))
                .filter(|stop| *stop <= HOLD_HELLO_BYTES)
            else {
                return self.drop_flight(index, Dropped::TooLong, report);
            };
            end = end.max(stop);
        }
        let flight = &self.hold.flights[index];
        let after = flight.datagram_bytes + datagram.len() + flight.stream.footprint_at(end);
        if after > HOLD_FLIGHT_BYTES {
            return self.drop_flight(index, Dropped::TooBig, report);
        }
        let growth = after - flight.bytes();
        // Room in the hold as a whole: the oldest other flights make way, as
        // a full table does.
        let mut index = index;
        while self.hold.bytes + growth > HOLD_TOTAL_BYTES && index > 0 {
            if let Some(oldest) = self.hold.remove(0) {
                report(oldest.from, Dropped::Evicted);
            }
            index -= 1;
        }
        if self.hold.bytes + growth > HOLD_TOTAL_BYTES {
            return self.drop_flight(index, Dropped::Evicted, report);
        }

        let flight = &mut self.hold.flights[index];
        for (offset, bytes) in fragments {
            if let Err(refused) = flight.stream.insert(*offset, bytes) {
                let why = match refused {
                    Refused::TooLong => Dropped::TooLong,
                    Refused::Conflict => Dropped::Conflict,
                };
                return self.drop_flight(index, why, report);
            }
        }
        flight.datagrams.push(HeldDatagram {
            meta,
            bytes: datagram.to_vec(),
        });
        flight.datagram_bytes += datagram.len();
        self.hold.bytes += growth;

        match judge(
            self.hold.flights[index].stream.contiguous(),
            policy,
            from,
            &mut self.replay,
        ) {
            None => Some(Taken::Held),
            Some(Err(why)) => self.drop_flight(index, why, report),
            Some(Ok(())) => {
                let flight = self.hold.remove(index)?;
                for datagram in flight.datagrams {
                    self.hold.bytes += datagram.bytes.len();
                    self.hold.released.push_back(datagram);
                }
                Some(Taken::Released)
            }
        }
    }

    /// Drops the flight at `index` and reports why.
    fn drop_flight(
        &mut self,
        index: usize,
        why: Dropped,
        report: &mut dyn FnMut(SocketAddr, Dropped),
    ) -> Option<Taken> {
        let flight = self.hold.remove(index)?;
        report(flight.from, why);
        None
    }
}

/// The verdict on a flight whose CRYPTO stream starts with `contiguous`:
/// `None` while the ClientHello is not whole, `Ok` to admit it.
///
/// The rule table of D115's batch 2, in the order a ClientHello answers it:
///
/// 1. An ECH extension that opens under the key is admitted, unless the
///    replay record holds its `enc` from another address. The outer name is
///    not consulted: the name a client asks for is the inner one, and the TLS
///    layer judges that one against `expected_sni`.
/// 2. An ECH extension that does not open, or is not a well-formed outer one,
///    is dropped, whether or not `require_ech` is on. Our own rule and a
///    deviation from RFC 9849 §7.1, which has the server go on with the outer
///    ClientHello: "Otherwise, if all candidate ECHConfig values fail to
///    decrypt the extension, the client-facing server MUST ignore the extension
///    and proceed with the connection using ClientHelloOuter". Going on would
///    send this server's ECHConfigList as `retry_configs` to a peer without
///    the key (D115, ruling 2 of 2026-11-20).
/// 3. No ECH extension is dropped under `require_ech`, and otherwise judged by
///    its name exactly as the stateless gate judges one, with an empty list
///    admitting every name.
///
/// A whole ClientHello that libssl would refuse to parse is dropped before
/// any of that, because this gate cannot say whether it carries an ECH
/// extension, and libssl, which would read it differently or not at all, is
/// the parser the rule protects.
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
        return Some(Err(Dropped::Unreadable));
    };
    Some(match ech {
        Ech::Outer(outer) => match policy.ech.as_deref() {
            Some(key) if key.opens(body, &outer) => {
                if replay.admit(&body[outer.enc.clone()], from) {
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
        Ech::Absent => match hello::server_name(body) {
            None => Err(Dropped::Anonymous),
            Some(name) => match std::str::from_utf8(name) {
                Ok(text) if policy.names.accepts(text) => Ok(()),
                _ => Err(Dropped::OtherName(name.to_vec())),
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stream_is_joined_from_fragments_in_any_order() {
        let mut stream = Stream::default();
        assert!(stream.insert(4, b"efgh").is_ok());
        assert_eq!(stream.contiguous(), b"");
        assert!(stream.insert(0, b"abcd").is_ok());
        assert_eq!(stream.contiguous(), b"abcdefgh");
        // A duplicate is welcome, a gap ends the prefix.
        assert!(stream.insert(2, b"cdef").is_ok());
        assert!(stream.insert(100, b"z").is_ok());
        assert_eq!(stream.contiguous(), b"abcdefgh");
        assert_eq!(stream.data.len(), 101);
    }

    /// A byte sent twice with two values is refused, and refusing it changes
    /// nothing that was there.
    #[test]
    fn a_fragment_that_disagrees_with_the_stream_is_refused_whole() {
        let mut stream = Stream::default();
        assert!(stream.insert(0, b"abcd").is_ok());
        assert!(matches!(stream.insert(2, b"cX"), Err(Refused::Conflict)));
        assert!(matches!(stream.insert(3, b"dZZ"), Ok(())));
        assert!(matches!(stream.insert(1, b"bc!"), Err(Refused::Conflict)));
        assert_eq!(stream.contiguous(), b"abcdZZ");
    }

    #[test]
    fn a_fragment_past_the_hello_limit_is_refused() {
        let mut stream = Stream::default();
        let limit = u64::try_from(HOLD_HELLO_BYTES).expect("small");
        assert!(stream.insert(limit - 1, b"a").is_ok());
        assert!(matches!(stream.insert(limit, b"b"), Err(Refused::TooLong)));
        assert!(matches!(
            stream.insert(u64::MAX, b"c"),
            Err(Refused::TooLong)
        ));
        assert_eq!(stream.data.len(), HOLD_HELLO_BYTES);
        assert_eq!(stream.footprint(), HOLD_HELLO_BYTES + HOLD_HELLO_BYTES / 8);
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], port))
    }

    /// The same `enc` is admitted again from its own address and refused from
    /// any other, and a cleared record forgets it.
    #[test]
    fn a_replay_is_an_enc_seen_from_another_address() {
        let mut replay = Replay::new();
        assert!(replay.admit(b"enc-one", addr(1)));
        assert!(replay.admit(b"enc-one", addr(1)));
        assert!(!replay.admit(b"enc-one", addr(2)));
        assert!(replay.admit(b"enc-two", addr(2)));
        assert_eq!(replay.len(), 2);
        replay.clear();
        assert_eq!(replay.len(), 0);
        assert!(replay.admit(b"enc-one", addr(2)));
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
}
