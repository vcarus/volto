//! Reading and opening a QUIC Initial packet, for the gate.
//!
//! The long-header constants, the reader of an Initial packet's header, the
//! removal of header and packet protection under the Initial keys, and the
//! walk of the frames that finds the CRYPTO data. Every byte read here comes
//! from a peer that has not authenticated.

use bytes::BytesMut;

use super::MAX_CONNECTION_ID;
use crate::hello::MAX_INITIAL_FLIGHT;
use crate::tls::ClientInitialKeys;
use crate::varint::peek_varint;

/// The QUIC version this server speaks, as it appears in a long header.
pub(super) const QUIC_V1: u32 = 0x0000_0001;

/// Header Form bit: set on a long header, clear on a short one (RFC 9000 §17).
pub(super) const LONG_HEADER_FORM: u8 = 0x80;

/// Long Packet Type bits of the first byte (RFC 9000 §17.2).
pub(super) const LONG_PACKET_TYPE: u8 = 0x30;

/// The Long Packet Type of an Initial packet in QUIC v1 (RFC 9000 §17.2.2).
pub(super) const INITIAL_PACKET_TYPE: u8 = 0x00;

/// Offset of the Destination Connection ID Length field in a long header.
///
/// One byte of flags plus four of version (RFC 9000 §17.2).
pub(super) const DCID_LENGTH_OFFSET: usize = 5;

/// The QUIC frame types an Initial packet may carry (RFC 9000 §17.2.2).
const FRAME_PADDING: u64 = 0x00;
const FRAME_PING: u64 = 0x01;
const FRAME_ACK: u64 = 0x02;
const FRAME_ACK_ECN: u64 = 0x03;
const FRAME_CRYPTO: u64 = 0x06;
const FRAME_CONNECTION_CLOSE: u64 = 0x1c;

/// Removes header protection and packet protection from an Initial packet,
/// returning the Initial keys it opened under and its frames.
///
/// `None` is either a packet too short for the keys to be applied (one
/// quinn could not read either) or an authentication failure under the
/// keys this packet's own Destination Connection ID derives. The caller
/// passes both through ([`classify`](super::classify) says why).
pub(super) fn decrypt(
    datagram: &[u8],
    header: &InitialHeader,
) -> Option<(ClientInitialKeys, BytesMut)> {
    // The header key (`tls::awslc::keys`) reads its sample from four bytes
    // past the start of the packet number and indexes the buffer it is given
    // without a check, so a packet too short for that would panic rather
    // than fail. RFC 9001 §5.4.2 puts the sample there.
    //
    // Checked before the key derivation, which is most of a packet's cost;
    // `open_with` checks the half that needs the cipher's sample size.
    let number_end_limit = header.packet_number_offset.checked_add(4)?;
    if number_end_limit > header.packet_end {
        return None;
    }

    // The keys are a function of the Destination Connection ID and the
    // version alone, which is what makes this possible at all without any
    // connection state.
    //
    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.2
    //# Initial packets apply the packet protection process, but use a secret
    //# derived from the Destination Connection ID field from the client's
    //# first Initial packet.
    // The server's own key code, the one its handshakes run (D115).
    let keys = crate::tls::client_initial_keys(&datagram[header.dcid.clone()]);
    let frames = open_with(&keys, datagram, header)?;
    Some((keys, frames))
}

/// The frames of every Initial packet coalesced behind the first one of
/// `datagram`, whose header is `first` and which opened under `keys`, that
/// belongs to the same flight.
///
/// Only the hold asks for these, because only the hold reads a flight rather
/// than a packet: a client may put two Initial packets of one first flight
/// into one datagram, and the ClientHello is then not whole without the
/// second. A packet behind the first belongs to the flight when it is a
/// version 1 Initial with the same Destination Connection ID, and then it
/// opens under the same keys, which RFC 9001 §5.2 derives from that connection
/// ID, so the keys the first packet opened under are used again rather than
/// derived a second time. One that does not open is skipped, as quinn skips
/// it. The walk stops at the first packet that is anything else, because RFC
/// 9000 §12.2 lets a receiver route on the first packet alone and a short
/// header can only be last. A datagram with nothing behind its first packet,
/// which is every first flight quinn and Surge send, costs nothing here.
pub(super) fn coalesced_frames(
    keys: &ClientInitialKeys,
    datagram: &[u8],
    first: &InitialHeader,
) -> Vec<BytesMut> {
    let mut frames = Vec::new();
    let dcid = &datagram[first.dcid.clone()];
    let mut at = first.packet_end;
    while let Some(packet @ [byte, ..]) = datagram.get(at..) {
        if byte & LONG_HEADER_FORM == 0
            || byte & LONG_PACKET_TYPE != INITIAL_PACKET_TYPE
            || packet.get(1..5) != Some(&QUIC_V1.to_be_bytes()[..])
        {
            break;
        }
        let Some(header) = InitialHeader::parse(packet) else {
            break;
        };
        if packet.get(header.dcid.clone()) != Some(dcid) {
            break;
        }
        if let Some(opened) = open_with(keys, packet, &header) {
            frames.push(opened);
        }
        at += header.packet_end;
    }
    frames
}

/// Removes header protection and packet protection from the Initial packet at
/// the start of `datagram`, whose header is `header`, under `keys`.
///
/// `None` for a packet too short for the keys to be applied or one that does
/// not authenticate; [`decrypt`] says what each means.
fn open_with(
    keys: &ClientInitialKeys,
    datagram: &[u8],
    header: &InitialHeader,
) -> Option<BytesMut> {
    let number_end_limit = header.packet_number_offset.checked_add(4)?;

    // The other half, which the cipher's sample size decides.
    let sample_end = number_end_limit.checked_add(keys.header.sample_size())?;
    if sample_end > header.packet_end {
        return None;
    }

    // Only the header and the sample it is unmasked with are copied. Header
    // protection reads up to `sample_end` and writes five bytes inside it,
    // the first byte and the packet number, so the rest of the packet has
    // no reason to be moved: the payload below is taken from the datagram
    // where it already is, and the associated data the AEAD needs is inside
    // this copy.
    let mut head = datagram[..sample_end].to_vec();
    keys.header.decrypt(header.packet_number_offset, &mut head);

    // The two bits the header protection was hiding.
    let number_length = usize::from(head[0] & 0x03) + 1;
    let number_end = header.packet_number_offset.checked_add(number_length)?;
    if number_end > header.packet_end {
        return None;
    }

    // The truncated packet number, used as the full one. A client's Initial
    // packet numbers start at zero and are still single digits by the time
    // its first flight is complete, so the encoded bits are the whole number.
    // RFC 9000 §17.1 makes the sender include enough of them for a peer
    // that has acknowledged nothing to reconstruct it, and there is nothing
    // to acknowledge yet.
    let mut number = 0u64;
    for byte in &head[header.packet_number_offset..number_end] {
        number = (number << 8) | u64::from(*byte);
    }

    // The AEAD tag is the tail of the payload; a "packet" too short to hold
    // one is not one, and the check is here rather than left to the cipher
    // so that this function is total on its own terms.
    if header.packet_end - number_end < keys.packet.tag_len() {
        return None;
    }

    let mut frames = BytesMut::from(&datagram[number_end..header.packet_end]);
    keys.packet
        .decrypt(number, &head[..number_end], &mut frames)
        .ok()?;
    Some(frames)
}

/// Where the interesting parts of a long header are.
pub(super) struct InitialHeader {
    /// The Destination Connection ID, as a range into the datagram.
    pub(super) dcid: std::ops::Range<usize>,
    /// Where the Packet Number field starts.
    packet_number_offset: usize,
    /// One past the last byte of this packet, which may be followed by more.
    packet_end: usize,
}

impl InitialHeader {
    /// Reads an Initial header, or `None` if it does not fit what arrived.
    ///
    /// Every field is bounds-checked against the datagram rather than trusted,
    /// because all of it is attacker-chosen and none of it is authenticated yet.
    pub(super) fn parse(datagram: &[u8]) -> Option<Self> {
        let mut at = DCID_LENGTH_OFFSET;

        let dcid_length = usize::from(*datagram.get(at)?);
        at += 1;
        if dcid_length > MAX_CONNECTION_ID {
            return None;
        }
        let dcid = at..at.checked_add(dcid_length)?;
        datagram.get(dcid.clone())?;
        at = dcid.end;

        let scid_length = usize::from(*datagram.get(at)?);
        at += 1;
        if scid_length > MAX_CONNECTION_ID {
            return None;
        }
        at = at.checked_add(scid_length)?;
        if at > datagram.len() {
            return None;
        }

        // The Token Length and Length fields are QUIC varints (RFC 9000 §16).
        let (token_length, read) = peek_varint(datagram.get(at..)?)?;
        at = at.checked_add(read)?;
        at = at.checked_add(usize::try_from(token_length).ok()?)?;
        if at > datagram.len() {
            return None;
        }

        let (length, read) = peek_varint(datagram.get(at..)?)?;
        let packet_number_offset = at.checked_add(read)?;
        let packet_end = packet_number_offset.checked_add(usize::try_from(length).ok()?)?;
        if packet_end > datagram.len() {
            return None;
        }

        Some(Self {
            dcid,
            packet_number_offset,
            packet_end,
        })
    }
}

/// The CRYPTO frames of an Initial packet's payload, in the order they came.
pub(super) struct Frames<'a> {
    /// Each frame's offset and data.
    pub(super) fragments: Vec<(u64, &'a [u8])>,
    /// Whether the walk reached the end of the payload, rather than stopping
    /// at a frame type RFC 9000 §17.2.2 does not allow in an Initial packet.
    pub(super) whole: bool,
}

/// Walks an Initial packet's frames and collects its CRYPTO frames.
///
/// `None` is a frame whose fields do not fit the payload. Frames are walked
/// rather than searched for, because a frame's length is implied by its type
/// and skipping one wrongly would find CRYPTO data that is not there. Only the
/// frame types RFC 9000 §17.2.2 allows in an Initial packet are understood;
/// anything else ends the walk with whatever was found so far, and says so.
pub(super) fn crypto_frames(payload: &[u8]) -> Option<Frames<'_>> {
    let mut fragments: Vec<(u64, &[u8])> = Vec::new();
    let mut at = 0usize;

    while at < payload.len() {
        let (frame, read) = peek_varint(&payload[at..])?;
        at += read;

        match frame {
            FRAME_PADDING | FRAME_PING => {}
            FRAME_ACK | FRAME_ACK_ECN => {
                // Largest Acknowledged, ACK Delay, ACK Range Count, First ACK
                // Range, then two varints per additional range, then three more
                // for the ECN counts (RFC 9000 §19.3).
                at = skip_varints(payload, at, 2)?;
                let (ranges, read) = peek_varint(payload.get(at..)?)?;
                at += read;
                at = skip_varints(payload, at, 1)?;
                let ranges = usize::try_from(ranges).ok()?.checked_mul(2)?;
                at = skip_varints(payload, at, ranges)?;
                if frame == FRAME_ACK_ECN {
                    at = skip_varints(payload, at, 3)?;
                }
            }
            FRAME_CRYPTO => {
                let (offset, read) = peek_varint(payload.get(at..)?)?;
                at += read;
                let (length, read) = peek_varint(payload.get(at..)?)?;
                at += read;
                let end = at.checked_add(usize::try_from(length).ok()?)?;
                fragments.push((offset, payload.get(at..end)?));
                at = end;
            }
            FRAME_CONNECTION_CLOSE => {
                // Error Code, Frame Type, Reason Phrase Length, Reason Phrase.
                at = skip_varints(payload, at, 2)?;
                let (reason, read) = peek_varint(payload.get(at..)?)?;
                at += read;
                at = at.checked_add(usize::try_from(reason).ok()?)?;
                if at > payload.len() {
                    return None;
                }
            }
            // Not a frame type an Initial packet may carry. Stop reading rather
            // than guess: what follows is not frames as we understand them.
            _ => {
                return Some(Frames {
                    fragments,
                    whole: false,
                });
            }
        }
    }

    Some(Frames {
        fragments,
        whole: true,
    })
}

/// A CRYPTO stream reassembled from offset 0, up to [`MAX_INITIAL_FLIGHT`]:
/// the one reassembly both of the gate's judgements read a ClientHello from.
///
/// The buffer grows to the highest offset seen and a bitmap records which of
/// its bytes have arrived, so inserting a fragment costs its own length plus
/// what the buffer grows by to reach its end, which over a flight's life is at
/// most [`MAX_INITIAL_FLIGHT`], and no arrangement of fragments costs more: no
/// fragment list to sort, no interval list to merge.
#[derive(Default)]
pub(super) struct Stream {
    data: Vec<u8>,
    /// One bit per byte of `data`: set once the byte has arrived.
    have: Vec<u64>,
    /// How many bytes from offset 0 have all arrived.
    prefix: usize,
}

/// A fragment that cannot join the stream.
pub(super) enum Refused {
    /// It reaches past [`MAX_INITIAL_FLIGHT`].
    TooLong,
    /// It disagrees with bytes already there.
    Conflict,
}

impl Stream {
    /// What the buffer and the bitmap count: their lengths, not their
    /// capacity.
    pub(super) fn footprint(&self) -> usize {
        self.data.len() + self.have.len() * 8
    }

    /// What [`Stream::footprint`] would be once the buffer reaches `end`.
    pub(super) fn footprint_at(&self, end: usize) -> usize {
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
    /// judged by the gate the one quinn hands libssl, whatever order quinn's own
    /// reassembly takes the overlapping fragments in.
    pub(super) fn insert(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Refused> {
        let start = usize::try_from(offset).map_err(|_| Refused::TooLong)?;
        let end = start.checked_add(bytes.len()).ok_or(Refused::TooLong)?;
        if end > MAX_INITIAL_FLIGHT {
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
    pub(super) fn contiguous(&self) -> &[u8] {
        &self.data[..self.prefix]
    }
}

/// Advances past `count` varints, or `None` if they do not all fit.
fn skip_varints(payload: &[u8], mut at: usize, count: usize) -> Option<usize> {
    for _ in 0..count {
        let (_, read) = peek_varint(payload.get(at..)?)?;
        at = at.checked_add(read)?;
    }
    Some(at)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CRYPTO frames of `payload` as the walk finds them.
    fn fragments(payload: &[u8]) -> Vec<(u64, &[u8])> {
        let walk = crypto_frames(payload).expect("the frames parse");
        assert!(walk.whole, "every frame is one an Initial may carry");
        walk.fragments
    }

    #[test]
    fn padding_and_ping_do_not_hide_the_crypto_frame() {
        let mut payload = vec![0x00; 16]; // PADDING
        payload.push(0x01); // PING
        payload.extend_from_slice(&[0x06, 0x00, 0x02, b'h', b'i']);
        payload.extend_from_slice(&[0x00; 8]); // trailing PADDING

        assert_eq!(fragments(&payload), vec![(0, &b"hi"[..])]);
    }

    #[test]
    fn an_ack_frame_is_skipped_by_its_own_shape() {
        // ACK: largest 1, delay 0, range count 1, first range 0, then one range
        // pair (gap 0, length 0); followed by the CRYPTO frame that matters.
        let mut payload = vec![0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00];
        payload.extend_from_slice(&[0x06, 0x00, 0x01, b'x']);

        assert_eq!(fragments(&payload), vec![(0, &b"x"[..])]);
    }

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
        let limit = u64::try_from(MAX_INITIAL_FLIGHT).expect("small");
        assert!(stream.insert(limit - 1, b"a").is_ok());
        assert!(matches!(stream.insert(limit, b"b"), Err(Refused::TooLong)));
        assert!(matches!(
            stream.insert(u64::MAX, b"c"),
            Err(Refused::TooLong)
        ));
        assert_eq!(stream.data.len(), MAX_INITIAL_FLIGHT);
        assert_eq!(
            stream.footprint(),
            MAX_INITIAL_FLIGHT + MAX_INITIAL_FLIGHT / 8
        );
    }

    /// The header reader is total: no input makes it panic, and none of the
    /// lengths in it can be trusted into an overflow.
    #[test]
    fn the_initial_header_reader_is_total() {
        for byte in 0u16..=255 {
            let datagram = vec![u8::try_from(byte).unwrap(); 64];
            let _ = InitialHeader::parse(&datagram);
        }

        // A token length that claims the whole varint space.
        let mut datagram = vec![0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
        datagram.extend_from_slice(&[0xff; 8]); // token length varint, huge
        datagram.extend_from_slice(&[0x00; 32]);
        assert!(InitialHeader::parse(&datagram).is_none());
    }

    #[test]
    fn a_frame_walk_is_total_over_arbitrary_bytes() {
        for seed in 0u16..=255 {
            let payload: Vec<u8> = (0..64u16)
                .map(|i| u8::try_from((i.wrapping_mul(31).wrapping_add(seed)) & 0xff).unwrap())
                .collect();
            let _ = crypto_frames(&payload);
        }
    }
}
