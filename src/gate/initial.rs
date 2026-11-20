//! Reading and opening a QUIC Initial packet, for the gate.
//!
//! The long-header constants, the reader of an Initial packet's header, the
//! removal of header and packet protection under the Initial keys, and the
//! walk of the frames that finds the CRYPTO data. Every byte read here comes
//! from a peer that has not authenticated.

use std::borrow::Cow;

use bytes::BytesMut;

use super::MAX_CONNECTION_ID;
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
) -> Option<(quinn::crypto::Keys, BytesMut)> {
    // The header key (`tls::awslc::keys`) reads its sample from four bytes
    // past the start of the packet number and indexes the buffer it is given
    // without a check, so a packet too short for that would panic rather
    // than fail. RFC 9001 §5.4.2 puts the sample there.
    //
    // The half of that test which does not need a cipher is asked first,
    // above the key derivation, because deriving Initial secrets is nearly
    // the whole cost of judging a packet and a packet with no room for the
    // four bytes is refused under every cipher there is. No packet changes
    // verdict: a sample end past the packet end follows from this one.
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
    let keys = crate::tls::server_initial_keys(&datagram[header.dcid.clone()]);
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
    keys: &quinn::crypto::Keys,
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
    keys: &quinn::crypto::Keys,
    datagram: &[u8],
    header: &InitialHeader,
) -> Option<BytesMut> {
    let number_end_limit = header.packet_number_offset.checked_add(4)?;

    // The other half, which the cipher's sample size decides.
    let sample_end = number_end_limit.checked_add(keys.header.remote.sample_size())?;
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
    keys.header
        .remote
        .decrypt(header.packet_number_offset, &mut head);

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
    if header.packet_end - number_end < keys.packet.remote.tag_len() {
        return None;
    }

    let mut frames = BytesMut::from(&datagram[number_end..header.packet_end]);
    keys.packet
        .remote
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

        // The Token Length and Length fields are QUIC varints, the same encoding
        // `crate::datagram` reads for HTTP Datagrams (RFC 9000 §16).
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

/// The CRYPTO stream bytes an Initial packet carries from offset 0 onwards.
///
/// `None` means the packet has no CRYPTO frame starting at offset 0 (an
/// acknowledgement, or a retransmitted middle of a first flight), which is the
/// case the stateless gate passes through rather than judging. The frames are
/// those [`crypto_frames`] finds.
pub(super) fn crypto_stream_prefix(payload: &[u8]) -> Option<Cow<'_, [u8]>> {
    let mut fragments = crypto_frames(payload)?.fragments;

    // Sorted and appended while contiguous, so a first flight split across
    // several CRYPTO frames in one packet reads as one stream.
    fragments.sort_by_key(|(offset, _)| *offset);

    // In practice there is exactly one frame and it starts at offset 0, which
    // is a first flight that fits in one packet, so that case is borrowed out
    // of the decrypted frames rather than copied into a second buffer.
    if let [(0, data)] = fragments.as_slice() {
        return (!data.is_empty()).then_some(Cow::Borrowed(*data));
    }

    let mut stream: Vec<u8> = Vec::new();
    for (offset, data) in fragments {
        let offset = usize::try_from(offset).ok()?;
        if offset > stream.len() {
            break;
        }
        // A retransmission may overlap what is already here.
        let skip = stream.len() - offset;
        if let Some(fresh) = data.get(skip..) {
            stream.extend_from_slice(fresh);
        }
    }

    (!stream.is_empty()).then_some(Cow::Owned(stream))
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
    use std::assert_matches;

    #[test]
    fn a_crypto_frame_at_offset_zero_is_the_one_that_is_read() {
        // CRYPTO, offset 0, length 3.
        let payload = [0x06, 0x00, 0x03, b'a', b'b', b'c'];
        // One fragment at offset 0, which is every first flight that fits in one
        // packet, is borrowed out of the frames rather than copied.
        assert_matches!(crypto_stream_prefix(&payload), Some(Cow::Borrowed(b"abc")));
        assert_eq!(crypto_stream_prefix(&payload).as_deref(), Some(&b"abc"[..]));

        // The same frame at offset 1 carries no beginning to judge.
        let payload = [0x06, 0x01, 0x03, b'a', b'b', b'c'];
        assert_eq!(crypto_stream_prefix(&payload), None);
    }

    #[test]
    fn padding_and_ping_do_not_hide_the_crypto_frame() {
        let mut payload = vec![0x00; 16]; // PADDING
        payload.push(0x01); // PING
        payload.extend_from_slice(&[0x06, 0x00, 0x02, b'h', b'i']);
        payload.extend_from_slice(&[0x00; 8]); // trailing PADDING

        assert_eq!(crypto_stream_prefix(&payload).as_deref(), Some(&b"hi"[..]));
    }

    #[test]
    fn an_ack_frame_is_skipped_by_its_own_shape() {
        // ACK: largest 1, delay 0, range count 1, first range 0, then one range
        // pair (gap 0, length 0); followed by the CRYPTO frame that matters.
        let mut payload = vec![0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00];
        payload.extend_from_slice(&[0x06, 0x00, 0x01, b'x']);

        assert_eq!(crypto_stream_prefix(&payload).as_deref(), Some(&b"x"[..]));
    }

    #[test]
    fn two_crypto_frames_are_joined_in_offset_order() {
        let mut payload = vec![0x06, 0x02, 0x02, b'c', b'd']; // offset 2
        payload.extend_from_slice(&[0x06, 0x00, 0x02, b'a', b'b']); // offset 0

        assert_eq!(
            crypto_stream_prefix(&payload).as_deref(),
            Some(&b"abcd"[..])
        );
    }

    /// A gap is not filled in: what is returned is the contiguous prefix, and a
    /// ClientHello read out of a stream with a hole in it would be nonsense.
    #[test]
    fn a_gap_ends_the_assembled_prefix() {
        let mut payload = vec![0x06, 0x00, 0x02, b'a', b'b']; // offset 0
        payload.extend_from_slice(&[0x06, 0x09, 0x02, b'y', b'z']); // offset 9

        assert_eq!(crypto_stream_prefix(&payload).as_deref(), Some(&b"ab"[..]));
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
            let _ = crypto_stream_prefix(&payload);
        }
    }
}
