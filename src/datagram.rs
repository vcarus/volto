//! HTTP Datagram payload coding (RFC 9297) and QUIC varints (RFC 9000 §16).
//!
//! An HTTP/3 datagram carried in a QUIC DATAGRAM frame is:
//!
//! ```text
//! Quarter Stream ID (varint) | Context ID (varint) | payload
//! ```
//!
//! The **Quarter Stream ID** is the request stream's id divided by four
//! (RFC 9297 §2.1) — not the stream id itself. Getting this wrong is the failure
//! mode that makes every UDP session after the first on a connection misroute,
//! which is exactly the `h3-datagram` 0.0.2 bug this crate avoids by encoding
//! datagrams here instead. The unit tests below pin the relationship.
//!
//! For CONNECT-UDP the Context ID is 0, meaning "the payload is a raw UDP
//! datagram" (RFC 9298 §4).

use bytes::{BufMut, Bytes, BytesMut};

/// Context ID for an unmodified UDP payload (RFC 9298 §4).
pub const CONTEXT_ID_UDP_PAYLOAD: u64 = 0;

/// Largest UDP payload that can be represented (RFC 9298 §5).
///
/// A UDP datagram's length field covers the 8-byte header, so the payload cannot
/// exceed `65535 - 8`.
pub const MAX_UDP_PAYLOAD: usize = 65527;

/// Largest value a QUIC varint can hold (RFC 9000 §16).
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Largest legal Quarter Stream ID (RFC 9297 §2.1).
///
/// "The largest legal QUIC stream ID value is 2^62-1, so the largest legal value
/// of the Quarter Stream ID field is 2^60-1." A varint can carry more than that,
/// so the excess has to be rejected here rather than assumed away.
pub const MAX_QUARTER_STREAM_ID: u64 = (1 << 60) - 1;

/// Why a datagram could not be decoded.
///
/// The three cases are kept apart because RFC 9297 §2.1 treats them differently:
/// the two that are about the Quarter Stream ID field are connection errors,
/// while a Context ID that does not parse is not covered by any such rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The payload was too short to hold a Quarter Stream ID.
    MissingQuarterStreamId,
    /// The Quarter Stream ID is larger than [`MAX_QUARTER_STREAM_ID`].
    QuarterStreamIdTooLarge(u64),
    /// The Quarter Stream ID parsed, but the Context ID varint did not.
    MissingContextId,
}

impl DecodeError {
    /// Whether RFC 9297 §2.1 requires the whole connection to be closed.
    ///
    /// Two MUSTs, both about the Quarter Stream ID field: a datagram carrying a
    /// value above 2^60-1, and one "whose payload is too short to allow parsing
    /// the Quarter Stream ID field", must each "be treated as an HTTP/3
    /// connection error of type H3_DATAGRAM_ERROR (0x33)". Both are quoted
    /// verbatim, with their machine-readable anchors, where they are acted on --
    /// `h3::connection::route_datagram` -- and this is the pointer to them
    /// rather than a second copy (D74).
    ///
    /// A truncated Context ID is deliberately *not* one of them. Nothing in
    /// RFC 9298 §5 says what to do with it, so dropping the datagram is
    /// legitimate, and escalating a droppable condition into a connection error
    /// would hand the peer a way to kill every session at once.
    pub fn is_connection_error(self) -> bool {
        matches!(
            self,
            Self::MissingQuarterStreamId | Self::QuarterStreamIdTooLarge(_)
        )
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingQuarterStreamId => {
                write!(f, "datagram ended before its quarter stream id")
            }
            Self::QuarterStreamIdTooLarge(value) => write!(
                f,
                "quarter stream id {value} exceeds the legal maximum {MAX_QUARTER_STREAM_ID}"
            ),
            Self::MissingContextId => write!(f, "datagram ended before its context id"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A decoded HTTP/3 datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// Request stream id divided by four (RFC 9297 §2.1).
    pub quarter_stream_id: u64,
    /// Payload interpretation; 0 is a raw UDP payload.
    pub context_id: u64,
    /// Everything after the two varints.
    pub payload: Bytes,
}

/// The Quarter Stream ID identifying the session on `stream_id`.
///
/// RFC 9297 §2.1: request streams are the client-initiated bidirectional
/// streams, whose ids are multiples of four, so dividing by four loses nothing.
#[inline]
pub fn quarter_stream_id(stream_id: u64) -> u64 {
    stream_id >> 2
}

/// Encodes a datagram for `quarter_stream_id` carrying a raw UDP payload.
pub fn encode_udp_payload(quarter_stream_id: u64, payload: &[u8]) -> Bytes {
    encode(quarter_stream_id, CONTEXT_ID_UDP_PAYLOAD, payload)
}

/// Encodes an HTTP/3 datagram.
pub fn encode(quarter_stream_id: u64, context_id: u64, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(
        varint_len(quarter_stream_id) + varint_len(context_id) + payload.len(),
    );
    put_varint(&mut buf, quarter_stream_id);
    put_varint(&mut buf, context_id);
    buf.put_slice(payload);
    buf.freeze()
}

/// The number of bytes [`encode`] will produce.
///
/// Used to decide whether a packet fits in a QUIC datagram before copying it.
pub fn encoded_len(quarter_stream_id: u64, context_id: u64, payload_len: usize) -> usize {
    varint_len(quarter_stream_id) + varint_len(context_id) + payload_len
}

/// Decodes an HTTP/3 datagram, sharing the payload buffer rather than copying.
///
/// The Quarter Stream ID is validated here rather than by the caller: RFC 9297
/// §2.1 makes an out-of-range value a connection error, which is only
/// distinguishable from "no session owns this id" if decoding says so.
pub fn decode(mut datagram: Bytes) -> Result<Datagram, DecodeError> {
    let quarter_stream_id =
        take_varint(&mut datagram).ok_or(DecodeError::MissingQuarterStreamId)?;
    if quarter_stream_id > MAX_QUARTER_STREAM_ID {
        return Err(DecodeError::QuarterStreamIdTooLarge(quarter_stream_id));
    }

    let context_id = take_varint(&mut datagram).ok_or(DecodeError::MissingContextId)?;

    Ok(Datagram {
        quarter_stream_id,
        context_id,
        payload: datagram,
    })
}

/// Encoded length of `value` as a QUIC varint.
#[inline]
pub fn varint_len(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}

/// Appends `value` as a QUIC varint.
///
/// # Panics
///
/// If `value` exceeds [`VARINT_MAX`], which is unrepresentable.
pub fn put_varint(buf: &mut BytesMut, value: u64) {
    assert!(
        value <= VARINT_MAX,
        "{value} is too large for a QUIC varint"
    );

    match varint_len(value) {
        1 => buf.put_u8(value as u8),
        2 => buf.put_u16(0x4000 | value as u16),
        4 => buf.put_u32(0x8000_0000 | value as u32),
        _ => buf.put_u64(0xc000_0000_0000_0000 | value),
    }
}

/// Reads a QUIC varint from the front of `buf`, consuming it.
///
/// `None` means the buffer does not hold a whole varint. Which error that is
/// depends on which field was being read, so the caller names it.
pub fn take_varint(buf: &mut Bytes) -> Option<u64> {
    let (value, length) = peek_varint(buf)?;
    let _ = buf.split_to(length);
    Some(value)
}

/// Decodes the varint at the start of `buf`, returning it and its byte length.
///
/// `None` means the buffer does not yet hold the whole varint, which is a
/// "need more bytes" signal for incremental parsers, not an error.
pub fn peek_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    // The two most significant bits give the length as a power of two.
    let length = 1usize << (first >> 6);
    if buf.len() < length {
        return None;
    }

    let mut value = u64::from(first & 0x3f);
    for byte in &buf[1..length] {
        value = (value << 8) | u64::from(*byte);
    }

    Some((value, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarter_stream_id_is_the_stream_id_over_four() {
        // Client-initiated bidirectional streams: 0, 4, 8, 12, ...
        assert_eq!(quarter_stream_id(0), 0);
        assert_eq!(quarter_stream_id(4), 1);
        assert_eq!(quarter_stream_id(8), 2);
        assert_eq!(quarter_stream_id(400), 100);
    }

    /// The regression that motivates this module: distinct sessions must encode
    /// to distinct Quarter Stream IDs. `h3-datagram` 0.0.2 emitted zero for all
    /// of them, misrouting every session after the first.
    #[test]
    fn distinct_streams_encode_to_distinct_datagrams() {
        let mut seen = std::collections::HashSet::new();
        for stream_id in [0u64, 4, 8, 12, 400, 4000] {
            let qsid = quarter_stream_id(stream_id);
            let encoded = encode_udp_payload(qsid, b"payload");
            let decoded = decode(encoded).expect("decodes");

            assert_eq!(decoded.quarter_stream_id, qsid);
            assert_eq!(decoded.context_id, CONTEXT_ID_UDP_PAYLOAD);
            assert_eq!(&decoded.payload[..], b"payload");
            assert!(seen.insert(decoded.quarter_stream_id), "duplicate QSID");
        }
        assert_eq!(seen.len(), 6);
    }

    #[test]
    fn varint_round_trips_at_every_length_boundary() {
        let values = [
            0,
            1,
            0x3f,
            0x40,
            0x3fff,
            0x4000,
            0x3fff_ffff,
            0x4000_0000,
            VARINT_MAX,
        ];

        for value in values {
            let mut buf = BytesMut::new();
            put_varint(&mut buf, value);
            assert_eq!(buf.len(), varint_len(value), "length for {value}");

            let (decoded, length) = peek_varint(&buf).expect("decodes");
            assert_eq!(decoded, value);
            assert_eq!(length, buf.len());
        }
    }

    /// The examples given in RFC 9000 §16.
    #[test]
    fn varint_matches_the_rfc_examples() {
        let cases: [(u64, &[u8]); 4] = [
            (37, &[0x25]),
            (15293, &[0x7b, 0xbd]),
            (494_878_333, &[0x9d, 0x7f, 0x3e, 0x7d]),
            (
                151_288_809_941_952_652,
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
            ),
        ];

        for (value, expected) in cases {
            let mut buf = BytesMut::new();
            put_varint(&mut buf, value);
            assert_eq!(&buf[..], expected, "encoding of {value}");
            assert_eq!(peek_varint(expected).expect("decodes").0, value);
        }
    }

    #[test]
    fn multi_byte_encodings_decode_to_the_same_value() {
        // RFC 9000 permits a longer-than-necessary encoding; decoding must
        // accept it even though we never produce it.
        assert_eq!(peek_varint(&[0x40, 0x25]), Some((37, 2)));
        assert_eq!(peek_varint(&[0x80, 0x00, 0x00, 0x25]), Some((37, 4)));
    }

    #[test]
    fn truncated_varints_are_reported_as_needing_more_bytes() {
        assert_eq!(peek_varint(&[]), None);
        assert_eq!(peek_varint(&[0x7b]), None, "2-byte varint, 1 byte present");
        assert_eq!(peek_varint(&[0x9d, 0x7f]), None, "4-byte varint");
        assert_eq!(peek_varint(&[0xc2; 7]), None, "8-byte varint");
    }

    /// The two truncations are different conditions, and RFC 9297 §2.1 only
    /// makes the first of them a connection error.
    #[test]
    fn truncated_datagrams_are_rejected() {
        assert_eq!(
            decode(Bytes::new()),
            Err(DecodeError::MissingQuarterStreamId)
        );
        // A first byte announcing an 8-byte varint, with one byte present.
        assert_eq!(
            decode(Bytes::from_static(&[0xc0])),
            Err(DecodeError::MissingQuarterStreamId)
        );
        // A Quarter Stream ID but no Context ID.
        assert_eq!(
            decode(Bytes::from_static(&[0x04])),
            Err(DecodeError::MissingContextId)
        );
    }

    /// RFC 9297 §2.1: a Quarter Stream ID above 2^60-1 could not name a QUIC
    /// stream, and is a connection error rather than an unknown session.
    #[test]
    fn quarter_stream_ids_above_the_legal_maximum_are_rejected() {
        let legal = decode(encode(MAX_QUARTER_STREAM_ID, 0, b"fits")).expect("decodes");
        assert_eq!(legal.quarter_stream_id, MAX_QUARTER_STREAM_ID);

        for value in [MAX_QUARTER_STREAM_ID + 1, VARINT_MAX] {
            assert_eq!(
                decode(encode(value, 0, b"too big")),
                Err(DecodeError::QuarterStreamIdTooLarge(value)),
                "quarter stream id {value}"
            );
        }
    }

    /// Which failures close the connection is the whole point of splitting the
    /// error, so it gets pinned here rather than left to the router.
    #[test]
    fn only_quarter_stream_id_failures_are_connection_errors() {
        assert!(DecodeError::MissingQuarterStreamId.is_connection_error());
        assert!(DecodeError::QuarterStreamIdTooLarge(1 << 60).is_connection_error());
        assert!(
            !DecodeError::MissingContextId.is_connection_error(),
            "a droppable datagram must not take the connection down"
        );
    }

    /// The Quarter Stream ID of the highest client-initiated bidirectional
    /// stream id is exactly the limit, so nothing legitimate is refused.
    #[test]
    fn the_largest_usable_stream_id_maps_onto_the_legal_maximum() {
        assert_eq!(quarter_stream_id(VARINT_MAX), MAX_QUARTER_STREAM_ID);
    }

    #[test]
    fn an_empty_payload_is_valid() {
        // A zero-length UDP datagram is legitimate and must survive the trip.
        let decoded = decode(encode_udp_payload(7, b"")).expect("decodes");
        assert_eq!(decoded.quarter_stream_id, 7);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn encoded_len_matches_what_encode_produces() {
        for (qsid, payload_len) in [(0u64, 0usize), (1, 5), (16_384, 1200), (VARINT_MAX, 3)] {
            let payload = vec![0u8; payload_len];
            let encoded = encode(qsid, CONTEXT_ID_UDP_PAYLOAD, &payload);
            assert_eq!(
                encoded.len(),
                encoded_len(qsid, CONTEXT_ID_UDP_PAYLOAD, payload_len)
            );
        }
    }

    #[test]
    fn non_zero_context_ids_survive_a_round_trip() {
        // Decoding must be faithful so the caller can drop unknown contexts.
        let decoded = decode(encode(3, 9, b"opaque")).expect("decodes");
        assert_eq!(decoded.context_id, 9);
        assert_eq!(&decoded.payload[..], b"opaque");
    }
}
