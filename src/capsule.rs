//! The Capsule Protocol (RFC 9297 §3).
//!
//! When a request stream carries `Capsule-Protocol: ?1`, its body is not a
//! representation but a sequence of capsules:
//!
//! ```text
//! Capsule Type (varint) | Capsule Length (varint) | Capsule Value
//! ```
//!
//! Two properties make this awkward and are the reason this module exists:
//!
//! * **Capsules do not align with stream chunks.** A capsule may be split across
//!   any number of reads, and one read may contain many capsules. The decoder is
//!   therefore a state machine fed arbitrary byte slices, and the tests below
//!   feed it a byte at a time to prove it.
//! * **Unknown capsule types must be skipped, not rejected** (RFC 9297 §3.2),
//!   which is what lets the protocol be extended. Skipping uses the declared
//!   length, so a decoder that cannot skip cannot resynchronise.
//!
//! Length is a varint and so may declare up to 2^62 bytes. Values of a known
//! type are buffered, which is bounded here by rejecting anything larger than a
//! UDP payload can be; values of unknown types are discarded as they arrive and
//! are never buffered at all. Without both rules a peer could name a huge length
//! and make the proxy allocate for it.

use bytes::{BufMut, Bytes, BytesMut};

use crate::datagram::{self, MAX_UDP_PAYLOAD};

/// DATAGRAM capsule type (RFC 9297 §3.5).
pub const CAPSULE_TYPE_DATAGRAM: u64 = 0x00;

/// Largest DATAGRAM capsule value accepted.
///
/// A DATAGRAM capsule value is a Context ID varint followed by the payload
/// (RFC 9297 §3.5). Beyond this the payload could not be a UDP datagram, so
/// RFC 9298 §5 requires the stream to be aborted rather than the value buffered.
pub const MAX_DATAGRAM_CAPSULE_VALUE: u64 = 8 + MAX_UDP_PAYLOAD as u64;

/// Why a capsule sequence could not be decoded.
///
/// All of these are malformed-message conditions and map onto
/// `H3_MESSAGE_ERROR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The stream ended part-way through a capsule.
    Truncated,
    /// A DATAGRAM capsule declared more bytes than a UDP payload can hold.
    DatagramTooLarge {
        /// The declared capsule length.
        length: u64,
    },
    /// A DATAGRAM capsule's value ended before its Context ID.
    MalformedDatagram,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "stream ended mid-capsule"),
            Self::DatagramTooLarge { length } => {
                write!(f, "DATAGRAM capsule of {length} bytes is too large")
            }
            Self::MalformedDatagram => write!(f, "DATAGRAM capsule has no context id"),
        }
    }
}

impl std::error::Error for Error {}

/// A decoded capsule.
///
/// Only the types this proxy acts on appear here; everything else is skipped
/// inside the decoder and never surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capsule {
    /// A DATAGRAM capsule (RFC 9297 §3.5).
    Datagram {
        /// Payload interpretation; 0 is a raw UDP payload.
        context_id: u64,
        /// Everything after the Context ID.
        payload: Bytes,
    },
}

/// Where the decoder is in the capsule sequence.
#[derive(Debug)]
enum State {
    /// Between capsules, reading a Type and Length.
    Header,
    /// Buffering the value of a capsule we intend to act on.
    Value {
        /// Total value length, still to be accumulated.
        length: usize,
    },
    /// Discarding the value of an unknown capsule type.
    Skip {
        /// Value bytes still to discard.
        remaining: u64,
    },
}

/// An incremental capsule decoder.
///
/// Feed it bytes with [`CapsuleDecoder::push`], then drain with
/// [`CapsuleDecoder::next_capsule`] until it yields `None`.
#[derive(Debug)]
pub struct CapsuleDecoder {
    buffer: BytesMut,
    state: State,
}

impl Default for CapsuleDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl CapsuleDecoder {
    /// A decoder positioned at the start of a capsule sequence.
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
            state: State::Header,
        }
    }

    /// Adds received bytes. Any number, split anywhere.
    pub fn push(&mut self, chunk: Bytes) {
        self.buffer.extend_from_slice(&chunk);
    }

    /// Whether the sequence is currently between capsules.
    ///
    /// False at end of stream means the peer stopped mid-capsule, which
    /// RFC 9297 §3.3 makes a malformed message.
    pub fn at_capsule_boundary(&self) -> bool {
        match self.state {
            State::Header => self.buffer.is_empty(),
            State::Skip { remaining: 0 } => self.buffer.is_empty(),
            _ => false,
        }
    }

    /// Decodes the next capsule of interest.
    ///
    /// `Ok(None)` means more bytes are needed — not an error. Unknown capsule
    /// types are consumed internally and never returned.
    pub fn next_capsule(&mut self) -> Result<Option<Capsule>, Error> {
        loop {
            match self.state {
                State::Skip { remaining } => {
                    if remaining == 0 {
                        self.state = State::Header;
                        continue;
                    }
                    if self.buffer.is_empty() {
                        return Ok(None);
                    }
                    // Discard as it arrives: an unknown capsule is never
                    // accumulated, however large it claims to be.
                    let discard = remaining.min(self.buffer.len() as u64);
                    let _ = self.buffer.split_to(discard as usize);
                    self.state = State::Skip {
                        remaining: remaining - discard,
                    };
                }

                State::Header => {
                    // Both varints must be present before either is consumed.
                    let Some((capsule_type, type_len)) = datagram::peek_varint(&self.buffer) else {
                        return Ok(None);
                    };
                    let Some((length, length_len)) =
                        datagram::peek_varint(&self.buffer[type_len..])
                    else {
                        return Ok(None);
                    };

                    let _ = self.buffer.split_to(type_len + length_len);

                    if capsule_type == CAPSULE_TYPE_DATAGRAM {
                        if length > MAX_DATAGRAM_CAPSULE_VALUE {
                            return Err(Error::DatagramTooLarge { length });
                        }
                        self.state = State::Value {
                            length: length as usize,
                        };
                    } else {
                        self.state = State::Skip { remaining: length };
                    }
                }

                State::Value { length } => {
                    if self.buffer.len() < length {
                        return Ok(None);
                    }

                    let mut value = self.buffer.split_to(length).freeze();
                    self.state = State::Header;

                    let context_id =
                        datagram::take_varint(&mut value).ok_or(Error::MalformedDatagram)?;

                    return Ok(Some(Capsule::Datagram {
                        context_id,
                        payload: value,
                    }));
                }
            }
        }
    }
}

/// Encodes a DATAGRAM capsule (RFC 9297 §3.5).
///
/// Used only when the peer has not enabled QUIC datagrams; see
/// `tunnel::udp::Session::forward_to_client`.
pub fn encode_datagram(context_id: u64, payload: &[u8]) -> Bytes {
    let value_len = datagram::varint_len(context_id) + payload.len();

    let mut buf = BytesMut::with_capacity(
        datagram::varint_len(CAPSULE_TYPE_DATAGRAM)
            + datagram::varint_len(value_len as u64)
            + value_len,
    );
    datagram::put_varint(&mut buf, CAPSULE_TYPE_DATAGRAM);
    datagram::put_varint(&mut buf, value_len as u64);
    datagram::put_varint(&mut buf, context_id);
    buf.put_slice(payload);

    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drains every capsule the decoder can currently produce.
    fn drain(decoder: &mut CapsuleDecoder) -> Result<Vec<Capsule>, Error> {
        let mut out = Vec::new();
        while let Some(capsule) = decoder.next_capsule()? {
            out.push(capsule);
        }
        Ok(out)
    }

    fn datagram_capsule(context_id: u64, payload: &[u8]) -> Capsule {
        Capsule::Datagram {
            context_id,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    #[test]
    fn decodes_a_single_datagram_capsule() {
        let mut decoder = CapsuleDecoder::new();
        decoder.push(encode_datagram(0, b"hello"));

        assert_eq!(
            drain(&mut decoder).unwrap(),
            vec![datagram_capsule(0, b"hello")]
        );
        assert!(decoder.at_capsule_boundary());
    }

    #[test]
    fn decodes_several_capsules_from_one_chunk() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&encode_datagram(0, b"one"));
        buf.extend_from_slice(&encode_datagram(0, b"two"));
        buf.extend_from_slice(&encode_datagram(0, b"three"));

        let mut decoder = CapsuleDecoder::new();
        decoder.push(buf.freeze());

        assert_eq!(
            drain(&mut decoder).unwrap(),
            vec![
                datagram_capsule(0, b"one"),
                datagram_capsule(0, b"two"),
                datagram_capsule(0, b"three"),
            ]
        );
    }

    /// The property that matters most: capsules do not align with reads.
    #[test]
    fn decodes_correctly_when_fed_one_byte_at_a_time() {
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&encode_datagram(0, b"first payload"));
        // An unknown type in the middle, to prove skipping resynchronises.
        wire.extend_from_slice(&encode_unknown(0x1234, &[0xff; 40]));
        wire.extend_from_slice(&encode_datagram(7, b"second"));
        let wire = wire.freeze();

        let mut decoder = CapsuleDecoder::new();
        let mut decoded = Vec::new();

        for index in 0..wire.len() {
            decoder.push(wire.slice(index..index + 1));
            decoded.extend(drain(&mut decoder).expect("decodes"));
        }

        assert_eq!(
            decoded,
            vec![
                datagram_capsule(0, b"first payload"),
                datagram_capsule(7, b"second"),
            ]
        );
        assert!(decoder.at_capsule_boundary());
    }

    /// Every possible split point of a two-capsule sequence must decode the same.
    #[test]
    fn decodes_correctly_at_every_split_point() {
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&encode_datagram(0, b"alpha"));
        wire.extend_from_slice(&encode_datagram(1, b"beta"));
        let wire = wire.freeze();

        let expected = vec![datagram_capsule(0, b"alpha"), datagram_capsule(1, b"beta")];

        for split in 0..=wire.len() {
            let mut decoder = CapsuleDecoder::new();
            decoder.push(wire.slice(..split));
            let mut decoded = drain(&mut decoder).expect("decodes");
            decoder.push(wire.slice(split..));
            decoded.extend(drain(&mut decoder).expect("decodes"));

            assert_eq!(decoded, expected, "split at {split}");
            assert!(decoder.at_capsule_boundary(), "split at {split}");
        }
    }

    #[test]
    fn skips_unknown_capsule_types() {
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&encode_unknown(0x41, b"ignored entirely"));
        wire.extend_from_slice(&encode_datagram(0, b"kept"));

        let mut decoder = CapsuleDecoder::new();
        decoder.push(wire.freeze());

        assert_eq!(
            drain(&mut decoder).unwrap(),
            vec![datagram_capsule(0, b"kept")]
        );
    }

    #[test]
    fn skips_an_unknown_capsule_with_an_empty_value() {
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&encode_unknown(0x41, b""));
        wire.extend_from_slice(&encode_datagram(0, b"kept"));

        let mut decoder = CapsuleDecoder::new();
        decoder.push(wire.freeze());

        assert_eq!(
            drain(&mut decoder).unwrap(),
            vec![datagram_capsule(0, b"kept")]
        );
        assert!(decoder.at_capsule_boundary());
    }

    /// An unknown capsule's value must never be buffered, no matter how large it
    /// claims to be.
    #[test]
    fn an_unknown_capsule_value_is_discarded_as_it_arrives() {
        let mut header = BytesMut::new();
        datagram::put_varint(&mut header, 0x41);
        datagram::put_varint(&mut header, 10_000_000);

        let mut decoder = CapsuleDecoder::new();
        decoder.push(header.freeze());
        assert_eq!(decoder.next_capsule().unwrap(), None);

        for _ in 0..100 {
            decoder.push(Bytes::from_static(&[0u8; 1024]));
            assert_eq!(decoder.next_capsule().unwrap(), None);
            assert!(
                decoder.buffer.len() < 4096,
                "buffered {} bytes of a skipped capsule",
                decoder.buffer.len()
            );
        }
    }

    #[test]
    fn truncation_is_detected_at_every_prefix() {
        let wire = encode_datagram(0, b"payload");

        // Every strict prefix leaves the decoder mid-capsule.
        for length in 0..wire.len() {
            let mut decoder = CapsuleDecoder::new();
            decoder.push(wire.slice(..length));
            drain(&mut decoder).expect("a prefix is not yet an error");

            if length == 0 {
                assert!(decoder.at_capsule_boundary(), "an empty body is complete");
            } else {
                assert!(
                    !decoder.at_capsule_boundary(),
                    "prefix of {length} bytes must read as incomplete"
                );
            }
        }

        // The whole thing is complete.
        let mut decoder = CapsuleDecoder::new();
        decoder.push(wire);
        drain(&mut decoder).expect("decodes");
        assert!(decoder.at_capsule_boundary());
    }

    #[test]
    fn an_oversized_datagram_capsule_is_rejected() {
        let mut header = BytesMut::new();
        datagram::put_varint(&mut header, CAPSULE_TYPE_DATAGRAM);
        datagram::put_varint(&mut header, MAX_DATAGRAM_CAPSULE_VALUE + 1);

        let mut decoder = CapsuleDecoder::new();
        decoder.push(header.freeze());

        assert_eq!(
            decoder.next_capsule(),
            Err(Error::DatagramTooLarge {
                length: MAX_DATAGRAM_CAPSULE_VALUE + 1
            })
        );
    }

    #[test]
    fn a_datagram_capsule_without_a_context_id_is_malformed() {
        // Type 0x00, length 0: no room for the Context ID varint.
        let mut wire = BytesMut::new();
        datagram::put_varint(&mut wire, CAPSULE_TYPE_DATAGRAM);
        datagram::put_varint(&mut wire, 0);

        let mut decoder = CapsuleDecoder::new();
        decoder.push(wire.freeze());

        assert_eq!(decoder.next_capsule(), Err(Error::MalformedDatagram));
    }

    #[test]
    fn an_empty_udp_payload_round_trips() {
        let mut decoder = CapsuleDecoder::new();
        decoder.push(encode_datagram(0, b""));

        assert_eq!(drain(&mut decoder).unwrap(), vec![datagram_capsule(0, b"")]);
    }

    #[test]
    fn non_zero_context_ids_are_preserved_for_the_caller_to_drop() {
        let mut decoder = CapsuleDecoder::new();
        decoder.push(encode_datagram(42, b"other context"));

        assert_eq!(
            drain(&mut decoder).unwrap(),
            vec![datagram_capsule(42, b"other context")]
        );
    }

    #[test]
    fn encoding_matches_the_wire_layout() {
        // Type 0x00, length 6 (1 byte context + 5 byte payload), context 0.
        assert_eq!(&encode_datagram(0, b"hello")[..], b"\x00\x06\x00hello");
    }

    /// Encodes a capsule of a type the decoder does not know.
    fn encode_unknown(capsule_type: u64, value: &[u8]) -> Bytes {
        let mut buf = BytesMut::new();
        datagram::put_varint(&mut buf, capsule_type);
        datagram::put_varint(&mut buf, value.len() as u64);
        buf.put_slice(value);
        buf.freeze()
    }
}
