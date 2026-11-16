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
//!   therefore a state machine fed arbitrary chunks, and the tests below feed it
//!   a byte at a time to prove it.
//! * **Unknown capsule types must be skipped, not rejected** (RFC 9297 §3.2),
//!   which is what lets the protocol be extended. Skipping uses the declared
//!   length, so a decoder that cannot skip cannot resynchronise.
//!
//! Length is a varint and so may declare up to 2^62 bytes. Values of a known
//! type are buffered, which is bounded here by rejecting anything larger than a
//! UDP payload can be; values of unknown types are discarded as they arrive and
//! are never buffered at all. Without both rules a peer could name a huge length
//! and make the proxy allocate for it.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::datagram::{self, MAX_UDP_PAYLOAD};

/// DATAGRAM capsule type (RFC 9297 §3.5).
pub const CAPSULE_TYPE_DATAGRAM: u64 = 0x00;

/// Largest DATAGRAM capsule value accepted.
///
/// A DATAGRAM capsule value is a Context ID varint followed by the payload
/// (RFC 9297 §3.5), and beyond this the payload could not be a UDP datagram.
///
/// The refusal is this crate's own, not the RFC's. RFC 9298 §5 says: "An
/// endpoint that receives an HTTP Datagram using Context ID zero whose UDP
/// Proxying Payload field is longer than 65527 MUST abort the corresponding
/// stream." That MUST is about Context ID zero, and the Context ID is the first
/// varint *inside* the value, so it is not known yet: this bound is read off
/// the declared capsule length, before any of the value. The payload check at
/// `tunnel::udp::forward_to_target` is where §5's own rule is applied, on a
/// payload whose Context ID has been read. Aborting here anyway is the memory
/// bound below: learning the Context ID would mean buffering the whole value
/// first, and a non-zero one names an extension this server has not negotiated.
///
/// It is also this decoder's memory bound, and therefore one of the three
/// buffers a CONNECT-UDP session holds
/// ([`crate::h3::connection::INBOUND_QUEUE_DEPTH`] accounts for all three). A
/// value has to be buffered whole because a UDP payload cannot be forwarded
/// piecewise, and a peer that declares the largest one allowed and then stops
/// one byte short is doing nothing RFC 9297 §3.2 forbids. So what is held is
/// held until the session's idle timeout. One capsule's worth is all of it:
/// the decoder copies a value only when it is split across chunks, into a
/// buffer allocated once at the declared length, and keeps no handle on any
/// chunk once it has been drained. An unknown type is discarded as it arrives
/// without being buffered at all.
// 65527 is exact in both types, and a `const` cannot reach `u64::try_from`.
#[allow(clippy::as_conversions)]
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
    /// Collecting the value of a capsule we intend to act on.
    Value {
        /// Total value length.
        length: usize,
    },
    /// Discarding the value of an unknown capsule type.
    Skip {
        /// Value bytes still to discard.
        remaining: u64,
    },
}

/// The longest capsule header: a Type and a Length, each a varint of at most 8
/// bytes.
const MAX_HEADER_LEN: usize = 16;

/// An incremental capsule decoder.
///
/// Feed it chunks with [`CapsuleDecoder::push`], then drain with
/// [`CapsuleDecoder::next_capsule`] until it yields `None`.
///
/// A capsule that lies whole inside one chunk is cut out of that chunk, so its
/// payload is a slice of the chunk and no byte is copied. Only a capsule split
/// across chunks is copied, into a buffer of the decoder's own: a header of at
/// most 16 bytes, or a DATAGRAM value of at most [`MAX_DATAGRAM_CAPSULE_VALUE`]
/// bytes, allocated once at the declared length. When `next_capsule` returns
/// `Ok(None)` the decoder no longer refers to any chunk it was given, so what it
/// holds between chunks is that buffer alone.
#[derive(Debug)]
pub struct CapsuleDecoder {
    /// The undecoded rest of the last chunk pushed.
    chunk: Bytes,
    /// The start of a header or a DATAGRAM value that an earlier chunk ended
    /// inside.
    partial: BytesMut,
    state: State,
}

impl Default for CapsuleDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads a whole capsule header off the front of `bytes`: the Type, the Length
/// and the number of bytes the two took.
fn peek_header(bytes: &[u8]) -> Option<(u64, u64, usize)> {
    let (capsule_type, type_len) = datagram::peek_varint(bytes)?;
    let (length, length_len) = datagram::peek_varint(&bytes[type_len..])?;
    Some((capsule_type, length, type_len + length_len))
}

impl CapsuleDecoder {
    /// A decoder positioned at the start of a capsule sequence.
    pub fn new() -> Self {
        Self {
            chunk: Bytes::new(),
            partial: BytesMut::new(),
            state: State::Header,
        }
    }

    /// Adds a received chunk. Any number of bytes, split anywhere.
    ///
    /// Taken by value because capsules are cut out of it. The caller drains the
    /// decoder before the next push. A push before that is still decoded
    /// correctly, but the undecoded rest of the earlier chunk is copied in front
    /// of the new one.
    pub fn push(&mut self, chunk: Bytes) {
        if self.chunk.is_empty() {
            self.chunk = chunk;
            return;
        }
        let mut joined = BytesMut::with_capacity(self.chunk.len() + chunk.len());
        joined.extend_from_slice(&self.chunk);
        joined.extend_from_slice(&chunk);
        self.chunk = joined.freeze();
    }

    /// Whether the sequence is currently between capsules.
    ///
    /// False at end of stream means the peer stopped mid-capsule, which
    /// RFC 9297 §3.3 makes a malformed message.
    pub fn at_capsule_boundary(&self) -> bool {
        // A spent `Skip` is never seen here: `next_capsule` turns it into
        // `Header` before it returns.
        matches!(self.state, State::Header) && self.partial.is_empty() && self.chunk.is_empty()
    }

    /// The number of bytes the decoder is currently holding.
    ///
    /// That is the undecoded rest of the last chunk, which is empty once
    /// [`CapsuleDecoder::next_capsule`] has returned `Ok(None)`, plus the start
    /// of a header or a DATAGRAM value that a chunk ended inside. A complete
    /// header is consumed, and the value of an unknown capsule type is discarded
    /// as it arrives, so neither is held. This is what a test needs to tell a
    /// decoder that skips an unknown capsule from one that buffers its value and
    /// returns the same `Ok(None)` either way.
    pub fn buffered_len(&self) -> usize {
        self.partial.len() + self.chunk.len()
    }

    /// Decodes the next capsule of interest.
    ///
    /// `Ok(None)` means more bytes are needed, not an error. Unknown capsule
    /// types are consumed internally and never returned.
    pub fn next_capsule(&mut self) -> Result<Option<Capsule>, Error> {
        let next = self.decode();
        // An empty slice still refers to the chunk it was cut from, and would
        // keep that whole chunk allocated.
        if self.chunk.is_empty() {
            self.chunk = Bytes::new();
        }
        next
    }

    fn decode(&mut self) -> Result<Option<Capsule>, Error> {
        loop {
            match self.state {
                State::Skip { remaining } => {
                    if remaining == 0 {
                        self.state = State::Header;
                        continue;
                    }
                    if self.chunk.is_empty() {
                        return Ok(None);
                    }
                    // Discard as it arrives: an unknown capsule is never
                    // accumulated, however large it claims to be.
                    // Both directions are exact: the minimum is at most the
                    // chunk's own length, so it is a `usize` value, and the
                    // widening back is the same number.
                    #[allow(clippy::as_conversions)]
                    let discard = remaining.min(self.chunk.len() as u64);
                    #[allow(clippy::as_conversions)]
                    self.chunk.advance(discard as usize);
                    self.state = State::Skip {
                        remaining: remaining - discard,
                    };
                }

                State::Header => {
                    let Some((capsule_type, length)) = self.take_header() else {
                        return Ok(None);
                    };

                    if capsule_type == CAPSULE_TYPE_DATAGRAM {
                        if length > MAX_DATAGRAM_CAPSULE_VALUE {
                            return Err(Error::DatagramTooLarge { length });
                        }
                        self.state = State::Value {
                            // The refusal above leaves nothing past
                            // `MAX_DATAGRAM_CAPSULE_VALUE` here, so the length
                            // is far inside a `usize`.
                            #[allow(clippy::as_conversions)]
                            length: length as usize,
                        };
                    } else {
                        self.state = State::Skip { remaining: length };
                    }
                }

                State::Value { length } => {
                    let Some(mut value) = self.take_value(length) else {
                        return Ok(None);
                    };
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

    /// Consumes a whole capsule header, or keeps what there is of one.
    ///
    /// Both varints must be present before either is consumed. A header that
    /// the chunk ends inside is moved to `partial`, and the next chunk completes
    /// it there.
    fn take_header(&mut self) -> Option<(u64, u64)> {
        if self.partial.is_empty() {
            if let Some((capsule_type, length, header_len)) = peek_header(&self.chunk) {
                self.chunk.advance(header_len);
                return Some((capsule_type, length));
            }
            if !self.chunk.is_empty() {
                self.partial = BytesMut::with_capacity(MAX_HEADER_LEN);
                self.partial.extend_from_slice(&self.chunk);
                self.chunk.clear();
            }
            return None;
        }

        // At most `MAX_HEADER_LEN` bytes are ever needed, and the bytes past
        // the header are left in the chunk.
        let held = self.partial.len();
        let take = self.chunk.len().min(MAX_HEADER_LEN - held);
        self.partial.extend_from_slice(&self.chunk[..take]);
        match peek_header(&self.partial) {
            Some((capsule_type, length, header_len)) => {
                self.chunk.advance(header_len - held);
                self.partial.clear();
                Some((capsule_type, length))
            }
            None => {
                // Two varints fit in `MAX_HEADER_LEN` bytes, so an incomplete
                // header means the whole chunk was taken.
                self.chunk.advance(take);
                None
            }
        }
    }

    /// Takes a DATAGRAM value of `length` bytes once all of it is here.
    ///
    /// A value inside the chunk is cut out of it. A value the chunk ends inside
    /// is collected in `partial`, which is allocated at the declared length
    /// when its first byte arrives and handed over whole when its last does.
    fn take_value(&mut self, length: usize) -> Option<Bytes> {
        if self.partial.is_empty() && self.chunk.len() >= length {
            return Some(self.chunk.split_to(length));
        }
        if self.chunk.is_empty() {
            return None;
        }
        if self.partial.is_empty() {
            self.partial = BytesMut::with_capacity(length);
        }
        let take = (length - self.partial.len()).min(self.chunk.len());
        self.partial.extend_from_slice(&self.chunk[..take]);
        self.chunk.advance(take);
        if self.partial.len() < length {
            return None;
        }
        Some(std::mem::take(&mut self.partial).freeze())
    }
}

/// Encodes a DATAGRAM capsule (RFC 9297 §3.5).
///
/// Used only when the peer has not enabled QUIC datagrams; see
/// `tunnel::udp::Session::forward_to_client`.
pub fn encode_datagram(context_id: u64, payload: &[u8]) -> Bytes {
    let value_len = datagram::varint_len(context_id) + payload.len();

    // A byte count is a `usize` and a varint is a `u64`; the widening is exact
    // on both supported targets and has no `From` to express it.
    #[allow(clippy::as_conversions)]
    let wire_len = value_len as u64;

    let mut buf = BytesMut::with_capacity(
        datagram::varint_len(CAPSULE_TYPE_DATAGRAM) + datagram::varint_len(wire_len) + value_len,
    );
    datagram::put_varint(&mut buf, CAPSULE_TYPE_DATAGRAM);
    datagram::put_varint(&mut buf, wire_len);
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

    /// A stream that ends on the last byte of a skipped capsule ended between
    /// capsules, not inside one. `next_capsule` turns a spent `Skip` into
    /// `Header` before it returns, so no caller sees the decoder in that state.
    #[test]
    fn a_fully_skipped_unknown_capsule_ends_at_a_boundary() {
        let mut decoder = CapsuleDecoder::new();
        decoder.push(encode_unknown(0x41, b"skipped whole"));
        assert!(drain(&mut decoder).unwrap().is_empty());
        assert!(decoder.at_capsule_boundary());

        // Not a boundary while bytes are still waiting: this one is the first of
        // the next capsule's header, which has not arrived whole.
        decoder.push(Bytes::from_static(&[0x00]));
        assert!(!decoder.at_capsule_boundary());
    }

    /// What [`CapsuleDecoder::buffered_len`] reports: a DATAGRAM value is held
    /// whole, while a header and a skipped value are not held at all.
    #[test]
    fn buffered_len_reports_the_bytes_still_held() {
        let mut decoder = CapsuleDecoder::new();
        let wire = encode_datagram(0, b"held");
        decoder.push(wire.clone());
        assert_eq!(
            decoder.buffered_len(),
            wire.len(),
            "a DATAGRAM value is held"
        );

        assert_eq!(
            drain(&mut decoder).unwrap(),
            vec![datagram_capsule(0, b"held")]
        );
        assert_eq!(decoder.buffered_len(), 0, "draining releases the value");

        let mut header = BytesMut::new();
        datagram::put_varint(&mut header, 0x41);
        datagram::put_varint(&mut header, 1_000_000);
        decoder.push(header.clone().freeze());
        assert_eq!(decoder.buffered_len(), header.len(), "the header is held");

        assert_eq!(decoder.next_capsule().unwrap(), None);
        assert_eq!(decoder.buffered_len(), 0, "the header is consumed");

        decoder.push(Bytes::from_static(b"a prefix of the value"));
        assert_eq!(decoder.next_capsule().unwrap(), None);
        assert_eq!(
            decoder.buffered_len(),
            0,
            "a skipped value is discarded as it arrives"
        );
    }

    /// A capsule inside one chunk is a slice of that chunk, and a drained
    /// decoder refers to no chunk at all.
    ///
    /// The second half is the memory bound: a decoder that kept any handle on a
    /// chunk would keep the whole chunk allocated, however little of it was
    /// left undecoded. Only the start of the unfinished capsule at the end is
    /// kept, as a copy.
    #[test]
    fn a_drained_decoder_keeps_no_chunk_alive() {
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&encode_datagram(0, b"whole"));
        wire.extend_from_slice(&encode_unknown(0x41, &[0xff; 100]));
        let mut header = BytesMut::new();
        datagram::put_varint(&mut header, CAPSULE_TYPE_DATAGRAM);
        datagram::put_varint(&mut header, 1000);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&[0x00; 10]);
        let chunk = wire.freeze();

        let mut decoder = CapsuleDecoder::new();
        decoder.push(chunk.clone());
        let decoded = drain(&mut decoder).unwrap();
        let Capsule::Datagram { payload, .. } = &decoded[0];
        assert_eq!(&payload[..], b"whole");
        assert!(
            chunk.as_ptr_range().contains(&payload.as_ptr()),
            "a capsule inside the chunk is not copied"
        );
        drop(decoded);

        assert!(
            chunk.is_unique(),
            "the drained decoder still refers to the chunk"
        );
        assert_eq!(decoder.buffered_len(), 10, "the unfinished value is kept");
        assert!(!decoder.at_capsule_boundary());

        decoder.push(Bytes::from(vec![0x5a; 990]));
        let Some(Capsule::Datagram { payload, .. }) = decoder.next_capsule().unwrap() else {
            panic!("the value is complete");
        };
        assert_eq!(payload.len(), 999);
        assert!(decoder.at_capsule_boundary());
    }

    /// A push before the decoder is drained still decodes the same sequence.
    #[test]
    fn a_push_before_the_drain_joins_the_chunks() {
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&encode_datagram(0, b"one"));
        wire.extend_from_slice(&encode_datagram(0, b"two"));
        let wire = wire.freeze();
        let cut = wire.len() - 2;

        let mut decoder = CapsuleDecoder::new();
        decoder.push(wire.slice(..cut));
        assert_eq!(
            decoder.next_capsule().unwrap(),
            Some(datagram_capsule(0, b"one"))
        );
        decoder.push(wire.slice(cut..));
        assert_eq!(
            drain(&mut decoder).unwrap(),
            vec![datagram_capsule(0, b"two")]
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
                decoder.buffered_len() < 4096,
                "buffered {} bytes of a skipped capsule",
                decoder.buffered_len()
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
        decoder.push(wire.clone());
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
        // The same exact widening the encoder above states.
        #[allow(clippy::as_conversions)]
        datagram::put_varint(&mut buf, value.len() as u64);
        buf.put_slice(value);
        buf.freeze()
    }
}
