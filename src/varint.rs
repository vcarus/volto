//! QUIC variable-length integers (RFC 9000 §16), and the type-and-length
//! header that HTTP/3 frames (RFC 9114 §7.1) and capsules (RFC 9297 §3.2) put
//! in front of their payload.
//!
//! The pre-authentication gate, the HTTP/3 layer, the capsule decoder and the
//! HTTP Datagram coding all read and write these. `quinn::VarInt` is not used
//! for it: its `size()` is `pub(crate)` in quinn-proto, and its decoder
//! consumes rather than peeks.

use bytes::{Buf, BufMut, Bytes};

/// Largest value a QUIC varint can hold (RFC 9000 §16).
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Longest a QUIC varint can be, in bytes (RFC 9000 §16), for sizing scratch
/// buffers. This is a length; the largest value is [`VARINT_MAX`].
pub const VARINT_MAX_LEN: usize = 8;

/// A byte count as the `u64` a varint carries.
///
/// The one place a `usize` length is widened to a varint's type. It is exact
/// because no target this crate builds for has a `usize` wider than 64 bits,
/// which the assertion below checks, and std has no `From<usize> for u64` to
/// say so.
#[allow(clippy::as_conversions)]
pub const fn len_u64(len: usize) -> u64 {
    len as u64
}

const _: () = assert!(usize::BITS <= u64::BITS);

/// How much of a `remaining`-byte field the chunk in hand settles, and what is
/// left of the field after it.
///
/// The frame decoder's DATA and skipped frames and the capsule decoder's
/// skipped capsules each run a declared length down chunk by chunk, and none
/// may read past its end. A `remaining` too large for a `usize` is larger than
/// any chunk, so the whole chunk is taken.
pub fn take_from(remaining: u64, chunk_len: usize) -> (usize, u64) {
    let take = usize::try_from(remaining).map_or(chunk_len, |remaining| remaining.min(chunk_len));
    (take, remaining - len_u64(take))
}

/// The length of the varint whose first byte is `first`: RFC 9000 §16 puts it
/// in the two most significant bits, as a power of two.
pub fn varint_len_of_first(first: u8) -> usize {
    1 << (first >> 6)
}

/// A type and a length, the two varints in front of every HTTP/3 frame
/// (RFC 9114 §7.1) and every capsule (RFC 9297 §3.2), assembled across chunks.
///
/// A header that lies whole inside a chunk is read off it in place. One that a
/// chunk ends inside is kept here, a byte at a time, until the next chunk
/// completes it. A fixed array rather than a growable buffer, so a decoder that
/// holds one allocates nothing for it. It cannot overflow: [`Self::take`]
/// stops as soon as both varints have arrived, and RFC 9000 §16 bounds each at
/// eight bytes.
#[derive(Debug, Default)]
pub(crate) struct TypeLength {
    held: [u8; 2 * VARINT_MAX_LEN],
    len: usize,
}

impl TypeLength {
    /// The type and the length, or `None` with every byte of `chunk` kept here.
    pub(crate) fn take(&mut self, chunk: &mut Bytes) -> Option<(u64, u64)> {
        if self.len == 0
            && let Some((kind, length, used)) = peek_two(chunk)
        {
            chunk.advance(used);
            return Some((kind, length));
        }
        while let Some(&byte) = chunk.first() {
            chunk.advance(1);
            self.held[self.len] = byte;
            self.len += 1;
            if let Some((kind, length, _)) = peek_two(&self.held[..self.len]) {
                self.len = 0;
                return Some((kind, length));
            }
        }
        None
    }

    /// How many bytes of an unfinished header are kept.
    pub(crate) fn held(&self) -> usize {
        self.len
    }
}

/// Two varints off the front of `bytes`, and the number of bytes they took.
fn peek_two(bytes: &[u8]) -> Option<(u64, u64, usize)> {
    let (first, first_len) = peek_varint(bytes)?;
    let (second, second_len) = peek_varint(&bytes[first_len..])?;
    Some((first, second, first_len + second_len))
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
///
/// Also if `buf` cannot hold the encoding. Only a fixed slice can fail that
/// way, because a `BytesMut` grows.
///
/// Each arm narrows to the width `varint_len` has just proved the value fits:
/// one byte only below 0x40, two only below 0x4000, four only below
/// 0x4000_0000.
///
/// Generic over the buffer so that a frame header can be written into room
/// already reserved inside a slice, which `h3::frame::seal_data` does.
#[allow(clippy::as_conversions)]
pub fn put_varint(buf: &mut impl BufMut, value: u64) {
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
    buf.advance(length);
    Some(value)
}

/// Decodes the varint at the start of `buf`, returning it and its byte length.
///
/// `None` means the buffer does not yet hold the whole varint, which is a
/// "need more bytes" signal for incremental parsers, not an error.
pub fn peek_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let length = varint_len_of_first(first);
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
    use bytes::BytesMut;

    use super::*;

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

    /// The examples given in RFC 9000 Appendix A.1.
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
}
