//! DATA frames sealed in place: the room a caller leaves in front of a
//! payload, and the header written into it.

use bytes::{Buf, Bytes, BytesMut};

use super::{DATA, put_header};
use crate::varint::len_u64;

/// Bytes a caller leaves at the front of a buffer for [`seal_data`] to write a
/// DATA frame header into.
///
/// The type byte of DATA plus a 4-byte length varint, the longest one a
/// payload below 2^30 bytes needs. Every buffer this server reads a tunnel's
/// bytes into is far below that. The layout is this server's own choice: what
/// reaches the wire is the frame [`put_header`] and the payload make together,
/// with the same minimal length encoding.
pub const DATA_HEADER_ROOM: usize = 5;

/// Turns `block` into one DATA frame without moving its payload.
///
/// `block` is [`DATA_HEADER_ROOM`] bytes of room followed by the payload. The
/// header is written right-aligned in the room, in the minimal encoding
/// [`put_header`] uses, and the unused bytes in front of it (0 to 3 of them)
/// are dropped from the returned piece. So the frame is one contiguous `Bytes`
/// that still shares the block it was read into, and its bytes are exactly
/// those of a header written separately and sent before the payload.
///
/// # Panics
///
/// If `block` holds no payload behind its room. A read of zero bytes is EOF,
/// and this server never sends an empty DATA frame. Also if the payload is
/// 2^30 bytes or more, which the room cannot describe.
pub fn seal_data(mut block: BytesMut) -> Bytes {
    let payload = block
        .len()
        .checked_sub(DATA_HEADER_ROOM)
        .filter(|&payload| payload > 0)
        .expect("a block to seal holds a payload: an empty DATA frame is never sent");
    let length = len_u64(payload);
    let header = crate::varint::varint_len(DATA) + crate::varint::varint_len(length);
    let start = DATA_HEADER_ROOM
        .checked_sub(header)
        .expect("a payload below 2^30 bytes, whose header fits the room");

    let mut room = &mut block[start..DATA_HEADER_ROOM];
    put_header(&mut room, DATA, length);
    debug_assert!(
        room.is_empty(),
        "the header fills the room it was sized for"
    );

    let mut frame = block.freeze();
    frame.advance(start);
    frame
}

#[cfg(test)]
mod tests {
    // Each conversion below is of a literal length or of a value below 251,
    // so each is in range.
    #![allow(clippy::as_conversions)]

    use super::*;

    /// A sealed block is one piece of the buffer it was read into, and its
    /// bytes are the frame `put_header` and the payload make together.
    ///
    /// The lengths sit on each side of the varint boundaries (63 and 64,
    /// 16383 and 16384), plus the largest payload a 64 KiB relay block holds
    /// behind its room and one far past it. The pointer checks are what show
    /// the payload was not copied: the frame starts inside the room, and its
    /// payload is still where the read put it.
    #[test]
    fn a_sealed_block_is_one_piece_with_the_minimal_header() {
        for length in [1usize, 63, 64, 16383, 16384, 65531, 1 << 20] {
            let mut block = BytesMut::with_capacity(DATA_HEADER_ROOM + length);
            block.resize(DATA_HEADER_ROOM, 0);
            let payload: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            block.extend_from_slice(&payload);
            let base = block.as_ptr();

            let frame = seal_data(block);

            let mut expected = BytesMut::new();
            put_header(&mut expected, DATA, length as u64);
            let header = expected.len();
            expected.extend_from_slice(&payload);
            assert_eq!(
                &frame[..],
                &expected[..],
                "a {length}-byte payload sealed to other bytes than put_header gives"
            );

            let start = DATA_HEADER_ROOM - header;
            assert!(
                std::ptr::eq(frame.as_ptr(), base.wrapping_add(start)),
                "the {length}-byte frame does not start inside its room"
            );
            assert!(
                std::ptr::eq(
                    frame[header..].as_ptr(),
                    base.wrapping_add(DATA_HEADER_ROOM)
                ),
                "the {length}-byte payload was moved"
            );
        }
    }

    /// The room fits the header of any payload a 4-byte varint can describe,
    /// which is every buffer this server reads into.
    #[test]
    fn the_room_fits_the_longest_header_a_block_needs() {
        assert_eq!(
            crate::varint::varint_len(DATA) + crate::varint::varint_len(0x3fff_ffff),
            DATA_HEADER_ROOM
        );
    }

    /// A block with nothing behind its room is a read of zero bytes, which is
    /// EOF and never a frame.
    #[test]
    #[should_panic(expected = "empty DATA frame")]
    fn an_empty_block_is_never_sealed() {
        let mut block = BytesMut::new();
        block.resize(DATA_HEADER_ROOM, 0);
        let _ = seal_data(block);
    }
}
