//! Huffman *encoding* for the test client (RFC 7541 Appendix B).
//!
//! The server only ever decodes: `src/h3/qpack.rs` writes every string literal
//! with `H = 0`, so nothing in the crate can produce a Huffman-coded field line
//! and `src/h3/huffman.rs` was never reached from the wire by `cargo test` --
//! while Surge Huffman-codes every request it sends. This module is the missing
//! half, and it lives here rather than in the server because the server has no
//! use for it.
//!
//! # Why the table is copied rather than imported
//!
//! [`CODES`] is a second transcription of RFC 7541 Appendix B, independent of
//! the one in `src/h3/huffman.rs`. That is the point: `it_huffman` round-trips
//! every symbol of this table through the server's decoder, so the two
//! transcriptions have to agree with each other *and* with the RFC. Deriving
//! this table from the server's would make that check vacuous -- a mistyped
//! entry would encode and decode to itself and nothing would notice.
//!
//! QPACK borrows the code unchanged: RFC 9204 §4.1.2 says "the Huffman table
//! from Appendix B of \[RFC7541\] is used without modification".

#![allow(dead_code)]
// Each integration test binary uses a subset of this.

// The package-wide default is `deny` (`Cargo.toml`); this file argues for its
// allow: an encoder mirroring the decoder under test, bit for bit.
#![allow(clippy::as_conversions)]

/// RFC 7541 Appendix B: `(code, code length in bits)` for symbols 0..=255,
/// then EOS at index 256.
///
/// The codes are aligned to the least significant bit, as the appendix's "code
/// as hex" column gives them.
#[rustfmt::skip]
pub const CODES: [(u32, u8); 257] = [
    (0x1ff8, 13),     (0x7fffd8, 23),   (0xfffffe2, 28),  (0xfffffe3, 28),
    (0xfffffe4, 28),  (0xfffffe5, 28),  (0xfffffe6, 28),  (0xfffffe7, 28),
    (0xfffffe8, 28),  (0xffffea, 24),   (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28),  (0x3ffffffd, 30), (0xfffffeb, 28),  (0xfffffec, 28),
    (0xfffffed, 28),  (0xfffffee, 28),  (0xfffffef, 28),  (0xffffff0, 28),
    (0xffffff1, 28),  (0xffffff2, 28),  (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28),  (0xffffff5, 28),  (0xffffff6, 28),  (0xffffff7, 28),
    (0xffffff8, 28),  (0xffffff9, 28),  (0xffffffa, 28),  (0xffffffb, 28),
    (0x14, 6),        (0x3f8, 10),      (0x3f9, 10),      (0xffa, 12),
    (0x1ff9, 13),     (0x15, 6),        (0xf8, 8),        (0x7fa, 11),
    (0x3fa, 10),      (0x3fb, 10),      (0xf9, 8),        (0x7fb, 11),
    (0xfa, 8),        (0x16, 6),        (0x17, 6),        (0x18, 6),
    (0x0, 5),         (0x1, 5),         (0x2, 5),         (0x19, 6),
    (0x1a, 6),        (0x1b, 6),        (0x1c, 6),        (0x1d, 6),
    (0x1e, 6),        (0x1f, 6),        (0x5c, 7),        (0xfb, 8),
    (0x7ffc, 15),     (0x20, 6),        (0xffb, 12),      (0x3fc, 10),
    (0x1ffa, 13),     (0x21, 6),        (0x5d, 7),        (0x5e, 7),
    (0x5f, 7),        (0x60, 7),        (0x61, 7),        (0x62, 7),
    (0x63, 7),        (0x64, 7),        (0x65, 7),        (0x66, 7),
    (0x67, 7),        (0x68, 7),        (0x69, 7),        (0x6a, 7),
    (0x6b, 7),        (0x6c, 7),        (0x6d, 7),        (0x6e, 7),
    (0x6f, 7),        (0x70, 7),        (0x71, 7),        (0x72, 7),
    (0xfc, 8),        (0x73, 7),        (0xfd, 8),        (0x1ffb, 13),
    (0x7fff0, 19),    (0x1ffc, 13),     (0x3ffc, 14),     (0x22, 6),
    (0x7ffd, 15),     (0x3, 5),         (0x23, 6),        (0x4, 5),
    (0x24, 6),        (0x5, 5),         (0x25, 6),        (0x26, 6),
    (0x27, 6),        (0x6, 5),         (0x74, 7),        (0x75, 7),
    (0x28, 6),        (0x29, 6),        (0x2a, 6),        (0x7, 5),
    (0x2b, 6),        (0x76, 7),        (0x2c, 6),        (0x8, 5),
    (0x9, 5),         (0x2d, 6),        (0x77, 7),        (0x78, 7),
    (0x79, 7),        (0x7a, 7),        (0x7b, 7),        (0x7ffe, 15),
    (0x7fc, 11),      (0x3ffd, 14),     (0x1ffd, 13),     (0xffffffc, 28),
    (0xfffe6, 20),    (0x3fffd2, 22),   (0xfffe7, 20),    (0xfffe8, 20),
    (0x3fffd3, 22),   (0x3fffd4, 22),   (0x3fffd5, 22),   (0x7fffd9, 23),
    (0x3fffd6, 22),   (0x7fffda, 23),   (0x7fffdb, 23),   (0x7fffdc, 23),
    (0x7fffdd, 23),   (0x7fffde, 23),   (0xffffeb, 24),   (0x7fffdf, 23),
    (0xffffec, 24),   (0xffffed, 24),   (0x3fffd7, 22),   (0x7fffe0, 23),
    (0xffffee, 24),   (0x7fffe1, 23),   (0x7fffe2, 23),   (0x7fffe3, 23),
    (0x7fffe4, 23),   (0x1fffdc, 21),   (0x3fffd8, 22),   (0x7fffe5, 23),
    (0x3fffd9, 22),   (0x7fffe6, 23),   (0x7fffe7, 23),   (0xffffef, 24),
    (0x3fffda, 22),   (0x1fffdd, 21),   (0xfffe9, 20),    (0x3fffdb, 22),
    (0x3fffdc, 22),   (0x7fffe8, 23),   (0x7fffe9, 23),   (0x1fffde, 21),
    (0x7fffea, 23),   (0x3fffdd, 22),   (0x3fffde, 22),   (0xfffff0, 24),
    (0x1fffdf, 21),   (0x3fffdf, 22),   (0x7fffeb, 23),   (0x7fffec, 23),
    (0x1fffe0, 21),   (0x1fffe1, 21),   (0x3fffe0, 22),   (0x1fffe2, 21),
    (0x7fffed, 23),   (0x3fffe1, 22),   (0x7fffee, 23),   (0x7fffef, 23),
    (0xfffea, 20),    (0x3fffe2, 22),   (0x3fffe3, 22),   (0x3fffe4, 22),
    (0x7ffff0, 23),   (0x3fffe5, 22),   (0x3fffe6, 22),   (0x7ffff1, 23),
    (0x3ffffe0, 26),  (0x3ffffe1, 26),  (0xfffeb, 20),    (0x7fff1, 19),
    (0x3fffe7, 22),   (0x7ffff2, 23),   (0x3fffe8, 22),   (0x1ffffec, 25),
    (0x3ffffe2, 26),  (0x3ffffe3, 26),  (0x3ffffe4, 26),  (0x7ffffde, 27),
    (0x7ffffdf, 27),  (0x3ffffe5, 26),  (0xfffff1, 24),   (0x1ffffed, 25),
    (0x7fff2, 19),    (0x1fffe3, 21),   (0x3ffffe6, 26),  (0x7ffffe0, 27),
    (0x7ffffe1, 27),  (0x3ffffe7, 26),  (0x7ffffe2, 27),  (0xfffff2, 24),
    (0x1fffe4, 21),   (0x1fffe5, 21),   (0x3ffffe8, 26),  (0x3ffffe9, 26),
    (0xffffffd, 28),  (0x7ffffe3, 27),  (0x7ffffe4, 27),  (0x7ffffe5, 27),
    (0xfffec, 20),    (0xfffff3, 24),   (0xfffed, 20),    (0x1fffe6, 21),
    (0x3fffe9, 22),   (0x1fffe7, 21),   (0x1fffe8, 21),   (0x7ffff3, 23),
    (0x3fffea, 22),   (0x3fffeb, 22),   (0x1ffffee, 25),  (0x1ffffef, 25),
    (0xfffff4, 24),   (0xfffff5, 24),   (0x3ffffea, 26),  (0x7ffff4, 23),
    (0x3ffffeb, 26),  (0x7ffffe6, 27),  (0x3ffffec, 26),  (0x3ffffed, 26),
    (0x7ffffe7, 27),  (0x7ffffe8, 27),  (0x7ffffe9, 27),  (0x7ffffea, 27),
    (0x7ffffeb, 27),  (0xffffffe, 28),  (0x7ffffec, 27),  (0x7ffffed, 27),
    (0x7ffffee, 27),  (0x7ffffef, 27),  (0x7fffff0, 27),  (0x3ffffee, 26),
    (0x3fffffff, 30),
];

/// The EOS symbol's index in [`CODES`].
///
/// Never emitted by [`encode`]: RFC 7541 §5.2 says "A Huffman-encoded string
/// literal containing the EOS symbol MUST be treated as a decoding error", so a
/// literal that carries it is a bug in the encoder, not a test case. The entry
/// is kept because the padding rule below is defined in terms of its code.
pub const EOS: usize = 256;

/// Huffman-encodes a string literal.
///
/// The final byte is padded as RFC 7541 §5.2 requires: "As the Huffman-encoded
/// data doesn't always end at an octet boundary, some padding is inserted after
/// it, up to the next octet boundary. To prevent this padding from being
/// misinterpreted as part of the string literal, the most significant bits of
/// the code corresponding to the EOS (end-of-string) symbol are used." Those
/// bits are all ones, which is why the padding below is simply that.
pub fn encode(input: &[u8]) -> Vec<u8> {
    // Never more than one byte per symbol plus the padding byte: the longest
    // code is 30 bits, but the codes that are longer than 8 bits belong to
    // symbols a field line practically never carries, and over-reserving by a
    // factor of four is not worth the arithmetic in a test helper.
    let mut out = Vec::with_capacity(input.len() + 1);

    // The bits written so far that do not yet fill a byte. Thirty bits of code
    // on top of at most seven left over needs 37, so `u64` is the natural size.
    let mut acc = 0u64;
    let mut bits = 0u32;

    for symbol in input {
        let (code, length) = CODES[usize::from(*symbol)];
        acc = (acc << length) | u64::from(code);
        bits += u32::from(length);

        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }

    if bits > 0 {
        let padding = 8 - bits;
        out.push(((acc << padding) | ((1u64 << padding) - 1)) as u8);
    }

    out
}
