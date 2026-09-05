//! Huffman decoding for QPACK string literals (RFC 7541 Appendix B).
//!
//! QPACK borrows HPACK's Huffman code unchanged (RFC 9204 §4.1.2: "the Huffman
//! table from Appendix B of \[RFC7541\] is used without modification"), so the
//! table below is RFC 7541 Appendix B verbatim: one `(code, bit length)` pair
//! per symbol, in symbol order, plus the EOS symbol at index 256.
//!
//! Only decoding lives here. This server never Huffman-encodes: RFC 9204 §4.1.2
//! leaves the choice to the encoder, a response of a few field lines saves a
//! handful of bytes at best, and not encoding removes a whole error path from
//! the send side.
//!
//! The code is *canonical* — within each length the codes are consecutive and
//! assigned in increasing symbol order — which is what makes the decoder below
//! two small arrays rather than a tree. The unit tests re-derive that property
//! from the table, so a mistyped entry fails the build rather than one client's
//! request.

use std::sync::OnceLock;

use super::error::{Code, Violation};

/// Longest code in the table, in bits.
///
/// A `usize` because every use of it is an array bound or an index into one:
/// the three per-length tables below are `MAX_CODE_BITS + 1` long, and the
/// decoder's running bit count is compared against it before it indexes them.
const MAX_CODE_BITS: usize = 30;

/// The EOS symbol's index in [`CODES`].
///
/// RFC 7541 §5.2: "A Huffman-encoded string literal containing the EOS symbol
/// MUST be treated as a decoding error", so it is never produced as output.
const EOS: u16 = 256;

/// RFC 7541 Appendix B: `(code, code length in bits)` for symbols 0..=255,
/// then EOS.
#[rustfmt::skip]
const CODES: [(u32, u8); 257] = [
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

/// The tables a canonical Huffman code needs to be decoded bit by bit.
///
/// `count[n]` is how many symbols have an `n`-bit code, `first_code[n]` the
/// smallest of them, and `first_index[n]` where that run starts in `symbols`.
/// Decoding is then: shift a bit in, and check whether the accumulated value
/// falls inside the run for the current length.
struct Table {
    count: [u16; MAX_CODE_BITS + 1],
    first_code: [u32; MAX_CODE_BITS + 1],
    first_index: [u16; MAX_CODE_BITS + 1],
    symbols: [u16; CODES.len()],
}

/// Builds [`Table`] from [`CODES`] on first use.
///
/// Derived rather than checked in: the canonical form is a consequence of the
/// RFC's table, so generating it here keeps one copy of the data and lets the
/// tests verify the derivation.
fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();

    TABLE.get_or_init(|| {
        let mut count = [0u16; MAX_CODE_BITS + 1];
        for (_, bits) in CODES {
            count[usize::from(bits)] += 1;
        }

        let mut first_code = [0u32; MAX_CODE_BITS + 1];
        let mut first_index = [0u16; MAX_CODE_BITS + 1];
        let mut code = 0u32;
        let mut index = 0u16;
        for bits in 1..=MAX_CODE_BITS {
            code = (code + u32::from(count[bits - 1])) << 1;
            first_code[bits] = code;
            first_index[bits] = index;
            index += count[bits];
        }

        // Within a length the codes are consecutive and ordered by symbol, so
        // walking the symbols in order fills each run left to right.
        let mut symbols = [0u16; CODES.len()];
        let mut next = first_index;
        // Counted in `u16` rather than through `enumerate`, because a symbol is
        // what `symbols` holds and the table is 257 entries long.
        for (symbol, (_, bits)) in (0u16..).zip(CODES.iter()) {
            let slot = &mut next[usize::from(*bits)];
            symbols[usize::from(*slot)] = symbol;
            *slot += 1;
        }

        Table {
            count,
            first_code,
            first_index,
            symbols,
        }
    })
}

/// Decodes a Huffman-encoded string literal.
///
/// Every failure is the same stream error, carrying QPACK_DECOMPRESSION_FAILED
/// and ending only the request that carried the literal -- this server's own
/// rule, not one RFC 7541 or RFC 9204 states; see `failed` below for why.
pub fn decode(encoded: &[u8]) -> Result<Vec<u8>, Violation> {
    let table = table();

    // A Huffman code is at least five bits, so this cannot over-reserve by more
    // than a factor of eight -- and never under-reserves, so the loop below
    // never grows the vector.
    let mut out = Vec::with_capacity(encoded.len() * 8 / 5 + 1);

    // The bits seen since the last complete symbol, and how many there are.
    let mut code = 0u32;
    let mut bits = 0usize;

    for byte in encoded {
        for shift in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> shift) & 1);
            bits += 1;

            if bits > MAX_CODE_BITS {
                return Err(failed("no Huffman code matches these bits"));
            }

            let offset = match code.checked_sub(table.first_code[bits]) {
                Some(offset) if offset < u32::from(table.count[bits]) => offset,
                // Not a code of this length; take another bit.
                _ => continue,
            };

            // The guard above put `offset` below `count[bits]`, and the counts
            // sum to the 257 entries of `CODES`, so this index is one of them.
            #[allow(clippy::as_conversions)]
            let symbol = table.symbols[usize::from(table.first_index[bits]) + offset as usize];
            if symbol == EOS {
                // RFC 7541 §5.2: EOS inside a literal is a decoding error.
                return Err(failed("the EOS symbol appeared in a string literal"));
            }
            // Every symbol below `EOS` is a byte, and `EOS` is the only entry
            // of `CODES` past 255; the line above refused it.
            #[allow(clippy::as_conversions)]
            out.push(symbol as u8);

            code = 0;
            bits = 0;
        }
    }

    // RFC 7541 §5.2: the padding is "the most significant bits of the code
    // corresponding to the EOS (end-of-string) symbol", i.e. all ones, and "A
    // padding strictly longer than 7 bits MUST be treated as a decoding
    // error". Padding that is not all ones is the start of a symbol that never
    // finished.
    if bits >= 8 {
        return Err(failed("Huffman padding is longer than seven bits"));
    }
    if code != (1 << bits) - 1 {
        return Err(failed("Huffman padding is not all ones"));
    }

    Ok(out)
}

/// The one error this module produces: a stream error, not a connection one.
///
/// RFC 7541 §5.2 states each of these faults as a "decoding error" and says
/// nothing about which class it belongs to, and RFC 9204 mandates a connection
/// error only for the three cases named in [`super::qpack`], none of which a
/// string literal can be. So this is our own rule rather than the RFC's: with a
/// zero dynamic table capacity nothing is carried between field sections, so a
/// literal this decoder cannot read desynchronises nothing, and answering on the
/// stream costs the one request instead of every tunnel on the connection.
fn failed(detail: &'static str) -> Violation {
    Violation::stream(Code::QPACK_DECOMPRESSION_FAILED, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> Vec<u8> {
        let digits: Vec<char> = hex.chars().filter(|c| !c.is_whitespace()).collect();
        digits
            .chunks(2)
            .map(|pair| u8::from_str_radix(&pair.iter().collect::<String>(), 16).expect("hex byte"))
            .collect()
    }

    /// The table is only usable if it really is a canonical prefix code, and a
    /// single mistyped entry would break that. Re-deriving the codes from the
    /// lengths alone and comparing is a complete check of both.
    #[test]
    fn the_table_is_a_canonical_prefix_code() {
        let table = table();

        let mut code = 0u32;
        for bits in 1..=MAX_CODE_BITS {
            code = (code + u32::from(table.count[bits - 1])) << 1;

            let mut expected = code;
            for (symbol, (actual, length)) in CODES.iter().enumerate() {
                if usize::from(*length) == bits {
                    assert_eq!(
                        *actual, expected,
                        "symbol {symbol} is not canonical at {bits} bits"
                    );
                    expected += 1;
                }
            }
        }
    }

    /// Spot checks against RFC 7541 Appendix B, at both ends of the table.
    #[test]
    fn the_table_matches_the_rfc_appendix() {
        assert_eq!(CODES[0], (0x1ff8, 13));
        assert_eq!(CODES[usize::from(b' ')], (0x14, 6));
        assert_eq!(CODES[usize::from(b'0')], (0x0, 5));
        assert_eq!(CODES[usize::from(b'a')], (0x3, 5));
        assert_eq!(CODES[255], (0x3ffffee, 26));
        assert_eq!(CODES[usize::from(EOS)], (0x3fffffff, 30));
    }

    /// The literals of RFC 7541 Appendix C.4, which are the ones a real client
    /// sends: a host name, a cache directive, and a custom name/value pair.
    #[test]
    fn the_rfc_7541_appendix_c4_examples_decode() {
        for (encoded, expected) in [
            ("f1e3 c2e5 f23a 6ba0 ab90 f4ff", &b"www.example.com"[..]),
            ("a8eb 1064 9cbf", &b"no-cache"[..]),
            ("25a8 49e9 5ba9 7d7f", &b"custom-key"[..]),
            ("25a8 49e9 5bb8 e8b4 bf", &b"custom-value"[..]),
        ] {
            assert_eq!(decode(&bytes(encoded)).expect("decodes"), expected);
        }
    }

    #[test]
    fn an_empty_literal_decodes_to_nothing() {
        assert_eq!(decode(&[]).expect("decodes"), b"");
    }

    /// RFC 7541 §5.2: padding must be the leading bits of EOS, so a zero bit in
    /// it is a decoding error rather than a symbol that happens to fit.
    #[test]
    fn padding_that_is_not_all_ones_is_rejected() {
        // "0" is 00000 (5 bits); padding the byte with zeros leaves 000.
        assert!(decode(&[0b0000_0000]).is_err());
        // The same symbol correctly padded.
        assert_eq!(decode(&[0b0000_0111]).expect("decodes"), b"0");
    }

    /// A whole byte of ones is eight bits of padding, one more than allowed.
    #[test]
    fn padding_longer_than_seven_bits_is_rejected() {
        let error = decode(&[0b0000_0111, 0b1111_1111]).expect_err("rejected");
        assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
        assert!(!error.is_connection_error(), "{error}");
    }

    /// RFC 7541 §5.2: EOS must never appear as a symbol.
    #[test]
    fn the_eos_symbol_is_rejected() {
        // EOS is thirty ones, then five ones of padding: five bytes of 0xff.
        assert!(decode(&[0xff; 5]).is_err());
    }

    /// Every failure carries QPACK_DECOMPRESSION_FAILED and ends the stream
    /// rather than the connection -- the class this server chose, and the one
    /// RFC 9204 §7.4 states for the only such failure it does classify.
    #[test]
    fn every_failure_is_a_qpack_stream_error() {
        for input in [vec![0u8], vec![0xff; 5], vec![0b0000_0111, 0xff]] {
            let error = decode(&input).expect_err("rejected");
            assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
            assert!(!error.is_connection_error(), "{error}");
        }
    }
}
