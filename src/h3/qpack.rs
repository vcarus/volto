//! QPACK field-section coding (RFC 9204), static table only.
//!
//! This server advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` and
//! `SETTINGS_QPACK_BLOCKED_STREAMS = 0`, which RFC 9204 §3.2.3 and §2.1.2 make
//! binding on the encoder: it may not insert into the dynamic table, so every
//! field line it sends is either a static-table reference or a literal. That is what lets the
//! whole dynamic table -- insertion, eviction, the two instruction streams, and
//! the head-of-line blocking they can introduce -- be left out rather than
//! written and never used. A field line that does reference the dynamic table is
//! therefore not merely unsupported but a protocol violation, and is answered as
//! RFC 9204 §2.2.3 requires.
//!
//! Encoding is the mirror image and just as small: the exact `(name, value)` in
//! the static table when there is one, its name alone when only that matches,
//! and a literal otherwise. Nothing is Huffman-encoded -- see [`super::huffman`].

use std::borrow::Cow;

use bytes::{BufMut, BytesMut};

use super::error::{Code, Violation};
use super::huffman;

/// Per-field overhead in the size formula of RFC 9114 §4.2.2.
///
/// "The size of a field list is calculated based on the uncompressed size of
/// fields, including the length of the name and value in bytes plus an overhead
/// of 32 bytes for each field."
const FIELD_OVERHEAD: u64 = 32;

/// One decoded field line.
///
/// Bytes rather than the [`super::message`] types, because a pseudo-header is
/// neither a field name nor a field value: `:method` is not a token, and
/// RFC 9114 §4.3's rule that the pseudo-headers come first can only be checked
/// while the two kinds are still one sequence. Sorting them out is
/// [`super::stream`]'s job, and it is the same pass that validates them.
///
/// `Cow` rather than `Vec` so that a static-table hit -- which is what every
/// pseudo-header of a CONNECT request is -- costs a pointer instead of a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// The field name, always lowercase on the wire (RFC 9114 §4.2).
    pub name: Cow<'static, [u8]>,
    /// The field value.
    pub value: Cow<'static, [u8]>,
}

impl Field {
    /// The field's contribution to the field section size (RFC 9114 §4.2.2).
    fn size(&self) -> u64 {
        self.name.len() as u64 + self.value.len() as u64 + FIELD_OVERHEAD
    }
}

/// The QPACK static table (RFC 9204 Appendix A), indexed from 0.
#[rustfmt::skip]
const STATIC_TABLE: [(&[u8], &[u8]); 99] = [
    (b":authority", b""),
    (b":path", b"/"),
    (b"age", b"0"),
    (b"content-disposition", b""),
    (b"content-length", b"0"),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"referer", b""),
    (b"set-cookie", b""),
    (b":method", b"CONNECT"),
    (b":method", b"DELETE"),
    (b":method", b"GET"),
    (b":method", b"HEAD"),
    (b":method", b"OPTIONS"),
    (b":method", b"POST"),
    (b":method", b"PUT"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"103"),
    (b":status", b"200"),
    (b":status", b"304"),
    (b":status", b"404"),
    (b":status", b"503"),
    (b"accept", b"*/*"),
    (b"accept", b"application/dns-message"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"accept-ranges", b"bytes"),
    (b"access-control-allow-headers", b"cache-control"),
    (b"access-control-allow-headers", b"content-type"),
    (b"access-control-allow-origin", b"*"),
    (b"cache-control", b"max-age=0"),
    (b"cache-control", b"max-age=2592000"),
    (b"cache-control", b"max-age=604800"),
    (b"cache-control", b"no-cache"),
    (b"cache-control", b"no-store"),
    (b"cache-control", b"public, max-age=31536000"),
    (b"content-encoding", b"br"),
    (b"content-encoding", b"gzip"),
    (b"content-type", b"application/dns-message"),
    (b"content-type", b"application/javascript"),
    (b"content-type", b"application/json"),
    (b"content-type", b"application/x-www-form-urlencoded"),
    (b"content-type", b"image/gif"),
    (b"content-type", b"image/jpeg"),
    (b"content-type", b"image/png"),
    (b"content-type", b"text/css"),
    (b"content-type", b"text/html; charset=utf-8"),
    (b"content-type", b"text/plain"),
    (b"content-type", b"text/plain;charset=utf-8"),
    (b"range", b"bytes=0-"),
    (b"strict-transport-security", b"max-age=31536000"),
    (b"strict-transport-security", b"max-age=31536000; includesubdomains"),
    (b"strict-transport-security", b"max-age=31536000; includesubdomains; preload"),
    (b"vary", b"accept-encoding"),
    (b"vary", b"origin"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-xss-protection", b"1; mode=block"),
    (b":status", b"100"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"302"),
    (b":status", b"400"),
    (b":status", b"403"),
    (b":status", b"421"),
    (b":status", b"425"),
    (b":status", b"500"),
    (b"accept-language", b""),
    (b"access-control-allow-credentials", b"FALSE"),
    (b"access-control-allow-credentials", b"TRUE"),
    (b"access-control-allow-headers", b"*"),
    (b"access-control-allow-methods", b"get"),
    (b"access-control-allow-methods", b"get, post, options"),
    (b"access-control-allow-methods", b"options"),
    (b"access-control-expose-headers", b"content-length"),
    (b"access-control-request-headers", b"content-type"),
    (b"access-control-request-method", b"get"),
    (b"access-control-request-method", b"post"),
    (b"alt-svc", b"clear"),
    (b"authorization", b""),
    (b"content-security-policy", b"script-src 'none'; object-src 'none'; base-uri 'none'"),
    (b"early-data", b"1"),
    (b"expect-ct", b""),
    (b"forwarded", b""),
    (b"if-range", b""),
    (b"origin", b""),
    (b"purpose", b"prefetch"),
    (b"server", b""),
    (b"timing-allow-origin", b"*"),
    (b"upgrade-insecure-requests", b"1"),
    (b"user-agent", b""),
    (b"x-forwarded-for", b""),
    (b"x-frame-options", b"deny"),
    (b"x-frame-options", b"sameorigin"),
];

/// Decodes an encoded field section.
///
/// `max_section_size` is the value advertised in
/// `SETTINGS_MAX_FIELD_SECTION_SIZE`; a peer that ignores it is cut off at that
/// point rather than allowed to make this server accumulate fields for it.
pub fn decode(block: &[u8], max_section_size: u64) -> Result<Vec<Field>, Violation> {
    let mut reader = Reader::new(block);
    let mut fields = Vec::new();
    let mut size = 0u64;

    // 4.5.1. Encoded Field Section Prefix.
    let (_, required_insert_count) = reader.take_int(8)?;
    if required_insert_count != 0 {
        // With a zero table capacity the encoder cannot have inserted anything,
        // so no conformant encoder could have produced a non-zero count.
        //
        //= https://www.rfc-editor.org/rfc/rfc9204#section-4.5.1.1
        //# If the decoder encounters a value of EncodedInsertCount that could
        //# not have been produced by a conformant encoder, it MUST treat this
        //# as a connection error of type QPACK_DECOMPRESSION_FAILED.
        return Err(connection_error(
            "a non-zero Required Insert Count with no dynamic table",
        ));
    }
    // 4.5.1.2. Base, encoded as a Sign bit and a Delta Base value. The Delta
    // Base itself is read and discarded: RFC 9204 §4.5.1.2 derives Base from
    // it, and Base only ever names dynamic entries, every one of which is
    // refused below. Parsing it is still necessary to find where the field
    // lines start.
    let (flags, _delta_base) = reader.take_int(7)?;

    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.5.1.2
    //# An endpoint MUST treat a field block with a Sign bit of 1 as invalid
    //# if the value of Required Insert Count is less than or equal to the
    //# value of Delta Base.
    //
    // Required Insert Count is zero above -- with a zero table capacity it can
    // be nothing else -- and zero is less than or equal to every Delta Base, so
    // here a Sign bit of 1 is invalid whatever follows it. "Invalid" is not
    // given a class in §4.5.1.2; this decoder answers it as the same connection
    // error as the Required Insert Count fault above, because a prefix that
    // cannot be read leaves this endpoint unable to say what the field lines
    // after it were encoded against.
    if flags & 1 == 1 {
        return Err(connection_error(
            "a Sign bit of 1 with a zero Required Insert Count",
        ));
    }

    while let Some(first) = reader.peek() {
        let field = if first & 0b1000_0000 != 0 {
            // 4.5.2. Indexed Field Line: | 1 | T | Index (6+) |
            let (_, index) = reader.take_int(6)?;
            if first & 0b0100_0000 == 0 {
                return Err(dynamic_reference());
            }
            let (name, value) = static_entry(index)?;
            Field {
                name: Cow::Borrowed(name),
                value: Cow::Borrowed(value),
            }
        } else if first & 0b1100_0000 == 0b0100_0000 {
            // 4.5.4. Literal Field Line With Name Reference:
            // | 0 | 1 | N | T | Name Index (4+) |
            let (_, index) = reader.take_int(4)?;
            if first & 0b0001_0000 == 0 {
                return Err(dynamic_reference());
            }
            let (name, _) = static_entry(index)?;
            Field {
                name: Cow::Borrowed(name),
                value: Cow::Owned(reader.take_string(7)?),
            }
        } else if first & 0b1110_0000 == 0b0010_0000 {
            // 4.5.6. Literal Field Line With Literal Name:
            // | 0 | 0 | 1 | N | H | Name Length (3+) |
            Field {
                name: Cow::Owned(reader.take_string(3)?),
                value: Cow::Owned(reader.take_string(7)?),
            }
        } else {
            // 4.5.3. Indexed Field Line With Post-Base Index and 4.5.5. Literal
            // Field Line With Post-Base Name Reference. Both name dynamic table
            // entries only, so neither can occur here.
            return Err(dynamic_reference());
        };

        size += field.size();
        if size > max_section_size {
            // Not a QPACK failure: the section decoded, it is simply larger
            // than what SETTINGS_MAX_FIELD_SECTION_SIZE told the peer to send.
            // RFC 9114 §8.1 defines H3_EXCESSIVE_LOAD for a peer "exhibiting a
            // behavior that might be generating excessive load", which is what
            // ignoring an advertised bound is.
            return Err(Violation::stream(
                Code::H3_EXCESSIVE_LOAD,
                format!("field section exceeds the advertised {max_section_size} bytes"),
            ));
        }
        fields.push(field);
    }

    Ok(fields)
}

/// Encodes a field section: the prefix, then one line per field.
///
/// The prefix is always `0x00 0x00` -- Required Insert Count 0, Base 0 -- which
/// RFC 9204 §4.5.1 requires of a section that references no dynamic entry.
pub fn encode<'a, I>(out: &mut BytesMut, fields: I)
where
    I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
{
    out.put_u8(0);
    out.put_u8(0);

    for (name, value) in fields {
        match find(name, value) {
            // 4.5.2. Indexed Field Line, T = 1 (static).
            Found::Entry(index) => put_int(out, 6, 0b11, index),
            // 4.5.4. Literal Field Line With Name Reference, N = 0, T = 1.
            Found::Name(index) => {
                put_int(out, 4, 0b0101, index);
                put_string(out, 7, 0, value);
            }
            // 4.5.6. Literal Field Line With Literal Name, N = 0, H = 0.
            Found::Nothing => {
                put_string(out, 3, 0b0010, name);
                put_string(out, 7, 0, value);
            }
        }
    }
}

/// What the static table has to offer for one field.
enum Found {
    /// Both name and value match entry `0`.
    Entry(u64),
    /// Only the name matches, at entry `0`.
    Name(u64),
    /// Neither: the field has to be spelled out.
    Nothing,
}

/// Searches the static table for `name`/`value`, in one pass.
///
/// Linear because the table is 99 entries and a response carries three of them
/// at most: an index would cost more to build than it could ever save.
fn find(name: &[u8], value: &[u8]) -> Found {
    let mut name_only = None;

    for (index, (entry_name, entry_value)) in STATIC_TABLE.iter().enumerate() {
        if *entry_name != name {
            continue;
        }
        if *entry_value == value {
            return Found::Entry(index as u64);
        }
        name_only.get_or_insert(index as u64);
    }

    name_only.map_or(Found::Nothing, Found::Name)
}

/// Looks up a static table entry, rejecting an index past its end.
fn static_entry(index: u64) -> Result<(&'static [u8], &'static [u8]), Violation> {
    usize::try_from(index)
        .ok()
        .and_then(|index| STATIC_TABLE.get(index))
        .copied()
        .ok_or_else(|| {
            //= https://www.rfc-editor.org/rfc/rfc9204#section-3.1
            //# When the decoder encounters an invalid static table index in a
            //# field line representation, it MUST treat this as a connection
            //# error of type QPACK_DECOMPRESSION_FAILED.
            connection_error("static table index out of range")
        })
}

/// A reference to the dynamic table, which this decoder never has entries for.
fn dynamic_reference() -> Violation {
    //= https://www.rfc-editor.org/rfc/rfc9204#section-2.2.3
    //# If the decoder encounters a reference in a field line representation to
    //# a dynamic table entry that has already been evicted or that has an
    //# absolute index greater than or equal to the declared Required Insert
    //# Count (Section 4.5.1), it MUST treat this as a connection error of type
    //# QPACK_DECOMPRESSION_FAILED.
    connection_error("a dynamic table reference with a zero table capacity")
}

/// A failure this decoder answers by closing the connection.
///
/// RFC 9204 states three of them, and this decoder can reach all three: a
/// reference to the dynamic table (§2.2.3), an invalid static table index
/// (§3.1), and a Required Insert Count no conformant encoder could have
/// produced (§4.5.1.1). A fourth, the field block §4.5.1.2 makes invalid
/// through its Sign bit, is graded the same way by this server's own reading --
/// the RFC leaves that one's class unstated. Each is quoted at the point it is
/// raised.
fn connection_error(detail: &'static str) -> Violation {
    Violation::connection(Code::QPACK_DECOMPRESSION_FAILED, detail)
}

/// A failure answered on the one stream it arrived on.
///
/// Everything else a field section can be wrong about -- a representation that
/// ends early, a string literal Huffman decoding rejects -- carries the same
/// QPACK_DECOMPRESSION_FAILED code but ends only the request that carried it.
/// That is this server's own reading, not a rule the RFC states: RFC 9204
/// mandates a connection error for the three cases in [`connection_error`] and
/// for those only, while RFC 7541 §5.2 calls a bad literal a "decoding error"
/// without naming a class at all. With a zero dynamic table capacity this
/// decoder holds no state between field sections, so a section it could not
/// read leaves nothing desynchronised, and the narrower answer costs one
/// request rather than every tunnel on the connection. The one case the RFC
/// does class is an integer too large to decode, which §7.4 makes a stream
/// error on a request stream -- quoted where it is raised.
fn stream_error(detail: &'static str) -> Violation {
    Violation::stream(Code::QPACK_DECOMPRESSION_FAILED, detail)
}

/// A cursor over an encoded field section.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// The next byte without consuming it, or `None` at the end of the section.
    fn peek(&self) -> Option<u8> {
        self.buf.first().copied()
    }

    /// Reads a prefixed integer with a `prefix_bits`-wide field (RFC 7541 §5.1).
    ///
    /// Returns the bits above the prefix -- the representation's flags -- along
    /// with the value.
    fn take_int(&mut self, prefix_bits: u32) -> Result<(u8, u64), Violation> {
        let (first, rest) = self.buf.split_first().ok_or_else(truncated)?;
        self.buf = rest;

        // Computed in `u16` so a full eight-bit prefix -- the Required Insert
        // Count -- does not shift a `u8` by its own width.
        let mask = ((1u16 << prefix_bits) - 1) as u8;
        let flags = (u16::from(*first) >> prefix_bits) as u8;
        let mut value = u64::from(first & mask);
        if value < u64::from(mask) {
            return Ok((flags, value));
        }

        // The continuation bytes carry seven bits each, least significant first.
        let mut shift = 0u32;
        loop {
            let (byte, rest) = self.buf.split_first().ok_or_else(truncated)?;
            self.buf = rest;

            let added = u64::from(byte & 0x7f)
                .checked_shl(shift)
                .and_then(|added| {
                    // A shift that dropped bits, or a sum past 2^64, is a value
                    // no field section can legitimately carry.
                    (added >> shift == u64::from(byte & 0x7f)).then_some(added)
                })
                .and_then(|added| value.checked_add(added))
                //= https://www.rfc-editor.org/rfc/rfc9204#section-7.4
                //# If an implementation encounters a value larger than it is
                //# able to decode, this MUST be treated as a stream error of
                //# type QPACK_DECOMPRESSION_FAILED if on a request stream or a
                //# connection error of the appropriate type if on the encoder
                //# or decoder stream.
                .ok_or_else(|| stream_error("prefixed integer overflows"))?;
            value = added;

            if byte & 0x80 == 0 {
                return Ok((flags, value));
            }
            shift += 7;
        }
    }

    /// Reads a string literal: a length with an `H` bit above it, then bytes.
    fn take_string(&mut self, prefix_bits: u32) -> Result<Vec<u8>, Violation> {
        let (flags, length) = self.take_int(prefix_bits)?;
        let length = usize::try_from(length).map_err(|_| truncated())?;
        if self.buf.len() < length {
            return Err(truncated());
        }

        let (literal, rest) = self.buf.split_at(length);
        self.buf = rest;

        // The Huffman bit is the one immediately above the length prefix.
        if flags & 1 == 0 {
            Ok(literal.to_vec())
        } else {
            huffman::decode(literal)
        }
    }
}

/// The section ended in the middle of a field line.
///
/// A stream error: see [`stream_error`] for why this class rather than the
/// other.
fn truncated() -> Violation {
    stream_error("the field section ended mid-representation")
}

/// Writes a prefixed integer with `flags` in the bits above the prefix.
fn put_int(out: &mut BytesMut, prefix_bits: u32, flags: u8, value: u64) {
    let mask = u64::from((1u16 << prefix_bits) - 1);
    let flags = ((u16::from(flags) << prefix_bits) & 0xff) as u8;

    if value < mask {
        out.put_u8(flags | value as u8);
        return;
    }

    out.put_u8(flags | mask as u8);
    let mut remaining = value - mask;
    while remaining >= 0x80 {
        out.put_u8((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    out.put_u8(remaining as u8);
}

/// Writes a string literal, never Huffman-encoded.
///
/// `flags` are the bits above the `H` bit, which this encoder always leaves
/// clear -- see [`super::huffman`] for why nothing is Huffman-encoded.
fn put_string(out: &mut BytesMut, prefix_bits: u32, flags: u8, value: &[u8]) {
    put_int(out, prefix_bits, flags << 1, value.len() as u64);
    out.put_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A field section with the `0x00 0x00` prefix in front of `body`.
    fn section(body: &[u8]) -> Vec<u8> {
        let mut block = vec![0, 0];
        block.extend_from_slice(body);
        block
    }

    fn decoded(block: &[u8]) -> Vec<(String, String)> {
        decode(block, super::super::MAX_FIELD_SECTION_SIZE)
            .expect("decodes")
            .into_iter()
            .map(|field| {
                (
                    String::from_utf8(field.name.into_owned()).expect("utf-8 name"),
                    String::from_utf8(field.value.into_owned()).expect("utf-8 value"),
                )
            })
            .collect()
    }

    #[test]
    fn the_static_table_matches_rfc_9204_appendix_a() {
        assert_eq!(STATIC_TABLE.len(), 99);
        assert_eq!(STATIC_TABLE[0], (&b":authority"[..], &b""[..]));
        assert_eq!(STATIC_TABLE[17], (&b":method"[..], &b"GET"[..]));
        assert_eq!(STATIC_TABLE[25], (&b":status"[..], &b"200"[..]));
        assert_eq!(
            STATIC_TABLE[98],
            (&b"x-frame-options"[..], &b"sameorigin"[..])
        );
    }

    /// RFC 9204 Appendix B.1: a field section that uses no dynamic table at
    /// all, one literal field line with the static name reference `:path`.
    #[test]
    fn the_rfc_9204_appendix_b1_example_decodes() {
        let block = [
            0x00, 0x00, 0x51, 0x0b, 0x2f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d,
            0x6c,
        ];
        assert_eq!(
            decoded(&block),
            vec![(":path".to_owned(), "/index.html".to_owned())]
        );
    }

    /// An indexed static field line, which is how every pseudo-header of a
    /// CONNECT request arrives.
    #[test]
    fn indexed_static_field_lines_decode() {
        // 0xcf = 1 (indexed) 1 (static) 001111 = index 15, `:method: CONNECT`.
        // 0xd7 = index 23, `:scheme: https`.
        assert_eq!(
            decoded(&section(&[0xcf, 0xd7])),
            vec![
                (":method".to_owned(), "CONNECT".to_owned()),
                (":scheme".to_owned(), "https".to_owned()),
            ]
        );
    }

    /// A literal with a static name reference, Huffman-encoded, which is what
    /// a client that compresses its field values emits for `:authority` and
    /// `:path`.
    #[test]
    fn a_huffman_literal_with_a_name_reference_decodes() {
        // 0x50 = 0101 0000: literal, N=0, T=1 (static), name index 0
        // (`:authority`). Then 0x8c = H=1, length 12, followed by the twelve
        // Huffman bytes RFC 7541 Appendix C.4 gives for "www.example.com".
        let mut body = vec![0x50, 0x8c];
        body.extend_from_slice(&[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ]);
        assert_eq!(
            decoded(&section(&body)),
            vec![(":authority".to_owned(), "www.example.com".to_owned())]
        );
    }

    /// The whole reason the dynamic table can be left out: a reference to it is
    /// impossible after advertising a zero capacity, so it is a violation
    /// rather than a gap.
    #[test]
    fn dynamic_table_references_are_refused() {
        for body in [
            vec![0x80],       // indexed field line, T = 0 (dynamic)
            vec![0x10],       // indexed field line with post-base index
            vec![0x40, 0x00], // literal with name reference, T = 0 (dynamic)
            vec![0x00, 0x00], // literal with post-base name reference
        ] {
            let error =
                decode(&section(&body), super::super::MAX_FIELD_SECTION_SIZE).expect_err("refused");
            assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
            assert!(error.is_connection_error(), "{error}");
        }
    }

    /// RFC 9204 §4.5.1.1: with a zero table capacity nothing can have been
    /// inserted, so a non-zero count is one no conformant encoder could send --
    /// one of the three failures the RFC states as a connection error.
    #[test]
    fn a_non_zero_required_insert_count_is_refused() {
        let error =
            decode(&[0x01, 0x00, 0xd7], super::super::MAX_FIELD_SECTION_SIZE).expect_err("refused");
        assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
        assert!(error.is_connection_error(), "{error}");
    }

    /// RFC 9204 §4.5.1.2 makes a field block with a Sign bit of 1 invalid
    /// "if the value of Required Insert Count is less than or equal to the
    /// value of Delta Base" -- and this decoder's Required Insert Count is
    /// always zero, so the Sign bit alone settles it.
    #[test]
    fn a_set_sign_bit_is_refused() {
        // 0x00 = Required Insert Count 0, 0x81 = S = 1 with Delta Base 1, then
        // an ordinary indexed static field line that would otherwise decode.
        let error =
            decode(&[0x00, 0x81, 0xd7], super::super::MAX_FIELD_SECTION_SIZE).expect_err("refused");
        assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
        assert!(error.is_connection_error(), "{error}");

        // S = 0 with the same Delta Base is the ordinary case and decodes.
        assert_eq!(
            decoded(&[0x00, 0x01, 0xd7]),
            vec![(":scheme".to_owned(), "https".to_owned())]
        );
    }

    /// RFC 9204 §3.1 states this one as a connection error too.
    #[test]
    fn a_static_index_past_the_table_is_refused() {
        // 0xff 0x24 = indexed static, index 63 + 36 = 99, one past the end.
        let error = decode(
            &section(&[0xff, 0x24]),
            super::super::MAX_FIELD_SECTION_SIZE,
        )
        .expect_err("refused");
        assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
        assert!(error.is_connection_error(), "{error}");
        // The last legal index still decodes.
        assert_eq!(
            decoded(&section(&[0xff, 0x23])),
            vec![("x-frame-options".to_owned(), "sameorigin".to_owned())]
        );
    }

    /// The RFC states no class for a truncated representation, so this server
    /// picks the narrower one: the request dies, the connection does not.
    #[test]
    fn a_truncated_representation_is_refused() {
        for body in [
            vec![0x51],             // a literal name whose length byte is missing
            vec![0x51, 0x0b, b'/'], // a literal name shorter than it declared
            vec![0xff],             // a prefixed integer with no continuation
        ] {
            let error =
                decode(&section(&body), super::super::MAX_FIELD_SECTION_SIZE).expect_err("refused");
            assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
            assert!(!error.is_connection_error(), "{error}");
        }
    }

    /// RFC 9204 §7.4 makes an undecodable value a *stream* error on a request
    /// stream, which is the only class the RFC states for this decoder's
    /// remaining failures.
    #[test]
    fn a_prefixed_integer_that_overflows_is_refused() {
        let mut body = vec![0xff];
        body.extend_from_slice(&[0xff; 12]);
        body.push(0x01);

        let error =
            decode(&section(&body), super::super::MAX_FIELD_SECTION_SIZE).expect_err("refused");
        assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
        assert!(!error.is_connection_error(), "{error}");
    }

    /// Prefixed integers round-trip at every boundary the prefix widths this
    /// codec uses can hit (RFC 7541 §5.1).
    #[test]
    fn prefixed_integers_round_trip() {
        for prefix_bits in [3u32, 4, 6, 7, 8] {
            let mask = u64::from((1u16 << prefix_bits) - 1);
            for value in [0, 1, mask - 1, mask, mask + 1, 1337, u64::from(u32::MAX)] {
                let mut buf = BytesMut::new();
                put_int(&mut buf, prefix_bits, 0, value);

                let (flags, decoded) = Reader::new(&buf).take_int(prefix_bits).expect("decodes");
                assert_eq!((flags, decoded), (0, value), "{prefix_bits}-bit prefix");
            }
        }
    }

    /// The example RFC 7541 §5.1 works through: 1337 in a five-bit prefix is
    /// `31, 154, 10`. This codec has no five-bit prefix, but the algorithm is
    /// the same one, so the check is worth having on a width it does use.
    #[test]
    fn prefixed_integers_match_the_rfc_encoding() {
        let mut buf = BytesMut::new();
        put_int(&mut buf, 7, 0, 1337);
        assert_eq!(&buf[..], &[127, 186, 9]);

        let mut buf = BytesMut::new();
        put_int(&mut buf, 8, 0, 42);
        assert_eq!(&buf[..], &[42]);
    }

    /// The whole of a 200 response to a CONNECT: prefix, then one byte.
    #[test]
    fn a_200_response_encodes_to_a_single_indexed_field() {
        let mut buf = BytesMut::new();
        encode(&mut buf, [(&b":status"[..], &b"200"[..])]);
        assert_eq!(&buf[..], &[0x00, 0x00, 0xd9]);
    }

    /// A status the table does not carry keeps the `:status` name reference and
    /// spells out the value.
    #[test]
    fn an_unlisted_status_uses_the_static_name() {
        let mut buf = BytesMut::new();
        encode(&mut buf, [(&b":status"[..], &b"407"[..])]);
        // 0x5f 0x09 = literal with static name reference, index 15 + 9 = 24
        // (`:status`), then a three-byte literal value.
        assert_eq!(&buf[..], &[0x00, 0x00, 0x5f, 0x09, 0x03, b'4', b'0', b'7']);
    }

    /// A field whose name is not in the table at all, such as the RFC 9209
    /// `proxy-status` this server answers refusals with.
    #[test]
    fn an_unlisted_name_encodes_as_a_literal() {
        let mut buf = BytesMut::new();
        encode(&mut buf, [(&b"proxy-status"[..], &b"volto"[..])]);

        // 0x27 = 001 (literal name) 0 (N) 0 (H) 111: a three-bit length
        // prefix at its maximum, so the remaining 5 of the 12 name bytes
        // follow as a continuation byte. The value's length fits its own
        // seven-bit prefix.
        let mut expected = vec![0x00, 0x00, 0x27, 0x05];
        expected.extend_from_slice(b"proxy-status");
        expected.push(5);
        expected.extend_from_slice(b"volto");
        assert_eq!(&buf[..], &expected[..]);
    }

    /// Everything this server sends must come back out of its own decoder.
    #[test]
    fn encoded_sections_decode_to_what_went_in() {
        let fields: [(&[u8], &[u8]); 4] = [
            (b":status", b"200"),
            (b"capsule-protocol", b"?1"),
            (b"proxy-status", b"volto; error=connection_refused"),
            (b"proxy-authenticate", b"Basic realm=\"volto\""),
        ];

        let mut buf = BytesMut::new();
        encode(&mut buf, fields);

        let expected: Vec<(String, String)> = fields
            .iter()
            .map(|(name, value)| {
                (
                    String::from_utf8_lossy(name).into_owned(),
                    String::from_utf8_lossy(value).into_owned(),
                )
            })
            .collect();
        assert_eq!(decoded(&buf), expected);
    }

    /// The advertised limit has to bite on the decode side too: a peer that
    /// ignores SETTINGS must not be able to make this server accumulate.
    #[test]
    fn a_field_section_past_the_limit_is_refused() {
        let mut buf = BytesMut::new();
        encode(&mut buf, [(&b"x-big"[..], &vec![b'a'; 4096][..])]);

        assert!(decode(&buf, super::super::MAX_FIELD_SECTION_SIZE).is_ok());

        let error = decode(&buf, 256).expect_err("refused");
        assert_eq!(error.code(), Code::H3_EXCESSIVE_LOAD);
        assert!(
            !error.is_connection_error(),
            "one oversized request is a stream problem, not a connection one"
        );
    }

    /// The size formula of RFC 9114 §4.2.2 counts 32 bytes of overhead per
    /// field, so a section of many tiny fields is bounded too.
    #[test]
    fn the_per_field_overhead_counts_towards_the_limit() {
        let field = Field {
            name: Cow::Borrowed(b"a"),
            value: Cow::Borrowed(b"b"),
        };
        assert_eq!(field.size(), 34);
    }

    /// The decoder reads untrusted bytes, so no input may panic it.
    #[test]
    fn arbitrary_bytes_never_panic_the_decoder() {
        proptest::proptest!(|(block: Vec<u8>)| {
            let _ = decode(&block, super::super::MAX_FIELD_SECTION_SIZE);
        });
    }
}
