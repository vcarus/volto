//! What the differential decoding oracle settled, pinned without Python.
//!
//! `tests/interop/difforacle` puts the same bytes through this server's QPACK
//! and Huffman decoders and through ls-qpack, and compares both the
//! accept/reject verdict and the decoded fields. Its findings belong here rather
//! than in a report: the campaign needs a pinned Python environment and is run
//! on demand, while everything it decided has to hold on every `cargo test`.
//!
//! Two kinds of case live in this file.
//!
//! * **Disagreements.** Five of them, none a fault in this server: three where
//!   ls-qpack refuses what RFC 9204 and RFC 7541 allow, and two where it accepts
//!   what they say MUST be refused. Each is pinned with the exact bytes the
//!   campaign produced and the sentence that settles it.
//! * **Agreements worth keeping.** The whole QPACK static table, entry by
//!   entry, as ls-qpack decodes it. `src/h3/qpack.rs` transcribes RFC 9204
//!   Appendix A by hand and its own unit test can only compare that
//!   transcription with itself; the table below is a second implementation's
//!   copy, so a mistyped entry -- a decoder that quietly reports the wrong
//!   field name -- fails here.
//!
//! Every RFC sentence quoted below was read from the RFC, not remembered.

use std::borrow::Cow;

use volto::h3::error::Code;
use volto::h3::qpack::{self, Field};
use volto::h3::{huffman, stream, MAX_FIELD_SECTION_SIZE};

/// A field section: the `0x00 0x00` prefix of RFC 9204 §4.5.1, then `body`.
fn section(body: &[u8]) -> Vec<u8> {
    let mut block = vec![0, 0];
    block.extend_from_slice(body);
    block
}

/// §4.5.2 Indexed Field Line with `T = 1`, the static table.
fn indexed_static(index: u64) -> Vec<u8> {
    if index < 63 {
        return vec![0b1100_0000 | index as u8];
    }
    let mut out = vec![0xff];
    let mut remaining = index - 63;
    while remaining >= 0x80 {
        out.push((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
    out
}

/// §4.5.4 Literal Field Line With Name Reference, `N = 0`, `T = 1`, whose value
/// is a Huffman-coded literal given as raw octets.
fn huffman_value(index: u64, literal: &[u8]) -> Vec<u8> {
    assert!(index < 15, "the four-bit prefix has to hold the index");
    assert!(
        literal.len() < 127,
        "the seven-bit prefix has to hold the length"
    );
    let mut out = vec![0b0101_0000 | index as u8, 0x80 | literal.len() as u8];
    out.extend_from_slice(literal);
    out
}

fn bytes(hex: &str) -> Vec<u8> {
    let digits: Vec<char> = hex.chars().filter(|c| !c.is_whitespace()).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(&pair.iter().collect::<String>(), 16).expect("hex byte"))
        .collect()
}

fn decode(block: &[u8]) -> Vec<Field> {
    qpack::decode(block, MAX_FIELD_SECTION_SIZE).expect("decodes")
}

fn field(name: &[u8], value: &[u8]) -> Field {
    Field {
        name: Cow::Owned(name.to_vec()),
        value: Cow::Owned(value.to_vec()),
    }
}

// ---------------------------------------------------------------------------
// Where ls-qpack refuses and the RFC does not
// ---------------------------------------------------------------------------

/// An encoded field section carrying no field lines at all is well formed.
///
/// ls-qpack refuses it, which is what put this test here; RFC 9204 §4.5 is
/// explicit that it must not:
///
//= https://www.rfc-editor.org/rfc/rfc9204#section-4.5
//# An encoded field section consists of a prefix and a possibly empty
//# sequence of representations defined in this section.
///
/// The Base is free too, so the same holds however the second prefix octet
/// spells it:
///
//= https://www.rfc-editor.org/rfc/rfc9204#section-4.5.1.2
//# A field section that was encoded without references to the dynamic table
//# can use any value for the Base; setting Delta Base to zero is one of the
//# most efficient encodings.
#[test]
fn an_empty_field_section_decodes_to_no_fields() {
    for block in [
        vec![0x00, 0x00],       // Required Insert Count 0, Base 0
        vec![0x00, 0x01],       // Delta Base 1
        vec![0x00, 0x4c],       // Delta Base 76
        vec![0x00, 0x7f, 0x00], // Delta Base 127, in two octets
    ] {
        assert_eq!(decode(&block), Vec::new(), "{block:02x?}");
    }
}

/// The empty section is refused one layer up, where the reason for refusing it
/// actually lives.
///
/// This is the other half of the test above: QPACK has nothing to say about a
/// field section with no fields, and HTTP has everything to say about a request
/// with no `:method`. Splitting them that way is what makes the QPACK decoder's
/// permissiveness safe, so the split is pinned rather than assumed.
///
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
//# All HTTP/3 requests MUST include exactly one value for the :method,
//# :scheme, and :path pseudo-header fields, unless the request is a
//# CONNECT request; see Section 4.4.
#[test]
fn an_empty_field_section_is_a_malformed_request() {
    let error = stream::build_request(Vec::new()).expect_err("malformed");
    assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
    assert!(!error.is_connection_error(), "{error}");
}

/// A field line whose name is a zero-length literal decodes, and is refused as
/// a request.
///
/// ls-qpack refuses it inside the decoder. RFC 9204 §4.5.6 puts no lower bound
/// on Name Length, and the rule that rejects it is HTTP's, so this server draws
/// the line where the rule is:
///
//= https://www.rfc-editor.org/rfc/rfc9110#section-5.1
//# field-name     = token
///
/// and a `token` is `1*tchar` (RFC 9110 §5.6.2), which the empty string is not.
///
/// The section is a CONNECT request that is otherwise complete, and the same
/// request with a one-character name is accepted just below: without that pair
/// the request would be refused for having no `:method` and the empty name
/// would never be reached.
#[test]
fn a_field_line_with_an_empty_name_is_refused_as_a_request() {
    // 0xcf = indexed static 15, `:method: CONNECT`.
    // 0x50 = literal with static name reference 0 (`:authority`), then a
    // fifteen-octet literal value.
    let mut request = vec![0xcf, 0x50, 0x0f];
    request.extend_from_slice(b"example.com:443");

    // 0x20 = 001 (literal name) 0 (N) 0 (H) 000: a name of length zero, then a
    // three-octet value.
    let mut empty_name = request.clone();
    empty_name.extend_from_slice(&[0x20, 0x03, b'a', b'b', b'c']);
    let block = section(&empty_name);

    let fields = decode(&block);
    assert_eq!(fields.len(), 3, "the decoder reads all three field lines");
    assert_eq!(fields[2], field(b"", b"abc"));

    let error = stream::build_request(fields).expect_err("malformed");
    assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
    assert!(!error.is_connection_error(), "{error}");

    // 0x21 = the same representation with a name of length one.
    let mut one_character = request;
    one_character.extend_from_slice(&[0x21, b'x', 0x03, b'a', b'b', b'c']);
    let fields = decode(&section(&one_character));
    assert_eq!(fields[2], field(b"x", b"abc"));
    stream::build_request(fields).expect("a one-character name is a token");
}

/// The same integer spelled at length decodes to the same value.
///
/// ls-qpack refuses a continuation list that carries octets adding nothing.
/// RFC 7541 §5.1 states the decoder's algorithm and stops there -- it says
/// nothing about the encoding being the shortest one:
///
//= https://www.rfc-editor.org/rfc/rfc7541#section-5.1
//# decode I from the next N bits
//# if I < 2^N - 1, return I
//# else
//#     M = 0
//#     repeat
//#         B = next octet
//#         I = I + (B & 127) * 2^M
//#         M = M + 7
//#     while B & 128 == 128
//#     return I
///
/// So this decoder follows the algorithm as written, and the accumulator is
/// what bounds it: an octet whose shift has passed 63 is refused as a value
/// too large to decode (RFC 9204 §7.4), whatever it would have added.
#[test]
fn a_prefixed_integer_spelled_at_length_decodes_to_the_same_value() {
    // 0xff = indexed static, six-bit prefix full, so 63 plus the continuation.
    // 0x81 adds 1 and continues; eight 0x80 octets add nothing and continue;
    // 0x00 adds nothing and ends. Index 64 is `:status: 204`.
    let block = bytes("0000 ff81 8080 8080 8080 8000");
    assert_eq!(decode(&block), vec![field(b":status", b"204")]);

    // The minimal spelling of the same index.
    assert_eq!(
        decode(&section(&indexed_static(64))),
        vec![field(b":status", b"204")]
    );

    // The same at the other boundary: 0x80 in place of 0x81 is index 63.
    let block = bytes("0000 ff80 8080 8080 8080 8000");
    assert_eq!(decode(&block), vec![field(b":status", b"100")]);

    // Ten continuation octets is the last shift the accumulator has room for;
    // the eleventh is refused rather than silently ignored.
    let block = bytes("0000 ff80 8080 8080 8080 8080 8000");
    let error = qpack::decode(&block, MAX_FIELD_SECTION_SIZE).expect_err("refused");
    assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
    assert!(!error.is_connection_error(), "{error}");
}

// ---------------------------------------------------------------------------
// Where ls-qpack accepts and the RFC says it must not
// ---------------------------------------------------------------------------

/// A Sign bit of 1 is refused however the Delta Base after it is spelled.
///
/// ls-qpack accepts every one of these. The Required Insert Count is zero --
/// with a zero table capacity it can be nothing else -- and zero is less than
/// or equal to every Delta Base, so RFC 9204 §4.5.1.2 settles all of them at
/// once:
///
//= https://www.rfc-editor.org/rfc/rfc9204#section-4.5.1.2
//# An endpoint MUST treat a field block with a Sign bit of 1 as invalid
//# if the value of Required Insert Count is less than or equal to the
//# value of Delta Base.
///
/// `src/h3/qpack.rs` has this for the one-octet case; what the campaign added
/// is the multi-octet Delta Base, where the value continues past the prefix.
#[test]
fn a_sign_bit_of_one_is_refused_however_delta_base_is_spelled() {
    for block in [
        bytes("0080 d7"),        // Delta Base 0
        bytes("0081 d7"),        // Delta Base 1
        bytes("0087 d7"),        // Delta Base 7
        bytes("00fe d7"),        // Delta Base 126, the last that fits the prefix
        bytes("00ff 00 d7"),     // Delta Base 127, the first that does not
        bytes("00ff 01 d7"),     // Delta Base 128
        bytes("00ff 49 d7"),     // Delta Base 200
        bytes("00ff 8680 00d7"), // Delta Base past a single continuation octet
    ] {
        let error = qpack::decode(&block, MAX_FIELD_SECTION_SIZE)
            .err()
            .unwrap_or_else(|| panic!("{block:02x?} must be refused"));
        assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
        assert!(error.is_connection_error(), "{error}");
    }

    // The same Delta Base values with the Sign bit clear are the ordinary case
    // and decode, so the test above is about the bit and not about the octets
    // around it.
    for block in [bytes("0000 d7"), bytes("0001 d7"), bytes("007f 49 d7")] {
        assert_eq!(decode(&block), vec![field(b":scheme", b"https")]);
    }
}

/// Huffman padding longer than seven bits is refused.
///
/// The three literals below are ones ls-qpack decoded and returned, discarding
/// eight, ten and nine bits of padding respectively. RFC 7541 §5.2 is a MUST
/// and states no exception:
///
//= https://www.rfc-editor.org/rfc/rfc7541#section-5.2
//# Upon decoding, an incomplete code at the end of the encoded data is
//# to be considered as padding and discarded.  A padding strictly longer
//# than 7 bits MUST be treated as a decoding error.  A padding not
//# corresponding to the most significant bits of the code for the EOS
//# symbol MUST be treated as a decoding error.  A Huffman-encoded string
//# literal containing the EOS symbol MUST be treated as a decoding
//# error.
///
/// Each is checked twice: through the Huffman decoder on its own, and inside
/// the field section it arrived in, because it is the section that a peer
/// actually sends.
#[test]
fn huffman_padding_longer_than_seven_bits_is_refused() {
    for (literal, valid_prefix, plain) in [
        // "lj]h" is 32 bits, so the trailing octet is eight bits of padding.
        ("a3a7ff27ff", "a3a7ff27", &b"lj]h"[..]),
        // "#Mg0" is 30 bits: two bits of padding finish the octet, eight more
        // follow, ten in all.
        ("ffad1303ff", "ffad1303", &b"#Mg0"[..]),
        // "CONNEu5" is 47 bits, so nine bits of padding.
        ("bdab4e9c16b7ff", "bdab4e9c16b7", &b"CONNEu5"[..]),
        // "10-" is exactly sixteen bits, so the added octet is the whole of the
        // padding and there is no partial octet to hide it. ls-qpack refuses
        // this one, which is what makes its acceptance of the three above a
        // quirk of its state machine rather than a reading of the RFC.
        ("0816ff", "0816", &b"10-"[..]),
    ] {
        let error = huffman::decode(&bytes(literal)).expect_err("refused");
        assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
        assert!(!error.is_connection_error(), "{error}");

        let block = section(&huffman_value(0, &bytes(literal)));
        let error = qpack::decode(&block, MAX_FIELD_SECTION_SIZE).expect_err("refused");
        assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);

        // The same literal without the extra octet is what a conformant encoder
        // would have sent, and it decodes -- so what is refused above is the
        // padding and not the codes in front of it.
        assert_eq!(
            huffman::decode(&bytes(valid_prefix)).expect("decodes"),
            plain
        );
    }
}

// ---------------------------------------------------------------------------
// Where the two agree, and that agreement is worth keeping
// ---------------------------------------------------------------------------

/// RFC 9204 Appendix A as a second implementation decodes it.
///
/// Every row is what ls-qpack returned for the Indexed Field Line naming that
/// index, transcribed from the campaign's output. `src/h3/qpack.rs` holds this
/// table by hand and its unit test spot-checks four entries against the RFC;
/// this walks all ninety-nine against a copy nobody in this tree typed.
#[rustfmt::skip]
const LSQPACK_STATIC_TABLE: [(&[u8], &[u8]); 99] = [
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

#[test]
fn every_static_table_entry_decodes_the_way_ls_qpack_decodes_it() {
    for (index, (name, value)) in LSQPACK_STATIC_TABLE.iter().enumerate() {
        let block = section(&indexed_static(index as u64));
        assert_eq!(
            decode(&block),
            vec![field(name, value)],
            "static table entry {index}"
        );
    }

    // And one past the end is refused, so the table's length is pinned too.
    let block = section(&indexed_static(LSQPACK_STATIC_TABLE.len() as u64));
    let error = qpack::decode(&block, MAX_FIELD_SECTION_SIZE).expect_err("refused");
    assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
    assert!(error.is_connection_error(), "{error}");
}

/// Field lines come out in the order they went in.
///
//= https://www.rfc-editor.org/rfc/rfc9204#section-2.2
//# The decoder MUST emit field lines in the order their representations
//# appear in the encoded field section.
///
/// The campaign compares the whole sequence rather than a set, so every
/// agreeing input it ran was also a check of this; the case below is the one
/// that says so on every `cargo test`. The indices are chosen to be distinct
/// entries whose order a set would lose.
#[test]
fn field_lines_are_emitted_in_the_order_they_were_encoded() {
    let mut body = Vec::new();
    for index in [23u64, 15, 25, 0, 64] {
        body.extend_from_slice(&indexed_static(index));
    }

    let expected: Vec<Field> = [23usize, 15, 25, 0, 64]
        .iter()
        .map(|index| {
            let (name, value) = LSQPACK_STATIC_TABLE[*index];
            field(name, value)
        })
        .collect();
    assert_eq!(decode(&section(&body)), expected);
}
