//! Huffman-coded field lines, from the wire (RFC 7541 Appendix B via RFC 9204).
//!
//! Surge Huffman-codes every request it sends, and until this file existed
//! nothing in `cargo test` did: the crate's own QPACK encoder always writes
//! `H = 0`, so `src/h3/huffman.rs` was reached only by its unit tests and a
//! regression in it would have been found in production rather than here.
//!
//! Two halves, and they need each other. The encoder is
//! [`common::huffman`], a second transcription of RFC 7541 Appendix B; the
//! first test round-trips every symbol of it through the server's decoder, so
//! the two transcriptions are checked against each other before anything is
//! built on either. The rest send real requests coded with it, and then two
//! literals that no conformant encoder could have produced.

mod common;

use bytes::BytesMut;
use common::rawstream::QPACK_DECOMPRESSION_FAILED;
use common::{
    ALLOW_PRIVATE, H3Client, TIMEOUT, TestServer, auth_section, authorized_connect, echoes,
    huffman, open_tcp_tunnel, open_udp_session, respond_to, spawn_echo_target,
    spawn_udp_echo_target, udp_round_trip,
};
use volto::h3::frame;
use volto::h3api::Status;

/// The user the authenticated cases below log in as.
const USER: (&str, &str) = ("surge", "s3cret-p4ssw0rd");

// ---------------------------------------------------------------------------
// The encoder, against the decoder it will be driving
// ---------------------------------------------------------------------------

/// Every symbol this encoder can emit must come back out of the server's
/// decoder unchanged.
///
/// This is what makes the two transcriptions of RFC 7541 Appendix B worth
/// having separately: a mistyped entry in either one shows up here as a symbol
/// that decodes to something else, or as a code that no longer parses at all.
/// Deriving one table from the other instead would make the check vacuous.
#[test]
fn the_encoder_and_the_servers_decoder_agree_on_every_symbol() {
    for symbol in 0..=255u8 {
        let encoded = huffman::encode(&[symbol]);
        let decoded = volto::h3::huffman::decode(&encoded)
            .unwrap_or_else(|error| panic!("symbol {symbol} did not decode: {error}"));
        assert_eq!(decoded, vec![symbol], "symbol {symbol} round-trips");
    }

    // Every symbol at once, so a code that only fails when it straddles a byte
    // boundary is caught too: the alphabet is 256 codes of 5 to 30 bits, which
    // lands on every alignment there is.
    let alphabet: Vec<u8> = (0..=255u8).collect();
    let encoded = huffman::encode(&alphabet);
    assert_eq!(
        volto::h3::huffman::decode(&encoded).expect("the whole alphabet decodes"),
        alphabet
    );

    // An empty literal is a legal one, and encodes to no bytes at all: there is
    // nothing to pad to a byte boundary.
    assert!(huffman::encode(b"").is_empty());
}

/// The examples RFC 7541 Appendix C.4 gives, encoded rather than decoded.
///
/// `src/h3/huffman.rs` decodes these already; producing the same bytes from the
/// other direction is what proves the encoder is the RFC's and not merely
/// self-consistent with its own decoder.
#[test]
fn the_rfc_7541_appendix_c4_examples_encode() {
    for (plain, expected) in [
        (&b"www.example.com"[..], "f1e3c2e5f23a6ba0ab90f4ff"),
        (&b"no-cache"[..], "a8eb10649cbf"),
        (&b"custom-key"[..], "25a849e95ba97d7f"),
        (&b"custom-value"[..], "25a849e95bb8e8b4bf"),
    ] {
        let encoded = huffman::encode(plain);
        let hex: String = encoded.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, expected, "{:?}", String::from_utf8_lossy(plain));
    }
}

/// The EOS entry is carried but never emitted, so its code is only ever checked
/// by reading it: RFC 7541 Appendix B gives it as thirty ones.
#[test]
fn the_eos_entry_matches_the_rfc_appendix() {
    assert_eq!(huffman::CODES[huffman::EOS], (0x3fff_ffff, 30));
    assert_eq!(huffman::CODES.len(), 257);
}

// ---------------------------------------------------------------------------
// Requests that are Huffman-coded end to end
// ---------------------------------------------------------------------------

/// A CONNECT whose every field name and value is Huffman-coded opens a tunnel
/// and carries bytes, exactly as the plain one does.
#[tokio::test]
async fn a_huffman_coded_connect_opens_a_tunnel() {
    let server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect_huffman(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    echoes(&mut stream, b"huffman").await;
}

/// The same for CONNECT-UDP, whose request carries the two pseudo-headers a
/// classic CONNECT does not -- `:path` with the RFC 9298 template in it, and
/// `:protocol` -- so a decoder that only ever saw the TCP shape is not enough.
#[tokio::test]
async fn a_huffman_coded_connect_udp_opens_a_session() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect_huffman(&server).await;

    let (quarter_stream_id, _stream) = open_udp_session(&mut client, &server, target).await;

    let echoed = udp_round_trip(&client, quarter_stream_id, b"hello").await;
    assert_eq!(&echoed[..], b"hello");
}

/// Credentials survive the round trip byte for byte.
///
/// The strongest statement this file can make about the decoder: base64
/// credentials are compared for exact equality against the configured password,
/// so a decoder that dropped, doubled or transposed a single symbol answers 407
/// instead of 200. The wrong password is sent first, so a server that answered
/// 200 to everything could not pass either.
#[tokio::test]
async fn huffman_coded_credentials_are_decoded_byte_for_byte() {
    let server = TestServer::start_with(&format!("{}{ALLOW_PRIVATE}", auth_section(&[USER]))).await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect_huffman(&server).await;

    let refused = respond_to(
        &mut client,
        authorized_connect(&target.to_string(), USER.0, "wrong"),
    )
    .await;
    assert_eq!(refused.status, Status::PROXY_AUTHENTICATION_REQUIRED);

    let accepted = respond_to(
        &mut client,
        authorized_connect(&target.to_string(), USER.0, USER.1),
    )
    .await;
    assert_eq!(
        accepted.status,
        Status::OK,
        "Huffman-coded credentials must decode to the same bytes that were sent"
    );
}

// ---------------------------------------------------------------------------
// Literals no conformant encoder could have produced
// ---------------------------------------------------------------------------

/// RFC 7541 §5.2: "A padding strictly longer than 7 bits MUST be treated as a
/// decoding error."
///
/// The server answers on the stream and leaves the connection alone, which is
/// this server's own classification rather than the RFC's -- the RFC calls it a
/// "decoding error" and stops there. Asserting the code *and* that the next
/// request still works is what pins that choice to the wire.
#[tokio::test]
async fn a_literal_padded_past_seven_bits_is_a_stream_error() {
    // The symbol '0' is five zero bits, padded to a byte with three ones; the
    // second byte is then eight more bits of padding, one past the limit.
    assert_reset_and_survives(&[0b0000_0111, 0b1111_1111]).await;
}

/// RFC 7541 §5.2: "A padding not corresponding to the most significant bits of
/// the code for the EOS symbol MUST be treated as a decoding error."
///
/// Those bits are all ones, so a zero anywhere in the padding is the error --
/// and this is the case a naive decoder gets wrong, because the padding here is
/// short enough to look like the start of a symbol.
#[tokio::test]
async fn a_literal_padded_with_zeroes_is_a_stream_error() {
    // '0' again, this time padded with three zeroes instead of three ones.
    assert_reset_and_survives(&[0b0000_0000]).await;
}

/// Sends `literal` as a Huffman-coded field value on a request stream of its
/// own, and asserts the server resets that stream -- both halves -- with
/// QPACK_DECOMPRESSION_FAILED while the connection carries on serving.
///
/// That code is what every failure in `src/h3/huffman.rs` carries, and a stream
/// error rather than a connection one: RFC 7541 §5.2 calls a bad literal a
/// "decoding error" without naming a class, and D75 settles it as a stream one
/// because a zero-capacity dynamic table leaves nothing desynchronised behind a
/// section that would not decode.
async fn assert_reset_and_survives(literal: &[u8]) {
    let server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (mut send, mut recv) = client.quic.open_bi().await.expect("open a request stream");

    let block = field_section_with_huffman_value(literal);
    let mut request = BytesMut::new();
    frame::put_header(&mut request, frame::HEADERS, block.len() as u64);
    request.extend_from_slice(&block);
    send.write_all(&request)
        .await
        .expect("send the HEADERS frame");

    // The response side is reset...
    let read = tokio::time::timeout(TIMEOUT, recv.read_chunk(64, true))
        .await
        .expect("the server answered");
    match read {
        Err(quinn::ReadError::Reset(code)) => assert_eq!(
            code.into_inner(),
            QPACK_DECOMPRESSION_FAILED,
            "expected QPACK_DECOMPRESSION_FAILED (0x200) on the response side, got {:#x}",
            code.into_inner()
        ),
        other => panic!("expected the response side to be reset, got {other:?}"),
    }

    // ...and the request side is stopped, with the same code.
    let stopped = tokio::time::timeout(TIMEOUT, send.stopped())
        .await
        .expect("the server stopped the request side")
        .expect("stop code");
    assert_eq!(
        stopped.map(quinn::VarInt::into_inner),
        Some(QPACK_DECOMPRESSION_FAILED),
        "expected STOP_SENDING with QPACK_DECOMPRESSION_FAILED (0x200)"
    );

    // The connection is untouched: a literal one request could not read says
    // nothing about the next one.
    let mut tunnel = open_tcp_tunnel(&mut client, &target.to_string()).await;
    echoes(&mut tunnel, b"still here").await;
}

/// A field section whose single field line carries `literal` as a Huffman-coded
/// value under a static name reference (RFC 9204 §4.5.4).
///
/// Spelled out byte by byte rather than built with the client's encoder,
/// because the bytes are the test: nothing here may be produced by the same
/// code the server parses it with.
fn field_section_with_huffman_value(literal: &[u8]) -> Vec<u8> {
    let mut block = vec![
        // Encoded Field Section Prefix (§4.5.1): Required Insert Count 0,
        // Delta Base 0 -- the prefix of a section that names no dynamic entry.
        0x00, 0x00,
        // Literal Field Line With Name Reference: | 0 | 1 | N=0 | T=1 | Name
        // Index (4+) = 0 |, and static entry 0 is `:authority`.
        0x50,
    ];
    // | H=1 | Value Length (7+) |. Every literal here is far shorter than the
    // 126 bytes a one-byte length can carry.
    block.push(0x80 | u8::try_from(literal.len()).expect("a short literal"));
    block.extend_from_slice(literal);
    block
}
