//! M0: the server must advertise extended CONNECT and HTTP Datagrams.
//!
//! Surge validates the server's SETTINGS frame during connection setup and
//! disconnects if either capability is missing, so this is asserted on the wire
//! rather than through the server's own configuration: the test reads the
//! server's HTTP/3 control stream as a raw QUIC stream and decodes the SETTINGS
//! frame itself.

mod common;

use std::collections::HashMap;

use common::{connect_quic, connect_request, H3Client, TestServer, TIMEOUT};

/// Unidirectional stream type of the HTTP/3 control stream (RFC 9114 §6.2.1).
const STREAM_TYPE_CONTROL: u64 = 0x00;

/// SETTINGS frame type (RFC 9114 §7.2.4).
const FRAME_SETTINGS: u64 = 0x04;

/// SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220 / RFC 8441 §3).
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

/// SETTINGS_H3_DATAGRAM (RFC 9297 §2.1.1).
const SETTINGS_H3_DATAGRAM: u64 = 0x33;

/// SETTINGS_MAX_FIELD_SECTION_SIZE (RFC 9114 §7.2.4.1).
const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;

/// The value the server must advertise, matching `h3api::MAX_FIELD_SECTION_SIZE`.
const EXPECTED_MAX_FIELD_SECTION_SIZE: u64 = 64 * 1024;

/// How many unidirectional streams to inspect before giving up.
///
/// `h3` also opens a grease stream, so the control stream is not guaranteed to
/// be the first one accepted.
const MAX_UNI_STREAMS: usize = 8;

#[tokio::test]
async fn server_advertises_extended_connect_and_h3_datagram() {
    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    let settings = read_settings(&connection).await;

    assert_eq!(
        settings.get(&SETTINGS_ENABLE_CONNECT_PROTOCOL),
        Some(&1),
        "SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08) must be 1 or Surge refuses the \
         connection; received settings: {settings:?}"
    );
    assert_eq!(
        settings.get(&SETTINGS_H3_DATAGRAM),
        Some(&1),
        "SETTINGS_H3_DATAGRAM (0x33) must be 1 or Surge refuses the connection; \
         received settings: {settings:?}"
    );
}

/// A header-size limit must be advertised, and it must be a real one.
///
/// `h3` defaults `max_field_section_size` to `VarInt::MAX`, which means an
/// unauthenticated peer's header block is buffered and decoded in full before the
/// server can look at it. Asserting the advertised value on the wire is what
/// keeps that default from creeping back in (audit 2026-08, finding 1.1b).
#[tokio::test]
async fn server_advertises_a_header_size_limit() {
    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    let settings = read_settings(&connection).await;

    let advertised = settings
        .get(&SETTINGS_MAX_FIELD_SECTION_SIZE)
        .copied()
        .unwrap_or_else(|| {
            panic!("SETTINGS_MAX_FIELD_SECTION_SIZE (0x06) must be advertised; got {settings:?}")
        });

    assert_eq!(advertised, EXPECTED_MAX_FIELD_SECTION_SIZE, "{settings:?}");
    // The point of the assertion is that it is *bounded*, not merely present.
    assert!(
        advertised < u64::from(u32::MAX),
        "the advertised limit must be a real bound, got {advertised}"
    );
}

/// The advertised limit has to bite, not just be announced.
///
/// A client that respects SETTINGS refuses to send an oversized header section at
/// all, which is the outcome this asserts: the request never reaches the server,
/// so nothing is buffered or QPACK-decoded on its behalf.
#[tokio::test]
async fn an_oversized_header_section_is_refused() {
    let server = TestServer::start().await;
    let mut client = H3Client::connect(&server).await;

    // One ordinary round trip first. SETTINGS arrives on the control stream after
    // the handshake, so without this the client may not have processed the limit
    // yet -- the same ordering trap that decision D5 records on the server side.
    let mut warm_up = client
        .send
        .send_request(connect_request("192.0.2.1:443"))
        .await
        .expect("send CONNECT");
    let _ = tokio::time::timeout(TIMEOUT, warm_up.recv_response())
        .await
        .expect("response arrived")
        .expect("response");

    // Comfortably past the 64 KiB limit, well under any flow-control window.
    let mut request = connect_request("192.0.2.1:443");
    request.headers_mut().insert(
        "x-volto-oversized",
        "A".repeat(128 * 1024).parse().expect("header value"),
    );

    let result = client.send.send_request(request).await;
    assert!(
        result.is_err(),
        "a header section past the advertised limit must be refused"
    );

    // And the connection survives it: one oversized request is a stream-level
    // problem, not a reason to drop everything else on the connection.
    let mut ok = client
        .send
        .send_request(connect_request("192.0.2.1:443"))
        .await
        .expect("the connection must still be usable");
    let response = tokio::time::timeout(TIMEOUT, ok.recv_response())
        .await
        .expect("response arrived")
        .expect("response");
    assert!(
        response.status().is_client_error()
            || response.status().is_server_error()
            || response.status().is_success()
    );
}

#[tokio::test]
async fn server_negotiates_the_h3_alpn() {
    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    let handshake = connection
        .handshake_data()
        .expect("handshake data")
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .expect("rustls handshake data");

    assert_eq!(handshake.protocol.as_deref(), Some(b"h3".as_slice()));
}

/// The QUIC transport parameter behind HTTP Datagrams must be advertised too.
///
/// `max_datagram_size` reports what the *peer* is willing to receive, so a
/// `Some` here means the server sent `max_datagram_frame_size`. CONNECT-UDP in
/// M2 depends on it.
#[tokio::test]
async fn server_advertises_max_datagram_frame_size() {
    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    assert!(
        connection.max_datagram_size().is_some(),
        "the server must advertise max_datagram_frame_size"
    );
}

/// Finds the control stream and returns the settings it carries.
async fn read_settings(connection: &quinn::Connection) -> HashMap<u64, u64> {
    for _ in 0..MAX_UNI_STREAMS {
        let mut recv = tokio::time::timeout(TIMEOUT, connection.accept_uni())
            .await
            .expect("a unidirectional stream arrived")
            .expect("unidirectional stream");

        if read_varint(&mut recv).await != STREAM_TYPE_CONTROL {
            // A grease stream or a QPACK stream; keep looking.
            continue;
        }

        // RFC 9114 §6.2.1: SETTINGS must be the first frame on the control
        // stream.
        let frame_type = read_varint(&mut recv).await;
        assert_eq!(
            frame_type, FRAME_SETTINGS,
            "the first control stream frame must be SETTINGS, got type {frame_type:#x}"
        );

        let length = read_varint(&mut recv).await;
        let mut payload = vec![0u8; usize::try_from(length).expect("settings frame length")];
        tokio::time::timeout(TIMEOUT, recv.read_exact(&mut payload))
            .await
            .expect("settings payload arrived")
            .expect("settings payload");

        return parse_settings(&payload);
    }

    panic!("no HTTP/3 control stream among the first {MAX_UNI_STREAMS} unidirectional streams");
}

/// Decodes the identifier/value pairs of a SETTINGS payload.
fn parse_settings(payload: &[u8]) -> HashMap<u64, u64> {
    let mut settings = HashMap::new();
    let mut rest = payload;

    while !rest.is_empty() {
        let (id, consumed) = decode_varint(rest).expect("setting identifier");
        rest = &rest[consumed..];
        let (value, consumed) = decode_varint(rest).expect("setting value");
        rest = &rest[consumed..];
        settings.insert(id, value);
    }

    settings
}

/// Reads one QUIC variable-length integer from a stream (RFC 9000 §16).
async fn read_varint(recv: &mut quinn::RecvStream) -> u64 {
    let mut first = [0u8; 1];
    tokio::time::timeout(TIMEOUT, recv.read_exact(&mut first))
        .await
        .expect("varint arrived")
        .expect("varint first byte");

    // The two most significant bits encode the length as a power of two.
    let length = 1usize << (first[0] >> 6);
    let mut value = u64::from(first[0] & 0x3f);

    if length > 1 {
        let mut tail = vec![0u8; length - 1];
        tokio::time::timeout(TIMEOUT, recv.read_exact(&mut tail))
            .await
            .expect("varint tail arrived")
            .expect("varint tail");
        for byte in tail {
            value = (value << 8) | u64::from(byte);
        }
    }

    value
}

/// Decodes a variable-length integer from a buffer, returning its byte length.
fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
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
