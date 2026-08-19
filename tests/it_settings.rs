//! M0: the server must advertise extended CONNECT and HTTP Datagrams.
//!
//! Surge validates the server's SETTINGS frame during connection setup and
//! disconnects if either capability is missing, so this is asserted on the wire
//! rather than through the server's own configuration: the test reads the
//! server's HTTP/3 control stream as a raw QUIC stream and decodes the SETTINGS
//! frame itself.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use common::{connect_quic, connect_request, spawn_udp_echo_target, H3Client, TestServer, TIMEOUT};
use volto::capsule::{Capsule, CapsuleDecoder};
use volto::datagram;

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

/// HEADERS frame type (RFC 9114 §7.2.2).
const FRAME_HEADERS: u64 = 0x01;

/// DATA frame type (RFC 9114 §7.2.1).
const FRAME_DATA: u64 = 0x00;

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
    //
    // Port 25 is on the default deny list, and the port rule is checked before the
    // resolver runs, so the 403 arrives without touching the network. CONNECT to a
    // TEST-NET address would instead hang on hosts that blackhole the SYN.
    let mut warm_up = client
        .send
        .send_request(connect_request("192.0.2.1:25"))
        .await
        .expect("send CONNECT");
    let _ = tokio::time::timeout(TIMEOUT, warm_up.recv_response())
        .await
        .expect("response arrived")
        .expect("response");

    // Comfortably past the 64 KiB limit, well under any flow-control window.
    let mut request = connect_request("192.0.2.1:25");
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
        .send_request(connect_request("192.0.2.1:25"))
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

// ---------------------------------------------------------------------------
// The peer's SETTINGS, arriving after the first request
// ---------------------------------------------------------------------------

/// A CONNECT-UDP session opened before the peer's SETTINGS were processed must
/// still move onto QUIC datagrams once they arrive.
///
/// `h3` reads the control stream whenever the accept future is polled, so its
/// own view of the peer's settings flips as soon as the SETTINGS frame lands —
/// but this server's copy of it used to be refreshed only when a *request* was
/// accepted. A session started before that point therefore stayed on the
/// RFC 9297 capsule fallback for target-to-client traffic until another request
/// happened along, which on a connection that opens one tunnel and keeps it is
/// never.
///
/// The in-repo `h3` client cannot produce that ordering: it sends SETTINGS as
/// part of connection setup, before any request can be made. So the client here
/// is raw quinn with a hand-encoded HEADERS frame, and the ordering is the whole
/// point — request first, control stream second.
#[tokio::test]
async fn a_session_opened_before_the_peer_settings_moves_onto_datagrams() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    // A CONNECT-UDP request on a bare QUIC connection: no control stream, so the
    // server has no peer settings to read and cannot know datagrams are allowed.
    let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
    let quarter_stream_id = datagram::quarter_stream_id(u64::from(send.id()));
    send.write_all(&connect_udp_headers_frame(
        &server.addr.to_string(),
        &target.ip().to_string(),
        target.port(),
    ))
    .await
    .expect("send the CONNECT-UDP request");

    // The response proves the session is established *now*, i.e. before anything
    // below sends SETTINGS. Without this the request and the settings could be
    // processed together and the ordering under test would never happen.
    let (frame_type, _) = read_frame(&mut recv).await;
    assert_eq!(
        frame_type, FRAME_HEADERS,
        "the server must answer the request with a HEADERS frame"
    );

    // And with datagrams not known to be allowed, the reply travels as a capsule
    // on the request stream — the fallback this test is about escaping.
    connection
        .send_datagram(datagram::encode_udp_payload(
            quarter_stream_id,
            b"before settings",
        ))
        .expect("send a UDP payload as a QUIC datagram");

    let (frame_type, payload) = read_frame(&mut recv).await;
    assert_eq!(
        frame_type, FRAME_DATA,
        "the capsule stream travels in DATA frames"
    );
    let mut decoder = CapsuleDecoder::new();
    decoder.push(Bytes::from(payload));
    match decoder.next_capsule().expect("well-formed capsules") {
        Some(Capsule::Datagram {
            context_id,
            payload,
        }) => {
            assert_eq!(context_id, datagram::CONTEXT_ID_UDP_PAYLOAD);
            assert_eq!(&payload[..], b"before settings");
        }
        other => panic!("expected a DATAGRAM capsule, got {other:?}"),
    }

    // Only now does the peer say datagrams are allowed. The control stream is
    // kept open for the rest of the test: closing it is H3_CLOSED_CRITICAL_STREAM.
    let mut control = connection
        .open_uni()
        .await
        .expect("open the control stream");
    control
        .write_all(&control_stream_with_datagrams_enabled())
        .await
        .expect("send SETTINGS");

    // From here the reply must arrive as a QUIC datagram. Retried rather than
    // slept on: the server samples the peer's settings on a timer, so which side
    // of the flip a single packet lands on is a race, while *never* flipping is
    // the bug.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "the session never moved onto QUIC datagrams after the peer's SETTINGS \
             enabled them"
        );

        connection
            .send_datagram(datagram::encode_udp_payload(
                quarter_stream_id,
                b"after settings",
            ))
            .expect("send a UDP payload as a QUIC datagram");

        match tokio::time::timeout(Duration::from_millis(200), connection.read_datagram()).await {
            Ok(raw) => {
                let decoded = datagram::decode(raw.expect("read a datagram"))
                    .expect("server datagrams must be well formed");
                assert_eq!(decoded.quarter_stream_id, quarter_stream_id);
                assert_eq!(decoded.context_id, datagram::CONTEXT_ID_UDP_PAYLOAD);
                assert_eq!(&decoded.payload[..], b"after settings");
                break;
            }
            // Nothing yet; the flag may not have been sampled. Try again.
            Err(_) => continue,
        }
    }
}

/// Encodes a CONNECT-UDP request (RFC 9298 §3) as an HTTP/3 HEADERS frame.
///
/// Hand-built because the point of the test above is an ordering the `h3` client
/// cannot produce. QPACK is used statelessly, which needs no encoder stream.
fn connect_udp_headers_frame(authority: &str, host: &str, port: u16) -> Vec<u8> {
    use h3::qpack::{encode_stateless, HeaderField};

    let fields = vec![
        HeaderField::new(&b":method"[..], &b"CONNECT"[..]),
        HeaderField::new(&b":protocol"[..], &b"connect-udp"[..]),
        HeaderField::new(&b":scheme"[..], &b"https"[..]),
        HeaderField::new(&b":authority"[..], authority.as_bytes()),
        HeaderField::new(
            &b":path"[..],
            format!("/.well-known/masque/udp/{host}/{port}/").into_bytes(),
        ),
    ];

    let mut block = Vec::new();
    encode_stateless(&mut block, &fields).expect("qpack encoding");

    let mut frame = BytesMut::new();
    datagram::put_varint(&mut frame, FRAME_HEADERS);
    datagram::put_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    frame.to_vec()
}

/// The bytes of a client control stream whose SETTINGS enable HTTP Datagrams.
fn control_stream_with_datagrams_enabled() -> Vec<u8> {
    let mut settings = BytesMut::new();
    datagram::put_varint(&mut settings, SETTINGS_H3_DATAGRAM);
    datagram::put_varint(&mut settings, 1);

    let mut stream = BytesMut::new();
    datagram::put_varint(&mut stream, STREAM_TYPE_CONTROL);
    datagram::put_varint(&mut stream, FRAME_SETTINGS);
    datagram::put_varint(&mut stream, settings.len() as u64);
    stream.extend_from_slice(&settings);
    stream.to_vec()
}

/// Reads one HTTP/3 frame from a raw request stream.
async fn read_frame(recv: &mut quinn::RecvStream) -> (u64, Vec<u8>) {
    let frame_type = read_varint(recv).await;
    let length = read_varint(recv).await;

    let mut payload = vec![0u8; usize::try_from(length).expect("frame length")];
    tokio::time::timeout(TIMEOUT, recv.read_exact(&mut payload))
        .await
        .expect("frame payload arrived")
        .expect("frame payload");

    (frame_type, payload)
}
