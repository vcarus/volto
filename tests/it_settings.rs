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
use common::{
    client_endpoint_with_transport, connect_quic, finish_connect, spawn_udp_echo_target,
    TestServer, TIMEOUT,
};
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
/// The server opens its two QPACK streams alongside the control stream, so the
/// control stream is not guaranteed to be the first one accepted.
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
/// Advertise none and an unauthenticated peer's header block is buffered and
/// decoded in full before the server can look at it, which is the state this
/// server was in until audit 2026-08, finding 1.1b. Asserting the advertised
/// value on the wire is what keeps it from coming back.
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

/// H3_EXCESSIVE_LOAD (RFC 9114 §8.1).
const H3_EXCESSIVE_LOAD: u64 = 0x107;

/// A client that respects SETTINGS never sends an oversized field section, so
/// this asserts what happens to the one that does not.
///
/// Driven on a raw QUIC stream on purpose: the shared test client checks the
/// advertised limit before it sends, and a test that stopped there would be
/// asserting the client's arithmetic rather than the server's answer. What the
/// server owes the peer is RFC 9114 §4.2.2's — "A server that receives a larger
/// header section than it is willing to handle can send an HTTP 431 (Request
/// Header Fields Too Large) status code" — followed by declining to read the
/// rest of it.
#[tokio::test]
async fn an_oversized_header_section_is_refused() {
    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");

    // Twice the advertised limit, declared in the frame header: the server
    // refuses it from the length alone, so the payload never has to be sent.
    let mut frame = BytesMut::new();
    datagram::put_varint(&mut frame, FRAME_HEADERS);
    datagram::put_varint(&mut frame, 2 * EXPECTED_MAX_FIELD_SECTION_SIZE);
    frame.extend_from_slice(&[0u8; 64]);
    send.write_all(&frame)
        .await
        .expect("send an oversized HEADERS frame");

    // The answer, before anything is reset: 431, and nothing after it.
    let (frame_type, payload) = read_frame(&mut recv).await;
    assert_eq!(
        frame_type, FRAME_HEADERS,
        "the refusal must arrive as a response, not as a bare reset"
    );
    assert_eq!(status_of(&payload), "431");

    let rest = tokio::time::timeout(TIMEOUT, recv.read_to_end(64))
        .await
        .expect("the response stream ended")
        .expect("the response stream ended cleanly");
    assert!(
        rest.is_empty(),
        "the response is the whole of it; got {rest:?}"
    );

    // And the rest of the field section is declined rather than read.
    assert_eq!(
        stopped_code(&mut send).await,
        H3_EXCESSIVE_LOAD,
        "the peer must be told which rule its request broke"
    );

    // The connection survives it: one oversized request is a stream-level
    // problem, not a reason to drop everything else on the connection. Port 25
    // is on the default deny list, and the port rule is checked before the
    // resolver runs, so the 403 arrives without touching the network.
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .expect("the connection must still be usable");
    send.write_all(&connect_headers_frame("192.0.2.1:25"))
        .await
        .expect("send a CONNECT request");

    let (frame_type, payload) = read_frame(&mut recv).await;
    assert_eq!(frame_type, FRAME_HEADERS);
    assert_eq!(status_of(&payload), "403");
}

/// Encodes a classic CONNECT request (RFC 9114 §4.4) as a HEADERS frame.
fn connect_headers_frame(authority: &str) -> Vec<u8> {
    let fields: [(&[u8], &[u8]); 2] = [
        (b":method", b"CONNECT"),
        (b":authority", authority.as_bytes()),
    ];

    let mut block = BytesMut::new();
    volto::h3::qpack::encode(&mut block, fields);

    let mut frame = BytesMut::new();
    datagram::put_varint(&mut frame, FRAME_HEADERS);
    datagram::put_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    frame.to_vec()
}

/// The `:status` of a response field section.
fn status_of(block: &[u8]) -> String {
    let fields = volto::h3::qpack::decode(block, EXPECTED_MAX_FIELD_SECTION_SIZE)
        .expect("the server's field section must decode");
    let status = fields
        .iter()
        .find(|field| field.name.as_ref() == b":status")
        .expect("a response carries :status");
    String::from_utf8(status.value.to_vec()).expect("a numeric status")
}

/// Writes until the peer stops the stream, and reports the code it used.
///
/// Retried rather than written once: STOP_SENDING travels while the response is
/// being read here, so a single write can still succeed before it lands.
async fn stopped_code(send: &mut quinn::SendStream) -> u64 {
    let stopped = async {
        loop {
            match send.write_all(&[0u8; 256]).await {
                Ok(()) => continue,
                Err(quinn::WriteError::Stopped(code)) => return code.into_inner(),
                Err(other) => panic!("expected STOP_SENDING, got {other}"),
            }
        }
    };

    tokio::time::timeout(TIMEOUT, stopped)
        .await
        .expect("the server must stop the stream it refused to read")
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

/// H3_MISSING_SETTINGS (RFC 9114 §8.1).
const H3_MISSING_SETTINGS: u64 = 0x10a;

/// The control stream must *open* with SETTINGS — a frame the server skips is
/// still a frame, and so is one that carries nothing.
///
/// Both shapes used to slip through, because neither produced anything for the
/// control stream's rules to be applied to: an unknown type was discarded inside
/// the frame decoder, and a zero-length DATA frame left no payload behind. A
/// peer greasing its control stream is testing exactly this rule, so the two
/// cases that escaped it are the two a greasing peer is most likely to send.
#[tokio::test]
async fn a_frame_before_settings_ends_the_connection() {
    /// A reserved "grease" frame type of the form 0x1f * N + 0x21 (RFC 9114 §9).
    ///
    /// N is arbitrary; this one differs from the server's and the test client's
    /// only so that the three greases can be told apart in a packet capture.
    const GREASE: u64 = 0x1f * 4 + 0x21;

    for (name, first) in [
        ("a grease frame", frame_bytes(GREASE, b"skip me")),
        // Empty on purpose: the decoder's "no bytes yet" state and an empty
        // frame are the same `remaining == 0`, and telling them apart is what
        // makes this case reportable at all.
        ("an empty DATA frame", frame_bytes(FRAME_DATA, b"")),
    ] {
        let server = TestServer::start().await;
        let (_endpoint, connection) = connect_quic(&server).await;

        let mut control = connection
            .open_uni()
            .await
            .expect("open the control stream");

        let mut stream = BytesMut::new();
        datagram::put_varint(&mut stream, STREAM_TYPE_CONTROL);
        stream.extend_from_slice(&first);
        // A perfectly good SETTINGS frame, second. The rule is about order, and
        // sending nothing after the offending frame would leave the server
        // waiting rather than deciding.
        stream.extend_from_slice(&settings_frame());
        control
            .write_all(&stream)
            .await
            .expect("send the control stream");

        let error = tokio::time::timeout(TIMEOUT, connection.closed())
            .await
            .unwrap_or_else(|_| panic!("{name} before SETTINGS must end the connection"));

        match error {
            quinn::ConnectionError::ApplicationClosed(close) => assert_eq!(
                close.error_code.into_inner(),
                H3_MISSING_SETTINGS,
                "{name} before SETTINGS must be H3_MISSING_SETTINGS; reason was {:?}",
                String::from_utf8_lossy(&close.reason)
            ),
            other => panic!("{name}: expected an application close, got {other}"),
        }
    }
}

/// Encodes one HTTP/3 frame: type, length, payload (RFC 9114 §7).
fn frame_bytes(kind: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = BytesMut::new();
    datagram::put_varint(&mut frame, kind);
    datagram::put_varint(&mut frame, payload.len() as u64);
    frame.extend_from_slice(payload);
    frame.to_vec()
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
///
/// Only the length is worked out here -- the first byte's two most significant
/// bits give it -- and `decode_varint` does the rest, so this file holds exactly
/// one varint decoder and it is the independent one.
async fn read_varint(recv: &mut quinn::RecvStream) -> u64 {
    let mut buf = [0u8; 8];
    tokio::time::timeout(TIMEOUT, recv.read_exact(&mut buf[..1]))
        .await
        .expect("varint arrived")
        .expect("varint first byte");

    let length = 1usize << (buf[0] >> 6);
    if length > 1 {
        tokio::time::timeout(TIMEOUT, recv.read_exact(&mut buf[1..length]))
            .await
            .expect("varint tail arrived")
            .expect("varint tail");
    }

    decode_varint(&buf[..length]).expect("a complete varint").0
}

/// Decodes a variable-length integer from a buffer, returning its byte length.
///
/// Hand-written rather than `volto::datagram::peek_varint`, which is the same
/// algorithm: the server's own SETTINGS are the one thing in this file that must
/// be read independently of the code under test, so a bug in that decoder cannot
/// make this test agree with it. The same reasoning as `basic_credentials` in
/// `tests/common`. The `datagram::put_varint` calls elsewhere here only *build*
/// client bytes, where a broken encoder fails loudly instead of passing quietly.
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
/// The regression is the one `volto::h3::connection`'s module documentation
/// describes: a datagram flag each session sampled rather than shared, which
/// left a session opened before the peer's SETTINGS on the capsule fallback for
/// the life of the connection.
///
/// The shared test client cannot produce that ordering: it sends SETTINGS as
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
    // slept on: the SETTINGS frame and this datagram are in flight at the same
    // time, so which side of the flip a single packet lands on is a race, while
    // *never* flipping is the bug.
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
/// Hand-built because the point of the test above is an ordering the shared test
/// client cannot produce. Only the QPACK static table and literals are used, so
/// no encoder stream is needed.
fn connect_udp_headers_frame(authority: &str, host: &str, port: u16) -> Vec<u8> {
    let path = format!("/.well-known/masque/udp/{host}/{port}/");
    let fields: [(&[u8], &[u8]); 5] = [
        (b":method", b"CONNECT"),
        (b":protocol", b"connect-udp"),
        (b":scheme", b"https"),
        (b":authority", authority.as_bytes()),
        (b":path", path.as_bytes()),
    ];

    let mut block = BytesMut::new();
    volto::h3::qpack::encode(&mut block, fields);

    let mut frame = BytesMut::new();
    datagram::put_varint(&mut frame, FRAME_HEADERS);
    datagram::put_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    frame.to_vec()
}

/// The bytes of a client control stream whose SETTINGS enable HTTP Datagrams.
fn control_stream_with_datagrams_enabled() -> Vec<u8> {
    let mut stream = BytesMut::new();
    datagram::put_varint(&mut stream, STREAM_TYPE_CONTROL);
    stream.extend_from_slice(&settings_frame());
    stream.to_vec()
}

/// A SETTINGS frame enabling HTTP Datagrams (RFC 9297 §2.1.1).
fn settings_frame() -> Vec<u8> {
    let mut settings = BytesMut::new();
    datagram::put_varint(&mut settings, SETTINGS_H3_DATAGRAM);
    datagram::put_varint(&mut settings, 1);
    frame_bytes(FRAME_SETTINGS, &settings)
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

/// A peer that says `SETTINGS_H3_DATAGRAM = 1` but never told QUIC how large a
/// DATAGRAM frame it accepts still gets its packets.
///
/// The two halves of the datagram path are negotiated separately: the HTTP/3
/// setting (RFC 9297 §2.1.1) and the `max_datagram_frame_size` transport
/// parameter (RFC 9221 §3). A peer that sends the first without the second is
/// contradicting itself, and neither RFC makes that an error — so the session
/// has to fall back to the capsule stream, which is the channel that exists.
/// Reading the missing parameter as a limit of zero instead made every reply
/// "too large" and the session a silent no-op.
///
/// The client here can still *send* QUIC datagrams, because the server
/// advertised the parameter; it is only the direction towards the client that
/// has no datagram path. The exchange is repeated so that it spans the moment
/// the server reads the client's SETTINGS: before that moment the fallback was
/// already correct, and it is the packets after it that used to disappear.
#[tokio::test]
async fn a_peer_without_max_datagram_frame_size_is_answered_with_capsules() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;

    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(None);
    let endpoint = client_endpoint_with_transport(&server.ca, &["h3"], transport);
    let connection = finish_connect(&endpoint, server.addr)
        .await
        .expect("handshake");
    // quinn ties the two directions together, so this client can neither
    // receive QUIC datagrams nor send them, and everything travels as capsules.
    // What the server sees is the part that matters: SETTINGS_H3_DATAGRAM = 1
    // and no `max_datagram_frame_size` to send one with.

    // The contradiction, on the control stream: datagrams are welcome.
    let mut control = connection
        .open_uni()
        .await
        .expect("open the control stream");
    control
        .write_all(&control_stream_with_datagrams_enabled())
        .await
        .expect("send SETTINGS");

    let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
    send.write_all(&connect_udp_headers_frame(
        &server.addr.to_string(),
        &target.ip().to_string(),
        target.port(),
    ))
    .await
    .expect("send the CONNECT-UDP request");

    let (frame_type, _) = read_frame(&mut recv).await;
    assert_eq!(frame_type, FRAME_HEADERS, "the session must be established");

    for round in 0..5 {
        send.write_all(&frame_bytes(
            FRAME_DATA,
            &volto::capsule::encode_datagram(datagram::CONTEXT_ID_UDP_PAYLOAD, b"no frame size"),
        ))
        .await
        .expect("send a UDP payload as a DATAGRAM capsule");

        let (frame_type, payload) = read_frame(&mut recv).await;
        assert_eq!(
            frame_type, FRAME_DATA,
            "round {round}: the capsule stream travels in DATA frames"
        );

        let mut decoder = CapsuleDecoder::new();
        decoder.push(Bytes::from(payload));
        match decoder.next_capsule().expect("well-formed capsules") {
            Some(Capsule::Datagram {
                context_id,
                payload,
            }) => {
                assert_eq!(context_id, datagram::CONTEXT_ID_UDP_PAYLOAD);
                assert_eq!(&payload[..], b"no frame size", "round {round}");
            }
            other => panic!("round {round}: expected a DATAGRAM capsule, got {other:?}"),
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
