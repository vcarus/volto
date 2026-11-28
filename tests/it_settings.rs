//! The server must advertise extended CONNECT and HTTP Datagrams.
//!
//! Surge validates the server's SETTINGS frame during connection setup and
//! disconnects if either capability is missing, so this is asserted on the wire
//! rather than through the server's own configuration: the test reads the
//! server's HTTP/3 control stream as a raw QUIC stream and decodes the SETTINGS
//! frame itself.

mod common;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use common::rawstream::{
    self, FRAME_DATA, FRAME_HEADERS, FRAME_SETTINGS, H3_EXCESSIVE_LOAD, H3_MISSING_SETTINGS,
    SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_H3_DATAGRAM, SETTINGS_MAX_FIELD_SECTION_SIZE,
    STREAM_CONTROL, connect_udp_headers_frame, decode_varint, open_uni_stream, read_frame,
    server_control_stream, status_of, still_serving, stopped_code,
};
use common::{
    H3Client, TIMEOUT, TestServer, client_endpoint_with_transport, connect_quic, connect_request,
    field_value, finish_connect, send_udp_payload, spawn_udp_echo_target, spawn_udp_target,
};
use volto::capsule::CapsuleDecoder;
use volto::datagram;
use volto::h3::connection::PEER_SETTINGS_WAIT;
use volto::h3api::{Code, StreamError};
use volto::varint;

/// The value the server must advertise, matching `h3api::MAX_FIELD_SECTION_SIZE`.
const EXPECTED_MAX_FIELD_SECTION_SIZE: u64 = 64 * 1024;

/// The server's SETTINGS carry extended CONNECT, HTTP Datagrams and a
/// header-size limit, and the limit is a real one.
///
/// Advertise no limit and an unauthenticated peer's header block is buffered
/// and decoded in full before the server can look at it.
#[tokio::test]
async fn server_advertises_extended_connect_datagrams_and_a_header_limit() {
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
    let advertised = settings
        .get(&SETTINGS_MAX_FIELD_SECTION_SIZE)
        .copied()
        .unwrap_or_else(|| {
            panic!("SETTINGS_MAX_FIELD_SECTION_SIZE (0x06) must be advertised; got {settings:?}")
        });

    assert_eq!(advertised, EXPECTED_MAX_FIELD_SECTION_SIZE, "{settings:?}");
}

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
    varint::put_varint(&mut frame, FRAME_HEADERS);
    varint::put_varint(&mut frame, 2 * EXPECTED_MAX_FIELD_SECTION_SIZE);
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
    // problem, not a reason to drop everything else on the connection.
    still_serving(&connection).await;
}

/// The shared test client refuses an oversized field section on its first
/// request, before it can have read the server's SETTINGS.
///
/// A harness check: the client starts from the limit this server advertises,
/// so a test's first request is judged as its later ones are, and an
/// oversized one never reaches the server.
#[tokio::test]
async fn the_test_client_refuses_an_oversized_first_request() {
    let server = TestServer::start().await;
    let mut client = H3Client::connect(&server).await;

    let mut request = connect_request(rawstream::DENIED_TARGET);
    let padding = "a".repeat(usize::try_from(EXPECTED_MAX_FIELD_SECTION_SIZE).expect("fits"));
    request.fields.append("x-padding", field_value(&padding));

    match client.send.send_request(request).await {
        Ok(_) => panic!("an oversized first request must be refused by the client"),
        Err(StreamError::Local(violation)) => {
            assert_eq!(violation.code(), Code::H3_EXCESSIVE_LOAD);
        }
        Err(other) => panic!("expected a local refusal, got {other:?}"),
    }
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
/// `Some` here means the server sent `max_datagram_frame_size`.
#[tokio::test]
async fn server_advertises_max_datagram_frame_size() {
    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    assert!(
        connection.max_datagram_size().is_some(),
        "the server must advertise max_datagram_frame_size"
    );
}

/// The control stream must *open* with SETTINGS — a frame the server skips is
/// still a frame, and so is one that carries nothing.
///
/// These are the two a greasing peer is most likely to send first, and neither
/// leaves a payload for the control-stream rules to judge.
#[tokio::test]
async fn a_frame_before_settings_ends_the_connection() {
    const GREASE: u64 = rawstream::grease_type(4);

    for (name, first) in [
        ("a grease frame", rawstream::frame(GREASE, b"skip me")),
        // Empty on purpose: the decoder's "no bytes yet" state and an empty
        // frame are the same `remaining == 0`, and telling them apart is what
        // makes this case reportable at all.
        ("an empty DATA frame", rawstream::frame(FRAME_DATA, b"")),
    ] {
        let server = TestServer::start().await;
        let (_endpoint, connection) = connect_quic(&server).await;

        let mut control = first;
        // A perfectly good SETTINGS frame, second. The rule is about order, and
        // sending nothing after the offending frame would leave the server
        // waiting rather than deciding.
        control.extend_from_slice(&datagram_settings());
        let _control = open_uni_stream(&connection, STREAM_CONTROL, &control).await;

        let (code, reason) = rawstream::application_close(&connection, TIMEOUT).await;
        assert_eq!(
            code, H3_MISSING_SETTINGS,
            "{name} before SETTINGS must be H3_MISSING_SETTINGS; reason was {reason:?}"
        );
    }
}

/// Reads the server's control stream and returns the settings it opens with.
async fn read_settings(connection: &quinn::Connection) -> HashMap<u64, u64> {
    let mut control = server_control_stream(connection).await;

    // RFC 9114 §6.2.1: SETTINGS must be the first frame on the control stream.
    let (frame_type, payload) = read_frame(&mut control).await;
    assert_eq!(
        frame_type, FRAME_SETTINGS,
        "the first control stream frame must be SETTINGS, got type {frame_type:#x}"
    );
    parse_settings(&payload)
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
    send_udp_payload(&connection, quarter_stream_id, b"before settings");

    let (frame_type, payload) = read_frame(&mut recv).await;
    assert_eq!(
        frame_type, FRAME_DATA,
        "the capsule stream travels in DATA frames"
    );
    let mut decoder = CapsuleDecoder::new();
    decoder.push(Bytes::from(payload));
    let capsule = common::next_udp_payload(&mut decoder).expect("a whole DATAGRAM capsule");
    assert_eq!(&capsule[..], b"before settings");

    // Only now does the peer say datagrams are allowed. The control stream is
    // kept open for the rest of the test: closing it is H3_CLOSED_CRITICAL_STREAM.
    let _control = open_uni_stream(&connection, STREAM_CONTROL, &datagram_settings()).await;

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

        send_udp_payload(&connection, quarter_stream_id, b"after settings");

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

/// A SETTINGS frame enabling HTTP Datagrams (RFC 9297 §2.1.1).
fn datagram_settings() -> Vec<u8> {
    rawstream::settings_frame(&[(SETTINGS_H3_DATAGRAM, 1)])
}

/// A CONNECT-UDP session is not set up while the peer's SETTINGS can still be
/// expected and have not been read (D119).
///
/// The peer here sends none, so only the bound ends the wait. The server's
/// clock for the bound starts when its own handshake is over, which is after
/// this client began to connect. A response that arrives less than the bound
/// after `started` was therefore sent before the bound had passed.
#[tokio::test]
async fn a_session_waits_for_the_peer_settings_until_the_bound() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;

    let started = Instant::now();
    let (_endpoint, connection) = connect_quic(&server).await;
    let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
    send.write_all(&connect_udp_headers_frame(
        &server.addr.to_string(),
        &target.ip().to_string(),
        target.port(),
    ))
    .await
    .expect("send the CONNECT-UDP request");

    let (frame_type, _) = read_frame(&mut recv).await;
    let answered = started.elapsed();
    assert_eq!(
        frame_type, FRAME_HEADERS,
        "the server must answer the request with a HEADERS frame"
    );
    assert!(
        answered >= PEER_SETTINGS_WAIT,
        "the session was set up {answered:?} after the client began to connect, with no \
         SETTINGS read and the bound of {PEER_SETTINGS_WAIT:?} not yet passed"
    );
    // And not long after it: the bound ends the wait, so a session is not left
    // waiting for SETTINGS that never come. Two seconds is room for a loaded
    // machine and far less than the read timeout of ten.
    assert!(
        answered < PEER_SETTINGS_WAIT + Duration::from_secs(2),
        "the session was set up only {answered:?} after the client began to connect, \
         long past the bound of {PEER_SETTINGS_WAIT:?}"
    );
}

/// How often [`a_session_set_up_once_the_settings_are_read_answers_on_datagrams`]
/// tries for a response that arrived before the bound could have passed.
const SETTINGS_ATTEMPTS: usize = 20;

/// How long that test waits for the target to stay silent before it sends the
/// SETTINGS. A server that does not wait relays the datagram about 11 ms after
/// the connect on the dev host. The window is under a third of
/// [`PEER_SETTINGS_WAIT`], so the SETTINGS and the answer have the rest of the
/// bound.
const UNSET_WINDOW: Duration = Duration::from_millis(100);

/// SETTINGS that are read within the bound end the wait, and the session is on
/// QUIC datagrams from its first packet (D119).
///
/// The request and a datagram for it go out first, and the SETTINGS only after
/// [`UNSET_WINDOW`] in which the target must hear nothing: a server that sets
/// the session up without waiting relays the datagram at once. A target that
/// reports each packet it receives tells the two apart without a fixed sleep.
///
/// An attempt counts only when the response arrived less than the bound after
/// the client's handshake ended: only then is it certain that the SETTINGS
/// ended the wait and the bound did not. The server's clock for the bound
/// starts when its own handshake ends, which is after the client's, so the
/// client's clock reads less than the server's. A machine that stalls for
/// longer makes an attempt prove nothing, and the next one runs on a new
/// connection.
#[tokio::test]
async fn a_session_set_up_once_the_settings_are_read_answers_on_datagrams() {
    let server = TestServer::start().await;

    for _ in 0..SETTINGS_ATTEMPTS {
        // A target of its own per attempt, so a packet relayed late on an
        // earlier connection is not counted against this one.
        let (heard, mut arrivals) = tokio::sync::mpsc::unbounded_channel();
        let target = spawn_udp_target(move |packet| {
            let _ = heard.send(());
            Some(packet.to_vec())
        })
        .await;

        let (_endpoint, connection) = connect_quic(&server).await;
        let started = Instant::now();
        let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
        let quarter_stream_id = datagram::quarter_stream_id(u64::from(send.id()));
        send.write_all(&connect_udp_headers_frame(
            &server.addr.to_string(),
            &target.ip().to_string(),
            target.port(),
        ))
        .await
        .expect("send the CONNECT-UDP request");
        send_udp_payload(&connection, quarter_stream_id, b"ahead of the settings");

        // D119 itself: with no SETTINGS read and the bound not passed, the
        // session does not exist, so nothing reaches the target.
        if tokio::time::timeout(UNSET_WINDOW, arrivals.recv())
            .await
            .is_ok()
        {
            assert!(
                started.elapsed() >= PEER_SETTINGS_WAIT,
                "the target heard from the session {:?} after the client's handshake \
                 ended, before any SETTINGS were sent and before the bound of \
                 {PEER_SETTINGS_WAIT:?}",
                started.elapsed()
            );
            continue;
        }
        let _control = open_uni_stream(&connection, STREAM_CONTROL, &datagram_settings()).await;

        let (frame_type, _) = read_frame(&mut recv).await;
        assert_eq!(
            frame_type, FRAME_HEADERS,
            "the server must answer the request with a HEADERS frame"
        );
        if started.elapsed() >= PEER_SETTINGS_WAIT {
            continue;
        }

        tokio::select! {
            raw = tokio::time::timeout(TIMEOUT, connection.read_datagram()) => {
                let raw = raw
                    .expect("the answer arrives on one of the two channels")
                    .expect("read a datagram");
                let decoded = datagram::decode(raw).expect("server datagrams must be well formed");
                assert_eq!(decoded.quarter_stream_id, quarter_stream_id);
                assert_eq!(decoded.context_id, datagram::CONTEXT_ID_UDP_PAYLOAD);
                assert_eq!(&decoded.payload[..], b"ahead of the settings");
                return;
            }
            (frame_type, _) = read_frame(&mut recv) => panic!(
                "the session was set up after the peer's SETTINGS were read, and its first \
                 answer still came on the request stream, in a frame of type {frame_type:#x}"
            ),
        }
    }

    panic!(
        "none of {SETTINGS_ATTEMPTS} responses arrived within {PEER_SETTINGS_WAIT:?} of the \
         end of its handshake, so none showed what ended the wait"
    );
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
///
/// Five rounds, because nothing on the wire tells the states before and after
/// the server reads the SETTINGS apart.
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
    let _control = open_uni_stream(&connection, STREAM_CONTROL, &datagram_settings()).await;

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
        send.write_all(&rawstream::frame(
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
        let capsule = common::next_udp_payload(&mut decoder).expect("a whole DATAGRAM capsule");
        assert_eq!(&capsule[..], b"no frame size", "round {round}");
    }
}
