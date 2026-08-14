//! M2: CONNECT-UDP tunnels (RFC 9298) over QUIC datagrams.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use common::{
    closed_udp_address, connect_udp_request, spawn_large_reply_udp_target, spawn_tagged_udp_target,
    spawn_udp_echo_target, H3Client, TestServer, TIMEOUT,
};
use http::StatusCode;
use volto::datagram;

/// Reads datagrams until one arrives for `quarter_stream_id`, returning its
/// payload.
///
/// Datagrams for other sessions are put aside rather than discarded so a caller
/// interleaving several sessions does not lose data.
async fn recv_payload_for(
    quic: &quinn::Connection,
    quarter_stream_id: u64,
    pending: &mut HashMap<u64, Vec<Bytes>>,
) -> Bytes {
    if let Some(queued) = pending.get_mut(&quarter_stream_id) {
        if !queued.is_empty() {
            return queued.remove(0);
        }
    }

    loop {
        let raw = tokio::time::timeout(TIMEOUT, quic.read_datagram())
            .await
            .expect("a datagram arrived")
            .expect("datagram");

        let decoded = datagram::decode(raw).expect("server datagrams must be well formed");
        assert_eq!(
            decoded.context_id,
            datagram::CONTEXT_ID_UDP_PAYLOAD,
            "a UDP payload must use context 0"
        );

        if decoded.quarter_stream_id == quarter_stream_id {
            return decoded.payload;
        }

        pending
            .entry(decoded.quarter_stream_id)
            .or_default()
            .push(decoded.payload);
    }
}

/// Opens a CONNECT-UDP session and returns its Quarter Stream ID.
async fn open_session(
    client: &mut H3Client,
    server: &TestServer,
    host: &str,
    port: u16,
) -> (u64, common::ClientStream) {
    let mut stream = client
        .send
        .send_request(connect_udp_request(server.addr, host, port))
        .await
        .expect("send CONNECT-UDP");

    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("response arrived")
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    // RFC 9297 §3.4: the response must announce the capsule protocol and must
    // not describe a body.
    assert_eq!(
        response
            .headers()
            .get("capsule-protocol")
            .map(|value| value.to_str().unwrap()),
        Some("?1"),
        "the 2xx must carry Capsule-Protocol: ?1"
    );
    assert!(response.headers().get("content-length").is_none());
    assert!(response.headers().get("content-type").is_none());

    let quarter_stream_id = datagram::quarter_stream_id(stream.id().into_inner());
    (quarter_stream_id, stream)
}

#[tokio::test]
async fn forwards_udp_payloads_to_a_target_and_back() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, _stream) = open_session(
        &mut client,
        &server,
        &target.ip().to_string(),
        target.port(),
    )
    .await;

    client
        .quic
        .send_datagram(datagram::encode_udp_payload(qsid, b"hello udp"))
        .expect("send datagram");

    let mut pending = HashMap::new();
    let echoed = recv_payload_for(&client.quic, qsid, &mut pending).await;
    assert_eq!(&echoed[..], b"hello udp");
}

/// The regression that guards against the `h3-datagram` #340 class of bug:
/// several sessions on one QUIC connection must each reach their own target.
///
/// Every target tags its reply, so a misrouted datagram shows up as the wrong
/// tag rather than as a silent pass.
#[tokio::test]
async fn concurrent_sessions_do_not_cross_talk() {
    let server = TestServer::start().await;
    let mut client = H3Client::connect(&server).await;

    let mut sessions = Vec::new();
    for tag in 1..=4u8 {
        let target = spawn_tagged_udp_target(tag).await;
        let (qsid, stream) = open_session(
            &mut client,
            &server,
            &target.ip().to_string(),
            target.port(),
        )
        .await;
        sessions.push((tag, qsid, stream));
    }

    // Distinct Quarter Stream IDs are the whole point: the bug this guards
    // against encoded every session as zero.
    let ids: std::collections::HashSet<u64> = sessions.iter().map(|(_, qsid, _)| *qsid).collect();
    assert_eq!(
        ids.len(),
        sessions.len(),
        "sessions must have distinct QSIDs"
    );

    // Send on every session before reading anything, so replies are in flight
    // together and a routing mistake cannot be masked by serialisation.
    for (tag, qsid, _) in &sessions {
        client
            .quic
            .send_datagram(datagram::encode_udp_payload(*qsid, &[*tag, 0xaa]))
            .expect("send datagram");
    }

    let mut pending = HashMap::new();
    for (tag, qsid, _) in &sessions {
        let payload = recv_payload_for(&client.quic, *qsid, &mut pending).await;
        assert_eq!(
            &payload[..],
            &[*tag, *tag, 0xaa],
            "session {qsid} received another session's data"
        );
    }
}

/// A session must survive a datagram carrying an unknown context id.
///
/// RFC 9298 §4 requires such datagrams to be dropped silently; killing the
/// session instead would be a denial-of-service handed to the peer.
#[tokio::test]
async fn unknown_context_ids_are_dropped_without_ending_the_session() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, _stream) = open_session(
        &mut client,
        &server,
        &target.ip().to_string(),
        target.port(),
    )
    .await;

    // Context 9 is not one we registered.
    client
        .quic
        .send_datagram(datagram::encode(qsid, 9, b"ignore me"))
        .expect("send datagram");

    // The session still works.
    client
        .quic
        .send_datagram(datagram::encode_udp_payload(qsid, b"still here"))
        .expect("send datagram");

    let mut pending = HashMap::new();
    let echoed = recv_payload_for(&client.quic, qsid, &mut pending).await;
    assert_eq!(&echoed[..], b"still here");
}

/// A datagram for a Quarter Stream ID with no session must be dropped, not
/// treated as a connection error.
#[tokio::test]
async fn datagrams_for_unknown_sessions_are_dropped() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, _stream) = open_session(
        &mut client,
        &server,
        &target.ip().to_string(),
        target.port(),
    )
    .await;

    client
        .quic
        .send_datagram(datagram::encode_udp_payload(qsid + 4242, b"nowhere"))
        .expect("send datagram");

    client
        .quic
        .send_datagram(datagram::encode_udp_payload(qsid, b"somewhere"))
        .expect("send datagram");

    let mut pending = HashMap::new();
    let echoed = recv_payload_for(&client.quic, qsid, &mut pending).await;
    assert_eq!(&echoed[..], b"somewhere");
}

#[tokio::test]
async fn refuses_a_path_that_is_not_the_connect_udp_template() {
    let server = TestServer::start().await;
    let mut client = H3Client::connect(&server).await;

    let uri: http::Uri = format!("https://{}/not-masque/1.2.3.4/53/", server.addr)
        .parse()
        .expect("uri");
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri)
        .body(())
        .expect("request");
    request
        .extensions_mut()
        .insert(h3::ext::Protocol::CONNECT_UDP);

    let mut stream = client
        .send
        .send_request(request)
        .await
        .expect("send CONNECT-UDP");
    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("response arrived")
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn refuses_an_invalid_port_in_the_template() {
    let server = TestServer::start().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = client
        .send
        .send_request(connect_udp_request(server.addr, "127.0.0.1", 0))
        .await
        .expect("send CONNECT-UDP");
    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("response arrived")
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// A session ends when the client closes the request stream (RFC 9298 §3.5).
///
/// Observable from outside: once the session is gone its Quarter Stream ID no
/// longer routes, so packets sent afterwards get no reply.
#[tokio::test]
async fn closing_the_request_stream_ends_the_session() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, mut stream) = open_session(
        &mut client,
        &server,
        &target.ip().to_string(),
        target.port(),
    )
    .await;

    // Confirm it works before closing it.
    client
        .quic
        .send_datagram(datagram::encode_udp_payload(qsid, b"before"))
        .expect("send datagram");
    let mut pending = HashMap::new();
    assert_eq!(
        &recv_payload_for(&client.quic, qsid, &mut pending).await[..],
        b"before"
    );

    stream.finish().await.expect("finish the request stream");

    // Give the server a moment to tear the session down, then confirm nothing
    // is routed any more.
    tokio::time::sleep(Duration::from_millis(200)).await;
    client
        .quic
        .send_datagram(datagram::encode_udp_payload(qsid, b"after"))
        .expect("send datagram");

    let stray = tokio::time::timeout(Duration::from_millis(500), client.quic.read_datagram()).await;
    assert!(
        stray.is_err(),
        "a closed session must not forward datagrams any more"
    );
}

/// A zero-length UDP payload is legitimate and must survive the round trip.
#[tokio::test]
async fn empty_payloads_are_forwarded() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, _stream) = open_session(
        &mut client,
        &server,
        &target.ip().to_string(),
        target.port(),
    )
    .await;

    client
        .quic
        .send_datagram(datagram::encode_udp_payload(qsid, b""))
        .expect("send datagram");

    let mut pending = HashMap::new();
    let echoed = recv_payload_for(&client.quic, qsid, &mut pending).await;
    assert!(echoed.is_empty(), "expected an empty payload back");
}

/// M3: with QUIC datagrams unavailable, the session must still work over
/// DATAGRAM capsules on the request stream.
///
/// The client never advertises `SETTINGS_H3_DATAGRAM`, so RFC 9297 §2.1.1 bars
/// the datagram path in both directions and everything has to travel as
/// capsules.
#[tokio::test]
async fn capsules_carry_payloads_when_datagrams_are_unavailable() {
    use volto::capsule::{self, Capsule, CapsuleDecoder};

    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect_without_datagrams(&server).await;

    let mut stream = client
        .send
        .send_request(connect_udp_request(
            server.addr,
            &target.ip().to_string(),
            target.port(),
        ))
        .await
        .expect("send CONNECT-UDP");

    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("response arrived")
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    // Send the UDP payload as a DATAGRAM capsule, split across two writes to
    // exercise reassembly on the server side.
    let encoded = capsule::encode_datagram(0, b"over capsules");
    let split = encoded.len() / 2;
    stream
        .send_data(encoded.slice(..split))
        .await
        .expect("send first half");
    stream
        .send_data(encoded.slice(split..))
        .await
        .expect("send second half");

    // The reply comes back as a capsule too, since datagrams are unavailable.
    let mut decoder = CapsuleDecoder::new();
    let payload = loop {
        if let Some(Capsule::Datagram {
            context_id,
            payload,
        }) = decoder.next_capsule().expect("well-formed capsules")
        {
            assert_eq!(context_id, 0);
            break payload;
        }

        let chunk = tokio::time::timeout(TIMEOUT, stream.recv_data())
            .await
            .expect("a capsule arrived")
            .expect("read succeeded")
            .expect("the stream must not end before the reply");

        decoder.push(Bytes::copy_from_slice(bytes::Buf::chunk(&chunk)));
    };

    assert_eq!(&payload[..], b"over capsules");
}

/// A capsule sequence that stops half-way through is a malformed message.
#[tokio::test]
async fn a_truncated_capsule_is_rejected() {
    use volto::capsule;

    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = client
        .send
        .send_request(connect_udp_request(
            server.addr,
            &target.ip().to_string(),
            target.port(),
        ))
        .await
        .expect("send CONNECT-UDP");

    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("response arrived")
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    // Half a capsule, then end the stream.
    let encoded = capsule::encode_datagram(0, b"incomplete");
    stream
        .send_data(encoded.slice(..encoded.len() - 4))
        .await
        .expect("send a partial capsule");
    stream.finish().await.expect("finish mid-capsule");

    // The server must reset the stream rather than treat this as a clean close.
    let error = loop {
        match tokio::time::timeout(TIMEOUT, stream.recv_data())
            .await
            .expect("the server responded")
        {
            Ok(Some(_)) => continue,
            Ok(None) => panic!("a truncated capsule must not read as a clean end of stream"),
            Err(error) => break error,
        }
    };

    match error {
        h3::error::StreamError::RemoteTerminate { code, .. } => assert_eq!(
            code.value(),
            0x010e,
            "expected H3_MESSAGE_ERROR (0x10e), got {code:?} = {:#x}",
            code.value()
        ),
        other => panic!("expected a stream reset, got {other:?}"),
    }
}

/// An unknown capsule type must be skipped, leaving the session usable.
#[tokio::test]
async fn unknown_capsule_types_are_skipped() {
    use volto::{capsule, datagram as dg};

    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, mut stream) = open_session(
        &mut client,
        &server,
        &target.ip().to_string(),
        target.port(),
    )
    .await;

    // An unknown capsule type, followed by a real one on the same stream.
    // Encoded with the varint codec rather than by hand: 0x41 written as a raw
    // byte would be read as the *first byte of a two-byte varint*, which is a
    // different capsule type entirely.
    let mut wire = bytes::BytesMut::new();
    dg::put_varint(&mut wire, 0x41); // an unknown capsule type
    dg::put_varint(&mut wire, 3); // its value length
    wire.extend_from_slice(b"xyz");
    wire.extend_from_slice(&capsule::encode_datagram(0, b"after unknown"));
    stream
        .send_data(wire.freeze())
        .await
        .expect("send capsules");

    // The payload after the unknown capsule still reaches the target, and the
    // reply arrives as a datagram since this client does support them.
    let mut pending = HashMap::new();
    let echoed = recv_payload_for(&client.quic, qsid, &mut pending).await;
    assert_eq!(&echoed[..], b"after unknown");
}

/// A target packet too large for a QUIC datagram is dropped, not downgraded.
///
/// RFC 9298 §6.1 says a proxy SHOULD NOT fall back to a capsule here: doing so
/// would silently turn a lossy flow into a reliable, head-of-line blocked one.
/// The session must survive the drop.
#[tokio::test]
async fn oversized_target_packets_are_dropped_not_sent_as_capsules() {
    let server = TestServer::start().await;
    // Comfortably above any QUIC datagram limit on a 1200-1500 byte path.
    let big_target = spawn_large_reply_udp_target(8000).await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, mut stream) = open_session(
        &mut client,
        &server,
        &big_target.ip().to_string(),
        big_target.port(),
    )
    .await;

    let limit = client
        .quic
        .max_datagram_size()
        .expect("the server must accept datagrams");
    assert!(limit < 8000, "the reply must not fit in a datagram");

    client
        .quic
        .send_datagram(datagram::encode_udp_payload(qsid, b"give me a big one"))
        .expect("send datagram");

    // Nothing must arrive: neither a datagram...
    let stray = tokio::time::timeout(Duration::from_millis(500), client.quic.read_datagram()).await;
    assert!(stray.is_err(), "an oversized packet must not be forwarded");

    // ...nor a capsule on the request stream.
    let capsule = tokio::time::timeout(Duration::from_millis(200), stream.recv_data()).await;
    assert!(
        capsule.is_err(),
        "an oversized packet must not be downgraded to a capsule (RFC 9298 §6.1)"
    );

    // The session is still alive: a small reply still gets through.
    let small_target = spawn_udp_echo_target().await;
    let (small_qsid, _small_stream) = open_session(
        &mut client,
        &server,
        &small_target.ip().to_string(),
        small_target.port(),
    )
    .await;
    client
        .quic
        .send_datagram(datagram::encode_udp_payload(small_qsid, b"small"))
        .expect("send datagram");

    let mut pending = HashMap::new();
    assert_eq!(
        &recv_payload_for(&client.quic, small_qsid, &mut pending).await[..],
        b"small"
    );
}

/// An idle session must close both its socket and its request stream.
///
/// RFC 9298 §3.5: UDP has no close signal, so the timeout is the only thing that
/// reclaims the socket, and leaving the request stream open afterwards would
/// leave the client believing the session still exists.
#[tokio::test]
async fn an_idle_session_closes_the_request_stream() {
    let server = TestServer::start_with_udp_timeout(1).await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, mut stream) = open_session(
        &mut client,
        &server,
        &target.ip().to_string(),
        target.port(),
    )
    .await;

    // The session works to begin with.
    client
        .quic
        .send_datagram(datagram::encode_udp_payload(qsid, b"alive"))
        .expect("send datagram");
    let mut pending = HashMap::new();
    assert_eq!(
        &recv_payload_for(&client.quic, qsid, &mut pending).await[..],
        b"alive"
    );

    // Now go idle. The server must end the request stream on its own.
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match stream.recv_data().await {
                Ok(Some(_)) => continue,
                Ok(None) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .expect("the server must close an idle session");

    assert!(
        ended.is_ok(),
        "the idle session should end cleanly, got {ended:?}"
    );
}

/// An unreachable target must close the session, not leave it hanging.
///
/// Sending to a port with nothing bound draws an ICMP port-unreachable, which the
/// kernel reports on the *connected* socket as `ECONNREFUSED`. RFC 9298 §3.5 says
/// that when the OS reports the socket unusable, the request stream must be closed
/// — so the client learns the target is gone instead of waiting out the 180s idle
/// timeout. Implemented in M2 as part of the socket error paths; this is its
/// regression test.
#[tokio::test]
async fn an_unreachable_target_closes_the_session() {
    let server = TestServer::start().await;
    // Nothing is bound here, but a *connected* UDP socket still opens, so the
    // session is established and answered with a 200 as RFC 9298 §3.2 requires.
    let closed = closed_udp_address().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, mut stream) = open_session(
        &mut client,
        &server,
        &closed.ip().to_string(),
        closed.port(),
    )
    .await;

    client
        .quic
        .send_datagram(datagram::encode_udp_payload(qsid, b"knock knock"))
        .expect("send datagram");

    // The server finishes its side of the request stream, which the client sees
    // as end-of-stream. Anything else — including nothing at all until the test
    // times out — means the ICMP error was swallowed.
    let ended = tokio::time::timeout(TIMEOUT, stream.recv_data()).await;
    match ended {
        Ok(Ok(None)) => {}
        Ok(Ok(Some(_))) => panic!("an unreachable target must not produce data"),
        // A reset instead of a clean finish also closes the session, which
        // satisfies the requirement.
        Ok(Err(_)) => {}
        Err(_) => panic!("the request stream was left open after ECONNREFUSED"),
    }
}
