//! M2: CONNECT-UDP tunnels (RFC 9298) over QUIC datagrams.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use common::{
    closed_udp_address, connect_udp_request, open_udp_session, open_udp_session_to, respond_to,
    spawn_flooding_udp_target, spawn_large_reply_udp_target, spawn_tagged_udp_target,
    spawn_udp_echo_target, H3Client, TestServer, TIMEOUT,
};
use http::StatusCode;
use volto::datagram;

/// H3_DATAGRAM_ERROR, the code RFC 9297 §2.1 names for an unusable datagram.
const H3_DATAGRAM_ERROR: u64 = 0x33;

/// H3_NO_ERROR, RFC 9114 §8.1: "no error. This is used when the connection or
/// stream needs to be closed, but there is no error to signal."
const H3_NO_ERROR: u64 = 0x100;

/// H3_REQUEST_CANCELLED, RFC 9114 §8.1: "the request or its response --
/// including pushed response -- is cancelled".
const H3_REQUEST_CANCELLED: u64 = 0x10c;

/// Waits for the server to close the QUIC connection, returning its error code.
///
/// Asserted on the wire rather than through server state: a CONNECTION_CLOSE
/// frame carrying this code is exactly what the RFC requires the peer to see.
async fn close_code(quic: &quinn::Connection) -> u64 {
    let error = tokio::time::timeout(TIMEOUT, quic.closed())
        .await
        .expect("the server must close the connection");

    match error {
        quinn::ConnectionError::ApplicationClosed(close) => close.error_code.into_inner(),
        other => panic!("expected an application close, got {other:?}"),
    }
}

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

#[tokio::test]
async fn forwards_udp_payloads_to_a_target_and_back() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, _stream) = open_udp_session(&mut client, &server, target).await;

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
        let (qsid, stream) = open_udp_session(&mut client, &server, target).await;
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

    let (qsid, _stream) = open_udp_session(&mut client, &server, target).await;

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

    let (qsid, _stream) = open_udp_session(&mut client, &server, target).await;

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

/// RFC 9297 §2.1: "The largest legal QUIC stream ID value is 2^62-1, so the
/// largest legal value of the Quarter Stream ID field is 2^60-1. Receipt of an
/// HTTP/3 Datagram that includes a larger value MUST be treated as an HTTP/3
/// connection error of type H3_DATAGRAM_ERROR (0x33)."
///
/// Not the same condition as the test above: a value in range that no session
/// owns is a legitimate drop, while one out of range cannot name a stream at
/// all. Both the first illegal value and the largest a varint can carry are
/// tried, since only the boundary distinguishes the two rules.
#[tokio::test]
async fn an_out_of_range_quarter_stream_id_closes_the_connection() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;

    for quarter_stream_id in [datagram::MAX_QUARTER_STREAM_ID + 1, datagram::VARINT_MAX] {
        let mut client = H3Client::connect(&server).await;

        // With a live session on the connection: the datagram must take the
        // whole connection down regardless of what else is running on it.
        let (qsid, _stream) = open_udp_session(&mut client, &server, target).await;
        assert!(qsid <= datagram::MAX_QUARTER_STREAM_ID, "a real session id");

        client
            .quic
            .send_datagram(datagram::encode(quarter_stream_id, 0, b"out of range"))
            .expect("send datagram");

        assert_eq!(
            close_code(&client.quic).await,
            H3_DATAGRAM_ERROR,
            "quarter stream id {quarter_stream_id} must close the connection"
        );
    }
}

/// RFC 9297 §2.1: "Receipt of a QUIC DATAGRAM frame whose payload is too short
/// to allow parsing the Quarter Stream ID field MUST be treated as an HTTP/3
/// connection error of type H3_DATAGRAM_ERROR (0x33)."
///
/// Two shapes of "too short": nothing at all, and a first byte announcing an
/// eight-byte varint that never arrives.
#[tokio::test]
async fn a_datagram_without_a_quarter_stream_id_closes_the_connection() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;

    for payload in [Bytes::new(), Bytes::from_static(&[0xc0])] {
        let mut client = H3Client::connect(&server).await;
        let (_qsid, _stream) = open_udp_session(&mut client, &server, target).await;

        client
            .quic
            .send_datagram(payload.clone())
            .expect("send datagram");

        assert_eq!(
            close_code(&client.quic).await,
            H3_DATAGRAM_ERROR,
            "a {}-byte datagram must close the connection",
            payload.len()
        );
    }
}

/// The other side of the same coin: a datagram whose Quarter Stream ID parses
/// but whose Context ID does not is **dropped**, and the session survives.
///
/// RFC 9297 §2.1 states its two connection errors about the Quarter Stream ID
/// field only, and RFC 9298 §5 says nothing about a truncated Context ID — so
/// escalating this one would let any peer kill every session on a connection
/// with a single one-byte datagram.
#[tokio::test]
async fn a_truncated_context_id_is_dropped_without_closing_the_connection() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, _stream) = open_udp_session(&mut client, &server, target).await;

    // A well-formed Quarter Stream ID and nothing after it.
    let mut truncated = bytes::BytesMut::new();
    datagram::put_varint(&mut truncated, qsid);
    client
        .quic
        .send_datagram(truncated.freeze())
        .expect("send datagram");

    // The connection is still usable and so is the session.
    client
        .quic
        .send_datagram(datagram::encode_udp_payload(qsid, b"still routed"))
        .expect("send datagram");

    let mut pending = HashMap::new();
    let echoed = recv_payload_for(&client.quic, qsid, &mut pending).await;
    assert_eq!(&echoed[..], b"still routed");
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

    let response = respond_to(&mut client, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn refuses_an_invalid_port_in_the_template() {
    let server = TestServer::start().await;
    let mut client = H3Client::connect(&server).await;

    let response = respond_to(
        &mut client,
        connect_udp_request(server.addr, "127.0.0.1", 0),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// A session ends when the client closes the request stream (RFC 9298 §3.1).
///
/// Observable from outside: once the session is gone its Quarter Stream ID no
/// longer routes, so packets sent afterwards get no reply.
#[tokio::test]
async fn closing_the_request_stream_ends_the_session() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, mut stream) = open_udp_session(&mut client, &server, target).await;

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

    let (qsid, _stream) = open_udp_session(&mut client, &server, target).await;

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

    let (_, mut stream) = open_udp_session(&mut client, &server, target).await;

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

    let (_, mut stream) = open_udp_session(&mut client, &server, target).await;

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

/// A DATAGRAM capsule declaring more bytes than a UDP payload can hold is a
/// *parse* error, and gets the code registered for one.
///
/// The pair to [`a_truncated_capsule_is_rejected`], and the reason both exist:
/// RFC 9297 §5.2 registers 0x33 as a "Datagram or Capsule Protocol parse error",
/// while RFC 9114 §4.1.2 wants H3_MESSAGE_ERROR (0x10e) for a message that is
/// merely malformed. This capsule failed to parse — its declared length can
/// never be a UDP datagram — whereas the truncated one parsed perfectly and just
/// stopped early. Asserting the two side by side is what keeps the distinction
/// from collapsing back into one code the next time this path is touched.
#[tokio::test]
async fn an_oversized_datagram_capsule_is_reset_as_a_parse_error() {
    use volto::capsule;

    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (_, mut stream) = open_udp_session(&mut client, &server, target).await;

    // Only the header: the decoder rejects the declared length before it waits
    // for a single byte of the value, which is the point — buffering 64 KiB to
    // find out it was never valid is exactly what the limit prevents.
    let mut wire = bytes::BytesMut::new();
    datagram::put_varint(&mut wire, capsule::CAPSULE_TYPE_DATAGRAM);
    datagram::put_varint(&mut wire, capsule::MAX_DATAGRAM_CAPSULE_VALUE + 1);
    stream
        .send_data(wire.freeze())
        .await
        .expect("send an oversized capsule header");

    let error = loop {
        match tokio::time::timeout(TIMEOUT, stream.recv_data())
            .await
            .expect("the server responded")
        {
            Ok(Some(_)) => continue,
            Ok(None) => panic!("an oversized capsule must not read as a clean end of stream"),
            Err(error) => break error,
        }
    };

    match error {
        h3::error::StreamError::RemoteTerminate { code, .. } => assert_eq!(
            code.value(),
            H3_DATAGRAM_ERROR,
            "expected H3_DATAGRAM_ERROR (0x33), got {code:?} = {:#x}",
            code.value()
        ),
        other => panic!("expected a stream reset, got {other:?}"),
    }
}

/// A session accepted and closed on the spot asks the client to stop sending
/// with H3_NO_ERROR, at once, on the CONNECT-UDP path as much as on the TCP one.
///
/// The blackhole answer (D49) is "a target that hung up immediately", and a
/// target hanging up is not an error. Any other code here would put a fault in
/// the client's log for a request this server deliberately treated as fine.
/// Observable because the STOP_SENDING goes out before the 200 does, so the
/// first write after the response is refused with the code it carried.
///
/// Both callers of the close share one helper, so this is the same wire
/// behaviour `it_policy` pins for a CONNECT — checked here because a CONNECT-UDP
/// session reaches it through a different route (the RFC 9298 path template, and
/// a 200 that has to carry the capsule protocol field) and could regress on its
/// own.
///
/// The time bound is the half that matters: a server that instead waits for the
/// client to close first and only stops it after a grace period — the shape
/// this path briefly had, and rolled back (D59) — satisfies everything else
/// here, just seconds later.
#[tokio::test]
async fn a_session_closed_on_the_spot_stops_the_client_with_no_error() {
    let server = TestServer::start().await;
    let mut client = H3Client::connect(&server).await;

    let (_, mut stream) = open_udp_session_to(&mut client, &server, "0.0.0.0", 443).await;

    let started = tokio::time::Instant::now();
    let error = loop {
        match stream
            .send_data(Bytes::from_static(b"anything at all"))
            .await
        {
            // quinn only surfaces the stop once the write reaches the peer's
            // state, so an early write can still be accepted locally.
            Ok(()) => {
                assert!(
                    started.elapsed() < TIMEOUT,
                    "the server never stopped the stream"
                );
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => break error,
        }
    };

    match error {
        h3::error::StreamError::RemoteTerminate { code, .. } => assert_eq!(
            code.value(),
            H3_NO_ERROR,
            "expected H3_NO_ERROR (0x100), got {code:?} = {:#x}",
            code.value()
        ),
        other => panic!("expected the peer to stop the stream, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the stop must be asked for up front, not after a wait; it took {:?}",
        started.elapsed()
    );
}

/// An unknown capsule type must be skipped, leaving the session usable.
#[tokio::test]
async fn unknown_capsule_types_are_skipped() {
    use volto::{capsule, datagram as dg};

    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, mut stream) = open_udp_session(&mut client, &server, target).await;

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

    let (qsid, mut stream) = open_udp_session(&mut client, &server, big_target).await;

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
    let (small_qsid, _small_stream) = open_udp_session(&mut client, &server, small_target).await;
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
/// RFC 9298 §3.1: UDP has no close signal, so the timeout is the only thing that
/// reclaims the socket, and leaving the request stream open afterwards would
/// leave the client believing the session still exists.
#[tokio::test]
async fn an_idle_session_closes_the_request_stream() {
    let server = TestServer::start_with_udp_timeout(1).await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, mut stream) = open_udp_session(&mut client, &server, target).await;

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

/// A client that stops reading the capsule stream gets that stream reset, and
/// the connection carrying it survives.
///
/// Only the capsule fallback can reach this: with QUIC datagrams the target's
/// packets bypass the request stream and its flow control entirely. On the
/// fallback they do not, so a client that stops reading parks the server inside
/// `send_data` with no way to make progress.
///
/// The idle timeout used to wrap that write along with the rest of the loop
/// step, and `send_data` is not cancel-safe: the cancelled write left a partial
/// DATA frame in the backend's buffer, and the tidy `finish()` that followed
/// FINned a truncated capsule — malformed by RFC 9297 §3.3. Worse on the *first*
/// request stream of a connection, which is what this session is: `h3` writes
/// one grease frame ahead of the FIN there, the backend refuses a second write
/// while the first is unflushed, and the whole connection went down with
/// H3_INTERNAL_ERROR. Opening a second session at the end is what pins that.
#[tokio::test]
async fn a_client_that_stops_reading_capsules_gets_the_stream_reset() {
    use volto::capsule;

    // Small enough that the target's replies cannot fit, so the server is parked
    // in its write long before the timeout rather than because of it.
    const STREAM_WINDOW: u32 = 64 * 1024;

    let server = TestServer::start_with_udp_timeout(1).await;
    let target = spawn_flooding_udp_target(512, 1200).await;
    let mut client =
        H3Client::connect_without_datagrams_with_stream_window(&server, STREAM_WINDOW).await;

    let (_, mut stream) = open_udp_session(&mut client, &server, target).await;

    // One capsule to wake the target, and then nothing: the replies come back as
    // capsules, fill the window, and stay there.
    stream
        .send_data(capsule::encode_datagram(0, b"go"))
        .await
        .expect("send the trigger capsule");

    // Deliberately not reading yet — reading would let the blocked write make
    // progress. Long enough for the one-second idle timeout to have fired.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let error = tokio::time::timeout(TIMEOUT, async {
        loop {
            match stream.recv_data().await {
                Ok(Some(_)) => continue,
                Ok(None) => panic!("a stalled capsule stream must be reset, not finished"),
                Err(error) => return error,
            }
        }
    })
    .await
    .expect("the server must end the stalled stream on its own");

    match error {
        h3::error::StreamError::RemoteTerminate { code, .. } => assert_eq!(
            code.value(),
            H3_REQUEST_CANCELLED,
            "expected H3_REQUEST_CANCELLED, got {code:?}"
        ),
        other => panic!("expected a stream reset, got {other:?}"),
    }

    // The connection itself must be untouched: one stalled response is a stream
    // error, never a connection error.
    let echo = spawn_udp_echo_target().await;
    let (_, _second) = open_udp_session(&mut client, &server, echo).await;
}

/// An unreachable target must close the session, not leave it hanging.
///
/// Sending to a port with nothing bound draws an ICMP port-unreachable, which the
/// kernel reports on the *connected* socket as `ECONNREFUSED`. RFC 9298 §3.1 says
/// that when the OS reports the socket unusable, the request stream must be closed
/// — so the client learns the target is gone instead of waiting out the 180s idle
/// timeout. Implemented in M2 as part of the socket error paths; this is its
/// regression test.
#[tokio::test]
async fn an_unreachable_target_closes_the_session() {
    let server = TestServer::start().await;
    // Nothing is bound here, but a *connected* UDP socket still opens, so the
    // session is established and answered with a 200 as RFC 9298 §3.1 requires.
    let closed = closed_udp_address().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, mut stream) = open_udp_session(&mut client, &server, closed).await;

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

/// RFC 9297 §3.2: the body of a CONNECT-UDP request stream is a capsule
/// sequence, so a field that frames HTTP content describes something that cannot
/// be there — "a receiver that observes a violation of these requirements MUST
/// treat the HTTP message as malformed".
///
/// The target is a working echo server and the same request without the offending
/// field is accepted at the end, so the refusals cannot be coming from anything
/// else about the request.
#[tokio::test]
async fn refuses_content_framing_fields_on_the_capsule_stream() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    for (name, value) in [
        ("content-length", "0"),
        ("content-length", "42"),
        ("content-type", "application/octet-stream"),
        ("transfer-encoding", "chunked"),
    ] {
        let mut request = connect_udp_request(server.addr, "127.0.0.1", target.port());
        request.headers_mut().insert(
            http::HeaderName::from_static(name),
            http::HeaderValue::from_static(value),
        );

        let response = respond_to(&mut client, request).await;

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{name}: {value} must be refused"
        );
    }

    let response = respond_to(
        &mut client,
        connect_udp_request(server.addr, "127.0.0.1", target.port()),
    )
    .await;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the same request without a framing field must be accepted"
    );
}

/// RFC 9297 §3.4: a `Capsule-Protocol` value that is not a Boolean "MUST be
/// handled as if the field were not present", and a false value "has the same
/// semantics as when the header is not present". None of that is a reason to
/// refuse a tunnel: the `connect-udp` upgrade token is what puts the capsule
/// protocol in use, and this server is the endpoint rather than an intermediary
/// that has to infer it.
///
/// This is a deliberate difference from proxies that reject `?0`, so it gets a
/// test of its own rather than a comment.
#[tokio::test]
async fn any_capsule_protocol_value_still_opens_a_tunnel() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    for value in ["?1", "?0", "not-a-boolean"] {
        let mut request = connect_udp_request(server.addr, "127.0.0.1", target.port());
        request.headers_mut().insert(
            http::HeaderName::from_static("capsule-protocol"),
            http::HeaderValue::from_str(value).expect("header value"),
        );

        let response = respond_to(&mut client, request).await;

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "capsule-protocol: {value} must not change the outcome"
        );
    }
}
