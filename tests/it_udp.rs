//! M2: CONNECT-UDP tunnels (RFC 9298) over QUIC datagrams.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use common::h3client::ends_cleanly;
use common::rawstream::{H3_DATAGRAM_ERROR, H3_NO_ERROR, H3_REQUEST_CANCELLED};
use common::{
    ALLOW_PRIVATE, DELIBERATE, H3Client, TIMEOUT, TestServer, assert_peer_reset,
    closed_udp_address, connect_udp_request, open_udp_session, open_udp_session_to, respond_to,
    send_udp_payload, spawn_flooding_udp_target, spawn_large_reply_udp_target,
    spawn_pushing_udp_target, spawn_silent_udp_target, spawn_tagged_udp_target,
    spawn_udp_echo_target, windowless_transport,
};
use volto::datagram;
use volto::h3api::{FieldValue, Method, Request, Status};

/// Waits for the server to close the QUIC connection, returning its error code.
///
/// Asserted on the wire rather than through server state: a CONNECTION_CLOSE
/// frame carrying this code is exactly what the RFC requires the peer to see.
async fn close_code(quic: &quinn::Connection) -> u64 {
    common::rawstream::application_close(quic, TIMEOUT).await.0
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
    if let Some(queued) = pending.get_mut(&quarter_stream_id)
        && !queued.is_empty()
    {
        return queued.remove(0);
    }

    loop {
        let decoded = common::recv_datagram(quic).await;

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

    send_udp_payload(&client.quic, qsid, b"hello udp");

    let mut pending = HashMap::new();
    let echoed = recv_payload_for(&client.quic, qsid, &mut pending).await;
    assert_eq!(&echoed[..], b"hello udp");
}

/// The regression that guards against the `h3-datagram` #340 class of bug:
/// several sessions on one QUIC connection must each reach their own target.
///
/// Every target tags its reply, so a misrouted datagram shows up as the wrong
/// tag rather than as a silent pass.
///
/// Twenty rather than a handful, for two reasons. A routing mistake that is off
/// by a small amount, or that folds several sessions onto one bucket, has more
/// room to show itself across twenty adjacent Quarter Stream IDs than across
/// four. And twenty request streams is past what an unauthenticated connection
/// may hold at once (`quic::INITIAL_BIDI_STREAMS`), so this now also carries
/// the routing half of the stream allowance being raised on authentication:
/// were it not, the sessions past the sixteenth would never open at all.
#[tokio::test]
async fn concurrent_sessions_do_not_cross_talk() {
    /// Enough sessions to be past the pre-authentication allowance, and a
    /// distinct byte for each of them.
    const SESSIONS: u8 = 20;

    let server = TestServer::start().await;
    let mut client = H3Client::connect(&server).await;

    let mut sessions = Vec::new();
    for tag in 1..=SESSIONS {
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
        send_udp_payload(&client.quic, *qsid, &[*tag, 0xaa]);
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
    send_udp_payload(&client.quic, qsid, b"still here");

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

    send_udp_payload(&client.quic, qsid + 4242, b"nowhere");

    send_udp_payload(&client.quic, qsid, b"somewhere");

    let mut pending = HashMap::new();
    let echoed = recv_payload_for(&client.quic, qsid, &mut pending).await;
    assert_eq!(&echoed[..], b"somewhere");
}

/// A flood of datagrams at one live session costs datagrams, not the session.
///
/// The session's inbound queue is bounded (`INBOUND_QUEUE_DEPTH` in
/// `src/h3/connection.rs`) and overflow is dropped rather than buffered or
/// blocked on, so a peer sending faster than the target drains can lose
/// packets -- UDP's own promise -- but must not be able to grow the server's
/// memory, stall the routing task, or take the session down. Which packets
/// drop is scheduling, so nothing here counts them: what is pinned is that
/// the session answers again once the flood stops, on the same connection,
/// with no close of any kind. The unclaimed-id mirror of this flood (a peer
/// filling its allowance with misses) has no queue to overflow -- those
/// datagrams are dropped at the routing table -- which is why this test aims
/// at a live session and the drop tests above aim past one.
#[tokio::test]
async fn a_datagram_flood_at_a_live_session_is_survived() {
    /// Well past `INBOUND_QUEUE_DEPTH` (64), so the overflow path is really
    /// entered rather than the queue merely filling.
    const FLOOD: usize = 1024;

    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, _stream) = open_udp_session(&mut client, &server, target).await;

    // Nothing is read while the flood is queued: reading would drain the
    // client's half and pace the server's, and the case is the unpaced one.
    for _ in 0..FLOOD {
        send_udp_payload(&client.quic, qsid, b"flood");
    }

    // The probe is retried rather than trusted: a probe that lands while the
    // queue is still full is dropped exactly as the flood's own overflow was,
    // and that drop is correct behaviour, not a failure. What would fail this
    // test is the session never answering again -- a routing task that
    // deadlocked, a queue that jammed shut -- which no number of retries
    // inside the deadline would paper over.
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    'probing: loop {
        send_udp_payload(&client.quic, qsid, b"probe");

        let window = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            let Ok(read) = tokio::time::timeout_at(window, client.quic.read_datagram()).await
            else {
                break;
            };
            let raw = read.expect("the connection must survive the flood");
            let decoded = datagram::decode(raw).expect("server datagrams must be well formed");
            assert_eq!(
                decoded.quarter_stream_id, qsid,
                "every answer belongs to the flooded session; there is no other"
            );
            if &decoded.payload[..] == b"probe" {
                break 'probing;
            }
        }

        assert!(
            tokio::time::Instant::now() < deadline,
            "the session never answered once the flood stopped"
        );
    }

    assert!(
        client.quic.close_reason().is_none(),
        "a flood is met with drops, never with a close"
    );
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
    send_udp_payload(&client.quic, qsid, b"still routed");

    let mut pending = HashMap::new();
    let echoed = recv_payload_for(&client.quic, qsid, &mut pending).await;
    assert_eq!(&echoed[..], b"still routed");
}

#[tokio::test]
async fn refuses_a_path_that_is_not_the_connect_udp_template() {
    let server = TestServer::start().await;
    let mut client = H3Client::connect(&server).await;

    let mut request = Request::new(Method::Connect);
    request.scheme = Some("https".into());
    request.authority = Some(server.addr.to_string().into());
    request.path = Some("/not-masque/1.2.3.4/53/".into());
    request.protocol = Some(common::CONNECT_UDP.into());

    let response = respond_to(&mut client, request).await;

    assert_eq!(response.status, Status::BAD_REQUEST);
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

    assert_eq!(response.status, Status::BAD_REQUEST);
}

/// A bracket that is not the enclosing pair is not part of a host (review M3).
///
/// RFC 9298 §3 writes an IPv6 literal bare and the bracketed form is accepted
/// only as a courtesy, so a bracket left over once that pair comes off is syntax
/// this template has no use for. `it_tcp::refuses_an_authority_with_a_stray_bracket`
/// pins the same answer on the other route; before this the two disagreed, and a
/// name with a bracket in it reached the resolver and came back a 502.
#[tokio::test]
async fn refuses_a_target_host_with_a_stray_bracket() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // The same target the tunnel would otherwise have reached, so what is under
    // test is the bracket and nothing about the destination.
    let response = respond_to(
        &mut client,
        connect_udp_request(server.addr, "127.0.0.1]", target.port()),
    )
    .await;

    assert_eq!(
        response.status,
        Status::BAD_REQUEST,
        "a host with a stray bracket is not the host without it"
    );
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
    send_udp_payload(&client.quic, qsid, b"before");
    let mut pending = HashMap::new();
    assert_eq!(
        &recv_payload_for(&client.quic, qsid, &mut pending).await[..],
        b"before"
    );

    stream.finish().expect("finish the request stream");

    // Give the server a moment to tear the session down, then confirm nothing
    // is routed any more.
    tokio::time::sleep(Duration::from_millis(200)).await;
    send_udp_payload(&client.quic, qsid, b"after");

    let stray = tokio::time::timeout(Duration::from_millis(500), client.quic.read_datagram()).await;
    assert!(
        stray.is_err(),
        "a closed session must not forward datagrams any more"
    );
}

/// The other way a session ends: the client resets the request stream instead of
/// finishing it.
///
/// The same requirement as the test above — RFC 9298 §3.1 ties a session's life
/// to its request stream — reached by the client's other gesture. Worth pinning
/// separately because a reset arrives at the session loop as something else
/// entirely: the read fails once with `RemoteTerminate`, and *then* the stream
/// reports its end, so the session is carried out through the same clean arm a
/// FIN uses and the error arm is only a transient on the way (verified by
/// mutation, 2026-08-29 — making the error arm continue does not keep the
/// session alive). Either way the `DatagramReceiver` has to go with it (D79).
///
/// The second session is the other half of the assertion, and the half nothing
/// else covers: a reset in the middle of one session must cost nothing outside
/// it, and the new session's answers must come back under the new session's id.
/// The tagged targets are what would catch an answer routed under the old one.
#[tokio::test]
async fn a_reset_request_stream_gives_up_its_quarter_stream_id() {
    let server = TestServer::start().await;
    let abandoned_target = spawn_tagged_udp_target(1).await;
    let live_target = spawn_tagged_udp_target(2).await;
    let mut client = H3Client::connect(&server).await;

    let (abandoned, mut stream) = open_udp_session(&mut client, &server, abandoned_target).await;

    // Confirm it works before abandoning it, or the silence below would prove
    // nothing at all.
    let mut pending = HashMap::new();
    send_udp_payload(&client.quic, abandoned, b"live");
    assert_eq!(
        &recv_payload_for(&client.quic, abandoned, &mut pending).await[..],
        b"\x01live"
    );

    // A RESET_STREAM and nothing else. The stream is deliberately kept rather
    // than dropped: dropping it would add a `STOP_SENDING`, and — more to the
    // point — the reset would then be followed by the end of the stream, which
    // the session's *clean* arm answers. Keeping it means the read error is the
    // only thing the session is ever told, which is what this test is for.
    stream.stop_stream(volto::h3api::Code::H3_REQUEST_CANCELLED);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Nothing outside the abandoned session was disturbed: a new one opens and
    // answers under its own id.
    let (live, _live_stream) = open_udp_session(&mut client, &server, live_target).await;
    assert_ne!(live, abandoned, "quinn does not reuse a stream id");
    send_udp_payload(&client.quic, live, b"still here");
    assert_eq!(
        &recv_payload_for(&client.quic, live, &mut pending).await[..],
        b"\x02still here"
    );

    // And the abandoned id routes nowhere.
    send_udp_payload(&client.quic, abandoned, b"after");
    let stray = tokio::time::timeout(Duration::from_millis(500), client.quic.read_datagram()).await;
    assert!(
        stray.is_err(),
        "a session its client reset must not forward datagrams any more"
    );
}

/// A zero-length UDP payload is legitimate and must survive the round trip.
#[tokio::test]
async fn empty_payloads_are_forwarded() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, _stream) = open_udp_session(&mut client, &server, target).await;

    send_udp_payload(&client.quic, qsid, b"");

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

        decoder.push(&Bytes::copy_from_slice(bytes::Buf::chunk(&chunk)));
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
    stream.finish().expect("finish mid-capsule");

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

    // H3_MESSAGE_ERROR (RFC 9114 §8.1): a message this server will not process.
    assert_peer_reset(&error, 0x010e);
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

    assert_peer_reset(&error, H3_DATAGRAM_ERROR);
}

/// The boundary of the size rule the session applies to what a client sends.
///
/// `MAX_UDP_PAYLOAD` is the largest payload a UDP datagram can carry, so a
/// context-0 payload of exactly that many bytes is one this proxy has to
/// forward; a longer one could not be a UDP datagram at all, which is the
/// malformation the session is aborted for. The two sides of that rule are one
/// byte apart and nothing pinned which side the boundary value itself falls on.
///
/// The target socket refuses this payload — an IPv4 datagram has room for fewer
/// bytes than an HTTP datagram may carry — and RFC 9298 §5 makes a payload the
/// link cannot take a discard rather than a fault, so a session that judged the
/// size correctly is still there afterwards. The second capsule is what shows
/// it: the stream is ordered, so it is forwarded only after the first was
/// judged.
#[tokio::test]
async fn a_payload_at_the_maximum_size_is_forwarded_and_keeps_the_session() {
    use volto::capsule;

    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, mut stream) = open_udp_session(&mut client, &server, target).await;

    // An order of magnitude past any QUIC datagram, so the capsule stream is the
    // only way a payload this size can arrive at all.
    let at_the_limit = vec![0x5c; datagram::MAX_UDP_PAYLOAD];
    stream
        .send_data(capsule::encode_datagram(
            datagram::CONTEXT_ID_UDP_PAYLOAD,
            &at_the_limit,
        ))
        .await
        .expect("send a payload of exactly the maximum size");
    stream
        .send_data(capsule::encode_datagram(
            datagram::CONTEXT_ID_UDP_PAYLOAD,
            b"still open",
        ))
        .await
        .expect("send the payload that answers whether the session survived");

    let mut pending = HashMap::new();
    let echoed = recv_payload_for(&client.quic, qsid, &mut pending).await;
    assert_eq!(
        &echoed[..],
        b"still open",
        "a payload of exactly the maximum size must be forwarded, not aborted"
    );
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

    assert_peer_reset(&error, H3_NO_ERROR);
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

    send_udp_payload(&client.quic, qsid, b"give me a big one");

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
    send_udp_payload(&client.quic, small_qsid, b"small");

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
    send_udp_payload(&client.quic, qsid, b"alive");
    let mut pending = HashMap::new();
    assert_eq!(
        &recv_payload_for(&client.quic, qsid, &mut pending).await[..],
        b"alive"
    );

    // Now go idle. The server must end the request stream on its own.
    ends_cleanly(&mut stream, "the idle session").await;
}

/// Bytes that finish no capsule must not postpone the session timeout.
///
/// The idle timeout exists to reclaim a session's socket, buffers and tunnel
/// slot, and "idle" has to mean "no packet crossed the proxy" for it to do
/// that job: a peer dripping one byte of a never-finished capsule every few
/// seconds moves no packet anywhere, and if arrival alone re-armed the clock,
/// that drip would hold the session's resources for ever on an authenticated
/// connection nothing else bounds. So the clock is re-armed by forwarded
/// traffic — a payload that reached the target, a packet that came back — and
/// by nothing less; a session fed only unproductive bytes closes on time, as
/// if they had never come.
#[tokio::test]
async fn bytes_that_finish_no_capsule_do_not_postpone_the_session_timeout() {
    let server = TestServer::start_with_udp_timeout(1).await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (_qsid, mut stream) = open_udp_session(&mut client, &server, target).await;

    // An unknown capsule type declaring a megabyte of value (RFC 9297 §3.2
    // requires it to be skipped, not refused), so every byte after this header
    // is discarded by the decoder's skip state and completes nothing.
    stream
        .send_data(Bytes::from_static(&[0x29, 0x80, 0x10, 0x00, 0x00]))
        .await
        .expect("send the capsule header");

    // Drip one byte of that value at a fraction of the timeout, forever if the
    // server lets it. The close is observed from the sending half: an idle
    // close stops receiving, and a stopped stream refuses further writes.
    let started = tokio::time::Instant::now();
    let mut dripped = 0u32;
    let closed = loop {
        if started.elapsed() > Duration::from_secs(10) {
            break false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        if stream.send_data(Bytes::from_static(&[0x00])).await.is_err() {
            break true;
        }
        dripped += 1;
    };
    assert!(
        closed,
        "a drip of unproductive bytes must not hold the session open past its timeout"
    );
    // Several drips landed first, so the close really did cut a stream that
    // was still speaking — and the bytes themselves were legal, since an
    // unknown capsule refused early would have ended the stream on the spot.
    assert!(
        dripped >= 2,
        "the session must have been dripped at while the deadline ran, got {dripped} sends"
    );

    // The response half ends too: socket and request stream close together
    // (RFC 9298 §3.1), exactly as they do for a session that idled silently.
    ends_cleanly(&mut stream, "the drip-fed session").await;
}

/// Nor does a flood of them, which is a different way round the same deadline.
///
/// The drip above spaces its bytes out, so between two of them the session loop
/// has nothing to do, parks on its three sources, and the deadline is looked at.
/// This one never lets it park, because `tokio::time::timeout_at` polls the
/// future it wraps **first** and returns its value without consulting the clock:
/// a lapsed deadline is only ever noticed on a poll where none of the three
/// sources was already ready. A peer that keeps one of them ready is therefore
/// the shape that steps over the branch reading the deadline rather than
/// re-arming it — and that same poll order really did defeat the connection's
/// silence deadline, which `it_handshake`'s churn test now pins (adversarial
/// pass 2026-08-29).
///
/// It does not defeat this one. The bytes are the fastest unproductive supply a
/// peer has on the stream: an unknown capsule type declaring a gigabyte of
/// value, which RFC 9297 §3.2 requires to be skipped, written as fast as the
/// stream will take it — around 18 MB before the cut. The session still closes
/// on its deadline to the millisecond, so the window below is tight; a
/// regression here is a session that outlives its timeout by the length of the
/// flood.
///
/// The stream is only half of it, though, and the quieter half: a chunk of
/// skipped bytes is one pass of the session loop however many bytes it carries,
/// so this flood asks the deadline one question per chunk. The datagram half
/// asks it one per *payload*, and that is where the poll order really did win —
/// see `it_udp_idle`, which pins it with the RFC 9298 §7 budget dropping every
/// payload after the first. It could not be written until now: the client end of
/// it used to trip an accounting bug in quinn-proto's drop-oldest branch
/// (`Datagrams::send` subtracting `payload_bytes` twice), fixed upstream and in
/// our pin since v0.5.2.
#[tokio::test(flavor = "multi_thread")]
async fn a_flood_of_skipped_capsule_bytes_does_not_postpone_the_timeout() {
    let server = TestServer::start_with_udp_timeout(1).await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (_qsid, mut stream) = open_udp_session(&mut client, &server, target).await;

    // Type 0x29, length 2^30: every byte after this header is discarded by the
    // decoder's skip state and completes nothing, so none of it re-arms the
    // deadline.
    stream
        .send_data(Bytes::from_static(&[
            0x29, 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        ]))
        .await
        .expect("send the capsule header");

    // The close is observed from the sending half: an idle close stops
    // receiving, and a stopped stream refuses further writes.
    let started = tokio::time::Instant::now();
    let chunk = Bytes::from(vec![0u8; 16 * 1024]);
    let mut written = 0usize;
    let closed = loop {
        if started.elapsed() > Duration::from_secs(6) {
            break false;
        }
        if stream.send_data(chunk.clone()).await.is_err() {
            break true;
        }
        written += chunk.len();
    };

    assert!(
        closed,
        "a flood of unproductive bytes must not hold the session open past its \
         timeout; wrote {written} bytes"
    );
    // Several megabytes landed first, so the close really did cut a stream that
    // was still speaking rather than one the server had refused outright.
    assert!(
        written > 1024 * 1024,
        "the session must have been flooded while the deadline ran, got {written} bytes"
    );

    // The response half ends too: socket and request stream close together
    // (RFC 9298 §3.1).
    ends_cleanly(&mut stream, "the flooded session").await;
}

/// Payloads reaching a silent target postpone the session timeout on their
/// own.
///
/// The clock has exactly two re-arm points — a payload reaching the target,
/// the target answering — and an echo target exercises both at once, which
/// would let either quietly stop working behind the other. This target never
/// answers, so outbound progress is the only progress there is: eight sends
/// spanning three timeouts must all reach it, and the session must still be
/// open when they stop. Its mirror below pins the inbound point the same way.
#[tokio::test]
async fn payloads_reaching_a_silent_target_postpone_the_session_timeout() {
    let server = TestServer::start_with_udp_timeout(1).await;
    let (target, received) = spawn_silent_udp_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, mut stream) = open_udp_session(&mut client, &server, target).await;

    // Well inside the default unanswered-packet budget (64), so every one of
    // these is forwarded rather than dropped by the amplification cap.
    for round in 0u8..8 {
        tokio::time::sleep(Duration::from_millis(400)).await;
        send_udp_payload(&client.quic, qsid, &[b'o', round]);
    }

    // All eight arrived: the session was alive to forward the last of them,
    // 3.2 s into a 1 s timeout. Waited out rather than asserted immediately,
    // since the sends are fire-and-forget.
    tokio::time::timeout(TIMEOUT, async {
        while received.load(std::sync::atomic::Ordering::Relaxed) < 8 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("all eight payloads must reach the silent target");

    // And once the sends stop, the timeout still does its job.
    ends_cleanly(&mut stream, "the quiesced session").await;
}

/// Packets from the target postpone the session timeout on their own.
///
/// The inbound half of the pair above: the client says one word to wake the
/// target and then only listens, so from the second packet on, the target
/// answering is the only progress there is. Eight pushes spanning three
/// timeouts must all come through.
#[tokio::test]
async fn packets_from_the_target_postpone_the_session_timeout() {
    let server = TestServer::start_with_udp_timeout(1).await;
    let target = spawn_pushing_udp_target(Duration::from_millis(400), 8).await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, mut stream) = open_udp_session(&mut client, &server, target).await;

    send_udp_payload(&client.quic, qsid, b"wake");

    let mut pending = HashMap::new();
    for index in 0u8..8 {
        assert_eq!(
            recv_payload_for(&client.quic, qsid, &mut pending).await[..],
            [b"push".as_slice(), &[index]].concat()[..],
            "push {index}: a session whose target keeps talking must stay open"
        );
    }

    // The target has said its eight; the session goes quiet and closes.
    ends_cleanly(&mut stream, "the quiesced session").await;
}

/// Forwarded packets do postpone the session timeout — the guard the drip
/// test needs to mean anything.
///
/// With "idle" meaning "no packet crossed the proxy", a session whose packets
/// are crossing must live for as long as they keep coming, however many
/// timeouts that spans; a deadline that quietly became absolute would pass the
/// drip test while cutting every long-lived flow at its first timeout, and
/// this is the round-trip shape — both re-arm points at once, the way real
/// traffic exercises them — that would catch it.
#[tokio::test]
async fn forwarded_packets_postpone_the_session_timeout() {
    let server = TestServer::start_with_udp_timeout(1).await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, mut stream) = open_udp_session(&mut client, &server, target).await;

    // Eight round trips spaced well inside the timeout but spanning three of
    // them end to end: every one must come back.
    let mut pending = HashMap::new();
    for round in 0u8..8 {
        tokio::time::sleep(Duration::from_millis(400)).await;
        let payload = [b"tick", &[round][..]].concat();
        send_udp_payload(&client.quic, qsid, &payload);
        assert_eq!(
            recv_payload_for(&client.quic, qsid, &mut pending).await[..],
            payload[..],
            "round {round}: a session whose packets are crossing must stay open"
        );
    }

    // And once the traffic stops, the timeout does its job as before.
    ends_cleanly(&mut stream, "the quiesced session").await;
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
/// DATA frame in the buffer, and the tidy `finish()` that followed FINned a
/// truncated capsule — malformed by RFC 9297 §3.3. It took the whole connection
/// down with it rather than just this stream, which is why a second session is
/// opened at the end: that is the half being pinned here.
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

    assert_peer_reset(&error, H3_REQUEST_CANCELLED);

    // The connection itself must be untouched: one stalled response is a stream
    // error, never a connection error.
    let echo = spawn_udp_echo_target().await;
    let (_, _second) = open_udp_session(&mut client, &server, echo).await;
}

/// The 200 that opens a session is bounded like every refusal.
///
/// The socket is already bound by the time this write happens, which used to be
/// the argument for exempting it — but the session loop that would notice the
/// client giving up is started by the line *after* this write, so a peer that
/// grants no flow-control credit parks the request task with the target socket
/// and the Quarter Stream ID claim in its hand. RFC 9114 §8.1's
/// H3_REQUEST_CANCELLED covers "the request or its response (including pushed
/// response) is cancelled", and a reset is the only end that reaches a peer
/// granting no window at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_200_the_peer_will_not_take_is_reset() {
    let server = TestServer::start_with(&format!("{DELIBERATE}{ALLOW_PRIVATE}")).await;
    let target = spawn_udp_echo_target().await;

    let endpoint =
        common::client_endpoint_with_transport(&server.ca, &["h3"], windowless_transport());
    let connection = common::finish_connect(&endpoint, server.addr)
        .await
        .expect("handshake");

    let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
    send.write_all(&common::rawstream::connect_udp_headers_frame(
        &server.addr.to_string(),
        "127.0.0.1",
        target.port(),
    ))
    .await
    .expect("send a connect-udp request that will be accepted");

    // Waited for rather than slept past: `received_reset` observes the reset
    // without granting the flow-control credit an ordinary read would, which is
    // the whole reason a window this small is the setup.
    let reset = tokio::time::timeout(TIMEOUT, recv.received_reset())
        .await
        .expect("the server must not wait for a window that is not coming")
        .expect("a 200 the peer would not take must end in a reset");
    assert_eq!(
        reset.map(quinn::VarInt::into_inner),
        Some(H3_REQUEST_CANCELLED),
        "an abandoned 200 is a cancelled request"
    );

    // One session that could not be opened is not a reason to drop everything
    // else on the connection.
    assert!(
        connection.close_reason().is_none(),
        "the connection must survive a session whose 200 could not be delivered"
    );
}

/// And no packet is forwarded for a session that 200 was going to open.
///
/// The reset above is what the peer sees. This is what the *target* sees, and
/// it is the other half of the same rule: `tunnel::respond` answers whether the
/// 200 reached the stream, `Responded::landed` reports the lapse and returns
/// `false`, and the whole meaning of that `false` is that `udp::run` stops
/// before the session loop. A caller that read the lapse and carried on would
/// open the session anyway, and the only place that shows is a target receiving
/// traffic on behalf of a client that was never told it had a tunnel.
///
/// The datagrams go out after the reset, on the Quarter Stream ID the client
/// computes for itself: a peer sends them whether or not it heard the 200, and
/// with a session running they are relayed (`it_settings` pins that a raw
/// connection which never sent SETTINGS still has its payloads forwarded).
///
/// The control at the end is what makes "nothing arrived" a measurement rather
/// than a broken target: a second, ordinary connection opens a session to the
/// same target and one payload must be counted. The four above were sent, and
/// processed, before that connection's handshake began.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_whose_200_never_landed_forwards_nothing() {
    let server = TestServer::start_with(&format!("{DELIBERATE}{ALLOW_PRIVATE}")).await;
    let (target, received) = spawn_silent_udp_target().await;

    let endpoint =
        common::client_endpoint_with_transport(&server.ca, &["h3"], windowless_transport());
    let connection = common::finish_connect(&endpoint, server.addr)
        .await
        .expect("handshake");

    let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
    let quarter_stream_id = datagram::quarter_stream_id(u64::from(send.id()));
    send.write_all(&common::rawstream::connect_udp_headers_frame(
        &server.addr.to_string(),
        "127.0.0.1",
        target.port(),
    ))
    .await
    .expect("send a connect-udp request that will be accepted");

    // Waited for rather than slept past: the reset is what says the response
    // deadline (this connection's idle timeout) has lapsed, so the request task
    // has decided by the time the datagrams below go out.
    tokio::time::timeout(TIMEOUT, recv.received_reset())
        .await
        .expect("the server must not wait for a window that is not coming")
        .expect("a 200 the peer would not take must end in a reset");

    // Well inside the unanswered-packet budget, so nothing here could be
    // dropped by the amplification cap instead of by the absent session.
    for round in 0u8..4 {
        send_udp_payload(&connection, quarter_stream_id, &[b'x', round]);
    }

    let mut client = H3Client::connect(&server).await;
    let (control, _stream) = open_udp_session(&mut client, &server, target).await;
    send_udp_payload(&client.quic, control, b"the control packet");

    tokio::time::timeout(TIMEOUT, async {
        while received.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the control session's payload must reach the target");

    assert_eq!(
        received.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "only the control session's packet may reach the target: a 200 that never \
         landed must stop `udp::run` before the session loop, so the four payloads \
         sent on the abandoned session are relayed by nobody"
    );
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

    send_udp_payload(&client.quic, qsid, b"knock knock");

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
///
/// `Transfer-Encoding` is the third field that paragraph forbids and is not
/// here: it is connection-specific under RFC 9114 §4.2 as well, and is refused
/// for every request before routing, which is where `it_tcp` pins it on this
/// route among others.
#[tokio::test]
async fn refuses_content_framing_fields_on_the_capsule_stream() {
    let server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    for (name, value) in [
        ("content-length", "0"),
        ("content-length", "42"),
        ("content-type", "application/octet-stream"),
    ] {
        let mut request = connect_udp_request(server.addr, "127.0.0.1", target.port());
        request.fields.append(name, FieldValue::from_static(value));

        let response = respond_to(&mut client, request).await;

        assert_eq!(
            response.status,
            Status::BAD_REQUEST,
            "{name}: {value} must be refused"
        );
    }

    let response = respond_to(
        &mut client,
        connect_udp_request(server.addr, "127.0.0.1", target.port()),
    )
    .await;

    assert_eq!(
        response.status,
        Status::OK,
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
        request
            .fields
            .append("capsule-protocol", common::field_value(value));

        let response = respond_to(&mut client, request).await;

        assert_eq!(
            response.status,
            Status::OK,
            "capsule-protocol: {value} must not change the outcome"
        );
    }
}
