//! M5: graceful shutdown (RFC 9114 §5.2 GOAWAY plus a bounded grace period).
//!
//! The property under test is not "the process exits" but "it exits without
//! cutting anyone off": a tunnel that is mid-transfer when SIGTERM arrives must
//! be allowed to finish, while new work is turned away immediately.

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::rawstream::connect_headers_frame;
use common::{
    connect_request, open_tcp_tunnel, open_udp_session, read_at_least, spawn_echo_target,
    spawn_udp_echo_target, udp_round_trip, H3Client, TestServer, ALLOW_PRIVATE, STOP_TIMEOUT,
    TIMEOUT,
};

/// H3_REQUEST_REJECTED, RFC 9114 §8.1: "A server rejected a request without
/// performing any application processing."
///
/// §4.1.1 is where it is asked for: "When the server cancels a request without
/// performing any application processing, the request is considered
/// 'rejected'. The server SHOULD abort its response stream with the error code
/// H3_REQUEST_REJECTED."
const H3_REQUEST_REJECTED: u64 = 0x10b;

/// The distance between consecutive client-initiated bidirectional stream ids
/// (RFC 9000 §2.1), and so between one request and the next.
const REQUEST_STREAM_STEP: u64 = 4;

/// A tunnel that is in use when the signal arrives keeps working, and the server
/// waits for it rather than dropping it.
#[tokio::test]
async fn an_established_tunnel_survives_goaway_and_finishes() {
    let mut server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    stream
        .send_data(Bytes::from_static(b"before"))
        .await
        .expect("send before shutdown");
    assert_eq!(&read_at_least(&mut stream, 6).await, b"before");

    server.shutdown();

    // The GOAWAY does not touch this tunnel: it must still carry data in both
    // directions afterwards.
    stream
        .send_data(Bytes::from_static(b"after!"))
        .await
        .expect("send after shutdown");
    assert_eq!(&read_at_least(&mut stream, 6).await, b"after!");

    // Once the client is done, the server should finish its side and stop —
    // well inside the default grace period.
    stream.finish().expect("finish the request stream");
    common::read_to_end(&mut stream).await;

    server.wait_until_stopped(STOP_TIMEOUT).await;
}

/// A UDP session is drained on the same terms as a TCP tunnel.
#[tokio::test]
async fn an_established_udp_session_survives_goaway() {
    let mut server = TestServer::start().await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, mut stream) = open_udp_session(&mut client, &server, target).await;

    server.shutdown();

    // Datagrams still flow: they do not go through the request stream at all, so
    // this is a genuinely separate path from the TCP case above.
    let echoed = udp_round_trip(&client, qsid, b"still here").await;
    assert_eq!(
        &echoed[..],
        b"still here",
        "the session still works after GOAWAY"
    );

    // Closing the stream ends the session, which lets the server finish.
    stream.finish().expect("finish the request stream");
    server.wait_until_stopped(STOP_TIMEOUT).await;
}

/// The GOAWAY names the first request the server will not serve, and a stream
/// opened past it is rejected on the wire.
///
/// The point of doing this with raw QUIC streams rather than through the test
/// client: that client refuses to open a request once it has seen a GOAWAY, so
/// [`new_requests_are_refused_after_goaway`] below would pass against a server
/// that had no rejection logic at all. Everything asserted here is the server's
/// -- the identifier it chose, and the two error codes it puts on the stream.
///
/// RFC 9114 §5.2: "Requests or pushes with the indicated identifier or greater
/// are rejected (Section 4.1.1) by the sender of the GOAWAY."
#[tokio::test]
async fn a_request_stream_past_the_goaway_identifier_is_rejected() {
    let mut server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // One tunnel, so the connection has something to drain and stays open while
    // the rejection below is asserted.
    let mut held = open_tcp_tunnel(&mut client, &target.to_string()).await;
    let last_accepted = held.id();

    server.shutdown();

    // The identifier is four past the last request the server accepted: that
    // request is untouched, and everything from the next stream on is refused.
    let identifier = client.await_goaway().await;
    assert_eq!(
        identifier,
        last_accepted + REQUEST_STREAM_STEP,
        "the GOAWAY must name the first request the server will not serve"
    );

    // A request stream at the identifier, carrying a CONNECT the server would
    // otherwise have served -- the same target the tunnel above is using.
    let (mut send, mut recv) = client
        .quic
        .open_bi()
        .await
        .expect("open a request stream past the GOAWAY identifier");
    assert!(
        u64::from(send.id()) >= identifier,
        "stream {} is not past the identifier {identifier}",
        send.id()
    );
    send.write_all(&connect_headers_frame(&target.to_string()))
        .await
        .expect("send the CONNECT request");

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
    //# The server SHOULD abort its response stream with the error code
    //# H3_REQUEST_REJECTED.
    let read = tokio::time::timeout(TIMEOUT, recv.read_chunk(64, true))
        .await
        .expect("the server answered the rejected request");
    match read {
        Err(quinn::ReadError::Reset(code)) => assert_eq!(
            code.into_inner(),
            H3_REQUEST_REJECTED,
            "expected H3_REQUEST_REJECTED (0x10b) on the response side, got {:#x}",
            code.into_inner()
        ),
        other => panic!("expected the response side to be reset, got {other:?}"),
    }

    // And the request side is stopped rather than read, so the client is not
    // left writing a body nobody will look at.
    let stopped = tokio::time::timeout(TIMEOUT, send.stopped())
        .await
        .expect("the server stopped the request side")
        .expect("stop code");
    assert_eq!(
        stopped.map(quinn::VarInt::into_inner),
        Some(H3_REQUEST_REJECTED),
        "expected STOP_SENDING with H3_REQUEST_REJECTED (0x10b)"
    );

    // Rejecting a late request does not disturb the tunnel that was already
    // open, which is the whole reason a GOAWAY has an identifier at all.
    held.send_data(Bytes::from_static(b"alive"))
        .await
        .expect("the held tunnel still works");
    assert_eq!(&read_at_least(&mut held, 5).await, b"alive");

    held.finish().expect("finish");
    common::read_to_end(&mut held).await;
    server.wait_until_stopped(STOP_TIMEOUT).await;
}

/// After the GOAWAY, the client stops opening requests of its own accord.
///
/// What this asserts is the *client* side of RFC 9114 §5.2 -- a peer that has
/// seen a GOAWAY takes its new work elsewhere -- plus the fact that the server
/// sends one at all, since the refusal below only starts once the frame has
/// been read off the server's control stream. What the server does with a
/// request that arrives anyway is
/// [`a_request_stream_past_the_goaway_identifier_is_rejected`] above; this test
/// cannot see it, because the client never puts such a request on the wire.
#[tokio::test]
async fn new_requests_are_refused_after_goaway() {
    let mut server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // One tunnel held open, so the connection is still draining and the refusal
    // cannot be confused with the connection simply being gone.
    let mut held = open_tcp_tunnel(&mut client, &target.to_string()).await;

    server.shutdown();

    // The GOAWAY has to reach the client's connection driver first, so poll until
    // a new request is refused rather than assuming it already has been.
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        match client
            .send
            .send_request(connect_request(&target.to_string()))
            .await
        {
            Err(_) => break,
            Ok(mut stream) => {
                // Not yet processed: this stream may still be served or rejected,
                // either is fine. Give the driver a moment and try again.
                let _ =
                    tokio::time::timeout(Duration::from_millis(50), stream.recv_response()).await;
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "new requests were still accepted after GOAWAY"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }

    // Meanwhile the tunnel opened before the signal is untouched.
    held.send_data(Bytes::from_static(b"alive"))
        .await
        .expect("the held tunnel still works");
    assert_eq!(&read_at_least(&mut held, 5).await, b"alive");

    held.finish().expect("finish");
    common::read_to_end(&mut held).await;
    server.wait_until_stopped(STOP_TIMEOUT).await;
}

/// A client that never closes its tunnel must not be able to hold the process
/// open: the grace period expires and the endpoint closes anyway.
#[tokio::test]
async fn the_grace_period_bounds_the_wait() {
    let mut server = TestServer::start_with(&format!("shutdown_grace = 1\n{ALLOW_PRIVATE}")).await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    // Deliberately left open, and deliberately still in use.
    stream
        .send_data(Bytes::from_static(b"keeping this open"))
        .await
        .expect("send");

    server.shutdown();

    // The server stops on its own, one second later, without the tunnel ever
    // being closed by the client.
    server.wait_until_stopped(STOP_TIMEOUT).await;

    // And the client is told, rather than left to time out: the endpoint sends
    // CONNECTION_CLOSE on the way out.
    tokio::time::timeout(TIMEOUT, client.quic.closed())
        .await
        .expect("the client learns the connection is closed");
}

/// With nothing to drain, shutdown does not wait out the grace period.
#[tokio::test]
async fn an_idle_server_stops_promptly() {
    let mut server =
        TestServer::start_with(&format!("shutdown_grace = 300\n{ALLOW_PRIVATE}")).await;

    // A connected but idle client: no tunnels, so nothing to wait for.
    let _client = H3Client::connect(&server).await;

    server.shutdown();
    // Far below the 300s grace period, which would otherwise be an upper bound
    // on how long an idle process takes to stop.
    server.wait_until_stopped(Duration::from_secs(15)).await;
}

/// Shutdown before anything ever connects has to work too — the case a failed
/// deployment hits when it starts and stops the service in quick succession.
#[tokio::test]
async fn a_server_with_no_connections_stops() {
    let mut server = TestServer::start_with("shutdown_grace = 300\n").await;
    server.shutdown();
    server.wait_until_stopped(Duration::from_secs(15)).await;
}
