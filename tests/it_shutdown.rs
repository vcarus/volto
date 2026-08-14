//! M5: graceful shutdown (RFC 9114 §5.2 GOAWAY plus a bounded grace period).
//!
//! The property under test is not "the process exits" but "it exits without
//! cutting anyone off": a tunnel that is mid-transfer when SIGTERM arrives must
//! be allowed to finish, while new work is turned away immediately.

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::{
    connect_request, connect_udp_request, read_at_least, spawn_echo_target, spawn_udp_echo_target,
    H3Client, TestServer, TIMEOUT,
};
use http::StatusCode;

/// Generous upper bound for a shutdown that should take about as long as its
/// grace period. Failing this means the grace period is not being enforced.
const STOP_TIMEOUT: Duration = Duration::from_secs(20);

/// A tunnel that is in use when the signal arrives keeps working, and the server
/// waits for it rather than dropping it.
#[tokio::test]
async fn an_established_tunnel_survives_goaway_and_finishes() {
    let mut server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = client
        .send
        .send_request(connect_request(&target.to_string()))
        .await
        .expect("send CONNECT");
    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("response arrived")
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

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
    // well inside the 30s default grace period.
    stream.finish().await.expect("finish the request stream");
    common::read_to_end(&mut stream).await;

    server.wait_until_stopped(STOP_TIMEOUT).await;
}

/// A UDP session is drained on the same terms as a TCP tunnel.
#[tokio::test]
async fn an_established_udp_session_survives_goaway() {
    let mut server = TestServer::start().await;
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

    let qsid = volto::datagram::quarter_stream_id(stream.id().into_inner());
    server.shutdown();

    // Datagrams still flow: they do not go through the request stream at all, so
    // this is a genuinely separate path from the TCP case above.
    client
        .quic
        .send_datagram(volto::datagram::encode_udp_payload(qsid, b"still here"))
        .expect("send datagram");
    let echoed = tokio::time::timeout(TIMEOUT, client.quic.read_datagram())
        .await
        .expect("the session still works after GOAWAY")
        .expect("datagram");
    let decoded = volto::datagram::decode(echoed).expect("well formed");
    assert_eq!(&decoded.payload[..], b"still here");

    // Closing the stream ends the session, which lets the server finish.
    stream.finish().await.expect("finish the request stream");
    server.wait_until_stopped(STOP_TIMEOUT).await;
}

/// After the GOAWAY, new requests are refused rather than served. The client sees
/// this as a failure to open the request at all, which is the signal RFC 9114
/// §5.2 says it may safely retry elsewhere on.
#[tokio::test]
async fn new_requests_are_refused_after_goaway() {
    let mut server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // One tunnel held open, so the connection is still draining and the refusal
    // cannot be confused with the connection simply being gone.
    let mut held = client
        .send
        .send_request(connect_request(&target.to_string()))
        .await
        .expect("send CONNECT");
    let response = tokio::time::timeout(TIMEOUT, held.recv_response())
        .await
        .expect("response arrived")
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

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

    held.finish().await.expect("finish");
    common::read_to_end(&mut held).await;
    server.wait_until_stopped(STOP_TIMEOUT).await;
}

/// A client that never closes its tunnel must not be able to hold the process
/// open: the grace period expires and the endpoint closes anyway.
#[tokio::test]
async fn the_grace_period_bounds_the_wait() {
    let mut server =
        TestServer::start_with("shutdown_grace = 1\n[security]\nallow_private_networks = true\n")
            .await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = client
        .send
        .send_request(connect_request(&target.to_string()))
        .await
        .expect("send CONNECT");
    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("response arrived")
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

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
        TestServer::start_with("shutdown_grace = 300\n[security]\nallow_private_networks = true\n")
            .await;

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
