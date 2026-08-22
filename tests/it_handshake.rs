//! The HTTP/3 handshake is bounded, because the peer decides whether it can
//! finish at all.
//!
//! Opening the three unidirectional streams RFC 9114 §6.2 asks for is not
//! something a server can do on its own: `open_uni` waits for stream credit the
//! peer's transport parameters grant, and a peer may grant none. That is a legal
//! QUIC connection and an impossible HTTP/3 one, and it used to park the
//! connection task forever.
//!
//! The QUIC idle timeout is not the backstop it looks like, which is why this
//! file exists rather than a comment saying the timeout will handle it: the
//! client here answers keep-alives, and every ACK restarts the idle timer. The
//! connection would stay open — holding a `max_connections` slot — for as long
//! as the peer cared to keep its socket open.

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::{
    client_endpoint_with_transport, open_tcp_tunnel, read_at_least, spawn_echo_target, H3Client,
    TestServer, ALLOW_PRIVATE, IMPATIENT, TIMEOUT,
};

/// H3_STREAM_CREATION_ERROR (RFC 9114 §8.1), the code the server hangs up with.
const H3_STREAM_CREATION_ERROR: u64 = 0x103;

/// A client that grants no unidirectional streams must not hold a connection
/// slot indefinitely.
///
/// The keep-alive is the point: without it this would prove nothing, because the
/// 1s idle timeout would close the connection whatever the server did about the
/// handshake.
#[tokio::test]
async fn a_peer_that_permits_no_unidirectional_streams_is_hung_up_on() {
    let server = TestServer::start_with(IMPATIENT).await;

    let mut transport = quinn::TransportConfig::default();
    // A legal QUIC peer that no HTTP/3 server can complete a handshake with:
    // the control stream can never be opened.
    transport.max_concurrent_uni_streams(0u32.into());
    // Far below the server's 1s idle timeout, so the connection is alive and
    // acknowledged throughout and only the handshake bound can end it.
    transport.keep_alive_interval(Some(Duration::from_millis(100)));

    let endpoint = client_endpoint_with_transport(&server.ca, &["h3"], transport);
    let connection = tokio::time::timeout(
        TIMEOUT,
        endpoint
            .connect(server.addr, "localhost")
            .expect("start connecting"),
    )
    .await
    .expect("handshake did not time out")
    .expect("the QUIC handshake itself must succeed");

    // Generous against the server's 1s bound, and far short of forever.
    let error = tokio::time::timeout(Duration::from_secs(5), connection.closed())
        .await
        .expect("the server must not hold the connection open indefinitely");

    match error {
        quinn::ConnectionError::ApplicationClosed(close) => assert_eq!(
            close.error_code.into_inner(),
            H3_STREAM_CREATION_ERROR,
            "the peer must be told which half of the handshake it failed; \
             reason was {:?}",
            String::from_utf8_lossy(&close.reason)
        ),
        // An idle timeout here would mean the keep-alive stopped working and
        // this test stopped testing what it says it does.
        other => panic!("expected the server to close the connection, got {other}"),
    }
}

/// The deadline must not touch a client that behaves, however tight it is.
///
/// Same 1s bound as above: an ordinary handshake on loopback has three orders of
/// magnitude of room, and a tunnel that carries a payload proves the whole
/// connection was built rather than merely accepted.
#[tokio::test]
async fn an_ordinary_client_is_untouched_by_the_deadline() {
    let server = TestServer::start_with(&format!("{IMPATIENT}{ALLOW_PRIVATE}")).await;
    let echo = spawn_echo_target().await;

    let mut client = H3Client::connect(&server).await;
    let mut tunnel = open_tcp_tunnel(&mut client, &echo.to_string()).await;

    tunnel
        .send_data(Bytes::from_static(b"payload"))
        .await
        .expect("send payload");
    assert_eq!(read_at_least(&mut tunnel, 7).await, b"payload");
}
