//! Hardening: connection cap, authentication-failure cap, and what an
//! unauthenticated peer may make one connection hold.
//!
//! All three are cheap defences against a peer that has proved nothing, and all
//! three are asserted the way the rest of this suite asserts things — by watching
//! what happens on the wire, not by reading counters out of the server.

mod common;

use std::time::Duration;

use bytes::BytesMut;
use common::{
    auth_section, basic_credentials, connect_quic, connect_request, open_tcp_tunnel,
    spawn_echo_target, H3Client, TestServer, ALLOW_PRIVATE, TIMEOUT,
};
use volto::datagram;
use volto::h3api::{FieldValue, Status};

/// HEADERS frame type (RFC 9114 §7.2.2).
const FRAME_HEADERS: u64 = 0x01;

/// H3_EXCESSIVE_LOAD (RFC 9114 §8.1).
const H3_EXCESSIVE_LOAD: u64 = 0x107;

/// H3_REQUEST_CANCELLED (RFC 9114 §8.1).
const H3_REQUEST_CANCELLED: u64 = 0x10c;

/// A 2s idle timeout, which is also how long an answer to a request may take.
///
/// Long enough that a deadline lapsing is a deliberate act rather than a slow
/// machine, and short enough to wait out twice: the connection-level bound of
/// D76 is two of these, so a test can tell one deadline from the other.
const DELIBERATE: &str = "[limits]\nmax_idle_timeout = 2\nkeep_alive_interval = 0\n";

/// A CONNECT attempt with the given credentials, returning the status.
async fn attempt(client: &mut H3Client, authority: &str, password: &str) -> Option<Status> {
    let mut request = connect_request(authority);
    request.fields.append(
        "proxy-authorization",
        FieldValue::parse(basic_credentials("user1", password).as_bytes())?,
    );

    let mut stream = client.send.send_request(request).await.ok()?;
    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .ok()?
        .ok()?;
    Some(response.status)
}

/// Past the cap, new connections are refused at the QUIC layer rather than
/// accepted and served.
#[tokio::test]
async fn the_connection_cap_refuses_further_connections() {
    let server =
        TestServer::start_with(&format!("[limits]\nmax_connections = 2\n{ALLOW_PRIVATE}")).await;
    let target = spawn_echo_target().await;

    // Two connections, both usable.
    let mut first = H3Client::connect(&server).await;
    let mut second = H3Client::connect(&server).await;
    for client in [&mut first, &mut second] {
        let _stream = open_tcp_tunnel(client, &target.to_string()).await;
    }

    // The third is refused during the handshake.
    let endpoint = common::client_endpoint(&server.ca, &["h3"]);
    let result = common::finish_connect(&endpoint, server.addr).await;

    assert!(
        result.is_err(),
        "a connection past the cap must be refused, got {result:?}"
    );

    // And the ones already established are untouched by the refusal.
    let mut stream = first
        .send
        .send_request(connect_request(&target.to_string()))
        .await
        .expect("the existing connection must still work");
    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("response arrived")
        .expect("response");
    assert_eq!(response.status, Status::OK);
}

/// A slot freed by a closed connection becomes available again.
#[tokio::test]
async fn a_closed_connection_frees_its_slot() {
    let server =
        TestServer::start_with(&format!("[limits]\nmax_connections = 1\n{ALLOW_PRIVATE}")).await;
    let target = spawn_echo_target().await;

    let mut client = H3Client::connect(&server).await;
    let stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    // Dropping both closes the QUIC connection, which ends the server-side task.
    drop(stream);
    drop(client);

    // The server reaps the finished connection task, so a new connection fits.
    // Retried because the reap happens a moment after the peer goes away.
    for attempt in 0..40 {
        let endpoint = common::client_endpoint(&server.ca, &["h3"]);
        let result = common::finish_connect(&endpoint, server.addr).await;

        if result.is_ok() {
            return;
        }
        assert!(attempt < 39, "the freed slot was never reused: {result:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Repeated bad credentials cost a handshake: the connection is closed once the
/// budget is spent, instead of allowing unlimited guesses down one connection.
#[tokio::test]
async fn repeated_authentication_failures_close_the_connection() {
    let server = TestServer::start_with(&format!(
        "{}[security]\nallow_private_networks = true\nmax_auth_failures = 3\n",
        auth_section(&[("user1", "s3cret")])
    ))
    .await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // The first two failures are answered normally with a 407.
    for i in 0..2 {
        assert_eq!(
            attempt(&mut client, &target.to_string(), "wrong").await,
            Some(Status::PROXY_AUTHENTICATION_REQUIRED),
            "attempt {i} should still be answered"
        );
    }

    // The third exhausts the budget. Whether it is answered before the close
    // lands is a race, so what is asserted is the outcome: the connection goes.
    let _ = attempt(&mut client, &target.to_string(), "wrong").await;

    tokio::time::timeout(TIMEOUT, client.quic.closed())
        .await
        .expect("the connection must be closed after the failure budget is spent");
}

/// A peer that will not read its 407 must still spend the budget.
///
/// The failure is counted before the answer goes out, and the answer itself is
/// bounded: a peer that grants a window smaller than a 407 used to leave the
/// count on the unreachable side of a write that never completed, which turned
/// "N guesses cost a handshake" into "guess once per stream, forever" — and left
/// a parked task holding the whole decoded request behind each of them
/// (review H1/H2).
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_never_reads_its_407_still_spends_its_budget() {
    let server = TestServer::start_with(&format!(
        "{DELIBERATE}{}[security]\nmax_auth_failures = 3\n",
        auth_section(&[("user1", "s3cret")])
    ))
    .await;
    let mut client = H3Client::connect_with_transport(&server, deaf_transport()).await;

    // Eight guesses, none of them read: `send_request` returns the stream and
    // nothing here ever asks it for the response, so every 407 is stuck on the
    // window the client refused to grow.
    let mut unread = Vec::new();
    for _ in 0..8 {
        let mut request = connect_request("192.0.2.1:443");
        request.fields.append(
            "proxy-authorization",
            FieldValue::parse(basic_credentials("user1", "wrong").as_bytes()).expect("credentials"),
        );
        unread.push(
            client
                .send
                .send_request(request)
                .await
                .expect("send a guess"),
        );
    }

    let error = tokio::time::timeout(TIMEOUT, client.quic.closed())
        .await
        .expect("a peer that will not read its answers must still run out of guesses");

    match error {
        quinn::ConnectionError::ApplicationClosed(close) => assert_eq!(
            close.error_code.into_inner(),
            volto::h3api::AUTH_FAILURE_LIMIT_CODE.into_inner(),
            "the budget must be what closed this connection, not the D76 bound; \
             reason was {:?}",
            String::from_utf8_lossy(&close.reason)
        ),
        other => panic!("expected an application close, got {other}"),
    }
}

/// A refusal the peer will not take is abandoned, and only that stream suffers.
///
/// The request task ends either way; what is asserted here is the signal it
/// leaves, because that is what returns the stream. RFC 9114 §8.1's
/// H3_REQUEST_CANCELLED covers "the request or its response (including pushed
/// response) is cancelled", and a reset is the only end that reaches a peer
/// granting no window at all — a FIN would wait behind bytes that cannot be
/// sent (review H1).
#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_the_peer_will_not_take_is_reset() {
    // No `[auth]` section, so the first request authenticates and the D76 bound
    // on the connection is out of the way: what is under test is the stream.
    let server = TestServer::start_with(DELIBERATE).await;
    let mut client = H3Client::connect_with_transport(&server, deaf_transport()).await;

    // Port 25 is on the default deny list and is checked before the resolver
    // runs, so the 403 arrives without touching the network — and it carries an
    // RFC 9209 `Proxy-Status` field, which puts it well past the window.
    let mut stream = client
        .send
        .send_request(connect_request("192.0.2.1:25"))
        .await
        .expect("send a request that will be refused");

    // Past the server's idle timeout, without reading a byte: reading is what
    // would grow the window and let the answer through.
    tokio::time::sleep(Duration::from_millis(3_000)).await;

    let error = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("the server must not wait for a window that is not coming")
        .expect_err("an answer the peer would not take must end in a reset");
    common::assert_peer_reset(&error, H3_REQUEST_CANCELLED);

    // One abandoned answer is not a reason to drop everything else.
    assert!(
        client.quic.close_reason().is_none(),
        "the connection must survive a stream it could not answer"
    );
}

/// Transport parameters for a peer that takes an answer and then stops reading.
///
/// 24 bytes is under every response this server sends and over the 19-byte
/// SETTINGS frame the handshake needs, so the connection is built normally and
/// only the answers are stuck. The keep-alive is what makes the test about the
/// application's deadlines: with it, the transport's own idle timeout can never
/// be the thing that ends anything.
fn deaf_transport() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(24u32.into());
    transport.keep_alive_interval(Some(Duration::from_millis(100)));
    transport
}

/// Correct credentials are unaffected by the cap, however many times they are
/// used — the counter must only move on failure.
#[tokio::test]
async fn successful_authentication_does_not_consume_the_budget() {
    let server = TestServer::start_with(&format!(
        "{}[security]\nallow_private_networks = true\nmax_auth_failures = 2\n",
        auth_section(&[("user1", "s3cret")])
    ))
    .await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    for i in 0..6 {
        assert_eq!(
            attempt(&mut client, &target.to_string(), "s3cret").await,
            Some(Status::OK),
            "request {i} with correct credentials must succeed"
        );
    }

    // Still up after six successes, with a budget of two failures.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), client.quic.closed())
            .await
            .is_err(),
        "a working client must not be disconnected"
    );
}

/// Zero disables the cap, for the operator who would rather fail2ban handle it.
#[tokio::test]
async fn a_zero_budget_disables_the_cap() {
    let server = TestServer::start_with(&format!(
        "{}[security]\nallow_private_networks = true\nmax_auth_failures = 0\n",
        auth_section(&[("user1", "s3cret")])
    ))
    .await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    for i in 0..8 {
        assert_eq!(
            attempt(&mut client, &target.to_string(), "wrong").await,
            Some(Status::PROXY_AUTHENTICATION_REQUIRED),
            "failure {i} must still be answered when the cap is off"
        );
    }

    assert!(
        tokio::time::timeout(Duration::from_millis(200), client.quic.closed())
            .await
            .is_err(),
        "with the cap disabled the connection must stay up"
    );
}

/// Request streams enough to run one connection past its buffering budget (D77).
///
/// Each of them announces the largest field section the server advertises, which
/// is also the most it will buffer for a single frame, so the budget divides into
/// exactly that many of them and the next one is the one that cannot fit. The
/// spare few are there because the peer does not have to get the arithmetic right
/// for the bound to hold, and because the server is entitled to be holding
/// nothing at all by the time the last of them arrives.
fn streams_past_the_budget() -> usize {
    volto::h3::HEADERS_BUFFER_BUDGET / volto::h3::MAX_FIELD_SECTION_SIZE as usize + 4
}

/// Opens a request stream, announces a full-sized HEADERS frame on it and sends
/// a single byte of it.
///
/// One byte rather than none so that the stream is genuinely mid-frame rather
/// than merely announced, and both halves are handed back rather than dropped:
/// dropping a [`quinn::SendStream`] finishes it, which would tell the server the
/// frame it is holding will never be completed.
async fn announce_oversized_headers(
    connection: &quinn::Connection,
) -> (quinn::SendStream, quinn::RecvStream) {
    let (mut send, recv) = connection.open_bi().await.expect("open a request stream");

    let mut frame = BytesMut::new();
    datagram::put_varint(&mut frame, FRAME_HEADERS);
    datagram::put_varint(&mut frame, volto::h3::MAX_FIELD_SECTION_SIZE);
    frame.extend_from_slice(b"\x00");
    send.write_all(&frame)
        .await
        .expect("announce a HEADERS frame");

    (send, recv)
}

/// Every frame here is within what the server will buffer for one frame, and no
/// stream breaks a rule of its own — so the bound that has to catch this is the
/// one on their sum, and the peer at fault is the connection (D77).
#[tokio::test(flavor = "multi_thread")]
async fn headers_buffered_across_a_connection_are_bounded() {
    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    // Held for the life of the test: a finished or reset stream would give its
    // share of the budget back, which is precisely what this must not rely on.
    let mut streams = Vec::new();
    for _ in 0..streams_past_the_budget() {
        streams.push(announce_oversized_headers(&connection).await);
    }

    let error = tokio::time::timeout(TIMEOUT, connection.closed())
        .await
        .expect("a connection past the buffering budget must be closed");

    match error {
        quinn::ConnectionError::ApplicationClosed(close) => {
            let reason = String::from_utf8_lossy(&close.reason);
            assert_eq!(
                close.error_code.into_inner(),
                H3_EXCESSIVE_LOAD,
                "the peer must be told which rule it broke; reason was {reason:?}"
            );
            assert!(
                reason.contains("unfinished frames"),
                "the reason {reason:?} does not say what the connection was holding"
            );
        }
        other => panic!("expected an application close, got {other}"),
    }
}

/// The other half of the bound: a client that finishes what it starts is never
/// touched by it, however many requests it has in flight.
///
/// Same number of streams as the test above, so the two differ in exactly one
/// thing — whether the HEADERS frames are complete.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_of_complete_requests_never_reaches_the_budget() {
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut tunnels = Vec::with_capacity(streams_past_the_budget());
    for _ in 0..streams_past_the_budget() {
        tunnels.push(open_tcp_tunnel(&mut client, &target.to_string()).await);
    }

    assert!(
        tokio::time::timeout(Duration::from_millis(200), client.quic.closed())
            .await
            .is_err(),
        "a client whose requests all arrived in full must not be disconnected"
    );
}
