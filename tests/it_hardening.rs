//! Hardening: connection cap, authentication-failure cap, and what an
//! unauthenticated peer may make one connection hold.
//!
//! All three are cheap defences against a peer that has proved nothing, and all
//! three are asserted the way the rest of this suite asserts things — by watching
//! what happens on the wire, not by reading counters out of the server.

mod common;

use std::time::Duration;

use bytes::BytesMut;
use common::rawstream::{assert_closed_with, authenticate, read_frame, status_of, stopped_code};
use common::{
    auth_section, authorized_connect, connect_quic, connect_request, open_tcp_tunnel,
    spawn_echo_target, H3Client, TestServer, ALLOW_PRIVATE, TIMEOUT,
};
use volto::datagram;
use volto::h3api::{Request, Status};

/// HEADERS frame type (RFC 9114 §7.2.2).
const FRAME_HEADERS: u64 = 0x01;

/// H3_EXCESSIVE_LOAD (RFC 9114 §8.1).
const H3_EXCESSIVE_LOAD: u64 = 0x107;

/// H3_REQUEST_CANCELLED (RFC 9114 §8.1).
const H3_REQUEST_CANCELLED: u64 = 0x10c;

/// H3_STREAM_CREATION_ERROR (RFC 9114 §8.1).
const H3_STREAM_CREATION_ERROR: u32 = 0x103;

/// A 2s idle timeout, which is also how long an answer to a request may take.
///
/// Long enough that a deadline lapsing is a deliberate act rather than a slow
/// machine, and short enough to wait out twice: the connection-level bound of
/// D76 is two of these, so a test can tell one deadline from the other.
const DELIBERATE: &str = "[limits]\nmax_idle_timeout = 2\nkeep_alive_interval = 0\n";

/// A CONNECT attempt as `user1` with the given password, returning the status.
async fn attempt(client: &mut H3Client, authority: &str, password: &str) -> Option<Status> {
    attempt_as(client, authority, "user1", password).await
}

/// [`attempt`] under a user-id of the caller's choosing.
///
/// Which user a failure names is what the budget is charged against, so a test
/// about that has to be able to name a second one.
async fn attempt_as(
    client: &mut H3Client,
    authority: &str,
    username: &str,
    password: &str,
) -> Option<Status> {
    attempt_with(client, authorized_connect(authority, username, password)).await
}

/// [`attempt`] with no credentials field at all.
///
/// The request that forgot its header rather than the one that guessed: it fails
/// authentication like the others, but names nobody for the failure to be
/// charged to.
async fn attempt_anonymously(client: &mut H3Client, authority: &str) -> Option<Status> {
    attempt_with(client, connect_request(authority)).await
}

/// Sends `request` and returns the status it is answered with, if it is answered.
async fn attempt_with(client: &mut H3Client, request: Request) -> Option<Status> {
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

/// `max_connections = 0` means no cap: everybody is admitted and nobody is
/// evicted.
///
/// The accept loop guards the whole roster comparison with `max_connections > 0`
/// for this, and the guard had nothing holding it: without it, zero would be the
/// tightest cap there is rather than no cap at all -- every roster is at or above
/// zero -- and an operator who asked for no limit would get a server that refuses
/// every connection it is offered.
///
/// Three unauthenticated peers, which is one more than the smallest cap that
/// would let all three coexist, and none of them is disturbed by the next.
#[tokio::test]
async fn a_zero_connection_cap_admits_everyone_and_evicts_nobody() {
    let server =
        TestServer::start_with(&format!("[limits]\nmax_connections = 0\n{ALLOW_PRIVATE}")).await;
    let target = spawn_echo_target().await;

    let first = H3Client::connect(&server).await;
    let second = H3Client::connect(&server).await;
    let mut third = H3Client::connect(&server).await;

    // None of the earlier ones lost its place to a later one. At any cap of one
    // or two, the oldest of these would have been evicted by now.
    for (name, client) in [("first", &first), ("second", &second)] {
        assert!(
            tokio::time::timeout(Duration::from_millis(200), client.quic.closed())
                .await
                .is_err(),
            "the {name} connection must not have been evicted"
        );
    }

    // And the newest is a working connection rather than a refused one.
    let _stream = open_tcp_tunnel(&mut third, &target.to_string()).await;
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

/// Failures that name nobody spend the budget too, on their own.
///
/// The three buckets are summed for the cap, and only this one is reachable
/// without ever naming a user-id: a peer that sends no credentials field at all
/// costs the server a decoded request and a 407 apiece, exactly as a guess does,
/// so a bucket left out of that sum would be free guessing down one connection.
/// The tests around this one always reach the cap through a *named* failure, so
/// the credential-less bucket could be dropped from the total with the whole
/// suite still green.
#[tokio::test]
async fn credential_less_failures_alone_close_the_connection() {
    let server = TestServer::start_with(&format!(
        "{}[security]\nallow_private_networks = true\nmax_auth_failures = 3\n",
        auth_section(&[("user1", "s3cret")])
    ))
    .await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // The first two are answered normally: no credentials is an authentication
    // failure like any other, and the 407 says so.
    for i in 0..2 {
        assert_eq!(
            attempt_anonymously(&mut client, &target.to_string()).await,
            Some(Status::PROXY_AUTHENTICATION_REQUIRED),
            "credential-less attempt {i} should still be answered"
        );
    }

    // The third exhausts the budget. Whether it is answered before the close
    // lands is a race, so what is asserted is the outcome: the connection goes.
    let _ = attempt_anonymously(&mut client, &target.to_string()).await;

    tokio::time::timeout(TIMEOUT, client.quic.closed())
        .await
        .expect("credential-less failures must count against the failure budget");
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
    // window the client refused to grow. The third guess is the one that ends
    // the connection, and it does so at once, so a later `send_request` may
    // already find it closed -- that is the behaviour under test, not a failure.
    let mut unread = Vec::new();
    for attempt in 0..8 {
        let request = authorized_connect("192.0.2.1:443", "user1", "wrong");
        match client.send.send_request(request).await {
            Ok(stream) => unread.push(stream),
            Err(error) => {
                assert!(attempt >= 3, "guess {attempt} was refused early: {error}");
                break;
            }
        }
    }

    let started = std::time::Instant::now();
    // The code is the assertion: what ends this connection has to be the failure
    // budget rather than the D76 bound, and the two close with different codes.
    assert_closed_with(
        &client.quic,
        volto::h3api::AUTH_FAILURE_LIMIT_CODE.into_inner(),
        TIMEOUT,
    )
    .await;

    // The close is decided before the 407 is written, so it does not wait on
    // the bounded write: the last guess ends the connection at once, not one
    // idle timeout (2 s here) later.
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the close must not wait behind the unanswerable 407; took {:?}",
        started.elapsed()
    );
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

/// The 431 the codec answers with is bounded like every other refusal.
///
/// It is written before any tunnel exists and by a different piece of code than
/// `tunnel::refuse_with`, so it needs the deadline said separately: a peer that
/// grants no room for the answer would otherwise park a server task on a window
/// that is not coming, holding the request it is refusing (review H1).
#[tokio::test(flavor = "multi_thread")]
async fn a_431_the_peer_will_not_take_is_reset() {
    let server = TestServer::start_with(DELIBERATE).await;
    let endpoint =
        common::client_endpoint_with_transport(&server.ca, &["h3"], windowless_transport());
    let connection = common::finish_connect(&endpoint, server.addr)
        .await
        .expect("handshake");

    // Twice the advertised limit, declared in the frame header: the server
    // refuses it from the length alone, so this is the 431 arm of the codec
    // rather than anything a tunnel decides.
    let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
    let mut frame = BytesMut::new();
    datagram::put_varint(&mut frame, FRAME_HEADERS);
    datagram::put_varint(&mut frame, 2 * volto::h3::MAX_FIELD_SECTION_SIZE);
    frame.extend_from_slice(b"\x00");
    send.write_all(&frame)
        .await
        .expect("announce an oversized field section");

    // Waited for rather than slept past: `received_reset` observes the reset
    // without granting the flow-control credit an ordinary read would, which is
    // the whole reason a window this small is the setup.
    let reset = tokio::time::timeout(TIMEOUT, recv.received_reset())
        .await
        .expect("the server must not wait for a window that is not coming")
        .expect("an answer the peer would not take must end in a reset");
    assert_eq!(
        reset.map(quinn::VarInt::into_inner),
        Some(H3_REQUEST_CANCELLED),
        "an abandoned answer is a cancelled request"
    );

    // One abandoned answer is not a reason to drop everything else.
    assert!(
        connection.close_reason().is_none(),
        "the connection must survive a stream it could not answer"
    );
}

/// Transport parameters for a peer with no room for an answer at all.
///
/// A ten-byte 431 fits in any per-stream window big enough for the server's own
/// 19-byte SETTINGS frame, so what has to be exhausted here is the *connection*
/// window. Nothing in this test reads the server's control stream, so those 19
/// bytes stay charged to that window for the whole of it and leave less than a
/// response behind them.
fn windowless_transport() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.receive_window(24u32.into());
    transport.stream_receive_window(24u32.into());
    transport.keep_alive_interval(Some(Duration::from_millis(100)));
    transport
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

/// A success clears the failures behind it, so they cannot add up over hours.
///
/// The cap is meant to price guessing, and a guesser never gets a success in
/// between. A long-lived client does: a password rotated at one end, an app that
/// omits the header on some request, and the count creeps to the cap over hours
/// — at which point the connection goes, every live tunnel with it. Two failures
/// with a success between them are exactly that shape at `max_auth_failures = 2`.
#[tokio::test]
async fn a_success_clears_the_failures_before_it() {
    let server = TestServer::start_with(&format!(
        "{}[security]\nallow_private_networks = true\nmax_auth_failures = 2\n",
        auth_section(&[("user1", "s3cret")])
    ))
    .await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    assert_eq!(
        attempt(&mut client, &target.to_string(), "wrong").await,
        Some(Status::PROXY_AUTHENTICATION_REQUIRED),
        "the first failure must be answered"
    );
    assert_eq!(
        attempt(&mut client, &target.to_string(), "s3cret").await,
        Some(Status::OK),
        "the credentials in between are the right ones"
    );
    assert_eq!(
        attempt(&mut client, &target.to_string(), "wrong").await,
        Some(Status::PROXY_AUTHENTICATION_REQUIRED),
        "this is the first failure since the success, not the second of two"
    );

    // The connection is still there, and still serving.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), client.quic.closed())
            .await
            .is_err(),
        "two failures with a success between them must not spend the budget"
    );
    assert_eq!(
        attempt(&mut client, &target.to_string(), "s3cret").await,
        Some(Status::OK),
        "and the client must still be able to open a tunnel"
    );
}

/// A success clears only the failures charged to the user it succeeded as.
///
/// `auth.users` is a list, so "a success clears the failures behind it" hands a
/// peer holding one valid credential a way out of the cap: guess at user2, spend
/// a good request as user1, guess again, and the count never reaches the limit
/// however long it goes on. The same three requests as
/// `a_success_clears_the_failures_before_it`, with the failures aimed at a user
/// the success is not for — and the opposite outcome.
#[tokio::test]
async fn a_success_does_not_clear_another_users_failures() {
    let server = TestServer::start_with(&format!(
        "{}[security]\nallow_private_networks = true\nmax_auth_failures = 2\n",
        auth_section(&[("user1", "s3cret"), ("user2", "hunter2")])
    ))
    .await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    assert_eq!(
        attempt_as(&mut client, &target.to_string(), "user2", "wrong").await,
        Some(Status::PROXY_AUTHENTICATION_REQUIRED),
        "the first guess at the second user must be answered"
    );
    // The credential the peer actually holds, used exactly as a working client
    // would use it.
    assert_eq!(
        attempt_as(&mut client, &target.to_string(), "user1", "s3cret").await,
        Some(Status::OK),
        "the peer's own credentials still work"
    );

    // The second guess at user2 is the second failure charged to user2, so it
    // spends the budget. Whether the 407 lands before the close is a race, as it
    // is in `repeated_authentication_failures_close_the_connection`, so the
    // outcome is what is asserted.
    let _ = attempt_as(&mut client, &target.to_string(), "user2", "wrong-again").await;

    tokio::time::timeout(TIMEOUT, client.quic.closed())
        .await
        .expect("a success as one user must not buy another user's guesses a reprieve");
}

/// The interleave that a single run of failures could not stop.
///
/// A peer holding one valid credential opens every cycle with a deliberate
/// failure as *itself*. With one run charged to the first failure that named
/// somebody, that claimed the run for a name the peer can clear at will, so the
/// success at the end of the cycle wiped the guesses at the second user out with
/// it -- measured against that version at `max_auth_failures = 5`: eight rounds,
/// twenty-four guesses, connection never closed.
///
/// With a bucket per user-id the success clears the peer's own and nothing else,
/// so the guesses stand and the *total* reaches the cap in the second round.
#[tokio::test]
async fn an_interleaved_cycle_of_guesses_still_reaches_the_cap() {
    let server = TestServer::start_with(&format!(
        "{}[security]\nallow_private_networks = true\nmax_auth_failures = 5\n",
        auth_section(&[("user1", "s3cret"), ("user2", "hunter2")])
    ))
    .await;
    let target = spawn_echo_target().await;
    let authority = target.to_string();
    let mut client = H3Client::connect(&server).await;

    // Round one, exactly as the attack runs it: the failure that used to claim
    // the run, three guesses at the other user, then the good request. Totals of
    // 1, 2, 3, 4 -- and 3 once the success has cleared user1's bucket.
    assert_eq!(
        attempt_as(&mut client, &authority, "user1", "wrong").await,
        Some(Status::PROXY_AUTHENTICATION_REQUIRED),
        "the failure that opens the cycle is answered like any other"
    );
    for guess in 0..3 {
        assert_eq!(
            attempt_as(&mut client, &authority, "user2", &format!("guess-{guess}")).await,
            Some(Status::PROXY_AUTHENTICATION_REQUIRED),
            "guess {guess} is inside the budget and must be answered"
        );
    }
    assert_eq!(
        attempt_as(&mut client, &authority, "user1", "s3cret").await,
        Some(Status::OK),
        "the peer's own credentials still work"
    );

    // Round two. The total is at three, so the fourth failure is still answered
    // and the fifth is the whole budget.
    assert_eq!(
        attempt_as(&mut client, &authority, "user1", "wrong").await,
        Some(Status::PROXY_AUTHENTICATION_REQUIRED),
        "the fourth failure of the connection is one short of the cap"
    );

    // The request that brings the total to five. Whether its 407 lands before
    // the close is a race, as it is in the tests above, so the outcome is what
    // is asserted.
    let _ = attempt_as(&mut client, &authority, "user2", "guess-3").await;

    tokio::time::timeout(TIMEOUT, client.quic.closed())
        .await
        .expect("a success as one user must not buy a second user's guesses another round");
}

/// A guess at a user-id nobody has is never cleared by anything.
///
/// Succeeding as a user that does not exist is not a thing that can happen, so a
/// success says nothing about such a guess and clears none of them. That bucket
/// is where a scan for user-ids lands, and it is the one a peer with a valid
/// credential cannot drain.
///
/// Two invented names either side of a success, at `max_auth_failures = 5`: the
/// fifth guess is the fifth failure whatever the success did.
#[tokio::test]
async fn a_success_never_clears_a_guess_at_a_user_that_does_not_exist() {
    let server = TestServer::start_with(&format!(
        "{}[security]\nallow_private_networks = true\nmax_auth_failures = 5\n",
        auth_section(&[("user1", "s3cret")])
    ))
    .await;
    let target = spawn_echo_target().await;
    let authority = target.to_string();
    let mut client = H3Client::connect(&server).await;

    for guess in 0..2 {
        assert_eq!(
            attempt_as(
                &mut client,
                &authority,
                "mallory",
                &format!("guess-{guess}")
            )
            .await,
            Some(Status::PROXY_AUTHENTICATION_REQUIRED),
            "a guess at an unconfigured name is answered like any other"
        );
    }
    assert_eq!(
        attempt_as(&mut client, &authority, "user1", "s3cret").await,
        Some(Status::OK),
        "the peer's own credentials still work"
    );

    // A second invented name, sharing the one bucket the success did not reach:
    // the totals are three and four.
    for guess in 0..2 {
        assert_eq!(
            attempt_as(&mut client, &authority, "eve", &format!("guess-{guess}")).await,
            Some(Status::PROXY_AUTHENTICATION_REQUIRED),
            "the budget must still hold two more failures"
        );
    }

    let _ = attempt_as(&mut client, &authority, "eve", "guess-2").await;

    tokio::time::timeout(TIMEOUT, client.quic.closed())
        .await
        .expect("guesses at a user that does not exist must survive a success as one that does");
}

/// A success clears the failures that named nobody, and only those.
///
/// The credential-less request is the benign case the clearing exists for -- the
/// app that dropped its header -- and any success answers for it. What must not
/// travel with it is a guess: that names somebody, so it is charged to that
/// name's bucket and stays there however many credential-less requests are sent
/// around it.
///
/// Five requests at `max_auth_failures = 3` pin both halves. If the success left
/// the credential-less failure standing, the fourth request would be the third
/// failure and the connection would go one request early; if it cleared the
/// guesses too, the fifth would be the second and it would never go at all.
#[tokio::test]
async fn a_success_clears_credential_less_failures_and_nothing_else() {
    let server = TestServer::start_with(&format!(
        "{}[security]\nallow_private_networks = true\nmax_auth_failures = 3\n",
        auth_section(&[("user1", "s3cret"), ("user2", "hunter2")])
    ))
    .await;
    let target = spawn_echo_target().await;
    let authority = target.to_string();
    let mut client = H3Client::connect(&server).await;

    assert_eq!(
        attempt_anonymously(&mut client, &authority).await,
        Some(Status::PROXY_AUTHENTICATION_REQUIRED),
        "a request with no credentials is answered like any other failure"
    );
    assert_eq!(
        attempt_as(&mut client, &authority, "user2", "wrong").await,
        Some(Status::PROXY_AUTHENTICATION_REQUIRED),
        "the guess beside it is charged to the name it guessed at"
    );
    assert_eq!(
        attempt_as(&mut client, &authority, "user1", "s3cret").await,
        Some(Status::OK),
        "the peer's own credentials still work"
    );
    assert_eq!(
        attempt_as(&mut client, &authority, "user2", "wrong-again").await,
        Some(Status::PROXY_AUTHENTICATION_REQUIRED),
        "with the credential-less failure cleared, this is the second of three"
    );

    // The third failure still standing against user2, so it spends the budget.
    // As in the tests above, whether the 407 lands before the close is a race.
    let _ = attempt_as(&mut client, &authority, "user2", "wrong-once-more").await;

    tokio::time::timeout(TIMEOUT, client.quic.closed())
        .await
        .expect("a success must not clear a guess along with the request that named nobody");
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

/// A unidirectional stream that never says what it is costs one stream, not the
/// connection.
///
/// Reading the stream type is the one wait in the HTTP/3 layer with no protocol
/// answer behind it: until the varint arrives there is nothing to say about the
/// stream at all. A peer that opens streams and writes half a varint on each
/// used to park a task apiece for the life of the connection, and the transport
/// could not end it either, since the keep-alive here is answered by the
/// client's own stack (review L3).
///
/// The bound is per stream and so is the answer. The 2s deadline is
/// `DELIBERATE`'s idle timeout, and the connection is still serving requests
/// afterwards.
#[tokio::test]
async fn a_unidirectional_stream_that_never_names_its_type_is_abandoned() {
    let server = TestServer::start_with(&format!("{DELIBERATE}{ALLOW_PRIVATE}")).await;
    let target = spawn_echo_target().await;

    let mut transport = quinn::TransportConfig::default();
    // `DELIBERATE` switches the server's keep-alive off, so the client supplies
    // one: without it the transport would close the connection at about the
    // moment the deadline fires and this would prove nothing.
    transport.keep_alive_interval(Some(Duration::from_millis(200)));
    let mut client = H3Client::connect_with_transport(&server, transport).await;

    let mut stalled = client
        .quic
        .open_uni()
        .await
        .expect("open a unidirectional stream");
    // 0x40 opens a two-byte varint (RFC 9000 §16), so the type is one byte short
    // of complete and the server is left reading for the rest of it.
    stalled
        .write_all(&[0x40])
        .await
        .expect("send half a stream type");

    let stopped = tokio::time::timeout(TIMEOUT, stalled.stopped())
        .await
        .expect("the server must not read for a stream type indefinitely")
        .expect("the stalled stream must be stopped, not broken");
    assert_eq!(
        stopped,
        Some(quinn::VarInt::from_u32(H3_STREAM_CREATION_ERROR)),
        "a stream that never declared itself is aborted the way an unknown one is"
    );

    assert!(
        client.quic.close_reason().is_none(),
        "abandoning one unidirectional stream must not end the connection"
    );
    // And it is still a working connection, not merely an unclosed one.
    let _tunnel = open_tcp_tunnel(&mut client, &target.to_string()).await;
}

/// Field sections of the largest advertised size one connection may hold
/// half-received at once (D77).
///
/// The whole of the bound, and written out rather than derived: dividing
/// `HEADERS_BUFFER_BUDGET` by `MAX_FIELD_SECTION_SIZE` is how the value was
/// chosen, so a change to either of them belongs in a test that says what the
/// number became.
const FULL_SIZED_FRAMES_THAT_FIT: usize = 16;

/// Request streams enough to run one connection past its buffering budget (D77).
///
/// Each of them announces the largest field section the server advertises, which
/// is also the most it will buffer for a single frame, so the budget divides into
/// exactly [`FULL_SIZED_FRAMES_THAT_FIT`] of them and the next one is the one
/// that cannot fit. The spare few are what makes the count of refusals exact
/// without the test having to know which stream the server's tasks reach first:
/// not one of these frames is ever completed, so every one past the budget is
/// refused whatever order they arrive in.
fn streams_past_the_budget() -> usize {
    FULL_SIZED_FRAMES_THAT_FIT + 4
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
/// one on their sum, and what it catches is the request rather than the
/// connection carrying it (D77).
///
/// Authenticated first, because the budget is now only *reachable* there. An
/// unauthenticated connection is held to `quic::INITIAL_BIDI_STREAMS` request
/// streams at once, and sixteen full-sized field sections are exactly the
/// budget — so a peer that has proved nothing can meet it and never overshoot
/// it, and this test's twenty streams cannot all be open. That is the clamp
/// doing D77's job before D77 is asked, not D77 becoming untestable: what still
/// has to hold is the budget on a connection with the configured 1024 streams
/// to spend, which is what this now measures.
#[tokio::test(flavor = "multi_thread")]
async fn headers_buffered_across_a_connection_are_bounded() {
    let server = TestServer::start().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    // No `[auth]` users on this server, so any completed request opens the
    // door. It costs the budget nothing: the frame it charges is complete
    // before the announcements below start.
    authenticate(&connection, None).await;

    assert_eq!(
        volto::h3::HEADERS_BUFFER_BUDGET / volto::h3::MAX_FIELD_SECTION_SIZE as usize,
        FULL_SIZED_FRAMES_THAT_FIT,
        "the budget is a number of full-sized frames, and the arithmetic below \
         is written in terms of that number"
    );

    // Every stream is held for the life of the test: a finished or reset one
    // would give its share of the budget back, which is precisely what this must
    // not rely on. Which of them is refused is up to the order the server's
    // tasks reach them in, so all of them are read at once and only the count is
    // asserted.
    let (refusals, mut refused) = tokio::sync::mpsc::channel(streams_past_the_budget());
    for _ in 0..streams_past_the_budget() {
        let (send, mut recv) = announce_oversized_headers(&connection).await;
        let refusals = refusals.clone();
        tokio::spawn(async move {
            // The sending half is parked here rather than dropped: dropping it
            // finishes the stream, which would tell the server the frame it is
            // holding will never be completed.
            let _send = send;
            if let Ok(response) = recv.read_to_end(4096).await {
                let _ = refusals.send(response).await;
            }
        });
    }
    drop(refusals);

    for _ in FULL_SIZED_FRAMES_THAT_FIT..streams_past_the_budget() {
        let response = tokio::time::timeout(TIMEOUT, refused.recv())
            .await
            .expect("a stream past the buffering budget must be refused")
            .expect("the refusals arrive on live streams");
        assert_eq!(
            status_of_response(&response),
            "431",
            "a request this connection cannot hold is refused as a request"
        );
    }

    assert!(
        tokio::time::timeout(Duration::from_millis(200), refused.recv())
            .await
            .is_err(),
        "only the streams the budget could not hold may be refused"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), connection.closed())
            .await
            .is_err(),
        "a request the connection cannot hold must not cost it the connection"
    );
}

/// The other half of the bound: a client that finishes what it starts, one
/// request at a time, is never anywhere near it.
///
/// Same number of streams as the test above, so the two differ in exactly one
/// thing — whether the HEADERS frames are complete. What a client with many
/// full-sized requests genuinely in flight meets is the test below this one.
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

/// A CONNECT request padded to the largest field section this server advertises.
///
/// Legal on both of the counts that bound one, which is what makes it the shape
/// this bound has to be judged on: the RFC 9114 §4.2.2 size — name plus value
/// plus 32 bytes a field — is exactly `SETTINGS_MAX_FIELD_SECTION_SIZE`, and the
/// encoded frame is smaller still, since the formula charges 32 bytes a field
/// that no encoding of it pays. A peer sending sixteen of these at once has
/// broken no rule about any one of them.
fn full_sized_connect_section(authority: &str) -> BytesMut {
    /// A field name a proxy has no opinion about, so only its size matters.
    const PADDING: &[u8] = b"x-padding";

    let mut fields: Vec<(&[u8], &[u8])> = vec![
        (b":method", b"CONNECT"),
        (b":authority", authority.as_bytes()),
    ];
    let named: usize = fields
        .iter()
        .map(|(name, value)| name.len() + value.len() + 32)
        .sum();
    let padding =
        vec![b'a'; volto::h3::MAX_FIELD_SECTION_SIZE as usize - named - PADDING.len() - 32];
    fields.push((PADDING, &padding));

    let mut block = BytesMut::new();
    volto::h3::qpack::encode(&mut block, fields.iter().copied());
    block
}

/// The bound is on what one connection holds at one moment, and a peer that
/// reaches it pays for it with one request (D77).
///
/// Sixteen full-sized field sections may be in flight at once and every one of
/// them is served; a seventeenth is answered with 431 and stopped, and the
/// connection — sixteen requests and sixteen tunnels still on it — carries on.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_past_the_buffering_budget_costs_only_that_request() {
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let target = spawn_echo_target().await;
    let (_endpoint, connection) = connect_quic(&server).await;

    let block = full_sized_connect_section(&target.to_string());
    let frame = common::rawstream::frame(FRAME_HEADERS, &block);

    let budget = volto::h3::HEADERS_BUFFER_BUDGET;
    let section = block.len();
    assert!(
        FULL_SIZED_FRAMES_THAT_FIT * section <= budget
            && (FULL_SIZED_FRAMES_THAT_FIT + 1) * section > budget,
        "{FULL_SIZED_FRAMES_THAT_FIT} field sections of {section} bytes are what a \
         budget of {budget} holds, and one more is what it does not"
    );

    // What a frame is charged is the length it announces rather than how much of
    // it has arrived, so the whole of the budget is committed by the frame
    // headers alone -- which is what lets these sixteen be genuinely at once,
    // without a megabyte of padding having to cross the wire first.
    let announced = frame.len() - section + 1;

    // Sixteen requests, every one of them announced before any is completed, so
    // the budget is fully committed at one moment. All sixteen are served: this
    // is the number the constant was chosen to allow.
    let mut streams = Vec::new();
    for _ in 0..FULL_SIZED_FRAMES_THAT_FIT {
        let (mut send, recv) = connection.open_bi().await.expect("open a request stream");
        send.write_all(&frame[..announced])
            .await
            .expect("announce a full-sized request");
        streams.push((send, recv));
    }
    for (send, _) in &mut streams {
        send.write_all(&frame[announced..])
            .await
            .expect("finish a full-sized request");
    }
    for (_, recv) in &mut streams {
        let (frame_type, payload) = read_frame(recv).await;
        assert_eq!(frame_type, FRAME_HEADERS);
        assert_eq!(
            status_of(&payload),
            "200",
            "a request the budget can hold must be served"
        );
    }

    // Seventeen, none of them ever completed, so nothing is given back and
    // exactly one charge has to fail -- whichever stream the server reaches
    // last, which is why the refusal is looked for rather than expected on a
    // particular one.
    let mut sends = Vec::new();
    let (refusals, mut refused) = tokio::sync::mpsc::channel(FULL_SIZED_FRAMES_THAT_FIT + 1);
    for index in 0..=FULL_SIZED_FRAMES_THAT_FIT {
        let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
        send.write_all(&frame[..announced])
            .await
            .expect("announce a full-sized request");
        sends.push(send);

        let refusals = refusals.clone();
        tokio::spawn(async move {
            // A refused request is answered and its stream finished; one the
            // budget holds says nothing at all, and this parks for the rest of
            // the test.
            if let Ok(response) = recv.read_to_end(4096).await {
                let _ = refusals.send((index, response)).await;
            }
        });
    }
    drop(refusals);

    let (index, response) = tokio::time::timeout(TIMEOUT, refused.recv())
        .await
        .expect("one of seventeen full-sized requests must be refused")
        .expect("the refusal arrives on a live stream");
    assert_eq!(
        status_of_response(&response),
        "431",
        "the request the budget could not hold is refused as a request"
    );
    assert_eq!(
        stopped_code(&mut sends[index]).await,
        H3_EXCESSIVE_LOAD,
        "the peer must be told which rule the request it lost broke"
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(200), refused.recv())
            .await
            .is_err(),
        "only the one request the budget could not hold may be refused"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), connection.closed())
            .await
            .is_err(),
        "a request the connection cannot hold must not cost it the connection"
    );
}

/// The `:status` of a response read whole from a raw request stream.
fn status_of_response(response: &[u8]) -> String {
    let (frame_type, used) = datagram::peek_varint(response).expect("a frame type");
    assert_eq!(frame_type, FRAME_HEADERS, "a response begins with HEADERS");
    let (length, more) = datagram::peek_varint(&response[used..]).expect("a frame length");

    let payload = &response[used + more..];
    assert_eq!(
        payload.len() as u64,
        length,
        "the response is the whole of what the stream carried"
    );
    status_of(payload)
}
