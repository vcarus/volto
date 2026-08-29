//! The HTTP/3 handshake is bounded, because the peer decides whether it can
//! finish at all.
//!
//! Why that bound has to exist is on `h3api::Connection::handshake`. What this
//! file adds is the proof on the wire, and the reason it is a test rather than a
//! comment: the clients here answer keep-alives, so the QUIC idle timeout never
//! fires and the handshake's own deadline is the only thing that can end the
//! connection.
//!
//! The rest of the file is the other half of the same problem (D76): a peer that
//! completes both handshakes and then says nothing, or sends a request it never
//! finishes. Both are bounded while the connection has never authenticated, and
//! both bounds vanish the moment one has.
//!
//! Bounding one connection is not the same as bounding a poolful of them, and
//! the last group of tests is that difference: at `max_connections` the oldest
//! connection that has never authenticated loses its slot to the newcomer, so a
//! peer that keeps handshaking and never sends a credential cannot hold the
//! server shut against clients that have one.

mod common;

use std::future::Future;
use std::net::SocketAddr;
use std::panic::Location;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use common::rawstream::{
    assert_closed_with, authenticated_connect_headers_frame, connect_headers_frame, read_frame,
    status_of,
};
use common::{
    auth_section, authorized_connect, basic_credentials, client_endpoint,
    client_endpoint_with_transport, finish_connect, open_tcp_tunnel, read_at_least,
    send_and_respond, spawn_echo_target, H3Client, TestServer, ALLOW_PRIVATE, IMPATIENT, TIMEOUT,
};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::{
    ClientSessionMemoryCache, ClientSessionStore, Resumption, Tls12ClientSessionValue,
    Tls13ClientSessionValue,
};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::NamedGroup;
use volto::h3api::Status;

/// H3_STREAM_CREATION_ERROR (RFC 9114 §8.1), the code the server hangs up with.
const H3_STREAM_CREATION_ERROR: u64 = 0x103;

/// H3_NO_ERROR (RFC 9114 §8.1): a close with nothing to report.
const H3_NO_ERROR: u64 = 0x100;

/// APPLICATION_ERROR (RFC 9000 §20.1), the transport code a server sends when it
/// closes for an application reason before the handshake has completed
/// (RFC 9000 §10.2.3).
const APPLICATION_ERROR: u64 = 0x0c;

/// H3_REQUEST_INCOMPLETE (RFC 9114 §8.1).
const H3_REQUEST_INCOMPLETE: u64 = 0x10d;

/// HEADERS frame type (RFC 9114 §7.2.2).
const FRAME_HEADERS: u64 = 0x01;

/// Room for two connections at a time, on top of the 1s idle timeout.
///
/// Small enough that a peer holding a slot it never uses is visible from the
/// outside: the third client is refused while the first two are alive.
const TWO_SLOTS: &str = "max_connections = 2\n";

/// Room for one connection at a time, so a slot held is a slot everyone can see
/// is gone: the second client is refused while the first holds it, and admitted
/// once it does not.
const ONE_SLOT: &str = "max_connections = 1\n";

/// The credentials the tests that configure authentication use.
const USER: (&str, &str) = ("user1", "s3cret");

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
    let connection = finish_connect(&endpoint, server.addr)
        .await
        .expect("the QUIC handshake itself must succeed");

    // Generous against the server's 1s bound, and far short of forever. The
    // code is the assertion: the peer has to be told which half of the
    // handshake it failed, rather than merely dropped.
    assert_closed_with(
        &connection,
        H3_STREAM_CREATION_ERROR,
        Duration::from_secs(5),
    )
    .await;
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

// ---------------------------------------------------------------------------
// D76: an unauthenticated connection may not sit on a slot for ever
// ---------------------------------------------------------------------------

/// A peer that completes the handshake and then never asks for anything must
/// give the slot back.
///
/// The two silent peers here are exactly the shape the v0.4.0 review found: a
/// plain QUIC connection, no request stream ever opened, kept alive by its own
/// stack answering the packets that cross it. Each is closed by the bound alone,
/// with nobody else arriving to prompt it.
///
/// Nothing here probes the connection cap any more, and that is deliberate: a
/// newcomer at the cap now takes one of these very slots by eviction, so a
/// refusal is no longer the symptom of a slot being held and an admission is no
/// longer proof of one being returned. The cap is asserted at the end of this
/// file instead; what is under test here is the bound each connection is under
/// on its own, with or without anyone waiting for its slot.
#[tokio::test]
async fn a_peer_that_never_sends_a_request_gives_its_slot_back() {
    let server = TestServer::start_with(&format!("{IMPATIENT}{TWO_SLOTS}")).await;

    let first = silent_peer(&server).await;
    let second = silent_peer(&server).await;

    // Two idle timeouts later both are gone, with nothing to report: neither
    // peer broke a rule, they simply had nothing to say.
    assert_closed_with(&first.1, H3_NO_ERROR, Duration::from_secs(8)).await;
    assert_closed_with(&second.1, H3_NO_ERROR, Duration::from_secs(8)).await;

    // And the server is serving afterwards rather than merely reporting the two
    // as closed.
    let (_endpoint, admitted) = common::connect_quic(&server).await;
    assert!(
        admitted.close_reason().is_none(),
        "the third client must be admitted once the silent peers are gone"
    );
}

/// A peer whose only request failed authentication is no better off.
///
/// 407 is not a slot: the connection has still never had an authenticated
/// request on it, so the bound still applies. This is the other half of the
/// review's C1 — a peer that answers the challenge by saying nothing at all.
#[tokio::test]
async fn a_peer_that_only_fails_authentication_gives_its_slot_back() {
    let server = TestServer::start_with(&format!(
        "{IMPATIENT}{}",
        auth_section(&[(USER.0, "the right password")])
    ))
    .await;

    let (_endpoint, connection) = silent_peer(&server).await;

    let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
    send.write_all(&authenticated_connect_headers_frame(
        "192.0.2.1:443",
        &basic_credentials(USER.0, "the wrong password"),
    ))
    .await
    .expect("send a CONNECT request");

    let (frame_type, payload) = read_frame(&mut recv).await;
    assert_eq!(frame_type, FRAME_HEADERS);
    assert_eq!(status_of(&payload), "407", "the guess must be refused");

    assert_closed_with(&connection, H3_NO_ERROR, Duration::from_secs(8)).await;
}

/// A connection that has authenticated once may idle for as long as it likes.
///
/// The invariant that makes the bound safe to ship: Surge keeps a connection
/// open between requests, and a proxy that hung up on it every couple of idle
/// timeouts would cost a handshake every time. Here the server's own keep-alive
/// holds the transport open, so the only thing that could close the connection
/// during the wait is the bound — and it must not.
#[tokio::test]
async fn an_authenticated_connection_is_not_bounded() {
    // A 3s idle timeout with keep-alives on, so the transport itself keeps the
    // connection alive while the test waits out more than the 6s bound.
    let server = TestServer::start_with(&format!(
        "[limits]\nmax_idle_timeout = 3\nkeep_alive_interval = 1\n{ALLOW_PRIVATE}{}",
        auth_section(&[USER])
    ))
    .await;
    let echo = spawn_echo_target().await;

    let mut client = H3Client::connect(&server).await;
    let mut tunnel = authenticated_tunnel(&mut client, &echo.to_string()).await;
    tunnel
        .send_data(Bytes::from_static(b"payload"))
        .await
        .expect("send payload");
    assert_eq!(read_at_least(&mut tunnel, 7).await, b"payload");

    // Longer than the bound (two 3s idle timeouts), with not a byte of HTTP/3
    // traffic in it.
    tokio::time::sleep(Duration::from_millis(6_500)).await;

    // Still usable, which it would not be if the bound had applied.
    let mut second = authenticated_tunnel(&mut client, &echo.to_string()).await;
    second
        .send_data(Bytes::from_static(b"still here"))
        .await
        .expect("send payload");
    assert_eq!(read_at_least(&mut second, 10).await, b"still here");
}

/// Opening request streams must not buy a peer more time to authenticate in.
///
/// The bound is a deadline measured from the handshake, not a timer restarted by
/// every wait, and this is the difference between the two. `accept()` returns the
/// moment the peer *opens* a stream, so a peer that opened one every other idle
/// timeout — a byte apiece, never a whole request, never a credential — used to
/// rearm the wait before it could expire and so held its slot for as long as it
/// cared to, which is the very symptom D76 exists to end (review C1').
///
/// Each of those streams is reset on its own after an idle timeout, and the
/// stream allowance comes back, so the peer can keep this up for nothing.
#[tokio::test]
async fn opening_request_streams_does_not_extend_the_bound() {
    let server = TestServer::start_with(&format!("{IMPATIENT}{ONE_SLOT}")).await;
    let (_endpoint, connection) = silent_peer(&server).await;

    // 1.2s apart, comfortably inside the 2s bound.
    let poking = tokio::spawn({
        let connection = connection.clone();
        async move {
            // Held open on purpose: a stream that is finished is a request that
            // ended, and what is under test is a stream that merely started.
            let mut open = Vec::new();
            while let Ok((mut send, recv)) = connection.open_bi().await {
                if send.write_all(&[0x01]).await.is_err() {
                    break;
                }
                open.push((send, recv));
                tokio::time::sleep(Duration::from_millis(1_200)).await;
            }
        }
    });

    // Two idle timeouts after the handshake, and not two after the last stream.
    // Nobody else connects while this runs: at the cap a newcomer would take
    // this slot by eviction, which closes the connection with the same code the
    // bound does and would leave the two indistinguishable.
    assert_closed_with(&connection, H3_NO_ERROR, Duration::from_secs(8)).await;
    poking.abort();

    let (_endpoint, admitted) = common::connect_quic(&server).await;
    assert!(
        admitted.close_reason().is_none(),
        "the server must still be serving once the peer that never authenticated is gone"
    );
}

/// A request stream that stalls before its HEADERS costs one stream, not the
/// connection.
///
/// `max_streams_bidi` is 1024 by default, and a byte apiece is all it takes to
/// park that many request tasks. The bound is per stream and so is the answer:
/// RFC 9114 §8.1's H3_REQUEST_INCOMPLETE, with everything else on the
/// connection untouched.
#[tokio::test]
async fn a_request_that_stalls_before_its_headers_is_reset() {
    let server = TestServer::start_with(IMPATIENT).await;
    let (_endpoint, connection) = silent_peer(&server).await;

    let (mut stalled_send, mut stalled_recv) =
        connection.open_bi().await.expect("open a request stream");
    // One byte: enough to open the stream at the server, not enough to be a
    // frame header, let alone a request.
    stalled_send
        .write_all(&[0x01])
        .await
        .expect("send one byte of a request");

    let error = tokio::time::timeout(TIMEOUT, stalled_recv.read_to_end(64))
        .await
        .expect("the server must not wait for a request that is not coming")
        .expect_err("the stalled stream must be reset");
    match error {
        quinn::ReadToEndError::Read(quinn::ReadError::Reset(code)) => assert_eq!(
            code.into_inner(),
            H3_REQUEST_INCOMPLETE,
            "the peer must be told its request never arrived"
        ),
        other => panic!("expected a reset, got {other}"),
    }

    // The connection is untouched: another request on it is served normally.
    // Port 25 is on the default deny list and the port rule is checked before
    // the resolver runs, so the 403 arrives without touching the network.
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

/// A batch of stalled requests is reset stream by stream, on a connection
/// nothing else bounds.
///
/// The single-stream test above runs unauthenticated, where D76's absolute
/// deadline would have answered the peer anyway. This one authenticates first,
/// so that deadline is lifted for good and the per-stream bound in
/// `Resolver::resolve` is the only thing standing between an authenticated
/// peer and `max_streams_bidi` parked decoder tasks. Per stream is the design
/// (D76 M2), so the batch is the shape that would catch it quietly becoming
/// per connection: one deadline tearing the connection down, or one reset
/// standing in for the lot. Every stream must draw its own
/// H3_REQUEST_INCOMPLETE, and the connection must come out serving.
#[tokio::test]
async fn a_batch_of_stalled_requests_is_reset_stream_by_stream() {
    /// Enough streams to be a batch rather than a coincidence, well under the
    /// 1024 the transport would grant: what is measured is one reset apiece,
    /// not the allowance.
    const STALLED: usize = 32;

    let server = TestServer::start_with(IMPATIENT).await;
    let (_endpoint, connection) = silent_peer(&server).await;

    // Authenticate first -- no `[auth]` section, so any completed request does
    // it. Port 25 is on the default deny list, so the 403 arrives without
    // touching the network, and it is the acceptance of the request rather
    // than its outcome that lifts the connection bound.
    let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
    send.write_all(&connect_headers_frame("192.0.2.1:25"))
        .await
        .expect("send a CONNECT request");
    let (frame_type, payload) = read_frame(&mut recv).await;
    assert_eq!(frame_type, FRAME_HEADERS);
    assert_eq!(
        status_of(&payload),
        "403",
        "the request must be answered, which is what lifts the D76 bound"
    );

    // Every stream gets its byte before any deadline is waited out, so the
    // batch really is concurrent: all of them are mid-request at once, and
    // their deadlines run together rather than one at a time.
    let mut stalled = Vec::new();
    for index in 0..STALLED {
        let (mut send, recv) = connection
            .open_bi()
            .await
            .unwrap_or_else(|error| panic!("stream {index} of {STALLED} was not granted: {error}"));
        // One byte: enough to open the stream at the server, not enough to be
        // a frame header, let alone a request.
        send.write_all(&[0x01])
            .await
            .expect("send one byte of a request");
        // The sending half is held: dropping it would finish the stream and
        // turn a request that stalled into one that ended, which has a
        // verdict of its own.
        stalled.push((send, recv));
    }

    for (index, (_send, mut recv)) in stalled.into_iter().enumerate() {
        let error = tokio::time::timeout(TIMEOUT, recv.read_to_end(64))
            .await
            .unwrap_or_else(|_| {
                panic!("stream {index} of {STALLED}: the server must not wait for a request that is not coming")
            })
            .expect_err("the stalled stream must be reset");
        match error {
            quinn::ReadToEndError::Read(quinn::ReadError::Reset(code)) => assert_eq!(
                code.into_inner(),
                H3_REQUEST_INCOMPLETE,
                "stream {index} of {STALLED} must draw its own reset"
            ),
            other => panic!("stream {index} of {STALLED}: expected a reset, got {other}"),
        }
    }

    assert!(
        connection.close_reason().is_none(),
        "the bound is per stream: a batch of stalled requests must not cost the connection"
    );
    // And it is a working connection, not merely an unclosed one.
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

/// A QUIC handshake that never finishes must not sit on a connection slot.
///
/// One layer below everything else in this file. The slot is taken when the
/// accept loop spawns the connection task, which is *before* the QUIC and TLS
/// handshake happens, and quinn has no handshake-specific timer — any
/// authenticated packet in any packet number space refreshes its idle timer, so
/// a peer that keeps sending Initials and never completes the handshake keeps
/// the slot (review M6).
///
/// The half-finished handshake is produced by relaying the client's packets to
/// the server and dropping the server's answers, which is the shape without
/// writing QUIC packets by hand: the server accepts a well-formed Initial and
/// answers into a void, while the client's retransmissions keep arriving.
///
/// What the second client proves is the whole point: it connects *directly*,
/// once the deadline has passed, and it can only be admitted if the slot came
/// back. Refusal is immediate rather than a timeout, so this does not depend on
/// how fast the machine running it is.
#[tokio::test]
async fn a_quic_handshake_that_never_completes_gives_its_slot_back() {
    let server = TestServer::start_with(&format!("{IMPATIENT}{ONE_SLOT}")).await;
    let relay = one_way_relay(server.addr).await;

    let mut transport = quinn::TransportConfig::default();
    // Retransmit briskly, so the server keeps receiving Initials and its idle
    // timer keeps being refreshed. Without this the transport's own timeout
    // would end the connection at about the same moment the deadline does, and
    // the test would pass whether the deadline existed or not.
    transport.initial_rtt(Duration::from_millis(20));
    let endpoint = client_endpoint_with_transport(&server.ca, &["h3"], transport);

    // Started and deliberately not awaited: this handshake cannot complete.
    // Dropping the `Connecting` would close it, which is exactly what must not
    // happen while the server is being watched.
    let _stalled = endpoint
        .connect(relay, "localhost")
        .expect("start a handshake that cannot finish");

    // Comfortably past the server's 1s deadline, and comfortably short of the
    // idle timeout the retransmissions above keep pushing out.
    tokio::time::sleep(Duration::from_millis(1_600)).await;

    let admitted = client_endpoint(&server.ca, &["h3"]);
    let connection = finish_connect(&admitted, server.addr)
        .await
        .expect("the slot must come back once the stalled handshake is abandoned");
    assert!(
        connection.close_reason().is_none(),
        "the second client must be admitted, not refused"
    );
}

// ---------------------------------------------------------------------------
// A full server takes the slot back rather than refusing the newcomer
// ---------------------------------------------------------------------------

/// At the cap, the connection that has never authenticated is the one that goes.
///
/// Each bound above is a bound on a single connection, and none of them bounds
/// how many slots unauthenticated peers hold between them: a peer that completes
/// a handshake about once a second and never sends a credential keeps every slot
/// occupied for ever, legitimately, while every client that has credentials is
/// refused. Here the parked peer is that peer, at a cap of one.
///
/// The idle timeouts are the shipped ones, so nothing in this test is waiting
/// for a clock: the parked connection is minutes away from any bound of its own,
/// and the only thing that can close it is the newcomer taking its slot.
#[tokio::test]
async fn a_full_server_evicts_the_connection_that_never_authenticated() {
    let server = TestServer::start_with(&format!("[limits]\n{ONE_SLOT}{ALLOW_PRIVATE}")).await;
    let echo = spawn_echo_target().await;

    // Holds the only slot: both handshakes complete, no request ever sent, so
    // nothing on it has been past the credentials check.
    let parked = H3Client::connect(&server).await;

    // The newcomer is admitted, and is a working client rather than merely a
    // completed handshake.
    let mut client = H3Client::connect(&server).await;
    let mut tunnel = open_tcp_tunnel(&mut client, &echo.to_string()).await;
    tunnel
        .send_data(Bytes::from_static(b"payload"))
        .await
        .expect("send payload");
    assert_eq!(read_at_least(&mut tunnel, 7).await, b"payload");

    // And the peer whose slot it took was told, with nothing to report: it broke
    // no rule, it simply had never asked this server for anything.
    assert_closed_with(&parked.quic, H3_NO_ERROR, TIMEOUT).await;
}

/// A connection that has authenticated keeps its slot, and the newcomer is
/// refused exactly as it always was.
///
/// The other half of the rule, and the one that keeps eviction from being a way
/// to knock a paying client off: with no users configured the first request past
/// the door counts as having got past it (D76), so one successful CONNECT is all
/// it takes to stop being a candidate.
#[tokio::test]
async fn an_authenticated_connection_is_never_the_one_evicted() {
    let server = TestServer::start_with(&format!("[limits]\n{ONE_SLOT}{ALLOW_PRIVATE}")).await;
    let echo = spawn_echo_target().await;

    let mut holder = H3Client::connect(&server).await;
    let mut tunnel = open_tcp_tunnel(&mut holder, &echo.to_string()).await;

    let refused = client_endpoint(&server.ca, &["h3"]);
    let error = finish_connect(&refused, server.addr)
        .await
        .expect_err("an authenticated connection must not lose its slot to a newcomer");
    assert!(
        matches!(
            error,
            quinn::ConnectionError::ConnectionClosed(_) | quinn::ConnectionError::Reset
        ),
        "expected the connection to be refused, got {error}"
    );

    // The connection that kept its slot is untouched: the tunnel it already had
    // still carries bytes, and it can still open another.
    tunnel
        .send_data(Bytes::from_static(b"payload"))
        .await
        .expect("send payload");
    assert_eq!(read_at_least(&mut tunnel, 7).await, b"payload");

    let mut second = open_tcp_tunnel(&mut holder, &echo.to_string()).await;
    second
        .send_data(Bytes::from_static(b"still here"))
        .await
        .expect("send payload");
    assert_eq!(read_at_least(&mut second, 10).await, b"still here");
}

/// Of two connections that have never authenticated, the older one goes.
///
/// Not a detail: eviction has to walk the pool in accept order, or a peer could
/// keep handshaking and have its own oldest connection spared while the queue
/// churns around it. Two parked peers and one arrival say which of the two was
/// picked, which a single-slot test cannot.
#[tokio::test]
async fn the_oldest_unauthenticated_connection_is_the_one_evicted() {
    let server = TestServer::start_with(&format!("[limits]\n{TWO_SLOTS}{ALLOW_PRIVATE}")).await;
    let echo = spawn_echo_target().await;

    let older = H3Client::connect(&server).await;
    let younger = H3Client::connect(&server).await;

    let mut client = H3Client::connect(&server).await;
    let mut tunnel = open_tcp_tunnel(&mut client, &echo.to_string()).await;
    tunnel
        .send_data(Bytes::from_static(b"payload"))
        .await
        .expect("send payload");
    assert_eq!(read_at_least(&mut tunnel, 7).await, b"payload");

    assert_closed_with(&older.quic, H3_NO_ERROR, TIMEOUT).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), younger.quic.closed())
            .await
            .is_err(),
        "only one slot was needed, so the younger parked connection must keep its own"
    );
}

/// Lowering `max_connections` under a running roster evicts down to the new
/// cap in one arrival, oldest first.
///
/// The eviction in the accept loop is a `while len >= max` rather than a
/// single step, because the cap it is measured against can move underneath the
/// roster: the cap is read per accepted connection so that a SIGHUP lowering
/// it during an incident takes effect at once (`docs/deployment.md`), and the
/// reload itself touches nobody -- it is applied where arrivals are, so the
/// roster stays over the new cap until somebody arrives. Four parked peers
/// over a cap of two mean the newcomer's arrival must take three victims at
/// once; a single-eviction reading of that loop would admit the newcomer with
/// the roster still over its cap, which is exactly what the one-at-a-time
/// tests above cannot notice (D80).
#[tokio::test]
async fn lowering_the_connection_cap_evicts_down_to_it() {
    let server =
        TestServer::start_with(&format!("[limits]\nmax_connections = 5\n{ALLOW_PRIVATE}")).await;
    let echo = spawn_echo_target().await;

    // Four connections that never authenticate, registered in this order --
    // which is the order eviction owes them nothing in.
    let parked = [
        H3Client::connect(&server).await,
        H3Client::connect(&server).await,
        H3Client::connect(&server).await,
        H3Client::connect(&server).await,
    ];

    server.rewrite_config(&format!("[limits]\nmax_connections = 2\n{ALLOW_PRIVATE}"));
    server.reload().expect("the lowered cap must load");

    // The reload alone evicts nobody: connections already accepted are
    // promised their configuration, and the squaring below happens at the
    // next arrival.
    for (index, client) in parked.iter().enumerate() {
        assert!(
            tokio::time::timeout(Duration::from_millis(200), client.quic.closed())
                .await
                .is_err(),
            "connection {index}: a reload is applied at arrivals, not to the connections \
             already accepted"
        );
    }

    // The arrival. It is over the cap the moment it knocks, so it pays the
    // validation round trip (quinn answers the Retry without telling anybody)
    // and then takes its slot from the oldest unauthenticated peers -- three
    // of them, because that is how far over the new cap the roster is.
    let mut newcomer = H3Client::connect(&server).await;
    let mut tunnel = open_tcp_tunnel(&mut newcomer, &echo.to_string()).await;
    tunnel
        .send_data(Bytes::from_static(b"payload"))
        .await
        .expect("send payload");
    assert_eq!(read_at_least(&mut tunnel, 7).await, b"payload");

    for victim in &parked[..3] {
        assert_closed_with(&victim.quic, H3_NO_ERROR, TIMEOUT).await;
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(200), parked[3].quic.closed())
            .await
            .is_err(),
        "the newcomer and the youngest parked connection fit the new cap of two, \
         so the fourth eviction must not happen"
    );
}

/// A newcomer may only evict once it has proved it can receive at the address
/// it claims.
///
/// Eviction turns an unverified source address into a way of closing other
/// people's connections, and a spoofed Initial costs an attacker one datagram
/// with no return path. So at the cap the answer to an unvalidated newcomer is a
/// Retry, which takes no slot and no crypto; the token it comes back with is
/// what buys it the right to take somebody else's place.
///
/// Read off the wire rather than out of the server: quinn's client handles a
/// Retry without telling anybody, so the relay in between is what sees it.
#[tokio::test]
async fn a_full_server_makes_a_newcomer_validate_its_address_before_it_evicts() {
    let server = TestServer::start_with(&format!("[limits]\n{ONE_SLOT}")).await;

    // Holds the only slot and has never authenticated, so it is exactly what
    // the newcomer below is entitled to displace.
    let parked = H3Client::connect(&server).await;

    let (relay, retries) = retry_counting_relay(server.addr).await;
    let endpoint = client_endpoint(&server.ca, &["h3"]);
    let connection = finish_connect(&endpoint, relay)
        .await
        .expect("a client that answers the Retry must still be admitted");

    assert!(
        connection.close_reason().is_none(),
        "the newcomer must end up admitted, not refused"
    );
    assert_eq!(
        retries.load(Ordering::Relaxed),
        1,
        "a full server must answer an unvalidated newcomer with exactly one Retry"
    );
    // And the Retry really is a step on the way to eviction rather than a
    // substitute for it: the slot changed hands.
    assert_closed_with(&parked.quic, H3_NO_ERROR, TIMEOUT).await;
}

/// Below the cap the extra round trip must not be charged to anybody.
///
/// The negation of the test above, on the same observation: one of two slots is
/// taken, so there is nothing to evict and nothing to prove, and Surge's
/// handshake has to stay the one round trip it always was.
#[tokio::test]
async fn a_server_with_room_asks_no_newcomer_to_validate_its_address() {
    let server = TestServer::start_with(&format!("[limits]\n{TWO_SLOTS}")).await;

    let parked = H3Client::connect(&server).await;

    let (relay, retries) = retry_counting_relay(server.addr).await;
    let endpoint = client_endpoint(&server.ca, &["h3"]);
    let connection = finish_connect(&endpoint, relay)
        .await
        .expect("there is room, so the newcomer is simply admitted");

    assert!(
        connection.close_reason().is_none(),
        "the newcomer must be admitted"
    );
    assert_eq!(
        retries.load(Ordering::Relaxed),
        0,
        "a server with a free slot must not make a client pay a round trip for it"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), parked.quic.closed())
            .await
            .is_err(),
        "with room to spare nobody's slot is taken"
    );
}

/// A client that has been here before evicts without paying the round trip.
///
/// A Retry is not the only way an address gets validated. quinn's `bloom`
/// feature is on (`Cargo.toml`), so this server sends NEW_TOKEN frames on every
/// connection whose path it validated — RFC 9000 §8.1 calls that the second way
/// the token is delivered — and quinn's client keeps them. So the client that
/// comes back is already validated when its Initial arrives, and the extra round
/// trip lands only on an address the server holds no token from.
///
/// Both connections go through the same relay so the server sees one address:
/// the token names the IP it was issued for and is refused for any other.
#[tokio::test]
async fn a_client_that_has_connected_before_evicts_without_a_retry() {
    let server = TestServer::start_with(&format!("[limits]\n{ONE_SLOT}")).await;

    let (relay, retries) = retry_counting_relay(server.addr).await;
    let endpoint = client_endpoint(&server.ca, &["h3"]);

    // First contact, on a server with its slot free: nothing to evict, no Retry,
    // and the completed handshake is what earns the tokens.
    let first = finish_connect(&endpoint, relay)
        .await
        .expect("the first connection is simply admitted");
    // The NEW_TOKEN frames are queued the moment the server processes the
    // client's Handshake packet, which is before the HTTP/3 layer has opened
    // anything — so the arrival of the server's control stream is proof that the
    // packet carrying them has been processed too.
    tokio::time::timeout(TIMEOUT, first.accept_uni())
        .await
        .expect("the server's control stream must arrive")
        .expect("the server's control stream must open");
    first.close(0u32.into(), b"");
    drop(first);

    // Refill the one slot with a peer that has never authenticated, so there is
    // something for the returning client to take.
    let parked = H3Client::connect(&server).await;

    let second = finish_connect(&endpoint, relay)
        .await
        .expect("a client holding a token must be admitted straight away");

    assert!(
        second.close_reason().is_none(),
        "the returning client must end up admitted, not refused"
    );
    assert_eq!(
        retries.load(Ordering::Relaxed),
        0,
        "an address the server has already issued a token to must not be asked to prove \
         itself again"
    );
    assert_closed_with(&parked.quic, H3_NO_ERROR, TIMEOUT).await;
}

/// The eviction signal reaches a connection still inside its QUIC handshake.
///
/// The slot is taken before the handshake starts, so a peer that never finishes
/// one is holding a slot that the roster can take back — and the branch that
/// takes it is a `select!` arm racing the handshake itself, on a connection that
/// has no `conn::handle` future to drop yet. Nothing had exercised that arm:
/// replacing it with `std::future::pending()` left every eviction test green,
/// because the roster frees the slot whether or not the victim ever hears about
/// it.
///
/// So this watches the victim rather than the newcomer. The relay carries the
/// client's first datagram and no more, so the server never sees the client's
/// Finished and stays in `Connecting`, while the client — which completes on the
/// server's flight — is left with a connection to watch. What arrives on it is
/// the close the eviction sends, well inside the handshake deadline of one idle
/// timeout.
///
/// It also settles what that close *is* (F4). An `Incoming` handed to
/// `tokio::time::timeout` has already been accepted, so this is not
/// `Incoming::refuse`'s CONNECTION_REFUSED: it is the application close that
/// dropping a `Connecting` performs, which RFC 9000 §10.2.3 has a server send
/// before the handshake completes as a transport close carrying APPLICATION_ERROR
/// and no reason.
#[tokio::test]
async fn a_connection_still_handshaking_hears_about_its_eviction() {
    let server = TestServer::start_with(&format!("[limits]\n{ONE_SLOT}")).await;

    let relay = deaf_after_the_first_packet(server.addr).await;
    let endpoint = client_endpoint(&server.ca, &["h3"]);
    let stalled = finish_connect(&endpoint, relay)
        .await
        .expect("the client finishes on the server's flight even though the server cannot");

    // The only slot is the stalled peer's, and the newcomer is entitled to it:
    // quinn answers the Retry for it, so it arrives validated.
    let _newcomer = H3Client::connect(&server).await;

    let error = tokio::time::timeout(TIMEOUT, stalled.closed())
        .await
        .expect("an evicted peer must be told at once, not left until the handshake deadline");

    let quinn::ConnectionError::ConnectionClosed(close) = error else {
        panic!("the eviction must arrive as a transport CONNECTION_CLOSE, got {error:?}");
    };
    assert_eq!(
        u64::from(close.error_code),
        APPLICATION_ERROR,
        "a `Connecting` dropped before the handshake completes closes with APPLICATION_ERROR"
    );
    assert!(
        close.reason.is_empty(),
        "the close carries no reason: {:?}",
        close.reason
    );
}

// ---------------------------------------------------------------------------
// 0-RTT is off, and pinned off rather than inherited
// ---------------------------------------------------------------------------

/// The server must not let a returning client send early data.
///
/// `src/tls.rs` builds the rustls `ServerConfig` by hand, so
/// `max_early_data_size` is whatever is set there — quinn's own
/// `with_single_cert` sets `u32::MAX`, and rustls' default is 0. The value is
/// pinned to 0 for the reason RFC 9001 §9.2 gives, and this is what says so from
/// the wire.
///
/// The client is as willing as a client can be: `enable_early_data`, a session
/// store it keeps, and a first connection whose ticket has demonstrably arrived
/// before the second one starts. Without that wait the assertion would hold for
/// the wrong reason — a client with nothing to resume cannot offer 0-RTT
/// whatever the server permits.
#[tokio::test]
async fn the_server_does_not_permit_zero_rtt() {
    let server = TestServer::start().await;
    let (endpoint, tickets) = resuming_client_endpoint(&server.ca);

    // Held open: the ticket arrives on this connection, after its handshake.
    let _first = finish_connect(&endpoint, server.addr)
        .await
        .expect("the first handshake must succeed");
    await_ticket(&tickets).await;

    let second = endpoint
        .connect(server.addr, "localhost")
        .expect("start the second handshake");
    let Err(second) = second.into_0rtt() else {
        panic!("the server offered 0-RTT: RFC 9001 section 9.2 has this proxy disable it");
    };

    // What was refused is the early data and not the connection: the ordinary
    // handshake still completes on the ticket the client kept.
    let second = tokio::time::timeout(TIMEOUT, second)
        .await
        .expect("the second handshake must not hang")
        .expect("the second handshake must succeed without 0-RTT");
    assert!(
        second.close_reason().is_none(),
        "the resumed connection must be usable"
    );
}

/// Waits until the server has sent a TLS 1.3 session ticket, or gives up.
///
/// The ticket is what a resumption is built on and it arrives after the
/// handshake, so this is the difference between asserting that 0-RTT was refused
/// and asserting that there was nothing to offer.
async fn await_ticket(tickets: &AtomicUsize) {
    let deadline = std::time::Instant::now() + TIMEOUT;
    while tickets.load(Ordering::Relaxed) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the server sent no session ticket within {TIMEOUT:?}, so there was never \
             anything to resume"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A client endpoint that keeps session tickets and is willing to use them for
/// early data.
///
/// Built here rather than through `common::client_endpoint` because it differs
/// from every other client in this suite in exactly the way this one test needs.
/// rustls leaves `enable_early_data` off, and quinn only sets it on the client
/// configs it builds itself, so the shared helper's client would never offer
/// 0-RTT and would agree with the server for the wrong reason.
fn resuming_client_endpoint(ca: &CertificateDer<'static>) -> (quinn::Endpoint, Arc<AtomicUsize>) {
    let tickets = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(CountingSessionStore {
        // rustls' own default size, and not a number to shrink for tidiness:
        // its cache divides the figure by the tickets it keeps per server and
        // then evicts when the resulting deque is at capacity, so a small size
        // drops the very entry it has just stored and no resumption is ever
        // possible.
        inner: ClientSessionMemoryCache::new(256),
        tickets: tickets.clone(),
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).expect("trust the test CA");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    crypto.resumption = Resumption::store(store);
    crypto.enable_early_data = true;

    let client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto).expect("quic tls"),
    ));
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("bind address")).expect("client");
    endpoint.set_default_client_config(client_config);

    (endpoint, tickets)
}

/// rustls' own in-memory session cache, with a count of the tickets that reach
/// it.
///
/// Every method delegates; the count is the only thing added, and it is what
/// [`await_ticket`] waits on.
#[derive(Debug)]
struct CountingSessionStore {
    inner: ClientSessionMemoryCache,
    tickets: Arc<AtomicUsize>,
}

impl ClientSessionStore for CountingSessionStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.inner.set_kx_hint(server_name, group);
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.inner.kx_hint(server_name)
    }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.inner.set_tls12_session(server_name, value);
    }

    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.inner.tls12_session(server_name)
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.inner.remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        self.tickets.fetch_add(1, Ordering::Relaxed);
        self.inner.insert_tls13_ticket(server_name, value);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        self.inner.take_tls13_ticket(server_name)
    }
}

/// Carries packets one way only: client to `server`, and nothing back.
///
/// The socket hears both ends — the client sends to it, and the server answers
/// to it, since that is the address its packets came from — so the direction is
/// decided by who a packet came from.
async fn one_way_relay(server: SocketAddr) -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind the relay socket");
    let addr = socket.local_addr().expect("the relay's address");

    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((read, from)) = socket.recv_from(&mut buf).await {
            if from == server {
                // The server's half of the handshake goes nowhere, which is
                // what leaves it half-finished.
                continue;
            }
            let _ = socket.send_to(&buf[..read], server).await;
        }
    });

    addr
}

/// Carries the client's first datagram to `server` and nothing after it, while
/// carrying everything the server sends back.
///
/// The asymmetry is the point. The client's Initial gets through, so the server
/// builds a connection and takes a slot for it; the client's Finished does not,
/// so the server's handshake never completes and the slot stays held. The other
/// direction is left open because the client is the observer here — a peer that
/// cannot hear the server cannot report what the server did.
async fn deaf_after_the_first_packet(server: SocketAddr) -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind the relay socket");
    let addr = socket.local_addr().expect("the relay's address");

    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut client: Option<SocketAddr> = None;
        let mut forwarded = 0usize;

        while let Ok((read, from)) = socket.recv_from(&mut buf).await {
            let datagram = &buf[..read];

            if from == server {
                if let Some(client) = client {
                    let _ = socket.send_to(datagram, client).await;
                }
                continue;
            }

            client = Some(from);
            if forwarded == 0 {
                forwarded += 1;
                let _ = socket.send_to(datagram, server).await;
            }
        }
    });

    addr
}

/// Carries packets both ways between one client and `server`, counting the
/// Retry packets the server sends.
///
/// A Retry is the one server packet a test can recognise without any keys,
/// which is what makes this an on-wire observation rather than a reading of the
/// server's own state — and it has to be observed here, because quinn's client
/// answers a Retry without telling the application anything at all.
async fn retry_counting_relay(server: SocketAddr) -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind the relay socket");
    let addr = socket.local_addr().expect("the relay's address");

    let retries = Arc::new(AtomicUsize::new(0));
    let counter = retries.clone();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        // Learned from the first packet that is not the server's, so the
        // answers have somewhere to go.
        let mut client: Option<SocketAddr> = None;

        while let Ok((read, from)) = socket.recv_from(&mut buf).await {
            let datagram = &buf[..read];

            if from == server {
                if is_retry(datagram) {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                if let Some(client) = client {
                    let _ = socket.send_to(datagram, client).await;
                }
            } else {
                client = Some(from);
                let _ = socket.send_to(datagram, server).await;
            }
        }
    });

    (addr, retries)
}

/// Whether `datagram` starts with a QUIC version 1 Retry packet.
///
/// RFC 9000 §17.2.5 gives a Retry a long header — "Header Form (1) = 1, Fixed
/// Bit (1) = 1, Long Packet Type (2) = 3" — with four Unused bits below them, so
/// the first byte is `0b1111xxxx`; the version follows, and the type bits only
/// mean what §17.2's Table 5 says they mean in version 1. RFC 9000 §12.2 puts a
/// Retry last in its datagram, and this server sends it alone, so the first
/// packet is the only one worth looking at.
fn is_retry(datagram: &[u8]) -> bool {
    matches!(datagram.first(), Some(first) if first & 0xf0 == 0xf0)
        && matches!(datagram.get(1..5), Some([0x00, 0x00, 0x00, 0x01]))
}

/// Opens a QUIC connection that keeps itself alive and never says anything.
///
/// The keep-alive is what makes these tests about the application bound rather
/// than about the transport's: with it, every ACK restarts the server's idle
/// timer, so the transport can never be the thing that closes the connection.
#[track_caller]
fn silent_peer(server: &TestServer) -> impl Future<Output = (quinn::Endpoint, quinn::Connection)> {
    let caller = Location::caller();
    let ca = server.ca.clone();
    let addr = server.addr;

    async move {
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_millis(100)));

        let endpoint = client_endpoint_with_transport(&ca, &["h3"], transport);
        let connection = finish_connect(&endpoint, addr)
            .await
            .unwrap_or_else(|error| panic!("the handshake at {caller} failed: {error}"));

        (endpoint, connection)
    }
}

/// Opens a CONNECT tunnel carrying credentials, and asserts it was accepted.
#[track_caller]
fn authenticated_tunnel<'a>(
    client: &'a mut H3Client,
    authority: &'a str,
) -> impl Future<Output = common::ClientStream> + 'a {
    let caller = Location::caller();
    async move {
        let request = authorized_connect(authority, USER.0, USER.1);
        let (response, stream) = send_and_respond(client, request).await;
        assert_eq!(
            response.status,
            Status::OK,
            "the tunnel opened at {caller} was refused"
        );
        stream
    }
}
