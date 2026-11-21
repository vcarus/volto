//! The SNI gate, asserted from outside the process (D106).
//!
//! What the gate promises is a *negative*: a client that cannot name this server
//! gets nothing back at all. Nothing internal can be inspected to check that —
//! the whole property is about bytes that do not appear on the wire — so every
//! test here drives a real client, or a raw UDP socket, against a real server and
//! judges what came back.
//!
//! # Telling silence from a refusal
//!
//! The distinction the gate lives or dies by is between *no answer* and *an
//! answer that says no*, and a handshake failure alone does not tell them apart.
//! So the certificate here covers two names, `localhost` and `other.example`,
//! and every negative test asks for a name the certificate would have accepted.
//! A `ConnectionError::TimedOut` is then the gate working: the client asked for a
//! name it could have completed a handshake under, and heard nothing. Anything
//! else — a transport error, a connection closed — means the server replied.
//!
//! The same pair of names is what makes the gate-off tests a red proof rather
//! than a formality: the identical client, asking for the identical name, opens a
//! connection when the list is empty and times out when it is not.

mod common;

use std::assert_matches;
use std::net::SocketAddr;
use std::panic::Location;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    ALLOW_PRIVATE, GATE_LOCALHOST, H3Client, Leg, Relay, Relayed, SharedBuffer, TestServer,
    bulk_alpn, client_endpoint, client_endpoint_with_transport, echoes, finish_connect_as,
    is_version_negotiation, open_tcp_tunnel, open_udp_session, spawn_echo_target,
    spawn_udp_echo_target, udp_answer, udp_answers, udp_answers_on, udp_relay, udp_round_trip,
    version_probe,
};
use rustls::pki_types::CertificateDer;

/// A second name on the test certificate, so a refusal and a mismatch differ.
const OTHER: &str = "other.example";

/// The gate on, naming only [`OTHER`].
const GATE_OTHER: &str =
    "[security]\nallow_private_networks = true\nexpected_sni = [\"other.example\"]\n";

/// The gate off, which is the shipped default.
const GATE_OFF: &str = ALLOW_PRIVATE;

/// The log the tests here read: the server's own line about its drain,
/// through [`SharedBuffer::shared`].
const LOG_FILTER: &str = "volto::quic=info";

/// How long a refused handshake is given to prove it is not coming back.
///
/// The client's own idle timeout, which is what turns silence into a
/// `TimedOut` rather than into this test binary hanging for quinn's 30-second
/// default. Two seconds so a loaded machine cannot mistake a slow reply for no
/// reply.
const CLIENT_IDLE: Duration = Duration::from_secs(2);

/// A client that gives up quickly, so that "no answer" is a fast answer.
fn impatient(ca: &CertificateDer<'static>) -> quinn::Endpoint {
    impatient_offering(ca, &["h3"])
}

/// [`impatient`] offering `alpn` instead of `h3` alone.
///
/// The two tests about a ClientHello too large for one Initial packet offer
/// `bulk_alpn()`, which is what makes the first flight span more than one: the
/// padding is in the ALPN list, so the client that sends it is the same client
/// in every other respect.
fn impatient_offering(ca: &CertificateDer<'static>, alpn: &[&str]) -> quinn::Endpoint {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(CLIENT_IDLE.try_into().expect("a legal idle timeout")));
    // Off, or the client would keep the connection it never opened alive.
    transport.keep_alive_interval(None);
    client_endpoint_with_transport(ca, alpn, transport)
}

/// Asserts that asking for `name` gets no answer of any kind.
///
/// Written as a synchronous function returning a future so that
/// `#[track_caller]` survives to the poll that panics (D66).
#[track_caller]
fn assert_silent<'a>(server: &'a TestServer, name: &'a str) -> impl Future<Output = ()> + 'a {
    let caller = Location::caller();
    async move {
        let endpoint = impatient(&server.ca);
        let error = finish_connect_as(&endpoint, server.addr, name)
            .await
            .expect_err("a name the gate does not know must not complete a handshake");

        assert_matches!(
            error,
            quinn::ConnectionError::TimedOut,
            "asking for {name:?} at {caller} must get silence, not a reply: {error:?}"
        );
    }
}

/// Asserts that asking for `name` completes a handshake.
#[track_caller]
fn assert_answered<'a>(
    server: &'a TestServer,
    name: &'a str,
) -> impl Future<Output = quinn::Connection> + 'a {
    let caller = Location::caller();
    async move {
        let endpoint = impatient(&server.ca);
        finish_connect_as(&endpoint, server.addr, name)
            .await
            .unwrap_or_else(|error| {
                panic!("asking for {name:?} at {caller} must be answered: {error:?}")
            })
    }
}

// ---------------------------------------------------------------------------
// (a) A name that is not on the list gets silence, not an alert
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_handshake_naming_another_host_is_dropped_without_a_reply() {
    let server = TestServer::start_with_certificate_names(GATE_LOCALHOST, &[OTHER]).await;

    // `other.example` is on the certificate, so nothing but the gate can be
    // what stops this handshake -- and it stops it by saying nothing.
    assert_silent(&server, OTHER).await;
}

/// The same, for a client that could not name anybody: the ClientHello carries
/// no `server_name` extension at all.
///
/// quinn's client always sends one, so this is driven by hand: an IP literal as
/// the server name is what rustls declines to put in the extension.
#[tokio::test]
async fn a_handshake_carrying_no_server_name_is_dropped_without_a_reply() {
    let server = TestServer::start_with_certificate_names(GATE_LOCALHOST, &[OTHER]).await;
    let endpoint = impatient(&server.ca);

    let error = finish_connect_as(&endpoint, server.addr, "127.0.0.1")
        .await
        .expect_err("a ClientHello with no server_name must not complete a handshake");

    assert_matches!(
        error,
        quinn::ConnectionError::TimedOut,
        "a nameless ClientHello must get silence, not a reply: {error:?}"
    );
}

// ---------------------------------------------------------------------------
// (b) The name on the list still works, all the way to a tunnel
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_name_on_the_list_reaches_both_kinds_of_tunnel() {
    let server = TestServer::start_with_certificate_names(GATE_LOCALHOST, &[OTHER]).await;
    let target = spawn_echo_target().await;
    let udp_target = spawn_udp_echo_target().await;

    let mut client = H3Client::connect(&server).await;

    let mut tunnel = open_tcp_tunnel(&mut client, &target.to_string()).await;
    echoes(&mut tunnel, b"through the gate").await;

    let (session, _stream) = open_udp_session(&mut client, &server, udp_target).await;
    assert_eq!(
        udp_round_trip(&client, session, b"and a datagram").await,
        b"and a datagram".as_slice()
    );
}

// ---------------------------------------------------------------------------
// (c) A version-negotiation probe: answered with the gate off, silent with it on
// ---------------------------------------------------------------------------

/// Sends `probe` from a fresh socket and returns whatever comes back.
async fn probe(addr: SocketAddr, probe: &[u8]) -> Option<Vec<u8>> {
    udp_answer(addr, probe, CLIENT_IDLE).await
}

#[tokio::test]
async fn an_unknown_version_draws_a_version_negotiation_packet_with_the_gate_off() {
    let server = TestServer::start_with(GATE_OFF).await;

    let answer = probe(server.addr, &version_probe())
        .await
        .expect("with the gate off, quinn answers an unsupported version");

    assert!(
        is_version_negotiation(&answer),
        "a Version Negotiation packet was expected: {answer:?}"
    );
}

#[tokio::test]
async fn an_unknown_version_draws_nothing_at_all_with_the_gate_on() {
    let server = TestServer::start_with(GATE_LOCALHOST).await;

    assert!(
        probe(server.addr, &version_probe()).await.is_none(),
        "with the gate on, an unsupported version must draw no reply"
    );
}

/// The probe a port scanner actually sends: an empty datagram, and a short one
/// of arbitrary bytes. Neither draws anything, gate or no gate — this is the
/// baseline the gate does not have to improve on, pinned so that a change to it
/// is noticed.
#[tokio::test]
async fn an_empty_probe_draws_nothing_either_way() {
    for extra in [GATE_OFF, GATE_LOCALHOST] {
        let server = TestServer::start_with(extra).await;

        // Independent probes on independent sockets, and each costs the whole
        // of `CLIENT_IDLE` on the success path, because proving silence takes
        // the full wait. So they wait together.
        let (empty, arbitrary) =
            tokio::join!(probe(server.addr, b""), probe(server.addr, b"volto?"));

        assert!(empty.is_none(), "an empty datagram must draw no reply");
        assert!(
            arbitrary.is_none(),
            "a short arbitrary datagram must draw no reply"
        );
    }
}

/// A UDP relay between one client and `server`, and the record of every
/// short-header datagram the client sends through it, in the order it came.
async fn recording_relay(server: SocketAddr) -> (Relay, Arc<Mutex<Vec<Vec<u8>>>>) {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let record = recorded.clone();
    let relay = udp_relay(server, move |leg, datagram| {
        if leg == Leg::FromClient && datagram.first().is_some_and(|first| first & 0x80 == 0) {
            record.lock().expect("the record").push(datagram.to_vec());
        }
        Relayed::Forward
    })
    .await;
    (relay, recorded)
}

/// The answers to a short-header packet of a connection that the server at
/// `server` has forgotten, sent again from the address the connection used
/// and from another.
///
/// A client connects to `server` through a relay that records its
/// short-header packets, waits for the server's first uni stream (whose 1-RTT
/// packets the client acknowledges in short-header packets of its own), and
/// closes the connection. `open_connections` reads how many connections the
/// server's endpoint holds; it must count this one before the close, and the
/// replay goes out once it reads zero, which is when quinn has drained the
/// connection and removed its connection IDs from the endpoint's index.
async fn replay_of_a_forgotten_connection(
    server: SocketAddr,
    ca: &CertificateDer<'static>,
    open_connections: impl Fn() -> usize,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (mut relay, recorded) = recording_relay(server).await;

    let endpoint = client_endpoint(ca, &["h3"]);
    let connection = endpoint
        .connect(relay.addr, "localhost")
        .expect("start connecting")
        .await
        .expect("a handshake through the relay");
    connection
        .accept_uni()
        .await
        .expect("the server's first uni stream");
    let deadline = tokio::time::Instant::now() + common::TIMEOUT;
    let packet = loop {
        let first = recorded.lock().expect("the record").first().cloned();
        if let Some(packet) = first {
            break packet;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the client sent no short-header packet"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    // quinn-proto answers nothing shorter than 22 bytes with a reset, so a
    // shorter packet would prove nothing.
    assert!(packet.len() >= 22, "{} bytes", packet.len());
    assert_eq!(open_connections(), 1, "the server holds the connection");
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    let deadline = tokio::time::Instant::now() + common::TIMEOUT;
    while open_connections() != 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the server still holds the connection"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Stopped, so that what comes back to the relay's socket is read here.
    relay.task.abort();
    let _ = (&mut relay.task).await;

    let replay = std::slice::from_ref(&packet);
    let same = udp_answers_on(&relay.socket, server, replay, CLIENT_IDLE).await;
    let other = udp_answers(server, replay, CLIENT_IDLE).await;
    (same, other)
}

/// A short-header packet of a connection the server has forgotten draws
/// nothing, sent again from the address the connection used or from any
/// other. quinn would answer it with a Stateless Reset (RFC 9000 §10.3),
/// because its connection ID is one the endpoint issued and passes the
/// default generator's `validate`; `quic::cid` makes that check fail for every
/// connection ID, which turns the reset into a silent drop. The gate is off,
/// because a short header passes the gate whether it is on or not.
///
/// The control below runs the same replay against quinn's own server, whose
/// endpoint configuration is the default, and asserts the reset at both
/// addresses. So the replayed packet is one that draws a reset when nothing
/// removes it, and it leaves the probing sockets.
#[tokio::test]
async fn a_packet_of_a_forgotten_connection_draws_no_stateless_reset() {
    let server = TestServer::start_with(GATE_OFF).await;

    let (same, other) =
        replay_of_a_forgotten_connection(server.addr, &server.ca, || server.open_connections())
            .await;

    assert!(
        same.is_empty() && other.is_empty(),
        "replayed, it drew {} datagrams at the connection's own address and {} at another",
        same.len(),
        other.len()
    );
}

/// The control of the test above: quinn's server with its default connection
/// ID generator answers the same replay with a Stateless Reset, a
/// short-header datagram, at the connection's own address and at another.
#[tokio::test]
async fn a_packet_of_a_forgotten_connection_draws_a_stateless_reset_from_quinns_default() {
    let (endpoint, ca) = common::h3_server_endpoint();
    let addr = endpoint.local_addr().expect("the server's address");
    let accepting = endpoint.clone();
    let serving = tokio::spawn(async move {
        let connection = accepting
            .accept()
            .await
            .expect("an incoming connection")
            .await
            .expect("the server side of the handshake");
        let mut stream = connection.open_uni().await.expect("a uni stream");
        stream
            .write_all(b"x")
            .await
            .expect("write to the uni stream");
        stream.finish().expect("finish the uni stream");
        connection.closed().await;
    });

    let (same, other) =
        replay_of_a_forgotten_connection(addr, &ca, || endpoint.open_connections()).await;
    serving.await.expect("the serving task");

    for (answers, at) in [(&same, "its own address"), (&other, "another address")] {
        assert!(
            answers
                .first()
                .is_some_and(|reset| reset.first().is_some_and(|first| first & 0x80 == 0)),
            "replayed at {at}, it drew {answers:?} and not a Stateless Reset"
        );
    }
}

/// An Initial that arrives during the shutdown grace draws nothing, with the
/// gate off.
///
/// `Server::drain` removes the endpoint's server configuration, and
/// quinn-proto 0.11.19 `Endpoint::handle_first_packet` answers an Initial it
/// cannot route with a Stateless Reset when there is none, before it reads
/// anything past the header. So the probe needs no sealed payload: a QUIC v1
/// Initial header with an eight-byte Destination Connection ID and 1200 bytes
/// in all. Without `gate::Expected::close` in the drain this probe drew one
/// short-header datagram.
///
/// A connection that never closes its tunnel keeps the server in its grace
/// period while the probe is out.
///
/// The probe waits for the drain's "shutting down: no new connections" line,
/// which `Server::drain` writes after it has closed the gate's expected set and
/// removed the server configuration. Its `grace_secs=3` is this test's own
/// grace period, which tells it from a drain of any other test here.
#[tokio::test]
async fn an_initial_during_the_shutdown_grace_draws_no_stateless_reset() {
    let log = SharedBuffer::shared(LOG_FILTER);
    let mut server =
        TestServer::start_with(&format!("shutdown_grace = 3\n{}", common::ALLOW_PRIVATE)).await;
    let target = common::spawn_echo_target().await;
    let mut client = common::H3Client::connect(&server).await;
    let mut stream = common::open_tcp_tunnel(&mut client, &target.to_string()).await;
    common::echoes(&mut stream, b"held open").await;

    // Before the drain the same bytes are an Initial that does not decrypt,
    // which quinn drops without a reply, so silence then proves nothing; the
    // probe is sent only after the drain has begun.
    let mark = log.mark();
    server.shutdown();
    log.wait_for_line(mark, &["log_id=\"7x7xt92f\"", "grace_secs=3"])
        .await;

    let mut initial = vec![0xc0]; // long header, fixed bit, Initial type
    initial.extend_from_slice(&1u32.to_be_bytes());
    initial.push(8); // Destination Connection ID length
    initial.extend_from_slice(&[0xcd; 8]);
    initial.push(0); // Source Connection ID length
    initial.push(0); // token length
    initial.extend_from_slice(&0x4400u16.to_be_bytes()); // Length, two bytes
    initial.resize(1200, 0x5a);

    // Sent through a relay that counts what it carries to the server and
    // carries every answer back, so that the silence is the server's and not
    // that of a probe that never left its socket.
    let carried = Arc::new(AtomicUsize::new(0));
    let count = carried.clone();
    let tap = udp_relay(server.addr, move |leg, _| {
        if leg == Leg::FromClient {
            count.fetch_add(1, Ordering::Relaxed);
        }
        Relayed::Forward
    })
    .await;
    let heard = common::udp_answers(
        tap.addr,
        std::slice::from_ref(&initial),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(
        carried.load(Ordering::Relaxed),
        1,
        "the probe must have been carried to the server"
    );
    assert!(
        heard.is_empty(),
        "an Initial during the grace drew {} datagrams, the first of {} bytes",
        heard.len(),
        heard.first().map_or(0, Vec::len)
    );

    // The tunnel was still being served while the probe was out, so the
    // silence is the grace period's and not a stopped server's.
    common::echoes(&mut stream, b"still up").await;
    server.wait_until_stopped(common::STOP_TIMEOUT).await;
}

// ---------------------------------------------------------------------------
// The second gate: a ClientHello too large for one Initial packet
// ---------------------------------------------------------------------------

/// A big ClientHello naming a host on the list still opens a connection.
///
/// The fail-open branch has to be open in *both* directions: a first flight the
/// socket-level check could not finish reading is passed on, and the handshake
/// then has to succeed on its own merits.
#[tokio::test]
async fn a_client_hello_too_large_for_one_packet_still_reaches_the_server() {
    let server = TestServer::start_with_certificate_names(GATE_LOCALHOST, &[OTHER]).await;
    let alpn = bulk_alpn();
    let alpn: Vec<&str> = alpn.iter().map(String::as_str).collect();
    let endpoint = impatient_offering(&server.ca, &alpn);

    let connection = finish_connect_as(&endpoint, server.addr, "localhost")
        .await
        .expect("a large ClientHello naming the right host must still connect");
    drop(connection);
}

/// The same ClientHello naming somebody else is refused a layer up, with an
/// alert rather than with silence.
///
/// This is the one hole the gate has and it is deliberate: refusing a first
/// flight before its extensions arrive would make a large ClientHello
/// unreachable, so such a handshake reaches rustls and is turned away by the
/// certificate resolver. What the test pins is that it *is* turned away — and
/// that the refusal is an answer, which is what D106 records as the cost.
#[tokio::test]
async fn a_large_client_hello_naming_another_host_is_refused_by_the_certificate_resolver() {
    let server = TestServer::start_with_certificate_names(GATE_LOCALHOST, &[OTHER]).await;
    let alpn = bulk_alpn();
    let alpn: Vec<&str> = alpn.iter().map(String::as_str).collect();
    let endpoint = impatient_offering(&server.ca, &alpn);

    let error = finish_connect_as(&endpoint, server.addr, OTHER)
        .await
        .expect_err("no certificate is resolved for a name that is not on the list");

    assert!(
        !matches!(error, quinn::ConnectionError::TimedOut),
        "a ClientHello the socket gate could not finish reading must reach TLS: {error:?}"
    );
}

// ---------------------------------------------------------------------------
// (d) A reload moves the list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_reload_replaces_the_names_the_gate_admits() {
    let server = TestServer::start_with_certificate_names(GATE_LOCALHOST, &[OTHER]).await;

    // Before: localhost is answered, other.example is not.
    let opened = assert_answered(&server, "localhost").await;
    drop(opened);
    assert_silent(&server, OTHER).await;

    server.rewrite_config(GATE_OTHER);
    server.reload().expect("the new list must load");

    // After: exactly the other way round, on the same running endpoint and the
    // same socket -- a reload cannot rebind, so this is the gate's own list
    // moving rather than a new server.
    let opened = assert_answered(&server, OTHER).await;
    drop(opened);
    assert_silent(&server, "localhost").await;
}

// ---------------------------------------------------------------------------
// (e) With the gate off, nothing changed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_empty_list_answers_to_any_name_the_certificate_covers() {
    let server = TestServer::start_with_certificate_names(GATE_OFF, &[OTHER]).await;

    // The same client and the same name that time out in the first test here.
    let opened = assert_answered(&server, OTHER).await;
    drop(opened);
    let opened = assert_answered(&server, "localhost").await;
    drop(opened);
}

/// With the gate off, a name the certificate does *not* cover still gets an
/// answer — the wrong one, from the client's point of view, but an answer.
///
/// This is what separates "the gate is off" from "the gate is on and this name
/// happens to be allowed": off, the server replies to everybody and the client
/// is the one that objects.
#[tokio::test]
async fn an_empty_list_answers_even_a_name_it_cannot_prove() {
    let server = TestServer::start_with(GATE_OFF).await;
    let endpoint = impatient(&server.ca);

    let error = finish_connect_as(&endpoint, server.addr, "nobody.example")
        .await
        .expect_err("the certificate cannot prove this name");

    assert!(
        !matches!(error, quinn::ConnectionError::TimedOut),
        "with the gate off the server must reply, and the client reject it: {error:?}"
    );
}
