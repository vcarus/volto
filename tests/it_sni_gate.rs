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

use std::net::SocketAddr;
use std::panic::Location;
use std::time::Duration;

use bytes::Bytes;
use common::{
    ALLOW_PRIVATE, GATE_LOCALHOST, H3Client, TestServer, bulk_alpn, client_endpoint_with_transport,
    finish_connect_as, open_tcp_tunnel, open_udp_session, read_at_least, spawn_echo_target,
    spawn_udp_echo_target, udp_answer, udp_round_trip,
};
use rustls::pki_types::CertificateDer;

/// A second name on the test certificate, so a refusal and a mismatch differ.
const OTHER: &str = "other.example";

/// The gate on, naming only [`OTHER`].
const GATE_OTHER: &str =
    "[security]\nallow_private_networks = true\nexpected_sni = [\"other.example\"]\n";

/// The gate off, which is the shipped default.
const GATE_OFF: &str = ALLOW_PRIVATE;

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

        assert!(
            matches!(error, quinn::ConnectionError::TimedOut),
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

    assert!(
        matches!(error, quinn::ConnectionError::TimedOut),
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
    tunnel
        .send_data(Bytes::from_static(b"through the gate"))
        .await
        .expect("send payload");
    assert_eq!(
        read_at_least(&mut tunnel, b"through the gate".len()).await,
        b"through the gate"
    );

    let (session, _stream) = open_udp_session(&mut client, &server, udp_target).await;
    assert_eq!(
        udp_round_trip(&client, session, b"and a datagram").await,
        b"and a datagram".as_slice()
    );
}

// ---------------------------------------------------------------------------
// (c) A version-negotiation probe: answered with the gate off, silent with it on
// ---------------------------------------------------------------------------

/// A 1200-byte long-header packet naming a QUIC version nobody speaks.
///
/// Large enough that RFC 9000 §5.2.2's "if the packet is large enough to
/// initiate a new connection" holds, so a server that follows that SHOULD
/// answers it. Everything before the version field is well formed, because
/// quinn reads the connection IDs out before it looks at the version.
fn unknown_version_probe() -> Vec<u8> {
    let mut packet = vec![0xc0]; // long header, fixed bit, Initial type
    packet.extend_from_slice(&0xdead_beefu32.to_be_bytes());
    packet.push(8); // Destination Connection ID length
    packet.extend_from_slice(&[0xab; 8]);
    packet.push(0); // Source Connection ID length
    packet.resize(1200, 0);
    packet
}

/// Sends `probe` from a fresh socket and returns whatever comes back.
async fn probe(addr: SocketAddr, probe: &[u8]) -> Option<Vec<u8>> {
    udp_answer(addr, probe, CLIENT_IDLE).await
}

#[tokio::test]
async fn an_unknown_version_draws_a_version_negotiation_packet_with_the_gate_off() {
    let server = TestServer::start_with(GATE_OFF).await;

    let answer = probe(server.addr, &unknown_version_probe())
        .await
        .expect("with the gate off, quinn answers an unsupported version");

    // RFC 9000 §17.2.1: a Version Negotiation packet is a long header whose
    // Version field is zero.
    assert!(
        answer.len() >= 5,
        "a Version Negotiation packet is longer than this: {answer:?}"
    );
    assert_ne!(answer[0] & 0x80, 0, "a long header was expected");
    assert_eq!(
        u32::from_be_bytes([answer[1], answer[2], answer[3], answer[4]]),
        0,
        "a Version Negotiation packet carries version 0"
    );
}

#[tokio::test]
async fn an_unknown_version_draws_nothing_at_all_with_the_gate_on() {
    let server = TestServer::start_with(GATE_LOCALHOST).await;

    assert!(
        probe(server.addr, &unknown_version_probe()).await.is_none(),
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
