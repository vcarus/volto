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
