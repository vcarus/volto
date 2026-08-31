//! Inter-tunnel isolation: what one tunnel on a connection can do to the rest.
//!
//! One QUIC connection from Surge multiplexes every tunnel, so everything those
//! tunnels share is a candidate for head-of-line blocking. Each test here holds
//! one tunnel in the worst state it can be held in and then asks a *different*
//! tunnel on the same connection to do its ordinary work.
//!
//! What is shared, and which test covers it:
//!
//! * the per-connection datagram router (`h3::connection::serve_peer`), the one
//!   task that decodes and routes inbound HTTP Datagrams for every CONNECT-UDP
//!   session on the connection (D79) --
//!   [`a_session_that_never_drains_its_queue_does_not_stall_the_router`] and
//!   [`a_session_that_never_drains_its_queue_does_not_stall_the_accept_loop`];
//! * the accept loop (`conn::handle`), the one task that turns request streams
//!   into tunnels --
//!   [`a_request_whose_headers_never_arrive_does_not_delay_other_requests`];
//! * the TCP relay's own state, which is per tunnel and shared with nothing --
//!   [`a_tcp_tunnel_whose_target_stops_reading_does_not_stall_its_neighbours`];
//! * the connection's aggregate receive credit (`quic::CONNECTION_RECEIVE_WINDOW`
//!   against `quic::STREAM_RECEIVE_WINDOW`, D47), the one shared resource a
//!   tunnel genuinely can take from its neighbours --
//!   [`a_connection_out_of_stream_credit_keeps_its_datagrams_and_downloads`] and
//!   the `#[ignore]`d [`measure_the_stalled_tunnel_crossover`].

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use bytes::{Buf, Bytes};
use common::{
    echoes, open_tcp_tunnel, open_udp_session, send_udp_payload, spawn_echo_target,
    spawn_flooding_udp_target, spawn_udp_echo_target, ClientStream, H3Client, TestServer, TIMEOUT,
};
use volto::capsule::{self, Capsule, CapsuleDecoder};

/// A per-stream receive window too small for a flooding target's replies, so
/// the server is parked in its write to the client rather than racing it.
///
/// The same value, and the same trick, as
/// `it_udp::a_client_that_stops_reading_capsules_gets_the_stream_reset`.
const STREAM_WINDOW: u32 = 64 * 1024;

/// Long enough for the server to have filled a window and parked in its write.
///
/// Not a synchronisation point -- nothing on the wire says "the peer is now
/// blocked in a write" -- so it is a wait rather than a wake-up. What makes it
/// sound is which way it can be wrong: too short leaves the session or the pump
/// still draining, which only makes the assertion that follows *easier* to pass,
/// so a slow host cannot turn a real stall into a green test. The stall it
/// produces lasts a whole `udp_session_timeout` (180 s by default), so there is
/// no upper end to get wrong either.
const PARK: Duration = Duration::from_millis(750);

/// Reads DATAGRAM capsules off a session's request stream until `payload`
/// arrives.
///
/// The capsule fallback is the reply path for the sessions in the first two
/// tests: their client never advertises `SETTINGS_H3_DATAGRAM`, so RFC 9297
/// §2.1.1 bars the server from answering in QUIC datagrams. What the client
/// still does is *send* them, which is the half those tests are about -- the
/// inbound router is the shared thing, and it routes whatever arrives.
async fn capsule_reply_is(stream: &mut ClientStream, payload: &[u8]) {
    let mut decoder = CapsuleDecoder::new();

    let found = tokio::time::timeout(TIMEOUT, async {
        loop {
            while let Some(capsule) = decoder.next_capsule().expect("well-formed capsules") {
                let Capsule::Datagram {
                    context_id,
                    payload: got,
                } = capsule;
                assert_eq!(context_id, 0, "a UDP payload travels under context 0");
                if got == payload {
                    return;
                }
            }

            let chunk = stream
                .recv_data()
                .await
                .expect("the session's stream must stay readable")
                .expect("the session's stream must not end");
            decoder.push(&Bytes::copy_from_slice(chunk.chunk()));
        }
    })
    .await;

    assert!(
        found.is_ok(),
        "no reply carrying {payload:?} arrived within {TIMEOUT:?}"
    );
}

/// A session whose task is parked, with its inbound queue full, must not stop
/// the connection's router from serving every other session on it.
///
/// # The shape being pinned
///
/// Inbound HTTP Datagrams for *every* session on a connection are decoded and
/// routed by one task (D79), which hands each payload to the bounded channel its
/// session claimed. Bounded means a full channel is a decision, and there is
/// only one right answer: drop the packet. The wrong one -- waiting for room --
/// reads as the polite thing to do and costs nothing on a queue that drains, but
/// a session whose task is not running never drains, and the router would then
/// be parked on it with every other session's datagrams behind it. Losing a UDP
/// packet is what a UDP tunnel promises; a stalled router is not.
///
/// # How the queue is made to stay full
///
/// A session is parked whenever it is inside `forward_to_client`, and the
/// capsule fallback is where that can last: `send_data` applies the client's
/// flow control, so a client that stops reading its own session's stream parks
/// the server there for a whole `udp_session_timeout`. That session's loop is
/// then not at its `select!` at all, so nothing takes anything off its inbound
/// queue, and `INBOUND_QUEUE_DEPTH` datagrams are enough to fill it.
///
/// The neighbour is an ordinary echo session on the same connection, asked for
/// an ordinary round trip.
///
/// Red check: making `Shared::deliver` await `Sender::send` instead of
/// `try_send` fails this and the test below, and nothing else in the suite.
#[tokio::test]
async fn a_session_that_never_drains_its_queue_does_not_stall_the_router() {
    let server = TestServer::start().await;
    let live_target = spawn_udp_echo_target().await;

    let (mut client, stalled_qsid, _stalled) = a_session_with_a_full_queue(&server).await;
    let (live_qsid, mut live) = open_udp_session(&mut client, &server, live_target).await;

    fill_inbound_queue(&client, stalled_qsid);

    // The whole test: a neighbour's round trip, through the router that is now
    // holding a full queue it cannot deliver to.
    send_udp_payload(&client.quic, live_qsid, b"neighbour");
    capsule_reply_is(&mut live, b"neighbour").await;

    assert!(
        client.quic.close_reason().is_none(),
        "a full queue on one session is met with drops, never with a close"
    );
}

/// The same isolation asked of the *accept* path: a session opened after the
/// flood must still be established and usable.
///
/// Distinct from the round trip above because a different task answers for it.
/// The router is `serve_peer`; accepting a request stream is `conn::handle`'s
/// loop, and a session could not be opened at all if the two were ever folded
/// together.
#[tokio::test]
async fn a_session_that_never_drains_its_queue_does_not_stall_the_accept_loop() {
    let server = TestServer::start().await;
    let echo = spawn_udp_echo_target().await;

    let (mut client, stalled_qsid, _stalled) = a_session_with_a_full_queue(&server).await;
    fill_inbound_queue(&client, stalled_qsid);

    // Opened *after* the flood, and it has to work end to end rather than
    // merely be answered.
    let (fresh_qsid, mut fresh) = open_udp_session(&mut client, &server, echo).await;
    send_udp_payload(&client.quic, fresh_qsid, b"fresh");
    capsule_reply_is(&mut fresh, b"fresh").await;
}

/// A client, and a CONNECT-UDP session on it whose task is parked in its write
/// to that client.
///
/// The session's stream is handed back so it stays open and unread; dropping it
/// would let the parked write finish and the session start draining again.
async fn a_session_with_a_full_queue(server: &TestServer) -> (H3Client, u64, ClientStream) {
    let target = spawn_flooding_udp_target(4096, 1200).await;
    let mut client =
        H3Client::connect_without_datagrams_with_stream_window(server, STREAM_WINDOW).await;

    let (qsid, mut stalled) = open_udp_session(&mut client, server, target).await;

    // One capsule wakes the flooding target; from here its replies fill the
    // window on this stream and the server parks in its write, because nothing
    // ever reads it.
    stalled
        .send_data(capsule::encode_datagram(0, b"go"))
        .await
        .expect("send the trigger capsule");
    tokio::time::sleep(PARK).await;

    (client, qsid, stalled)
}

/// Sends four times `INBOUND_QUEUE_DEPTH` datagrams at one session, so its queue
/// is full and staying full rather than merely reaching its last slot.
fn fill_inbound_queue(client: &H3Client, quarter_stream_id: u64) {
    for _ in 0..4 * volto::h3::connection::INBOUND_QUEUE_DEPTH {
        send_udp_payload(&client.quic, quarter_stream_id, b"queued");
    }
}

/// A request stream whose HEADERS never finish arriving must not hold up the
/// requests behind it.
///
/// # The shape being pinned
///
/// A request stream is accepted the moment the peer opens it, and reading its
/// field section is a wait on the peer: `Resolver::resolve` gives it one whole
/// `max_idle_timeout` (D76) before resetting the stream. The accept loop must
/// not be inside that wait -- it hands each accepted stream to a task of its own
/// and goes straight back to `accept()`. A loop that resolved inline would serve
/// requests strictly in the order they were opened, so one peer sending three
/// bytes of a field section and stopping would cost every request behind it a
/// whole idle timeout.
///
/// The bound below is the assertion, and `max_idle_timeout` is left at the
/// server's default 60 s on purpose: the gap between "a few milliseconds" and "a
/// minute" is what makes this a verdict rather than a timing measurement, and no
/// scheduling noise fills it.
///
/// Red check: replacing the `tokio::spawn` in `conn::handle` with an inline
/// `handle_request(..).await` fails this and nothing else here.
#[tokio::test]
async fn a_request_whose_headers_never_arrive_does_not_delay_other_requests() {
    /// Stalled streams to leave in front of the request that matters. Under
    /// `quic::INITIAL_BIDI_STREAMS`, so no authentication dance is needed.
    const STALLED: usize = 8;

    /// Far under the server's `max_idle_timeout` (60 s), which is what a
    /// serialised accept loop would charge for each stalled stream.
    const WITHIN: Duration = Duration::from_secs(5);

    let server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // Each of these opens a request stream, declares a HEADERS frame and then
    // sends almost none of it. Both halves are held so quinn neither finishes
    // nor resets the stream.
    let mut _stalled = Vec::new();
    for _ in 0..STALLED {
        let (mut send, recv) = client.quic.open_bi().await.expect("open a request stream");
        send.write_all(&PARTIAL_HEADERS)
            .await
            .expect("write a partial field section");
        _stalled.push((send, recv));
    }

    // The request behind them, which owes nothing to any of them.
    let opened =
        tokio::time::timeout(WITHIN, open_tcp_tunnel(&mut client, &target.to_string())).await;
    let mut tunnel = opened.unwrap_or_else(|_| {
        panic!(
            "a tunnel opened behind {STALLED} stalled request streams took longer than {WITHIN:?}"
        )
    });

    // Established, not merely answered.
    echoes(&mut tunnel, b"behind the stall").await;
}

/// A HEADERS frame declaring 4096 bytes of field section, with three of them.
///
/// Enough for the server to have accepted a request stream and to be waiting on
/// its field section, and never enough for the wait to end.
const PARTIAL_HEADERS: [u8; 6] = [0x01, 0x50, 0x00, 0xab, 0xcd, 0xef];

/// A TCP tunnel parked in its write to a target that has stopped reading must
/// not stall the tunnel beside it.
///
/// # The shape being pinned
///
/// `client_to_target` reads a chunk off the request stream and writes it to the
/// target socket, and that write parks for as long as the target refuses to
/// read -- which is the right answer, because back-pressure is what a proxy owes
/// both ends. What must not follow from it is anything shared: the pump holds no
/// lock, no connection-wide buffer and no place in a queue.
///
/// One stalled tunnel is the subject, not eight: eight is where the
/// *connection's* aggregate receive credit runs out, and that is a different
/// mechanism with a test of its own below.
///
/// The stalled target is a listener that never accepts. The connection completes
/// in the kernel's backlog, so `connect` succeeds and the socket has a receive
/// buffer that fills and is never drained -- a target that has stopped reading,
/// with no cooperation from any test code.
#[tokio::test]
async fn a_tcp_tunnel_whose_target_stops_reading_does_not_stall_its_neighbours() {
    let server = TestServer::start().await;
    let (deaf, deaf_addr) = deaf_target().await;
    let echo = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stalled = open_tcp_tunnel(&mut client, &deaf_addr.to_string()).await;
    let mut live = open_tcp_tunnel(&mut client, &echo.to_string()).await;

    let pushed = push_until_parked(&mut stalled).await;
    assert!(
        pushed > 0,
        "the stalled tunnel took nothing at all, so nothing was proved about it"
    );

    // The neighbour, on the same connection, through the same server.
    live.send_data(Bytes::from_static(b"unaffected"))
        .await
        .expect("write to the live tunnel");
    let echoed = tokio::time::timeout(
        TIMEOUT,
        common::read_at_least(&mut live, b"unaffected".len()),
    )
    .await
    .expect("the live tunnel answered while its neighbour was parked");
    assert_eq!(&echoed, b"unaffected");

    drop(deaf);
}

/// A connection whose aggregate receive credit is exhausted still carries the
/// datagrams and the downloads of the tunnels already on it.
///
/// # What this is about
///
/// D47 records the one place a tunnel genuinely takes something from its
/// neighbours: `stream_receive_window` (2 MiB) against `receive_window`
/// (16 MiB) means eight tunnels whose targets stop reading hold every byte of
/// the connection's aggregate credit, and the client can then send nothing on
/// any stream. That is the priced cost of multiplexing everything onto one
/// connection, not a defect, and it is not what this pins.
///
/// What this pins is how far it reaches, which D47 states more broadly than the
/// wire does ("every other tunnel stops together"). Measured here, exhausted
/// credit stops exactly one thing: the client's *stream* sending direction.
///
/// * an open CONNECT-UDP session keeps working in both directions, because
///   RFC 9221 §5.3 puts DATAGRAM frames outside flow control entirely -- "DATAGRAM
///   frames do not provide any explicit flow control signaling and do not
///   contribute to any per-flow or connection-wide data limit" -- so Surge's DNS
///   keeps resolving through a connection whose stream side is frozen;
/// * an open TCP tunnel keeps *downloading*, because the server-to-client
///   direction spends the client's credit and not this one;
/// * what stops is opening anything new and uploading anything, both of which
///   are the client writing to a stream. `stall_the_connection` asserts that, so
///   it is the precondition rather than a claim of its own.
#[tokio::test]
async fn a_connection_out_of_stream_credit_keeps_its_datagrams_and_downloads() {
    let server = TestServer::start().await;
    let (deaf, deaf_addr) = deaf_target().await;
    let udp_echo = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // Both opened while the connection is still healthy.
    let (qsid, _session) = open_udp_session(&mut client, &server, udp_echo).await;
    let (pusher, pusher_addr) = pushing_target().await;
    let mut download = open_tcp_tunnel(&mut client, &pusher_addr.to_string()).await;
    common::read_at_least(&mut download, PUSH_CHUNK).await;

    let _held = stall_the_connection(&mut client, deaf_addr).await;

    // The download direction of a tunnel opened before the freeze.
    let flowing =
        tokio::time::timeout(TIMEOUT, common::read_at_least(&mut download, PUSH_CHUNK)).await;
    assert!(
        flowing.is_ok(),
        "a tunnel's download direction spends the client's credit, not the server's"
    );

    // And the session, whose payloads never touch a stream at all.
    send_udp_payload(&client.quic, qsid, b"dns");
    let answered = tokio::time::timeout(TIMEOUT, async {
        loop {
            let reply = common::recv_datagram(&client.quic).await;
            if reply.quarter_stream_id == qsid && reply.payload[..] == b"dns"[..] {
                return;
            }
        }
    })
    .await;
    assert!(
        answered.is_ok(),
        "QUIC datagrams are outside stream flow control and must survive the freeze"
    );

    drop(pusher);
    drop(deaf);
}

/// Reports how many stalled tunnels it takes to exhaust one connection's
/// aggregate receive credit.
///
/// D47 derives the number -- `receive_window` / `stream_receive_window`, so 8 at
/// the shipped values -- and this is what measures it. `#[ignore]`d because it
/// is a measurement rather than a verdict: what it prints depends on how much of
/// each stream's window the target's own socket buffer absorbs, so the answer is
/// a small range around the arithmetic rather than a constant to assert.
///
/// Run it when the windows move:
///
/// ```text
/// cargo test --test it_isolation -- --ignored --nocapture measure_the_stalled
/// ```
#[tokio::test]
#[ignore = "a measurement, printed rather than asserted; see the doc comment"]
async fn measure_the_stalled_tunnel_crossover() {
    let server = TestServer::start().await;
    let (deaf, deaf_addr) = deaf_target().await;
    let mut client = H3Client::connect(&server).await;

    let held = stall_the_connection(&mut client, deaf_addr).await;
    println!(
        "stalled tunnels needed to exhaust the connection's receive credit: {}",
        held.len()
    );

    drop(deaf);
}

/// A listener that never accepts: a target whose socket buffer fills and is
/// never drained.
///
/// The connection completes in the kernel's backlog, so `connect` succeeds and
/// nothing in the test has to cooperate to keep the target silent.
async fn deaf_target() -> (tokio::net::TcpListener, SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener that never accepts");
    let address = listener.local_addr().expect("listener address");
    (listener, address)
}

/// Bytes the pushing target sends per burst.
const PUSH_CHUNK: usize = 4096;

/// A TCP target that sends without being asked, so a tunnel's download
/// direction can be watched with nothing travelling the other way.
async fn pushing_target() -> (tokio::task::JoinHandle<()>, SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a pushing target");
    let address = listener.local_addr().expect("target address");

    let handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                while socket.write_all(&[0x33u8; PUSH_CHUNK]).await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            });
        }
    });

    (handle, address)
}

/// Writes into `tunnel` until the write parks, reporting how much it took.
///
/// The park is the state every test using this wants: the server's pump has
/// stopped reading the request stream, so the bytes still on it are held against
/// the connection's aggregate credit.
async fn push_until_parked(tunnel: &mut ClientStream) -> usize {
    /// Comfortably past a stream window plus any loopback socket buffer.
    const CEILING: usize = 8 * 1024 * 1024;

    let block = Bytes::from(vec![0x7eu8; 64 * 1024]);
    let mut pushed = 0usize;

    while pushed < CEILING {
        match tokio::time::timeout(PARK, tunnel.send_data(block.clone())).await {
            Ok(Ok(())) => pushed += block.len(),
            // Parked: what the caller is after.
            Err(_elapsed) => break,
            Ok(Err(error)) => panic!("the stalled tunnel failed instead of parking: {error}"),
        }
    }

    pushed
}

/// Opens stalled tunnels until the connection's aggregate receive credit is
/// gone, and hands back the tunnels holding it.
///
/// Stops on the measured condition rather than a fixed count, because how much
/// of each stream's window survives on the connection depends on how much the
/// target's own socket buffer swallowed first. The panic is the point of the
/// cap: a caller of this needs the connection frozen, and a caller that got a
/// list of healthy tunnels instead would go on to assert nothing at all.
async fn stall_the_connection(client: &mut H3Client, deaf: SocketAddr) -> Vec<ClientStream> {
    /// Well past `receive_window` / `stream_receive_window` = 8.
    const CAP: usize = 32;

    let mut held = Vec::new();

    for _ in 0..CAP {
        if out_of_stream_credit(client).await {
            return held;
        }

        let mut tunnel = open_tcp_tunnel(client, &deaf.to_string()).await;
        push_until_parked(&mut tunnel).await;
        held.push(tunnel);
    }

    panic!("{CAP} stalled tunnels did not exhaust the connection's receive credit");
}

/// Whether the connection has any aggregate credit left for the client to write
/// with.
///
/// Asked on a stream of its own, because a stream that is already blocked on its
/// *own* window would answer the wrong question. The few bytes written are a
/// HEADERS frame the peer will wait out and then reset (D76); a probe that found
/// credit has spent none of it beyond those bytes.
async fn out_of_stream_credit(client: &H3Client) -> bool {
    /// Long enough that a connection with credit answers, short enough that the
    /// walk up to the crossover stays quick.
    const PROBE: Duration = Duration::from_millis(400);

    let (mut send, _recv) = client.quic.open_bi().await.expect("open a probe stream");
    let blocked = tokio::time::timeout(PROBE, send.write_all(&PARTIAL_HEADERS))
        .await
        .is_err();
    // H3_REQUEST_CANCELLED (RFC 9114 §8.1): this probe's request is going
    // nowhere, and the code says so rather than leaving the peer to time it out.
    let _ = send.reset(quinn::VarInt::from_u32(0x10c));
    blocked
}
