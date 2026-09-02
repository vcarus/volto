//! One connection, worked hard: the failures a short test cannot show.
//!
//! Every other binary in this suite opens a handful of tunnels and asserts what
//! happens to them. Nothing asserts what happens to the *connection* after a
//! few hundred tunnels have come and gone on it — and that is where a different
//! class of fault lives. A leak of one map entry, one task, one descriptor or
//! one uncounted event per cycle is invisible at N = 3 and fatal on a server
//! that runs for weeks. So is a counter that double-counts by one in a rare
//! branch, or an idle deadline that is re-armed by addition instead of from the
//! clock.
//!
//! # What is driven
//!
//! One QUIC connection, [`CYCLES`] sequential mixed cycles on it — a TCP
//! CONNECT tunnel and a CONNECT-UDP session open at the same time, each used,
//! each closed, the two kinds alternating how they close — followed by
//! [`BATCHES`] batches of [`BATCH_WIDTH`] tunnels of each kind open
//! concurrently. Then the same question one level up: [`CONNECTION_CYCLES`]
//! whole connections, each opening a tunnel of each kind before it goes.
//!
//! Every number here is a constant at the top of the file: raise [`CYCLES`]
//! alone for a deep local run — `CYCLES = 5_000` is 10 060 tunnels and 15 000
//! dropped datagrams on one connection, takes about a minute in a debug build,
//! and is what these assertions were developed against. The committed figures
//! are sized for CI, where this runs on every push on two platforms.
//!
//! # What is asserted, and why each is a soak assertion
//!
//! * **Tunnel slots and stream credit come back.** `max_targets_per_conn` and
//!   `max_streams_bidi` are both set to [`CHURN_SLOTS`], far below the number of
//!   tunnels and streams the run uses. A slot that is not released fails the run
//!   at cycle ~16 with a 503; QUIC stream credit that is never returned parks
//!   `open_bi` for ever a cycle later. Neither is reachable at the scale the
//!   rest of the suite runs at: `it_stress` churns 500 tunnels, which is inside
//!   the default 1024-stream credit and so never asks whether any of it comes
//!   back.
//! * **Descriptors are flat.** Sampled mid-run and again at the end, once for
//!   the tunnel churn and once for the connection churn, so process warm-up is
//!   outside each comparison and only the steady state is measured. A socket
//!   leaked per cycle shows up as a count that grew with the cycles.
//! * **A connection gives back everything it held.** Its roster slot above all,
//!   which is asserted on the wire without a counter: the churning server is
//!   given far fewer slots than the run uses connections, and every connection
//!   here authenticates, so a slot that outlived its connection could never be
//!   evicted to make room for the next one.
//! * **The counters on the closing line are exact.** The run drives a known
//!   number of tunnels and a known number of drop-worthy datagrams, three
//!   shapes of them, and the line must report exactly those totals — not
//!   approximately, and not off by the handful that a double-count in one arm
//!   or a missed increment in another would produce. These counters are the
//!   only production-visible trace the drops leave (RFC 9298 §5 and RFC 9297
//!   §2.1 both ask for silence), so nothing else would notice them drifting.
//! * **The UDP idle deadline neither drifts nor sticks.** Sessions kept busy
//!   across many re-arms survive well past the timeout; sessions left alone are
//!   reclaimed at it; and a session that goes quiet after all those re-arms is
//!   reclaimed one timeout later rather than one timeout per re-arm.
//!
//! # Shape of the file
//!
//! One `#[tokio::test]`, because the assertions on the closing line need a
//! capturing subscriber and `tracing_subscriber::fmt().init()` may run once per
//! process — the same reason `it_close_log` is one function.

mod common;

#[path = "common/fds.rs"]
mod fds;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use common::{
    ALLOW_PRIVATE, ClientStream, H3Client, SharedBuffer, TIMEOUT, TestServer, close_and_drain,
    echoes, numeric_field, open_tcp_tunnel, open_udp_session, read_to_end, recv_datagram,
    send_udp_payload, spawn_echo_target, spawn_udp_echo_target, udp_round_trip,
};
use fds::settled_fds;
use volto::datagram;

/// Sequential mixed cycles the committed soak runs.
///
/// One cycle is one TCP tunnel and one CONNECT-UDP session, overlapping, both
/// used and both closed. A hundred and twenty is chosen to clear [`CHURN_SLOTS`]
/// many times over — the point is to run long past every per-connection limit,
/// not to run long — while keeping the whole binary inside a few seconds on the
/// slower of the two CI platforms.
///
/// This is the one-line change for a deeper local run; nothing else in the file
/// needs touching.
const CYCLES: usize = 120;

/// Batches of concurrent tunnels run after the sequential churn.
const BATCHES: usize = 6;

/// Tunnels of each kind opened at once in a batch.
///
/// `2 * BATCH_WIDTH` tunnels are live at the peak, which has to stay under
/// [`CHURN_SLOTS`] with room for the releases still in flight behind the client.
const BATCH_WIDTH: usize = 5;

/// Tunnel slots and QUIC stream credit the connection is given.
///
/// Deliberately far below what the run consumes, so that anything not returned
/// fails the run within a few cycles instead of at some unreachable scale. The
/// headroom over `2 * BATCH_WIDTH` is for the server-side releases that trail
/// the client's view of a closed tunnel by a scheduling turn — the same reason
/// `it_stress` picks a number rather than the exact peak.
const CHURN_SLOTS: u32 = 32;

/// Drop-worthy datagrams sent per cycle, one of each shape.
///
/// Three of the four ways the router drops an inbound datagram: an unknown
/// Context ID, a Quarter Stream ID no session claims, and a datagram cut short
/// of its Context ID. The fourth — a session whose queue is full — is left out
/// on purpose: it is the one shape whose count depends on how fast the session
/// drains, which is a race rather than an arrangement, and this assertion is
/// about exactness.
const DROPS_PER_CYCLE: u64 = 3;

/// Distance from a live Quarter Stream ID to one nothing will ever claim.
///
/// Quarter Stream IDs on a connection are its request stream ids divided by
/// four, so they run 0, 1, 2, ... in step with the requests. Anything this far
/// ahead is past every id this run can reach, which is what makes a datagram
/// addressed to it unroutable for the whole of the soak rather than only until
/// the stream counter catches up.
const UNCLAIMED_OFFSET: u64 = 1_000_000;

/// A Context ID this server does not implement (RFC 9298 §4 reserves only 0).
const UNKNOWN_CONTEXT: u64 = 7;

/// Connections opened, worked and closed one after another.
///
/// The other axis of the same question: a server that runs for weeks churns
/// connections as well as tunnels, and everything a connection owns — its
/// roster slot, its `serve_peer` task, its three unidirectional streams, its
/// routing table — is released by a `Drop` somewhere rather than by a call at
/// the end of a function. Nothing else in the suite opens more than a handful.
const CONNECTION_CYCLES: usize = 60;

/// Connection slots the churning server is given.
///
/// Far below [`CONNECTION_CYCLES`], and the roster's own release path is what
/// keeps the run going: a slot that outlived its connection would leave every
/// entry held by a connection that had authenticated, which is the one state
/// the eviction rule refuses to break into — so the run would stop at
/// connection 17 with a refused handshake rather than at some scale no test
/// reaches.
const CONNECTION_SLOTS: u32 = 16;

/// UDP sessions kept busy in the deadline phase, and sessions left alone.
const DEADLINE_SESSIONS: usize = 3;

/// How long the busy sessions are kept busy, and the interval between pings.
///
/// Twice the one-second `udp_session_timeout` the phase configures, so a session
/// that is not being re-armed is reclaimed twice over inside the window, and
/// twenty re-arms is enough that a deadline pushed out by addition rather than
/// from the clock lands a visible twenty seconds late.
const BUSY_WINDOW: Duration = Duration::from_secs(2);
const PING_INTERVAL: Duration = Duration::from_millis(100);

/// The `udp_session_timeout` the deadline phase runs with, in seconds.
const SESSION_TIMEOUT_SECS: u64 = 1;

/// How long after its last packet a busy session may take to be reclaimed.
///
/// One timeout plus slack for the scheduler. The failure this bounds is not
/// subtle: a deadline that accumulated one timeout per re-arm would be twenty
/// seconds out, and one that was never re-armed at all would have closed the
/// session during the busy window instead.
const RECLAIM_BOUND: Duration = Duration::from_secs(3);

/// How many descriptors the steady state may drift by between two samples.
///
/// Not zero: the runtime opens and closes descriptors of its own — timers,
/// wakers, the odd DNS handle — and a sample is a directory listing rather than
/// a barrier. Measured drift between the two samples on the dev host is zero or
/// one, so this is an order of magnitude of headroom over the noise and still
/// two orders below what a descriptor leaked per cycle would come to.
const FD_SLACK: usize = 12;

/// How long to leave between the descriptor samples [`fds::settled_fds`] takes.
///
/// Longer than `it_os_faults` uses, because what has to drain here is a target
/// socket the server closes after the client has seen the FIN, rather than a
/// refusal that owned nothing.
const FD_SAMPLE_INTERVAL: Duration = Duration::from_millis(50);

/// Sends the three drop-worthy datagram shapes at `live`'s session.
///
/// Two of them name that session and one names an id nothing owns, which is the
/// point: the router has to drop all three and count all three while the session
/// they are aimed at goes on working. The caller fences afterwards.
fn send_the_three_drop_shapes(client: &H3Client, live: u64) {
    // RFC 9298 §5: a Context ID this proxy never registered. Aimed at a live
    // session, so a router that looked the id up before the context would
    // deliver it.
    client
        .quic
        .send_datagram(datagram::encode(live, UNKNOWN_CONTEXT, b"unknown context"))
        .expect("send an unknown-context datagram");

    // RFC 9297 §2.1: a Quarter Stream ID with no session behind it, which is
    // what every datagram in flight past a session's close looks like.
    send_udp_payload(&client.quic, live + UNCLAIMED_OFFSET, b"nowhere");

    // The one malformation RFC 9297 §2.1 does not make a connection error: the
    // Quarter Stream ID parses and the Context ID is simply not there.
    let mut truncated = bytes::BytesMut::new();
    datagram::put_varint(&mut truncated, live);
    client
        .quic
        .send_datagram(truncated.freeze())
        .expect("send a truncated datagram");
}

/// Awaits an open under a bound, naming the cycle if it does not complete.
///
/// The bound is an assertion rather than scaffolding. `open_bi` waits for QUIC
/// stream credit, and credit comes back only once the server is finished with a
/// stream in both directions — so a teardown that leaves streams half-retired
/// does not fail this run, it parks it, and a parked test is a CI timeout with
/// nothing in it to read. Bounding every open turns that back into a failure
/// that says which cycle stopped making progress.
///
/// `what` rather than `#[track_caller]`: the attribute is a no-op on an `async
/// fn` (D66), and the caller here is one of two lines in a loop — which cycle it
/// was is the part worth reporting.
async fn opened<T>(what: &str, open: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(TIMEOUT, open)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{what} did not open within {TIMEOUT:?}: tunnel slots or QUIC stream credit are \
                 not coming back from the tunnels already closed"
            )
        })
}

/// Uses and closes one TCP tunnel, both directions, per RFC 9114 §4.4.
///
/// The client's FIN reaches the target as a write shutdown, the target answers
/// its EOF by closing, and the server finishes its own sending side — so this
/// returns only once the tunnel is over at both ends and its slot, socket and
/// pump tasks are owed back.
async fn use_and_close_tcp(tunnel: &mut ClientStream, payload: &str) {
    // The payload names the tunnel it belongs to, so a mismatch here is a
    // tunnel that received another tunnel's data.
    echoes(tunnel, payload.as_bytes()).await;

    let trailing = close_and_drain(tunnel).await;
    assert!(
        trailing.is_empty(),
        "an echo tunnel owes nothing past its echo, got {trailing:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_long_mixed_run_leaks_nothing_and_counts_everything() {
    let buffer = SharedBuffer::install("volto=info");

    let server = TestServer::start_with(&format!(
        "[limits]\n\
         max_targets_per_conn = {CHURN_SLOTS}\n\
         max_streams_bidi = {CHURN_SLOTS}\n\
         {ALLOW_PRIVATE}"
    ))
    .await;
    let tcp_target = spawn_echo_target().await;
    let tcp_authority = tcp_target.to_string();
    let udp_target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // Everything the closing line will be checked against, accumulated as the
    // run goes rather than computed from the constants at the end: a count
    // derived from the same arithmetic the run uses would agree with a run that
    // did the wrong number of things.
    let mut expected_tunnels = 0u64;
    let mut expected_drops = 0u64;

    // Sampled a third of the way in, once the runtime has grown whatever it is
    // going to grow, so what the end is compared against is a steady state and
    // not a cold process.
    let mut baseline_fds = None;

    // --- Phase 1: sequential mixed cycles, both kinds live at once. ---
    for cycle in 0..CYCLES {
        let mut tcp = opened(
            &format!("the TCP tunnel of cycle {cycle}"),
            open_tcp_tunnel(&mut client, &tcp_authority),
        )
        .await;
        let (qsid, mut udp) = opened(
            &format!("the UDP session of cycle {cycle}"),
            open_udp_session(&mut client, &server, udp_target),
        )
        .await;
        expected_tunnels += 2;

        let payload = format!("cycle-{cycle:05}");
        let echoed = udp_round_trip(&client, qsid, payload.as_bytes()).await;
        assert_eq!(String::from_utf8_lossy(&echoed), payload);

        send_the_three_drop_shapes(&client, qsid);
        expected_drops += DROPS_PER_CYCLE;

        // The fence. The router takes this connection's datagrams in arrival
        // order, so an answer to a datagram sent after the three proves all
        // three have already been judged and counted — which is what makes the
        // total at the end a total and not a snapshot of a race.
        let fenced = udp_round_trip(&client, qsid, b"fence").await;
        assert_eq!(&fenced[..], b"fence");

        use_and_close_tcp(&mut tcp, &payload).await;

        // The two ways a client ends a session, alternating: the tidy FIN that
        // waits for the server's own, and simply letting go — which quinn turns
        // into a FIN plus STOP_SENDING and the server has to treat as the same
        // ending. Both must return the slot, the socket and the routing entry.
        if cycle % 2 == 0 {
            close_and_drain(&mut udp).await;
        } else {
            drop(udp);
        }

        if cycle == CYCLES / 3 {
            baseline_fds = settled_fds(FD_SAMPLE_INTERVAL).await;
        }
    }

    // --- Phase 2: batches with both kinds open at the same time. ---
    for batch in 0..BATCHES {
        let mut tunnels = Vec::with_capacity(BATCH_WIDTH);
        let mut sessions = Vec::with_capacity(BATCH_WIDTH);

        for index in 0..BATCH_WIDTH {
            tunnels.push(
                opened(
                    &format!("tunnel {index} of batch {batch}"),
                    open_tcp_tunnel(&mut client, &tcp_authority),
                )
                .await,
            );
            sessions.push(
                opened(
                    &format!("session {index} of batch {batch}"),
                    open_udp_session(&mut client, &server, udp_target),
                )
                .await,
            );
        }
        expected_tunnels += 2 * BATCH_WIDTH as u64;

        // Every session is written to before any is read, so all of them are
        // genuinely in flight together and a datagram delivered under the wrong
        // Quarter Stream ID has somewhere wrong to arrive. This is the
        // regression baseline's shape, run once per batch.
        let mut awaited: HashMap<u64, String> = HashMap::new();
        for (index, (qsid, _)) in sessions.iter().enumerate() {
            let payload = format!("batch-{batch}-session-{index}");
            send_udp_payload(&client.quic, *qsid, payload.as_bytes());
            awaited.insert(*qsid, payload);
        }
        while !awaited.is_empty() {
            let answer = recv_datagram(&client.quic).await;
            let expected = awaited
                .remove(&answer.quarter_stream_id)
                .unwrap_or_else(|| {
                    panic!("a datagram arrived on an unexpected or repeated session")
                });
            assert_eq!(
                String::from_utf8_lossy(&answer.payload),
                expected,
                "a session received another session's data"
            );
        }

        for (index, tunnel) in tunnels.iter_mut().enumerate() {
            use_and_close_tcp(tunnel, &format!("batch-{batch}-tunnel-{index}")).await;
        }
        for (_, mut stream) in sessions {
            close_and_drain(&mut stream).await;
        }
    }

    // --- Phase 3: descriptors are flat between the two samples. ---
    let baseline_fds = baseline_fds.expect("both CI platforms list this process's descriptors");
    let final_fds = settled_fds(FD_SAMPLE_INTERVAL)
        .await
        .expect("descriptor listing");
    assert!(
        final_fds <= baseline_fds + FD_SLACK,
        "descriptors grew with the run: {baseline_fds} a third of the way in, {final_fds} after \
         {CYCLES} cycles and {BATCHES} batches — a socket or a task per tunnel is not being \
         released"
    );

    // --- Phase 4: the closing line's counters are exact. ---
    let mark = buffer.mark();
    client.quic.close(quinn::VarInt::from_u32(0), b"");

    let line = buffer
        .wait_for_line(
            mark,
            &[" INFO ", "connection closed", "reason=\"peer_close\""],
        )
        .await;
    assert_eq!(
        numeric_field(&line, "tunnels"),
        expected_tunnels,
        "every tunnel granted a slot is counted once and only once; line was:\n{line}"
    );
    assert_eq!(
        numeric_field(&line, "dropped_datagrams"),
        expected_drops,
        "every dropped datagram is counted once and only once, across all three shapes; \
         line was:\n{line}"
    );

    connections_release_everything_they_held().await;
    deadlines_hold_across_many_rearms().await;
}

/// The same question one level up: a connection's own teardown, many times.
///
/// Everything a connection owns is given back by a `Drop` rather than by a call
/// at the end of a function — its place on the server's roster, the task reading
/// the peer's streams and datagrams, the three unidirectional streams it opened,
/// the table its sessions registered in. Each of those has exactly one release
/// site, and a run that opens two connections cannot tell a release site that
/// works from one that is never reached.
///
/// The roster is asserted on the wire and needs no counter to be visible: the
/// server is given [`CONNECTION_SLOTS`] slots, and every connection here
/// authenticates (an open proxy counts its first request as having got past a
/// door that is not there), so a slot that outlived its connection could never
/// be evicted to make room. The run would stop at connection 17 with a refused
/// handshake.
async fn connections_release_everything_they_held() {
    let server = TestServer::start_with(&format!(
        "[limits]\nmax_connections = {CONNECTION_SLOTS}\n{ALLOW_PRIVATE}"
    ))
    .await;
    let tcp_target = spawn_echo_target().await;
    let tcp_authority = tcp_target.to_string();
    let udp_target = spawn_udp_echo_target().await;

    let mut baseline_fds = None;

    for cycle in 0..CONNECTION_CYCLES {
        let mut client = H3Client::connect(&server).await;

        let mut tcp = opened(
            &format!("the tunnel on connection {cycle}"),
            open_tcp_tunnel(&mut client, &tcp_authority),
        )
        .await;
        let (qsid, mut udp) = opened(
            &format!("the session on connection {cycle}"),
            open_udp_session(&mut client, &server, udp_target),
        )
        .await;

        let payload = format!("connection-{cycle:04}");
        let echoed = udp_round_trip(&client, qsid, payload.as_bytes()).await;
        assert_eq!(String::from_utf8_lossy(&echoed), payload);
        use_and_close_tcp(&mut tcp, &payload).await;
        close_and_drain(&mut udp).await;

        // Closed the way Surge closes, rather than left to the endpoint's own
        // teardown: the server sees a CONNECTION_CLOSE and its task returns,
        // which is the moment every one of those `Drop`s has to run.
        client.quic.close(quinn::VarInt::from_u32(0), b"");
        drop(client);

        if cycle == CONNECTION_CYCLES / 3 {
            baseline_fds = settled_fds(FD_SAMPLE_INTERVAL).await;
        }
    }

    let baseline_fds = baseline_fds.expect("both CI platforms list this process's descriptors");
    let final_fds = settled_fds(FD_SAMPLE_INTERVAL)
        .await
        .expect("descriptor listing");
    assert!(
        final_fds <= baseline_fds + FD_SLACK,
        "descriptors grew with the connections: {baseline_fds} a third of the way in, \
         {final_fds} after {CONNECTION_CYCLES} — a connection is not giving back everything \
         it held"
    );
}

/// The D84 progress deadline, exercised by re-arming it many times over.
///
/// Three things at once, none of which a single session shows: that a session
/// carrying packets is not reclaimed however long it lasts, that one carrying
/// nothing is reclaimed at the timeout, and that the many re-arms of the first
/// leave its own reclamation a timeout away rather than a timeout per re-arm.
///
/// Real time rather than tokio's paused clock: the sessions here are real UDP
/// sockets on a real QUIC connection, and pausing the clock under them stops the
/// transport too.
async fn deadlines_hold_across_many_rearms() {
    let server = TestServer::start_with(&format!(
        "[limits]\nudp_session_timeout = {SESSION_TIMEOUT_SECS}\n{ALLOW_PRIVATE}"
    ))
    .await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut busy = Vec::with_capacity(DEADLINE_SESSIONS);
    let mut quiet = Vec::with_capacity(DEADLINE_SESSIONS);
    for _ in 0..DEADLINE_SESSIONS {
        busy.push(open_udp_session(&mut client, &server, target).await);
        quiet.push(open_udp_session(&mut client, &server, target).await);
    }

    // One packet each, so every session is established and its deadline armed
    // from the same moment. The quiet ones send nothing after this.
    for (qsid, _) in busy.iter().chain(quiet.iter()) {
        let echoed = udp_round_trip(&client, *qsid, b"opening").await;
        assert_eq!(&echoed[..], b"opening");
    }

    let started = Instant::now();
    while started.elapsed() < BUSY_WINDOW {
        tokio::time::sleep(PING_INTERVAL).await;
        for (qsid, _) in &busy {
            let echoed = udp_round_trip(&client, *qsid, b"ping").await;
            assert_eq!(
                &echoed[..],
                b"ping",
                "a session carrying a packet every {PING_INTERVAL:?} was reclaimed anyway, \
                 {:?} in",
                started.elapsed()
            );
        }
    }

    // The quiet sessions have had the whole window to be reclaimed, which is
    // twice their timeout. Their streams are closed, and reading one returns its
    // end rather than blocking.
    for (qsid, stream) in &mut quiet {
        let trailing = tokio::time::timeout(TIMEOUT, read_to_end(stream))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the session on quarter stream id {qsid} sent nothing for {BUSY_WINDOW:?} \
                     and must have been reclaimed at its {SESSION_TIMEOUT_SECS}s timeout"
                )
            });
        assert!(
            trailing.is_empty(),
            "a reclaimed session owes no capsule, got {trailing:?}"
        );
    }

    // And now the point of the many re-arms: each busy session goes quiet, and
    // must be reclaimed one timeout later. A deadline pushed out by addition
    // would be twenty timeouts away instead.
    let went_quiet = Instant::now();
    for (qsid, stream) in &mut busy {
        let trailing = tokio::time::timeout(RECLAIM_BOUND, read_to_end(stream))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the session on quarter stream id {qsid} was re-armed for {BUSY_WINDOW:?} \
                     and then went quiet; it must be reclaimed within {RECLAIM_BOUND:?} of that, \
                     not one timeout per re-arm"
                )
            });
        assert!(
            trailing.is_empty(),
            "a reclaimed session owes no capsule, got {trailing:?}"
        );
    }
    assert!(
        went_quiet.elapsed() < RECLAIM_BOUND,
        "the sessions were reclaimed {:?} after going quiet, past the {RECLAIM_BOUND:?} a \
         {SESSION_TIMEOUT_SECS}s timeout allows",
        went_quiet.elapsed()
    );
}
