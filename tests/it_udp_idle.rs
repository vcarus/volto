//! A CONNECT-UDP session flooded with dropped HTTP Datagrams still closes on
//! its idle timeout once the flood stops, and the flood crosses nothing.
//!
//! `it_udp` pins the deadline against the two shapes a peer can produce on the
//! *request stream* — a drip of bytes that finish no capsule, and a flood of
//! them. This is the third shape and the one that reaches the deadline by the
//! other road: HTTP Datagrams the RFC 9298 §7 unanswered-packet budget drops.
//! They arrive on the session's own queue rather than on the stream, they move
//! no packet across the proxy, and a peer can produce them as fast as its link
//! allows.
//!
//! The verdict on D92 belongs to the `before_deadline` unit tests in
//! `src/tunnel/udp.rs`, which flood a paused clock. This binary cannot catch
//! that regression, because the close comes once the flood stops. What it
//! checks is the end-to-end shape: the session closes on its own, the flood ran
//! while the deadline did, and the budget forwarded one packet and no more.
//!
//! It is a test of its own, rather than part of `it_udp`, for two reasons:
//!
//! * The observation is the server's own DEBUG line, not the close arriving on
//!   the client's stream. A client flooding hard enough to matter is also a
//!   client whose connection lock its own sender is holding, and the close then
//!   reaches the test's reader seconds late — timing the wrong clock. The line
//!   is written by the session task on the step that ends it.
//! * Installing that subscriber is also what makes the flood able to outrun the
//!   session, which is what a loaded production host does for free: writing a
//!   line per dropped payload slows the drain enough for the queue to stay
//!   non-empty. Without it the same flood on an idle dev host is a coin toss.
//!
//! `tracing_subscriber::fmt().init()` may run once per process, so this is a
//! binary of its own (the convention `it_udp_socket_log` and the other `*_log`
//! binaries follow).

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{
    ALLOW_PRIVATE, H3Client, SharedBuffer, TestServer, counted_at_least, open_udp_session,
    spawn_silent_udp_target,
};
use tokio::time::Instant;
use volto::datagram;

/// The session timeout the server is started with.
///
/// Far below the two minutes RFC 9298 §3.1 recommends — which the config layer
/// warns about — because no test can wait out a realistic one.
const NOMINAL: Duration = Duration::from_secs(1);

/// How long the flood keeps running after the deadline it is trying to hold
/// open has passed.
///
/// Long enough that the deadline is unambiguously behind the session while the
/// queue is still being supplied, which is the situation in which the unfixed
/// loop never measured its deadline, and short enough not to stretch the test.
/// Nothing is asserted at this boundary; it only has to lie past `NOMINAL`.
const FLOOD_OVERRUN: Duration = Duration::from_secs(1);

/// How long after the flood stops the close may take before it is a bug.
///
/// Not a timing probe: the module doc says why this binary cannot catch the
/// unfixed loop, and the deterministic verdict on it belongs to the
/// `before_deadline` unit tests. While the flood runs, a loaded host can starve
/// the session task outright, so no bound holds there. Once the flood stops,
/// only being scheduled stands between the session and its close line, and ten
/// seconds is the suite's bound for a wait that exists to fail rather than
/// hang.
const SLACK: Duration = Duration::from_secs(10);

/// A budget of one packet, so exactly one payload ever crosses.
///
/// RFC 9298 §7 caps what a session may send before its target has answered, and
/// the target below never answers. The first payload is forwarded and arms the
/// deadline; every one after it is dropped, and a dropped payload re-arms
/// nothing — which is what makes the flood idle traffic by the definition the
/// timeout uses.
const ONE_PACKET_BUDGET: &str = "unanswered_packet_budget = 1\n";

#[tokio::test(flavor = "multi_thread")]
async fn a_flooded_session_closes_once_the_flood_stops_and_the_flood_crosses_nothing() {
    let buffer = SharedBuffer::shared("volto=debug");

    let server = TestServer::start_with(&format!(
        "[limits]\nudp_session_timeout = {}\n{ALLOW_PRIVATE}{ONE_PACKET_BUDGET}",
        NOMINAL.as_secs()
    ))
    .await;
    let (target, received) = spawn_silent_udp_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, _stream) = open_udp_session(&mut client, &server, target).await;
    let mark = buffer.mark();

    // The flood starts first, and its own first payload is the one the budget
    // allows: that packet crosses, arms the deadline, and every one after it is
    // dropped. Flooding before the deadline is armed keeps the dropped-payload
    // count below independent of how fast a spawned task starts. A flood that
    // is already saturating the connection when the window opens has
    // no such gap. Dropped payloads re-arm nothing — that is the property under
    // test — so nothing about the ordering changes what the deadline measures.
    //
    // One sender is the saturating shape: `send_datagram` replaces its own
    // queued datagrams once the client's buffer is full, so the arrival rate at
    // the server is the wire's, and more sender tasks on the same connection
    // would add contention rather than pressure. The yield is not politeness:
    // the server shares this runtime, and a sender that never gives it back
    // would be measuring the test harness rather than the server.
    let quic = client.quic.clone();
    let flood = tokio::spawn(async move {
        let payload = datagram::encode_udp_payload(qsid, &[0x5au8; 64]);
        let mut sent = 0u64;
        while quic.send_datagram(payload.clone()).is_ok() {
            sent += 1;
            if sent.is_multiple_of(16) {
                tokio::task::yield_now().await;
            }
        }
    });

    // Waited for at the target, so the deadline is known to be armed — and
    // armed by the flood's first packet, the only one the budget forwards —
    // with the flood already at full rate behind it.
    counted_at_least(&received, 1).await;
    let armed = Instant::now();

    // Hold the flood over the whole deadline window and past it, then stop it
    // deliberately before judging. Judging during the flood is what a loaded
    // machine defeats (see `SLACK`). On a quiet host the close lands mid-flood
    // at ~1 s and the
    // wait below finds the line already written; the flood outliving the close
    // costs nothing, since `send_datagram` on a closing connection just starts
    // failing.
    tokio::time::sleep(NOMINAL + FLOOD_OVERRUN).await;
    flood.abort();

    let give_up = Instant::now() + SLACK;
    let closed = loop {
        if !buffer
            .lines_since(mark, &["udp session idle timeout"])
            .is_empty()
        {
            break true;
        }
        if Instant::now() >= give_up {
            break false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let waited = armed.elapsed();

    assert!(
        closed,
        "the flooded session never reached its {NOMINAL:?} idle timeout: still no idle \
         close {waited:?} after the last packet crossed, {SLACK:?} of it with the flood \
         already stopped"
    );

    // The flood really did run while the deadline did, so the close above was
    // reached through a busy session rather than a quiet one: every one of these
    // lines is a payload that arrived after the first one armed the deadline,
    // was dropped, and bought no time.
    //
    // Two lines is the smallest count that rules out both a flood that never
    // ran and a flood whose first drop landed after the close; a rate would
    // measure the host.
    let dropped = buffer
        .lines_since(mark, &["unanswered packet budget exhausted"])
        .len();
    assert!(
        dropped > 1,
        "the session must have been flooded while its deadline ran, got {dropped} dropped payloads"
    );

    // And the flood crossed nothing: the target heard the one packet the budget
    // allowed and not a byte more, which is what makes all of this idle time.
    assert_eq!(
        received.load(Ordering::Relaxed),
        1,
        "the amplification cap let flood packets through, so the session was not idle at all"
    );
}
