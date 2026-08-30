//! A flooded CONNECT-UDP session still closes on its idle deadline.
//!
//! `it_udp` pins the deadline against the two shapes a peer can produce on the
//! *request stream* — a drip of bytes that finish no capsule, and a flood of
//! them. This is the third shape and the one that reaches the deadline by the
//! other road: HTTP Datagrams the RFC 9298 §7 unanswered-packet budget drops.
//! They arrive on the session's own queue rather than on the stream, they move
//! no packet across the proxy, and a peer can produce them as fast as its link
//! allows.
//!
//! What that defeated is the poll order of `tokio::time::timeout_at`, which
//! returns the wrapped future's value without ever consulting the clock (D92):
//! while the queue never ran dry, the deadline was not measured at all. Pinned
//! here rather than in `it_udp` for two reasons, both about being able to see
//! the server's verdict at all:
//!
//! * The observation is the server's own DEBUG line, not the close arriving on
//!   the client's stream. A client flooding hard enough to matter is also a
//!   client whose connection lock its own sender is holding, and the close then
//!   reaches the test's reader seconds late — timing the wrong clock. The line
//!   is written by the session task on the step that ends it.
//! * Installing that subscriber is also what makes the flood able to outrun the
//!   session, which is what a loaded production host does for free: writing a
//!   line per dropped payload slows the drain enough for the queue to stay
//!   non-empty. Without it the same flood on an idle dev host is a coin toss,
//!   which is exactly why this went unpinned when D92 first named it.
//!
//! `tracing_subscriber::fmt().init()` may run once per process, so this is a
//! binary of its own (the convention `it_udp_socket_log` and the other `*_log`
//! binaries follow).

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{
    open_udp_session, spawn_silent_udp_target, H3Client, SharedBuffer, TestServer, ALLOW_PRIVATE,
};
use tokio::time::Instant;
use volto::datagram;

/// The session timeout the server is started with.
///
/// Far below the two minutes RFC 9298 §3.1 recommends — which the config layer
/// warns about — because no test can wait out a realistic one.
const NOMINAL: Duration = Duration::from_secs(1);

/// How late the close may be before it is a bug rather than scheduling.
///
/// The server's own measurement of this is sub-millisecond once the clock is
/// read; the slack is for everything between that decision and this test
/// seeing the line — the flood's share of the machine, and the poll below.
/// A slack of one second was red 3/3 against the unfixed loop when this was
/// written, but a merely busy dev host once pushed a *fixed* run past it too:
/// a probe and a scheduling margin should not share a boundary. So the bound
/// is sized for a loaded two-core CI runner instead, and the deterministic
/// verdict against the unfixed shape belongs to the `before_deadline` unit
/// tests, which flood a paused clock and are exact. Whether this test would
/// also catch it depends on how long the machine keeps the queue non-empty —
/// nothing to build an assertion on. What it pins is the wiring: the deadline
/// is real, the flood really ran, and the close arrived — the whole test
/// finishes in 1.0-1.5 s on the dev host, against a bound of four.
const SLACK: Duration = Duration::from_secs(3);

/// A budget of one packet, so exactly one payload ever crosses.
///
/// RFC 9298 §7 caps what a session may send before its target has answered, and
/// the target below never answers. The first payload is forwarded and arms the
/// deadline; every one after it is dropped, and a dropped payload re-arms
/// nothing — which is what makes the flood idle traffic by the definition the
/// timeout uses.
const ONE_PACKET_BUDGET: &str = "unanswered_packet_budget = 1\n";

#[tokio::test(flavor = "multi_thread")]
async fn a_datagram_flood_does_not_hold_a_session_past_its_idle_timeout() {
    let buffer = SharedBuffer::install("volto=debug");

    let server = TestServer::start_with(&format!(
        "[limits]\nudp_session_timeout = {}\n{ALLOW_PRIVATE}{ONE_PACKET_BUDGET}",
        NOMINAL.as_secs()
    ))
    .await;
    let (target, received) = spawn_silent_udp_target().await;
    let mut client = H3Client::connect(&server).await;

    let (qsid, _stream) = open_udp_session(&mut client, &server, target).await;
    let mark = buffer.mark();

    // The one payload the budget allows. Waited for at the target, so the
    // deadline is known to be armed — and armed by this packet — before the
    // flood starts.
    client
        .quic
        .send_datagram(datagram::encode_udp_payload(qsid, b"one"))
        .expect("send the one payload the budget allows");
    while received.load(Ordering::Relaxed) == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let armed = Instant::now();

    // Now keep the session's queue supplied for as long as this test lasts. One
    // sender is the saturating shape: `send_datagram` replaces its own queued
    // datagrams once the client's buffer is full, so the arrival rate at the
    // server is the wire's, and more sender tasks on the same connection would
    // add contention rather than pressure. The yield is not politeness: the
    // server shares this runtime, and a sender that never gives it back would be
    // measuring the test harness rather than the server.
    let quic = client.quic.clone();
    let flood = tokio::spawn(async move {
        let payload = datagram::encode_udp_payload(qsid, &[0x5au8; 64]);
        let mut sent = 0u64;
        while quic.send_datagram(payload.clone()).is_ok() {
            sent += 1;
            if sent % 16 == 0 {
                tokio::task::yield_now().await;
            }
        }
    });

    let give_up = armed + NOMINAL + SLACK;
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
    flood.abort();

    assert!(
        closed,
        "a flood of dropped payloads held the session open past its {NOMINAL:?} timeout: \
         still no idle close {waited:?} after the last packet crossed"
    );

    // The flood really did run while the deadline did, so the close above was
    // reached through a busy session rather than a quiet one: every one of these
    // lines is a payload that arrived, was dropped, and bought no time.
    let dropped = buffer
        .lines_since(mark, &["unanswered packet budget exhausted"])
        .len();
    assert!(
        dropped > 100,
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
