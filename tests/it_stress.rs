//! M5: load and churn regressions — concurrency, and the absence of leaks.
//!
//! # How a leak is detected on the wire
//!
//! A leaked tunnel slot is normally invisible until the process runs out of file
//! descriptors hours later. These tests make it visible immediately by running
//! with a deliberately small `max_targets_per_conn`: if a finished tunnel does not
//! return its slot, the run fails at iteration `limit + 1` with a 503 instead of
//! degrading silently. That keeps the assertion on the wire rather than reaching
//! into the server's counters.
//!
//! The heaviest scenarios from the spec's §8.3 acceptance list are `#[ignore]`d so
//! `cargo test` stays quick; run them with
//! `cargo test --test it_stress -- --ignored --nocapture`.

mod common;

use bytes::Bytes;
use common::{
    close_and_drain, echoes, open_tcp_tunnel, open_udp_session, read_at_least, spawn_echo_target,
    spawn_udp_echo_target, udp_round_trip, H3Client, TestServer, ALLOW_PRIVATE,
};

/// Slots to run the churn tests with.
///
/// Small enough that a leak fails fast, with enough headroom that the handful of
/// server-side releases still in flight behind the client cannot be mistaken for
/// one.
const CHURN_SLOTS: u32 = 32;

/// Runs `count` tunnels at once on a single connection, each verifying that what
/// comes back is its own data.
///
/// Cross-talk between tunnels — the failure mode that a shared buffer or a
/// mis-keyed routing table produces — shows up as a payload from the wrong tunnel
/// rather than as an error.
async fn concurrent_tunnels(count: usize) {
    let server = TestServer::start_with(&format!(
        "[limits]\nmax_targets_per_conn = {}\n{ALLOW_PRIVATE}",
        count + 8
    ))
    .await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut streams = Vec::with_capacity(count);
    for _ in 0..count {
        streams.push(open_tcp_tunnel(&mut client, &target.to_string()).await);
    }

    // Everything is written before anything is read, so all `count` tunnels are
    // genuinely in flight at the same time.
    let payloads: Vec<String> = (0..count).map(|i| format!("tunnel-{i:05}")).collect();
    for (stream, payload) in streams.iter_mut().zip(&payloads) {
        stream
            .send_data(Bytes::from(payload.clone()))
            .await
            .expect("send payload");
    }

    for (i, (stream, payload)) in streams.iter_mut().zip(&payloads).enumerate() {
        let echoed = read_at_least(stream, payload.len()).await;
        assert_eq!(
            String::from_utf8_lossy(&echoed),
            *payload,
            "tunnel {i} received another tunnel's data"
        );
    }
}

/// Opens and closes `cycles` tunnels one after another on a single connection.
async fn tcp_churn(cycles: usize) {
    let server = TestServer::start_with(&format!(
        "[limits]\nmax_targets_per_conn = {CHURN_SLOTS}\n{ALLOW_PRIVATE}"
    ))
    .await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    for i in 0..cycles {
        let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

        let payload = format!("cycle-{i}");
        echoes(&mut stream, payload.as_bytes()).await;

        // Half-close, then wait for the server's own FIN: the tunnel is fully
        // over, and its slot must come back.
        close_and_drain(&mut stream).await;
    }
}

/// Opens and closes `cycles` UDP sessions one after another on a single
/// connection.
async fn udp_churn(cycles: usize) {
    let server = TestServer::start_with(&format!(
        "[limits]\nmax_targets_per_conn = {CHURN_SLOTS}\n{ALLOW_PRIVATE}"
    ))
    .await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    for i in 0..cycles {
        let (qsid, mut stream) = open_udp_session(&mut client, &server, target).await;

        // A round trip proves the session is really wired up, so the churn is
        // over live sessions rather than over refusals. The helper asserts the
        // answer came back on this session's quarter stream id, which is what a
        // datagram still routed to a previous session would fail.
        let payload = format!("session-{i}");
        let echoed = udp_round_trip(&client, qsid, payload.as_bytes()).await;
        assert_eq!(String::from_utf8_lossy(&echoed), payload);

        // Closing the stream ends the session, deregisters it, and frees its slot.
        close_and_drain(&mut stream).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hundred_concurrent_tunnels_stay_independent() {
    concurrent_tunnels(100).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn five_hundred_tcp_tunnel_cycles_leak_nothing() {
    tcp_churn(500).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn five_hundred_udp_session_cycles_leak_nothing() {
    udp_churn(500).await;
}

/// The spec's §8.3 figure: 500 tunnels open at once on one connection.
///
/// Ignored by default because it needs a fd limit well above the macOS default of
/// 256 (`ulimit -n 4096`), not because it is slow.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "heavy: 500 concurrent tunnels, needs a raised fd limit"]
async fn five_hundred_concurrent_tunnels() {
    concurrent_tunnels(500).await;
}

/// The spec's §8.3 figure: 10 000 open/close cycles without leaking descriptors.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "heavy: 10 000 tunnel cycles"]
async fn ten_thousand_tcp_tunnel_cycles() {
    tcp_churn(10_000).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "heavy: 10 000 UDP session cycles"]
async fn ten_thousand_udp_session_cycles() {
    udp_churn(10_000).await;
}
