//! Which verdict a failed send to a UDP target earns, where only the log sees it.
//!
//! RFC 9298 draws the line in two places. §3.1 requires the request stream to be
//! closed when "a UDP proxy is notified by its operating system that its socket
//! is no longer usable"; §5 says a proxy that "can only send out UDP packets of
//! a certain length due to its underlying link MTU [...] has no choice but to
//! discard incoming HTTP Datagrams" longer than that. `is_per_packet_send_error`
//! decides which of the two a failed send is, and its own unit tests pin the
//! errno list — but they stay green if the call site stops asking it, because
//! the session has a *second* reader of the same error. An ICMP error reaches
//! both the send and the socket read, and the read ends the session
//! unconditionally, so `it_udp` cannot tell a session that judged the send from
//! one that never looked: both end the same way, a moment apart.
//!
//! The two branches write different lines, and that is the whole of the visible
//! difference — one says a packet was dropped, the other that the socket is
//! gone. A dedicated binary because those lines are at DEBUG and
//! `tracing_subscriber::fmt().init()` may run once per process.

mod common;

use bytes::BytesMut;
use common::{H3Client, SharedBuffer, TestServer, closed_udp_address, open_udp_session};
use volto::{capsule, datagram};

/// Loopback targets reachable, with the RFC 9298 §7 amplification cap lifted.
///
/// The cap counts packets a session may send before its target has answered, and
/// the target below never answers: at its default of 64 the session would stop
/// sending part-way through the burst, and the burst is what the test is made
/// of.
const UNCAPPED: &str =
    "[security]\nallow_private_networks = true\nunanswered_packet_budget = 100000\n";

/// Capsules in the burst.
///
/// A batch of capsules that arrives in one chunk is forwarded packet after
/// packet with nothing else polled in between, which is the only state in which
/// a *send* rather than the socket read is the step that meets the ICMP error the
/// first packet drew. The count is far past what that takes: the error comes back
/// within tens of microseconds and these sends are a microsecond apart, so any
/// chunk worth of them covers it several times over.
const BURST: usize = 8192;

#[tokio::test]
async fn a_socket_the_os_reported_broken_is_not_logged_as_a_dropped_packet() {
    let buffer = SharedBuffer::install("volto=debug");

    let server = TestServer::start_with(UNCAPPED).await;
    // Nothing is bound here, so every packet draws an ICMP port-unreachable,
    // which a connected socket reports as ECONNREFUSED.
    let closed = closed_udp_address().await;
    let mut client = H3Client::connect(&server).await;

    let (_, mut stream) = open_udp_session(&mut client, &server, closed).await;
    let mark = buffer.mark();

    // One write, and empty payloads so that as many of them as possible reach the
    // session as a single chunk.
    let mut burst = BytesMut::new();
    for _ in 0..BURST {
        burst.extend_from_slice(&capsule::encode_datagram(
            datagram::CONTEXT_ID_UDP_PAYLOAD,
            b"",
        ));
    }
    stream
        .send_data(burst.freeze())
        .await
        .expect("send the burst");

    let line = buffer
        .wait_for_line(mark, &["failed to send to the target"])
        .await;
    assert!(
        line.contains("error="),
        "the line an operator reads must name the error it is about: {line}"
    );

    // The other half, and the one that says the two verdicts have not collapsed
    // into one: a socket the operating system has given up on is not a packet
    // that did not fit.
    let dropped = buffer.lines_since(mark, &["target socket refused this packet, dropping it"]);
    assert!(
        dropped.is_empty(),
        "ECONNREFUSED is a verdict on the socket, not on one packet, got:\n{}",
        dropped.join("\n")
    );
}
