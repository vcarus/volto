//! Two tunnel log lines whose *level* and *wording* are the product.
//!
//! The blackhole line is INFO (D44, D49), and the oversize line is the sentinel
//! for the peer's `max_datagram_frame_size` (D48 §3). The policy refusal, INFO
//! by D111, is held by `it_log_amplification`.
//!
//! None of that is visible to a test that only checks the response: the decision
//! functions behind these lines (`policy::is_dns_blackhole`, `tunnel::udp::path::grade`)
//! are unit-tested and stay green if the line they feed is renamed, demoted, or
//! bypassed entirely. That last hop is what this binary drives.
//!
//! One test function, for the reason `SharedBuffer::shared` gives.

mod common;

use common::{
    ALLOW_PRIVATE, H3Client, SharedBuffer, TestServer, connect_request, field_text, numeric_field,
    open_udp_session, respond_to, send_udp_payload, spawn_udp_target,
};
use volto::h3api::Status;

/// A name whose every address is the unspecified one: the shape a filtering
/// resolver returns, and the only thing `is_dns_blackhole` accepts.
const BLACKHOLED: &str = "0.0.0.0:443";

#[tokio::test]
async fn tunnel_refusals_and_drops_are_logged_at_the_level_they_were_graded() {
    let buffer = SharedBuffer::shared("volto=info");

    blackhole_is_information(&buffer).await;
    the_oversize_sentinel_reports_on_a_doubling_schedule(&buffer).await;
}

/// D44/D49: a name the resolver blackholed is not this proxy's verdict, so its
/// line is INFO and nothing about it may reach WARN.
///
/// The server runs the *default* policy, which is the point: the unspecified
/// address is in the never-allowed bucket, so this branch is reached the same way
/// whatever `allow_private_networks` says. The policy refusal, the other INFO
/// refusal, is held by `it_log_amplification`'s policy storm.
async fn blackhole_is_information(buffer: &SharedBuffer) {
    let server = TestServer::start_with("").await;
    let mut client = H3Client::connect(&server).await;
    let mark = buffer.mark();

    let response = respond_to(&mut client, connect_request(BLACKHOLED)).await;
    assert_eq!(
        response.status,
        Status::OK,
        "a blackholed name is accepted and closed, not refused (D49)"
    );

    let line = buffer
        .wait_for_line(
            mark,
            &[" INFO ", "every address of the target is a DNS blackhole"],
        )
        .await;
    assert_eq!(
        (field_text(&line, "host"), numeric_field(&line, "port")),
        ("\"0.0.0.0\"", 443),
        "the line must name the authority it is about: {line}"
    );

    // The half that makes the demotion worth anything: nothing about this
    // request may still be shouting. Matched on the authority so an unrelated
    // warning from another scenario cannot satisfy it.
    let warnings = buffer.lines_since(mark, &[" WARN ", BLACKHOLED]);
    assert!(
        warnings.is_empty(),
        "a blackholed name must produce no warning at all, got:\n{}",
        warnings.join("\n")
    );
}

/// D48 §2 as D97 leaves it: an oversized drop is INFO on the doubling schedule,
/// with the two numbers that make it actionable and the running total, and every
/// drop between reports is quiet.
///
/// This is the only reading we have on whether the peer still accepts datagrams
/// of the size we assumed. Its failure mode is why it needs a test: if the line
/// is demoted or the call site bypassed, the journal shows zero occurrences —
/// byte for byte what "no drops are happening" looks like.
///
/// Driven one packet at a time and asserted after each reported drop, so a
/// failure names the drop.
async fn the_oversize_sentinel_reports_on_a_doubling_schedule(buffer: &SharedBuffer) {
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    // Comfortably above any QUIC datagram limit on a 1200-1500 byte path.
    let target = spawn_udp_target(|_| Some(vec![0x5a; 8000])).await;
    let mut client = H3Client::connect(&server).await;
    let mark = buffer.mark();

    let (qsid, _stream) = open_udp_session(&mut client, &server, target).await;

    let limit = client
        .quic
        .max_datagram_size()
        .expect("the server must accept datagrams");
    assert!(limit < 8000, "the reply must not fit in a datagram");

    // Eight drops on the one session, one packet at a time. `owed` is what the
    // schedule has promised so far: a report on the 1st, 2nd, 4th and 8th drop,
    // and nothing for the drops between them.
    let mut owed = 0usize;
    for nth in 1..=8u8 {
        send_udp_payload(&client.quic, qsid, &[nth]);

        if nth.is_power_of_two() {
            owed += 1;
            let line = buffer
                .wait_for_line(
                    mark,
                    &[
                        " INFO ",
                        "target packet too large for a QUIC datagram",
                        &format!("drops={nth}"),
                    ],
                )
                .await;
            // The numbers are the reading. A line saying only "too large" would
            // tell an operator nothing about how much too large, which is what
            // decides whether `max_datagram_frame_size` moved or the targets
            // simply got chattier — and `drops` is what says how long it has
            // been happening, which is the half the unsampled version never
            // told anybody.
            assert!(
                line.contains("encoded_len=") && line.contains("limit=") && line.contains(" mtu="),
                "the sentinel must carry the encoded length, the datagram limit and the path MTU: {line}"
            );

            // A drop between reports goes to DEBUG, so a line for one of them
            // shows here as one line too many.
            let sentinels = buffer.lines_since(
                mark,
                &[" INFO ", "target packet too large for a QUIC datagram"],
            );
            assert_eq!(
                sentinels.len(),
                owed,
                "after {nth} drop(s) the schedule owes {owed} line(s); got:\n{}",
                sentinels.join("\n")
            );
        }
    }

    // A dropped packet is not a fault: the session survived it, and nothing here
    // is an operator's problem.
    let warnings = buffer.lines_since(mark, &[" WARN "]);
    assert!(
        warnings.is_empty(),
        "dropping an oversized target packet must not warn, got:\n{}",
        warnings.join("\n")
    );
}
