//! The three tunnel log lines whose *level* and *wording* are the product.
//!
//! Each of these lines is read by something other than a person debugging: the
//! DNS-blackhole line was demoted to INFO so that `journalctl -p warning` means
//! something again (D44, 89% of a day's warnings were that one line), the policy
//! refusal was deliberately left at WARN because SSRF-shaped evidence must stay
//! loud, and the oversized-datagram line is the only sentinel watching whether
//! the peer has lowered `max_datagram_frame_size` under us (D48 §3).
//!
//! None of that is visible to a test that only checks the response: the decision
//! functions behind these lines (`policy::is_dns_blackhole`, `oversize_verdict`)
//! are unit-tested and stay green if the line they feed is renamed, demoted, or
//! bypassed entirely. That last hop is what this binary drives — mutating the
//! blackhole `info!` into a `warn!` leaves all 19 `it_policy` tests passing.
//!
//! One test function, because `tracing_subscriber::fmt().init()` may run once per
//! process. The scenarios are attributed to each other by taking a mark into the
//! shared buffer before each one and only reading the lines logged after it.

mod common;

use std::time::Duration;

use common::{
    ALLOW_PRIVATE, H3Client, SharedBuffer, TestServer, connect_request, open_udp_session,
    respond_to, send_udp_payload, spawn_large_reply_udp_target,
};
use volto::h3api::Status;

/// A name whose every address is the unspecified one: the shape a filtering
/// resolver returns, and the only thing `is_dns_blackhole` accepts.
const BLACKHOLED: &str = "0.0.0.0:443";

/// Loopback, which the default policy refuses. A different authority from
/// [`BLACKHOLED`] so the two scenarios' lines can never be confused.
const PROHIBITED: &str = "127.0.0.1:443";

#[tokio::test]
async fn tunnel_refusals_and_drops_are_logged_at_the_level_they_were_graded() {
    let buffer = SharedBuffer::install("volto=info");

    blackhole_is_information(&buffer).await;
    policy_refusal_is_still_a_warning(&buffer).await;
    the_oversize_sentinel_reports_on_a_doubling_schedule(&buffer).await;
}

/// D44/D49: a name the resolver blackholed is not this proxy's verdict, so its
/// line is INFO and nothing about it may reach WARN.
///
/// The server runs the *default* policy, which is the point: the unspecified
/// address is in the never-allowed bucket, so this branch is reached the same way
/// whatever `allow_private_networks` says, and the comparison against the next
/// scenario is between two refusals of the same server.
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
    assert!(
        line.contains(BLACKHOLED),
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

/// D44's explicit boundary: every *other* refusal keeps its warning.
///
/// A client probing loopback through the proxy is what SSRF looks like from
/// here, and the whole argument for demoting the blackhole line was that it
/// buried evidence like this.
async fn policy_refusal_is_still_a_warning(buffer: &SharedBuffer) {
    let server = TestServer::start_with("").await;
    let mut client = H3Client::connect(&server).await;
    let mark = buffer.mark();

    let response = respond_to(&mut client, connect_request(PROHIBITED)).await;
    assert_eq!(response.status, Status::FORBIDDEN);

    let line = buffer
        .wait_for_line(
            mark,
            &[
                " WARN ",
                "every address of the target is prohibited by policy",
            ],
        )
        .await;
    assert!(
        line.contains(PROHIBITED),
        "the line must name the authority it is about: {line}"
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
/// The schedule replaced a plain "first only" flag (`logfmt::Sampler`, D97): the
/// first drop is as immediate as it ever was, and what follows now says how far
/// the count has got instead of nothing at all. Driven one packet at a time and
/// asserted after each, so the test names the exact drop a report was owed for
/// rather than counting lines at the end and hoping.
async fn the_oversize_sentinel_reports_on_a_doubling_schedule(buffer: &SharedBuffer) {
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    // Comfortably above any QUIC datagram limit on a 1200-1500 byte path.
    let target = spawn_large_reply_udp_target(8000).await;
    let mut client = H3Client::connect(&server).await;
    let mark = buffer.mark();

    let (qsid, _stream) = open_udp_session(&mut client, &server, target).await;

    let limit = client
        .quic
        .max_datagram_size()
        .expect("the server must accept datagrams");
    assert!(limit < 8000, "the reply must not fit in a datagram");

    let send_one = |nth: u8| {
        send_udp_payload(&client.quic, qsid, &[nth]);
    };

    // Eight drops on the one session, one packet at a time. `owed` is what the
    // schedule has promised so far: a report on the 1st, 2nd, 4th and 8th drop,
    // and nothing for the drops between them.
    let mut owed = 0usize;
    for nth in 1..=8u8 {
        send_one(nth);

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
                line.contains("encoded_len=") && line.contains("limit="),
                "the sentinel must carry the encoded length and the datagram limit: {line}"
            );
        } else {
            // A drop between reports goes to DEBUG, which a `volto=info`
            // subscriber does not carry, so there is no line to wait for: what
            // is observable is that no new one appears.
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

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

    // A dropped packet is not a fault: the session survived it, and nothing here
    // is an operator's problem.
    let warnings = buffer.lines_since(mark, &[" WARN "]);
    assert!(
        warnings.is_empty(),
        "dropping an oversized target packet must not warn, got:\n{}",
        warnings.join("\n")
    );
}
