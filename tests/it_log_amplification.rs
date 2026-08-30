//! How many log lines one peer can make this server write, and what may ride in
//! them.
//!
//! The log is an attack surface of its own. `journalctl` rate limiting counts
//! *lines*, not bytes, and it is per unit: a peer that can drive one line per
//! request at a level that survives to production does not merely fill a disk,
//! it knocks this service's genuine lines out of the journal for the rest of the
//! window. So the interesting question about a peer-reachable log statement is
//! not whether it is useful but how many of it one connection can buy, and with
//! how few bytes.
//!
//! Everything here runs at `volto=info`, which is the shipped default
//! (`script/config.example.toml`, `docs/configuration.md`): DEBUG is invisible in
//! production, so a line only counts if it reaches this filter.
//!
//! Its own binary because a capturing subscriber is process-wide and
//! `tracing_subscriber::fmt().init()` may run once, which is why every scenario
//! lives inside the one `#[tokio::test]` and takes a mark into the shared buffer
//! rather than starting from an empty one.

mod common;

use std::time::Duration;

use common::{
    auth_section, authorize, authorized_connect, basic_credentials, closed_udp_address,
    connect_request, connect_udp_request, open_tcp_tunnel, respond_to, spawn_echo_target, H3Client,
    SharedBuffer, TestServer, ALLOW_PRIVATE,
};
use volto::h3api::Status;

/// Loopback, which the default policy refuses: what an SSRF probe looks like
/// from here, and the cheapest production-level warning a peer can buy.
const PROHIBITED: &str = "127.0.0.1:443";

/// Requests per storm.
///
/// Small enough to stay a second of test time and large enough that a 1:1 line
/// rate is unmistakable next to any bound: nothing that samples could produce
/// this many lines by accident. A power of two so that the last request of a
/// storm is one the doubling sampler reports, which is what lets the running
/// total be asserted rather than inferred.
const STORM: usize = 64;

/// The credentials the authenticating servers below are configured with.
const USER: &str = "user1";
const PASSWORD: &str = "s3cret-pa55word";

#[tokio::test]
async fn one_peer_cannot_buy_an_unbounded_number_of_production_log_lines() {
    let buffer = SharedBuffer::install("volto=info");

    a_policy_refusal_storm_is_sampled(&buffer).await;
    a_tunnel_limit_storm_is_sampled(&buffer).await;
    an_authentication_storm_is_bounded_by_the_failure_budget(&buffer).await;
    a_peer_close_reason_never_reaches_the_journal(&buffer).await;
    a_udp_session_costs_exactly_one_line(&buffer).await;
}

/// The SSRF warning must stay loud without being one line per request.
///
/// `admit_target`'s refusal is the cheapest production-level line in the server:
/// an IP literal takes no resolver slot and holds no socket, so the whole cost to
/// a peer is one HEADERS frame — under a hundred bytes for a `WARN` that reaches
/// the journal. A port scan through the proxy is 65535 of them.
///
/// D44 settled that this line stays at WARN, and it must: it is the evidence an
/// operator is left with when somebody probes the private side of the host. What
/// is bounded here is the *volume*, not the loudness — the first refusal warns
/// exactly as before, and later ones warn again as the running count doubles, so
/// a scan still announces itself and now says how large it was.
async fn a_policy_refusal_storm_is_sampled(buffer: &SharedBuffer) {
    let server = TestServer::start_with("").await;
    let mut client = H3Client::connect(&server).await;
    let mark = buffer.mark();

    for _ in 0..STORM {
        let response = respond_to(&mut client, connect_request(PROHIBITED)).await;
        assert_eq!(response.status, Status::FORBIDDEN);
    }

    let warnings = buffer.lines_since(
        mark,
        &[
            " WARN ",
            "every address of the target is prohibited by policy",
        ],
    );
    assert!(
        !warnings.is_empty(),
        "the SSRF-shaped refusal must still be audible at WARN"
    );
    assert!(
        warnings.len() < STORM,
        "{STORM} refusals bought {} production warnings; one per request means a peer \
         decides how much of this journal is left for anybody else:\n{}",
        warnings.len(),
        warnings.join("\n")
    );
    assert!(
        warnings
            .last()
            .expect("a warning")
            .contains(&format!("refusals={STORM}")),
        "the last warning must carry the running total, or bounding the volume \
         throws away the size of the scan:\n{}",
        warnings.join("\n")
    );

    // Nothing was silenced: every refusal the peer made is still answered, and
    // the ones that did not warn are on the debug channel an operator can turn
    // on. What the sampler removes is repetition, not the record.
    let refused = buffer.lines_since(mark, &["every address of the target is prohibited"]);
    assert_eq!(
        refused.len(),
        warnings.len(),
        "at `info` only the sampled lines may appear at all"
    );
}

/// The same treatment for the other refusal a peer can repeat at will.
///
/// Reaching the tunnel limit costs a peer `max_targets_per_conn` live tunnels,
/// which is real resource commitment — but once it is there, *every* further
/// request is a warning, for ever, at one HEADERS frame apiece. The limit is set
/// to one here so the storm is the point rather than the setup.
async fn a_tunnel_limit_storm_is_sampled(buffer: &SharedBuffer) {
    let target = spawn_echo_target().await;
    let server = TestServer::start_with(&format!(
        "[limits]\nmax_targets_per_conn = 1\n{ALLOW_PRIVATE}"
    ))
    .await;
    let mut client = H3Client::connect(&server).await;

    // Held for the rest of this scenario: it is the one tunnel the quota allows,
    // so every request below is refused.
    let _held = open_tcp_tunnel(&mut client, &target.to_string()).await;
    let mark = buffer.mark();

    for _ in 0..STORM {
        let response = respond_to(&mut client, connect_request(&target.to_string())).await;
        assert_eq!(response.status, Status::SERVICE_UNAVAILABLE);
    }

    let warnings = buffer.lines_since(mark, &[" WARN ", "connection is at its tunnel limit"]);
    assert!(
        !warnings.is_empty(),
        "a connection sitting on its limit is still worth telling an operator about"
    );
    assert!(
        warnings.len() < STORM,
        "{STORM} refused requests bought {} production warnings:\n{}",
        warnings.len(),
        warnings.join("\n")
    );
}

/// The 407 path already has a bound, and this is what proves it is the *log*
/// that is bounded and not just the connection.
///
/// `security.max_auth_failures` exists to make guessing cost a handshake, and the
/// warning per failure is deliberate — it is what a fail2ban rule reads. The
/// property that keeps it from being a flood is that the budget is charged per
/// connection and the connection is closed when it runs out, so the line count
/// per handshake is bounded by a configured number rather than by how many
/// streams the peer feels like opening.
async fn an_authentication_storm_is_bounded_by_the_failure_budget(buffer: &SharedBuffer) {
    const BUDGET: usize = 3;

    let server = TestServer::start_with(&format!(
        "{}\n[security]\nmax_auth_failures = {BUDGET}\n",
        auth_section(&[(USER, PASSWORD)])
    ))
    .await;
    let mut client = H3Client::connect(&server).await;
    let mark = buffer.mark();

    // Every one of these is a wrong guess; the connection is closed part-way
    // through, so the later ones fail to send rather than being answered.
    for _ in 0..STORM {
        let request = authorized_connect(PROHIBITED, USER, "wrong-password");
        if client.send.send_request(request).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let failures = buffer.lines_since(mark, &[" WARN ", "authentication failed"]);
    assert!(
        failures.len() <= BUDGET,
        "the failure budget is {BUDGET}, so a connection may not write more than \
         {BUDGET} warnings about it; got {}:\n{}",
        failures.len(),
        failures.join("\n")
    );

    // The password may not appear anywhere, at any level, however the attempt
    // was graded -- and neither may the real one, which nothing here ever sends.
    let contents = buffer.since(mark);
    assert!(
        !contents.contains("wrong-password") && !contents.contains(PASSWORD),
        "a credential reached the log:\n{contents}"
    );
}

/// The closing line records its error with `Display`, which escapes nothing — so
/// nothing peer-chosen may be inside it.
///
/// A peer closing a QUIC connection chooses both the error code and a reason
/// phrase, and the reason phrase is arbitrary bytes of its choosing. `%error` on
/// a `WARN` would put them in the journal unescaped: `systemd` splits a service's
/// stdout on `\n`, so a newline in there is a forged journal entry, attributed to
/// this server, from an unauthenticated peer that has done nothing but complete a
/// handshake.
///
/// What keeps that out is `ConnectionError`'s conversion, which keeps the code
/// and drops the peer's prose. Nothing else pins it, and the conversion reads as
/// a tidying-up rather than as a defence, so this is the test that says it is
/// load-bearing.
///
/// This drives the *application* close, which is the one a peer can send through
/// quinn's public API and so the one a test can reach. The transport close —
/// frame type 0x1c, whose reason phrase is kept rather than dropped, bounded and
/// escaped instead — needs a hostile QUIC stack to send, so it is pinned in
/// `volto::h3::error`'s own tests against the same conversion.
async fn a_peer_close_reason_never_reaches_the_journal(buffer: &SharedBuffer) {
    /// The bytes a peer would like the journal to carry. The newline is the
    /// attack; the rest is what it would forge.
    const FORGED: &str = "goodbye\nINFO volto: authentication succeeded for admin";

    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let client = H3Client::connect(&server).await;
    let mark = buffer.mark();

    // A code that is not a clean goodbye, so the connection is graded as an
    // error and the line is a WARN rather than the INFO a benign close gets.
    client
        .quic
        .close(quinn::VarInt::from_u32(0x1234), FORGED.as_bytes());

    let line = buffer
        .wait_for_line(mark, &[" WARN ", "connection closed with error"])
        .await;
    assert!(
        !line.contains("goodbye"),
        "the peer's reason phrase reached the journal: {line}"
    );

    let contents = buffer.since(mark);
    assert!(
        !contents.contains("authentication succeeded"),
        "a peer forged a log line through a close reason:\n{contents}"
    );
}

/// The baseline every bound above is measured against: a tunnel is worth one
/// line, and a peer that opens tunnels is *meant* to be able to write one line
/// each.
///
/// A CONNECT-UDP session is the cheapest of them — the target is never contacted,
/// only bound and connected — so this is the floor on what an authorised client
/// costs the journal. It is deliberately not bounded: an access log that drops
/// records is not an access log. Pinned so that the number is a decision somebody
/// made rather than an accident, and so a second line per session cannot be added
/// without this saying so.
async fn a_udp_session_costs_exactly_one_line(buffer: &SharedBuffer) {
    const SESSIONS: usize = 8;

    let server = TestServer::start_with(&format!(
        "{}\n{ALLOW_PRIVATE}",
        auth_section(&[(USER, PASSWORD)])
    ))
    .await;
    let closed = closed_udp_address().await;
    let mut client = H3Client::connect(&server).await;
    let mark = buffer.mark();

    for _ in 0..SESSIONS {
        let mut request = connect_udp_request(server.addr, &closed.ip().to_string(), closed.port());
        authorize(&mut request, &basic_credentials(USER, PASSWORD));
        let (response, mut stream) = common::send_and_respond(&mut client, request).await;
        assert_eq!(response.status, Status::OK);
        stream.finish().expect("finish the session");
    }

    let established = buffer.lines_since(mark, &[" INFO ", "udp session established"]);
    assert_eq!(
        established.len(),
        SESSIONS,
        "one line per session is the access log; more than one is amplification"
    );
}
