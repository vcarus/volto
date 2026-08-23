//! Operator-facing log fields print values, not Rust's `Option` spelling.
//!
//! The fields asserted here — `alpn`, `server_name`, `target` on both tunnel
//! lines, `username` — used to be formatted with tracing's `?` sigil straight off
//! an `Option`, so production lines read `alpn=Some("h3")` and
//! `target=Some(104.16.132.229:80)`.
//! Nothing pinned that shape, which is the failure mode D51 catalogued: the
//! predicate is tested, the last hop to the observable output is not, and a
//! change to it goes unnoticed until someone reads a log a week later. Hence this
//! binary.
//!
//! `username` is the exception that proves the rule: its bytes are the peer's, so
//! "the value" is the quoted, Debug-escaped spelling tracing gives every `str`
//! field — `username="user1"` — and the test below also pins that a newline or
//! an escape sequence smuggled into a user-id cannot forge a log line, and that
//! a user-id the size of a field section cannot buy a log line of its own size.
//!
//! The absent half of each field is unit-tested in `volto::logfmt` instead: a
//! handshake without ALPN cannot complete against this server, and a socket whose
//! `peer_addr()` fails is not something a test can arrange.

mod common;

use common::{
    auth_section, authorized_connect, open_tcp_tunnel, open_udp_session, respond_to,
    spawn_echo_target, spawn_udp_echo_target, H3Client, SharedBuffer, TestServer, ALLOW_PRIVATE,
};
use volto::h3api::Status;

/// One test function: `tracing_subscriber::fmt().init()` is process-wide, so
/// splitting these would race over installing it.
#[tokio::test]
async fn operator_facing_fields_print_values_not_options() {
    let buffer = SharedBuffer::install("volto=info");

    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let target = spawn_echo_target().await;
    let udp_target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;
    let _stream = open_tcp_tunnel(&mut client, &target.to_string()).await;
    let (_qsid, _session) = open_udp_session(&mut client, &server, udp_target).await;

    let logged = buffer.contents();

    // The handshake line. The test client negotiates ALPN `h3` and sends
    // `localhost` as its SNI, so both fields have a value to print.
    let established = logged
        .lines()
        .find(|line| line.contains("connection established"))
        .unwrap_or_else(|| panic!("no connection established line; log was:\n{logged}"));
    assert!(
        established.contains("alpn=h3"),
        "the negotiated ALPN must print as its value; line was:\n{established}"
    );
    assert!(
        established.contains("server_name=localhost"),
        "the SNI must print as its value; line was:\n{established}"
    );

    // The tunnel line, whose `target` is the address the proxy actually dialled.
    let tunnel = logged
        .lines()
        .find(|line| line.contains("tcp tunnel established"))
        .unwrap_or_else(|| panic!("no tcp tunnel established line; log was:\n{logged}"));
    assert!(
        tunnel.contains(&format!("target={target}")),
        "the dialled address must print as its value; line was:\n{tunnel}"
    );

    // The session line, same field, other tunnel. The first release of this
    // test opened no UDP session, and `target=Some(…)` on this line reached
    // production while the `!contains("Some(")` backstop below stayed green.
    let session = logged
        .lines()
        .find(|line| line.contains("udp session established"))
        .unwrap_or_else(|| panic!("no udp session established line; log was:\n{logged}"));
    assert!(
        session.contains(&format!("target={udp_target}")),
        "the connected address must print as its value; line was:\n{session}"
    );

    // The `username` of a rejected attempt, on the WARN line a fail2ban rule
    // reads. A second server because the first one has no users configured.
    let guarded = TestServer::start_with(&auth_section(&[("user1", "a-real-password")])).await;
    let mut caller = H3Client::connect(&guarded).await;
    let request = authorized_connect("192.0.2.1:443", "user1", "wrong-guess");
    let response = respond_to(&mut caller, request).await;
    assert_eq!(response.status, Status::PROXY_AUTHENTICATION_REQUIRED);

    let logged = buffer.contents();
    let failure = logged
        .lines()
        .find(|line| line.contains("authentication failed"))
        .unwrap_or_else(|| panic!("no authentication failed line; log was:\n{logged}"));
    assert!(
        failure.contains(r#"username="user1""#),
        "the attempted user-id must print as a quoted string; line was:\n{failure}"
    );

    // The `username` is the one field whose bytes the peer chose, so printing it
    // "as a value" must still mean *escaped*. systemd splits a service's stdout
    // on `\n`, so a newline in a rejected user-id would otherwise become a
    // journal entry of its own, stamped with volto's unit and a timestamp; a
    // terminal escape sequence would reach the operator's screen raw. (A user-id
    // cannot carry a `:` — RFC 7617 splits at the first one — which is why the
    // forgery below has none, and why the documented fail2ban `failregex`,
    // which needs `remote=<HOST>:\d+`, cannot be satisfied from inside it.)
    let forged = "evil\nWARN volto - authentication failed stream_id=4 \
                  remote=198.51.100.9 username=\"x\"\u{1b}[2K";
    let request = authorized_connect("192.0.2.1:443", forged, "wrong-guess");
    let response = respond_to(&mut caller, request).await;
    assert_eq!(response.status, Status::PROXY_AUTHENTICATION_REQUIRED);

    let logged = buffer.contents();
    let failures: Vec<&str> = logged
        .lines()
        .filter(|line| line.contains("authentication failed"))
        .collect();
    assert_eq!(
        failures.len(),
        2,
        "two rejected attempts must give exactly two lines; log was:\n{logged}"
    );
    assert!(
        !logged.contains('\u{1b}'),
        "a control character from the peer must not reach the log raw; log was:\n{logged}"
    );
    for line in &failures {
        let remote = line.find("remote=127.0.0.1:").unwrap_or_else(|| {
            panic!("every failure line must carry the real peer address; line was:\n{line}")
        });
        let username = line.find("username=").expect("username field");
        assert!(
            remote < username,
            "the real `remote=` must come before the peer-chosen text; line was:\n{line}"
        );
    }
    assert!(
        logged.contains(r#"username="evil\nWARN volto - authentication... <truncated from "#),
        "the peer-chosen text must print quoted, Debug-escaped and cut to the \
         bound; log was:\n{logged}"
    );

    // The length of a claimed user-id is the peer's choice as much as its bytes
    // are: it is everything before the first colon of a base64 blob that may be
    // a whole field section. Unbounded, one guess bought a 288 KB WARN line for
    // 57 KB of upstream — five times the attacker's cost, aimed at the journal
    // that is this server's only forensic channel (review H3).
    let request = authorized_connect("192.0.2.1:443", &"u".repeat(48_000), "wrong-guess");
    let response = respond_to(&mut caller, request).await;
    assert_eq!(response.status, Status::PROXY_AUTHENTICATION_REQUIRED);

    let logged = buffer.contents();
    let bloated = logged
        .lines()
        .find(|line| line.contains("truncated from 48000 bytes"))
        .unwrap_or_else(|| {
            panic!("the huge user-id must be logged, cut short; log was:\n{logged}")
        });
    assert!(
        bloated.len() < 1024,
        "a 48 KB user-id must not buy a log line of its own size; the line was {} bytes",
        bloated.len()
    );

    // The point of the whole exercise: no `Option` reaches an operator's eyes.
    assert!(
        !logged.contains("Some("),
        "no operator-facing field may print Rust's Option spelling; log was:\n{logged}"
    );
}
