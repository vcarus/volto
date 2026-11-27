//! Operator-facing log fields print values, not Rust's `Option` spelling.
//!
//! The fields asserted here are `alpn`, `server_name`, `target` on both tunnel
//! lines, and `username` (D51: the last hop to the output is what this binary
//! tests).
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
    ALLOW_PRIVATE, H3Client, SharedBuffer, TestServer, auth_section, authorized_connect,
    numeric_field, open_tcp_tunnel, open_udp_session, respond_to, spawn_echo_target,
    spawn_udp_echo_target,
};
use volto::h3api::Status;

#[tokio::test]
async fn operator_facing_fields_print_values_not_options() {
    let buffer = SharedBuffer::shared("volto=info");

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

    // The session line, same field, other tunnel.
    let session = logged
        .lines()
        .find(|line| line.contains("udp session established"))
        .unwrap_or_else(|| panic!("no udp session established line; log was:\n{logged}"));
    assert!(
        session.contains(&format!("target={udp_target}")),
        "the connected address must print as its value; line was:\n{session}"
    );

    // How long each tunnel took to set up, in whole milliseconds, on the line
    // that says it is established. The parts are measured inside the whole, so
    // they cannot add up to more than it. Both targets are on loopback, so the
    // values are near zero and only their presence and that order are judged.
    let (resolve, connect, setup) = (
        numeric_field(tunnel, "resolve_ms"),
        numeric_field(tunnel, "connect_ms"),
        numeric_field(tunnel, "setup_ms"),
    );
    assert!(
        resolve + connect <= setup && setup < 10_000,
        "resolving and connecting are parts of the setup; line was:\n{tunnel}"
    );
    assert!(
        numeric_field(session, "resolve_ms") <= numeric_field(session, "setup_ms"),
        "resolving is a part of the setup; line was:\n{session}"
    );
    assert!(
        !session.contains("connect_ms="),
        "a UDP session connects to nothing, so it has no connect time; line was:\n{session}"
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
    // a whole field section.
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

    // The close line's nine controller readings come from this crate's own
    // controller.
    // Under another one there is nothing to count, and each field prints the
    // dash an absent value prints as, not a zero that would read as a
    // measurement.
    let other = TestServer::start_with("[limits]\ncongestion_control = \"cubic\"\n").await;
    let mark = buffer.mark();
    let leaving = H3Client::connect(&other).await;
    leaving.quic.close(quinn::VarInt::from_u32(0), b"");
    let closed = buffer
        .wait_for_line(mark, &["connection closed", "reason=\"peer_close\""])
        .await;
    for field in [
        "window_limited_ms=-",
        "window_floor_ms=-",
        "window_floor_lossless_ms=-",
        "peak_bytes_per_sec=-",
        "window_turnover_permille=-",
        "flight_over_min_rtt_permille=-",
        "base_loss_mean_ppm=-",
        "base_loss_peak_ppm=-",
        "gain_mean_permille=-",
    ] {
        assert!(
            closed.contains(field),
            "under `cubic` the close line must carry {field}; line was:\n{closed}"
        );
    }

    // The point of the whole exercise: no `Option` reaches an operator's eyes.
    assert!(
        !logged.contains("Some("),
        "no operator-facing field may print Rust's Option spelling; log was:\n{logged}"
    );
}
