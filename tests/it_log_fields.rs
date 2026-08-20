//! Operator-facing log fields print values, not Rust's `Option` spelling.
//!
//! The four fields asserted here — `alpn`, `server_name`, `target`, `username` —
//! used to be formatted with tracing's `?` sigil straight off an `Option`, so
//! production lines read `alpn=Some("h3")` and `target=Some(104.16.132.229:80)`.
//! Nothing pinned that shape, which is the failure mode D51 catalogued: the
//! predicate is tested, the last hop to the observable output is not, and a
//! change to it goes unnoticed until someone reads a log a week later. Hence this
//! binary.
//!
//! The absent half of each field is unit-tested in `volto::logfmt` instead: a
//! handshake without ALPN cannot complete against this server, and a socket whose
//! `peer_addr()` fails is not something a test can arrange.

mod common;

use common::{
    auth_section, basic_credentials, connect_request, open_tcp_tunnel, respond_to,
    spawn_echo_target, H3Client, SharedBuffer, TestServer, ALLOW_PRIVATE,
};
use http::{HeaderName, StatusCode};

/// One test function: `tracing_subscriber::fmt().init()` is process-wide, so
/// splitting these would race over installing it.
#[tokio::test]
async fn operator_facing_fields_print_values_not_options() {
    let buffer = SharedBuffer::default();
    tracing_subscriber::fmt()
        .with_env_filter("volto=info")
        .with_writer(buffer.clone())
        .with_ansi(false)
        .init();

    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;
    let _stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

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

    // The `username` of a rejected attempt, on the WARN line a fail2ban rule
    // reads. A second server because the first one has no users configured.
    let guarded = TestServer::start_with(&auth_section(&[("user1", "a-real-password")])).await;
    let mut caller = H3Client::connect(&guarded).await;
    let mut request = connect_request("192.0.2.1:443");
    request.headers_mut().insert(
        HeaderName::from_static("proxy-authorization"),
        basic_credentials("user1", "wrong-guess")
            .parse()
            .expect("header value"),
    );
    let response = respond_to(&mut caller, request).await;
    assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);

    let logged = buffer.contents();
    let failure = logged
        .lines()
        .find(|line| line.contains("authentication failed"))
        .unwrap_or_else(|| panic!("no authentication failed line; log was:\n{logged}"));
    assert!(
        failure.contains("username=user1"),
        "the attempted user-id must print as its value; line was:\n{failure}"
    );

    // The point of the whole exercise: no `Option` reaches an operator's eyes.
    assert!(
        !logged.contains("Some("),
        "no operator-facing field may print Rust's Option spelling; log was:\n{logged}"
    );
}
