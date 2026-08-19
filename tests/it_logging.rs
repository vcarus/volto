//! Every inbound request must be logged at DEBUG, with credentials redacted.
//!
//! This is how Surge's actual wire behaviour will be established on first
//! contact — which header it carries credentials in, which URI template it uses
//! for CONNECT-UDP — so the logging is a deliverable in its own right, not a
//! debugging aid. Without a subscriber installed the logging code short-circuits
//! and never runs, hence this dedicated test binary with a capturing subscriber.
//!
//! The tension this test pins down: the header *name* and the auth scheme must
//! survive, because that is the evidence decision D3 is waiting for, while the
//! credential itself must not reach the log at all.

mod common;

use common::{closed_address, connect_request, respond_to, H3Client, SharedBuffer, TestServer};

#[tokio::test]
async fn inbound_requests_are_logged_with_every_header() {
    let buffer = SharedBuffer::default();
    tracing_subscriber::fmt()
        .with_env_filter("volto=debug")
        .with_writer(buffer.clone())
        .with_ansi(false)
        .init();

    let server = TestServer::start().await;
    // Nothing needs to be listening: the request is logged before we dial out.
    let target = closed_address().await;
    let mut client = H3Client::connect(&server).await;

    let mut request = connect_request(&target.to_string());
    request
        .headers_mut()
        .insert("authorization", "Basic dXNlcjE6c2VjcmV0".parse().unwrap());
    request
        .headers_mut()
        .insert("x-volto-probe", "surge-behaviour".parse().unwrap());

    // Once the response is in, the request has certainly been logged.
    let _ = respond_to(&mut client, request).await;

    let logged = buffer.contents();

    assert!(logged.contains("inbound request"), "log was:\n{logged}");
    assert!(logged.contains("method=CONNECT"), "log was:\n{logged}");
    assert!(
        logged.contains(&target.to_string()),
        "the authority must be logged; log was:\n{logged}"
    );
    // `:protocol` is absent on a classic CONNECT, and that must be visible
    // rather than omitted: it is what distinguishes a TCP tunnel request.
    assert!(logged.contains("protocol=None"), "log was:\n{logged}");

    // M6 reversed this assertion. The credential header still has to *appear* --
    // establishing which header Surge uses is the whole point of this log, and
    // decision D3 is still open -- but its value must not.
    assert!(
        logged.contains("authorization: Basic <redacted 16 bytes>"),
        "the credential header must be logged with its scheme and a redacted \
         value; log was:\n{logged}"
    );
    assert!(
        !logged.contains("dXNlcjE6c2VjcmV0"),
        "the credential must not appear anywhere in the log; log was:\n{logged}"
    );
    // Non-credential headers are unaffected: they are the other half of what this
    // log exists for.
    assert!(
        logged.contains("x-volto-probe: surge-behaviour"),
        "arbitrary headers must be logged; log was:\n{logged}"
    );
}
