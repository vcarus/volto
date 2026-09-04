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
//!
//! The second half of the test is about the other DEBUG line a request can
//! produce -- the one naming an unimplemented `:protocol`. That token is the
//! peer's bytes, and since audit L6 it must be an RFC 9110 §5.6.2 token, so a
//! newline in one is refused before anything is logged. Both halves of that are
//! asserted: the refusal, and the line the token that *is* a token still draws.

mod common;

use common::rawstream::H3_MESSAGE_ERROR;
use common::{
    H3Client, SharedBuffer, TIMEOUT, TestServer, assert_peer_reset, closed_address,
    connect_request, respond_to,
};

#[tokio::test]
async fn inbound_requests_are_logged_with_every_header() {
    let buffer = SharedBuffer::install("volto=debug");

    let server = TestServer::start().await;
    // Nothing needs to be listening: the request is logged before we dial out.
    let target = closed_address().await;
    let mut client = H3Client::connect(&server).await;

    let mut request = connect_request(&target.to_string());
    request.fields.append(
        "authorization",
        common::field_value("Basic dXNlcjE6c2VjcmV0"),
    );
    request
        .fields
        .append("x-volto-probe", common::field_value("surge-behaviour"));

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

    // A token carrying a newline reaches no log line at all: it is not an
    // RFC 9110 §5.6.2 token, so the request is malformed and the stream is reset
    // before anything is logged (audit L6). It used to be accepted, classified
    // as an unimplemented protocol and echoed into a DEBUG line of its own --
    // and systemd splits a service's stdout on `\n`, so printed through
    // `Display` it was a complete forged entry, stamped with volto's unit and a
    // timestamp of its own (review M5). The escaping that answered M5 is still
    // there and neither half is worth depending on alone, so what is asserted
    // here is the outcome both of them exist for.
    let mut forgery = connect_request(&target.to_string());
    forgery.scheme = Some("https".into());
    forgery.path = Some("/".into());
    forgery.protocol = Some("x\nWARN volto - forged".into());

    let mut stream = client
        .send
        .send_request(forgery)
        .await
        .expect("send a :protocol that is not a token");
    let error = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("the server must answer promptly")
        .expect_err("a :protocol that is not a token must be refused as malformed");
    assert_peer_reset(&error, H3_MESSAGE_ERROR);

    let logged = buffer.contents();
    assert!(
        !logged.lines().any(|line| line == "WARN volto - forged"),
        "a newline in a peer's token must not buy it a journal entry; log was:\n{logged}"
    );
    assert!(
        !logged.contains("forged"),
        "a refused :protocol reaches no log line at all; log was:\n{logged}"
    );

    // The DEBUG line an unimplemented `:protocol` draws is still reachable, by a
    // value that is a token: it is the other half of what this log exists for,
    // and a malformed verdict must not have swallowed it.
    let mut unimplemented = connect_request(&target.to_string());
    unimplemented.scheme = Some("https".into());
    unimplemented.path = Some("/".into());
    unimplemented.protocol = Some("connect-ip".into());
    let _ = respond_to(&mut client, unimplemented).await;

    let logged = buffer.contents();
    assert!(
        logged.contains("unsupported :protocol"),
        "an unimplemented :protocol must draw its own line; log was:\n{logged}"
    );
    assert!(
        logged.contains("connect-ip"),
        "and that line must name the token; log was:\n{logged}"
    );
}
