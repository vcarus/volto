//! The authentication path must not log the attempted password, in any form.
//!
//! The request log (`it_logging`) names the credential header and redacts its
//! value; this binary proves the authentication path adds no copy in
//! plaintext.

mod common;

use common::{
    H3Client, SharedBuffer, TestServer, auth_section, authorize, basic_credentials,
    connect_request, respond_to,
};
use volto::h3api::Status;

const USERNAME: &str = "user1";
const PASSWORD: &str = "unlikely-plaintext-password";

/// A guess is refused, and nothing derived from it, or from the credential it
/// was guessing at, survives in the log.
#[tokio::test]
async fn the_authentication_path_never_puts_a_credential_in_the_log() {
    let buffer = SharedBuffer::shared("volto=debug");

    // Before the server starts, not after: what is asserted below is that the
    // password appears in *no* line this test produced, and startup is where a
    // configuration dump would put one.
    let mark = buffer.mark();

    let server = TestServer::start_with(&auth_section(&[(USERNAME, PASSWORD)])).await;
    let mut client = H3Client::connect(&server).await;

    // Right user, wrong password: the case where a log line is most tempted to
    // include what was tried.
    let attempted = basic_credentials(USERNAME, "wrong-guess");
    let mut request = connect_request("192.0.2.1:443");
    authorize(&mut request, &attempted);

    let response = respond_to(&mut client, request).await;
    assert_eq!(response.status, Status::PROXY_AUTHENTICATION_REQUIRED);

    let logged = buffer.since(mark);

    // The failure is visible, and says why; `it_log_fields` reads its
    // `username`.
    let failure = logged
        .lines()
        .find(|line| line.contains("authentication failed"))
        .unwrap_or_else(|| panic!("the failure must be logged; log was:\n{logged}"));
    assert!(failure.contains("credentials rejected"), "{failure}");

    // No line carries the attempted password, at the debug level where a
    // forensic dump would put it.
    assert!(
        !logged.contains("wrong-guess"),
        "the attempted password must not be logged; log was:\n{logged}"
    );

    // And the real password appears nowhere at all, in any form.
    assert!(
        !logged.contains(PASSWORD),
        "the configured password must never be logged; log was:\n{logged}"
    );

    // Nor the attempted credential, in any line.
    assert!(
        !logged.contains(attempted.trim_start_matches("Basic ")),
        "no credential may survive anywhere in the log; log was:\n{logged}"
    );
}
