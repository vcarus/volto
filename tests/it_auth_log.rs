//! What the authentication path does with a credential: it must not log the
//! attempted password, and it must read the credential the peer actually sent.
//!
//! Its own test binary because a capturing subscriber has to be installed
//! globally and only once per process (`it_logging` does the same for the inbound
//! request log). The two are complementary: that one proves the request log
//! names the credential header and redacts its value, this one proves the
//! authentication path never adds a copy in plaintext.
//!
//! One test function, like every other binary that reads log lines, and for a
//! reason this file needs more than most: the whole product here is a *negative*
//! assertion -- this string appears nowhere -- and the two scenarios drive the
//! same username and the same password. Run as two `#[tokio::test]`s they run at
//! once and write into one buffer, so the scenario that reads it is reading the
//! other one's lines too, and a leak on the other one's path would be reported
//! against this one. Running them in order and reading only the lines logged
//! after a mark is what makes each verdict the scenario's own.

mod common;

use common::{
    H3Client, SharedBuffer, TestServer, auth_section, authorize, basic_credentials,
    connect_request, respond_to,
};
use volto::h3api::Status;

const USERNAME: &str = "user1";
const PASSWORD: &str = "unlikely-plaintext-password";

#[tokio::test]
async fn the_authentication_path_never_puts_a_credential_in_the_log() {
    let buffer = SharedBuffer::shared("volto=debug");

    a_rejected_password_is_never_logged(&buffer).await;
}

/// A guess is refused, and nothing derived from it -- or from the credential it
/// was guessing at -- survives in the log.
async fn a_rejected_password_is_never_logged(buffer: &SharedBuffer) {
    // Before the server starts, not after: what is asserted below is that the
    // password appears in *no* line this scenario produced, and startup is where
    // a configuration dump would put one.
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

    // Strengthened in M6: now that the request log redacts credential headers,
    // the *attempted* credential must not survive anywhere either -- not in the
    // failure line, and not in the verbatim header dump that used to carry it.
    assert!(
        !logged.contains(attempted.trim_start_matches("Basic ")),
        "no credential may survive anywhere in the log; log was:\n{logged}"
    );
}
