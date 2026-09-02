//! What the authentication path does with a credential: it must not log the
//! attempted password, and it must read the credential the peer actually sent.
//!
//! Its own test binary because a capturing subscriber has to be installed
//! globally and only once per process (`it_logging` does the same for the inbound
//! request log). The two are complementary: that one proves credentials *are*
//! logged verbatim by the request log until M6 redacts them, this one proves the
//! authentication path never adds a second copy in plaintext.
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
    ALLOW_PRIVATE, H3Client, SharedBuffer, TestServer, auth_section, authorize, authorized_connect,
    basic_credentials, connect_request, field_value, respond_to, spawn_echo_target,
};
use volto::h3api::Status;

const USERNAME: &str = "user1";
const PASSWORD: &str = "unlikely-plaintext-password";

#[tokio::test]
async fn the_authentication_path_never_puts_a_credential_in_the_log() {
    let buffer = SharedBuffer::install("volto=debug");

    a_rejected_password_is_never_logged(&buffer).await;
    credentials_padded_with_whitespace_are_still_credentials().await;
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

    // The failure is visible, and says who and why.
    let failure = logged
        .lines()
        .find(|line| line.contains("authentication failed"))
        .unwrap_or_else(|| panic!("the failure must be logged; log was:\n{logged}"));
    assert!(failure.contains(USERNAME), "{failure}");
    assert!(failure.contains("credentials rejected"), "{failure}");

    // But it carries nothing derived from the secret.
    assert!(
        !failure.contains("wrong-guess"),
        "the attempted password must not be logged: {failure}"
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

/// RFC 9110 §5.5: the optional whitespace around a field value is not part of
/// the value, so a credential padded with one is the same credential.
///
/// A leading space is what an HTTP/1 habit produces -- `Proxy-Authorization:
/// Basic ...` writes one after the colon, and a client that carries the field
/// across unchanged carries the space with it. Read literally, that value has an
/// empty auth scheme and is refused: a 407 to a peer that guessed nothing, and
/// one of the `max_auth_failures` attempts that are meant to cost a guesser its
/// connection.
///
/// A live target rather than a refusal, so what is asserted is the tunnel
/// opening and not merely a different way of being turned away.
///
/// Reads no log lines, and takes no mark: it is here because it belongs to the
/// credential-handling story this binary tells, and its only claim is on the
/// wire.
async fn credentials_padded_with_whitespace_are_still_credentials() {
    let server = TestServer::start_with(&format!(
        "{ALLOW_PRIVATE}{}",
        auth_section(&[(USERNAME, PASSWORD)])
    ))
    .await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // Both ends, and a HTAB as well as a space: the whitespace §5.5 excludes is
    // the SP and HTAB of its `field-content` grammar.
    let padded = format!(" {}\t", basic_credentials(USERNAME, PASSWORD));
    let mut request = connect_request(&target.to_string());
    request
        .fields
        .append("proxy-authorization", field_value(&padded));

    let response = respond_to(&mut client, request).await;
    assert_eq!(
        response.status,
        Status::OK,
        "padded credentials must open the tunnel: proxy-status={:?}",
        response.fields.get("proxy-status")
    );

    // The same credentials unpadded, so the case above cannot be passing for
    // want of any authentication at all.
    let response = respond_to(
        &mut client,
        authorized_connect(&target.to_string(), USERNAME, PASSWORD),
    )
    .await;
    assert_eq!(response.status, Status::OK);
}
