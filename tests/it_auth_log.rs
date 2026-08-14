//! An authentication failure must be logged without the attempted password.
//!
//! Its own test binary because a capturing subscriber has to be installed
//! globally and only once per process (`it_logging` does the same for the inbound
//! request log). The two are complementary: that one proves credentials *are*
//! logged verbatim by the request log until M6 redacts them, this one proves the
//! authentication path never adds a second copy in plaintext.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::{auth_section, basic_credentials, connect_request, H3Client, TestServer, TIMEOUT};
use http::{HeaderName, StatusCode};
use tracing_subscriber::fmt::MakeWriter;

const USERNAME: &str = "user1";
const PASSWORD: &str = "unlikely-plaintext-password";

/// A writer that accumulates everything logged into a shared buffer.
#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("buffer lock")).into_owned()
    }
}

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedBuffer {
    type Writer = SharedBuffer;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn a_rejected_password_is_never_logged() {
    let buffer = SharedBuffer::default();
    tracing_subscriber::fmt()
        .with_env_filter("volto=debug")
        .with_writer(buffer.clone())
        .with_ansi(false)
        .init();

    let server = TestServer::start_with(&auth_section(&[(USERNAME, PASSWORD)])).await;
    let mut client = H3Client::connect(&server).await;

    // Right user, wrong password: the case where a log line is most tempted to
    // include what was tried.
    let attempted = basic_credentials(USERNAME, "wrong-guess");
    let mut request = connect_request("192.0.2.1:443");
    request.headers_mut().insert(
        HeaderName::from_static("proxy-authorization"),
        attempted.parse().expect("header value"),
    );

    let mut stream = client
        .send
        .send_request(request)
        .await
        .expect("send CONNECT");
    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("response arrived")
        .expect("response");
    assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);

    let logged = buffer.contents();

    // The failure is visible, and says who and why.
    let failure = logged
        .lines()
        .find(|line| line.contains("authentication failed"))
        .unwrap_or_else(|| panic!("the failure must be logged; log was:\n{logged}"));
    assert!(failure.contains(USERNAME), "{failure}");
    assert!(failure.contains("credentials rejected"), "{failure}");

    // But it carries nothing derived from the secret — neither the guess nor the
    // encoded credential it arrived in.
    assert!(
        !failure.contains("wrong-guess"),
        "the attempted password must not be logged: {failure}"
    );
    assert!(
        !failure.contains(attempted.trim_start_matches("Basic ")),
        "the encoded credential must not be logged: {failure}"
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
