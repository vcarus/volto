//! The three tunnel log lines whose *level* and *wording* are the product.
//!
//! Each of these lines is read by something other than a person debugging: the
//! DNS-blackhole line was demoted to INFO so that `journalctl -p warning` means
//! something again (D44, 89% of a day's warnings were that one line), the policy
//! refusal was deliberately left at WARN because SSRF-shaped evidence must stay
//! loud, and the oversized-datagram line is the only sentinel watching whether
//! the peer has lowered `max_datagram_frame_size` under us (D48 §3).
//!
//! None of that is visible to a test that only checks the response: the decision
//! functions behind these lines (`policy::is_dns_blackhole`, `oversize_verdict`)
//! are unit-tested and stay green if the line they feed is renamed, demoted, or
//! bypassed entirely. That last hop is what this binary drives — mutating the
//! blackhole `info!` into a `warn!` leaves all 19 `it_policy` tests passing.
//!
//! One test function, because `tracing_subscriber::fmt().init()` may run once per
//! process. The scenarios are attributed to each other by taking a mark into the
//! shared buffer before each one and only reading the lines logged after it.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{
    connect_request, spawn_large_reply_udp_target, H3Client, TestServer, ALLOW_PRIVATE, TIMEOUT,
};
use http::StatusCode;
use tracing_subscriber::fmt::MakeWriter;
use volto::datagram;

/// A name whose every address is the unspecified one: the shape a filtering
/// resolver returns, and the only thing `is_dns_blackhole` accepts.
const BLACKHOLED: &str = "0.0.0.0:443";

/// Loopback, which the default policy refuses. A different authority from
/// [`BLACKHOLED`] so the two scenarios' lines can never be confused.
const PROHIBITED: &str = "127.0.0.1:443";

/// A writer that accumulates everything logged into a shared buffer.
#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    /// How much has been logged so far, as an offset for [`Self::since`].
    ///
    /// Lines are written whole, so this is always a line boundary.
    fn mark(&self) -> usize {
        self.0.lock().expect("buffer lock").len()
    }

    /// Everything logged after `mark`.
    fn since(&self, mark: usize) -> String {
        let buffer = self.0.lock().expect("buffer lock");
        String::from_utf8_lossy(&buffer[mark.min(buffer.len())..]).into_owned()
    }

    /// The lines logged after `mark` that contain every one of `needles`.
    fn lines_since(&self, mark: usize, needles: &[&str]) -> Vec<String> {
        self.since(mark)
            .lines()
            .filter(|line| needles.iter().all(|needle| line.contains(needle)))
            .map(str::to_owned)
            .collect()
    }

    /// Waits for a line logged after `mark` containing every one of `needles`.
    ///
    /// Polled rather than slept through: the server logs from its own task, so
    /// the line lands some unpredictable moment after the client sees a result.
    async fn wait_for_line(&self, mark: usize, needles: &[&str]) -> String {
        let deadline = Instant::now() + TIMEOUT;

        loop {
            if let Some(line) = self.lines_since(mark, needles).into_iter().next() {
                return line;
            }

            assert!(
                Instant::now() < deadline,
                "no line containing {needles:?} within {TIMEOUT:?}; log was:\n{}",
                self.since(mark)
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
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
async fn tunnel_refusals_and_drops_are_logged_at_the_level_they_were_graded() {
    let buffer = SharedBuffer::default();
    tracing_subscriber::fmt()
        .with_env_filter("volto=info")
        .with_writer(buffer.clone())
        .with_ansi(false)
        .init();

    blackhole_is_information(&buffer).await;
    policy_refusal_is_still_a_warning(&buffer).await;
    the_oversize_sentinel_fires_once_per_session(&buffer).await;
}

/// D44/D49: a name the resolver blackholed is not this proxy's verdict, so its
/// line is INFO and nothing about it may reach WARN.
///
/// The server runs the *default* policy, which is the point: the unspecified
/// address is in the never-allowed bucket, so this branch is reached the same way
/// whatever `allow_private_networks` says, and the comparison against the next
/// scenario is between two refusals of the same server.
async fn blackhole_is_information(buffer: &SharedBuffer) {
    let server = TestServer::start_with("").await;
    let mut client = H3Client::connect(&server).await;
    let mark = buffer.mark();

    let mut stream = client
        .send
        .send_request(connect_request(BLACKHOLED))
        .await
        .expect("send CONNECT");
    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("response arrived")
        .expect("response");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a blackholed name is accepted and closed, not refused (D49)"
    );

    let line = buffer
        .wait_for_line(
            mark,
            &[" INFO ", "every address of the target is a DNS blackhole"],
        )
        .await;
    assert!(
        line.contains(BLACKHOLED),
        "the line must name the authority it is about: {line}"
    );

    // The half that makes the demotion worth anything: nothing about this
    // request may still be shouting. Matched on the authority so an unrelated
    // warning from another scenario cannot satisfy it.
    let warnings = buffer.lines_since(mark, &[" WARN ", BLACKHOLED]);
    assert!(
        warnings.is_empty(),
        "a blackholed name must produce no warning at all, got:\n{}",
        warnings.join("\n")
    );
}

/// D44's explicit boundary: every *other* refusal keeps its warning.
///
/// A client probing loopback through the proxy is what SSRF looks like from
/// here, and the whole argument for demoting the blackhole line was that it
/// buried evidence like this.
async fn policy_refusal_is_still_a_warning(buffer: &SharedBuffer) {
    let server = TestServer::start_with("").await;
    let mut client = H3Client::connect(&server).await;
    let mark = buffer.mark();

    let mut stream = client
        .send
        .send_request(connect_request(PROHIBITED))
        .await
        .expect("send CONNECT");
    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("response arrived")
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let line = buffer
        .wait_for_line(
            mark,
            &[
                " WARN ",
                "every address of the target is prohibited by policy",
            ],
        )
        .await;
    assert!(
        line.contains(PROHIBITED),
        "the line must name the authority it is about: {line}"
    );
}

/// D48 §2: the first oversized drop of a session is INFO, with the two numbers
/// that make it actionable, and every later one is quiet.
///
/// This is the only reading we have on whether the peer still accepts datagrams
/// of the size we assumed. Its failure mode is why it needs a test: if the line
/// is demoted or the call site bypassed, the journal shows zero occurrences —
/// byte for byte what "no drops are happening" looks like.
async fn the_oversize_sentinel_fires_once_per_session(buffer: &SharedBuffer) {
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    // Comfortably above any QUIC datagram limit on a 1200-1500 byte path.
    let target = spawn_large_reply_udp_target(8000).await;
    let mut client = H3Client::connect(&server).await;
    let mark = buffer.mark();

    let mut stream = client
        .send
        .send_request(common::connect_udp_request(
            server.addr,
            &target.ip().to_string(),
            target.port(),
        ))
        .await
        .expect("send CONNECT-UDP");
    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("response arrived")
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let limit = client
        .quic
        .max_datagram_size()
        .expect("the server must accept datagrams");
    assert!(limit < 8000, "the reply must not fit in a datagram");

    let qsid = datagram::quarter_stream_id(stream.id().into_inner());
    let send_one = |nth: u8| {
        client
            .quic
            .send_datagram(datagram::encode_udp_payload(qsid, &[nth]))
            .expect("send datagram");
    };

    send_one(1);

    let line = buffer
        .wait_for_line(
            mark,
            &[" INFO ", "target packet too large for a QUIC datagram"],
        )
        .await;
    // The numbers are the reading. A line saying only "too large" would tell an
    // operator nothing about how much too large, which is what decides whether
    // `max_datagram_frame_size` moved or the targets simply got chattier.
    assert!(
        line.contains("encoded_len=") && line.contains("limit="),
        "the sentinel must carry the encoded length and the datagram limit: {line}"
    );

    // Two more drops on the same session. Waiting for the *second* of them to be
    // logged at DEBUG is not possible under a `volto=info` subscriber, so the
    // bound is a plain one: nothing more may appear within it.
    send_one(2);
    send_one(3);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let sentinels = buffer.lines_since(
        mark,
        &[" INFO ", "target packet too large for a QUIC datagram"],
    );
    assert_eq!(
        sentinels.len(),
        1,
        "one INFO per session, then silence; got:\n{}",
        sentinels.join("\n")
    );

    // A dropped packet is not a fault: the session survived it, and nothing here
    // is an operator's problem.
    let warnings = buffer.lines_since(mark, &[" WARN "]);
    assert!(
        warnings.is_empty(),
        "dropping an oversized target packet must not warn, got:\n{}",
        warnings.join("\n")
    );
}
