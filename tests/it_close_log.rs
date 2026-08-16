//! How a connection ended must decide the level its closing line is logged at.
//!
//! An idle timeout is the everyday goodbye — Surge abandons connections without
//! a CONNECTION_CLOSE — and so is a peer that closes cleanly. Neither is a fault,
//! so neither may reach WARN; anything else still has to.
//!
//! This test exists because the first attempt at that grading (D36) shipped
//! without one and never worked in production: it asked the QUIC connection for
//! its `close_reason()` after the fact, and that value has already been
//! overwritten with `LocallyClosed` by the time the HTTP/3 connection is dropped
//! on the way out. Only a test that drives a real idle timeout and reads the real
//! log line can tell the two apart, hence this dedicated binary with a capturing
//! subscriber (`tracing_subscriber::fmt().init()` may run once per process).

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{H3Client, TestServer, ALLOW_PRIVATE, TIMEOUT};
use tracing_subscriber::fmt::MakeWriter;

/// One second of idle timeout, with keep-alives off so nothing refreshes it.
///
/// The same fragment `it_transport` uses: a client that connects and then says
/// nothing is timed out by the server after about a second.
const IMPATIENT: &str = "[limits]\nmax_idle_timeout = 1\nkeep_alive_interval = 0\n";

/// A writer that accumulates everything logged into a shared buffer.
#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("buffer lock")).into_owned()
    }

    /// Waits for a logged line containing every one of `needles`.
    ///
    /// Polled rather than slept through: the server logs from its own task, so
    /// the line appears some unpredictable moment after the client observes the
    /// connection go away.
    async fn wait_for_line(&self, needles: &[&str]) -> String {
        let deadline = Instant::now() + TIMEOUT;

        loop {
            let logged = self.contents();
            let found = logged
                .lines()
                .find(|line| needles.iter().all(|needle| line.contains(needle)))
                .map(str::to_owned);

            if let Some(line) = found {
                return line;
            }

            assert!(
                Instant::now() < deadline,
                "no line containing {needles:?} within {TIMEOUT:?}; log was:\n{logged}"
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

/// The three ways a connection ends, each with the level and reason it earns.
///
/// One test function, because the subscriber is process-wide: splitting the
/// scenarios into separate `#[tokio::test]`s would race over installing it.
#[tokio::test]
async fn close_logs_are_graded_by_how_the_connection_ended() {
    let buffer = SharedBuffer::default();
    tracing_subscriber::fmt()
        .with_env_filter("volto=info")
        .with_writer(buffer.clone())
        .with_ansi(false)
        .init();

    let server = TestServer::start_with(&format!("{IMPATIENT}{ALLOW_PRIVATE}")).await;

    // 1. The peer goes silent and the idle timeout expires. This is the case the
    //    production logs were full of, misfiled as an error.
    {
        let client = H3Client::connect(&server).await;
        let error = tokio::time::timeout(TIMEOUT, client.quic.closed())
            .await
            .expect("a 1s idle timeout must close the connection well within 10s");
        assert!(
            matches!(error, quinn::ConnectionError::TimedOut),
            "expected an idle timeout, got {error}"
        );

        let line = buffer
            .wait_for_line(&[" INFO ", "connection closed", "reason=\"idle\""])
            .await;
        assert!(
            !line.contains("with error"),
            "an idle timeout must not be logged as an error; line was:\n{line}"
        );
    }

    // 2. The peer closes cleanly with application error code 0x0, which is what
    //    Surge sends. Nothing slow may happen between connecting and closing, or
    //    the 1s idle timeout would decide this scenario instead.
    {
        let client = H3Client::connect(&server).await;
        client.quic.close(quinn::VarInt::from_u32(0), b"");

        let line = buffer
            .wait_for_line(&[" INFO ", "connection closed", "reason=\"peer_close\""])
            .await;
        assert!(
            !line.contains("with error"),
            "a clean peer close must not be logged as an error; line was:\n{line}"
        );
    }

    // 3. Any other application error code is the peer reporting a problem, and
    //    still deserves a warning.
    {
        let client = H3Client::connect(&server).await;
        client.quic.close(quinn::VarInt::from_u32(42), b"");

        buffer
            .wait_for_line(&[" WARN ", "connection closed with error", "ApplicationClose"])
            .await;
    }

    // The whole point of the grading: exactly one of the three closes was worth a
    // warning, and it was not either of the routine ones.
    let logged = buffer.contents();
    let warnings: Vec<&str> = logged
        .lines()
        .filter(|line| line.contains("connection closed with error"))
        .collect();
    assert_eq!(
        warnings.len(),
        1,
        "only the non-zero application close may warn; log was:\n{logged}"
    );
    assert!(
        !warnings[0].contains("Timeout"),
        "an idle timeout must never reach a warning; line was:\n{}",
        warnings[0]
    );
}
