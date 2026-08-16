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

    /// How much has been logged so far, as an offset for [`Self::since`].
    ///
    /// Lines are written whole, so this is always a line boundary. Taking one
    /// before each scenario is what stops a scenario from being satisfied by an
    /// earlier scenario's line — two of them close for the same reason.
    fn mark(&self) -> usize {
        self.0.lock().expect("buffer lock").len()
    }

    /// Everything logged after `mark`.
    fn since(&self, mark: usize) -> String {
        let buffer = self.0.lock().expect("buffer lock");
        String::from_utf8_lossy(&buffer[mark.min(buffer.len())..]).into_owned()
    }

    /// Waits for a line logged after `mark` containing every one of `needles`.
    ///
    /// Polled rather than slept through: the server logs from its own task, so
    /// the line appears some unpredictable moment after the client observes the
    /// connection go away.
    async fn wait_for_line(&self, mark: usize, needles: &[&str]) -> String {
        let deadline = Instant::now() + TIMEOUT;

        loop {
            let logged = self.since(mark);
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

/// Generous upper bound for a shutdown that has nothing to drain.
const STOP_TIMEOUT: Duration = Duration::from_secs(20);

/// The five ways a connection ends, each with the level and reason it earns.
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

    let mut server = TestServer::start_with(&format!("{IMPATIENT}{ALLOW_PRIVATE}")).await;

    // 1. The peer goes silent and the idle timeout expires. This is the case the
    //    production logs were full of, misfiled as an error.
    {
        let mark = buffer.mark();
        let client = H3Client::connect(&server).await;
        let error = tokio::time::timeout(TIMEOUT, client.quic.closed())
            .await
            .expect("a 1s idle timeout must close the connection well within 10s");
        assert!(
            matches!(error, quinn::ConnectionError::TimedOut),
            "expected an idle timeout, got {error}"
        );

        let line = buffer
            .wait_for_line(mark, &[" INFO ", "connection closed", "reason=\"idle\""])
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
        let mark = buffer.mark();
        let client = H3Client::connect(&server).await;
        client.quic.close(quinn::VarInt::from_u32(0), b"");

        let line = buffer
            .wait_for_line(
                mark,
                &[" INFO ", "connection closed", "reason=\"peer_close\""],
            )
            .await;
        assert!(
            !line.contains("with error"),
            "a clean peer close must not be logged as an error; line was:\n{line}"
        );
    }

    // 3. Any other application error code is the peer reporting a problem, and
    //    still deserves a warning.
    {
        let mark = buffer.mark();
        let client = H3Client::connect(&server).await;
        client.quic.close(quinn::VarInt::from_u32(42), b"");

        buffer
            .wait_for_line(
                mark,
                &[" WARN ", "connection closed with error", "ApplicationClose"],
            )
            .await;
    }

    // 4. H3_NO_ERROR (0x100), which RFC 9114 §8.1 defines as "no error [...] used
    //    when the connection or stream needs to be closed, but there is no error
    //    to signal". Surge does not send it — it uses 0x0, scenario 2 — so this
    //    branch has no production traffic keeping it honest, and dropping it
    //    would put every spec-following client back into the warning stream.
    {
        let mark = buffer.mark();
        let client = H3Client::connect(&server).await;
        client.quic.close(quinn::VarInt::from_u32(0x100), b"");

        let line = buffer
            .wait_for_line(
                mark,
                &[" INFO ", "connection closed", "reason=\"peer_close\""],
            )
            .await;
        assert!(
            !line.contains("with error"),
            "H3_NO_ERROR is the absence of an error; line was:\n{line}"
        );
    }

    // 5. The server shuts down: GOAWAY goes out, there is nothing to drain, and
    //    the accept loop returns `Ok(())` on its own terms rather than through an
    //    error. Last, because it stops the server.
    {
        let mark = buffer.mark();
        let client = H3Client::connect(&server).await;
        server.shutdown();

        let line = buffer
            .wait_for_line(mark, &[" INFO ", "connection closed", "reason=\"drained\""])
            .await;
        assert!(
            !line.contains("with error"),
            "a completed drain is the tidiest ending there is; line was:\n{line}"
        );

        drop(client);
        server.wait_until_stopped(STOP_TIMEOUT).await;
    }

    // Every routine close still carries the two diagnostic fields the transport
    // is tuned from. Both are read off the connection *after* `conn::handle` has
    // returned and dropped the HTTP/3 layer — the same object at the same moment
    // that made `close_reason()` unusable — so nothing but an assertion stands
    // between them and quietly becoming a placeholder. `initial_rtt_ms = 150`
    // was derived from `rtt_ms` samples, and `remote_now` is the only externally
    // visible trace of a migration or NAT rebind mid-connection.
    let logged = buffer.contents();
    let closes: Vec<&str> = logged
        .lines()
        .filter(|line| line.contains(" INFO ") && line.contains("connection closed"))
        .collect();
    assert_eq!(
        closes.len(),
        4,
        "four of the five closes are routine; log was:\n{logged}"
    );
    for line in &closes {
        assert!(
            line.contains("rtt_ms="),
            "a close log must carry the measured RTT; line was:\n{line}"
        );
        // The real address, not an empty or default one: this is what a
        // migration would show up as having changed.
        assert!(
            line.contains("remote_now=127.0.0.1:"),
            "a close log must carry the address the peer ended on; line was:\n{line}"
        );
    }

    // The whole point of the grading: exactly one of the five closes was worth a
    // warning, and it was none of the routine ones.
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
