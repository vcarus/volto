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

use bytes::Bytes;
use common::{
    open_tcp_tunnel, read_at_least, spawn_echo_target, H3Client, SharedBuffer, TestServer,
    ALLOW_PRIVATE, IMPATIENT, STOP_TIMEOUT, TIMEOUT,
};

/// Reads a numeric field's value off a formatted log line.
///
/// Most assertions here pin a field's presence, which is enough for a counter
/// whose value the test cannot arrange. The traffic counters can be arranged —
/// this connection did send packets — and a field wired to the wrong source is
/// present and zero rather than absent, so those are read rather than matched.
#[track_caller]
fn numeric_field(line: &str, name: &str) -> u64 {
    let rest = line
        .split_once(&format!("{name}="))
        .unwrap_or_else(|| panic!("no {name}= in:\n{line}"))
        .1;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("{name}= is not a number in:\n{line}"))
}

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
    let echo = spawn_echo_target().await;

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
        // Nothing was ever tunnelled over this connection, and the counter has
        // to say so rather than fall to whatever the previous one held.
        assert!(
            line.contains("tunnels=0"),
            "a connection that opened no tunnel must report none; line was:\n{line}"
        );
    }

    // 2. The peer closes cleanly with application error code 0x0, which is what
    //    Surge sends. Nothing slow may happen between connecting and closing, or
    //    the 1s idle timeout would decide this scenario instead.
    //
    //    This is also the one connection here that does any work — a tunnel with
    //    a payload echoed back through it — so it is where the traffic counters
    //    are read with something in them.
    {
        let mark = buffer.mark();
        let mut client = H3Client::connect(&server).await;
        let mut tunnel = open_tcp_tunnel(&mut client, &echo.to_string()).await;
        tunnel
            .send_data(Bytes::from_static(b"payload"))
            .await
            .expect("send payload");
        assert_eq!(read_at_least(&mut tunnel, 7).await, b"payload");
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
        // One request took a tunnel slot on this connection, and only one.
        assert!(
            line.contains("tunnels=1"),
            "the connection that opened one tunnel must report one; line was:\n{line}"
        );
        // Bytes and packets are read off the transport, so a connection that
        // completed a handshake and echoed a payload cannot report zero in
        // either direction.
        assert!(
            numeric_field(&line, "tx_bytes") > 0,
            "a connection that answered must have sent UDP bytes; line was:\n{line}"
        );
        assert!(
            numeric_field(&line, "rx_bytes") > 0,
            "a connection that was driven must have received UDP bytes; line was:\n{line}"
        );
        assert!(
            numeric_field(&line, "sent_packets") > 0,
            "a connection that answered must have sent packets; line was:\n{line}"
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

    // Every routine close still carries the diagnostic fields the transport is
    // read through. All are taken off the connection *after* `conn::handle`
    // has returned and dropped the HTTP/3 layer — the same object at the same
    // moment that made `close_reason()` unusable — so nothing but an assertion
    // stands between them and quietly becoming a placeholder. `initial_rtt_ms =
    // 150` was derived from `rtt_ms` samples, `remote_now` is the only
    // externally visible trace of a migration or NAT rebind mid-connection,
    // `mtu` is what path MTU discovery settled on, `mtu_black_holes` is how
    // often it was knocked back to the floor on the way, and the five D72
    // counters say how much the connection carried while it lasted.
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
        // The packet size DPLPMTUD settled on, which is how an operator tells a
        // path that carried the probes from one that black-holed them. Never
        // below the QUIC floor, so a zero here is a placeholder rather than a
        // measurement.
        assert!(
            line.contains("mtu=1"),
            "a close log must carry the path MTU discovery settled on; line was:\n{line}"
        );
        // Loopback drops nothing, so the detector has nothing to fire on: the
        // count is a real zero, and its presence is what is being pinned.
        assert!(
            line.contains("mtu_black_holes=0"),
            "a close log must carry the black-hole detector's count; line was:\n{line}"
        );
        // The real address, not an empty or default one: this is what a
        // migration would show up as having changed.
        assert!(
            line.contains("remote_now=127.0.0.1:"),
            "a close log must carry the address the peer ended on; line was:\n{line}"
        );
        // How much this connection carried: one tunnel count and four transport
        // counters, all taken from the same snapshot as the fields above. Their
        // values depend on what the scenario did — scenario 2 is where they are
        // checked against real traffic — but every close line owes them.
        for field in [
            "tunnels=",
            "tx_bytes=",
            "rx_bytes=",
            "sent_packets=",
            "lost_packets=",
        ] {
            assert!(
                line.contains(field),
                "a close log must carry {field}; line was:\n{line}"
            );
        }
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
