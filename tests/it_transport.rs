//! M7 increment: the QUIC transport parameters are configuration, not constants.
//!
//! `max_idle_timeout` is the one of the five that can be observed from outside
//! without reaching into quinn, so it stands in for the group: if the configured
//! value reaches `TransportConfig`, it reaches it for all of them, since they are
//! set together in `quic::server_config`.
//!
//! The second test is the one that matters for operations. The README tells an
//! operator to lower `keep_alive_interval` when the relay's conntrack timeout is
//! shorter than the default, and the way to apply that is `systemctl reload` — so
//! a reload really has to carry transport parameters to new connections, not just
//! credentials and certificates.

mod common;

use std::time::{Duration, Instant};

use common::{H3Client, TestServer, ALLOW_PRIVATE, IMPATIENT, TIMEOUT};
/// The configured idle timeout is the one that applies.
///
/// Asserting both bounds matters: that the connection closes at all proves the
/// value is not quinn's 30s default or our 60s one, and that it takes about a
/// second proves it closed on the timeout rather than failing outright.
#[tokio::test]
async fn an_idle_connection_is_closed_after_the_configured_timeout() {
    let server = TestServer::start_with(&format!("{IMPATIENT}{ALLOW_PRIVATE}")).await;
    let client = H3Client::connect(&server).await;

    let start = Instant::now();
    let error = tokio::time::timeout(TIMEOUT, client.quic.closed())
        .await
        .expect("a 1s idle timeout must close the connection well within 10s");

    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(750),
        "closed after {elapsed:?}, which is too fast to be the 1s idle timeout: {error}"
    );
    assert!(
        matches!(error, quinn::ConnectionError::TimedOut),
        "expected an idle timeout, got {error}"
    );
}

/// A reload carries transport parameters to new connections — and leaves the ones
/// already negotiated alone, because QUIC cannot renegotiate them mid-connection.
#[tokio::test]
async fn reloading_changes_the_transport_parameters_for_new_connections() {
    // Starts with the defaults: a 60s idle timeout and keep-alives on.
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let patient = H3Client::connect(&server).await;

    server.rewrite_config(&format!("{IMPATIENT}{ALLOW_PRIVATE}"));
    server.reload().expect("the reload must apply");

    // A connection accepted after the reload gets the new timeout.
    let impatient = H3Client::connect(&server).await;
    let start = Instant::now();
    tokio::time::timeout(TIMEOUT, impatient.quic.closed())
        .await
        .expect("the reloaded idle timeout must apply to new connections");
    assert!(
        start.elapsed() >= Duration::from_millis(750),
        "closed too fast to be the 1s idle timeout"
    );

    // The connection that predates the reload kept the 60s timeout it negotiated,
    // so it is still up even though the impatient one has already gone.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), patient.quic.closed())
            .await
            .is_err(),
        "an established connection must keep the transport parameters it negotiated"
    );
}
