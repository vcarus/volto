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
//!
//! The last two are about the one transport parameter that is *not* simply the
//! configured value: the bidirectional stream allowance, which a connection
//! starts below and is raised to by authenticating.

// The package-wide default is `deny` (`Cargo.toml`); this file argues for its
// allow: the transport numbers are ones this file writes out itself.
#![allow(clippy::as_conversions)]

mod common;

use std::time::{Duration, Instant};

use common::rawstream::H3_REQUEST_CANCELLED;
use common::{
    ALLOW_PRIVATE, H3Client, IMPATIENT, TIMEOUT, TestServer, auth_section, connect_quic,
    open_tcp_tunnel, read_at_least, spawn_echo_target,
};

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

// ---------------------------------------------------------------------------
// The bidirectional stream allowance
// ---------------------------------------------------------------------------

/// Request streams a peer may have open at once before it has authenticated.
///
/// Stated here rather than imported from `quic::INITIAL_BIDI_STREAMS`, for the
/// reason every other on-wire number in this suite is spelled out: a test that
/// took the server's own constant would agree with it whatever it held, and
/// what is under test is the number that reaches the wire.
const INITIAL_STREAMS: usize = 16;

/// What `[limits] max_streams_bidi` is set to below, and so what a connection
/// past the credentials check is worth.
///
/// Neither 16 nor a power of two nor the shipped default, so that a raise to
/// *this* number cannot be confused with a raise to something else — or with no
/// clamp having been applied in the first place.
const CONFIGURED_STREAMS: usize = 24;

/// A peer that has not authenticated gets the clamp, not `max_streams_bidi`.
///
/// The configured allowance is what a connection is worth once a request on it
/// has passed the credentials check; what the transport parameters advertise at
/// the handshake is a small fixed allowance, so a peer that has proved nothing
/// cannot open a thousand request streams and draw a refusal on each. With the
/// clamp gone this connection would be granted all 1024 and the seventeenth
/// below would open at once.
///
/// Credentials are configured and never sent, so nothing here can lift it.
#[tokio::test]
async fn an_unauthenticated_connection_is_held_to_the_initial_stream_allowance() {
    let server = TestServer::start_with(&format!(
        "[limits]\nmax_streams_bidi = 1024\n{}",
        auth_section(&[("user1", "s3cret")])
    ))
    .await;
    let (_endpoint, connection) = connect_quic(&server).await;

    // Every one of them granted, and without a wait: the clamp is an allowance,
    // not a rationing of the first request.
    let mut streams = Vec::new();
    for n in 0..INITIAL_STREAMS {
        let (mut send, recv) = tokio::time::timeout(TIMEOUT, connection.open_bi())
            .await
            .unwrap_or_else(|_| panic!("request stream {n} of the initial allowance was refused"))
            .expect("open a request stream");

        // A byte apiece, so the streams exist in the server's stream table and
        // not only in this client's bookkeeping -- it is the server freeing
        // them that returns the credit the last block waits for. One byte is
        // not a frame header, let alone a request, so none of them can
        // authenticate.
        send.write_all(&[0x01])
            .await
            .expect("send a byte of a request");
        streams.push((send, recv));
    }

    // The seventeenth is not refused, it is not granted: there is no credit for
    // it, so it never leaves this client's stack. That is backpressure --
    // STREAMS_BLOCKED, RFC 9000 §4.6 -- and not an error, so the connection is
    // untouched by it.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), connection.open_bi())
            .await
            .is_err(),
        "a request stream past the initial allowance must not be granted before \
         authentication"
    );
    assert!(
        connection.close_reason().is_none(),
        "asking for one stream too many is not a protocol violation"
    );

    // And the allowance bounds streams open at once rather than streams opened
    // ever: giving all sixteen back buys sixteen more, with nothing having
    // authenticated in between. All sixteen rather than one, because quinn
    // announces a raised limit only once an eighth of the window has come back
    // -- which is a detail of when credit is announced and not of whether it is
    // returned, and pinning it here would be pinning quinn rather than this
    // server.
    //
    // Reset rather than dropped: a dropped `SendStream` *finishes* the stream,
    // and a request that ends part-way through a frame is a connection error
    // (H3_FRAME_ERROR) rather than a stream that was given back.
    for (send, _) in &mut streams {
        send.reset(quinn::VarInt::from_u32(H3_REQUEST_CANCELLED as u32))
            .expect("abandon a request stream");
    }
    drop(streams);

    for n in 0..INITIAL_STREAMS {
        tokio::time::timeout(TIMEOUT, connection.open_bi())
            .await
            .unwrap_or_else(|_| {
                panic!("a closed request stream must return its credit: stream {n} never came back")
            })
            .expect("open a request stream");
    }
}

/// The first request to authenticate raises the allowance to the configured
/// one, for the life of the connection.
///
/// Twenty-four tunnels open at once on a connection whose handshake advertised
/// sixteen: the first CONNECT is what buys the other eight, and it buys them
/// before it has opened a socket, so a client that fires a burst waits at most
/// the round trip it was already waiting for its first answer.
///
/// The count is the configured value exactly, and the assertion has both edges.
/// Reaching twenty-four proves the raise happened at all; a twenty-fifth being
/// refused proves it went to `[limits] max_streams_bidi` rather than to some
/// other number that merely happens to be larger than the clamp.
///
/// No `[auth]` users, so the first completed request is what gets past the door
/// -- the same door, and the same moment, as a server that checks credentials.
#[tokio::test(flavor = "multi_thread")]
async fn authenticating_raises_the_stream_allowance_to_the_configured_one() {
    let server = TestServer::start_with(&format!(
        "[limits]\nmax_streams_bidi = {CONFIGURED_STREAMS}\n{ALLOW_PRIVATE}"
    ))
    .await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut tunnels = Vec::new();
    for n in 0..CONFIGURED_STREAMS {
        let tunnel = tokio::time::timeout(
            TIMEOUT,
            open_tcp_tunnel(&mut client, &target.to_string()),
        )
        .await
        .unwrap_or_else(|_| {
            panic!(
                "tunnel {n} was never granted a request stream: the allowance was not raised \
                     past the {INITIAL_STREAMS} an unauthenticated connection gets"
            )
        });
        tunnels.push(tunnel);
    }

    // Held open, not opened and closed in turn: what is measured is
    // concurrency, and a connection that opened them one at a time would need
    // an allowance of one.
    for (n, tunnel) in tunnels.iter_mut().enumerate() {
        let payload = format!("tunnel-{n:02}");
        tunnel
            .send_data(bytes::Bytes::from(payload.clone()))
            .await
            .expect("send through a tunnel");
        assert_eq!(
            read_at_least(tunnel, payload.len()).await,
            payload.as_bytes(),
            "tunnel {n} must still be carrying traffic while the other {} are open",
            CONFIGURED_STREAMS - 1
        );
    }

    // The raise is to the configured allowance and stops there.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(500),
            open_tcp_tunnel(&mut client, &target.to_string())
        )
        .await
        .is_err(),
        "authentication must raise the allowance to limits.max_streams_bidi, not past it"
    );
}
