//! TCP CONNECT tunnels (RFC 9114 §4.4).
//!
//! # Close semantics
//!
//! A CONNECT tunnel is two independent byte streams, and getting their
//! termination right is what makes protocols that half-close (notably older
//! HTTP and some database clients) work through the proxy:
//!
//! | event | reaction |
//! |---|---|
//! | client finishes its sending side (FIN) | shut down **only** the write side of the TCP socket, keep reading from the target |
//! | target reaches EOF | finish our sending side, keep reading from the client |
//! | target resets or errors | reset the request stream with `H3_CONNECT_ERROR`, whichever direction noticed |
//! | client resets the request stream, or stops reading it | close the TCP connection with a reset |
//!
//! The two directions therefore run as independent pumps that are joined, plus a
//! sticky teardown signal for the abnormal cases where one direction failing
//! must stop the other. The signal carries *why* the tunnel is being torn down —
//! see `Teardown` below — because the two reasons need opposite things from the pump
//! that did not see the failure: a target error has to be spelled out on that
//! half too, whereas a client abort has already been spelled out by the client.
//!
//! Only the last row aborts the TCP connection; see `abort_target` for why the
//! other three keep their FIN semantics.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::BytesMut;
use http::{HeaderMap, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, info};

use crate::h3api::{self, Buffer, Reader, Stream, Writer};
use crate::tunnel;
use crate::tunnel::{Context, Unreachable};

/// Bytes read from the target per relay iteration.
const RELAY_BUF_SIZE: usize = 16 * 1024;

/// Why the tunnel is being torn down, carried on the teardown channel.
///
/// A bare "stop now" flag is not enough, because neither pump can tell from a
/// flag alone how to close its own half — and simply returning gets it wrong in
/// one direction each time. `quinn::SendStream::drop` finishes the stream, so a
/// writer dropped on a target error puts a clean FIN on the wire and a truncated
/// response reads to the client as a complete one; `quinn::RecvStream::drop`
/// stops the peer with code 0, so a reader dropped on the same target error
/// contradicts the `H3_CONNECT_ERROR` the other half just sent.
///
/// With the reason attached, a target error reaches the client as
/// `H3_CONNECT_ERROR` whichever pump noticed it (RFC 9114 §4.4), and a client
/// abort still leaves both halves alone, since the client is the one that closed
/// them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Teardown {
    /// Nothing has gone wrong; both directions are still relaying.
    Running,
    /// The client reset the request stream or stopped reading it.
    ClientAbort,
    /// The connection to the target failed, in either direction.
    TargetError,
}

/// Establishes a TCP tunnel to `authority` and relays until both directions end.
pub async fn run(authority: &str, mut stream: Stream, stream_id: u64, ctx: &Context) {
    let (host, port) = match split_authority(authority) {
        Ok(target) => target,
        Err(reason) => {
            debug!(stream_id, authority, reason, "malformed CONNECT authority");
            tunnel::refuse(&mut stream, StatusCode::BAD_REQUEST, stream_id).await;
            return;
        }
    };

    // Port policy, resolution and destination policy, in that order and with
    // every refusal already answered by the time this returns — see
    // [`tunnel::admit_target`]. An accepted TCP tunnel carries no response
    // headers of its own, so the 200-then-close path is handed an empty map.
    let Some(allowed) =
        tunnel::admit_target(&host, port, ctx, &mut stream, stream_id, HeaderMap::new).await
    else {
        return;
    };

    let tcp = match connect_any(&allowed, ctx.connect_timeout).await {
        Ok(tcp) => tcp,
        Err(failure) => {
            // RFC 9114 §4.4: a proxy that cannot establish the connection
            // answers with a non-2xx status rather than resetting the stream.
            // Which non-2xx follows from the RFC 9209 type, so a timeout is a
            // 504 and an unreachable target a 503 rather than all of them 502,
            // and the answer names the address that failed.
            debug!(
                stream_id,
                authority,
                ?allowed,
                error = %failure.error,
                "failed to connect to target"
            );
            tunnel::refuse_unreachable(&mut stream, &failure, stream_id).await;
            return;
        }
    };

    // A proxy should not add Nagle delay on top of whatever the endpoints do.
    if let Err(error) = tcp.set_nodelay(true) {
        debug!(stream_id, %error, "failed to set TCP_NODELAY on the target socket");
    }

    let target = tcp.peer_addr().ok();

    if let Err(error) = stream.respond(StatusCode::OK).await {
        debug!(stream_id, %error, "failed to send 200 for CONNECT");
        // Dropping `tcp` closes the connection we just opened.
        return;
    }

    info!(stream_id, authority, ?target, "tcp tunnel established");

    let (writer, reader) = stream.split();
    let (tcp_read, tcp_write) = tcp.into_split();

    // Sticky so a teardown cannot be missed by a pump that is not yet waiting.
    // The sender lives here, outliving both pumps.
    let (teardown, teardown_rx) = watch::channel(Teardown::Running);

    tokio::join!(
        client_to_target(reader, tcp_write, &teardown, teardown_rx.clone()),
        target_to_client(writer, tcp_read, &teardown, teardown_rx),
    );

    debug!(stream_id, authority, "tcp tunnel closed");
}

/// Connects to the first address that accepts, reporting the last failure.
///
/// Trying every address matters for dual-stack targets, where the AAAA record
/// may be unreachable while the A record works. The address of the last attempt
/// travels with the error, since that is the hop the client is told about.
///
/// `budget` bounds the **whole** loop rather than each address, so a name with
/// several unreachable addresses cannot multiply the wait by their number. Why
/// it is bounded at all: the tunnel slot and the file descriptor behind it are
/// held for the length of this call, and a target that silently drops SYNs
/// otherwise holds them for as long as the operating system retries — around two
/// minutes on Linux. No attacker is needed for that; a handful of black-holed
/// addresses during ordinary browsing is enough to spend a connection's whole
/// `max_targets_per_conn` on tunnels that will never open.
///
/// One thing this deliberately does not do is notice the client giving up: a
/// request stream reset mid-connect leaves the attempt running until it finishes
/// or the budget expires. Bounding it is what makes that acceptable.
async fn connect_any(
    addresses: &[SocketAddr],
    budget: Option<Duration>,
) -> Result<TcpStream, Unreachable> {
    connect_any_with(addresses, budget, TcpStream::connect).await
}

/// [`connect_any`] with the per-address connect step supplied by the caller.
///
/// Split out only so the budget can be tested against a connect that never
/// completes; production always passes [`TcpStream::connect`].
async fn connect_any_with<C, F>(
    addresses: &[SocketAddr],
    budget: Option<Duration>,
    connect: C,
) -> Result<TcpStream, Unreachable>
where
    C: Fn(SocketAddr) -> F,
    F: std::future::Future<Output = io::Result<TcpStream>>,
{
    // Taken once, before the first attempt: every address draws on the same
    // budget.
    let deadline = budget.map(|budget| tokio::time::Instant::now() + budget);
    let mut last = None;

    for address in addresses {
        let attempt = connect(*address);

        let result = match deadline {
            Some(deadline) => match tokio::time::timeout_at(deadline, attempt).await {
                Ok(result) => result,
                // Reported as the hop that was still in flight, which is the one
                // the client is waiting on.
                Err(_) => {
                    return Err(Unreachable {
                        next_hop: Some(*address),
                        error: io::Error::new(
                            io::ErrorKind::TimedOut,
                            "the connect budget expired before the target answered",
                        ),
                    })
                }
            },
            None => attempt.await,
        };

        match result {
            Ok(tcp) => return Ok(tcp),
            Err(error) => {
                debug!(%address, %error, "target address unreachable, trying the next");
                last = Some(Unreachable {
                    next_hop: Some(*address),
                    error,
                });
            }
        }
    }

    Err(last.unwrap_or_else(Unreachable::no_addresses))
}

/// Pumps client → target.
async fn client_to_target(
    mut reader: Reader,
    mut tcp_write: OwnedWriteHalf,
    teardown: &watch::Sender<Teardown>,
    mut teardown_rx: watch::Receiver<Teardown>,
) {
    loop {
        let chunk = tokio::select! {
            biased;
            // The other direction ended the tunnel abnormally. Shutting the
            // write side down on the way out would put a FIN on the wire, which
            // is the wrong signal for every path that gets here — and would
            // overtake the reset when the other pump armed one.
            reason = torn_down(&mut teardown_rx) => {
                // The other pump found the target broken and reset its half with
                // H3_CONNECT_ERROR. Ask for the same code here rather than
                // letting the `Reader` drop stop the client with code 0, which
                // would leave the two halves carrying different verdicts on the
                // same failure.
                //
                // Only a request, not a guarantee, at the pinned `h3-quinn`
                // revision: its `RecvStream::poll_data` moves the `quinn` stream
                // into a boxed read future, and a `stop_sending` arriving while
                // that read is in flight is parked in `pending_stop` and applied
                // only when the read resolves — which it will not, since nothing
                // more is coming. The client is then stopped with code 0 by the
                // drop, as before. It lands when the teardown beats the first
                // read, and it is what this half means either way; the response
                // direction, which is the one that could truncate data, is
                // reset unconditionally by the other pump.
                if reason == Teardown::TargetError {
                    reader.stop_receiving(h3api::CONNECT_ERROR);
                }
                tcp_write.forget();
                return;
            }
            chunk = reader.recv_data() => chunk,
        };

        match chunk {
            Ok(Some(data)) => {
                if let Err(error) = tcp_write.write_all(&data).await {
                    // The target is gone (RST, EPIPE): the tunnel is broken.
                    debug!(%error, "write to target failed");
                    reader.stop_receiving(h3api::CONNECT_ERROR);
                    let _ = teardown.send(Teardown::TargetError);
                    return;
                }
            }
            // The client finished its sending side. Propagate it as a TCP FIN
            // and leave the other direction running, so anything the target
            // still has to say reaches the client.
            Ok(None) => {
                if let Err(error) = tcp_write.shutdown().await {
                    debug!(%error, "failed to shut down the target write side");
                }
                return;
            }
            Err(error) => {
                match h3api::peer_reset_code(&error) {
                    Some(code) => debug!(code, "client reset the tunnel"),
                    None => debug!(%error, "reading from the client failed"),
                }
                // The request stream is unusable: close the TCP connection by
                // stopping the other pump, which drops the read half. The client
                // aborted the tunnel, so that close is a reset (RFC 9114 §4.4)
                // rather than the FIN a natural drop would produce.
                abort_target(tcp_write.as_ref());
                tcp_write.forget();
                let _ = teardown.send(Teardown::ClientAbort);
                return;
            }
        }
    }
}

/// Pumps target → client.
async fn target_to_client(
    mut writer: Writer,
    mut tcp_read: OwnedReadHalf,
    teardown: &watch::Sender<Teardown>,
    mut teardown_rx: watch::Receiver<Teardown>,
) {
    let mut buf = BytesMut::with_capacity(RELAY_BUF_SIZE);

    loop {
        // Keep a full-size window available. Without this, `read_buf` reserves
        // only 64 bytes at a time once the initial capacity is used up.
        buf.reserve(RELAY_BUF_SIZE);

        let read = tokio::select! {
            biased;
            reason = torn_down(&mut teardown_rx) => {
                // The write pump found the target broken. RFC 9114 §4.4 makes
                // that a stream error of type H3_CONNECT_ERROR, and returning
                // without saying so would drop the `Writer` — and a dropped
                // `quinn::SendStream` finishes rather than resets, so the client
                // would read a truncated response as a complete one.
                //
                // A client abort needs nothing from this side: the client has
                // already reset the stream or stopped reading it, and answering
                // its own close with a reset only adds a second signal.
                if reason == Teardown::TargetError {
                    writer.reset(h3api::CONNECT_ERROR);
                }
                return;
            }
            read = tcp_read.read_buf(&mut buf) => read,
        };

        match read {
            // Target EOF: finish our sending side only. The client may still
            // have data for the target.
            Ok(0) => {
                if let Err(error) = writer.finish().await {
                    debug!(%error, "failed to finish the response stream");
                }
                return;
            }
            Ok(_) => {
                // `split` hands the filled bytes over without copying them.
                let data: Buffer = buf.split().freeze();
                if let Err(error) = writer.send_data(data).await {
                    match h3api::peer_reset_code(&error) {
                        Some(code) => debug!(code, "client reset the tunnel"),
                        None => debug!(%error, "sending to the client failed"),
                    }
                    // RFC 9114 §4.4's other client-side abort: the client has
                    // stopped reading the tunnel, so what is left of the target
                    // connection is closed with a reset. The other pump does the
                    // dropping; this only decides how the socket closes.
                    abort_target(tcp_read.as_ref());
                    let _ = teardown.send(Teardown::ClientAbort);
                    return;
                }
            }
            Err(error) => {
                // The target reset the connection. RFC 9114 §4.4 maps this onto
                // a stream reset with H3_CONNECT_ERROR.
                debug!(%error, "read from target failed");
                writer.reset(h3api::CONNECT_ERROR);
                let _ = teardown.send(Teardown::TargetError);
                return;
            }
        }
    }
}

/// Arms an abortive close on the target connection (RFC 9114 §4.4).
///
/// §4.4 requires the TCP connection to be closed when the proxy "detects that
/// the client has reset the stream or aborted reading from the stream", and adds
/// that "in all these cases, if the underlying TCP implementation permits it,
/// the proxy SHOULD send a TCP segment with the RST bit set". `SO_LINGER` at
/// zero is how that is asked for: the next close of the socket aborts instead of
/// draining, so the target learns the tunnel was cut rather than politely
/// finished, and stops holding a half-open connection until its own timeout.
///
/// Setting the option has no effect until the socket is closed, so arming it on
/// the way out cannot disturb anything still in flight.
///
/// **This is only ever called on the two client-abort paths.** A clean client
/// FIN, a target EOF, and a target that resets or errors all keep their existing
/// FIN semantics — the half-close table at the top of this module is the
/// behaviour this proxy exists to get right, and a reset is not a substitute for
/// any of it.
///
/// `set_linger` is deprecated in tokio because `SO_LINGER` can make a close block
/// the thread while the send buffer drains. That is the *non-zero* timeout; at
/// zero the close is by definition immediate, which is exactly why this is the
/// one safe use of it.
fn abort_target(tcp: &TcpStream) {
    #[allow(deprecated)]
    if let Err(error) = tcp.set_linger(Some(Duration::ZERO)) {
        // The connection still closes, just with a FIN: a SHOULD unmet, not a
        // tunnel broken.
        debug!(%error, "failed to arm a TCP reset on the target socket");
    }
}

/// Resolves once either direction has asked for the tunnel to be torn down,
/// with the reason it gave.
async fn torn_down(teardown_rx: &mut watch::Receiver<Teardown>) -> Teardown {
    loop {
        let reason = *teardown_rx.borrow_and_update();
        if reason != Teardown::Running {
            return reason;
        }
        // The sender outlives both pumps, so this cannot actually fail; treat a
        // closed channel as a teardown anyway. Reported as a client abort,
        // which is the reason that asks nothing of the waking pump.
        if teardown_rx.changed().await.is_err() {
            return Teardown::ClientAbort;
        }
    }
}

/// Splits a CONNECT `:authority` into host and port.
///
/// RFC 9114 §4.4 requires authority-form (`host:port`), with IPv6 literals in
/// brackets as per RFC 3986.
fn split_authority(authority: &str) -> Result<(String, u16), &'static str> {
    if authority.contains('@') {
        return Err("userinfo is not allowed in a CONNECT authority");
    }

    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => {
            let (host, rest) = rest.split_once(']').ok_or("unterminated IPv6 literal")?;
            if host.is_empty() {
                return Err("empty host");
            }
            let port = rest
                .strip_prefix(':')
                .ok_or("missing port after IPv6 literal")?;
            (host.to_owned(), port)
        }
        None => {
            let (host, port) = authority.rsplit_once(':').ok_or("missing port")?;
            if host.is_empty() {
                return Err("empty host");
            }
            if host.contains(':') {
                // Ambiguous with host:port; brackets are mandatory.
                return Err("unbracketed IPv6 literal");
            }
            (host.to_owned(), port)
        }
    };

    let port: u16 = port.parse().map_err(|_| "invalid port")?;
    if port == 0 {
        return Err("port must not be zero");
    }

    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::{connect_any_with, split_authority};
    use std::io;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::net::TcpStream;

    fn address(literal: &str) -> SocketAddr {
        literal.parse().expect("socket address")
    }

    /// A target that black-holes SYNs is the case the budget exists for: the
    /// operating system would keep retrying for around two minutes, and the
    /// tunnel slot and file descriptor are held for all of it.
    ///
    /// Real time with a small budget rather than a paused clock, because tokio's
    /// `test-util` feature is not enabled in this tree. The upper bound is two
    /// orders of magnitude above the budget, so only an unbounded wait fails it.
    #[tokio::test]
    async fn the_connect_budget_bounds_a_target_that_never_answers() {
        let addresses = [address("192.0.2.1:443"), address("192.0.2.2:443")];
        let budget = Duration::from_millis(50);
        let started = std::time::Instant::now();

        // The outer timeout is what turns a regression here into a failure
        // rather than a hung test run.
        let failure = tokio::time::timeout(
            Duration::from_secs(5),
            connect_any_with(&addresses, Some(budget), |_| {
                std::future::pending::<io::Result<TcpStream>>()
            }),
        )
        .await
        .expect("the budget must bound the wait")
        .expect_err("a connect that never answers must not succeed");
        let elapsed = started.elapsed();

        assert_eq!(failure.error.kind(), io::ErrorKind::TimedOut);
        // The hop named is the one still in flight, which is the one the client
        // is waiting on.
        assert_eq!(failure.next_hop, Some(addresses[0]));
        assert!(elapsed >= budget, "returned early, after {elapsed:?}");
    }

    /// One budget for the whole list, not one per address: several unreachable
    /// addresses must not multiply the wait by their number.
    ///
    /// The first address spends three quarters of the budget and fails, the
    /// second never answers. Shared, that ends at the budget; one budget each
    /// would end at 1.75 times it, which the upper bound below excludes.
    #[tokio::test]
    async fn every_address_draws_on_the_same_budget() {
        let addresses = [address("192.0.2.1:443"), address("192.0.2.2:443")];
        let budget = Duration::from_millis(400);
        let started = std::time::Instant::now();

        let failure = tokio::time::timeout(
            Duration::from_secs(5),
            connect_any_with(&addresses, Some(budget), |address| async move {
                if address == addresses[0] {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                }
                std::future::pending().await
            }),
        )
        .await
        .expect("the budget must bound the wait")
        .expect_err("the budget must expire");
        let elapsed = started.elapsed();

        assert_eq!(failure.error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(failure.next_hop, Some(addresses[1]));
        assert!(
            elapsed < Duration::from_millis(600),
            "the second address got a budget of its own: {elapsed:?}"
        );
    }

    /// With the budget disabled the loop behaves exactly as it did before it
    /// existed: every address is tried, and the last failure is what travels out.
    #[tokio::test]
    async fn a_disabled_budget_tries_every_address() {
        let addresses = [address("192.0.2.1:443"), address("192.0.2.2:443")];
        let attempted = std::cell::RefCell::new(Vec::new());

        let failure = connect_any_with(&addresses, None, |address| {
            attempted.borrow_mut().push(address);
            async move { Err(io::Error::from(io::ErrorKind::ConnectionRefused)) }
        })
        .await
        .expect_err("every address refuses");

        assert_eq!(attempted.into_inner(), addresses);
        assert_eq!(failure.error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(failure.next_hop, Some(addresses[1]));
    }

    /// An empty list has no hop to name, and must not be reported as a timeout.
    #[tokio::test]
    async fn an_empty_address_list_names_no_hop() {
        let failure = tokio::time::timeout(
            Duration::from_secs(5),
            connect_any_with(&[], Some(Duration::from_secs(10)), |_| {
                std::future::pending::<io::Result<TcpStream>>()
            }),
        )
        .await
        .expect("an empty list needs no waiting at all")
        .expect_err("there is nothing to connect to");

        assert_eq!(failure.error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(failure.next_hop, None);
    }

    #[test]
    fn accepts_host_and_port() {
        assert_eq!(
            split_authority("example.com:443"),
            Ok(("example.com".to_owned(), 443))
        );
        assert_eq!(
            split_authority("192.0.2.1:8080"),
            Ok(("192.0.2.1".to_owned(), 8080))
        );
    }

    #[test]
    fn accepts_bracketed_ipv6() {
        assert_eq!(
            split_authority("[2001:db8::1]:443"),
            Ok(("2001:db8::1".to_owned(), 443))
        );
        assert_eq!(split_authority("[::1]:53"), Ok(("::1".to_owned(), 53)));
    }

    #[test]
    fn rejects_missing_or_bad_port() {
        assert!(split_authority("example.com").is_err());
        assert!(split_authority("example.com:").is_err());
        assert!(split_authority("example.com:0").is_err());
        assert!(split_authority("example.com:99999").is_err());
        assert!(split_authority("example.com:http").is_err());
        assert!(split_authority("[2001:db8::1]").is_err());
        assert!(split_authority("[2001:db8::1]443").is_err());
    }

    #[test]
    fn rejects_ambiguous_and_malformed_hosts() {
        assert!(split_authority(":443").is_err());
        assert!(split_authority("2001:db8::1:443").is_err());
        assert!(split_authority("[2001:db8::1:443").is_err());
        assert!(split_authority("user:pass@example.com:443").is_err());
    }
}
