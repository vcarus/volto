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
//! | target resets or errors | reset the request stream with `H3_CONNECT_ERROR` |
//! | client resets the request stream, or stops reading it | close the TCP connection with a reset |
//!
//! The two directions therefore run as independent pumps that are joined, plus a
//! sticky teardown signal for the abnormal cases where one direction failing
//! must stop the other.
//!
//! Only the last row aborts the TCP connection; see [`abort_target`] for why the
//! other three keep their FIN semantics.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::BytesMut;
use http::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::h3api::{self, Buffer, Reader, Stream, Writer};
use crate::tunnel::{Context, ProxyError, Unreachable};
use crate::{net, policy, tunnel};

/// Bytes read from the target per relay iteration.
const RELAY_BUF_SIZE: usize = 16 * 1024;

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

    // The port rule needs no address, so it is applied before the resolver is
    // asked anything: a denied port cannot be used to make the proxy run lookups.
    if !ctx.policy.allows_port(port) {
        debug!(stream_id, authority, port, "target port denied by policy");
        tunnel::refuse_because(
            &mut stream,
            StatusCode::FORBIDDEN,
            ProxyError::HttpRequestDenied,
            stream_id,
        )
        .await;
        return;
    }

    // Resolution is explicit so the addresses are visible to the policy below —
    // `TcpStream::connect((host, port))` would resolve internally and leave
    // nothing to filter.
    let addresses = match net::resolve(&host, port).await {
        Ok(addresses) => addresses,
        Err(error) => {
            // A resolver failure is not the client's fault (decision D9), so it is
            // a 502 with the RFC 9209 reason rather than a 400.
            debug!(stream_id, authority, %error, "failed to resolve target");
            tunnel::refuse_because(
                &mut stream,
                StatusCode::BAD_GATEWAY,
                ProxyError::DnsError,
                stream_id,
            )
            .await;
            return;
        }
    };

    // A name resolving to a mix of public and private addresses keeps only the
    // public ones, so DNS rebinding onto loopback gains nothing.
    let allowed = ctx.policy.allowed_addresses(&addresses);
    if allowed.is_empty() {
        // Same refusal either way; only the volume differs. A name that resolves
        // to nothing but the unspecified address was blocked by a filtering
        // resolver upstream, which is neither this proxy's business nor worth a
        // warning. Every other refusal — loopback, RFC 1918, a mix — stays loud
        // because that is what an SSRF probe looks like from here.
        if policy::is_dns_blackhole(&addresses) {
            info!(
                stream_id,
                authority,
                ?addresses,
                "every address of the target is a DNS blackhole"
            );
        } else {
            warn!(
                stream_id,
                authority,
                ?addresses,
                "every address of the target is prohibited by policy"
            );
        }
        tunnel::refuse_because(
            &mut stream,
            StatusCode::FORBIDDEN,
            ProxyError::DestinationIpProhibited,
            stream_id,
        )
        .await;
        return;
    }

    let tcp = match connect_any(&allowed).await {
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
    let (teardown, teardown_rx) = watch::channel(false);

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
async fn connect_any(addresses: &[SocketAddr]) -> Result<TcpStream, Unreachable> {
    let mut last = None;

    for address in addresses {
        match TcpStream::connect(address).await {
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

    // Callers only ever pass a non-empty list, so the fallback is the empty-list
    // arm written out rather than asserted: there is no hop to name in it.
    Err(last.unwrap_or_else(|| Unreachable {
        next_hop: None,
        error: io::Error::new(io::ErrorKind::InvalidInput, "no addresses to connect to"),
    }))
}

/// Pumps client → target.
async fn client_to_target(
    mut reader: Reader,
    mut tcp_write: OwnedWriteHalf,
    teardown: &watch::Sender<bool>,
    mut teardown_rx: watch::Receiver<bool>,
) {
    loop {
        let chunk = tokio::select! {
            biased;
            // The other direction ended the tunnel abnormally. Shutting the
            // write side down on the way out would put a FIN on the wire, which
            // is the wrong signal for every path that gets here — and would
            // overtake the reset when the other pump armed one.
            () = torn_down(&mut teardown_rx) => {
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
                    let _ = teardown.send(true);
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
                let _ = teardown.send(true);
                return;
            }
        }
    }
}

/// Pumps target → client.
async fn target_to_client(
    mut writer: Writer,
    mut tcp_read: OwnedReadHalf,
    teardown: &watch::Sender<bool>,
    mut teardown_rx: watch::Receiver<bool>,
) {
    let mut buf = BytesMut::with_capacity(RELAY_BUF_SIZE);

    loop {
        // Keep a full-size window available. Without this, `read_buf` reserves
        // only 64 bytes at a time once the initial capacity is used up.
        buf.reserve(RELAY_BUF_SIZE);

        let read = tokio::select! {
            biased;
            () = torn_down(&mut teardown_rx) => return,
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
                    let _ = teardown.send(true);
                    return;
                }
            }
            Err(error) => {
                // The target reset the connection. RFC 9114 §4.4 maps this onto
                // a stream reset with H3_CONNECT_ERROR.
                debug!(%error, "read from target failed");
                writer.reset(h3api::CONNECT_ERROR);
                let _ = teardown.send(true);
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

/// Resolves once either direction has asked for the tunnel to be torn down.
async fn torn_down(teardown_rx: &mut watch::Receiver<bool>) {
    loop {
        if *teardown_rx.borrow_and_update() {
            return;
        }
        // The sender outlives both pumps, so this cannot actually fail; treat a
        // closed channel as a teardown anyway.
        if teardown_rx.changed().await.is_err() {
            return;
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
    use super::split_authority;

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
