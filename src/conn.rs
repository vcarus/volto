//! Per-connection driving: accept request streams, authenticate them, dispatch
//! them.
//!
//! A connection owns the things every tunnel on it shares: the Quarter Stream ID
//! routing table, the task that reads QUIC datagrams and delivers them through it,
//! the credentials and destination policy each request is checked against, and the
//! tunnel quota they all draw on. All of it lives in [`crate::tunnel::Context`],
//! cloned per request.
//!
//! The accept loop is also where graceful shutdown is observed: see
//! [`handle`] for the GOAWAY and drain sequence.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use http::{Request, StatusCode};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::shutdown::Shutdown;
use crate::tunnel::{self, udp, Context, ProxyError, Route};
use crate::{auth, h3api};

/// Drives one QUIC connection until the peer stops sending requests.
///
/// Returns `Err` only for connection-level failures; per-request problems are
/// logged and confined to their own stream.
///
/// # Shutdown
///
/// When `shutdown` fires this sends a GOAWAY and then keeps the connection alive
/// until its tunnels finish, so an in-flight page load or call is not cut off
/// mid-sentence. Two details make that work:
///
/// * dropping the `h3` connection closes the QUIC connection, so returning early
///   would kill the very tunnels being drained — the loop has to stay;
/// * `accept()` cannot report the end of the drain, because at this `h3` revision
///   it only does so once the *client* has also sent a GOAWAY. The tunnel quota
///   going idle is the signal instead.
///
/// The wait is deliberately unbounded here: the grace period belongs to the
/// endpoint ([`crate::quic`]), which closes everything when it expires. Bounding
/// it in both places would mean two timeouts to keep consistent.
pub async fn handle(
    quic: quinn::Connection,
    config: Arc<Config>,
    mut shutdown: Shutdown,
) -> anyhow::Result<()> {
    // Cloned before the handshake: `h3` takes ownership of the connection, but
    // HTTP Datagrams bypass `h3` entirely and need the QUIC connection directly.
    let datagrams = quic.clone();

    let mut connection = h3api::Connection::handshake(quic).await?;
    let context = Context::new(&config, datagrams.clone());

    // One reader per connection, demultiplexing datagrams to sessions by
    // Quarter Stream ID.
    let router = tokio::spawn(udp::route_datagrams(datagrams, context.sessions.clone()));

    let mut going_away = false;

    let result = loop {
        tokio::select! {
            biased;

            // Guarded so the branch stops competing once the latch has fired:
            // it is sticky, and would otherwise win every iteration forever.
            () = shutdown.fired(), if !going_away => {
                going_away = true;

                if let Err(error) = connection.shutdown().await {
                    // The connection is unusable, so there is nothing left to
                    // drain politely.
                    debug!(%error, "failed to send GOAWAY");
                    break Ok(());
                }

                let live = context.quota.live();
                info!(live_tunnels = live, "sent GOAWAY, draining tunnels");
                if live == 0 {
                    break Ok(());
                }
            }

            // Only meaningful after GOAWAY: before it, an idle connection is
            // simply idle, not finished.
            () = context.quota.wait_until_idle(), if going_away => {
                info!("every tunnel finished after GOAWAY");
                break Ok(());
            }

            accepted = connection.accept() => match accepted {
                Ok(Some(resolver)) => {
                    // Refreshed on every request: at handshake time the peer's
                    // SETTINGS frame has usually not been processed yet.
                    if connection.peer_datagrams_enabled() {
                        context.peer_datagrams.store(true, Ordering::Relaxed);
                    }

                    tokio::spawn(handle_request(resolver, context.clone()));
                }
                // The peer will send no further requests.
                Ok(None) => break Ok(()),
                Err(error) => break Err(error.into()),
            },
        }
    };

    // No sessions can outlive the connection, so neither should the router.
    router.abort();

    result
}

/// Resolves one request, authenticates it, and routes it to a tunnel.
async fn handle_request(resolver: h3api::Resolver, context: Context) {
    let (req, mut stream) = match resolver.resolve().await {
        Ok(resolved) => resolved,
        Err(error) => {
            // Malformed headers, a client reset mid-headers, and similar. `h3`
            // has already reset the stream for us.
            debug!(%error, "failed to resolve request");
            return;
        }
    };

    let stream_id = stream.id();
    log_request(&req, stream_id);

    // Before routing, not after: an unauthenticated client should not be able to
    // tell from the response which `:protocol` values this proxy implements, and
    // every CONNECT — TCP or UDP — has to pass through here.
    match context.auth.authenticate(req.headers()) {
        Ok(Some(username)) => debug!(stream_id, username, "request authenticated"),
        // No users configured: an open proxy, as warned about at startup.
        Ok(None) => {}
        Err(denied) => {
            // The attempted user-id is logged, never anything derived from the
            // password. `remote` is here so a fail2ban rule has something to act
            // on; behind a relay it is the relay's address.
            warn!(
                stream_id,
                remote = %context.remote,
                username = ?denied.username(),
                reason = denied.reason(),
                "authentication failed"
            );
            tunnel::refuse_with(
                &mut stream,
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                auth::challenge_headers(),
                stream_id,
            )
            .await;

            // Guessing should cost a handshake every few attempts rather than
            // being free for the life of one connection.
            if context.record_auth_failure() {
                warn!(
                    remote = %context.remote,
                    failures = context.max_auth_failures,
                    "closing the connection after repeated authentication failures"
                );
                context.datagrams.close(
                    h3api::AUTH_FAILURE_LIMIT_CODE,
                    b"too many authentication failures",
                );
            }
            return;
        }
    }

    // One slot per request, held until this task ends however it ends. Taken
    // before any socket is opened, so the limit bounds file descriptors rather
    // than trailing them.
    let Some(_slot) = context.quota.acquire() else {
        warn!(
            stream_id,
            live = context.quota.live(),
            "connection is at its tunnel limit"
        );
        tunnel::refuse_because(
            &mut stream,
            StatusCode::SERVICE_UNAVAILABLE,
            ProxyError::ConnectionLimitReached,
            stream_id,
        )
        .await;
        return;
    };

    match tunnel::route(&req) {
        Route::Tcp => match req.uri().authority() {
            Some(authority) => {
                let authority = authority.as_str().to_owned();
                tunnel::tcp::run(&authority, stream, stream_id, &context).await;
            }
            None => {
                // RFC 9114 §4.4: a CONNECT request must carry :authority.
                debug!(stream_id, "CONNECT request without :authority");
                tunnel::refuse(&mut stream, StatusCode::BAD_REQUEST, stream_id).await;
            }
        },
        Route::ConnectUdp => {
            udp::run(&req, stream, stream_id, context).await;
        }
        Route::UnsupportedProtocol(protocol) => {
            debug!(stream_id, protocol, "unsupported :protocol");
            tunnel::refuse(&mut stream, StatusCode::NOT_IMPLEMENTED, stream_id).await;
        }
        Route::NotConnect => {
            debug!(
                stream_id,
                method = %req.method(),
                "not a CONNECT request; this server only proxies"
            );
            tunnel::refuse(&mut stream, StatusCode::NOT_IMPLEMENTED, stream_id).await;
        }
    }
}

/// Logs every inbound request at DEBUG, with credentials redacted.
///
/// This is the primary tool for establishing empirically what Surge actually
/// sends — which header it puts credentials in, which URI template it uses for
/// CONNECT-UDP — so every header *line* is logged. What is redacted is only the
/// secret itself: the header name and the auth scheme survive, because
///
/// * which of `Proxy-Authorization` and `Authorization` Surge uses is still
///   unconfirmed (decision D3), and this log is how it gets confirmed;
/// * the scheme distinguishes "Surge sent Basic as expected" from "Surge sent
///   something we do not implement", which is a different bug entirely.
///
/// Neither of those needs the credential, so the credential does not appear.
fn log_request(req: &Request<()>, stream_id: u64) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }

    let headers: Vec<String> = req
        .headers()
        .iter()
        .map(|(name, value)| {
            if is_credential_header(name) {
                return format!("{name}: {}", redact_credentials(value));
            }
            match value.to_str() {
                Ok(value) => format!("{name}: {value}"),
                Err(_) => format!("{name}: <{} non-utf8 bytes>", value.len()),
            }
        })
        .collect();

    let protocol = match h3api::connect_protocol(req) {
        h3api::ConnectProtocol::Absent => None,
        h3api::ConnectProtocol::ConnectUdp => Some("connect-udp"),
        h3api::ConnectProtocol::Unsupported(name) => Some(name),
    };

    debug!(
        stream_id,
        method = %req.method(),
        path = %req.uri().path(),
        authority = ?req.uri().authority().map(|a| a.as_str()),
        scheme = ?req.uri().scheme_str(),
        protocol = ?protocol,
        headers = ?headers,
        "inbound request"
    );
}

/// Whether a header carries credentials and must therefore be redacted.
///
/// Both names this server accepts (decision D3), matched case-insensitively —
/// `http` lowercases header names on receipt, but this must not depend on that.
fn is_credential_header(name: &http::HeaderName) -> bool {
    name == http::header::PROXY_AUTHORIZATION || name == http::header::AUTHORIZATION
}

/// Renders a credential header value as its scheme plus the size of the secret.
///
/// The length is kept because it is diagnostic — "Basic <redacted 0 bytes>" is a
/// client sending an empty credential, which looks nothing like a wrong password
/// — and because it reveals nothing a network observer could not count for
/// itself.
///
/// The scheme is echoed only when it is short and alphanumeric. It is
/// attacker-controlled, so this bounds what an unauthenticated peer can write
/// into the log: without the check, a huge or newline-laden "scheme" could bloat
/// the log or forge log lines through it.
fn redact_credentials(value: &http::HeaderValue) -> String {
    /// Longest scheme name echoed into the log. "Negotiate" is 9.
    const MAX_SCHEME: usize = 16;

    let Ok(text) = value.to_str() else {
        return format!("<redacted {} bytes>", value.len());
    };

    match text.split_once(' ') {
        Some((scheme, secret))
            if !scheme.is_empty()
                && scheme.len() <= MAX_SCHEME
                && scheme.chars().all(|c| c.is_ascii_alphanumeric()) =>
        {
            // Extra spaces between scheme and token are legal, and are not secret.
            let secret = secret.trim_start_matches(' ');
            format!("{scheme} <redacted {} bytes>", secret.len())
        }
        // No scheme, or one not worth trusting: redact the whole value.
        _ => format!("<redacted {} bytes>", text.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{AUTHORIZATION, PROXY_AUTHORIZATION};
    use http::{HeaderName, HeaderValue};

    fn redact(value: &str) -> String {
        redact_credentials(&HeaderValue::from_str(value).expect("header value"))
    }

    #[test]
    fn both_credential_headers_are_recognised() {
        assert!(is_credential_header(&PROXY_AUTHORIZATION));
        assert!(is_credential_header(&AUTHORIZATION));
        assert!(!is_credential_header(&HeaderName::from_static(
            "user-agent"
        )));
        assert!(!is_credential_header(&HeaderName::from_static(
            "x-volto-probe"
        )));
    }

    /// The scheme survives, the secret does not.
    #[test]
    fn the_scheme_is_kept_and_the_secret_is_not() {
        // base64("user1:s3cret") is 16 bytes.
        assert_eq!(
            redact("Basic dXNlcjE6czNjcmV0"),
            "Basic <redacted 16 bytes>"
        );
        assert_eq!(redact("Bearer abcdef"), "Bearer <redacted 6 bytes>");
        // Extra whitespace is not part of the secret.
        assert_eq!(redact("Basic   abcd"), "Basic <redacted 4 bytes>");
        // An empty credential is diagnostic in itself.
        assert_eq!(redact("Basic "), "Basic <redacted 0 bytes>");
    }

    #[test]
    fn no_credential_material_survives_redaction() {
        for value in [
            "Basic dXNlcjE6czNjcmV0",
            "basic dXNlcjE6czNjcmV0",
            "dXNlcjE6czNjcmV0",
            "Bearer eyJhbGciOiJIUzI1NiJ9.c3VwZXItc2VjcmV0",
        ] {
            let redacted = redact(value);
            assert!(
                !redacted.contains("dXNlcjE6czNjcmV0") && !redacted.contains("c3VwZXItc2VjcmV0"),
                "{value:?} leaked as {redacted:?}"
            );
        }
    }

    /// A value with no scheme at all is redacted whole: there is nothing to keep,
    /// and the bytes may well be a credential sent the wrong way round.
    #[test]
    fn a_schemeless_value_is_redacted_whole() {
        assert_eq!(redact("dXNlcjE6czNjcmV0"), "<redacted 16 bytes>");
        assert_eq!(redact(""), "<redacted 0 bytes>");
    }

    /// The scheme is attacker-controlled, so it cannot be echoed unconditionally:
    /// this is what stops an unauthenticated peer writing arbitrary text — or a
    /// forged log line — into the log through it.
    #[test]
    fn an_untrustworthy_scheme_is_not_echoed() {
        let long = "S".repeat(17);
        assert_eq!(redact(&format!("{long} secret")), "<redacted 24 bytes>");

        for scheme in ["Ba-sic", "Ba_sic", "Ba.sic", "Ba\tsic", "Ba:sic"] {
            let redacted = redact(&format!("{scheme} dXNlcjE6czNjcmV0"));
            assert!(
                !redacted.contains(scheme),
                "scheme {scheme:?} must not be echoed: {redacted:?}"
            );
            assert!(!redacted.contains("dXNlcjE6czNjcmV0"), "{redacted:?}");
        }
    }

    /// A non-UTF-8 value cannot be split into scheme and secret, so all of it goes.
    #[test]
    fn a_non_utf8_value_is_redacted_whole() {
        let value = HeaderValue::from_bytes(&[0x42, 0x61, 0x73, 0x69, 0x63, 0x20, 0xff, 0xfe])
            .expect("header value");
        assert_eq!(redact_credentials(&value), "<redacted 8 bytes>");
    }
}
