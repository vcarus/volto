//! Per-connection driving: accept request streams, authenticate them, dispatch
//! them.
//!
//! A connection owns the things every tunnel on it shares: the credentials and
//! destination policy each request is checked against, the QUIC connection its
//! UDP sessions send datagrams on, and the tunnel quota they all draw on. All of
//! it lives in [`crate::tunnel::Context`], cloned per request. Inbound datagrams
//! are not among them: they are routed by the HTTP/3 connection, to the request
//! stream each one names (D79).
//!
//! The accept loop is also where graceful shutdown is observed: see
//! [`handle`] for the GOAWAY and drain sequence.

use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::auth;
use crate::config::Config;
use crate::h3api::{self, FieldValue, Request, Status};
use crate::shutdown::Shutdown;
use crate::tunnel::{self, udp, Context, ProxyError, Route};

/// Drives one QUIC connection until the peer stops sending requests.
///
/// Returns `Err` only for connection-level failures; per-request problems are
/// logged and confined to their own stream.
///
/// `tunnels` counts the requests that get a tunnel slot here; it belongs to
/// [`crate::quic`], which reads it after this returns (D72).
///
/// # Shutdown
///
/// When `shutdown` fires this sends a GOAWAY and then keeps the connection alive
/// until its tunnels finish, so an in-flight page load or call is not cut off
/// mid-sentence. Two details make that work:
///
/// * dropping the HTTP/3 connection closes the QUIC connection, so returning
///   early would kill the very tunnels being drained — the loop has to stay;
/// * `accept()` cannot report the end of the drain: a client GOAWAY says nothing
///   about the requests already in flight, so [`crate::h3api::Connection::accept`]
///   never reports one. The tunnel quota going idle is the signal instead.
///
/// The wait is deliberately unbounded here: the grace period belongs to the
/// endpoint ([`crate::quic`]), which closes everything when it expires. Bounding
/// it in both places would mean two timeouts to keep consistent.
///
/// # The unauthenticated bound
///
/// Until some request on this connection has passed the credentials check, the
/// wait for the next request stream is bounded by `SILENCE_FACTOR` idle
/// timeouts, after which the connection is closed with H3_NO_ERROR. Without it
/// a peer that completes the QUIC handshake and then says nothing holds a
/// `max_connections` slot for as long as it keeps its socket open, since the
/// keep-alive PINGs `quic.rs` sends are answered by its QUIC stack with no
/// application involved and so keep the transport's idle timeout from ever
/// firing (D76). Once a request authenticates the bound is gone for the life of
/// the connection.
pub async fn handle(
    quic: quinn::Connection,
    config: Arc<Config>,
    mut shutdown: Shutdown,
    tunnels: Arc<AtomicU64>,
) -> Result<(), h3api::ConnectionError> {
    // Cloned before the handshake, which takes ownership of the connection: a
    // UDP session sends its datagrams on the QUIC connection itself, and asks it
    // per packet how large a datagram may be and how far behind its send queue
    // is. Only the sending half -- inbound datagrams are routed by the HTTP/3
    // connection to the request stream that claimed them (D79).
    let datagrams = quic.clone();

    // One idle timeout for the whole HTTP/3 handshake -- the same value
    // `quic.rs` puts in this connection's transport parameters. Why a handshake
    // needs a deadline of its own is on `h3api::Connection::handshake`.
    let mut connection =
        h3api::Connection::handshake(quic, config.limits.max_idle_timeout()).await?;

    // The datagram flag handed to the context is the connection's own rather
    // than a copy of it; `crate::h3::connection`'s module documentation says
    // what the copy cost.
    let context = Context::new(&config, datagrams, connection.peer_datagrams(), tunnels);

    let mut going_away = false;
    let silence = config.limits.max_idle_timeout() * SILENCE_FACTOR;

    loop {
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

            accepted = next_request(&mut connection, &context, silence) => match accepted {
                NextRequest::Stream(resolver) => {
                    tokio::spawn(handle_request(resolver, context.clone()));
                }
                // The peer will send no further requests.
                NextRequest::Finished => break Ok(()),
                NextRequest::Failed(error) => break Err(error),

                // Nothing wrong happened here: a peer that has not
                // authenticated is simply not owed a connection slot it is not
                // using. So this is a close with no error to signal rather than
                // a violation, and `quic.rs` logs it as the idle ending it is
                // (D76).
                NextRequest::Silent => {
                    debug!(
                        remote = %context.remote,
                        timeout_secs = silence.as_secs(),
                        "no request within the bound on an unauthenticated connection"
                    );
                    break Err(connection.close_quietly(
                        "no request within the idle timeout",
                    ));
                }
            },

        }
    }
}

/// How many idle timeouts an unauthenticated connection may spend saying
/// nothing before it is closed (D76).
///
/// The factor is not padding. The transport's own idle timeout is the primary
/// mechanism and has to keep its primacy: it needs no application involvement,
/// it reports a peer that vanished exactly as that, and every existing test and
/// log line about an idle connection is about it. It fires one idle timeout
/// after the last packet *received*, while the bound here is armed when the
/// wait begins -- never later than that packet, and at the handshake earlier --
/// so at one idle timeout the two would race, and the application timer would
/// win even on a peer that is merely gone.
///
/// Two therefore separates them: a peer that stops sending is closed by the
/// transport, exactly as before, and this bound acts only on the peers the
/// transport cannot see as idle at all -- one whose stack is answering our
/// keep-alive PINGs, or one sending packets of its own. The cost of the factor
/// is that such a peer holds its slot for two idle timeouts rather than one,
/// which is bounded either way.
const SILENCE_FACTOR: u32 = 2;

/// What waiting for the next request stream produced.
enum NextRequest {
    /// A request stream, ready to be resolved.
    Stream(h3api::Resolver),
    /// The peer will send no further requests.
    Finished,
    /// Nothing arrived within the bound, on a connection that has never
    /// authenticated (D76).
    Silent,
    /// The connection failed or was closed.
    Failed(h3api::ConnectionError),
}

impl From<Result<Option<h3api::Resolver>, h3api::ConnectionError>> for NextRequest {
    fn from(accepted: Result<Option<h3api::Resolver>, h3api::ConnectionError>) -> Self {
        match accepted {
            Ok(Some(resolver)) => Self::Stream(resolver),
            Ok(None) => Self::Finished,
            Err(error) => Self::Failed(error),
        }
    }
}

/// Waits for the next request stream, bounded while nothing has authenticated.
///
/// Cancel-safe, because [`h3api::Connection::accept`] is: the timeout adds no
/// state of its own, so a caller may poll this inside a `select!` and lose only
/// the elapsed part of the bound.
///
/// The flag is read on every pass rather than once, because it is written by the
/// request tasks: a request accepted a moment ago may be authenticating right
/// now, and a bound that had already been armed against it must not close the
/// connection out from under it.
async fn next_request(
    connection: &mut h3api::Connection,
    context: &Context,
    within: Duration,
) -> NextRequest {
    loop {
        if context.is_authenticated() {
            return connection.accept().await.into();
        }

        match tokio::time::timeout(within, connection.accept()).await {
            Ok(accepted) => return accepted.into(),
            Err(_elapsed) if context.is_authenticated() => continue,
            Err(_elapsed) => return NextRequest::Silent,
        }
    }
}

/// Resolves one request, authenticates it, and routes it to a tunnel.
async fn handle_request(resolver: h3api::Resolver, context: Context) {
    // Bounded for the same reason the accept loop is: a peer may open a request
    // stream, send one byte and stop, and `max_streams_bidi` of those would be
    // `max_streams_bidi` parked tasks per connection, from a peer that has not
    // authenticated. On expiry the stream is reset with H3_REQUEST_INCOMPLETE
    // and the connection carries on (D76).
    let (req, mut stream) = match resolver.resolve(context.max_idle_timeout).await {
        Ok(resolved) => resolved,
        Err(error) => {
            // Malformed headers, a client reset mid-headers, and similar. The
            // resolver has already reset the stream for us.
            debug!(%error, "failed to resolve request");
            return;
        }
    };

    let stream_id = stream.id();
    log_request(&req, stream_id);

    // Before routing, not after: an unauthenticated client should not be able to
    // tell from the response which `:protocol` values this proxy implements, and
    // every CONNECT — TCP or UDP — has to pass through here.
    match context.auth.authenticate(&req.fields) {
        Ok(Some(username)) => {
            // Lifts D76's bound for the rest of this connection's life: the peer
            // has proved who it is, and may now hold the connection idle for as
            // long as the transport allows.
            context.mark_authenticated();
            debug!(stream_id, username, "request authenticated");
        }
        // No users configured: an open proxy, as warned about at startup. There
        // is no door to get past, so the first request past this point counts as
        // having got past it -- otherwise every connection to an unauthenticated
        // proxy would be living under D76's bound, tunnels and all.
        Ok(None) => context.mark_authenticated(),
        Err(denied) => {
            // The attempted user-id is logged, never anything derived from the
            // password. `remote` is here so a fail2ban rule has something to act
            // on; behind a relay it is the relay's address.
            warn!(
                stream_id,
                remote = %context.remote,
                // Recorded as a `str`, not through `or_dash`: these bytes are the
                // peer's, and tracing prints a `str` field quoted and escaped, so
                // a newline or a terminal escape in a guessed user-id cannot
                // forge a journal line. See `logfmt`'s third rule.
                username = denied.username().unwrap_or(crate::logfmt::ABSENT),
                reason = denied.reason(),
                "authentication failed"
            );
            tunnel::refuse_with(
                &mut stream,
                Status::PROXY_AUTHENTICATION_REQUIRED,
                auth::challenge_fields(),
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
            Status::SERVICE_UNAVAILABLE,
            ProxyError::ConnectionLimitReached,
            stream_id,
        )
        .await;
        return;
    };

    // Counted where the slot is taken rather than where the request arrived, so
    // the connection's closing line reports tunnels this connection actually
    // got, not requests it made (D72).
    context.tunnels.fetch_add(1, Ordering::Relaxed);

    // Judged before routing because the rule is about the message, not the
    // tunnel type: RFC 9114 §4.2 makes a request carrying a connection-specific
    // field malformed whatever it asks for.
    if let Some(field) = tunnel::connection_specific_field(&req) {
        debug!(
            stream_id,
            field, "request carries a connection-specific field"
        );
        tunnel::refuse(&mut stream, Status::BAD_REQUEST, stream_id).await;
        return;
    }

    match tunnel::route(&req) {
        Route::Tcp => match req.authority.as_deref() {
            Some(authority) => {
                let authority = authority.to_owned();
                tunnel::tcp::run(&authority, stream, stream_id, &context).await;
            }
            None => {
                // RFC 9114 §4.4: a CONNECT request must carry :authority.
                debug!(stream_id, "CONNECT request without :authority");
                tunnel::refuse(&mut stream, Status::BAD_REQUEST, stream_id).await;
            }
        },
        Route::ConnectUdp => {
            udp::run(&req, stream, stream_id, context).await;
        }
        Route::UnsupportedProtocol(protocol) => {
            debug!(
                stream_id,
                protocol = %bounded(protocol),
                "unsupported :protocol"
            );
            tunnel::refuse(&mut stream, Status::NOT_IMPLEMENTED, stream_id).await;
        }
        Route::NotConnect => {
            debug!(
                stream_id,
                method = %req.method,
                "not a CONNECT request; this server only proxies"
            );
            tunnel::refuse(&mut stream, Status::NOT_IMPLEMENTED, stream_id).await;
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
fn log_request(req: &Request, stream_id: u64) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }

    let headers: Vec<String> = req
        .fields
        .iter()
        .map(|(name, value)| {
            if is_credential_header(name) {
                return format!("{name}: {}", redact_credentials(value));
            }
            match value.to_str() {
                Some(value) => format!("{name}: {value}"),
                None => format!("{name}: <{} non-utf8 bytes>", value.len()),
            }
        })
        .collect();

    let protocol = match h3api::connect_protocol(req) {
        h3api::ConnectProtocol::Absent => None,
        h3api::ConnectProtocol::ConnectUdp => Some(Cow::Borrowed("connect-udp")),
        h3api::ConnectProtocol::Unsupported(name) => Some(bounded(name)),
    };

    debug!(
        stream_id,
        method = %req.method,
        path = %req.path.as_deref().unwrap_or_default(),
        authority = ?req.authority.as_deref(),
        scheme = ?req.scheme.as_deref(),
        protocol = ?protocol,
        headers = ?headers,
        "inbound request"
    );
}

/// Caps a peer-controlled token at what a log line can afford to carry.
///
/// The `:protocol` value is kept as the bytes that arrived, so that the 501
/// RFC 9220 §3 asks for can name the protocol the client actually requested —
/// and those bytes are a field section's worth, up to
/// [`h3api::MAX_FIELD_SECTION_SIZE`], from a peer that has not authenticated.
/// Logging it whole would put tens of kilobytes in the journal twice per
/// request, for free. Only the head of it is logged, on the same reasoning as
/// [`redact_credentials`]'s bound on the auth scheme; the routing decision and
/// the response still see the whole value.
///
/// The length is kept because a token cut short is otherwise indistinguishable
/// from a short one, and truncation lands on a character boundary because
/// slicing a `str` anywhere else panics.
fn bounded(token: &str) -> Cow<'_, str> {
    /// Longest token echoed into the log in full. `connect-udp` is 11.
    const MAX_TOKEN: usize = 32;

    if token.len() <= MAX_TOKEN {
        return Cow::Borrowed(token);
    }

    let mut end = MAX_TOKEN;
    while !token.is_char_boundary(end) {
        end -= 1;
    }
    Cow::Owned(format!(
        "{}... <truncated from {} bytes>",
        &token[..end],
        token.len()
    ))
}

/// Whether a header carries credentials and must therefore be redacted.
///
/// Both names this server accepts (decision D3), matched case-insensitively —
/// a field name is lowercase by the time it gets here (RFC 9114 §4.2, enforced
/// by `h3::stream`), but this must not depend on that.
fn is_credential_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("proxy-authorization") || name.eq_ignore_ascii_case("authorization")
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
fn redact_credentials(value: &FieldValue) -> String {
    /// Longest scheme name echoed into the log. "Negotiate" is 9.
    const MAX_SCHEME: usize = 16;

    let Some(text) = value.to_str() else {
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

    fn redact(value: &str) -> String {
        redact_credentials(&FieldValue::parse(value.as_bytes()).expect("field value"))
    }

    #[test]
    fn both_credential_headers_are_recognised() {
        assert!(is_credential_header("proxy-authorization"));
        assert!(is_credential_header("authorization"));
        // The wire name is lowercase (RFC 9114 §4.2); the match does not lean
        // on that having been enforced elsewhere.
        assert!(is_credential_header("Proxy-Authorization"));
        assert!(is_credential_header("AUTHORIZATION"));
        assert!(!is_credential_header("user-agent"));
        assert!(!is_credential_header("x-volto-probe"));
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

    /// An unauthenticated peer can name a 64 KiB `:protocol`; the log gets the
    /// head of it and the length, not the whole thing.
    #[test]
    fn a_logged_token_is_bounded() {
        assert_eq!(bounded("connect-udp"), "connect-udp");
        assert_eq!(bounded(""), "");
        // Exactly at the bound is still echoed whole.
        let full = "p".repeat(32);
        assert_eq!(bounded(&full), full);

        let long = "p".repeat(64 * 1024);
        let logged = bounded(&long);
        assert_eq!(
            logged,
            format!("{full}... <truncated from 65536 bytes>"),
            "the head and the real length, and nothing else"
        );
        assert!(logged.len() < 80, "{logged}");
    }

    /// Truncation must land on a character boundary, or slicing panics.
    #[test]
    fn a_multibyte_token_is_cut_on_a_boundary() {
        // Ten three-byte characters: the 32-byte cut falls inside the eleventh.
        let token = "\u{20ac}".repeat(20);
        let logged = bounded(&token);
        assert!(
            logged.starts_with(&"\u{20ac}".repeat(10)),
            "expected ten whole characters, got {logged}"
        );
        assert!(logged.contains("truncated from 60 bytes"), "{logged}");
    }

    /// A non-UTF-8 value cannot be split into scheme and secret, so all of it goes.
    #[test]
    fn a_non_utf8_value_is_redacted_whole() {
        let value = FieldValue::parse(&[0x42, 0x61, 0x73, 0x69, 0x63, 0x20, 0xff, 0xfe])
            .expect("field value");
        assert_eq!(redact_credentials(&value), "<redacted 8 bytes>");
    }
}
