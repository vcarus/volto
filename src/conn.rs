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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::auth;
use crate::config::Config;
use crate::h3api::{self, FieldValue, Request, Status};
use crate::logfmt::bounded;
use crate::quic::AuthGate;
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
///   never reports one. The connection going idle is the signal instead —
///   [`crate::tunnel::Quota::is_busy`], which counts accepted requests as well as
///   open tunnels. Both halves are needed: a request stream is accepted the
///   moment the peer opens it and does not take a tunnel slot until its headers
///   have arrived and its credentials have been checked, so a drain that watched
///   only the tunnel count reported "nothing left to do" while a request below
///   the GOAWAY identifier was still being read. RFC 9114 §5.2 tells the peer
///   such requests "might have been processed" and leaves a server the choice
///   of rejecting them individually (REQUEST_REJECTED, §4.1.1, so the client
///   knows to retry); this server's choice is to serve them, and closing the
///   connection mid-request is neither.
///
/// The wait for the tunnels is deliberately unbounded here: the grace period
/// belongs to the endpoint ([`crate::quic`]), which closes everything when it
/// expires. Bounding it in both places would mean two timeouts to keep
/// consistent.
///
/// Sending the GOAWAY is a different matter and is bounded, because it is a
/// write and the peer decides when a write completes: the control stream
/// carries the peer's flow control, and this one sits in the same `select!` as
/// the drain, so a peer granting no window used to park the drain behind it for
/// the whole grace period. A frame that cannot be sent within one idle timeout
/// is given up on and the connection drains without it.
///
/// # The unauthenticated bound
///
/// A connection has `SILENCE_FACTOR` idle timeouts *from the handshake* to get
/// one request past the credentials check, after which it is closed with
/// H3_NO_ERROR. Without a bound of some kind a peer that completes the QUIC
/// handshake and then says nothing holds a `max_connections` slot for as long
/// as it keeps its socket open, since the keep-alive PINGs `quic.rs` sends are
/// answered by its QUIC stack with no application involved and so keep the
/// transport's idle timeout from ever firing (D76). Once a request
/// authenticates the bound is gone for the life of the connection.
///
/// The deadline is absolute rather than rearmed on each wait, which is the
/// difference between bounding a connection and bounding a pause in it: a
/// request stream is accepted the moment the peer opens it, so a peer that
/// opened one every other idle timeout — a byte apiece, never a request, never
/// a credential — used to reset the timer for ever and hold the slot anyway
/// (review C1'). Nothing legitimate is near it: a client that has just
/// completed two handshakes sends its first request within a round trip.
///
/// The deadline bounds how long such a connection may last; what bounds how
/// much of this server it may occupy while it does is a second, transport-level
/// clamp on its request streams (`quic::INITIAL_BIDI_STREAMS`), lifted by the
/// same request that lifts this one.
///
/// `resolver` is the server's blocking-pool allowance; the connection takes its
/// own view of it here, which is what bounds the threads its name lookups can
/// hold (D90).
///
/// `authenticated` is that state, and it belongs to [`crate::quic`] for the same
/// reason `tunnels` does: the accept loop reads it after this has been handed
/// the connection, to decide which connection loses its slot when the server is
/// full. `dropped_datagrams` belongs there too — it is read for the closing
/// line, at the same moment `tunnels` is — and is handed on to the HTTP/3
/// connection, whose datagram router is the thing that drops.
pub async fn handle(
    quic: quinn::Connection,
    config: Arc<Config>,
    mut shutdown: Shutdown,
    resolver: &crate::net::ResolverBudget,
    tunnels: Arc<AtomicU64>,
    dropped_datagrams: Arc<AtomicU64>,
    authenticated: AuthGate,
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
        h3api::Connection::handshake(quic, config.limits.max_idle_timeout(), dropped_datagrams)
            .await?;

    // The datagram flag handed to the context is the connection's own rather
    // than a copy of it; `crate::h3::connection`'s module documentation says
    // what the copy cost.
    let context = Context::new(
        &config,
        datagrams,
        connection.peer_datagrams(),
        resolver,
        tunnels,
        authenticated,
    );

    let mut going_away = false;
    // The one idle timeout every peer-dependent write in this server gets; see
    // the GOAWAY arm below.
    let goaway_within = config.limits.max_idle_timeout();
    let silence = config.limits.max_idle_timeout() * SILENCE_FACTOR;
    // Armed here and never again: the clock the peer is racing runs from the
    // moment it could first have sent a request.
    let deadline = tokio::time::Instant::now() + silence;

    loop {
        tokio::select! {
            biased;

            // Guarded so the branch stops competing once the latch has fired:
            // it is sticky, and would otherwise win every iteration forever.
            () = shutdown.fired(), if !going_away => {
                going_away = true;

                // Bounded like every other write that depends on the peer
                // taking it ([`h3api::Stream::respond_within`]): the control
                // stream applies the peer's flow control, and this write is a
                // `select!` arm of the loop that drains the connection, so a
                // peer granting no window parks the drain with it -- the arm
                // below never polled again, the connection never reported
                // finished, and the whole process waiting out
                // `server.shutdown_grace` for one peer that is under no
                // obligation to read anything (adversarial pass 2026-08-29).
                let sent = match tokio::time::timeout(
                    goaway_within,
                    connection.shutdown(),
                ).await {
                    Ok(Ok(())) => true,
                    Ok(Err(error)) => {
                        // The connection is unusable, so there is nothing left
                        // to drain politely.
                        debug!(%error, "failed to send GOAWAY");
                        break Ok(());
                    }
                    // Not a break: the GOAWAY is a courtesy, and this
                    // connection's tunnels are somebody's live traffic. Giving
                    // up on the frame and draining anyway is what keeps the
                    // promise the grace period makes to them; returning here
                    // would drop the HTTP/3 connection and cut every one.
                    Err(_elapsed) => false,
                };

                let live = context.quota.live();
                if sent {
                    info!(live_tunnels = live, "sent GOAWAY, draining tunnels");
                } else {
                    debug!(
                        remote = %context.remote,
                        live_tunnels = live,
                        timeout_secs = goaway_within.as_secs(),
                        "the peer would not take a GOAWAY; draining without one"
                    );
                }
                // Not `live == 0`: a request accepted before the signal whose
                // headers are still arriving holds no tunnel slot yet, and it
                // is below the identifier this GOAWAY just published -- one the
                // peer was told "might have been processed" (RFC 9114 §5.2).
                // This server serves those rather than rejecting them
                // individually, and reading only the tunnel count closed the
                // connection out from under it instead (adversarial pass
                // 2026-08-30).
                if !context.quota.is_busy() {
                    break Ok(());
                }
            }

            // Only meaningful after GOAWAY: before it, an idle connection is
            // simply idle, not finished.
            () = context.quota.wait_until_idle(), if going_away => {
                info!("every tunnel finished after GOAWAY");
                break Ok(());
            }

            accepted = next_request(&mut connection, &context, deadline) => match accepted {
                NextRequest::Stream(resolver) => {
                    // Taken here rather than inside the task, and before the
                    // spawn: what it records is that this connection has
                    // accepted a request, which is true from this line on
                    // whether or not the task has been polled yet. Held for the
                    // task's whole life, so the drain below cannot mistake a
                    // request whose headers are still arriving -- one this
                    // server means to serve, per the GOAWAY identifier above it
                    // (RFC 9114 §5.2) -- for a connection with nothing left to
                    // do.
                    let pending = context.quota.enter();
                    let context = context.clone();
                    tokio::spawn(async move {
                        let _pending = pending;
                        handle_request(resolver, context).await;
                    });
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
/// after the last packet *received*, while the deadline here is armed at the
/// handshake and so is always the earlier of the two to start counting; at one
/// idle timeout they would race, and the application timer would win even on a
/// peer that is merely gone.
///
/// Two therefore separates them: a peer that stops sending is closed by the
/// transport, exactly as before, and this bound acts only on the peers the
/// transport cannot see as idle at all -- one whose stack is answering our
/// keep-alive PINGs, or one sending packets of its own. The cost of the factor
/// is that such a peer holds its slot for two idle timeouts rather than one,
/// which is bounded either way.
///
/// Visible to the crate because [`crate::config`]'s test for D86 multiplies by
/// it: the ceiling on `max_idle_timeout` is what keeps `Instant::now() + idle *
/// this` inside what the arithmetic can take, and a ceiling pinned against a
/// copy of the factor would stop meaning anything the day the factor moved.
/// `validate` itself never multiplies -- it compares against the ceiling
/// constant, and this is the number that ceiling was chosen for.
pub(crate) const SILENCE_FACTOR: u32 = 2;

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

/// Waits for the next request stream, until `deadline` while nothing has
/// authenticated.
///
/// Cancel-safe, because [`h3api::Connection::accept`] is: the deadline is a
/// point in time rather than a duration to count down, so a caller may poll this
/// inside a `select!` and lose nothing at all by doing so.
///
/// The flag is read on every pass rather than once, because it is written by the
/// request tasks: a request accepted a moment ago may be authenticating right
/// now, and a deadline that has just expired must not close the connection out
/// from under it. That re-read is the *only* place the verdict is reached, which
/// is why a lapsed wait goes back round the loop instead of deciding for itself.
///
/// # Why the clock is read as well as awaited
///
/// `tokio::time::timeout_at` polls the future it wraps **first** and returns its
/// value without ever consulting the clock, so a lapsed deadline is only noticed
/// on a poll where nothing was ready. [`h3api::Connection::accept`] is ready the
/// moment the peer has opened a stream, and a peer may always have another one
/// queued: with `max_streams_bidi` raised, one that opens a request stream and
/// finishes it empty -- a stream error apiece, so the connection survives every
/// one and the allowance comes straight back -- kept the loop supplied
/// indefinitely and was never measured against the deadline at all. D76 made the
/// deadline absolute so that it could not be *rearmed*; this is what stops it
/// being stepped over (adversarial pass 2026-08-29).
///
/// A peer under the pre-authentication clamp (`quic::INITIAL_BIDI_STREAMS`) can
/// no longer keep a supply of that depth: the configured allowance does not
/// reach it at all, and sixteen streams' worth of credit comes back three at a
/// time. That makes this the second line rather than the first, and it stays,
/// because hard to reach is not the same as unreachable -- the clamp is lifted
/// by authentication and the deadline exists only until authentication, so
/// neither can be the other's proof.
///
/// So the clock is read before each wait. The cost is one `Instant::now()` per
/// accepted stream, and only while the connection has yet to authenticate.
async fn next_request(
    connection: &mut h3api::Connection,
    context: &Context,
    deadline: tokio::time::Instant,
) -> NextRequest {
    loop {
        if context.is_authenticated() {
            return connection.accept().await.into();
        }

        // The verdict, and the only place it is reached. The authentication
        // flag has just been read above, so this races a request that is
        // authenticating exactly as the wait below used to.
        if tokio::time::Instant::now() >= deadline {
            return NextRequest::Silent;
        }

        match tokio::time::timeout_at(deadline, connection.accept()).await {
            Ok(accepted) => return accepted.into(),
            // Back round the loop rather than deciding here: the next pass
            // re-reads the authentication flag -- a request may have
            // authenticated while this waited -- and then the clock, which has
            // just reached the deadline. Deciding in this arm as well would be
            // a second copy of that judgement to keep in step.
            Err(_elapsed) => continue,
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
    let (req, mut stream) = match resolver.resolve().await {
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

    // Before authentication, before the quota, before routing: RFC 9114 §4.2
    // makes a message carrying a connection-specific field malformed, and that
    // is a judgement about the message rather than about who sent it or what it
    // asks for. The other half of the same sentence -- the `Connection` field
    // itself -- is refused in the codec, which is earlier still, so judging this
    // half after the credentials check made one MUST answer 407 to an
    // unauthenticated peer and 400 to an authenticated one (review M4).
    if let Some(field) = tunnel::connection_specific_field(&req) {
        debug!(
            stream_id,
            field, "request carries a connection-specific field"
        );
        tunnel::refuse(&mut stream, Status::BAD_REQUEST, stream_id).await;
        return;
    }

    // Before routing, not after: an unauthenticated client should not be able to
    // tell from the response which `:protocol` values this proxy implements, and
    // every CONNECT — TCP or UDP — has to pass through here.
    match context.auth.authenticate(&req.fields) {
        Ok(Some(username)) => {
            // Lifts D76's bound for the rest of this connection's life: the peer
            // has proved who it is, and may now hold the connection idle for as
            // long as the transport allows -- and, on the first request to get
            // here, raises the connection's request-stream allowance from the
            // handshake's clamp to the configured one. Both are the same door,
            // so both are opened in one place.
            context.mark_authenticated(Some(username));
            debug!(stream_id, username, "request authenticated");
        }
        // No users configured: an open proxy, as warned about at startup. There
        // is no door to get past, so the first request past this point counts as
        // having got past it -- otherwise every connection to an unauthenticated
        // proxy would be living under D76's bound, tunnels and all.
        Ok(None) => context.mark_authenticated(None),
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
                // forge a journal line. See `logfmt`'s third rule. Their number
                // is the peer's too -- a user-id is whatever it put before the
                // first colon of a field section -- and `auth` has already cut
                // it to what a log line can carry (review H3).
                username = denied.username().unwrap_or(crate::logfmt::ABSENT),
                reason = denied.reason(),
                "authentication failed"
            );

            // Counted before the answer goes out rather than after it: what is
            // counted is a wrong guess, not the peer having been told about it.
            // With the count on the far side of the write, a peer that grants no
            // flow-control window never reaches it and guesses for free until it
            // runs out of streams (review H1).
            // Guessing should cost a handshake every few attempts rather than
            // being free for the life of one connection. The close is decided
            // here too, before the 407 is written: a peer that will not take
            // the answer must not keep the connection for another idle timeout
            // while the write waits on it (review H1, re-verification).
            if context.record_auth_failure(denied.username()) {
                warn!(
                    remote = %context.remote,
                    failures = context.max_auth_failures,
                    "closing the connection after repeated authentication failures"
                );
                context.quic.close(
                    h3api::AUTH_FAILURE_LIMIT_CODE,
                    b"too many authentication failures",
                );
                return;
            }

            tunnel::refuse_with(
                &mut stream,
                Status::PROXY_AUTHENTICATION_REQUIRED,
                auth::challenge_fields(),
                stream_id,
            )
            .await;
            return;
        }
    }

    // One slot per request, held until this task ends however it ends. Taken
    // before any socket is opened, so the limit bounds file descriptors rather
    // than trailing them.
    let Some(_slot) = context.quota.acquire() else {
        // Sampled for the reason `tunnel::admit_target`'s refusal is: a
        // connection that has reached its limit answers every further request
        // this way, at one HEADERS frame apiece, for as long as the peer keeps
        // asking. The first refusal is as loud as it ever was and the reports
        // carry the running total, so an operator still sees both that the
        // limit was hit and how hard (`crate::logfmt::Sampler`).
        let live = context.quota.live();
        match context.limit_refusals.record() {
            Some(refusals) => warn!(
                stream_id,
                live,
                refusals,
                "connection is at its tunnel limit; further refusals on this connection are \
                 logged at debug level until the count doubles"
            ),
            None => debug!(stream_id, live, "connection is at its tunnel limit"),
        }
        tunnel::refuse_because(&mut stream, ProxyError::ConnectionLimitReached, stream_id).await;
        return;
    };

    // Counted where the slot is taken rather than where the request arrived, so
    // the connection's closing line reports tunnels this connection actually
    // got, not requests it made (D72).
    context.tunnels.fetch_add(1, Ordering::Relaxed);

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
                // As a `str` rather than through `%`: `bounded` cuts the length
                // and nothing else, and a `:protocol` token is only checked for
                // being UTF-8, so a newline in one would forge a journal line
                // straight through `Display` (review M5). See `logfmt`.
                protocol = bounded(protocol).as_ref(),
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
            if auth::is_credential_field(name) {
                return format!("{name}: {}", redact_credentials(value));
            }
            match value.to_str() {
                Some(value) => format!("{name}: {value}"),
                None => format!("{name}: <{} non-utf8 bytes>", value.len()),
            }
        })
        .collect();

    // Every `:protocol` token alike, through `bounded`, which cuts the length
    // and nothing else: a token may be a whole field section's worth of bytes.
    // What keeps a newline in one from forging a journal line is the `?` it is
    // recorded with below -- a `:protocol` token is only checked for being
    // UTF-8, and Debug formatting escapes control characters, which is the same
    // division of labour the 501 path above states for the `str` it logs. See
    // `logfmt`.
    let protocol = req.protocol.as_deref().map(bounded);

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

    /// The redaction above and the acceptance in [`auth`] read the same list,
    /// which is the point: two of them would let decision D3 be settled in one
    /// place and print the credential in the other.
    #[test]
    fn both_credential_headers_are_recognised() {
        assert!(auth::is_credential_field("proxy-authorization"));
        assert!(auth::is_credential_field("authorization"));
        // The wire name is lowercase (RFC 9114 §4.2); the match does not lean
        // on that having been enforced elsewhere.
        assert!(auth::is_credential_field("Proxy-Authorization"));
        assert!(auth::is_credential_field("AUTHORIZATION"));
        assert!(!auth::is_credential_field("user-agent"));
        assert!(!auth::is_credential_field("x-volto-probe"));
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
        let value = FieldValue::parse(&[0x42, 0x61, 0x73, 0x69, 0x63, 0x20, 0xff, 0xfe])
            .expect("field value");
        assert_eq!(redact_credentials(&value), "<redacted 8 bytes>");
    }
}
