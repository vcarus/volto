//! Per-connection driving: accept request streams, authenticate them, dispatch
//! them.
//!
//! A connection owns the things every tunnel on it shares: the credentials and
//! destination policy each request is checked against, the QUIC connection its
//! UDP sessions send datagrams on, and the tunnel quota they all draw on. All of
//! it lives in [`crate::tunnel::Context`], built once and held in an `Arc` that
//! every request on the connection shares rather than copies. Inbound datagrams
//! are not among them: they are routed by the HTTP/3 connection, to the request
//! stream each one names (D79).
//!
//! The accept loop is also where graceful shutdown is observed: see
//! [`handle`] for the GOAWAY and drain sequence.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::auth;
use crate::h3api::{self, FieldValue, Request, Status};
use crate::logfmt::bounded;
use crate::quic::AuthGate;
use crate::shutdown::Shutdown;
use crate::tunnel::{self, Context, ProxyError, Route, udp};

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
///   early would end the tunnels being drained. The loop has to stay.
/// * `accept()` cannot report the end of the drain: a client GOAWAY says nothing
///   about the requests already in flight, so [`crate::h3api::Connection::accept`]
///   never reports one. The connection going idle is the signal instead:
///   [`crate::tunnel::Quota::is_busy`], which counts accepted requests as well as
///   open tunnels. Both halves are needed, because a request stream does not
///   take a tunnel slot until its headers have arrived and its credentials have
///   been checked. RFC 9114 §5.2 tells the peer such requests "might have been
///   processed" and leaves a server the choice of rejecting them individually
///   (REQUEST_REJECTED, §4.1.1, so the client knows to retry). This server's
///   choice is to serve them, and closing the connection mid-request is
///   neither.
///
/// The wait for the tunnels is deliberately unbounded here: the grace period
/// belongs to the endpoint ([`crate::quic`]), which closes everything when it
/// expires. Bounding it in both places would mean two timeouts to keep
/// consistent.
///
/// Sending the GOAWAY is bounded, because it is a write and the peer decides
/// when a write completes; see `announce_goaway`.
///
/// # Request tasks
///
/// Each request runs in a task of its own, held in a `JoinSet` that this
/// function owns. When this returns, or when its future is dropped by an
/// eviction or by the end of the shutdown grace, the set is dropped and every
/// request task still running is aborted. That drops its target socket, which
/// is the close RFC 9114 §4.4 asks for: "if a proxy detects an error with the
/// stream or the QUIC connection, it MUST close the TCP connection." A request
/// that is still resolving its target or connecting to it watches neither the
/// stream nor the connection, so without this it would hold its socket, its
/// tunnel slot and the connection's [`Context`] until the connect budget ran
/// out. None of those would then count against `max_connections`, because the
/// connection's slot is released when this returns.
///
/// Nothing needs a request task to outlive this function. Every return drops
/// the HTTP/3 connection, which closes the QUIC connection. The drain returns
/// `Ok` only once no request is pending, or once the GOAWAY write has failed on
/// a connection that is gone. A lookup already on the blocking pool is not
/// cut short by the abort: its slot travels with the thread (D90).
///
/// # The unauthenticated bound
///
/// A connection has `SILENCE_FACTOR` idle timeouts *from the handshake* to get
/// one request past the credentials check, after which it is closed with
/// H3_NO_ERROR. Without it a peer that completes the QUIC handshake and then
/// says nothing holds a `max_connections` slot for as long as it keeps its
/// socket open, since its QUIC stack answers our keep-alive PINGs and so keeps
/// the transport's idle timeout from ever firing (D76). Once a request
/// authenticates the bound is gone for the life of the connection.
///
/// The deadline is absolute rather than rearmed on each wait. A request stream
/// is accepted the moment the peer opens it, so with a rearmed timer a peer
/// that opened one every other idle timeout (a byte apiece, never a credential)
/// would hold the slot for ever. Nothing legitimate is near the deadline: a
/// client that has just completed two handshakes sends its first request within
/// a round trip. How much of this server such a connection may occupy meanwhile
/// is bounded by the stream clamp `quic::INITIAL_BIDI_STREAMS`, lifted by the
/// same request.
///
/// `generation` is the configuration the connection was accepted under, with
/// the credentials and destination rules built from it. `resolver` is the
/// connection's own view of the server's blocking-pool allowance, which bounds
/// the threads its name lookups can hold (D90).
///
/// `authenticated` is that state, and it belongs to [`crate::quic`] for the same
/// reason `tunnels` does: the accept loop reads it after this has been handed
/// the connection, to decide which connection loses its slot when the server is
/// full. `dropped_datagrams` belongs there too, because it is read for the
/// closing line at the same moment `tunnels` is. It is handed on to the HTTP/3
/// connection, whose datagram router is the thing that drops.
pub async fn handle(
    quic: quinn::Connection,
    generation: Arc<tunnel::Generation>,
    mut shutdown: Shutdown,
    resolver: crate::net::ConnectionResolver,
    tunnels: Arc<AtomicU64>,
    dropped_datagrams: Arc<AtomicU64>,
    authenticated: AuthGate,
) -> Result<(), h3api::ConnectionError> {
    // Cloned before the handshake, which takes ownership of the connection. The
    // context needs the connection itself, not only its datagram half: a UDP
    // session sends datagrams on it and asks it per packet how large one may be
    // and how far behind the send queue is, and the first authenticated
    // request raises its stream allowance (D98).
    let for_context = quic.clone();

    // Every request task of this connection. Dropping the set aborts what is
    // still running, so a request cannot outlive the connection it arrived on;
    // see "# Request tasks" above.
    //
    // Declared before the connection on purpose. Locals are dropped in reverse
    // order, so on every way out the connection is closed first and the tasks
    // are ended after it. Ended first, a task would drop its half of a request
    // stream while the connection was still open, and quinn finishes a dropped
    // send stream: the client could read a DATA frame cut short and then a
    // clean end, which RFC 9114 §7.1 makes a connection error on its side.
    let mut requests = JoinSet::new();

    // One idle timeout for the whole HTTP/3 handshake, the same value
    // `quic/transport.rs` puts in this connection's transport parameters. Why a
    // handshake needs a deadline of its own is on
    // `h3api::Connection::handshake`.
    let idle = generation.config.limits.max_idle_timeout();
    let mut connection = h3api::Connection::handshake(quic, idle, dropped_datagrams).await?;

    // The datagram flag handed to the context is the connection's own rather
    // than a copy of it; `h3api::Connection::peer_datagrams` says why.
    let context = Arc::new(Context::new(
        generation,
        for_context,
        connection.peer_datagrams(),
        resolver,
        tunnels,
        authenticated,
    ));

    let mut going_away = false;
    // The one idle timeout every peer-dependent write in this server gets; see
    // the GOAWAY arm below.
    let goaway_within = idle;
    let silence = idle * SILENCE_FACTOR;
    // Armed here and never again: the clock the peer is racing runs from the
    // moment it could first have sent a request.
    let deadline = tokio::time::Instant::now() + silence;

    loop {
        // Reaped at the top of every pass, the way `quic::Server::run` reaps
        // connections, so the set holds the live requests rather than every
        // request the connection has served. A task's output is `()`, and a
        // panic has already been reported by the panic hook.
        while requests.try_join_next().is_some() {}

        tokio::select! {
            biased;

            // Guarded so the branch stops competing once the latch has fired:
            // it is sticky, and would otherwise win every iteration forever.
            () = shutdown.fired(), if !going_away => {
                going_away = true;

                if let Drain::Finished = announce_goaway(
                    &mut connection,
                    &context,
                    goaway_within,
                ).await {
                    break Ok(());
                }
            }

            // Only meaningful after GOAWAY: before it, an idle connection is
            // simply idle, not finished.
            () = context.quota.wait_until_idle(), if going_away => {
                info!(log_id = "2l3q6ors", "every tunnel finished after GOAWAY");
                break Ok(());
            }

            accepted = next_request(&mut connection, &context, deadline) => match accepted {
                NextRequest::Stream(resolver) => {
                    // Taken here rather than inside the task, and before the
                    // spawn: what it records is that this connection has
                    // accepted a request, which is true from this line on
                    // whether or not the task has been polled yet. Held for the
                    // task's whole life, so the drain cannot mistake a request
                    // whose headers are still arriving for a connection with
                    // nothing left to do (see [`crate::tunnel::Pending`]).
                    let pending = context.quota.enter();
                    let context = Arc::clone(&context);
                    requests.spawn(async move {
                        let _pending = pending;
                        handle_request(resolver, context).await;
                    });
                }
                NextRequest::Failed(error) => break Err(error),

                // Nothing wrong happened here: a peer that has not
                // authenticated is simply not owed a connection slot it is not
                // using. So this is a close with no error to signal rather than
                // a violation, and `quic/mod.rs` logs it as the idle ending it
                // is (D76).
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

            // Cancel-safe, so losing this race costs nothing; the reaping at
            // the top of the loop is what keeps the set trimmed while requests
            // keep arriving.
            Some(_) = requests.join_next(), if !requests.is_empty() => {}
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
/// transport, and this bound acts only on the peers the transport cannot see as
/// idle at all: one whose stack is answering our keep-alive PINGs, or one
/// sending packets of its own. The cost of the factor is that such a peer holds
/// its slot for two idle timeouts rather than one, which is bounded either way.
///
/// Visible to the crate because [`crate::config`]'s test for D86 multiplies by
/// it: the ceiling on `max_idle_timeout` is what keeps `Instant::now() + idle *
/// this` inside what the arithmetic can take, and a ceiling pinned against a
/// copy of the factor would stop meaning anything the day the factor moved.
/// `validate` itself never multiplies. It compares against the ceiling
/// constant, and this is the number that ceiling was chosen for.
pub(crate) const SILENCE_FACTOR: u32 = 2;

/// Whether a connection still has work to do once its GOAWAY is out.
enum Drain {
    /// Requests are still in flight; keep serving them.
    Pending,
    /// Nothing is left to serve, or nothing can be: close now.
    Finished,
}

/// Tells the peer this connection is going away, and reports whether anything
/// is left to drain.
///
/// The GOAWAY write is bounded like every other write that depends on the peer
/// taking it ([`h3api::Stream::respond_within`]). The control stream applies
/// the peer's flow control, and this runs inside the loop that drains the
/// connection, so a peer granting no window would park the drain with it. The
/// accept arm would never be polled again, the connection would never report
/// finished, and the whole process would wait out `server.shutdown_grace` for
/// one peer that is under no obligation to read anything.
async fn announce_goaway(
    connection: &mut h3api::Connection,
    context: &Context,
    within: Duration,
) -> Drain {
    let sent = match tokio::time::timeout(within, connection.shutdown()).await {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            // The connection is unusable, so there is nothing left to drain
            // politely.
            debug!(%error, "failed to send GOAWAY");
            return Drain::Finished;
        }
        // Not a `Finished`: the GOAWAY is a courtesy, and this connection's
        // tunnels are somebody's live traffic. Giving up on the frame and
        // draining anyway is what keeps the promise the grace period makes to
        // them; returning here would drop the HTTP/3 connection and cut every
        // one.
        Err(_elapsed) => false,
    };

    let live = context.quota.live();
    if sent {
        info!(
            log_id = "2rquy1sk",
            live_tunnels = live,
            "sent GOAWAY, draining tunnels"
        );
    } else {
        debug!(
            remote = %context.remote,
            live_tunnels = live,
            timeout_secs = within.as_secs(),
            "the peer would not take a GOAWAY; draining without one"
        );
    }

    // Not `live == 0`: a request accepted before the signal whose headers are
    // still arriving holds no tunnel slot yet, and it is below the identifier
    // this GOAWAY just published. See [`crate::tunnel::Quota::is_busy`].
    if context.quota.is_busy() {
        Drain::Pending
    } else {
        Drain::Finished
    }
}

/// What waiting for the next request stream produced.
enum NextRequest {
    /// A request stream, ready to be resolved.
    Stream(h3api::Resolver),
    /// Nothing arrived within the bound, on a connection that has never
    /// authenticated (D76).
    Silent,
    /// The connection failed or was closed.
    Failed(h3api::ConnectionError),
}

impl From<Result<h3api::Resolver, h3api::ConnectionError>> for NextRequest {
    fn from(accepted: Result<h3api::Resolver, h3api::ConnectionError>) -> Self {
        match accepted {
            Ok(resolver) => Self::Stream(resolver),
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
/// queued. With `max_streams_bidi` raised, a peer that opens request streams
/// and finishes each one empty (a stream error apiece, so the connection
/// survives every one and the allowance comes straight back) can keep the loop
/// supplied indefinitely, and the deadline is then never measured. Reading the
/// clock stops it being skipped, as being absolute stops it being rearmed (D92).
///
/// A peer under the pre-authentication clamp (`quic::INITIAL_BIDI_STREAMS`)
/// cannot keep a supply of that depth: the configured allowance does not reach
/// it at all, and sixteen streams' worth of credit comes back three at a time.
/// That makes this the second defence rather than the first. It stays, because
/// hard to reach is not unreachable: the clamp is lifted by authentication and
/// the deadline exists only until authentication, so neither can stand in for
/// the other.
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
        // flag has just been read above, so a request that is authenticating
        // can race this only in the moment between that read and this one.
        if tokio::time::Instant::now() >= deadline {
            return NextRequest::Silent;
        }

        match tokio::time::timeout_at(deadline, connection.accept()).await {
            Ok(accepted) => return accepted.into(),
            // Back round the loop rather than deciding here: the next pass
            // re-reads the authentication flag, because a request may have
            // authenticated while this waited, and then the clock, which has
            // just reached the deadline. Deciding in this arm as well would be
            // a second copy of that judgement to keep in step.
            Err(_elapsed) => {}
        }
    }
}

/// Resolves one request, authenticates it, and routes it to a tunnel.
///
/// Four phases, in this order, and each may answer the request and end it: the
/// checks on the message, the credentials, the connection's tunnel quota, and
/// the route.
async fn handle_request(resolver: h3api::Resolver, context: Arc<Context>) {
    let Some((req, mut stream)) = resolve(resolver).await else {
        return;
    };
    let stream_id = stream.id();
    log_request(&req, stream_id);

    if let Some(refusal) = refused_as_a_message(&req) {
        refusal.log(stream_id);
        tunnel::refuse(&mut stream, Status::BAD_REQUEST).await;
        return;
    }

    if !authenticate(&req, &context, &mut stream).await {
        return;
    }

    // One slot per request, held until this task ends however it ends.
    let Some(_slot) = take_slot(&context, &mut stream).await else {
        return;
    };

    route(&req, stream, &context).await;
}

/// Reads a request's headers, or `None` when the stream has already been dealt
/// with.
async fn resolve(resolver: h3api::Resolver) -> Option<(Request, h3api::Stream)> {
    // Bounded for the same reason the accept loop is: a peer may open a request
    // stream, send one byte and stop, and `max_streams_bidi` of those would be
    // `max_streams_bidi` parked tasks per connection, from a peer that has not
    // authenticated. On expiry the stream is reset with H3_REQUEST_INCOMPLETE
    // and the connection carries on (D76).
    match resolver.resolve().await {
        Ok(resolved) => Some(resolved),
        Err(error) => {
            // Malformed headers, a client reset mid-headers, and similar. The
            // resolver has already reset the stream for us.
            debug!(%error, "failed to resolve request");
            None
        }
    }
}

/// Why a request is refused with 400 for what its message carries, before
/// anything has looked at who sent it.
#[derive(Debug, PartialEq, Eq)]
enum MessageRefusal {
    /// A connection-specific field, named.
    ConnectionSpecificField(&'static str),
    /// More credential values than [`auth::MAX_CREDENTIAL_VALUES`], counted.
    TooManyCredentials(usize),
}

impl MessageRefusal {
    fn log(&self, stream_id: u64) {
        match *self {
            Self::ConnectionSpecificField(field) => debug!(
                stream_id,
                field, "request carries a connection-specific field"
            ),
            Self::TooManyCredentials(offered) => debug!(
                stream_id,
                offered,
                allowed = auth::MAX_CREDENTIAL_VALUES,
                "request carries more credential values than it may"
            ),
        }
    }
}

/// The 400 verdicts on the message itself, in the order they are judged.
///
/// Both come before authentication, before the quota and before routing,
/// because each is a judgement about the message rather than about who sent it
/// or what it asks for.
fn refused_as_a_message(req: &Request) -> Option<MessageRefusal> {
    // RFC 9114 §4.2 makes a message carrying a connection-specific field
    // malformed. The other half of the same sentence, the `Connection` field
    // itself, is refused in the codec, which is earlier still. Judging this half
    // after the credentials check would answer one MUST with 407 to an
    // unauthenticated peer and 400 to an authenticated one.
    if let Some(field) = tunnel::connection_specific_field(req) {
        return Some(MessageRefusal::ConnectionSpecificField(field));
    }

    // Before any credential is tried, and so before any of them is charged: a
    // request carrying more values than `auth::MAX_CREDENTIAL_VALUES` is a batch
    // of guesses answered by one 407.
    let offered = auth::credential_values(&req.fields);
    if offered > auth::MAX_CREDENTIAL_VALUES {
        return Some(MessageRefusal::TooManyCredentials(offered));
    }

    None
}

/// Checks the request's credentials, and answers it when they fail.
///
/// `true` means the request may go on to the quota and the route.
async fn authenticate(req: &Request, context: &Context, stream: &mut h3api::Stream) -> bool {
    let stream_id = stream.id();

    // Before routing, not after: an unauthenticated client should not be able to
    // tell from the response which `:protocol` values this proxy implements, and
    // every CONNECT, TCP or UDP, has to pass through here.
    match context.generation.auth.authenticate(&req.fields) {
        // `None` is an open proxy (no users configured, as warned about at
        // startup): there is no check to pass, so the first request past this
        // point counts as having passed it. Otherwise every connection to an
        // unauthenticated proxy would live under D76's bound, tunnels and all.
        Ok(user) => {
            // Lifts D76's bound for the rest of this connection's life: the peer
            // has proved who it is, and may now hold the connection idle for as
            // long as the transport allows. On the first request to get here it
            // also raises the connection's request-stream allowance from the
            // handshake's clamp to the configured one. Both follow from the same
            // check, so both are done in one place. `false` means an eviction
            // claimed the connection first: the accept loop is already closing
            // it, and the request must not be routed or answered.
            if !context.mark_authenticated(user) {
                return false;
            }
            if let Some(username) = user {
                debug!(stream_id, username, "request authenticated");
            }
            true
        }
        Err(denials) => {
            // One line per refused request, not one per refused value: the
            // first refusal comes from the highest-priority header and is the
            // one most likely to be the client's real attempt, and D97 prices
            // log volume per line.
            let denied = denials.reported();

            // The attempted user-id is logged, never anything derived from the
            // password. `remote` is here so a fail2ban rule has something to act
            // on; behind a relay it is the relay's address.
            warn!(
                log_id = "3gmzhaq7",
                stream_id,
                remote = %context.remote,
                // Recorded as a `str`, not through `or_dash`: these bytes are the
                // peer's, and tracing prints a `str` field quoted and escaped, so
                // a newline or a terminal escape in a guessed user-id cannot
                // forge a journal line. See `logfmt`'s third rule. Their number
                // is the peer's too, since a user-id is whatever it put before
                // the first colon of a field section, and `auth` has already
                // cut it to what a log line can carry.
                username = denied.username().unwrap_or(crate::logfmt::ABSENT),
                reason = denied.reason(),
                "authentication failed"
            );

            // Guessing should cost a handshake every few attempts rather than
            // being free for the life of one connection. Counted before the
            // answer goes out: what is counted is a wrong guess, not the peer
            // having been told about it. With the count after the write, a
            // peer that grants no flow-control window would never reach it and
            // would guess for free until it ran out of streams. The close is
            // decided here too, before the 407 is written, so a peer that will
            // not take the answer cannot keep the connection for another idle
            // timeout while the write waits on it.
            //
            // One charge per refused value, each to the user-id that value
            // claimed (`auth::MAX_CREDENTIAL_VALUES`). Every value is charged
            // before the answer is decided, so `|` rather than `||`.
            let mut spent = false;
            for claim in denials.claims() {
                spent |= context.record_auth_failure(claim);
            }

            if spent {
                warn!(
                    log_id = "4fmkbtxl",
                    remote = %context.remote,
                    failures = context.max_auth_failures,
                    "closing the connection after repeated authentication failures"
                );
                // Through the stream rather than `context.quic`, so the close
                // is recorded as the connection's reason. A task that finds a
                // violation afterwards in buffered data cannot rename it in the
                // closing line.
                stream.close_connection(
                    h3api::AUTH_FAILURE_LIMIT_CODE,
                    "too many authentication failures",
                );
                return false;
            }

            tunnel::refuse_with(
                stream,
                Status::PROXY_AUTHENTICATION_REQUIRED,
                auth::challenge_fields(),
            )
            .await;
            false
        }
    }
}

/// Takes one of the connection's tunnel slots, or refuses the request when it
/// has none left.
///
/// Taken before any socket is opened, so the limit bounds file descriptors
/// rather than trailing them.
async fn take_slot(context: &Context, stream: &mut h3api::Stream) -> Option<tunnel::Slot> {
    let Some(slot) = context.quota.acquire() else {
        // Sampled for the reason `tunnel::admit_target`'s refusal is: a
        // connection that has reached its limit answers every further request
        // this way, at one HEADERS frame apiece, for as long as the peer keeps
        // asking. The first refusal is a warning and the reports carry the
        // running total, so an operator sees both that the limit was hit and
        // how hard (`crate::logfmt::Sampler`).
        let stream_id = stream.id();
        let live = context.quota.live();
        match context.limit_refusals.record() {
            Some(refusals) => warn!(
                log_id = "6qq80h9t",
                stream_id,
                live,
                refusals,
                "connection is at its tunnel limit; further refusals on this connection are \
                 logged at debug level until the count doubles"
            ),
            None => debug!(stream_id, live, "connection is at its tunnel limit"),
        }
        tunnel::refuse_because(stream, ProxyError::ConnectionLimitReached).await;
        return None;
    };

    // Counted where the slot is taken rather than where the request arrived, so
    // the connection's closing line reports tunnels this connection actually
    // got, not requests it made (D72).
    context.tunnels.fetch_add(1, Ordering::Relaxed);
    Some(slot)
}

/// Hands an admitted request to the tunnel its method and `:protocol` name.
async fn route(req: &Request, mut stream: h3api::Stream, context: &Context) {
    let stream_id = stream.id();

    match tunnel::route(req) {
        Route::Tcp => match req.authority.as_deref() {
            Some(authority) => {
                tunnel::tcp::run(authority, stream, context).await;
            }
            None => {
                // Unreachable: RFC 9114 §4.4 is enforced in the codec, which
                // rejects "a CONNECT request without :authority" as malformed
                // before `handle_request` is reached, and `Route::Tcp` is the
                // same predicate the codec takes that branch on. Answered
                // rather than asserted, for the reason `udp::run` gives its own
                // unreachable arm: a panic would take the connection down over
                // a request nobody can send.
                debug!(stream_id, "CONNECT request without :authority");
                tunnel::refuse(&mut stream, Status::BAD_REQUEST).await;
            }
        },
        Route::ConnectUdp => {
            udp::run(req, stream, context).await;
        }
        Route::UnsupportedProtocol(protocol) => {
            debug!(
                stream_id,
                // A token, cut by `bounded` and still escaped as a `str`, so
                // neither the token check nor the escaping is relied on alone.
                protocol = bounded(protocol).as_ref(),
                "unsupported :protocol"
            );
            tunnel::refuse(&mut stream, Status::NOT_IMPLEMENTED).await;
        }
        Route::NotConnect => {
            debug!(
                stream_id,
                method = %req.method,
                "not a CONNECT request; this server only proxies"
            );
            tunnel::refuse(&mut stream, Status::NOT_IMPLEMENTED).await;
        }
    }
}

/// Logs every inbound request at DEBUG, with credentials redacted.
///
/// This is the primary tool for establishing empirically what Surge actually
/// sends (which header it puts credentials in, which URI template it uses for
/// CONNECT-UDP), so every header *line* is logged. What is redacted is only the
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

    // Cut by `bounded` and escaped by `?`, as the 501 line in `route` does.
    let protocol = req.protocol.as_deref().map(bounded);

    // `:method` is a token and `:path` is pchar, `/` and `?` only, so `%`
    // cannot forge a line with either; `bounded` cuts their length, which the
    // peer chooses before it has authenticated.
    debug!(
        stream_id,
        method = %bounded(req.method.as_str()),
        path = %bounded(req.path.as_deref().unwrap_or_default()),
        authority = ?req.authority.as_deref(),
        scheme = ?req.scheme.as_deref(),
        protocol = ?protocol,
        headers = ?headers,
        "inbound request"
    );
}

/// Renders a credential header value as its scheme plus the size of the secret.
///
/// The length is kept because it is diagnostic ("Basic <redacted 0 bytes>" is a
/// client sending an empty credential, which looks nothing like a wrong
/// password), and because it reveals nothing a network observer could not count
/// for itself.
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

    /// A CONNECT request carrying the given fields.
    fn request_with(fields: &[(&str, &str)]) -> Request {
        let mut request = Request::new(h3api::Method::Connect);
        request.authority = Some("example.com:443".into());
        for (name, value) in fields {
            request.fields.append(
                *name,
                FieldValue::parse(value.as_bytes()).expect("field value"),
            );
        }
        request
    }

    /// A request with nothing wrong in its message is left to the later phases,
    /// credentials and all.
    #[test]
    fn an_ordinary_message_is_not_refused() {
        assert_eq!(refused_as_a_message(&request_with(&[])), None);
        assert_eq!(
            refused_as_a_message(&request_with(&[
                ("proxy-authorization", "Basic eA=="),
                ("authorization", "Basic eQ=="),
                ("user-agent", "surge"),
            ])),
            None,
            "one value per credential field is every value D3 answers for"
        );
    }

    /// Each connection-specific field is named in the refusal.
    #[test]
    fn a_connection_specific_field_is_refused_by_name() {
        for field in [
            "proxy-connection",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
        ] {
            assert_eq!(
                refused_as_a_message(&request_with(&[(field, "x")])),
                Some(MessageRefusal::ConnectionSpecificField(field)),
            );
        }
    }

    /// A third credential value is refused, and counted, whichever name it
    /// repeats.
    #[test]
    fn more_credential_values_than_allowed_are_refused() {
        let three = request_with(&[
            ("proxy-authorization", "Basic eA=="),
            ("proxy-authorization", "Basic eQ=="),
            ("authorization", "Basic ej0="),
        ]);
        assert_eq!(
            refused_as_a_message(&three),
            Some(MessageRefusal::TooManyCredentials(3))
        );
    }

    /// The field check is judged first, so a request failing both is refused
    /// for the field.
    #[test]
    fn the_field_check_comes_before_the_credential_count() {
        let both = request_with(&[
            ("authorization", "Basic eA=="),
            ("authorization", "Basic eQ=="),
            ("authorization", "Basic ej0="),
            ("upgrade", "h2c"),
        ]);
        assert_eq!(
            refused_as_a_message(&both),
            Some(MessageRefusal::ConnectionSpecificField("upgrade"))
        );
    }

    /// The request dump runs before the credentials check, so a peer that has
    /// not authenticated chooses how long its `:path` and `:method` are. Both
    /// are cut to what [`bounded`] keeps, like every other peer token a log line
    /// carries.
    #[test]
    fn the_request_dump_bounds_the_peer_path_and_method() {
        use std::sync::Mutex;

        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("buffer lock").extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let long_path = format!("/{}", "p".repeat(4096));
        let long_method = "M".repeat(4096);
        let mut request = Request::new(h3api::Method::Other(long_method.as_str().into()));
        request.path = Some(long_path.as_str().into());

        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter("debug")
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || log_request(&request, 0));

        let logged = String::from_utf8_lossy(&buffer.0.lock().expect("buffer lock")).into_owned();
        assert!(logged.contains("inbound request"), "{logged}");
        assert!(logged.contains(bounded(&long_path).as_ref()), "{logged}");
        assert!(logged.contains(bounded(&long_method).as_ref()), "{logged}");
        assert!(
            !logged.contains(&"p".repeat(64)),
            "an unbounded :path: {logged}"
        );
        assert!(
            !logged.contains(&"M".repeat(64)),
            "an unbounded :method: {logged}"
        );
    }

    /// A non-UTF-8 value cannot be split into scheme and secret, so all of it goes.
    #[test]
    fn a_non_utf8_value_is_redacted_whole() {
        let value = FieldValue::parse(&[0x42, 0x61, 0x73, 0x69, 0x63, 0x20, 0xff, 0xfe])
            .expect("field value");
        assert_eq!(redact_credentials(&value), "<redacted 8 bytes>");
    }
}
