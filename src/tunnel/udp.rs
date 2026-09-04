//! CONNECT-UDP tunnels (RFC 9298) over HTTP Datagrams (RFC 9297).
//!
//! # Shape of a session
//!
//! A CONNECT-UDP request opens a *session*: one request stream plus one
//! connected UDP socket. Unlike a TCP tunnel, the payload does not travel on the
//! request stream — it travels in QUIC DATAGRAM frames shared by every session
//! on the connection, each tagged with the Quarter Stream ID of its request
//! stream. So a session needs three things pumped at once:
//!
//! * inbound datagrams, delivered by the HTTP/3 connection's router through the
//!   channel this session claimed for its Quarter Stream ID;
//! * outbound packets read from the UDP socket;
//! * the request stream itself, which carries capsules and the close signal.
//!
//! # Deliberate asymmetries
//!
//! * The 2xx is sent **immediately** after the socket is ready (RFC 9298 §3.1):
//!   UDP has no handshake, so waiting for the target to answer would hang.
//! * Name resolution happens **before** the 2xx, so an unresolvable target is
//!   refused rather than becoming a silent black hole.
//! * The session is registered for datagram delivery **before** that resolution,
//!   so the packets a client is allowed to send optimistically (RFC 9298 §5) are
//!   buffered instead of dropped, and discarded with the session if the request
//!   is refused.
//! * An oversized outbound packet is **dropped**, never downgraded to a capsule
//!   (RFC 9298 §6.1).
//! * On the capsule fallback, a write to the client that does not complete
//!   within one idle timeout ends the session by **resetting** the request
//!   stream rather than finishing it — see `Session::forward_to_client`, which
//!   is also why the idle timeout covers only the wait for work and not the
//!   work.
//! * Closing the socket also closes the request stream, and vice versa
//!   (RFC 9298 §3.1) — a half-open UDP session has no meaning.

use std::sync::Arc;

use bytes::Bytes;
use percent_encoding::percent_decode_str;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::capsule::{self, Capsule, CapsuleDecoder};
use crate::datagram::{self, MAX_UDP_PAYLOAD};
use crate::h3api::{
    self, DatagramReceiver, FieldValue, Fields, Reader, Request, Status, Stream, Writer,
};
use crate::tunnel::{Context, Responded, Unreachable};
use crate::{net, tunnel};

/// Path prefix of the RFC 9298 §2 default URI template.
pub const WELL_KNOWN_PREFIX: &str = "/.well-known/masque/udp/";

/// The `:protocol` token that asks for a UDP tunnel (RFC 9298 §3).
///
/// Next to the template prefix because the two are the same RFC's wire syntax
/// for the same request, and [`super::route`] is the one place that reads it.
pub(super) const CONNECT_UDP: &str = "connect-udp";

/// Establishes a UDP tunnel for a `connect-udp` request and runs it.
pub async fn run(req: &Request, mut stream: Stream, stream_id: u64, ctx: Arc<Context>) {
    if let Err(reason) = validate(req) {
        debug!(stream_id, reason, "malformed connect-udp request");
        tunnel::refuse(&mut stream, Status::BAD_REQUEST).await;
        return;
    }

    let path = req.path.as_deref().unwrap_or_default();
    let (host, port) = match parse_target(path, req.query.as_deref()) {
        Ok(target) => target,
        Err(reason) => {
            debug!(stream_id, path, reason, "malformed connect-udp request");
            tunnel::refuse(&mut stream, Status::BAD_REQUEST).await;
            return;
        }
    };

    // The Quarter Stream ID follows from the stream id alone, so the session can
    // start collecting datagrams as soon as the request is known to be a
    // well-formed CONNECT-UDP one — before the resolver is asked anything.
    //
    // RFC 9298 §5: "A client MAY optimistically start sending UDP packets in
    // HTTP Datagrams before receiving the response to its UDP proxying request",
    // and a proxy receiving them early "SHALL either drop that HTTP Datagram
    // silently or buffer it temporarily (on the order of a round trip)".
    // Claiming here takes the second option: the packets land in the queue the
    // session is about to read from, so a client that opens a tunnel and sends
    // immediately does not lose its first packets to name resolution.
    //
    // Every refusal below returns, dropping the receiver and with it both the
    // queue and the claim — which is the discard the same paragraph calls for
    // when the request the datagrams were waiting on never succeeds.
    let quarter_stream_id = datagram::quarter_stream_id(stream_id);
    let Some(inbound) = stream.datagrams() else {
        // Unreachable: a request stream reaches exactly one tunnel, and this is
        // the only place that asks for its datagrams. Answered rather than
        // asserted, because a session that cannot receive anything is a broken
        // tunnel and 500 says so, where a panic would take the connection down.
        debug!(
            stream_id,
            "the datagrams of this stream are already claimed"
        );
        tunnel::refuse(&mut stream, Status::INTERNAL_SERVER_ERROR).await;
        return;
    };

    // Port policy, resolution and destination policy, in that order and with
    // every refusal already answered by the time this returns — see
    // [`tunnel::admit_target`]. RFC 9298 §3.1 is what puts it here rather than
    // after the 2xx: resolution must complete first, so a bad name is refused
    // instead of silently swallowing every packet. The 200-then-close path is
    // handed [`capsule_fields`] because that answer is a real successful
    // response to a CONNECT-UDP request, and the RFC 9297 `Capsule-Protocol`
    // field is what makes it one.
    //
    // Every path out of here that answers the request returns, dropping
    // `inbound` with it — which gives up the Quarter Stream ID and discards
    // whatever the client sent optimistically; the router then drops later
    // datagrams for that id silently, exactly as it does for a session that has
    // just closed.
    let Some(allowed) = tunnel::admit_target(&host, port, &ctx, &mut stream, capsule_fields).await
    else {
        return;
    };

    let socket = match bind_any(&allowed).await {
        Ok(socket) => socket,
        Err(failure) => {
            // As on the TCP path, the status follows from the RFC 9209 type
            // rather than collapsing every failure into one 502, and the answer
            // names the address that failed.
            debug!(
                stream_id,
                allowed = %crate::logfmt::addresses(&allowed),
                error = %failure.error,
                "failed to open target UDP socket"
            );
            tunnel::refuse_unreachable(&mut stream, &failure).await;
            return;
        }
    };

    // Bounded exactly as every refusal is, and for the reason
    // [`tunnel::respond`] gives: the session below does not exist until this
    // write returns, so nothing else would ever end the wait. On expiry the
    // stream has already been reset with H3_REQUEST_CANCELLED, and returning
    // here drops the socket and the Quarter Stream ID claim with it.
    let sent = tunnel::respond(
        &mut stream,
        Status::OK,
        capsule_fields(),
        "failed to send 200 for connect-udp",
    )
    .await;

    match sent {
        Responded::Sent => {}
        Responded::Failed => return,
        Responded::Expired => {
            debug!(
                stream_id,
                "gave up on a 200 for connect-udp the peer would not take"
            );
            return;
        }
    }

    let target = socket.peer_addr().ok();
    info!(
        stream_id,
        quarter_stream_id,
        host,
        port,
        target = %crate::logfmt::or_dash(target),
        // A snapshot, and named as one: a session raced ahead of the peer's
        // SETTINGS reads false here, while the send path re-reads the flag on
        // every packet and moves onto datagrams the moment they are allowed.
        datagrams_at_setup = ctx.datagrams_allowed(),
        "udp session established"
    );

    let (writer, reader) = stream.split();
    let mut session = Session {
        stream_id,
        quarter_stream_id,
        socket,
        inbound,
        reader,
        writer,
        decoder: CapsuleDecoder::new(),
        // Zero is the operator's way of switching the mitigation off, so it means
        // "uncapped" rather than "nothing may be sent".
        unanswered_budget: match ctx.unanswered_packet_budget {
            0 => None,
            budget => Some(budget),
        },
        oversize_drops: crate::logfmt::Sampler::new(),
        evictions: crate::logfmt::Sampler::new(),
        deadline: tokio::time::Instant::now() + ctx.stall_budget,
        ctx,
    };

    session.run().await;

    debug!(stream_id, quarter_stream_id, "udp session closed");
}

/// A running UDP session.
struct Session {
    /// The request stream's id, and the Quarter Stream ID that follows from it.
    ///
    /// Both are fixed for the life of the session and every line it writes
    /// names one or the other, so they are carried beside the halves of the
    /// stream rather than threaded through each method as an argument.
    stream_id: u64,
    quarter_stream_id: u64,
    socket: UdpSocket,
    /// Payloads the connection's router decoded for this session, and this
    /// session's claim on its Quarter Stream ID.
    inbound: DatagramReceiver,
    reader: Reader,
    writer: Writer,
    /// The request stream body is a capsule sequence (RFC 9297 §3.2).
    decoder: CapsuleDecoder,
    /// Packets still allowed towards a target that has never answered.
    ///
    /// RFC 9298 §7: until the target says something, this session might be an
    /// attempt to use the proxy as a reflector or a port scanner, so what it can
    /// emit is capped. `None` means uncapped — either the target has answered,
    /// which lifts the cap for good because the target has consented to the
    /// conversation, or the operator disabled the mitigation.
    ///
    /// This half is per session and is recreated by opening one, so it bounds a
    /// conversation and not a client. The connection's own total
    /// ([`Context::unanswered_connection_budget`]) is what a new session does
    /// not restore, and it is charged from here.
    unanswered_budget: Option<u32>,
    /// How many oversized drops this session has had, on a doubling schedule.
    ///
    /// The drops themselves are per packet and can arrive at line rate, so a
    /// line each would be the flood [`crate::logfmt::Sampler`] exists to stop;
    /// see [`oversize_verdict`]. One sampler per session, so a session cannot
    /// spend a quiet neighbour's allowance.
    oversize_drops: crate::logfmt::Sampler,
    /// How many send-buffer evictions this session has had, likewise.
    ///
    /// The same shape and the same reason as `oversize_drops`: see
    /// [`send_buffer_verdict`].
    evictions: crate::logfmt::Sampler,
    /// When this session becomes idle enough to close.
    ///
    /// Pushed out by [`Self::touch`] whenever a packet crosses the proxy, and
    /// by nothing else — see [`Self::run`] for why arrival alone must not
    /// count.
    deadline: tokio::time::Instant,
    ctx: Arc<Context>,
}

/// What a single step of the session loop decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Keep going.
    ///
    /// Deliberately not what re-arms the idle deadline: the steps that moved a
    /// packet call [`Session::touch`] themselves, so one that merely consumed
    /// bytes — a skipped capsule, a dropped packet — continues without buying
    /// the session time.
    Continue,
    /// The session is over; close the request stream tidily.
    Stop,
    /// The session is over and the request stream has **already been reset**.
    ///
    /// Distinct from [`Step::Stop`] because the tidy close would contradict the
    /// reset: telling the peer "no error" on a stream we just aborted leaves it
    /// to guess which signal to believe.
    Aborted,
}

/// Which of a session's three sources produced work, before it is handled.
///
/// Exists so the idle timeout can cover the *waiting* and nothing else; see
/// [`Session::run`].
enum Event {
    /// A payload the connection's datagram router decoded for this session, or
    /// `None` if it will send nothing further.
    Inbound(Option<Bytes>),
    /// A packet read from the target socket, or the error that ended it.
    Socket(std::io::Result<usize>),
    /// A chunk of the request stream's capsule sequence, its end, or its error.
    Stream(Result<Option<Bytes>, h3api::StreamError>),
}

/// Waits for `work`, unless the idle deadline has been reached already.
///
/// `None` is "this session is idle": the deadline is behind us, and whatever the
/// peer still has queued does not change that.
///
/// # Why the clock is read as well as awaited
///
/// `tokio::time::timeout_at` polls the future it wraps **first** and returns its
/// value without consulting the clock, so a lapsed deadline is only noticed on a
/// poll where the inner future was not already ready. Two of a session's three
/// sources are things a peer can keep ready for as long as it likes without a
/// single packet crossing the proxy — bytes that finish no capsule, and payloads
/// the unanswered-packet budget drops — and the second of those, sent fast
/// enough, kept the loop supplied so that the deadline was never measured at
/// all. Measured on a dev host: a 1 s timeout closed anywhere between on time
/// and 2.4 s late under one flooding sender, ran 9.3 s past its deadline under
/// four, and in one run of four had not closed at all when the test gave up at
/// 30 s. How far it ran was a matter of how long the queue stayed non-empty, so
/// a busy host was the worst case — and this is the only bound an authenticated
/// peer's session is under, since D76's covers connections that never
/// authenticated.
///
/// So the clock is read before each wait, which is D92's rule for the
/// connection's own silence deadline applied to the other absolute deadline in
/// this tree: a deadline paired with an inner future the peer can keep ready has
/// to be *read*, not only awaited. The cost is one `Instant::now()` per packet,
/// the same price D92 accepted there.
///
/// The timer arm decides as well, and may: `timeout_at` expires only once the
/// clock has passed `deadline`, so it is the same verdict as the read above
/// reached by the other road, with nothing else to weigh. That is where this
/// differs from D92's loop, which had to go back round because a second input —
/// the authentication flag — could have changed while it waited.
async fn before_deadline<T>(
    deadline: tokio::time::Instant,
    work: impl std::future::Future<Output = T>,
) -> Option<T> {
    if tokio::time::Instant::now() >= deadline {
        return None;
    }

    tokio::time::timeout_at(deadline, work).await.ok()
}

impl Session {
    /// Pumps the session until it closes, one direction at a time.
    async fn run(&mut self) {
        let stream_id = self.stream_id;

        // A UDP datagram can be at most this big, so one buffer serves forever.
        // It cannot be smaller: `UdpSocket::recv` truncates a longer packet
        // silently rather than reporting it, and the capsule fallback forwards
        // packets up to this size. The ~64 KiB is held for the life of the
        // session, and is one of the two per-session terms in the memory
        // product `docs/configuration.md` gives for `max_connections` x
        // `max_targets_per_conn`; the other is the inbound datagram queue,
        // `INBOUND_QUEUE_DEPTH` in `crate::h3::connection`.
        let mut packet = vec![0u8; MAX_UDP_PAYLOAD];

        loop {
            // The deadline covers *waiting for* one of the three sources and
            // nothing else: all three awaits below are cancel-safe
            // (`DatagramReceiver::recv`, `UdpSocket::recv` and the stream read
            // all resume where they left off), so an expiry here cannot lose
            // anything half-done.
            //
            // Handling the event is deliberately outside it. `forward_to_client`
            // writes to the request stream on the capsule path, and a write in
            // flight is exactly what must not be cancelled: the backend keeps a
            // partial DATA frame, which the tidy `finish()` below would then FIN
            // in the middle of a capsule. That branch bounds its own write
            // instead, and ends the session by resetting rather than finishing.
            //
            // A deadline rather than a per-wait timeout, because "idle" has to
            // mean "no packet crossed the proxy", not "no bytes arrived":
            // [`Self::touch`] pushes it out when a payload reaches the target
            // or the target answers, and nothing else does. A wait re-armed by
            // arrival alone would let a peer hold this session's socket,
            // buffers and tunnel slot for ever by dripping bytes that complete
            // nothing — one a second into a capsule that never finishes — and
            // an authenticated peer is under no other bound: D76's deadline
            // covers only connections that never authenticated.
            //
            // Waited on through [`before_deadline`] rather than `timeout_at`
            // alone, because two of the three sources are ones a peer can keep
            // ready for ever without moving a packet: see that function for why
            // the clock has to be read as well as awaited (D92).
            let sources = async {
                tokio::select! {
                    payload = self.inbound.recv() => Event::Inbound(payload),
                    received = self.socket.recv(&mut packet) => Event::Socket(received),
                    chunk = self.reader.recv_data() => Event::Stream(chunk),
                }
            };

            let Some(event) = before_deadline(self.deadline, sources).await else {
                debug!(
                    stream_id,
                    timeout_secs = self.ctx.stall_budget.as_secs(),
                    "udp session idle timeout"
                );
                break;
            };

            let step = match event {
                Event::Inbound(Some(payload)) => self.forward_to_target(payload).await,
                // Only reachable if the routing table lost this session's
                // entry, which nothing but dropping `inbound` can do.
                Event::Inbound(None) => Step::Stop,
                Event::Socket(Ok(length)) => self.forward_to_client(&packet[..length]).await,
                Event::Socket(Err(error)) => {
                    // ICMP errors surface here on a connected socket. RFC 9298
                    // §3.1: the request stream must be closed.
                    debug!(stream_id, %error, "target socket failed");
                    Step::Stop
                }
                Event::Stream(chunk) => self.handle_stream_chunk(chunk).await,
            };

            match step {
                Step::Continue => {}
                Step::Stop => break,
                // The stream carries its own error signal already; anything
                // added here would only muddy it. The socket still closes, with
                // `self`.
                Step::Aborted => return,
            }
        }

        // RFC 9298 §3.1: closing the UDP socket and closing the request stream
        // go together. The socket closes when `self` drops; the stream needs
        // saying explicitly.
        self.reader.stop_receiving(h3api::NO_ERROR);
        if let Err(error) = self.writer.finish() {
            debug!(stream_id, %error, "failed to finish the connect-udp stream");
        }
    }

    /// Pushes the idle deadline out by one timeout from now.
    ///
    /// Called exactly twice: when a payload reaches the target, and when the
    /// target answers. Bytes that produce neither — a capsule still being
    /// assembled or skipped, a packet dropped by a budget or a full queue —
    /// leave the deadline where it is, which is what makes the timeout a
    /// measure of the session doing its job rather than of the peer talking.
    ///
    /// The two directions are deliberately not symmetric about drops: a target
    /// packet counts on receipt, before the RFC 9298 §6.1 size check that may
    /// yet drop it, because a target answering at all is the target consenting
    /// to the conversation — while a client payload the unanswered budget
    /// drops counts for nothing, because the budget exists precisely to doubt
    /// that consent.
    fn touch(&mut self) {
        self.deadline = tokio::time::Instant::now() + self.ctx.stall_budget;
    }

    /// Forwards a payload received from the client to the target.
    async fn forward_to_target(&mut self, payload: Bytes) -> Step {
        // RFC 9298 §5: a context-0 payload larger than this cannot be a UDP
        // datagram, so the stream is aborted rather than truncating it.
        if payload.len() > MAX_UDP_PAYLOAD {
            warn!(
                quarter_stream_id = self.quarter_stream_id,
                length = payload.len(),
                "client sent an oversized UDP payload, aborting the session"
            );
            self.writer.reset(h3api::DATAGRAM_ERROR);
            return Step::Aborted;
        }

        // RFC 9298 §7. The packet is dropped rather than the session closed: a
        // legitimate flow whose target is merely slow to answer must be able to
        // recover once a reply arrives, and UDP loss is not an error condition.
        if let Some(remaining) = self.unanswered_budget.as_mut() {
            if *remaining == 0 {
                debug!(
                    quarter_stream_id = self.quarter_stream_id,
                    "unanswered packet budget exhausted, dropping outbound packet"
                );
                return Step::Continue;
            }

            // The connection's own total, which a new session does not restore
            // (`Context::unanswered_connection_budget`). Exhausting it ends this
            // session rather than muting it: a client that has spent the whole
            // connection's allowance on targets that never answered has said
            // what it is doing, and a muted session would hold a socket, a
            // routing entry and a stream until the idle timeout while the next
            // one costs it nothing to open.
            if !self.ctx.charge_unanswered() {
                match self.ctx.unanswered_closures.record() {
                    Some(closures) => warn!(
                        stream_id = self.stream_id,
                        quarter_stream_id = self.quarter_stream_id,
                        closures,
                        "the connection's unanswered packet budget is spent, closing this \
                         session; further closures on this connection are logged at debug \
                         level until the count doubles"
                    ),
                    None => debug!(
                        stream_id = self.stream_id,
                        quarter_stream_id = self.quarter_stream_id,
                        "the connection's unanswered packet budget is spent, closing this session"
                    ),
                }
                self.writer.reset(h3api::REQUEST_CANCELLED);
                return Step::Aborted;
            }

            *remaining -= 1;
        }

        match self.socket.send(&payload).await {
            Ok(_) => {
                // A payload crossed the proxy: the one direction of progress
                // this side of the session can make.
                self.touch();
                Step::Continue
            }
            Err(error) if is_per_packet_send_error(&error) => {
                debug!(
                    quarter_stream_id = self.quarter_stream_id,
                    length = payload.len(),
                    %error,
                    "target socket refused this packet, dropping it"
                );
                Step::Continue
            }
            Err(error) => {
                // The target is unreachable (ICMP) or the socket is broken.
                debug!(%error, "failed to send to the target");
                Step::Stop
            }
        }
    }

    /// The largest QUIC datagram this peer can be sent right now, if any.
    ///
    /// `None` is "there is no QUIC datagram path", not "the path is zero bytes
    /// wide": both the HTTP/3 setting and the QUIC transport parameter have to
    /// be there, and either one missing sends the session's replies to the
    /// capsule stream instead. quinn reports the transport half as `None` both
    /// when the peer sent no `max_datagram_frame_size` and when datagram support
    /// is off locally, which are the same answer for this purpose.
    fn datagram_limit(&self) -> Option<usize> {
        self.ctx
            .datagrams_allowed()
            .then(|| self.ctx.quic.max_datagram_size())
            .flatten()
    }

    /// Forwards a packet received from the target to the client.
    async fn forward_to_client(&mut self, packet: &[u8]) -> Step {
        let stream_id = self.stream_id;

        // The socket is connected, so anything arriving here really is from the
        // target: the conversation is two-way and the amplification cap is done.
        // A target that is answering is also the other direction of progress,
        // whatever becomes of this particular packet below.
        self.unanswered_budget = None;
        self.touch();

        let encoded_len = datagram::encoded_len(
            self.quarter_stream_id,
            datagram::CONTEXT_ID_UDP_PAYLOAD,
            packet.len(),
        );

        // Both halves of the datagram path have to be there, and they are
        // negotiated separately: `SETTINGS_H3_DATAGRAM` is the HTTP/3 one
        // (RFC 9297 §2.1.1), while `max_datagram_frame_size` is the QUIC
        // transport parameter that says how large a DATAGRAM frame the peer will
        // accept — `None` here meaning it sent none, so the peer cannot receive
        // a QUIC datagram at all (RFC 9221 §3). A peer that advertises the first
        // without the second is contradicting itself, but nothing in either RFC
        // makes that a protocol error, and treating the missing limit as a
        // limit of zero made every packet "too large" and the session a silent
        // no-op. There is no datagram path to bypass, so the capsule stream is
        // the correct channel rather than a downgrade.
        if let Some(limit) = self.datagram_limit() {
            // The QUIC datagram path. If the packet does not fit, it is dropped:
            // RFC 9298 §6.1 says SHOULD NOT fall back to a capsule, because
            // doing so silently converts a lossy flow into a head-of-line
            // blocked one.
            match oversize_verdict(encoded_len, limit, &self.oversize_drops) {
                Oversize::Fits => {}
                Oversize::DropAndReport(drops) => {
                    info!(
                        quarter_stream_id = self.quarter_stream_id,
                        encoded_len,
                        limit,
                        drops,
                        "target packet too large for a QUIC datagram, dropping; further \
                         drops on this session are logged at debug level until the count \
                         doubles"
                    );
                    return Step::Continue;
                }
                Oversize::DropQuietly => {
                    debug!(
                        quarter_stream_id = self.quarter_stream_id,
                        encoded_len, limit, "target packet too large for a QUIC datagram, dropping"
                    );
                    return Step::Continue;
                }
            }

            let encoded = datagram::encode_udp_payload(self.quarter_stream_id, packet);

            // quinn's `send_datagram` is `send(data, drop = true)`: when the
            // outgoing queue would grow past `datagram_send_buffer_size` it
            // silently drops the *oldest* queued datagrams to make room, saying
            // so only in its own `trace!`. The `Blocked` error that would
            // otherwise report it is `unreachable!()` on this path, so the
            // `debug!` below can never see this loss — the remaining space,
            // read before the send, is the only handle on it there is (D72).
            //
            // The packet still goes out unchanged: the eviction was decided by
            // how far behind the queue already is, and holding this packet back
            // would only trade a fresh datagram for a stale one. Visibility,
            // nothing more.
            //
            // Steady-state cost is one extra connection-lock acquisition per
            // outbound UDP packet, the same order as the one `send_datagram`
            // itself takes.
            let space = self.ctx.quic.datagram_send_buffer_space();
            let len = encoded.len();
            match send_buffer_verdict(len, space, &self.evictions) {
                SendBuffer::Room => {}
                SendBuffer::EvictsAndReport(evictions) => info!(
                    stream_id,
                    quarter_stream_id = self.quarter_stream_id,
                    space,
                    len,
                    evictions,
                    "QUIC datagram send buffer full, older datagrams evicted; further \
                     evictions on this session are logged at debug level until the count \
                     doubles"
                ),
                SendBuffer::EvictsQuietly => debug!(
                    stream_id,
                    quarter_stream_id = self.quarter_stream_id,
                    space,
                    len,
                    "QUIC datagram send buffer full, older datagrams evicted"
                ),
            }

            if let Err(error) = self.ctx.quic.send_datagram(encoded) {
                debug!(%error, "failed to send a QUIC datagram");
            }
            return Step::Continue;
        }

        // No datagram path: either the peer never advertised
        // SETTINGS_H3_DATAGRAM, which RFC 9297 §2.1.1 makes a prohibition rather
        // than a preference, or it never told QUIC what size of DATAGRAM frame
        // it accepts. Either way the request stream is the only way out. This is
        // not the same situation as the oversize case above: there a datagram
        // path exists and RFC 9298 §6.1 says not to bypass it, whereas here
        // there is none, so capsules are the correct channel.
        let encoded = capsule::encode_datagram(datagram::CONTEXT_ID_UDP_PAYLOAD, packet);

        // The one write in this session that can block for as long as the peer
        // likes: `send_data` applies the peer's flow control, so a client that
        // stops reading the stream parks it indefinitely. A write that has not
        // completed within a whole idle timeout is that client — the bound is
        // on the write finishing, not on progress inside it, the same reading
        // the TCP half-close bound gives the same knob.
        //
        // It cannot simply be abandoned. A cancelled send leaves a partial DATA
        // frame on the stream, and the tidy `finish()` the session otherwise
        // ends with would then FIN a truncated capsule — malformed by RFC 9297
        // §3.3. So the stream is reset instead, which says the same thing
        // without leaving a half-written frame behind.
        match tokio::time::timeout(self.ctx.stall_budget, self.writer.send_data(encoded)).await {
            Ok(Ok(())) => Step::Continue,
            Ok(Err(error)) => {
                debug!(%error, "failed to send a DATAGRAM capsule");
                Step::Stop
            }
            Err(_elapsed) => {
                debug!(
                    quarter_stream_id = self.quarter_stream_id,
                    timeout_secs = self.ctx.stall_budget.as_secs(),
                    "client stopped reading the capsule stream, resetting it"
                );
                self.writer.reset(h3api::REQUEST_CANCELLED);
                Step::Aborted
            }
        }
    }

    /// Handles bytes, EOF or an error on the request stream.
    ///
    /// The body is a capsule sequence. A DATAGRAM capsule carries a UDP payload
    /// the client chose to send reliably instead of in a QUIC datagram, and is
    /// forwarded exactly the same way.
    async fn handle_stream_chunk(
        &mut self,
        chunk: Result<Option<Bytes>, h3api::StreamError>,
    ) -> Step {
        let stream_id = self.stream_id;

        match chunk {
            Ok(Some(data)) => {
                self.decoder.push(&data);

                loop {
                    match self.decoder.next_capsule() {
                        Ok(Some(Capsule::Datagram {
                            context_id,
                            payload,
                        })) => {
                            if context_id != datagram::CONTEXT_ID_UDP_PAYLOAD {
                                // RFC 9298 §5, as for datagrams: drop silently.
                                debug!(
                                    stream_id,
                                    context_id, "dropping capsule with an unknown context id"
                                );
                                continue;
                            }
                            match self.forward_to_target(payload).await {
                                Step::Continue => {}
                                over => return over,
                            }
                        }
                        // More bytes needed.
                        Ok(None) => return Step::Continue,
                        Err(error) => {
                            // RFC 9297 §5.2 registers 0x33 as exactly this: a
                            // "Datagram or Capsule Protocol parse error".
                            debug!(stream_id, %error, "malformed capsule");
                            self.writer.reset(h3api::DATAGRAM_ERROR);
                            return Step::Aborted;
                        }
                    }
                }
            }
            // RFC 9298 §3.1: the client closing the stream ends the session.
            Ok(None) => {
                if self.decoder.at_capsule_boundary() {
                    debug!(stream_id, "client closed the connect-udp stream");
                    Step::Stop
                } else {
                    // RFC 9297 §3.3: a stream carrying capsules that "is
                    // terminated cleanly [...] and the last Capsule on the
                    // stream was truncated [...] MUST be treated as if it were a
                    // malformed or incomplete message", and the same section
                    // sends HTTP/3 to RFC 9114 §4.1.2, where a malformed message
                    // "MUST be treated as a stream error of type
                    // H3_MESSAGE_ERROR".
                    //
                    // Deliberately *not* the 0x33 used for the parse failures
                    // above, even though both arrive through the capsule
                    // decoder. 0x33 is registered as a "Datagram or Capsule
                    // Protocol parse error", and nothing failed to parse here:
                    // every capsule received was well formed, and the message
                    // simply ended somewhere other than a capsule boundary. The
                    // two codes cover different faults and this one is the
                    // message's, so the code the RFC names for a malformed
                    // message is the right one to send.
                    debug!(
                        stream_id,
                        error = %capsule::Error::Truncated,
                        "connect-udp stream ended mid-capsule"
                    );
                    self.writer.reset(h3api::MESSAGE_ERROR);
                    Step::Aborted
                }
            }
            Err(error) => {
                match h3api::peer_reset_code(&error) {
                    Some(code) => debug!(stream_id, code, "client reset the connect-udp stream"),
                    None => debug!(stream_id, %error, "connect-udp stream failed"),
                }
                Step::Stop
            }
        }
    }
}

/// What to do with a packet the target sent, on the QUIC datagram path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Oversize {
    /// Within the negotiated datagram size; send it unchanged.
    Fits,
    /// Too large, and a drop the schedule reports: worth an `info!`, carrying
    /// how many this session has had.
    DropAndReport(u64),
    /// Too large, and between reports: `debug!` only.
    DropQuietly,
}

/// Decides whether an outbound packet fits, and whether a drop is worth reporting.
///
/// The drop itself is not negotiable — RFC 9298 §6.1 rules out falling back to a
/// capsule, so an oversized packet is lost the way a UDP packet on a too-small
/// link would be. What is negotiable is how loudly it is said. At `debug!` it was
/// invisible in production, and the condition is not hypothetical: Surge
/// advertises `max_datagram_frame_size = 1300`, which a large EDNS0 or DNSSEC
/// answer and any QUIC-in-QUIC flow through the tunnel clear routinely. So the
/// drops the schedule picks are raised to `info!` — one line naming the length,
/// the limit and how many drops there have been, enough for an operator to
/// recognise what is happening and how hard — and the rest stay at `debug!`,
/// because these arrive per packet and a flood of one benign message is what
/// buries the warnings that matter.
///
/// [`crate::logfmt::Sampler`] is what picks them, on the doubling schedule this
/// crate bounds every peer-repeatable line with: the first drop of a session is
/// as immediate as it ever was, and the reports after it are 2, 4, 8 and so on
/// rather than silence. `drops` is the session's sampler and is advanced here,
/// which is the whole state this costs: no allocation, no lock, one atomic
/// increment on the forwarding path. A packet that fits leaves it untouched, so
/// the schedule counts real drops and nothing else.
fn oversize_verdict(encoded_len: usize, limit: usize, drops: &crate::logfmt::Sampler) -> Oversize {
    if encoded_len <= limit {
        return Oversize::Fits;
    }

    match drops.record() {
        Some(total) => Oversize::DropAndReport(total),
        None => Oversize::DropQuietly,
    }
}

/// Whether the outbound datagram queue still has room for a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendBuffer {
    /// Room for this datagram; nothing queued is lost.
    Room,
    /// No room, and a send the schedule reports: worth an `info!`, carrying how
    /// many this session has had.
    EvictsAndReport(u64),
    /// No room, and between reports: `debug!` only.
    EvictsQuietly,
}

/// Decides whether sending this datagram evicts older ones, and how loudly.
///
/// quinn queues outbound datagrams in a buffer of `datagram_send_buffer_size`
/// (1 MiB by default) and, on the path `send_datagram` takes, makes room for a
/// new one by discarding the oldest queued ones rather than by refusing the new
/// one or applying backpressure. That is the right trade for UDP — the fresh
/// packet is the useful one — but it happens entirely inside quinn, so a session
/// losing packets to a QUIC sender that has fallen a megabyte behind looks, from
/// every log this server writes, exactly like a session that is fine.
///
/// So the space is read before the send and the shortfall reported, on the same
/// terms as [`oversize_verdict`]: the session's [`crate::logfmt::Sampler`]
/// raises the 1st, 2nd, 4th and so on to `info!` and leaves the rest at
/// `debug!`, because evictions arrive per packet and a flood of one benign
/// message buries the warnings that matter. Nothing is dropped or delayed here —
/// the caller sends the packet either way.
///
/// Exactly-enough space is room, not an eviction. `datagram_send_buffer_space()`
/// is the limit minus what is queued minus one datagram's own overhead, which
/// makes `len <= space` quinn's own "this one fits" predicate written the other
/// way round — the same comparison that would return `Blocked` if the caller had
/// asked not to drop. A datagram larger than that is what puts the queue over
/// its limit, and quinn brings it back under by discarding from the front, on
/// this send or the next one; either way the loss is already decided by the time
/// anything here could react to it, which is why this function only grades how
/// loudly to say so.
fn send_buffer_verdict(len: usize, space: usize, evictions: &crate::logfmt::Sampler) -> SendBuffer {
    if len <= space {
        return SendBuffer::Room;
    }

    match evictions.record() {
        Some(total) => SendBuffer::EvictsAndReport(total),
        None => SendBuffer::EvictsQuietly,
    }
}

/// Whether a target-socket `send` failure affects only this packet.
///
/// RFC 9298 draws the line in two places. §3.1 requires the request stream to be
/// closed when "a UDP proxy is notified by its operating system that its socket
/// is no longer usable" — ECONNREFUSED from an ICMP port-unreachable is that
/// case. §5, on the other hand, says a proxy that "can only send out UDP packets
/// of a certain length due to its underlying link MTU [...] has no choice but to
/// discard incoming HTTP Datagrams" longer than that. Discard means discard: the
/// session survives.
///
/// The errors below are per-packet verdicts, not verdicts on the socket:
///
/// * `EMSGSIZE` — the direct consequence of the DF bit [`crate::net`] sets on
///   Linux (`IP_PMTUDISC_DO`), raised for every payload above the path MTU. This
///   is the one that matters in production: a client is entitled to send a 4 KiB
///   UDP packet, and tearing its tunnel down for it would be a bug the dev host
///   cannot reproduce, since macOS has no equivalent socket option.
/// * `EPERM` / `EACCES` — a local firewall rejecting individual packets.
/// * `ENOBUFS` — the kernel's send buffer momentarily full. The socket is
///   still usable, the shortage is local and transient, and dropping the
///   packet is exactly what the network would have done with it (D89's rule
///   in miniature: a local shortage is not a verdict on the peer).
///
/// Kept as a plain function over the OS error number because `std` maps none of
/// these onto a stable `ErrorKind`.
fn is_per_packet_send_error(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EMSGSIZE | libc::EPERM | libc::EACCES | libc::ENOBUFS)
    )
}

/// The response fields of a CONNECT-UDP 2xx.
///
/// RFC 9297 §3.4 says a response that uses the Capsule Protocol SHOULD carry
/// `Capsule-Protocol: ?1`, and §3.2 forbids Content-Length, Content-Type and
/// Transfer-Encoding on it, since the body is a capsule sequence rather than a
/// representation. Sending only the one field satisfies both.
fn capsule_fields() -> Fields {
    let mut fields = Fields::new();
    fields.append("capsule-protocol", FieldValue::from_static("?1"));
    fields
}

/// Opens a connected UDP socket to the first address that works.
///
/// As on the TCP path, the address of the last attempt travels with the error:
/// it is the hop an RFC 9209 `next-hop` parameter names.
///
/// Unlike the TCP path, this is not a failover: connecting a UDP socket only
/// asks the kernel for a route, so the first address with one wins and nothing
/// later can correct the choice. The family ordering applied at resolution
/// (decision D58) is therefore the whole of the decision here.
async fn bind_any(addresses: &[std::net::SocketAddr]) -> Result<UdpSocket, Unreachable> {
    let mut last = None;

    for address in addresses {
        match net::connected_udp_socket(*address).await {
            Ok(socket) => return Ok(socket),
            Err(error) => {
                debug!(%address, %error, "could not open a socket to the target");
                last = Some(Unreachable {
                    next_hop: Some(*address),
                    error,
                });
            }
        }
    }

    Err(last.unwrap_or_else(Unreachable::no_addresses))
}

/// Checks a CONNECT-UDP request against the rules that are about the message
/// rather than the target.
///
/// Two of them, both stated as requirements on the receiver:
///
/// * RFC 9298 §3.4 — "The :path and :scheme pseudo-header fields SHALL NOT be
///   empty", and "a UDP proxying request that does not conform to these
///   restrictions is malformed". RFC 9220 says the same in the other direction:
///   an extended CONNECT request must carry both. `:path` needs no check here
///   because [`parse_target`] already refuses anything that is not the template.
/// * RFC 9297 §3.2 — "The Capsule Protocol MUST NOT be used with messages that
///   contain Content-Length, Content-Type, or Transfer-Encoding header fields
///   [...] A receiver that observes a violation of these requirements MUST treat
///   the HTTP message as malformed." The body of this request stream is a
///   capsule sequence, so all three describe a framing that cannot exist here.
///
/// Two rules deliberately *not* enforced, both of which some proxies do enforce:
///
/// * the `:scheme` value is not required to be `https`. RFC 9298 derives it from
///   whatever URI template the client was configured with rather than fixing it,
///   and this server only ever listens under TLS, so the value decides nothing.
///   Rejecting `http` would be stricter than the specification for no gain.
/// * `Capsule-Protocol: ?0`, or a value that is not a Boolean, is not rejected.
///   RFC 9297 §3.4 says a non-Boolean value "MUST be handled as if the field
///   were not present" and that a false value "has the same semantics as when
///   the header is not present" — so the conformant reaction to both is to
///   ignore the field, which is what this server does by never reading it. The
///   field tells an *intermediary* that capsules are in flight; an endpoint that
///   knows the `connect-udp` upgrade token knows it already (RFC 9297 §3).
///
/// A violation is answered with 400 and a clean stream close rather than a
/// RESET_STREAM. RFC 9114 §4.1.2 allows a server to send a response before
/// closing the stream, and resetting instead would discard the buffered
/// response, leaving the client to guess why its tunnel was refused.
fn validate(req: &Request) -> Result<(), &'static str> {
    if req.scheme.as_deref().is_none_or(str::is_empty) {
        return Err("connect-udp requires a non-empty :scheme");
    }

    // Named one at a time so the log says which field was the problem.
    if req.fields.contains("content-length") {
        return Err("content-length is forbidden on a capsule stream");
    }
    if req.fields.contains("content-type") {
        return Err("content-type is forbidden on a capsule stream");
    }
    // Transfer-Encoding is the third field RFC 9297 §3.2 forbids here; it is
    // connection-specific under RFC 9114 §4.2 as well, and is refused for every
    // request before routing, so it never reaches this point.

    Ok(())
}

/// Parses the RFC 9298 §2 default URI template.
///
/// ```text
/// /.well-known/masque/udp/{target_host}/{target_port}/
/// ```
///
/// Parsing is deliberately lenient about the things clients disagree on — the
/// trailing slash is optional, and an IPv6 literal is accepted both in the
/// RFC 9298 §3 form (bare, only the colons escaped) and bracketed — while
/// staying strict about anything ambiguous. What comes out is a host, with the
/// brackets of the second form already off: [`crate::net::resolve`] resolves
/// names and literals, not URI components.
pub fn parse_target(path: &str, query: Option<&str>) -> Result<(String, u16), &'static str> {
    // A query string would make the URI something other than the template.
    if query.is_some_and(|query| !query.is_empty()) {
        return Err("the connect-udp template accepts no query");
    }

    let rest = path
        .strip_prefix(WELL_KNOWN_PREFIX)
        .ok_or("path is not the connect-udp template")?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);

    // Split before decoding: a percent-encoded slash inside a segment must not
    // create a segment boundary.
    let mut segments = rest.split('/');
    let host = segments.next().unwrap_or_default();
    let port = segments.next().ok_or("missing target_port")?;
    if segments.next().is_some() {
        return Err("too many path segments for the connect-udp template");
    }

    let host = percent_decode_str(host)
        .decode_utf8()
        .map_err(|_| "target_host is not valid UTF-8")?;
    if host.is_empty() {
        return Err("empty target_host");
    }

    // The brackets belong to this template and come off here. RFC 9298 §3
    // writes an IPv6 literal bare, with only its colons escaped, but some
    // clients send the bracketed form and it costs nothing to accept -- and
    // taking them off is this parser's job rather than the resolver's, which is
    // handed a host and not a piece of URI syntax.
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .filter(|literal| !literal.is_empty())
        .map(str::to_owned);
    let host = match unbracketed {
        Some(literal) => literal,
        None => host.into_owned(),
    };

    // A bracket that survived that pair is not part of any host, and is refused
    // here for the reason `tcp::split_authority` gives on the other route. The
    // two are the same malformation and now earn the same 400: until this,
    // `example.com%5D` went on to the resolver and came back a 502 dns_error.
    if host.contains(['[', ']']) {
        return Err("stray bracket in host");
    }

    let port = percent_decode_str(port)
        .decode_utf8()
        .map_err(|_| "target_port is not valid UTF-8")?;
    let port: u16 = port.parse().map_err(|_| "invalid target_port")?;
    if port == 0 {
        return Err("target_port must not be zero");
    }

    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn parse(path: &str) -> Result<(String, u16), &'static str> {
        parse_target(path, None)
    }

    // -----------------------------------------------------------------------
    // The idle deadline
    // -----------------------------------------------------------------------
    //
    // [`before_deadline`] is the whole of the session's idle bound: the loop
    // rebuilds its three sources on every pass and hands them here, so what this
    // decides is when a session ends. On a paused clock the answers are exact
    // rather than approximate, and the flood the deadline has to survive is a
    // future that is ready on every poll -- which is what a peer with another
    // packet always queued amounts to.

    /// A source the peer keeps ready must not carry a session past its deadline.
    ///
    /// The regression this exists for: `timeout_at` polls the future it wraps
    /// first and returns its value without consulting the clock, so a peer that
    /// always had another payload queued was never measured against the deadline
    /// at all. A thousand ready polls is a flood in miniature, and not one of
    /// them may buy the session a step.
    #[tokio::test(start_paused = true)]
    async fn a_source_that_is_always_ready_does_not_step_over_the_deadline() {
        let budget = Duration::from_secs(180);
        let deadline = tokio::time::Instant::now() + budget;

        // The deadline itself is already late enough -- the comparison is `>=`,
        // so a session does not get one more pass for landing exactly on it.
        tokio::time::advance(budget).await;

        for step in 0..1000 {
            assert_eq!(
                before_deadline(deadline, std::future::ready(())).await,
                None,
                "a peer with another packet always ready stepped over the deadline at {step}"
            );
        }
    }

    /// And a clock that jumps clean past the deadline lands on the same answer.
    ///
    /// The shape a paused VM resumes in, as on the TCP path: `Instant::now()` is
    /// hours beyond where the deadline was armed and every timer in the process
    /// fires at once. A session being flooded at that moment must still read the
    /// clock and stop, rather than keep serving what is queued.
    #[tokio::test(start_paused = true)]
    async fn a_clock_that_jumps_hours_ends_a_flooded_session() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(180);

        tokio::time::advance(Duration::from_secs(3 * 60 * 60)).await;

        assert_eq!(
            before_deadline(deadline, std::future::ready(())).await,
            None
        );
    }

    /// Work that arrives before the deadline is still served.
    ///
    /// The other half of the clock read, and the one that would turn a bound
    /// into a bug: a session with a millisecond left is a working session, and
    /// the packet in its queue belongs to the target, not to the floor.
    #[tokio::test(start_paused = true)]
    async fn work_that_beats_the_deadline_is_served() {
        let budget = Duration::from_secs(180);
        let deadline = tokio::time::Instant::now() + budget;

        tokio::time::advance(budget - Duration::from_millis(1)).await;

        assert_eq!(
            before_deadline(deadline, std::future::ready(7)).await,
            Some(7),
            "a session was cut a millisecond early"
        );
    }

    /// A silent session ends at its deadline, and not a millisecond before.
    ///
    /// Nothing is ready here, which is the ordinary case the timer serves: the
    /// wait is still unresolved a millisecond short of the budget, and over at
    /// the budget. Auto-advance carries the paused clock through both without a
    /// real millisecond passing.
    #[tokio::test(start_paused = true)]
    async fn a_silent_session_ends_at_its_deadline_and_not_before() {
        let budget = Duration::from_secs(180);
        let deadline = tokio::time::Instant::now() + budget;

        assert!(
            tokio::time::timeout(
                budget - Duration::from_millis(1),
                before_deadline(deadline, std::future::pending::<()>()),
            )
            .await
            .is_err(),
            "the idle bound expired early"
        );

        assert_eq!(
            before_deadline(deadline, std::future::pending::<()>()).await,
            None,
            "the idle bound did not expire at the deadline"
        );
    }

    #[test]
    fn parses_the_default_template() {
        assert_eq!(
            parse("/.well-known/masque/udp/192.0.2.1/53/"),
            Ok(("192.0.2.1".to_owned(), 53))
        );
    }

    #[test]
    fn the_trailing_slash_is_optional() {
        assert_eq!(
            parse("/.well-known/masque/udp/example.com/443"),
            Ok(("example.com".to_owned(), 443))
        );
        assert_eq!(
            parse("/.well-known/masque/udp/example.com/443/"),
            Ok(("example.com".to_owned(), 443))
        );
    }

    #[test]
    fn percent_encoded_hosts_are_decoded() {
        assert_eq!(
            parse("/.well-known/masque/udp/dns.example%2Ecom/53"),
            Ok(("dns.example.com".to_owned(), 53))
        );
    }

    /// RFC 9298 §3: an IPv6 literal appears with its colons escaped and no
    /// brackets.
    #[test]
    fn parses_bare_ipv6_literals() {
        assert_eq!(
            parse("/.well-known/masque/udp/2001%3Adb8%3A%3A1/53/"),
            Ok(("2001:db8::1".to_owned(), 53))
        );
    }

    /// A bracket anywhere but around the whole host is not part of a host.
    ///
    /// `tcp::split_authority` refuses the same shape on the other route, and the
    /// two must diagnose one malformed target the same way rather than one
    /// answering 400 and the other letting the resolver answer 502.
    #[test]
    fn rejects_a_stray_bracket_in_the_target_host() {
        assert!(parse("/.well-known/masque/udp/example.com%5D/53/").is_err());
        assert!(parse("/.well-known/masque/udp/example.com%5B/53/").is_err());
        assert!(parse("/.well-known/masque/udp/%5Bexample.com/53/").is_err());
        assert!(parse("/.well-known/masque/udp/exa%5Dmple.com/53/").is_err());
    }

    /// Not the standard form, but cheap to accept and some clients send it. The
    /// brackets are this template's syntax, so they come off with it.
    #[test]
    fn tolerates_bracketed_ipv6_literals() {
        assert_eq!(
            parse("/.well-known/masque/udp/%5B2001%3Adb8%3A%3A1%5D/53/"),
            Ok(("2001:db8::1".to_owned(), 53))
        );
    }

    #[test]
    fn rejects_a_foreign_path() {
        assert!(parse("/").is_err());
        assert!(parse("/.well-known/masque/ip/192.0.2.1/53/").is_err());
        assert!(parse("/masque/udp/192.0.2.1/53/").is_err());
    }

    #[test]
    fn rejects_a_missing_or_invalid_port() {
        assert!(parse("/.well-known/masque/udp/192.0.2.1").is_err());
        assert!(parse("/.well-known/masque/udp/192.0.2.1/").is_err());
        assert!(parse("/.well-known/masque/udp/192.0.2.1/0").is_err());
        assert!(parse("/.well-known/masque/udp/192.0.2.1/65536").is_err());
        assert!(parse("/.well-known/masque/udp/192.0.2.1/domain").is_err());
    }

    #[test]
    fn rejects_an_empty_host() {
        assert!(parse("/.well-known/masque/udp//53").is_err());
    }

    #[test]
    fn rejects_extra_segments() {
        assert!(parse("/.well-known/masque/udp/192.0.2.1/53/extra").is_err());
    }

    #[test]
    fn rejects_a_query_string() {
        assert!(parse_target("/.well-known/masque/udp/192.0.2.1/53/", Some("x=1")).is_err());
        // An empty query is indistinguishable from none.
        assert!(parse_target("/.well-known/masque/udp/192.0.2.1/53/", Some("")).is_ok());
    }

    /// A percent-encoded slash must stay inside its segment.
    #[test]
    fn an_encoded_slash_does_not_split_segments() {
        assert_eq!(
            parse("/.well-known/masque/udp/a%2Fb/53"),
            Ok(("a/b".to_owned(), 53))
        );
    }

    /// Builds a well-formed CONNECT-UDP request, which the caller then spoils.
    fn connect_udp_request() -> Request {
        let mut request = Request::new(crate::h3api::Method::Connect);
        request.scheme = Some("https".into());
        request.authority = Some("proxy.example".into());
        request.path = Some("/.well-known/masque/udp/192.0.2.1/53/".into());
        request.protocol = Some("connect-udp".into());
        request
    }

    #[test]
    fn accepts_a_well_formed_request() {
        assert_eq!(validate(&connect_udp_request()), Ok(()));
    }

    /// RFC 9298 §3.4: `:scheme` must be there and must not be empty. Only a
    /// hand-rolled client can get this wrong — a client library fills the field
    /// in — which is exactly why the server cannot assume it.
    #[test]
    fn rejects_a_request_without_a_scheme() {
        let mut request = connect_udp_request();
        request.scheme = None;
        assert!(validate(&request).is_err());

        request.scheme = Some("".into());
        assert!(validate(&request).is_err());
    }

    /// RFC 9298 §3.4 does not fix the scheme to `https`, so neither does this.
    #[test]
    fn accepts_any_non_empty_scheme() {
        let mut request = connect_udp_request();
        request.scheme = Some("http".into());

        assert_eq!(validate(&request), Ok(()));
    }

    /// RFC 9297 §3.2: none of these can describe the body of a capsule stream,
    /// and a receiver that sees one must treat the message as malformed.
    #[test]
    fn rejects_content_framing_headers() {
        for (name, value) in [
            ("content-length", "0"),
            ("content-length", "42"),
            ("content-type", "application/octet-stream"),
        ] {
            let mut request = connect_udp_request();
            request.fields.append(name, FieldValue::from_static(value));

            assert!(
                validate(&request).is_err(),
                "{name}: {value} must be refused"
            );
        }
    }

    /// The capsule protocol is in use because the upgrade token says so, so the
    /// header is advisory and none of its values change what happens here.
    #[test]
    fn the_capsule_protocol_header_is_never_a_reason_to_refuse() {
        for value in ["?1", "?0", "1", "not-a-boolean", ""] {
            let mut request = connect_udp_request();
            request.fields.append(
                "capsule-protocol",
                FieldValue::parse(value.as_bytes()).expect("field value"),
            );

            assert_eq!(validate(&request), Ok(()), "capsule-protocol: {value:?}");
        }

        // Absent entirely: only a SHOULD in RFC 9297 §3.4.
        assert_eq!(validate(&connect_udp_request()), Ok(()));
    }

    /// RFC 9298 §5: a payload the link cannot carry is discarded, not a reason
    /// to end the session.
    ///
    /// Tested as a pure function because the condition cannot be produced on
    /// loopback: `EMSGSIZE` needs the DF bit, which is a no-op on macOS, and a
    /// Linux loopback MTU is far larger than anything a test would send. The
    /// three codes below are POSIX and present in `libc` on both hosts.
    #[test]
    fn per_packet_send_errors_do_not_end_the_session() {
        for code in [libc::EMSGSIZE, libc::EPERM, libc::EACCES, libc::ENOBUFS] {
            let error = std::io::Error::from_raw_os_error(code);
            assert!(
                is_per_packet_send_error(&error),
                "errno {code} ({error}) must only cost one packet"
            );
        }
    }

    /// The other half of the rule: RFC 9298 §3.1 requires the request stream to
    /// be closed when the socket itself is reported unusable, which is what
    /// `ECONNREFUSED` from an ICMP port-unreachable means.
    #[test]
    fn socket_failures_still_end_the_session() {
        for code in [libc::ECONNREFUSED, libc::ENETUNREACH, libc::EHOSTUNREACH] {
            let error = std::io::Error::from_raw_os_error(code);
            assert!(
                !is_per_packet_send_error(&error),
                "errno {code} ({error}) must end the session"
            );
        }

        // An error with no OS number at all is not a per-packet verdict either.
        assert!(!is_per_packet_send_error(&std::io::Error::other(
            "synthetic"
        )));
    }

    /// What Surge advertises as `max_datagram_frame_size`, and therefore the
    /// limit the oversize path actually meets in production.
    const SURGE_MAX_DATAGRAM_FRAME_SIZE: usize = 1300;

    /// An `info!` on the doubling schedule, and the running total in it.
    ///
    /// RFC 9298 §6.1 fixes the behaviour — the packet is dropped, never downgraded
    /// to a capsule — so only its visibility is in question here. At `debug!`
    /// alone the condition could not be seen at all in production, and a line per
    /// dropped packet would be the flood D44 removed elsewhere.
    ///
    /// Eight drops, because the schedule is the assertion: reports land on the
    /// 1st, 2nd, 4th and 8th and on none of the others, and each says how many
    /// drops this session has had. Asserting the whole sequence at once rather
    /// than "the first one only" is what tells the schedule apart from the two
    /// mutations next to it — reporting always, and reporting on everything but
    /// the first.
    ///
    /// A pure function for the same reason as the errno rule above: a live session
    /// needs a real QUIC connection, while the decision being asserted lives
    /// entirely in the arithmetic and the sampler.
    #[test]
    fn oversize_drops_of_a_session_are_reported_on_a_doubling_schedule() {
        // A 4 KiB answer — an EDNS0/DNSSEC response is routinely this size.
        let oversize = datagram::encoded_len(9, datagram::CONTEXT_ID_UDP_PAYLOAD, 4096);
        assert!(oversize > SURGE_MAX_DATAGRAM_FRAME_SIZE);

        let drops = crate::logfmt::Sampler::new();
        let verdicts: Vec<Oversize> = (0..8)
            .map(|_| oversize_verdict(oversize, SURGE_MAX_DATAGRAM_FRAME_SIZE, &drops))
            .collect();

        assert_eq!(
            verdicts,
            vec![
                Oversize::DropAndReport(1),
                Oversize::DropAndReport(2),
                Oversize::DropQuietly,
                Oversize::DropAndReport(4),
                Oversize::DropQuietly,
                Oversize::DropQuietly,
                Oversize::DropQuietly,
                Oversize::DropAndReport(8),
            ],
            "an operator must be told at once that this is happening, and then how \
             far it has got -- without a line per dropped packet"
        );
    }

    /// The other half: an ordinary packet is sent untouched and does not advance
    /// the session's schedule.
    #[test]
    fn a_packet_within_the_limit_is_sent_and_costs_no_report() {
        let fits = datagram::encoded_len(9, datagram::CONTEXT_ID_UDP_PAYLOAD, 512);
        assert!(fits <= SURGE_MAX_DATAGRAM_FRAME_SIZE);

        let drops = crate::logfmt::Sampler::new();
        for _ in 0..3 {
            assert_eq!(
                oversize_verdict(fits, SURGE_MAX_DATAGRAM_FRAME_SIZE, &drops),
                Oversize::Fits
            );
        }
        assert_eq!(drops.seen(), 0, "a packet that fits is not a drop");

        // Exactly the limit still fits; one byte past it does not, and that is the
        // first drop of the session, so it is the first thing reported.
        assert_eq!(
            oversize_verdict(
                SURGE_MAX_DATAGRAM_FRAME_SIZE,
                SURGE_MAX_DATAGRAM_FRAME_SIZE,
                &drops
            ),
            Oversize::Fits
        );
        assert_eq!(
            oversize_verdict(
                SURGE_MAX_DATAGRAM_FRAME_SIZE + 1,
                SURGE_MAX_DATAGRAM_FRAME_SIZE,
                &drops
            ),
            Oversize::DropAndReport(1)
        );
    }

    /// The same doubling schedule for a queue that has fallen behind.
    ///
    /// Pure arithmetic and a sampler, like the oversize rule above, and asserted
    /// the same way: a live session would need a QUIC connection whose send queue
    /// is a megabyte behind, which is exactly the state no test can arrange.
    #[test]
    fn send_buffer_evictions_of_a_session_are_reported_on_a_doubling_schedule() {
        let evictions = crate::logfmt::Sampler::new();
        let verdicts: Vec<SendBuffer> = (0..8)
            .map(|_| send_buffer_verdict(1200, 0, &evictions))
            .collect();

        assert_eq!(
            verdicts,
            vec![
                SendBuffer::EvictsAndReport(1),
                SendBuffer::EvictsAndReport(2),
                SendBuffer::EvictsQuietly,
                SendBuffer::EvictsAndReport(4),
                SendBuffer::EvictsQuietly,
                SendBuffer::EvictsQuietly,
                SendBuffer::EvictsQuietly,
                SendBuffer::EvictsAndReport(8),
            ],
            "an operator must be told at once that queued datagrams are being \
             discarded, and then how many"
        );
    }

    /// The other half: room is room, and exactly enough of it is still room.
    #[test]
    fn a_datagram_the_queue_has_room_for_costs_no_report() {
        let evictions = crate::logfmt::Sampler::new();
        for _ in 0..3 {
            assert_eq!(
                send_buffer_verdict(1200, 1_048_576, &evictions),
                SendBuffer::Room
            );
        }
        assert_eq!(
            evictions.seen(),
            0,
            "a datagram that fits displaces nothing"
        );

        // The boundary quinn itself draws: `datagram_send_buffer_space()` has the
        // per-datagram overhead subtracted already, so a datagram of exactly that
        // many bytes is the last one that fits.
        assert_eq!(
            send_buffer_verdict(1200, 1200, &evictions),
            SendBuffer::Room
        );
        assert_eq!(
            send_buffer_verdict(1201, 1200, &evictions),
            SendBuffer::EvictsAndReport(1)
        );
    }
}
