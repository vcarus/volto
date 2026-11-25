//! CONNECT-UDP tunnels (RFC 9298) over HTTP Datagrams (RFC 9297).
//!
//! # Shape of a session
//!
//! A CONNECT-UDP request opens a *session*: one request stream plus one
//! connected UDP socket. Unlike a TCP tunnel, the payload does not travel on the
//! request stream. It travels in QUIC DATAGRAM frames shared by every session
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
//!   stream rather than finishing it. `Session::forward_to_client` says why,
//!   and that is also why the idle timeout covers only the wait for work and
//!   not the work.
//! * Closing the socket also closes the request stream, and vice versa
//!   (RFC 9298 §3.1). A half-open UDP session has no meaning.

use bytes::Bytes;
use percent_encoding::percent_decode_str;
use rustix::io::Errno;
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::capsule::{Capsule, CapsuleDecoder};
use crate::datagram::{self, MAX_UDP_PAYLOAD};
use crate::h3api::{
    self, DatagramReceiver, FieldValue, Fields, Reader, Request, Status, Stream, Writer,
};
use crate::tunnel::{Context, Unreachable};
use crate::{net, tunnel};

mod block;
mod path;

use block::PacketBlock;
pub use block::{RECV_BLOCK_SIZE, RECV_WINDOW};
use path::DatagramPath;

/// Path prefix of the RFC 9298 §2 default URI template.
pub const WELL_KNOWN_PREFIX: &str = "/.well-known/masque/udp/";

/// The `:protocol` token that asks for a UDP tunnel (RFC 9298 §3).
///
/// Next to the template prefix because the two are the same RFC's wire syntax
/// for the same request, and [`super::route`] is the one place that reads it.
pub(super) const CONNECT_UDP: &str = "connect-udp";

/// Establishes a UDP tunnel for a `connect-udp` request and runs it.
pub async fn run(req: &Request, mut stream: Stream, ctx: &Context) {
    let stream_id = stream.id();

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
    // well-formed CONNECT-UDP one, before the resolver is asked anything.
    //
    // RFC 9298 §5: "A client MAY optimistically start sending UDP packets in
    // HTTP Datagrams before receiving the response to its UDP proxying request.
    // However, implementers should note that such proxied packets may not be
    // processed by the UDP proxy if it responds to the request with a failure
    // [...]". The RFC does not require these packets to be kept. Keeping them
    // is this server's own choice: claiming here puts them in the queue the
    // session is about to read from, so a client that opens a tunnel and sends
    // immediately does not lose its first packets to name resolution. The same
    // section says "Receivers that buffer datagrams SHOULD apply buffering
    // limits", and the limit here is the depth of the queue the
    // `h3api::DatagramReceiver` reads (D99). Packets that arrived even before
    // this claim, while the request was being decoded and authenticated, were
    // held by the connection and are put in the queue by the claim, ahead of
    // later ones (`EARLY_DATAGRAMS`, D114).
    //
    // Every refusal below returns, dropping the receiver and with it both the
    // queue and the claim, so the packets of a request that fails are not
    // processed, as the sentence above allows.
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
    // every refusal already answered by the time this returns; see
    // [`tunnel::admit_target`]. RFC 9298 §3.1 puts it before the 2xx:
    // resolution must complete first, so a bad name is refused instead of
    // silently swallowing every packet. The 200-then-close path is handed
    // [`capsule_fields`] because that answer is a real successful response to a
    // CONNECT-UDP request, and the RFC 9297 `Capsule-Protocol` field is what
    // makes it one.
    //
    // Every path out of here that answers the request returns, dropping
    // `inbound` with it. That gives up the Quarter Stream ID and discards
    // whatever the client sent optimistically. The router then drops later
    // datagrams for that id silently, as it does for a session that has just
    // closed.
    let Some(allowed) = tunnel::admit_target(&host, port, ctx, &mut stream, capsule_fields).await
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

    // The peer's SETTINGS decide whether this session's packets go to the
    // client as QUIC datagrams or as capsules, and this request can be here
    // before the SETTINGS have been read: the control stream has a reader of
    // its own, and nothing orders the two tasks. A session set up in that
    // window would send its first answers as capsules to a peer that asked for
    // datagrams. So the session waits for the frame before it exists, within
    // the bound [`h3api::PeerSettings::read`] describes (D119). The wait is
    // over at once when the frame has been read, which is the usual case, or
    // when the bound has passed.
    //
    // Only a peer that can take a QUIC datagram at all is waited for: without
    // `max_datagram_frame_size` the capsule stream is the only way out,
    // whatever the SETTINGS say (see `Session::datagrams`).
    if !ctx.datagrams_allowed() && ctx.quic.max_datagram_size().is_some() {
        ctx.peer_settings.read().await;
    }

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
        "gave up on a 200 for connect-udp the peer would not take",
    )
    .await;
    if !sent {
        return;
    }

    let target = socket.peer_addr().ok();
    info!(
        log_id = "uemzs420",
        stream_id,
        quarter_stream_id,
        host,
        port,
        target = %crate::logfmt::or_dash(target),
        // A snapshot, and named as one: a session set up before the peer's
        // SETTINGS were read, which the wait above allows only once its bound
        // has passed, reads false here, while the send path re-reads the flag
        // on every packet and moves onto datagrams the moment they are
        // allowed.
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
        amplification: match ctx.unanswered.per_session() {
            0 => Amplification::Uncounted,
            budget => Amplification::Unanswered {
                remaining: budget,
                charged: 0,
            },
        },
        datagrams: ctx
            .quic
            .max_datagram_size()
            .map(|limit| DatagramPath::new(stream_id, quarter_stream_id, limit)),
        deadline: tokio::time::Instant::now() + ctx.stall_budget,
        ctx,
    };

    session.run().await;

    debug!(stream_id, quarter_stream_id, "udp session closed");
}

/// Where a UDP session stands against the RFC 9298 §7 amplification limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Amplification {
    /// Packets towards the target are not counted. The operator set
    /// `security.unanswered_packet_budget` to 0, or the target has answered.
    Uncounted,
    /// The target has not answered yet, so each packet towards it is counted.
    Unanswered {
        /// Packets this session may still send before the target answers.
        remaining: u32,
        /// Packets this session has charged to the connection's total so far.
        /// [`super::quota::Unanswered::refund`] returns them when the target first
        /// answers, so an answered session has cost the connection nothing.
        charged: u32,
    },
}

/// A running UDP session.
struct Session<'a> {
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
    /// Whether packets towards the target are still counted, and how many.
    ///
    /// RFC 9298 §7: until the target says something, this session might be an
    /// attempt to use the proxy as a reflector or a port scanner, so what it can
    /// emit is capped. [`Amplification::Uncounted`] means uncapped: either the
    /// target has answered, which lifts the cap for good because the target has
    /// consented to the conversation, or the operator disabled the mitigation.
    ///
    /// This half is per session; the connection's total, which a new session
    /// does not restore, is [`super::quota::Unanswered`]. It is charged from
    /// here and repaid through the `charged` count of
    /// [`Amplification::Unanswered`].
    amplification: Amplification,
    /// The QUIC datagram half of the target -> client direction, or `None`
    /// when the peer's transport parameters leave no QUIC datagram path.
    ///
    /// Asked once, when the session starts: quinn answers `None` exactly when
    /// the peer sent no `max_datagram_frame_size`, and the peer's transport
    /// parameters are fixed by the handshake, which is over before any request
    /// arrives. The HTTP/3 half, `SETTINGS_H3_DATAGRAM`, can still arrive after
    /// the session starts, which is why [`Context::datagrams_allowed`] is read
    /// for every packet.
    datagrams: Option<DatagramPath>,
    /// When this session becomes idle enough to close.
    ///
    /// Pushed out by [`Self::touch`] whenever a packet crosses the proxy, and
    /// by nothing else. [`Self::run`] says why arrival alone must not count.
    deadline: tokio::time::Instant,
    /// The connection state this session reads its budgets and its QUIC
    /// connection from.
    ///
    /// Borrowed rather than an `Arc` share: the session is built and awaited
    /// inside [`run`], which already holds the borrow, so it never outlives it.
    ctx: &'a Context,
}

/// What a single step of the session loop decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Keep going.
    ///
    /// Deliberately not what re-arms the idle deadline: the steps that moved a
    /// packet call [`Session::touch`] themselves, so one that only consumed
    /// bytes (a skipped capsule, a dropped packet) continues without extending
    /// the deadline.
    Continue,
    /// The session is over; close the request stream tidily.
    Stop,
    /// The session is over and the request stream has **already been reset**,
    /// with the code carried here.
    ///
    /// Distinct from [`Step::Stop`] because the tidy close would contradict the
    /// reset: telling the peer "no error" on a stream we just aborted leaves it
    /// to guess which signal to believe.
    ///
    /// The code travels with the verdict so that the STOP_SENDING sent on the
    /// way out can carry it too. Only [`Session::abort`] builds this value, and
    /// it resets the sending half with the code first, so the receiving half
    /// ends with the same one. Four of the five callers send the
    /// STOP_SENDING; the fifth is the stream ending mid-capsule, where the
    /// peer's FIN has already been read, so quinn has nothing left to stop and
    /// the call is a no-op.
    Aborted(h3api::Code),
}

/// How many events one wake of a session handles from the source that woke
/// it before the session waits again.
///
/// A burst runs from the wait's own event through what the same source already
/// has ready, and the wait comes back after at most this many. That bounds two
/// things. The other two sources are polled again at least once per this many
/// packets, so a target flooding the socket cannot keep the request stream or
/// the inbound queue from being read, and a flooding client cannot do it to
/// the socket. And the idle deadline is read on every wait, by
/// [`before_deadline`], so it is read at least once per this many packets,
/// which is D92's rule for a source the peer can keep ready: a burst of
/// payloads the unanswered budget drops moves no packet and still reaches the
/// clock. 32 spreads one wake over a burst of packets and keeps one wake to a
/// few hundred microseconds of work.
const BURST: usize = 32;

/// Whether a burst that has handled `handled` events, the last ending in
/// `step`, may take another.
///
/// Any step but [`Step::Continue`] ends it at once: the session is over.
fn burst_continues(handled: usize, step: Step) -> bool {
    step == Step::Continue && handled < BURST
}

/// A source a burst can take more from without waiting.
#[derive(Debug, Clone, Copy)]
enum Source {
    /// The inbound datagram queue.
    Inbound,
    /// The target socket.
    Socket,
}

/// Which of a session's three sources produced work, before it is handled.
///
/// Exists so the idle timeout can cover the *waiting* and nothing else; see
/// [`Session::run`].
enum Event {
    /// A payload the connection's datagram router decoded for this session, or
    /// `None` if it will send nothing further.
    Inbound(Option<Bytes>),
    /// A packet read from the target socket into the session's
    /// [`PacketBlock`], with its length, or the error that ended it.
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
/// single packet crossing the proxy: bytes that finish no capsule, and payloads
/// the unanswered-packet budget drops. The second of those, sent fast enough,
/// keeps the loop supplied so that the deadline is never measured (D92 records
/// how late it ran). This is the only bound an authenticated peer's session is
/// under, since D76's covers connections that never authenticated.
///
/// So the clock is read before each wait, which is D92's rule for the
/// connection's own silence deadline applied to the other absolute deadline in
/// this tree: a deadline paired with an inner future the peer can keep ready has
/// to be *read*, not only awaited. The cost is one `Instant::now()` per packet,
/// the same price D92 accepted there.
///
/// The timer arm may decide as well: `timeout_at` expires only once the clock
/// has passed `deadline`, so it reaches the same verdict as the read above,
/// with nothing else to weigh. D92's loop differs here: it has to go back round
/// because a second input, the authentication flag, could have changed while it
/// waited.
async fn before_deadline<T>(
    deadline: tokio::time::Instant,
    work: impl std::future::Future<Output = T>,
) -> Option<T> {
    if tokio::time::Instant::now() >= deadline {
        return None;
    }

    tokio::time::timeout_at(deadline, work).await.ok()
}

impl Session<'_> {
    /// Pumps the session until it closes, one direction at a time.
    async fn run(&mut self) {
        let stream_id = self.stream_id;

        // Each target packet lands behind room for its prefix in a block, so
        // both paths hand quinn a piece of the block rather than a copy. A
        // session leaves room for a capsule unless it can never send one: the
        // peer's SETTINGS_H3_DATAGRAM is never withdrawn once it has arrived,
        // and the transport parameter behind `datagrams` is fixed at the
        // handshake, so a session that starts on the datagram path stays on it.
        // Nothing is allocated until the target first sends; after that the
        // session holds one `RECV_BLOCK_SIZE` block, 16 KiB, across every wait.
        // That block is one of the per-session terms in the memory product
        // `docs/configuration.md` gives for `max_connections` x
        // `max_targets_per_conn`; the others are the inbound datagram queue the
        // `h3api::DatagramReceiver` reads, and the capsule decoder. See
        // [`RECV_BLOCK_SIZE`] for what pieces still in quinn's queue can add to
        // it.
        let mut packets = if self.datagrams.is_some() && self.ctx.datagrams_allowed() {
            PacketBlock::new(self.quarter_stream_id)
        } else {
            PacketBlock::with_capsule_room(self.quarter_stream_id)
        };

        loop {
            // The deadline covers *waiting for* one of the three sources and
            // nothing else: all three awaits below are cancel-safe
            // (`DatagramReceiver::recv`, the socket's `async_io` and the stream
            // read all resume where they left off), so an expiry here cannot
            // lose anything half-done. The socket's receive runs only once the
            // socket is ready, inside one poll, and the same `READABLE |
            // ERROR` interest `UdpSocket::recv` waits on is what wakes the
            // session for an ICMP error queued on the socket.
            //
            // Handling the event is deliberately outside it: the capsule write
            // in `forward_to_client` must not be cancelled, and bounds itself
            // (see there).
            //
            // A deadline rather than a per-wait timeout, because "idle" has to
            // mean "no packet crossed the proxy", not "no bytes arrived":
            // [`Self::touch`] pushes it out when a payload reaches the target
            // or the target answers, and nothing else does. A wait re-armed by
            // arrival alone would let a peer hold this session's socket,
            // buffers and tunnel slot for ever by sending bytes that complete
            // nothing, such as one byte a second into a capsule that never
            // finishes.
            //
            // Waited on through [`before_deadline`] rather than `timeout_at`
            // alone; see that function for why the clock has to be read as
            // well as awaited (D92).
            let sources = async {
                tokio::select! {
                    payload = self.inbound.recv() => Event::Inbound(payload),
                    received = self.socket.async_io(
                        Interest::READABLE | Interest::ERROR,
                        || packets.recv(&self.socket),
                    ) => Event::Socket(received),
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

            // What else the source that woke the session already has ready is
            // handled before the next wait, up to `BURST` events in all; see
            // there for the bound. Only payloads and packets: a stream chunk is
            // decoded whole by `handle_stream_chunk`, and the request stream's
            // reader already reads ahead.
            let source = match &event {
                Event::Inbound(Some(_)) => Some(Source::Inbound),
                Event::Socket(Ok(_)) => Some(Source::Socket),
                _ => None,
            };

            let mut step = self.handle(event, &mut packets).await;
            let mut handled = 1;
            while let Some(source) = source
                && burst_continues(handled, step)
            {
                let Some(event) = self.ready(source, &mut packets) else {
                    break;
                };
                step = self.handle(event, &mut packets).await;
                handled += 1;
            }

            match step {
                Step::Continue => {}
                Step::Stop => break,
                // The sending half has already been reset with `code`, and the
                // receiving half ends with the same one. Returning without
                // saying so does not leave the peer with nothing: dropping the
                // `Reader` makes quinn send STOP_SENDING with code 0, which RFC
                // 9114 §8.1 makes equivalent to H3_NO_ERROR, so the peer would
                // read a fault on one half and "no error" on the other. Both
                // halves carry the one code instead. The socket still closes,
                // with `self`.
                Step::Aborted(code) => {
                    self.reader.stop_receiving(code);
                    return;
                }
            }
        }

        // RFC 9298 §3.1: closing the UDP socket and closing the request stream
        // go together. The socket closes when `self` drops; the stream needs
        // saying explicitly.
        self.reader.stop_receiving(h3api::Code::H3_NO_ERROR);
        if let Err(error) = self.writer.finish() {
            debug!(stream_id, %error, "failed to finish the connect-udp stream");
        }
    }

    /// Handles one event from one of the three sources.
    ///
    /// Every rule that applies to a packet is applied here, one packet at a
    /// time, whether the event came from the wait or from a burst.
    async fn handle(&mut self, event: Event, packets: &mut PacketBlock) -> Step {
        match event {
            Event::Inbound(Some(payload)) => self.forward_to_target(payload).await,
            // Only reachable if the routing table lost this session's
            // entry, which nothing but dropping `inbound` can do.
            Event::Inbound(None) => Step::Stop,
            Event::Socket(Ok(_)) => self.forward_to_client(packets).await,
            Event::Socket(Err(error)) => {
                // ICMP errors surface here on a connected socket, and they
                // are not all the same thing. A socket the operating system
                // has given up on ends the session, which is RFC 9298 §3.1;
                // an error about one packet costs that packet, the same rule
                // the send side applies. See [`read_verdict`] for what was
                // measured.
                let verdict = read_verdict(&error);
                debug!(
                    stream_id = self.stream_id,
                    %error,
                    per_packet = verdict == Step::Continue,
                    "target socket failed"
                );
                verdict
            }
            Event::Stream(chunk) => self.handle_stream_chunk(chunk).await,
        }
    }

    /// The next event `source` has ready, without waiting, or `None` if it has
    /// nothing.
    ///
    /// The socket is read with `READABLE` alone. tokio's `try_io` compares its
    /// cached readiness with `Interest::mask`, and in tokio 1.54 that mask is
    /// empty for a combined interest such as `READABLE | ERROR`, so a combined
    /// interest would never read at all. An error the kernel returns from the
    /// read is graded as the wait grades it. An error with no readable packet
    /// behind it ends the burst, and the next wait, which does include
    /// `ERROR`, picks it up. The socket is read only while packets go out as
    /// QUIC datagrams: on the capsule fallback every packet is a write to the
    /// request stream that can wait for the client, and those are left one per
    /// wake.
    fn ready(&mut self, source: Source, packets: &mut PacketBlock) -> Option<Event> {
        match source {
            Source::Inbound => self
                .inbound
                .try_recv()
                .map(|payload| Event::Inbound(Some(payload))),
            Source::Socket => {
                if self.datagrams.is_none() || !self.ctx.datagrams_allowed() {
                    return None;
                }
                match self
                    .socket
                    .try_io(Interest::READABLE, || packets.recv(&self.socket))
                {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
                    received => Some(Event::Socket(received)),
                }
            }
        }
    }

    /// Resets the sending half with `code` and ends the session with
    /// [`Step::Aborted`] carrying the same code.
    fn abort(&mut self, code: h3api::Code) -> Step {
        self.writer.reset(code);
        Step::Aborted(code)
    }

    /// Pushes the idle deadline out by one timeout from now.
    ///
    /// Called from exactly two places: when a payload reaches the target, and
    /// when the target answers. Bytes that produce neither (a capsule still
    /// being assembled or skipped, a packet dropped by a budget or a full
    /// queue) leave the deadline where it is. So the timeout measures the
    /// session moving packets, not the peer sending bytes.
    ///
    /// The two directions are deliberately not symmetric about drops. A target
    /// packet counts on receipt, before the RFC 9298 §6.1 size check that may
    /// yet drop it, because a target answering at all is the target consenting
    /// to the conversation. A client payload the unanswered budget drops counts
    /// for nothing, because the budget exists to doubt that consent.
    fn touch(&mut self) {
        self.deadline = tokio::time::Instant::now() + self.ctx.stall_budget;
    }

    /// Forwards a payload received from the client to the target.
    async fn forward_to_target(&mut self, payload: Bytes) -> Step {
        // RFC 9298 §5: a context-0 payload larger than this cannot be a UDP
        // datagram, so the stream is aborted rather than truncating it.
        if payload.len() > MAX_UDP_PAYLOAD {
            warn!(
                log_id = "wh1im9zt",
                quarter_stream_id = self.quarter_stream_id,
                length = payload.len(),
                "client sent an oversized UDP payload, aborting the session"
            );
            return self.abort(h3api::Code::H3_DATAGRAM_ERROR);
        }

        // RFC 9298 §7. The packet is dropped rather than the session closed: a
        // legitimate flow whose target is merely slow to answer must be able to
        // recover once a reply arrives, and UDP loss is not an error condition.
        if let Amplification::Unanswered { remaining, charged } = &mut self.amplification {
            if *remaining == 0 {
                debug!(
                    quarter_stream_id = self.quarter_stream_id,
                    "unanswered packet budget exhausted, dropping outbound packet"
                );
                return Step::Continue;
            }

            // The connection's own total. Exhausting it ends this session
            // rather than muting it; `quota::Unanswered::charge` says why.
            if !self.ctx.unanswered.charge() {
                match self.ctx.unanswered_closures.record() {
                    Some(closures) => warn!(
                        log_id = "xc3zqhh7",
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
                return self.abort(h3api::Code::H3_REQUEST_CANCELLED);
            }

            *remaining -= 1;
            *charged += 1;
        }

        match self.socket.send(&payload).await {
            Ok(_) => {
                // A payload crossed the proxy: the one direction of progress
                // this side of the session can make.
                self.touch();
                Step::Continue
            }
            Err(error) if is_per_packet_error(&error) => {
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

    /// Forwards the packet in `packets` to the client.
    async fn forward_to_client(&mut self, packets: &mut PacketBlock) -> Step {
        // The socket is connected, so anything arriving here really is from the
        // target: the conversation is two-way and the amplification cap is done.
        // A target that is answering is also the other direction of progress,
        // whatever becomes of this particular packet below.
        // And it was not a silent target, so what this session spent of the
        // connection's total on the way to its first answer goes back, once.
        if let Amplification::Unanswered { charged, .. } =
            std::mem::replace(&mut self.amplification, Amplification::Uncounted)
        {
            self.ctx.unanswered.refund(charged);
        }
        self.touch();

        // Both halves of the datagram path have to be there, and they are
        // negotiated separately: `SETTINGS_H3_DATAGRAM` is the HTTP/3 one
        // (RFC 9297 §2.1.1), while `max_datagram_frame_size` is the QUIC
        // transport parameter that says how large a DATAGRAM frame the peer will
        // accept. `None` from quinn means it sent none, so the peer cannot
        // receive a QUIC datagram at all (RFC 9221 §3). A peer that advertises
        // the first without the second contradicts itself, but neither RFC
        // makes that a protocol error. Treating the missing limit as a limit of
        // zero would make every packet "too large" and the session a silent
        // no-op.
        if self.ctx.datagrams_allowed()
            && let Some(datagrams) = self.datagrams.as_mut()
        {
            datagrams.send(self.ctx, packets);
            return Step::Continue;
        }

        // No datagram path: either the peer never advertised
        // SETTINGS_H3_DATAGRAM, which RFC 9297 §2.1.1 makes a prohibition rather
        // than a preference, or it never told QUIC what size of DATAGRAM frame
        // it accepts. Either way the request stream is the only way out. This is
        // not the oversize case in `DatagramPath::send`: there a datagram path
        // exists and RFC 9298 §6.1 says not to bypass it, whereas here there is
        // none, so capsules are the correct channel rather than a downgrade.
        // The capsule header goes into the room in front of the packet, so the
        // frame is a piece of the block and the packet is not copied.
        let frame = packets.take_capsule();

        // The one write in this session that can block for as long as the peer
        // likes: `send_data_in_place` applies the peer's flow control, so a
        // client that stops reading the stream parks it indefinitely. A write
        // that has not completed within a whole idle timeout is treated as that
        // client. The bound is on the write finishing, not on progress inside
        // it, as with the TCP half-close bound that uses the same knob.
        //
        // It cannot simply be abandoned: `send_data_in_place` is not
        // cancel-safe, and its rustdoc carries the rule. The tidy `finish()`
        // this session otherwise ends with would FIN a truncated capsule,
        // malformed by RFC 9297 §3.3 as well. So the stream is reset instead.
        let sent = self.writer.send_data_in_place(frame);
        match tokio::time::timeout(self.ctx.stall_budget, sent).await {
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
                self.abort(h3api::Code::H3_REQUEST_CANCELLED)
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
                self.decoder.push(data);

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
                            return self.abort(h3api::Code::H3_DATAGRAM_ERROR);
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
                    // ended somewhere other than a capsule boundary. That is a
                    // fault of the message, so the code the RFC names for a
                    // malformed message is sent.
                    debug!(stream_id, "connect-udp stream ended mid-capsule");
                    self.abort(h3api::Code::H3_MESSAGE_ERROR)
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

/// What a failure of the target socket's *read* side costs.
///
/// Most errors arriving here are the operating system reporting the socket
/// unusable, which ends the session (RFC 9298 §3.1). Not all of them are: Linux
/// queues an ICMP-derived error on a connected socket and hands it to whichever
/// syscall comes next, which is `recv` whenever the session is waiting for the
/// target rather than forwarding to it.
///
/// On Linux, with the `IP_PMTUDISC_DO` that [`crate::net`] sets, an ICMP
/// fragmentation-needed answer to an oversized send makes the following `recv`
/// return **`EMSGSIZE`**, one of the errnos the send side forgives (D89
/// records the run). An ICMP port-unreachable arrives as `ECONNREFUSED`,
/// admin-prohibited as `EHOSTUNREACH` and net-prohibited as `ENETUNREACH`, all
/// verdicts on the socket that end the session. `EPERM` from a local firewall
/// rule is returned by `send` itself and never reaches a read.
///
/// So the two directions grade errors the same way, with
/// [`is_per_packet_error`] as the one rule. A read that is forgiven does **not**
/// call [`Session::touch`]: nothing crossed the proxy, so the session still ends
/// at its idle deadline if the target never answers. There is no loop to spin
/// in either, because the kernel clears a queued error when it is read and only
/// another packet of ours can produce the next one.
fn read_verdict(error: &std::io::Error) -> Step {
    if is_per_packet_error(error) {
        Step::Continue
    } else {
        Step::Stop
    }
}

/// Whether a target-socket failure affects only this packet.
///
/// RFC 9298 draws the line in two places. §3.1 requires the request stream to be
/// closed when "a UDP proxy is notified by its operating system that its socket
/// is no longer usable". ECONNREFUSED from an ICMP port-unreachable is that
/// case. §5, on the other hand, says a proxy that "can only send out UDP packets
/// of a certain length due to its underlying link MTU [...] has no choice but to
/// discard incoming HTTP Datagrams" longer than that. Discard means discard: the
/// session survives.
///
/// The errors below are per-packet verdicts, not verdicts on the socket:
///
/// * `EMSGSIZE`: the direct consequence of the DF bit [`crate::net`] sets on
///   Linux (`IP_PMTUDISC_DO`), raised for every payload above the path MTU. This
///   is the one that matters in production: a client is entitled to send a 4 KiB
///   UDP packet, and tearing its tunnel down for it would be a bug the dev host
///   cannot reproduce, since macOS has no equivalent socket option.
/// * `EPERM` / `EACCES`: a local firewall rejecting individual packets.
/// * `ENOBUFS`: the kernel's send buffer momentarily full. The socket is still
///   usable, the shortage is local and transient, and dropping the packet is
///   what the network would have done with it (D89: a local shortage is not a
///   verdict on the peer).
///
/// Kept as a plain function over the OS error number because `std` maps none of
/// these onto a stable `ErrorKind`.
fn is_per_packet_error(error: &std::io::Error) -> bool {
    matches!(
        Errno::from_io_error(error),
        Some(Errno::MSGSIZE | Errno::PERM | Errno::ACCESS | Errno::NOBUFS)
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
    tunnel::first_reachable(
        addresses,
        None,
        net::connected_udp_socket,
        "could not open a socket to the target",
    )
    .await
}

/// Checks a CONNECT-UDP request against the rules that are about the message
/// rather than the target.
///
/// Two of them, both stated as requirements on the receiver:
///
/// * RFC 9298 §3.4: "The :path and :scheme pseudo-header fields SHALL NOT be
///   empty", and "a UDP proxying request that does not conform to these
///   restrictions is malformed". RFC 9220 says the same in the other direction:
///   an extended CONNECT request must carry both. `:path` needs no check here
///   because [`parse_target`] already refuses anything that is not the template.
/// * RFC 9297 §3.2: "The Capsule Protocol MUST NOT be used with messages that
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
///   the header is not present". So the conformant reaction to both is to
///   ignore the field, which is what this server does by never reading it. The
///   field tells an *intermediary* that capsules are in flight; an endpoint that
///   knows the `connect-udp` upgrade token knows it already (RFC 9297 §3).
///
/// A violation is answered with 400 and a clean stream close rather than a
/// RESET_STREAM. RFC 9114 §4.1.2 allows a server to send a response before
/// closing the stream, and resetting instead would discard the buffered
/// response, leaving the client to guess why its tunnel was refused.
///
/// Hidden, and public for the reason `gate::judgement` is (D83): the `request`
/// fuzz target is outside this crate and has to be able to hand every request
/// `build_request` accepts to the judgement a real CONNECT-UDP gets. It is not
/// an entry point of its own; the socket path calls this same function.
#[doc(hidden)]
pub fn validate(req: &Request) -> Result<(), &'static str> {
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
/// Parsing is deliberately lenient about the things clients disagree on, and
/// strict about anything ambiguous. The trailing slash is optional, and an IPv6
/// literal is accepted both in the RFC 9298 §3 form (bare, only the colons
/// escaped) and bracketed. The host is judged by `tunnel::parse_host`, the
/// rule `tcp::split_authority` uses too, so the two routes give one host one
/// answer. What comes out is a host, with the brackets of the second form
/// already off: [`crate::net::ConnectionResolver::lookup`] resolves names and
/// literals, not URI components.
pub fn parse_target(path: &str, query: Option<&str>) -> Result<(String, u16), &'static str> {
    // A query string would make the URI something other than the template.
    if query.is_some_and(|query| !query.is_empty()) {
        return Err("the connect-udp template accepts no query");
    }

    let rest = path
        .strip_prefix(WELL_KNOWN_PREFIX)
        .ok_or("path is not the connect-udp template")?;
    let rest = rest.trim_suffix('/');

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

    // RFC 9298 §3.1: the proxy "decodes their percent-encoding", and what that
    // gives is judged by the rule the authority route uses
    // ([`tunnel::parse_host`]), which also takes off the brackets of the one
    // bracketed form it accepts.
    let host = tunnel::parse_host(&host)?.to_owned();

    let port = percent_decode_str(port)
        .decode_utf8()
        .map_err(|_| "target_port is not valid UTF-8")?;
    // RFC 9298 §3 writes `target_port = port`, which is RFC 3986 §3.2.3's
    // `*DIGIT`; the template is decoded first, so `%2B443` meets the same rule
    // as `+443` does. See [`tunnel::parse_port`].
    let port = tunnel::parse_port(&port)?;

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

    /// A burst takes at most `BURST` events, and ends at the first step that
    /// ends the session.
    ///
    /// The bound is what lets the other two sources and the idle deadline be
    /// read between bursts; the early end is what keeps a closed or aborted
    /// session from handling another packet.
    #[test]
    fn a_burst_is_bounded_and_ends_with_the_session() {
        // Counted over a range past the bound, so a burst with no bound fails
        // here rather than running for ever.
        let taken = (1..=4 * BURST)
            .take_while(|&handled| burst_continues(handled, Step::Continue))
            .count();
        assert_eq!(taken + 1, BURST, "a burst handles {BURST} events in all");
        assert!(!burst_continues(BURST, Step::Continue));

        for over in [Step::Stop, Step::Aborted(h3api::Code::H3_REQUEST_CANCELLED)] {
            assert!(
                !burst_continues(1, over),
                "{over:?} must end the burst after the event that produced it"
            );
        }
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

    /// RFC 9298 §3 writes `target_port = port`, which is RFC 3986 §3.2.3's
    /// `*DIGIT`, and `u16::from_str` accepts a leading sign on top of that. The
    /// percent-encoded spellings are here because this template is decoded
    /// before the number is read, so `%2B443` is the same request as `+443` and
    /// has to meet the same rule.
    #[test]
    fn rejects_a_port_that_is_not_digits() {
        for path in [
            "/.well-known/masque/udp/192.0.2.1/+443/",
            "/.well-known/masque/udp/192.0.2.1/-443/",
            "/.well-known/masque/udp/192.0.2.1/%2B443/",
            "/.well-known/masque/udp/192.0.2.1/%20443/",
            "/.well-known/masque/udp/192.0.2.1/443%20/",
        ] {
            assert!(parse(path).is_err(), "{path} must not be dialled");
        }
    }

    /// The authority route's rule for a port with a leading zero, and on the
    /// decoded segment, so `%30443` meets it as `0443` does.
    #[test]
    fn rejects_a_port_with_a_leading_zero() {
        for path in [
            "/.well-known/masque/udp/192.0.2.1/0443/",
            "/.well-known/masque/udp/192.0.2.1/00443/",
            "/.well-known/masque/udp/192.0.2.1/080/",
            "/.well-known/masque/udp/192.0.2.1/%30443/",
        ] {
            assert_eq!(
                parse(path),
                Err("port has a leading zero"),
                "{path} must not be dialled"
            );
        }
        assert_eq!(
            parse("/.well-known/masque/udp/192.0.2.1/0/"),
            Err("port must not be zero")
        );
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

    /// A percent-encoded slash must stay inside its segment. It then reaches
    /// the host rule as part of the host, which refuses it: a slash is not a
    /// reg-name character. A split at it would have refused the path for its
    /// segment count instead.
    #[test]
    fn an_encoded_slash_does_not_split_segments() {
        assert_eq!(
            parse("/.well-known/masque/udp/a%2Fb/53"),
            Err("host is not a registered name or an IP address")
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

    /// One rule for both directions: an error about one packet costs that
    /// packet, and an error about the socket ends the session.
    ///
    /// RFC 9298 §5: a payload the link cannot carry is discarded, not a reason
    /// to end the session. RFC 9298 §3.1 requires the request stream to be
    /// closed when the socket itself is reported unusable, which is what
    /// `ECONNREFUSED` from an ICMP port-unreachable means. The send side asks
    /// [`is_per_packet_error`] and the read side [`read_verdict`], which is
    /// that predicate mapped onto a step, so the verdicts below hold both. On
    /// Linux a queued ICMP error is handed to whichever syscall comes next, and
    /// `recv` is the one a session waiting on its target is parked in;
    /// [`read_verdict`] records the run that showed `EMSGSIZE` reaching a read.
    ///
    /// Tested as a pure function because the condition cannot be produced on
    /// loopback: `EMSGSIZE` needs the DF bit, which is a no-op on macOS, and a
    /// Linux loopback MTU is far larger than anything a test would send. The
    /// codes below are POSIX and defined on both hosts.
    #[test]
    fn a_per_packet_error_on_the_read_side_does_not_end_the_session() {
        for code in [Errno::MSGSIZE, Errno::PERM, Errno::ACCESS, Errno::NOBUFS] {
            let error = std::io::Error::from(code);
            assert_eq!(
                read_verdict(&error),
                Step::Continue,
                "errno {code} ({error}) must only cost one packet"
            );
        }

        for code in [Errno::CONNREFUSED, Errno::NETUNREACH, Errno::HOSTUNREACH] {
            let error = std::io::Error::from(code);
            assert_eq!(
                read_verdict(&error),
                Step::Stop,
                "errno {code} ({error}) is a verdict on the socket (RFC 9298 §3.1)"
            );
        }

        assert_eq!(
            read_verdict(&std::io::Error::other("synthetic")),
            Step::Stop,
            "an error with no OS number is not a per-packet verdict"
        );
    }
}
