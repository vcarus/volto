//! One server-side HTTP/3 connection: SETTINGS, the control stream, GOAWAY.
//!
//! # Shape
//!
//! A connection is three things:
//!
//! * the three unidirectional streams this endpoint opens and then holds open
//!   for its lifetime -- control, QPACK encoder, QPACK decoder;
//! * a background task that serves everything the peer sends outside its
//!   request streams: its unidirectional streams, its control stream, and its
//!   HTTP Datagrams;
//! * [`Connection::accept`], which hands request streams to the caller.
//!
//! The background task is what makes the peer's SETTINGS usable the moment they
//! arrive, and it is worth a paragraph because the alternative cost a release.
//! `h3` reads the control stream only while its accept future is being polled,
//! so a caller had to *sample* the answer -- and a CONNECT-UDP session started
//! from the same breath as the handshake read a stale "datagrams not allowed"
//! and stayed on the RFC 9297 capsule fallback, on a connection that opens one
//! tunnel and keeps it, for good. Here the control stream has a reader of its
//! own and the flag it writes is the very one the sessions hold
//! ([`Connection::peer_datagrams`]), so there is no moment at which the peer's
//! answer is known and not yet acted on, and nothing to poll.
//!
//! # HTTP Datagrams
//!
//! That same task routes the peer's HTTP Datagrams (RFC 9297), because what a
//! datagram names is a request stream: the first varint of its payload is a
//! Quarter Stream ID, which is a request stream's id divided by four. A session
//! claims one by asking its stream for a [`DatagramReceiver`]
//! ([`Stream::datagrams`](super::stream::Stream::datagrams)) and holds the
//! claim for exactly as long as it holds the receiver, so a stream that ends --
//! through any of the half-dozen paths a tunnel can end through -- takes its
//! routing entry with it and nothing has to remember to deregister it (D79).
//!
//! Only the receiving half is here. A datagram goes *out* on the
//! [`quinn::Connection`] itself, which the UDP sessions hold anyway for the
//! send-buffer and datagram-size questions they ask per packet, and which has
//! no HTTP/3 in it to consult.
//!
//! # How a connection error is signalled
//!
//! RFC 9114 §8 defines an HTTP/3 connection error as a QUIC CONNECTION_CLOSE
//! carrying the HTTP/3 error code, which is precisely
//! [`quinn::Connection::close`]. So that call *is* the mechanism: there is no
//! error to propagate between tasks, because closing the connection makes every
//! operation on it fail on its own. The only thing that has to travel is the
//! *reason*, which quinn overwrites with "closed locally" -- so it is recorded
//! on the way past and read back by [`Connection::accept`].

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tracing::debug;

use crate::datagram::{self, peek_varint, put_varint, varint_len};

use super::error::{Code, ConnectionError, StreamError, Violation};
use super::frame::{self, BufferBudget, Frame, FrameReader, Item};
use super::stream::Resolver;
use super::{VARINT_MAX_LEN, varint};

/// Control stream (RFC 9114 §6.2.1).
const STREAM_CONTROL: u64 = 0x00;
/// Push stream (RFC 9114 §6.2.2), which only a server may open.
const STREAM_PUSH: u64 = 0x01;
/// QPACK encoder stream (RFC 9204 §4.2).
const STREAM_QPACK_ENCODER: u64 = 0x02;
/// QPACK decoder stream (RFC 9204 §4.2).
const STREAM_QPACK_DECODER: u64 = 0x03;

/// The distance between consecutive client-initiated bidirectional stream ids.
///
/// RFC 9000 §2.1: the two least significant bits of a stream id encode its
/// initiator and directionality, so each kind of stream is numbered in fours.
const REQUEST_STREAM_STEP: u64 = 4;

/// Connection state that outlives any one stream or task.
#[derive(Default)]
pub(crate) struct Shared {
    /// Whether the peer's SETTINGS enabled HTTP Datagrams (RFC 9297 §2.1.1).
    ///
    /// Its own `Arc` because it is the one piece of connection state that
    /// leaves this layer: the sessions in `tunnel::udp` hold the same flag and
    /// read it per packet, so the moment the control stream reports it, every
    /// session on the connection is already looking at the new value.
    peer_datagrams: Arc<AtomicBool>,
    /// What this connection may hold in half-received frames at once (D77).
    ///
    /// Its own `Arc` for the same reason `peer_datagrams` has one: it is held
    /// by things that outlive no single scope. Every request stream's
    /// [`FrameReader`] draws on this one, which is what makes the bound a
    /// property of the connection rather than of each stream separately. The
    /// peer's control stream is the one reader that does not: see
    /// [`BufferBudget::unshared`].
    buffered: Arc<BufferBudget>,
    /// Where an inbound HTTP Datagram goes, keyed by Quarter Stream ID.
    ///
    /// The whole of the connection's datagram routing: an entry is a live
    /// session's claim on one Quarter Stream ID, put there by
    /// [`Self::register_datagrams`] and taken out again when the
    /// [`DatagramReceiver`] it belongs to is dropped. A request stream that
    /// never asks -- every TCP tunnel -- never appears here at all.
    sessions: Mutex<HashMap<u64, mpsc::Sender<Bytes>>>,
    /// Why this endpoint closed the connection, if it did.
    local_error: OnceLock<Violation>,
    /// Whether a control stream has already been accepted (RFC 9114 §6.2.1).
    control_seen: AtomicBool,
    /// Whether a QPACK encoder stream has already been accepted.
    encoder_seen: AtomicBool,
    /// Whether a QPACK decoder stream has already been accepted.
    decoder_seen: AtomicBool,
    /// Inbound HTTP Datagrams dropped instead of delivered, all three ways at
    /// once: an unknown Context ID, a Quarter Stream ID no session claims, and
    /// a session whose inbound queue was full.
    ///
    /// The drops themselves are the silence RFC 9298 §5 and RFC 9297 §2.1 ask
    /// for, so this counter is the only production-visible trace they leave —
    /// it is read once, by the closing line in [`crate::quic`], which is
    /// written after this struct is gone. Hence the `Arc`: injected by
    /// [`Connection::handshake`]'s caller so the count outlives the
    /// connection, for the same reason that line's `tunnels` counter is
    /// created outside it.
    dropped_datagrams: Arc<AtomicU64>,
    /// How often each way of dropping has been reported, on a doubling
    /// schedule.
    ///
    /// Drops arrive at whatever rate the peer sends, so a line per drop would
    /// be log amplification under a debug subscriber and a formatting cost on
    /// the routing task either way. [`crate::logfmt::Sampler`] is the whole of
    /// this crate's answer to that question, so these use it rather than a
    /// flag of their own: the first drop of each shape names it as immediately
    /// as it ever did, and the reports that follow say how far the count has
    /// got without one line per packet. Four samplers rather than one because
    /// the shapes have different diagnoses — an extension this server does not
    /// speak, a session racing its own close (or a misdirected flood), a
    /// target not draining, and a datagram cut short of its Context ID — and
    /// each should be able to double at its own rate.
    ///
    /// The closing line's `dropped_datagrams` is still the total across all
    /// four; these bound the running commentary, not the count.
    unknown_context_drops: crate::logfmt::Sampler,
    unroutable_drops: crate::logfmt::Sampler,
    queue_full_drops: crate::logfmt::Sampler,
    malformed_drops: crate::logfmt::Sampler,
}

/// Which way an inbound HTTP Datagram was dropped, and so which of [`Shared`]'s
/// four samplers keeps its schedule.
///
/// Naming the shape rather than handing [`Shared::count_drop`] one of its own
/// fields keeps the choice of sampler in one place, and lets the compiler say
/// so when a fifth shape appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropKind {
    /// A Context ID this server has no extension for (RFC 9298 §5).
    UnknownContext,
    /// A Quarter Stream ID no session claims.
    Unroutable,
    /// A session whose inbound queue was full.
    QueueFull,
    /// A datagram cut short of its Context ID.
    Malformed,
}

impl Shared {
    /// Records why this endpoint is closing the connection, keeping the first
    /// reason, and reports the one that was kept.
    ///
    /// The return value is what the CONNECTION_CLOSE must carry. Two tasks can
    /// find a violation at the same moment -- the control stream reader and a
    /// request stream, say -- and only one of them wins the `OnceLock`; closing
    /// with the loser's code would then contradict the reason
    /// [`Connection::accept`] goes on to report.
    fn record(&self, violation: Violation) -> Violation {
        self.local_error.get_or_init(|| violation).clone()
    }

    /// Claims `quarter_stream_id` for a session, or reports that it is taken.
    ///
    /// `None` means an entry already exists, which is a caller asking twice for
    /// one stream: the receiver was handed out once and a second one would
    /// deregister the first on drop. The map is the guard, so there is no
    /// separate flag to keep in step with it.
    fn register_datagrams(self: &Arc<Self>, quarter_stream_id: u64) -> Option<DatagramReceiver> {
        let (sink, inbound) = mpsc::channel(INBOUND_QUEUE_DEPTH);

        match self.lock().entry(quarter_stream_id) {
            Entry::Occupied(_) => return None,
            Entry::Vacant(slot) => slot.insert(sink),
        };

        Some(DatagramReceiver {
            shared: Arc::clone(self),
            quarter_stream_id,
            inbound,
        })
    }

    /// Hands one decoded datagram to the session that claimed its Quarter
    /// Stream ID, or drops it.
    ///
    /// Every outcome here is a drop rather than an error. RFC 9297 §2.1's two
    /// MUST-close conditions are about the Quarter Stream ID *field* and are
    /// settled before this is reached, by [`crate::datagram::decode`]; what is
    /// left is a well-formed datagram with nowhere to go, which happens
    /// routinely when a session closes with packets still in flight.
    fn deliver(&self, decoded: datagram::Datagram) {
        if decoded.context_id != datagram::CONTEXT_ID_UDP_PAYLOAD {
            //= https://www.rfc-editor.org/rfc/rfc9298#section-5
            //# If an HTTP/3 Datagram that carries an unknown Context ID is
            //# received, the receiver SHALL either drop that datagram silently
            //# or buffer it temporarily (on the order of a round trip) while
            //# awaiting the registration of the corresponding Context ID.
            //
            // Two ways to comply and this is the first: we drop. RFC 9298 §4
            // reserves Context ID 0 for UDP payloads and leaves every non-zero
            // one to a future extension, and this proxy implements none, so
            // buffering would be holding packets for a registration that has no
            // way to arrive.
            self.count_drop(DropKind::UnknownContext, |drops| {
                debug!(
                    quarter_stream_id = decoded.quarter_stream_id,
                    context_id = decoded.context_id,
                    drops,
                    "dropping datagrams with an unknown context id; further ones are \
                     logged as the count doubles"
                )
            });
            return;
        }

        // One map operation under the lock, `try_send` included: it never
        // waits, and sending inside the guard spares the routing task a sender
        // clone -- two refcount bumps -- on every datagram it routes.
        let delivered = self
            .lock()
            .get(&decoded.quarter_stream_id)
            .map(|inbound| inbound.try_send(decoded.payload).is_ok());

        match delivered {
            Some(true) => {}
            None => self.count_drop(DropKind::Unroutable, |drops| {
                debug!(
                    quarter_stream_id = decoded.quarter_stream_id,
                    drops,
                    "dropping datagrams for sessions that do not exist; further ones are \
                     logged as the count doubles"
                )
            }),
            // Never block the router on one slow session: dropping a UDP
            // packet is legitimate, stalling every other session is not.
            Some(false) => self.count_drop(DropKind::QueueFull, |drops| {
                debug!(
                    quarter_stream_id = decoded.quarter_stream_id,
                    drops,
                    "dropping datagrams a session's full queue cannot take; further ones \
                     are logged as the count doubles"
                )
            }),
        }
    }

    /// Counts one dropped datagram, and lets its shape say so on the doubling
    /// schedule.
    ///
    /// The count is for the closing line in [`crate::quic`]; the reports are
    /// for whoever is reading a debug log while it happens, and each carries
    /// the running total of its own shape so a report says how far this has
    /// got rather than only that it started. Everything is `Relaxed` because
    /// nothing is published through either atomic: each is a single
    /// read-modify-write ordered against nothing else.
    fn count_drop(&self, kind: DropKind, report: impl FnOnce(u64)) {
        let sampler = match kind {
            DropKind::UnknownContext => &self.unknown_context_drops,
            DropKind::Unroutable => &self.unroutable_drops,
            DropKind::QueueFull => &self.queue_full_drops,
            DropKind::Malformed => &self.malformed_drops,
        };
        if let Some(drops) = sampler.record() {
            report(drops);
        }
        self.dropped_datagrams.fetch_add(1, Ordering::Relaxed);
    }

    /// The routing table, with a poisoned lock treated as an ordinary one.
    ///
    /// Nothing under it can be left half-updated: every use is a single map
    /// operation, so a panic elsewhere in the process says nothing about the
    /// state of this map.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, mpsc::Sender<Bytes>>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Inbound datagrams buffered per session before packets start being dropped.
///
/// Bounded on purpose: UDP allows loss, whereas an unbounded queue would let a
/// slow target turn into unbounded memory growth. The same queue serves both
/// phases of a session — the one before the target socket exists, where it holds
/// what RFC 9298 §5 calls optimistically sent packets, and the running one — so
/// this constant is the whole per-session bound rather than one of two.
///
/// # What this costs at the configured limits
///
/// A session holds three buffers, and this constant sizes only the first of
/// them.
///
/// The queue is `depth x payload`. Only the payload needs care: a QUIC DATAGRAM
/// frame cannot be fragmented, so a datagram never exceeds the
/// `max_udp_payload_size` this server advertises (quinn's default, 1472 bytes)
/// even though RFC 9298 §5 permits a 65527-byte UDP payload in principle. At
/// `INBOUND_QUEUE_DEPTH` = 64 that is ~92 KiB.
///
/// The second is the buffer a running session reads its *target* socket into
/// ([`crate::tunnel`]'s UDP path), one per session and sized for the largest UDP
/// payload there can be — the whole 65527 bytes, ~64 KiB — because a packet that
/// has arrived must fit somewhere before its length is known. Unlike the queue it
/// exists only once the session loop is running, so a session refused before its
/// socket is bound never allocates one.
///
/// The third is the [`crate::capsule::CapsuleDecoder`] on the request stream,
/// which buffers a DATAGRAM capsule's value until all of it has arrived —
/// [`crate::capsule::MAX_DATAGRAM_CAPSULE_VALUE`] bounds it, and a peer that
/// declares that much and stops one byte short holds it for the session's idle
/// timeout. Measured at ~78 KiB, since the `BytesMut` behind it doubles its way
/// to 64 KiB rather than landing on it
/// (`tests/it_bounds.rs::a_session_holds_one_unfinished_capsule_and_no_more`).
///
/// A session therefore costs ~236 KiB, and the worst case is that times
/// `max_targets_per_conn` times `max_connections`. With the shipped defaults
/// (`max_targets_per_conn` = 256, `max_connections` = 256) that is ~59 MiB per
/// connection and ~14.7 GiB across a server saturated at both limits — an
/// operator lowering either limit lowers it proportionally.
///
/// All three are released by dropping what owns them rather than by any explicit
/// call, on whichever of the half-dozen paths a session ends by;
/// `tests/it_bounds.rs::a_connection_keeps_nothing_for_the_sessions_it_has_closed`
/// is where that composition is weighed rather than reasoned about.
///
/// Registering a session before its target socket exists does **not** raise that
/// ceiling: the queue is the same size in both phases, sessions are still capped
/// by the per-connection tunnel quota, and a full queue is already reachable on a
/// running session whenever a client sends faster than the proxy forwards. What
/// it changes is how long a full queue can sit undrained — no longer than name
/// resolution takes, after which the session either starts draining or is refused
/// and the queue is discarded with it.
pub const INBOUND_QUEUE_DEPTH: usize = 64;

/// One session's inbound HTTP Datagrams, and its claim on a Quarter Stream ID.
///
/// Obtained from [`Stream::datagrams`](super::stream::Stream::datagrams) and
/// held for the life of the session. Dropping it takes the Quarter Stream ID
/// out of the connection's routing table, which is what keeps the table from
/// leaking entries: a session can end through any of half a dozen paths --
/// refused before it started, idle, reset, its socket broken -- and every one of
/// them drops this.
///
/// Datagrams that arrive after the drop are dropped like any other unknown id,
/// which is exactly what RFC 9297 §2.1 permits for a stream that no longer
/// exists.
pub struct DatagramReceiver {
    shared: Arc<Shared>,
    quarter_stream_id: u64,
    inbound: mpsc::Receiver<Bytes>,
}

impl DatagramReceiver {
    /// Waits for the next payload routed to this session.
    ///
    /// `None` means the connection's router will send nothing further, which on
    /// a live connection cannot happen: the sending half lives in the routing
    /// table under this receiver's own entry, and that entry outlives the
    /// receiver by nothing at all.
    ///
    /// Cancel-safe ([`tokio::sync::mpsc::Receiver::recv`] is), so a session may
    /// poll it inside a `select!` with a timeout -- which is what a UDP session
    /// does with all three of its sources.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.inbound.recv().await
    }
}

impl Drop for DatagramReceiver {
    fn drop(&mut self) {
        self.shared.lock().remove(&self.quarter_stream_id);
    }
}

/// A cheap handle to the connection, held by every stream and task on it.
///
/// Cloning is two refcount bumps: `quinn::Connection` is itself a handle.
#[derive(Clone)]
pub(crate) struct Handle {
    /// The QUIC connection underneath.
    pub(crate) quic: quinn::Connection,
    /// The connection's idle timeout, as [`Connection::handshake`] was given it.
    ///
    /// Carried because it is the only clock this layer has for the waits that
    /// nothing else bounds: `crate::quic` owns the transport parameter and
    /// quinn's own idle timer is no help while the peer keeps a keep-alive
    /// answered. [`serve_stream`] and every bounded response write
    /// ([`super::stream::Stream::respond_within`]) are those waits.
    pub(super) idle: Duration,
    shared: Arc<Shared>,
}

impl Handle {
    /// The connection's frame-buffering budget, for a request stream about to
    /// start reading frames (D77).
    ///
    /// The peer's control stream is the one reader that does not draw on it;
    /// [`BufferBudget::unshared`] says why.
    pub(crate) fn budget(&self) -> Arc<BufferBudget> {
        self.shared.buffered.clone()
    }

    /// Claims a Quarter Stream ID for a session on this connection.
    ///
    /// The stream's own call, forwarded: only [`super::stream::Stream`] knows
    /// the stream id this is derived from, and only [`Shared`] holds the table
    /// it goes into.
    pub(crate) fn register_datagrams(&self, quarter_stream_id: u64) -> Option<DatagramReceiver> {
        self.shared.register_datagrams(quarter_stream_id)
    }

    /// Ends the connection because the peer broke a rule (RFC 9114 §8).
    ///
    /// The reason is recorded before the close so that [`Connection::accept`],
    /// which will now fail with quinn's "closed locally", can report what
    /// actually happened rather than that this endpoint hung up.
    pub(crate) fn fail(&self, violation: Violation) -> ConnectionError {
        debug!(%violation, "closing the connection on a protocol violation");

        // Only the first violation is kept: it is the one that caused the
        // close, and anything after it is a consequence. Everything below uses
        // the violation that was *stored* rather than the one passed in, so the
        // code on the wire, the reason in the log and the error this returns
        // cannot disagree when two tasks fail at once.
        let stored = self.shared.record(violation);
        self.quic
            .close(varint(stored.code()), stored.to_string().as_bytes());

        ConnectionError::Local(stored)
    }

    /// Interprets a QUIC connection failure, restoring our own reason if the
    /// connection ended because [`Self::fail`] closed it.
    fn interpret(&self, error: quinn::ConnectionError) -> ConnectionError {
        match (&error, self.shared.local_error.get()) {
            (quinn::ConnectionError::LocallyClosed, Some(violation)) => {
                ConnectionError::Local(violation.clone())
            }
            _ => error.into(),
        }
    }

    /// Answers a failed write to one of this endpoint's critical streams.
    ///
    /// RFC 9114 §6.2.1 forbids a peer from resetting or stopping the control
    /// stream, so anything other than the connection going away is the peer
    /// breaking that rule:
    ///
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
    //# If either control stream is closed at any point, this MUST be treated
    //# as a connection error of type H3_CLOSED_CRITICAL_STREAM.
    ///
    /// The same verdict covers the two QPACK streams this endpoint opens, on the
    /// strength of RFC 9204 §4.2 rather than this sentence (the reasoning is on
    /// [`Connection::_qpack`]); three of this endpoint's streams write through
    /// here and all three are critical.
    ///
    /// Routed through [`Self::fail`] rather than merely returned, because a
    /// connection error in this layer *is* the CONNECTION_CLOSE that carries the
    /// code (RFC 9114 §8). Returning the violation on its own left the peer
    /// seeing whatever came next -- in practice the H3_NO_ERROR that
    /// [`Connection`]'s `Drop` sends -- which is this endpoint saying nothing
    /// was wrong about the one thing the RFC names a MUST here.
    fn critical_write(&self, error: quinn::WriteError) -> ConnectionError {
        match error {
            quinn::WriteError::ConnectionLost(error) => error.into(),
            other => self.fail(Violation::connection(
                Code::H3_CLOSED_CRITICAL_STREAM,
                other.to_string(),
            )),
        }
    }

    /// Opens a unidirectional stream and writes its type (RFC 9114 §6.2).
    async fn open_typed(&self, stream_type: u64) -> Result<quinn::SendStream, ConnectionError> {
        let mut send = self.quic.open_uni().await?;

        let mut header = BytesMut::with_capacity(varint_len(stream_type));
        put_varint(&mut header, stream_type);
        send.write_all(&header)
            .await
            .map_err(|error| self.critical_write(error))?;

        Ok(send)
    }

    /// Opens this endpoint's three critical streams: control, then the QPACK
    /// pair.
    ///
    /// Every await here is on the peer: `open_uni` waits for the stream credit
    /// its transport parameters grant, and the writes wait for flow control. A
    /// peer that grants neither parks this forever, which is why
    /// [`Connection::handshake`] runs it under a deadline.
    async fn open_critical_streams(&self) -> Result<[quinn::SendStream; 3], ConnectionError> {
        // The control stream goes out first, so that a peer reading streams in
        // the order they arrive sees SETTINGS before anything else.
        let settings = frame::settings_payload();
        let mut preface = BytesMut::with_capacity(settings.len() + 2 * VARINT_MAX_LEN);
        put_varint(&mut preface, STREAM_CONTROL);
        frame::put_header(&mut preface, frame::SETTINGS, settings.len() as u64);
        preface.extend_from_slice(&settings);

        let mut control = self.quic.open_uni().await?;
        control
            .write_all(&preface)
            .await
            .map_err(|error| self.critical_write(error))?;

        let encoder = self.open_typed(STREAM_QPACK_ENCODER).await?;
        let decoder = self.open_typed(STREAM_QPACK_DECODER).await?;

        Ok([control, encoder, decoder])
    }
}

/// An accepted HTTP/3 connection.
pub struct Connection {
    handle: Handle,
    /// This endpoint's control stream, kept for the GOAWAY that ends it.
    control: quinn::SendStream,
    /// The QPACK encoder and decoder streams.
    ///
    /// Never written to again, and never dropped before the connection is:
    /// dropping a [`quinn::SendStream`] finishes it, and RFC 9204 §4.2 makes
    /// the closure of either stream a connection error at the peer.
    _qpack: [quinn::SendStream; 2],
    /// The task reading the peer's unidirectional streams and datagrams.
    peer: JoinHandle<()>,
    /// The highest request stream id handed to the caller.
    last_accepted: Option<u64>,
    /// The identifier sent in GOAWAY, once [`Self::shutdown`] has sent one.
    going_away: Option<u64>,
}

impl Connection {
    /// Performs the HTTP/3 handshake on an established QUIC connection.
    ///
    /// The SETTINGS this sends are not a preference but a requirement: Surge
    /// validates `SETTINGS_ENABLE_CONNECT_PROTOCOL` and `SETTINGS_H3_DATAGRAM`
    /// during setup and disconnects if either is missing.
    ///
    /// The two QPACK streams are opened even though RFC 9204 §4.2 permits
    /// omitting them ("An endpoint MAY avoid creating an encoder stream if it
    /// will not be used"). Nothing is ever written to them; they exist because
    /// every deployed stack opens them, and interoperating with one particular
    /// client is this server's whole purpose.
    ///
    /// # The deadline
    ///
    /// `within` bounds all of that, and it has to: opening three unidirectional
    /// streams is the peer's decision, not this endpoint's. Transport
    /// parameters that allow fewer than three of them -- or no data on them --
    /// park the handshake with no way out, and the QUIC idle timeout is no
    /// backstop, because [`crate::quic`] enables a keep-alive whose PINGs the
    /// peer's stack answers without any application ever being involved. Each
    /// such connection would hold a `max_connections` slot for as long as the
    /// peer cares to keep the socket open.
    ///
    /// One idle timeout is the bound the caller passes, and it is generous by
    /// construction: a peer that cannot complete a three-stream handshake in
    /// the time it is allowed to say nothing at all is not going to complete
    /// it.
    ///
    /// `dropped_datagrams` is where this connection counts every inbound HTTP
    /// Datagram it drops rather than delivers. The caller supplies it, keeping
    /// a clone of its own, because the count is read for the connection's
    /// closing log line -- which is written after everything constructed here
    /// is gone.
    pub async fn handshake(
        quic: quinn::Connection,
        within: Duration,
        dropped_datagrams: Arc<AtomicU64>,
    ) -> Result<Self, ConnectionError> {
        let handle = Handle {
            quic,
            idle: within,
            shared: Arc::new(Shared {
                dropped_datagrams,
                ..Shared::default()
            }),
        };

        let opened = tokio::time::timeout(within, handle.open_critical_streams()).await;

        // Our own rule, not the RFC's: nothing in RFC 9114 says what to do
        // about a peer that will not let these streams be created, because
        // nothing in it obliges a peer to allow them. H3_STREAM_CREATION_ERROR
        // is the closest registered code -- §8.1 gives it for a stream that
        // could not be created, which is exactly what happened -- and it tells
        // the peer which half of the handshake it failed.
        let [control, encoder, decoder] = match opened {
            Ok(streams) => streams?,
            Err(_) => {
                return Err(handle.fail(Violation::connection(
                    Code::H3_STREAM_CREATION_ERROR,
                    "the HTTP/3 handshake did not complete within one idle timeout",
                )));
            }
        };

        let peer = tokio::spawn(serve_peer(handle.clone()));

        Ok(Self {
            handle,
            control,
            _qpack: [encoder, decoder],
            peer,
            last_accepted: None,
            going_away: None,
        })
    }

    /// A live view of whether the peer advertised `SETTINGS_H3_DATAGRAM = 1`.
    ///
    /// RFC 9297 §2.1.1 forbids sending HTTP Datagrams before this is true, and
    /// a CONNECT-UDP session falls back to capsules on the request stream while
    /// it is not. The flag is handed out rather than sampled, for the reason
    /// the module documentation gives.
    ///
    /// Until the peer's SETTINGS arrive it reads `false`, which is the safe
    /// direction to be wrong in.
    pub fn peer_datagrams(&self) -> Arc<AtomicBool> {
        self.handle.shared.peer_datagrams.clone()
    }

    /// Waits for the next request stream.
    ///
    /// Cancel-safe: [`quinn::Connection::accept_bi`] leaves an unaccepted stream
    /// queued, so a caller may poll this inside a `select!`.
    ///
    /// `Ok(None)` would mean "the peer will send no further requests", and this
    /// server never reports it. The only thing that could say so is a GOAWAY
    /// from the client, which promises nothing about the requests already in
    /// flight -- while the caller reads `Ok(None)` as permission to drop the
    /// connection, and dropping it would cut those requests off mid-tunnel. A
    /// connection therefore ends when the peer closes it or the idle timeout
    /// fires, both of which arrive here as `Err`.
    pub async fn accept(&mut self) -> Result<Option<Resolver>, ConnectionError> {
        loop {
            let (send, recv) = self
                .handle
                .quic
                .accept_bi()
                .await
                .map_err(|error| self.handle.interpret(error))?;

            let id = u64::from(send.id());

            //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
            //# Requests or pushes with the indicated identifier or greater are
            //# rejected (Section 4.1.1) by the sender of the GOAWAY.

            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
            //# When the server cancels a request without performing any
            //# application processing, the request is considered "rejected".
            //# The server SHOULD abort its response stream with the error code
            //# H3_REQUEST_REJECTED.
            if self
                .going_away
                .is_some_and(|first_rejected| id >= first_rejected)
            {
                let (mut send, mut recv) = (send, recv);
                let _ = send.reset(varint(Code::H3_REQUEST_REJECTED));
                let _ = recv.stop(varint(Code::H3_REQUEST_REJECTED));
                debug!(
                    stream_id = id,
                    "rejecting a request that arrived after GOAWAY"
                );
                continue;
            }

            self.last_accepted = Some(id);
            return Ok(Some(Resolver::new(self.handle.clone(), send, recv)));
        }
    }

    /// Starts a graceful shutdown by sending GOAWAY (RFC 9114 §5.2).
    ///
    /// The identifier is the *first* request this connection will not serve --
    /// four past the last one accepted, or zero if none was -- so everything
    /// already in flight is untouched and the client knows to take new work
    /// elsewhere. Requests arriving past it are rejected in [`Self::accept`]
    /// with H3_REQUEST_REJECTED, the code a client may safely retry on.
    ///
    /// Note what this does *not* do: it does not wait for anything, and the
    /// connection stays usable afterwards. Deciding when the existing tunnels
    /// are done is the caller's job.
    pub async fn shutdown(&mut self) -> Result<(), ConnectionError> {
        let next = next_request_id(self.last_accepted);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
        //# An endpoint MAY send multiple GOAWAY frames indicating different
        //# identifiers, but the identifier in each frame MUST NOT be greater
        //# than the identifier in any previous frame, since clients might
        //# already have retried unprocessed requests on another HTTP
        //# connection.
        let identifier = self.going_away.map_or(next, |sent| sent.min(next));
        self.going_away = Some(identifier);

        let mut goaway = BytesMut::with_capacity(2 * VARINT_MAX_LEN + varint_len(identifier));
        frame::put_header(&mut goaway, frame::GOAWAY, varint_len(identifier) as u64);
        put_varint(&mut goaway, identifier);

        // Written before the answer is judged, so the borrow of `self.control`
        // is over by the time `self.handle` is asked what a failure means.
        let written = self.control.write_all(&goaway).await;
        written.map_err(|error| self.handle.critical_write(error))
    }

    /// Ends the connection because this endpoint is done with it, not because
    /// anything went wrong.
    ///
    /// The counterpart of the violation close: the same mechanism -- RFC 9114 §8
    /// makes a CONNECTION_CLOSE carrying an HTTP/3 code *be* the connection
    /// error -- with the code §8.1 defines for having nothing to report:
    ///
    //= https://www.rfc-editor.org/rfc/rfc9114#section-8.1
    //# H3_NO_ERROR (0x0100):  No error.  This is used when the connection or
    //# stream needs to be closed, but there is no error to signal.
    ///
    /// `reason` reaches the peer in the CONNECTION_CLOSE frame and comes back
    /// in the returned error, which [`crate::h3api::benign_close`] grades as a
    /// routine ending rather than a fault -- so the caller can `break` on it
    /// and let the connection's closing line stay at the level an idle timeout
    /// gets. Returning the error rather than logging here is what keeps that
    /// grading in one place (D50).
    pub fn close_quietly(&self, reason: &'static str) -> ConnectionError {
        self.handle
            .quic
            .close(varint(Code::H3_NO_ERROR), reason.as_bytes());
        ConnectionError::Local(Violation::connection(Code::H3_NO_ERROR, reason))
    }
}

impl Drop for Connection {
    /// Closes the QUIC connection and stops reading the peer's streams and
    /// datagrams.
    ///
    /// H3_NO_ERROR is RFC 9114 §8.1's code for when "the connection or stream
    /// needs to be closed, but there is no error to signal". `quic.rs` depends
    /// on this happening: it is why `quinn::Connection::close_reason()` cannot be used
    /// to grade a connection's closing log line, and why the error *value*
    /// returned by `conn::handle` is graded instead.
    fn drop(&mut self) {
        self.handle.quic.close(
            varint(Code::H3_NO_ERROR),
            b"connection closed by the server",
        );
        self.peer.abort();
    }
}

/// The stream id four past `last_accepted`, or zero if nothing was accepted.
///
/// The GOAWAY identifier this server sends: the first request it will not
/// serve. Clamped to [`crate::datagram::VARINT_MAX`] because the sum is written
/// as a QUIC varint and nothing above that is representable -- RFC 9000 §2.1
/// bounds a stream id by the same value, so no legitimate peer can reach the
/// clamp, and a saturating `u64::MAX` would be an assertion failure rather than
/// a GOAWAY.
fn next_request_id(last_accepted: Option<u64>) -> u64 {
    last_accepted.map_or(0, |id| {
        id.saturating_add(REQUEST_STREAM_STEP)
            .min(crate::datagram::VARINT_MAX)
    })
}

/// Serves what the peer sends outside its request streams, for the life of the
/// connection: its unidirectional streams and its HTTP Datagrams.
///
/// One task for both, because both are the connection's rather than any
/// stream's, both end when it does, and neither can be starved by the other:
/// [`quinn::Connection::accept_uni`] leaves an unaccepted stream queued and
/// [`quinn::Connection::read_datagram`] an undelivered datagram, so a branch
/// that loses the race here loses nothing but the poll. Handling is not done
/// inline either -- a unidirectional stream gets a task of its own, and a
/// datagram is a map lookup and a `try_send` that never blocks -- so a flood of
/// one kind cannot hold the other up.
async fn serve_peer(handle: Handle) {
    let mut streams = JoinSet::new();

    loop {
        tokio::select! {
            accepted = handle.quic.accept_uni() => {
                let Ok(recv) = accepted else {
                    // The connection is gone; so is anything that could arrive
                    // on it.
                    return;
                };

                // Reap the handlers that have finished, so a peer opening
                // streams in a loop cannot make this set grow without bound.
                while streams.try_join_next().is_some() {}

                streams.spawn(serve_stream(handle.clone(), recv));
            }

            received = handle.quic.read_datagram() => {
                let datagram = match received {
                    Ok(datagram) => datagram,
                    // The connection is gone; so is every session on it.
                    Err(error) => {
                        debug!(%error, "stopped reading QUIC datagrams");
                        return;
                    }
                };

                if route_datagram(&handle, datagram).is_break() {
                    return;
                }
            }
        }
    }
}

/// Decodes one QUIC datagram and delivers it, or ends the connection.
///
/// What happens to a datagram that cannot be delivered depends on *why*, and
/// RFC 9297 §2.1 draws the lines:
///
/// * a Quarter Stream ID that cannot be parsed, or one above 2^60-1, is a
///   **connection error** of type H3_DATAGRAM_ERROR -- neither can name a QUIC
///   stream, so there is nothing to drop it *for*;
/// * a Quarter Stream ID with no live session is **dropped**. The RFC permits
///   discarding a datagram whose request stream does not exist, which happens
///   routinely when a session closes with packets still in flight;
/// * a datagram whose Context ID is truncated or unknown is likewise dropped.
///
/// One SHOULD is deliberately not implemented: a Quarter Stream ID naming a
/// stream "that cannot be created due to client-initiated bidirectional stream
/// limits" SHOULD draw H3_ID_ERROR. Those are this endpoint's limits, not the
/// peer's — `initial_max_streams_bidi` is a transport parameter a receiver
/// advertises — and RFC 9297 §2.1 grants the exemption this router relies on:
/// "Generating an error is not mandatory because the QUIC stream limit might be
/// unknown to the HTTP/3 layer". It is unknown to this one. The limit is set by
/// [`crate::quic`] from `[limits] max_streams_bidi` and nothing here reads it,
/// so a Quarter Stream ID past it cannot be told apart from a session that has
/// already closed.
fn route_datagram(handle: &Handle, datagram: Bytes) -> ControlFlow<()> {
    //= https://www.rfc-editor.org/rfc/rfc9297#section-2.1
    //# The largest legal QUIC stream ID value is 2^62-1, so the largest legal
    //# value of the Quarter Stream ID field is 2^60-1. Receipt of an HTTP/3
    //# Datagram that includes a larger value MUST be treated as an HTTP/3
    //# connection error of type H3_DATAGRAM_ERROR (0x33).

    //= https://www.rfc-editor.org/rfc/rfc9297#section-2.1
    //# Receipt of a QUIC DATAGRAM frame whose payload is too short to allow
    //# parsing the Quarter Stream ID field MUST be treated as an HTTP/3
    //# connection error of type H3_DATAGRAM_ERROR (0x33).
    //
    // Both are decided by `datagram::decode` and reported by
    // `DecodeError::is_connection_error`; the arm below is where they are
    // acted on, so this is the one copy of them (D79).
    match datagram::decode(datagram) {
        Ok(decoded) => {
            handle.shared.deliver(decoded);
            ControlFlow::Continue(())
        }

        // The two conditions RFC 9297 §2.1 states as MUST-close. Reported
        // through `fail` like every other connection error in this layer, so
        // the code on the wire and the reason the caller is given cannot
        // disagree -- and so a datagram violation racing with a stream one ends
        // the connection once, with whichever was first.
        Err(error) if error.is_connection_error() => {
            handle.fail(Violation::connection(
                Code::H3_DATAGRAM_ERROR,
                format!("an unusable HTTP datagram: {error}"),
            ));
            ControlFlow::Break(())
        }

        Err(error) => {
            // The one malformation §2.1 does not make a connection error: a
            // datagram cut short of its Context ID. Dropped like the routing
            // misses in [`Shared::deliver`], and counted with them.
            handle.shared.count_drop(DropKind::Malformed, |drops| {
                debug!(
                    %error,
                    drops,
                    "dropping malformed HTTP datagrams; further ones are logged as the \
                     count doubles"
                )
            });
            ControlFlow::Continue(())
        }
    }
}

/// Dispatches one unidirectional stream by its type (RFC 9114 §6.2).
///
/// # The deadline on the type
///
/// A stream that has been opened but whose type varint has not arrived is a
/// stream this endpoint can say nothing about: the type is what decides whether
/// it is the control stream, a QPACK stream, or something to abort. Reading it
/// is therefore the one wait here with no protocol answer to it, and a peer that
/// opens streams and writes half a varint on each parks a task apiece for as
/// long as the connection lives -- which is as long as it likes, since the QUIC
/// idle timeout is fed by a keep-alive its own stack answers (review L3).
///
/// One idle timeout bounds it, matching [`Connection::handshake`]'s. What
/// follows is a `stop`, not a connection error: nothing was violated, the
/// stream simply never said what it was, and the peer keeps every stream it has
/// underway. H3_STREAM_CREATION_ERROR is this endpoint's own choice of code and
/// not the RFC's -- RFC 9114 §8.1 gives it for a stream that could not be
/// created, which is the nearest registered thing to a stream that never
/// declared itself, and it is what an unknown stream type is aborted with three
/// arms below.
async fn serve_stream(handle: Handle, mut recv: quinn::RecvStream) {
    let typed = tokio::time::timeout(handle.idle, read_stream_type(&mut recv)).await;

    let stream_type = match typed {
        Ok(Ok(Some(stream_type))) => stream_type,

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
        //# A receiver MUST tolerate unidirectional streams being closed or reset
        //# prior to the reception of the unidirectional stream header.
        Ok(Ok(None)) => return,
        Ok(Err(error)) => {
            debug!(%error, "a unidirectional stream failed before its type arrived");
            return;
        }
        Err(_elapsed) => {
            debug!(
                timeout_secs = handle.idle.as_secs(),
                "abandoning a unidirectional stream whose type never arrived"
            );
            let _ = recv.stop(varint(Code::H3_STREAM_CREATION_ERROR));
            return;
        }
    };

    match stream_type {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //# Only one control stream per peer is permitted; receipt of a second
        //# stream claiming to be a control stream MUST be treated as a
        //# connection error of type H3_STREAM_CREATION_ERROR.
        STREAM_CONTROL => {
            if handle.shared.control_seen.swap(true, Ordering::Relaxed) {
                handle.fail(duplicate("a second control stream"));
                return;
            }
            serve_control(&handle, recv).await;
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.2
        //# Only servers can push; if a server receives a client-initiated push
        //# stream, this MUST be treated as a connection error of type
        //# H3_STREAM_CREATION_ERROR.
        STREAM_PUSH => {
            handle.fail(Violation::connection(
                Code::H3_STREAM_CREATION_ERROR,
                "a client opened a push stream",
            ));
        }

        STREAM_QPACK_ENCODER => serve_qpack(&handle, recv, QpackStream::Encoder).await,
        STREAM_QPACK_DECODER => serve_qpack(&handle, recv, QpackStream::Decoder).await,

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
        //# Recipients of unknown stream types MUST either abort reading of the
        //# stream or discard incoming data without further processing. [...]
        //# The recipient MUST NOT consider unknown stream types to be a
        //# connection error of any kind.
        other => {
            debug!(
                stream_type = other,
                "aborting a unidirectional stream of an unknown type"
            );
            let _ = recv.stop(varint(Code::H3_STREAM_CREATION_ERROR));
        }
    }
}

/// Reads the peer's control stream until the connection ends.
async fn serve_control(handle: &Handle, recv: quinn::RecvStream) {
    // Not the connection's budget: one control stream buffering one frame at a
    // time is already bounded, and a refusal here could not be the stream-class
    // one that budget hands out (see [`BufferBudget::unshared`]).
    let mut frames = FrameReader::new(recv, BufferBudget::unshared());
    let mut control = Control::default();

    loop {
        let item = match frames.next().await {
            Ok(Some(item)) => item,

            Ok(None) => {
                if let Some(violation) =
                    control_stream_finished(handle.quic.close_reason().as_ref())
                {
                    handle.fail(violation);
                }
                return;
            }

            // Every framing rule is fatal here, whatever it would have been on
            // a request stream: the connection cannot go on without the stream
            // that carries SETTINGS and GOAWAY.
            Err(frame::Error::Protocol(violation)) => {
                handle.fail(violation.into_fatal());
                return;
            }
            // The connection ending under the control stream is not the
            // control stream failing: whoever is waiting in `accept` already
            // has the real reason, and reporting a critical-stream error here
            // would overwrite an idle timeout -- the everyday goodbye -- with a
            // protocol violation in the operator's log.
            Err(frame::Error::Stream(StreamError::Connection(_))) => return,

            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
            //# The sender MUST NOT close the control stream, and the receiver
            //# MUST NOT request that the sender close the control stream.
            Err(frame::Error::Stream(error)) => {
                handle.fail(Violation::connection(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    format!("the peer reset its control stream: {error}"),
                ));
                return;
            }
        };

        if let Err(violation) = control.accept(item, &handle.shared) {
            handle.fail(violation);
            return;
        }
    }
}

/// What a clean end of the peer's control stream means, given `close_reason`.
///
/// `close_reason` is [`quinn::Connection::close_reason`]: `Some` once the
/// connection is over, whoever ended it.
///
/// The rule below is not negotiable. What is negotiable is whether reaching its
/// verdict is worth anything on a connection that has already ended: a peer
/// tearing one down finishes its send streams and sends CONNECTION_CLOSE in the
/// same breath, and the two can be read here in either order. Answering an
/// ordinary goodbye with a protocol error would turn that race into a fault in
/// the operator's log, on behalf of a connection there is nothing left to
/// protect -- the same reasoning [`serve_qpack`] records for the QPACK streams.
fn control_stream_finished(close_reason: Option<&quinn::ConnectionError>) -> Option<Violation> {
    if close_reason.is_some() {
        return None;
    }

    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
    //# If either control stream is closed at any point, this MUST be treated
    //# as a connection error of type H3_CLOSED_CRITICAL_STREAM.
    Some(Violation::connection(
        Code::H3_CLOSED_CRITICAL_STREAM,
        "the peer closed its control stream",
    ))
}

/// The control stream's frame rules (RFC 9114 §6.2.1).
///
/// Separated from the reading loop so the rules can be tested as a table rather
/// than through a live connection.
#[derive(Debug, Default)]
struct Control {
    /// Whether the peer's SETTINGS frame has been seen.
    settings: bool,
    /// The last GOAWAY identifier the peer sent.
    goaway: Option<u64>,
    /// The largest push ID the peer has allowed (RFC 9114 §7.2.7), if any.
    ///
    /// Kept only to enforce that it never shrinks: this server never pushes,
    /// so the value itself is never consulted.
    max_push_id: Option<u64>,
    /// Frames of an unknown type this stream has skipped, and when the next one
    /// is worth a line.
    ///
    /// An unknown frame with a zero length is two bytes on the wire, and RFC
    /// 9114 §9 says to ignore it — so a peer may send them back to back for as
    /// long as the connection lives, and a line apiece was the highest ratio of
    /// journal to peer bytes anywhere in this server. It is a `debug!`, so it
    /// does not reach a default production log at all; what it does reach is the
    /// operator who turned `debug` on to read what a client is actually sending,
    /// which is the one moment the flood costs the most.
    ///
    /// Ignoring them silently is not the answer: greasing is exactly how a peer
    /// checks that this server skips what it does not know, so an unexplained
    /// gap in a debug trace would be the wrong reading. The doubling schedule
    /// keeps the first one and the size of the flood, and drops the repetition.
    skipped: crate::logfmt::Sampler,
}

impl Control {
    /// Applies one item from the control stream.
    fn accept(&mut self, item: Item, shared: &Shared) -> Result<(), Violation> {
        let frame = match item {
            Item::Frame(frame) => frame,

            // DATA on the control stream is a frame that does not belong there,
            // and as the first thing on it, it is simply not SETTINGS. An empty
            // one is no different: §6.2.1 asks which frame *type* came first,
            // and a DATA frame that carries nothing is still a DATA frame.
            Item::Data(_) => {
                return Err(if self.settings {
                    unexpected("a DATA frame on the control stream")
                } else {
                    missing_settings()
                });
            }

            // RFC 9114 §9's rule that unknown values are ignored, quoted in
            // full in `super`. Ignored -- but only after SETTINGS. A grease
            // frame sent first is still "any other frame type" below, and the
            // greasing endpoint is precisely the one testing whether this
            // server enforces that.
            Item::Skipped { kind } => {
                if !self.settings {
                    return Err(missing_settings());
                }
                if let Some(skipped) = self.skipped.record() {
                    debug!(
                        frame_type = kind,
                        skipped,
                        "ignoring a frame of an unknown type on the control stream; \
                         further ones are logged as the count doubles"
                    );
                }
                return Ok(());
            }
        };

        match (frame, self.settings) {
            (Frame::Settings(settings), false) => {
                self.settings = true;
                if settings.datagrams {
                    shared.peer_datagrams.store(true, Ordering::Relaxed);
                }
                Ok(())
            }

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
            //# If an endpoint receives a second SETTINGS frame on the control
            //# stream, the endpoint MUST respond with a connection error of type
            //# H3_FRAME_UNEXPECTED.
            (Frame::Settings(_), true) => Err(unexpected("a second SETTINGS frame")),

            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
            //# If the first frame of the control stream is any other frame type,
            //# this MUST be treated as a connection error of type
            //# H3_MISSING_SETTINGS.
            (_, false) => Err(missing_settings()),

            (Frame::Goaway(identifier), true) => {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
                //# Receiving a GOAWAY containing a larger identifier than
                //# previously received MUST be treated as a connection error of
                //# type H3_ID_ERROR.
                if self.goaway.is_some_and(|previous| identifier > previous) {
                    return Err(Violation::connection(
                        Code::H3_ID_ERROR,
                        format!("a GOAWAY identifier that grew to {identifier}"),
                    ));
                }
                self.goaway = Some(identifier);
                Ok(())
            }

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
            //# If a server receives a CANCEL_PUSH frame for a push ID that has
            //# not yet been mentioned by a PUSH_PROMISE frame, this MUST be
            //# treated as a connection error of type H3_ID_ERROR.
            //
            // This server never sends PUSH_PROMISE, so no push ID has ever been
            // mentioned and every CANCEL_PUSH names one that has not.
            (Frame::CancelPush(push_id), true) => Err(Violation::connection(
                Code::H3_ID_ERROR,
                format!("a CANCEL_PUSH for push ID {push_id}, which was never promised"),
            )),

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
            //# A MAX_PUSH_ID frame cannot reduce the maximum push ID; receipt of
            //# a MAX_PUSH_ID frame that contains a smaller value than previously
            //# received MUST be treated as a connection error of type H3_ID_ERROR.
            (Frame::MaxPushId(push_id), true) => {
                if self.max_push_id.is_some_and(|previous| push_id < previous) {
                    return Err(Violation::connection(
                        Code::H3_ID_ERROR,
                        format!("a MAX_PUSH_ID that shrank to {push_id}"),
                    ));
                }
                self.max_push_id = Some(push_id);
                Ok(())
            }

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
            //# A server MUST treat the receipt of a PUSH_PROMISE frame as a
            //# connection error of type H3_FRAME_UNEXPECTED.
            (Frame::PushPromise, true) => Err(unexpected("a PUSH_PROMISE frame")),

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.2
            //# HEADERS frames can only be sent on request streams or push
            //# streams. If a HEADERS frame is received on a control stream,
            //# the recipient MUST respond with a connection error of type
            //# H3_FRAME_UNEXPECTED.
            (Frame::Headers(_), true) => Err(unexpected("a HEADERS frame on the control stream")),
        }
    }
}

/// Which of the peer's two QPACK streams (RFC 9204 §4.2) is being read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QpackStream {
    /// The peer's encoder stream, carrying encoder instructions (RFC 9204 §4.3).
    Encoder,
    /// The peer's decoder stream, carrying decoder instructions (RFC 9204 §4.4).
    Decoder,
}

impl QpackStream {
    /// The flag recording whether a stream of this kind has been accepted.
    fn seen(self, shared: &Shared) -> &AtomicBool {
        match self {
            Self::Encoder => &shared.encoder_seen,
            Self::Decoder => &shared.decoder_seen,
        }
    }

    /// The error code RFC 9204 §6 assigns to a fault on this stream.
    fn code(self) -> Code {
        match self {
            Self::Encoder => Code::QPACK_ENCODER_STREAM_ERROR,
            Self::Decoder => Code::QPACK_DECODER_STREAM_ERROR,
        }
    }

    /// What to call this stream in a message.
    fn name(self) -> &'static str {
        match self {
            Self::Encoder => "encoder",
            Self::Decoder => "decoder",
        }
    }
}

/// What an end of one of the peer's QPACK streams means, given `close_reason`.
///
/// `detail` says which ending it was, for the message only: RFC 9204 §4.2 makes
/// a clean finish and a reset the same verdict.
///
/// The same rule and the same exemption as [`control_stream_finished`], which
/// carries the reasoning: a peer tearing a connection down finishes its send
/// streams and sends CONNECTION_CLOSE in the same breath, and answering an
/// ordinary goodbye with a protocol error would put a fault in the operator's
/// log on behalf of a connection there is nothing left to protect.
fn qpack_stream_ended(
    detail: String,
    close_reason: Option<&quinn::ConnectionError>,
) -> Option<Violation> {
    if close_reason.is_some() {
        return None;
    }

    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
    //# The sender MUST NOT close either of these streams, and the receiver
    //# MUST NOT request that the sender close either of these streams.
    //# Closure of either unidirectional stream type MUST be treated as a
    //# connection error of type H3_CLOSED_CRITICAL_STREAM.
    Some(Violation::connection(
        Code::H3_CLOSED_CRITICAL_STREAM,
        detail,
    ))
}

/// The most continuation bytes an instruction's prefixed integer may run to.
///
/// RFC 9204 §4.1.1 requires decoding integers "up to and including 62 bits
/// long", which a 5- or 6-bit prefix reaches in nine continuation bytes of
/// seven bits each. A tenth is a value no conformant encoder produces, and this
/// server's own rule is to end the stream there rather than read on forever.
const MAX_INTEGER_CONTINUATION: usize = 9;

/// How far the last accepted instruction's prefixed integer has run.
///
/// The whole of [`serve_qpack`]'s per-byte state, in one place rather than in
/// two bindings inside its loop. The peer chooses where its stream is cut into
/// `read_chunk` results, and the judgement may not depend on that, so the state
/// has to live across chunks and the step that advances it has to be a function
/// of one byte and this. Both halves are testable that way, which the loop
/// alone was not: driving it needs a live [`quinn::RecvStream`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct QpackProgress {
    /// Whether the last accepted instruction's integer is still running.
    continuing: bool,
    /// How many continuation bytes of it have been read.
    continuation: usize,
}

impl QpackProgress {
    /// Judges one byte of the peer's QPACK stream and advances the state.
    ///
    /// A byte is either a continuation of the integer the last instruction
    /// started, in which case only its top bit matters and [`Self::continuation`]
    /// counts it, or the first byte of a new instruction, which
    /// [`qpack_instruction`] judges.
    fn take(&mut self, kind: QpackStream, byte: u8) -> Result<(), Violation> {
        if self.continuing {
            self.continuation += 1;
            if self.continuation > MAX_INTEGER_CONTINUATION {
                return Err(Violation::connection(
                    kind.code(),
                    "an integer past 62 bits",
                ));
            }
            self.continuing = byte & 0b1000_0000 != 0;
            return Ok(());
        }

        self.continuing = qpack_instruction(kind, byte)?;
        self.continuation = 0;
        Ok(())
    }
}

/// Reads one of the peer's QPACK streams for the life of the connection.
///
/// This decoder advertised a table capacity of zero and this encoder never
/// touches the dynamic table, so neither stream can carry an instruction that
/// changes anything here -- but they still have to be read: a receiver that
/// never reads stalls the peer's stream flow control, and RFC 9204 §4.2 forbids
/// the peer from closing them, so stopping them is not an option either. Reading
/// means checking: with no table, nearly every instruction is one the RFC makes
/// a connection error, and [`qpack_instruction`] says which. Only the first byte
/// of each is ever needed, so the rest of an accepted instruction is read past.
/// [`QpackProgress`] is the state that does the reading past, and it is held
/// across `read_chunk` results rather than inside one: the peer chooses where
/// its stream is cut into chunks, and the verdict may not depend on that.
///
/// RFC 9204 §4.2 also makes the *peer* closing one of these streams a
/// connection error of type H3_CLOSED_CRITICAL_STREAM, and
/// [`qpack_stream_ended`] reports it, with the one exemption the control stream
/// makes for the same race: a connection that has already ended is not
/// disturbed. Both endings count, a clean finish and a reset alike, which is
/// what §4.2 says.
async fn serve_qpack(handle: &Handle, mut recv: quinn::RecvStream, kind: QpackStream) {
    if kind.seen(&handle.shared).swap(true, Ordering::Relaxed) {
        handle.fail(duplicate("a second QPACK stream of the same kind"));
        return;
    }

    let mut progress = QpackProgress::default();

    loop {
        let chunk = match recv.read_chunk(usize::MAX, true).await {
            Ok(Some(chunk)) => chunk,

            // The two endings §4.2 forbids. A read error that is the connection
            // itself ending needs no arm of its own: `close_reason` is `Some`
            // by then, which is exactly the exemption.
            Ok(None) => {
                let detail = format!("the peer closed its QPACK {} stream", kind.name());
                if let Some(violation) =
                    qpack_stream_ended(detail, handle.quic.close_reason().as_ref())
                {
                    handle.fail(violation);
                }
                return;
            }
            Err(error) => {
                let detail = format!("the peer reset its QPACK {} stream: {error}", kind.name());
                if let Some(violation) =
                    qpack_stream_ended(detail, handle.quic.close_reason().as_ref())
                {
                    handle.fail(violation);
                }
                return;
            }
        };

        for &byte in &chunk.bytes {
            if let Err(violation) = progress.take(kind, byte) {
                handle.fail(violation);
                return;
            }
        }
    }
}

/// Judges an instruction on one of the peer's QPACK streams by its first byte.
///
/// `Ok(true)` means the instruction is acceptable and its integer continues into
/// the bytes that follow; `Ok(false)` that it is acceptable and complete; `Err`
/// that it is a connection error. The first byte is always enough: every
/// refused instruction is refused by its opcode alone, and for the two that are
/// allowed the prefix bits settle the only question there is.
fn qpack_instruction(kind: QpackStream, first: u8) -> Result<bool, Violation> {
    let refuse = |what: &'static str| Err(Violation::connection(kind.code(), what));

    match kind {
        QpackStream::Encoder => {
            //= https://www.rfc-editor.org/rfc/rfc9204#section-3.2.2
            //# It is an error if the encoder attempts to add an entry that is
            //# larger than the dynamic table capacity; the decoder MUST treat
            //# this as a connection error of type QPACK_ENCODER_STREAM_ERROR.
            //
            // With a capacity of zero every entry is larger than it, which
            // covers both Insert instructions (§4.3.2, §4.3.3) and Duplicate
            // (§4.3.4), which adds an entry too.
            if first & 0b1000_0000 != 0 {
                return refuse("an Insert with Name Reference with no dynamic table");
            }
            if first & 0b0100_0000 != 0 {
                return refuse("an Insert with Literal Name with no dynamic table");
            }
            if first & 0b0010_0000 != 0 {
                //= https://www.rfc-editor.org/rfc/rfc9204#section-4.3.1
                //# The decoder MUST treat a new dynamic table capacity value that
                //# exceeds this limit as a connection error of type
                //# QPACK_ENCODER_STREAM_ERROR.
                //
                // The limit is the zero this server advertised, and a 5-bit
                // prefix of zero is the only encoding of zero (§4.1.1), so the
                // first byte decides.
                if first & 0b0001_1111 != 0 {
                    return refuse("a dynamic table capacity above the zero this server allows");
                }
                return Ok(false);
            }
            refuse("a Duplicate with no dynamic table")
        }

        QpackStream::Decoder => {
            if first & 0b1000_0000 != 0 {
                //= https://www.rfc-editor.org/rfc/rfc9204#section-4.4.1
                //# If an encoder receives a Section Acknowledgment instruction
                //# referring to a stream on which every encoded field section
                //# with a non-zero Required Insert Count has already been
                //# acknowledged, this MUST be treated as a connection error of
                //# type QPACK_DECODER_STREAM_ERROR.
                //
                // This encoder never uses the dynamic table, so no field section
                // it sent had a non-zero Required Insert Count: on every stream,
                // all of them -- none -- stand acknowledged already.
                return refuse("a Section Acknowledgment for a field section that needed none");
            }
            if first & 0b0100_0000 != 0 {
                // Stream Cancellation (§4.4.2): nothing to undo and nothing the
                // RFC asks to check; only the stream id has to be read past.
                return Ok(first & 0b0011_1111 == 0b0011_1111);
            }
            //= https://www.rfc-editor.org/rfc/rfc9204#section-4.4.3
            //# An encoder that receives an Increment field equal to zero, or one
            //# that increases the Known Received Count beyond what the encoder
            //# has sent, MUST treat this as a connection error of type
            //# QPACK_DECODER_STREAM_ERROR.
            //
            // This encoder has sent no insertions, so any increment is beyond
            // them, and an increment of zero is an error in its own right.
            refuse("an Insert Count Increment when nothing was inserted")
        }
    }
}

/// Reads a unidirectional stream's type, the varint it opens with.
///
/// `Ok(None)` means the stream ended before the type was complete, which
/// RFC 9114 §6.2 requires a receiver to tolerate.
async fn read_stream_type(recv: &mut quinn::RecvStream) -> Result<Option<u64>, StreamError> {
    let mut buf = [0u8; VARINT_MAX_LEN];

    match recv.read_exact(&mut buf[..1]).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(_)) => return Ok(None),
        Err(quinn::ReadExactError::ReadError(error)) => return Err(error.into()),
    }

    // RFC 9000 §16: the two most significant bits give the length as a power
    // of two.
    let length = 1usize << (buf[0] >> 6);
    if length > 1 {
        match recv.read_exact(&mut buf[1..length]).await {
            Ok(()) => {}
            Err(quinn::ReadExactError::FinishedEarly(_)) => return Ok(None),
            Err(quinn::ReadExactError::ReadError(error)) => return Err(error.into()),
        }
    }

    Ok(peek_varint(&buf[..length]).map(|(value, _)| value))
}

/// A second stream of a kind the peer may only open once (RFC 9114 §6.2.1).
fn duplicate(detail: &'static str) -> Violation {
    Violation::connection(Code::H3_STREAM_CREATION_ERROR, detail)
}

/// A frame that is not allowed where it appeared (RFC 9114 §7.2).
fn unexpected(detail: &'static str) -> Violation {
    Violation::connection(Code::H3_FRAME_UNEXPECTED, detail)
}

/// The control stream did not open with SETTINGS (RFC 9114 §6.2.1).
fn missing_settings() -> Violation {
    Violation::connection(
        Code::H3_MISSING_SETTINGS,
        "the control stream did not begin with SETTINGS",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn settings(datagrams: bool) -> Item {
        Item::Frame(Frame::Settings(frame::Settings { datagrams }))
    }

    /// [`DatagramReceiver::recv`] with a deadline, so a router that stops
    /// delivering is a named failure rather than a hung test binary.
    #[track_caller]
    fn recv_within(
        inbound: &mut DatagramReceiver,
    ) -> impl std::future::Future<Output = Option<Bytes>> + '_ {
        let caller = std::panic::Location::caller();
        async move {
            tokio::time::timeout(Duration::from_secs(5), inbound.recv())
                .await
                .unwrap_or_else(|_| panic!("no datagram was delivered within 5s (from {caller})"))
        }
    }

    #[test]
    fn the_first_frame_must_be_settings() {
        let shared = Shared::default();

        for first in [
            Item::Frame(Frame::Goaway(0)),
            Item::Frame(Frame::MaxPushId(0)),
            Item::Data(Bytes::from_static(b"nope")),
            // A frame carrying nothing, and a frame this server cannot read,
            // are both frames: neither is SETTINGS.
            Item::Data(Bytes::new()),
            Item::Skipped {
                kind: 0x1f * 3 + 0x21,
            },
        ] {
            let error = Control::default()
                .accept(first, &shared)
                .expect_err("refused");
            assert_eq!(error.code(), Code::H3_MISSING_SETTINGS);
            assert!(error.is_connection_error());
        }

        assert!(Control::default().accept(settings(true), &shared).is_ok());
    }

    /// RFC 9114 §9 once the connection is up: an unknown frame type on the
    /// control stream is ignored, and greasing peers send them on purpose.
    #[test]
    fn an_unknown_frame_after_settings_is_ignored() {
        let shared = Shared::default();
        let mut control = Control::default();
        control.accept(settings(true), &shared).expect("accepted");

        control
            .accept(
                Item::Skipped {
                    kind: 0x1f * 6 + 0x21,
                },
                &shared,
            )
            .expect("ignored");

        // And the stream carries on working afterwards.
        control
            .accept(Item::Frame(Frame::Goaway(4)), &shared)
            .expect("accepted");
    }

    /// A grease frame is two bytes on the wire and a peer may send them for as
    /// long as the connection lives, so the line they used to buy apiece was the
    /// highest ratio of journal to peer bytes in this server.
    ///
    /// What is asserted here is that every one of them reaches the sampler,
    /// which is the half the log cannot show: the schedule's whole point is that
    /// most occurrences produce no line, so a test reading lines could not tell
    /// "sampled" from "stopped counting". The schedule itself — 1, 2, 4, 8, and
    /// seventeen lines for sixty-five thousand — is
    /// `logfmt::tests::a_sampler_turns_a_flood_into_a_handful_of_lines`.
    #[test]
    fn every_skipped_frame_is_counted_and_only_a_few_are_said_out_loud() {
        const FLOOD: u64 = 1000;

        let shared = Shared::default();
        let mut control = Control::default();
        control.accept(settings(true), &shared).expect("accepted");

        for kind in 0..FLOOD {
            control
                .accept(
                    Item::Skipped {
                        kind: 0x1f * kind + 0x21,
                    },
                    &shared,
                )
                .expect("ignored");
        }

        assert_eq!(
            control.skipped.seen(),
            FLOOD,
            "the sampler has to see every skipped frame, or the count it reports \
             is not the size of the flood"
        );
    }

    /// An empty DATA frame after SETTINGS is a DATA frame like any other, and
    /// RFC 9114 §7.2.1 does not allow one here.
    #[test]
    fn an_empty_data_frame_after_settings_is_still_unexpected() {
        let shared = Shared::default();
        let mut control = Control::default();
        control.accept(settings(true), &shared).expect("accepted");

        let error = control
            .accept(Item::Data(Bytes::new()), &shared)
            .expect_err("refused");
        assert_eq!(error.code(), Code::H3_FRAME_UNEXPECTED);
    }

    /// The whole reason the control stream is read in its own task: the flag
    /// the sessions hold is written by whoever parsed the frame, so there is no
    /// moment at which the peer's answer is known here but not there.
    #[test]
    fn the_peers_settings_reach_the_shared_flag() {
        for datagrams in [true, false] {
            let shared = Shared::default();
            let seen_by_a_session = shared.peer_datagrams.clone();
            assert!(!seen_by_a_session.load(Ordering::Relaxed), "nothing yet");

            Control::default()
                .accept(settings(datagrams), &shared)
                .expect("accepted");

            assert_eq!(seen_by_a_session.load(Ordering::Relaxed), datagrams);
        }
    }

    #[test]
    fn a_second_settings_frame_is_refused() {
        let shared = Shared::default();
        let mut control = Control::default();
        control.accept(settings(true), &shared).expect("accepted");

        let error = control
            .accept(settings(true), &shared)
            .expect_err("refused");
        assert_eq!(error.code(), Code::H3_FRAME_UNEXPECTED);
    }

    #[test]
    fn frames_that_belong_on_a_request_stream_are_refused() {
        let shared = Shared::default();
        for frame in [Frame::Headers(Bytes::new()), Frame::PushPromise] {
            let mut control = Control::default();
            control.accept(settings(true), &shared).expect("accepted");

            let error = control
                .accept(Item::Frame(frame), &shared)
                .expect_err("refused");
            assert_eq!(error.code(), Code::H3_FRAME_UNEXPECTED);
        }
    }

    /// This server never sends PUSH_PROMISE, so no push ID was ever mentioned
    /// and RFC 9114 §7.2.3 makes every CANCEL_PUSH an H3_ID_ERROR.
    #[test]
    fn a_cancel_push_names_a_push_that_was_never_promised() {
        let shared = Shared::default();
        let mut control = Control::default();
        control.accept(settings(true), &shared).expect("accepted");

        let error = control
            .accept(Item::Frame(Frame::CancelPush(7)), &shared)
            .expect_err("refused");
        assert_eq!(error.code(), Code::H3_ID_ERROR);
    }

    #[test]
    fn a_max_push_id_may_grow_but_not_shrink() {
        let shared = Shared::default();
        let mut control = Control::default();
        control.accept(settings(true), &shared).expect("accepted");

        for push_id in [9, 9, 12] {
            control
                .accept(Item::Frame(Frame::MaxPushId(push_id)), &shared)
                .expect("a push ID that does not shrink is allowed");
        }
        let error = control
            .accept(Item::Frame(Frame::MaxPushId(8)), &shared)
            .expect_err("a smaller push ID is refused");
        assert_eq!(error.code(), Code::H3_ID_ERROR);
    }

    #[test]
    fn qpack_encoder_instructions_are_refused_except_a_zero_capacity() {
        for (first, what) in [
            (0b1000_0000, "an Insert with Name Reference"),
            (0b1111_1111, "an Insert with Name Reference, every bit set"),
            (0b0100_0000, "an Insert with Literal Name"),
            (0b0000_0000, "a Duplicate"),
            (0b0010_0001, "a capacity of 1"),
            (0b0011_1111, "a capacity of 31 or more"),
        ] {
            let error = qpack_instruction(QpackStream::Encoder, first).expect_err(what);
            assert_eq!(error.code(), Code::QPACK_ENCODER_STREAM_ERROR, "{what}");
            assert!(error.is_connection_error(), "{what}");
        }

        let more = qpack_instruction(QpackStream::Encoder, 0b0010_0000).expect("a capacity of 0");
        assert!(!more, "a capacity of 0 is complete in its first byte");
    }

    #[test]
    fn qpack_decoder_instructions_are_refused_except_stream_cancellation() {
        for (first, what) in [
            (0b1000_0000, "a Section Acknowledgment"),
            (0b1111_1111, "a Section Acknowledgment, every bit set"),
            (0b0000_0000, "an Insert Count Increment of 0"),
            (0b0000_0001, "an Insert Count Increment of 1"),
            (0b0011_1111, "an Insert Count Increment of 63 or more"),
        ] {
            let error = qpack_instruction(QpackStream::Decoder, first).expect_err(what);
            assert_eq!(error.code(), Code::QPACK_DECODER_STREAM_ERROR, "{what}");
            assert!(error.is_connection_error(), "{what}");
        }

        let more = qpack_instruction(QpackStream::Decoder, 0b0100_0100).expect("cancel stream 4");
        assert!(!more, "a small stream id is complete in its first byte");
        let more =
            qpack_instruction(QpackStream::Decoder, 0b0111_1111).expect("cancel a big stream");
        assert!(more, "a stream id of 63 or more continues");
    }

    /// Feeds `chunks` to a fresh [`QpackProgress`] in order and reports what
    /// the stream drew.
    ///
    /// The first violation, or the state left behind if there was none. Two
    /// runs agree only if they refused at the same point for the same reason,
    /// or accepted everything and are equally far through an integer.
    fn judge_qpack(kind: QpackStream, chunks: &[&[u8]]) -> Result<QpackProgress, Violation> {
        let mut progress = QpackProgress::default();
        for chunk in chunks {
            for &byte in *chunk {
                progress.take(kind, byte)?;
            }
        }
        Ok(progress)
    }

    /// The peer chooses where its QPACK stream is cut, and the verdict may not
    /// depend on that.
    ///
    /// `serve_qpack` judges whatever `read_chunk` hands it, and a peer may send
    /// one instruction a byte at a time or a hundred in one packet. The state
    /// that has to survive a cut is an integer still running from the last
    /// instruction, which is the only thing an instruction leaves behind.
    ///
    /// Fed as one run and as an arbitrary split of the same bytes, in order.
    /// The oracle is the whole run rather than a second implementation, which
    /// is what makes this a property of the cutting alone.
    #[test]
    fn a_qpack_stream_is_judged_the_same_however_it_is_cut() {
        proptest::proptest!(|(bytes: Vec<u8>, cuts: Vec<u8>, encoder: bool)| {
            let kind = if encoder {
                QpackStream::Encoder
            } else {
                QpackStream::Decoder
            };

            // Each cut is somewhere in the sequence, including both ends, so an
            // empty fragment is a shape the peer can send and this can produce.
            let mut points: Vec<usize> = cuts
                .iter()
                .map(|cut| usize::from(*cut) % (bytes.len() + 1))
                .collect();
            points.sort_unstable();

            let mut fragments: Vec<&[u8]> = Vec::new();
            let mut at = 0usize;
            for point in points {
                fragments.push(&bytes[at..point]);
                at = point;
            }
            fragments.push(&bytes[at..]);

            proptest::prop_assert_eq!(
                judge_qpack(kind, &fragments),
                judge_qpack(kind, &[&bytes[..]])
            );
        });
    }

    #[test]
    fn a_goaway_identifier_may_shrink_but_not_grow() {
        let shared = Shared::default();
        let mut control = Control::default();
        control.accept(settings(true), &shared).expect("accepted");

        control
            .accept(Item::Frame(Frame::Goaway(12)), &shared)
            .expect("accepted");
        control
            .accept(Item::Frame(Frame::Goaway(8)), &shared)
            .expect("a smaller identifier is allowed");

        let error = control
            .accept(Item::Frame(Frame::Goaway(9)), &shared)
            .expect_err("refused");
        assert_eq!(error.code(), Code::H3_ID_ERROR);
    }

    /// The stream ids of client-initiated bidirectional streams are multiples
    /// of four, so "the next one" is four past the last (RFC 9000 §2.1).
    #[test]
    fn the_goaway_identifier_is_the_first_request_not_served() {
        assert_eq!(REQUEST_STREAM_STEP, 4);
        assert_eq!(next_request_id(None), 0);
        assert_eq!(next_request_id(Some(0)), 4);
        assert_eq!(next_request_id(Some(16)), 20);
    }

    /// The identifier is written as a QUIC varint, so the arithmetic must stay
    /// inside one however absurd the stream id it starts from. A saturating
    /// `u64::MAX` would reach `put_varint`'s assertion instead of the wire.
    #[test]
    fn the_goaway_identifier_stays_inside_a_varint() {
        let max = crate::datagram::VARINT_MAX;

        for last_accepted in [max - REQUEST_STREAM_STEP, max, u64::MAX] {
            let identifier = next_request_id(Some(last_accepted));
            assert!(
                identifier <= max,
                "{last_accepted} produced {identifier}, past the varint maximum"
            );
            // Encodable is the property that matters: this is the call
            // `shutdown` makes.
            let mut buf = BytesMut::new();
            put_varint(&mut buf, identifier);
        }

        assert_eq!(next_request_id(Some(max - REQUEST_STREAM_STEP)), max);
    }

    /// Two tasks can reach a violation at the same moment; only one of them
    /// wins, and the winner has to be the one the close and the report agree
    /// on.
    #[test]
    fn only_the_first_violation_is_kept_and_it_is_the_one_reported() {
        let shared = Shared::default();

        let first = Violation::connection(Code::H3_FRAME_UNEXPECTED, "the first one");
        let second = Violation::connection(Code::H3_ID_ERROR, "the second one");

        assert_eq!(shared.record(first.clone()), first);
        // The second caller is told what will actually be on the wire, not what
        // it asked for.
        let reported = shared.record(second);
        assert_eq!(reported, first);
        assert_eq!(reported.code(), Code::H3_FRAME_UNEXPECTED);
    }

    /// A datagram as it arrives on the wire: two varints and a payload.
    fn datagram(quarter_stream_id: u64, context_id: u64, payload: &[u8]) -> datagram::Datagram {
        datagram::decode(datagram::encode(quarter_stream_id, context_id, payload))
            .expect("a well-formed datagram")
    }

    /// The routing rule itself: a datagram reaches the session that claimed its
    /// Quarter Stream ID and no other.
    ///
    /// The bug class this guards against is silent -- a session receiving
    /// another's traffic looks exactly like a session that works -- so both
    /// halves are asserted: what each receiver got, and that neither got the
    /// other's.
    #[tokio::test]
    async fn a_datagram_reaches_the_session_that_claimed_its_quarter_stream_id() {
        let shared = Arc::new(Shared::default());
        let mut first = shared.register_datagrams(1).expect("a free id");
        let mut second = shared.register_datagrams(2).expect("a free id");

        shared.deliver(datagram(1, datagram::CONTEXT_ID_UDP_PAYLOAD, b"for one"));
        shared.deliver(datagram(2, datagram::CONTEXT_ID_UDP_PAYLOAD, b"for two"));

        assert_eq!(
            recv_within(&mut first).await.as_deref(),
            Some(b"for one".as_slice())
        );
        assert_eq!(
            recv_within(&mut second).await.as_deref(),
            Some(b"for two".as_slice())
        );
        assert!(first.inbound.try_recv().is_err(), "one payload each");
        assert!(second.inbound.try_recv().is_err(), "one payload each");
    }

    /// The claim lasts exactly as long as the receiver: this is what keeps the
    /// table from leaking an entry per session, and what makes a datagram for a
    /// session that has ended a drop rather than a delivery to a queue nobody
    /// reads.
    #[tokio::test]
    async fn dropping_the_receiver_gives_up_the_quarter_stream_id() {
        let shared = Arc::new(Shared::default());

        let inbound = shared.register_datagrams(1).expect("a free id");
        assert!(
            shared.register_datagrams(1).is_none(),
            "a claimed id must not be handed out twice"
        );
        drop(inbound);

        assert!(shared.lock().is_empty(), "the entry must be gone");

        // Which is observable from the outside: the id is free again, and a
        // datagram that arrives in between is dropped instead of piling up in
        // the queue the finished session left behind.
        shared.deliver(datagram(1, datagram::CONTEXT_ID_UDP_PAYLOAD, b"too late"));
        let mut reopened = shared.register_datagrams(1).expect("free again");
        assert!(
            reopened.inbound.try_recv().is_err(),
            "a new session must not inherit a finished one's datagrams"
        );
    }

    /// The same claim over a churn of sessions: the table returns to its
    /// baseline every time, rather than to its baseline plus one.
    ///
    /// The single-session test above proves the entry goes; this proves the
    /// table is *flat*, which is the property a server that runs for weeks
    /// depends on and the one a single cycle cannot tell apart from a leak. A
    /// live session is held throughout so the baseline is non-empty: a table
    /// that grew by an entry per session would still be "back to one" after the
    /// first cycle and only diverge after many, which is exactly the shape that
    /// hides at N = 1.
    #[tokio::test]
    async fn the_routing_table_is_flat_across_a_churn_of_sessions() {
        const CHURN: u64 = 512;

        let shared = Arc::new(Shared::default());
        let held = shared.register_datagrams(0).expect("a free id");

        for id in 1..=CHURN {
            let inbound = shared.register_datagrams(id).expect("a free id");
            assert_eq!(
                shared.lock().len(),
                2,
                "one held session and one live one, whatever id {id} we are on"
            );
            drop(inbound);
            assert_eq!(
                shared.lock().len(),
                1,
                "session {id} took its entry with it"
            );
        }

        drop(held);
        assert!(
            shared.lock().is_empty(),
            "nothing is left once the last session has gone"
        );
    }

    /// The same table with the router and the sessions running at once.
    ///
    /// Every test above drives it one step at a time, which is the one ordering
    /// the server never produces: [`serve_peer`] routes datagrams on a task of
    /// its own while the sessions on the connection claim and give up their
    /// Quarter Stream IDs on theirs, so a delivery and a claim ending race by
    /// construction. Three failures could hide in that race and all three are
    /// silent -- a payload handed to the session next door, an entry left behind
    /// by a receiver that was being delivered to as it dropped, and an id a
    /// session cannot re-claim because its own entry outlived it -- so all three
    /// are asserted rather than inferred from the table being the right size.
    ///
    /// Bounded on both sides: the sessions do a fixed number of rounds, and the
    /// router stops on their last one or on its own deadline, whichever comes
    /// first, so nothing here can spin. Each session also *waits* for its first
    /// delivery rather than sampling for one -- `FIRST_DELIVERY` below says why
    /// -- so that what the assertions judge is the table rather than how the
    /// machine happened to schedule the router.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn delivery_racing_registration_neither_misroutes_nor_leaks() {
        const SESSIONS: u64 = 24;
        const ROUNDS: usize = 128;
        /// How long a session waits for its first delivery before the run is
        /// judged to have failed rather than to have been unlucky.
        ///
        /// The sessions and the router race by design, and on a loaded machine
        /// the router can lose that race outright: it is one task against
        /// `SESSIONS` of them, and a session that only ever `try_recv`s can run
        /// all `ROUNDS` of its loop through an empty queue and finish having
        /// received nothing. That is this test's own scheduling, not a routing
        /// fault, and it used to surface as the "nothing was ever routed"
        /// assertion failing under parallel load.
        ///
        /// Waiting once per session fixes the shape rather than the symptom --
        /// every session now starts from a delivery it can account for, and the
        /// churn of claims and drops that actually runs the race is unchanged
        /// in the `ROUNDS - 1` rounds after it. Nothing here is being measured,
        /// so the number only has to outlast any scheduling delay while staying
        /// well inside the router's own 30s deadline.
        const FIRST_DELIVERY: Duration = Duration::from_secs(10);

        let shared = Arc::new(Shared::default());
        let stop = Arc::new(AtomicBool::new(false));
        let sent = Arc::new(AtomicU64::new(0));

        // The router: every id, over and over, whether or not anyone is there.
        let router = tokio::spawn({
            let shared = shared.clone();
            let stop = stop.clone();
            let sent = sent.clone();
            async move {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                while !stop.load(Ordering::Relaxed) && tokio::time::Instant::now() < deadline {
                    for id in 0..SESSIONS {
                        // The payload names the session it is for, which is how
                        // a misroute is told from an ordinary drop.
                        shared.deliver(datagram(
                            id,
                            datagram::CONTEXT_ID_UDP_PAYLOAD,
                            &id.to_be_bytes(),
                        ));
                        sent.fetch_add(1, Ordering::Relaxed);
                    }
                    tokio::task::yield_now().await;
                }
            }
        });

        // The sessions: each one opens, drains what it was given, and closes.
        let sessions: Vec<_> = (0..SESSIONS)
            .map(|id| {
                let shared = shared.clone();
                tokio::spawn(async move {
                    let mut received = 0u64;
                    for round in 0..ROUNDS {
                        let mut inbound = shared.register_datagrams(id).unwrap_or_else(|| {
                            panic!("session {id} could not re-claim its own id on round {round}")
                        });

                        // The one blocking wait, and only on the round that has
                        // no predecessor to have left anything in the queue.
                        // What arrives here is a delivery like any other, so it
                        // is held to the same misroute assertion and counted
                        // the same way.
                        if round == 0 {
                            let first = tokio::time::timeout(
                                FIRST_DELIVERY,
                                inbound.inbound.recv(),
                            )
                            .await
                            .unwrap_or_else(|_| {
                                panic!(
                                    "session {id} was not delivered to within {FIRST_DELIVERY:?}"
                                )
                            })
                            .unwrap_or_else(|| {
                                panic!("session {id}'s queue closed while it held the receiver")
                            });
                            assert_eq!(
                                first.as_ref(),
                                id.to_be_bytes().as_slice(),
                                "session {id} was handed another session's payload"
                            );
                            received += 1;
                        }

                        while let Ok(payload) = inbound.inbound.try_recv() {
                            assert_eq!(
                                payload.as_ref(),
                                id.to_be_bytes().as_slice(),
                                "session {id} was handed another session's payload"
                            );
                            received += 1;
                        }
                        drop(inbound);
                        tokio::task::yield_now().await;
                    }
                    received
                })
            })
            .collect();

        let mut received = 0u64;
        for session in sessions {
            received += session.await.expect("session task");
        }
        stop.store(true, Ordering::Relaxed);
        router.await.expect("router task");

        assert!(
            shared.lock().is_empty(),
            "an entry outlived the receiver that owned it"
        );
        assert!(
            received > 0,
            "nothing was ever routed, so the race was never run"
        );
        assert!(
            received <= sent.load(Ordering::Relaxed),
            "more payloads arrived than were ever sent"
        );
    }

    /// Both of the drops RFC 9297 §2.1 and RFC 9298 §5 call for, and the
    /// session surviving each of them.
    #[tokio::test]
    async fn unknown_ids_are_dropped_and_the_session_survives() {
        let shared = Arc::new(Shared::default());
        let mut inbound = shared.register_datagrams(1).expect("a free id");

        // A Quarter Stream ID no session owns: legitimate whenever a session
        // closes with packets still in flight.
        shared.deliver(datagram(9, datagram::CONTEXT_ID_UDP_PAYLOAD, b"nowhere"));
        // A context this server never registered (RFC 9298 §5).
        shared.deliver(datagram(1, 9, b"unknown context"));

        assert!(
            inbound.inbound.try_recv().is_err(),
            "neither may reach a session"
        );
        assert_eq!(
            shared.dropped_datagrams.load(Ordering::Relaxed),
            2,
            "both drops are counted for the closing line"
        );

        shared.deliver(datagram(1, datagram::CONTEXT_ID_UDP_PAYLOAD, b"still here"));
        assert_eq!(
            recv_within(&mut inbound).await.as_deref(),
            Some(b"still here".as_slice())
        );
        assert_eq!(
            shared.dropped_datagrams.load(Ordering::Relaxed),
            2,
            "a delivery is not a drop"
        );
    }

    /// RFC 9298 §5 lets a client send UDP payloads before the response arrives,
    /// and lets the proxy buffer them. Claiming the Quarter Stream ID before the
    /// target socket exists is what turns that permission into behaviour: a
    /// datagram the router delivers while the session loop has not started yet
    /// must still be there when it does — once, in order, and without a consumer
    /// running.
    ///
    /// Deterministic on purpose: forcing that ordering through a live server
    /// would mean racing the resolver, so the guarantee is asserted where it
    /// actually lives, on the routing table and its queue.
    #[tokio::test]
    async fn datagrams_delivered_before_the_session_starts_are_kept() {
        let shared = Arc::new(Shared::default());
        let mut inbound = shared.register_datagrams(9).expect("a free id");

        for payload in [b"first".as_slice(), b"second".as_slice()] {
            shared.deliver(datagram(9, datagram::CONTEXT_ID_UDP_PAYLOAD, payload));
        }

        // The session loop starts only now.
        assert_eq!(
            recv_within(&mut inbound).await.as_deref(),
            Some(b"first".as_slice())
        );
        assert_eq!(
            recv_within(&mut inbound).await.as_deref(),
            Some(b"second".as_slice())
        );
        assert!(
            inbound.inbound.try_recv().is_err(),
            "a buffered datagram must be delivered once, not replayed"
        );
    }

    /// The other half of the same design: the buffer is bounded by
    /// [`INBOUND_QUEUE_DEPTH`], and the router drops rather than blocks or grows
    /// when a session is not draining it.
    #[tokio::test]
    async fn the_early_buffer_is_bounded_and_the_overflow_is_dropped() {
        let shared = Arc::new(Shared::default());
        let mut inbound = shared.register_datagrams(9).expect("a free id");

        for index in 0..INBOUND_QUEUE_DEPTH {
            shared.deliver(datagram(
                9,
                datagram::CONTEXT_ID_UDP_PAYLOAD,
                &[index as u8],
            ));
        }
        shared.deliver(datagram(
            9,
            datagram::CONTEXT_ID_UDP_PAYLOAD,
            b"past the depth",
        ));

        for index in 0..INBOUND_QUEUE_DEPTH {
            assert_eq!(
                recv_within(&mut inbound).await.as_deref(),
                Some([index as u8].as_slice()),
                "everything within the depth is kept, in order"
            );
        }
        assert!(
            inbound.inbound.try_recv().is_err(),
            "the queue must stop accepting at its depth rather than grow"
        );
        assert_eq!(
            shared.dropped_datagrams.load(Ordering::Relaxed),
            1,
            "the overflow is the one drop this connection saw, and it is counted"
        );
    }

    /// A drop shape speaks on the doubling schedule; every drop counts.
    ///
    /// Eight drops rather than three, because the schedule itself is the
    /// assertion now: a report has to land on the 1st, 2nd, 4th and 8th drop
    /// and on none of the others, and each has to carry the running total. The
    /// two mutations a weaker test would let through -- reporting always, and
    /// reporting on every call but the first -- both produce a sequence this
    /// one names as wrong.
    #[test]
    fn a_drop_shape_is_reported_on_a_doubling_schedule_and_counted_every_time() {
        let shared = Shared::default();
        let mut reports: Vec<u64> = Vec::new();
        for _ in 0..8 {
            shared.count_drop(DropKind::Unroutable, |drops| reports.push(drops));
        }
        assert_eq!(
            reports,
            vec![1, 2, 4, 8],
            "the first drop is as loud as it ever was, and the reports that follow \
             say how far the count has got"
        );
        assert_eq!(
            shared.dropped_datagrams.load(Ordering::Relaxed),
            8,
            "every drop is counted, reported or not"
        );
        // A different shape keeps its own schedule, from its own first drop.
        shared.count_drop(DropKind::QueueFull, |drops| reports.push(drops));
        assert_eq!(reports, vec![1, 2, 4, 8, 1], "each shape speaks for itself");
    }

    /// RFC 9114 §6.2.1 stands while the connection does; once it is over, the
    /// same FIN is the peer saying goodbye a packet early.
    #[test]
    fn a_control_stream_fin_is_a_fault_only_while_the_connection_lives() {
        let violation = control_stream_finished(None).expect("a live connection must report it");
        assert_eq!(violation.code(), Code::H3_CLOSED_CRITICAL_STREAM);
        assert!(violation.is_connection_error());

        for closed in [
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(0),
                reason: Bytes::new(),
            }),
            quinn::ConnectionError::TimedOut,
            quinn::ConnectionError::LocallyClosed,
        ] {
            assert!(
                control_stream_finished(Some(&closed)).is_none(),
                "a connection already closed by {closed} needs no fault report"
            );
        }
    }
}
