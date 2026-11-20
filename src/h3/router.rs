//! The routing of the peer's HTTP Datagrams (RFC 9297) to the request stream
//! each one names, and the hold for datagrams that arrive before their session
//! has claimed its Quarter Stream ID (D79, D114).
//!
//! This is the datagram surface a peer reaches before any request has
//! authenticated. The routing state lives in the connection's `Shared`; the
//! methods that read and write it are here.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::ops::ControlFlow;
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::debug;

use crate::datagram;

use super::connection::{Handle, Shared};
use super::error::{Code, Violation};

/// Which way an inbound HTTP Datagram was dropped, and so which of [`Shared`]'s
/// four samplers keeps its schedule.
///
/// Naming the shape rather than passing [`Shared::count_drop`] one of its own
/// fields keeps the choice of sampler in one place. A fifth shape then fails to
/// compile until it has a sampler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropKind {
    /// A Context ID this server has no extension for (RFC 9298 §5).
    UnknownContext,
    /// A Quarter Stream ID no session claims, including a held datagram whose
    /// session never claimed it in time.
    Unroutable,
    /// A session whose inbound queue was full.
    QueueFull,
    /// A datagram cut short of its Context ID.
    Malformed,
}

impl Shared {
    /// Claims `quarter_stream_id` for a session, or reports that it is taken.
    ///
    /// `None` means an entry already exists, which is a caller asking twice for
    /// one stream: the receiver was handed out once and a second one would
    /// deregister the first on drop. The map is the guard, so there is no
    /// separate flag to keep in step with it.
    ///
    /// The datagrams held for this Quarter Stream ID go into the new queue
    /// here, in the order they arrived, before the lock is released. So they
    /// are ahead of every datagram the router delivers after the claim.
    pub(super) fn register_datagrams(
        self: &Arc<Self>,
        quarter_stream_id: u64,
    ) -> Option<DatagramReceiver> {
        self.register_datagrams_at(quarter_stream_id, Instant::now)
    }

    /// [`Self::register_datagrams`] with the clock passed in, so a test can
    /// step it. `now` is read only if something is held.
    fn register_datagrams_at(
        self: &Arc<Self>,
        quarter_stream_id: u64,
        now: impl FnOnce() -> Instant,
    ) -> Option<DatagramReceiver> {
        let (sink, inbound) = mpsc::channel(INBOUND_QUEUE_DEPTH);

        let mut routes = self.lock();
        match routes.sessions.entry(quarter_stream_id) {
            Entry::Occupied(_) => return None,
            Entry::Vacant(slot) => slot.insert(sink),
        };
        routes.claimed(quarter_stream_id);
        let (expired, released) = if routes.early.is_empty() {
            (Vec::new(), 0)
        } else {
            (routes.expire(now()), routes.release(quarter_stream_id))
        };
        drop(routes);

        self.count_expired(expired);
        if released > 0 {
            debug!(
                quarter_stream_id,
                released, "delivering datagrams that arrived before their session"
            );
        }

        Some(DatagramReceiver {
            shared: Arc::clone(self),
            quarter_stream_id,
            inbound,
        })
    }

    /// Hands one decoded datagram to the session that claimed its Quarter
    /// Stream ID, holds it for a session that may be about to claim it, or
    /// drops it.
    ///
    /// Every outcome here is a drop rather than an error. RFC 9297 §2.1's two
    /// MUST-close conditions are about the Quarter Stream ID *field* and are
    /// settled before this is reached, by [`crate::datagram::decode`]; what is
    /// left is a well-formed datagram with nowhere to go, which happens
    /// routinely when a session closes with packets still in flight.
    fn deliver(&self, decoded: datagram::Datagram) {
        self.deliver_at(decoded, Instant::now);
    }

    /// [`Self::deliver`] with the clock passed in, so a test can step it.
    /// `now` is read only on the way into the hold.
    fn deliver_at(&self, decoded: datagram::Datagram, now: impl FnOnce() -> Instant) {
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

        let quarter_stream_id = decoded.quarter_stream_id;

        // One lock for the lookup and, on a miss, the hold. `try_send` is
        // inside it too: it never waits, and sending inside the guard saves a
        // sender clone (two refcount bumps) on every datagram routed.
        let (routed, expired) = {
            let mut routes = self.lock();
            match routes.sessions.get(&quarter_stream_id) {
                Some(inbound) => {
                    let routed = if enqueue(inbound, decoded.payload) {
                        Routed::Queued
                    } else {
                        Routed::QueueFull
                    };
                    (routed, Vec::new())
                }
                None if routes.may_hold(quarter_stream_id) => {
                    //= https://www.rfc-editor.org/rfc/rfc9297#section-2.1
                    //# If an HTTP/3 Datagram is received and its Quarter Stream ID field
                    //# maps to a stream that has not yet been created, the receiver SHALL
                    //# either drop that datagram silently or buffer it temporarily (on the
                    //# order of a round trip) while awaiting the creation of the
                    //# corresponding stream.
                    //
                    // The second choice, bounded by `EARLY_DATAGRAMS` and
                    // `EARLY_DATAGRAM_HOLD`. Expired entries go first, so a
                    // full hold is full of datagrams that are still current.
                    let now = now();
                    let expired = routes.expire(now);
                    (
                        routes.hold(quarter_stream_id, &decoded.payload, now),
                        expired,
                    )
                }
                None => (Routed::Unroutable, Vec::new()),
            }
        };

        self.count_expired(expired);
        match routed {
            Routed::Queued | Routed::Held => {}
            Routed::Unroutable => self.count_unroutable(quarter_stream_id),
            // Never block the router on one slow session: dropping a UDP
            // packet is legitimate, stalling every other session is not.
            Routed::QueueFull => self.count_drop(DropKind::QueueFull, |drops| {
                debug!(
                    quarter_stream_id,
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
    /// The count is for the closing line in [`crate::quic`]. The reports are
    /// for a debug log, and each carries the running total of its own shape.
    /// Everything is `Relaxed` because nothing is published through either
    /// atomic: each is a single read-modify-write ordered against nothing else.
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

    /// Counts one datagram for a Quarter Stream ID no session claims.
    fn count_unroutable(&self, quarter_stream_id: u64) {
        self.count_drop(DropKind::Unroutable, |drops| {
            debug!(
                quarter_stream_id,
                drops,
                "dropping datagrams for sessions that do not exist; further ones are \
                 logged as the count doubles"
            )
        });
    }

    /// Counts the held datagrams that were let go unclaimed, expired or
    /// dropped with the connection, after the lock that took them out of the
    /// hold is released.
    ///
    /// Each is a datagram whose session never claimed it, so each is the
    /// unroutable drop it would have been without the hold, only later.
    fn count_expired(&self, expired: impl IntoIterator<Item = Early>) {
        for early in expired {
            self.count_unroutable(early.quarter_stream_id);
        }
    }

    /// Lets go of every held datagram, and holds no more from now on.
    ///
    /// Called when the connection is dropped, so that nothing held outlives
    /// it and every held datagram is counted before the connection's closing
    /// line reads the count. After this a datagram with no session is dropped
    /// at once.
    pub(super) fn close_routes(&self) {
        let held = {
            let mut routes = self.lock();
            routes.closed = true;
            std::mem::take(&mut routes.early)
        };
        self.count_expired(held);
    }

    /// The routing table and the hold, with a poisoned lock treated as an
    /// ordinary one.
    ///
    /// A panic elsewhere in the process says nothing about the state behind
    /// this lock. Each step under it leaves a state the next holder can use:
    /// the claim is inserted before held datagrams are moved into it, so an
    /// interruption between the two leaves a held datagram that waits out its
    /// hold time like any other.
    fn lock(&self) -> std::sync::MutexGuard<'_, Routes> {
        self.routes.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What [`Shared::deliver`] did with one datagram of Context ID 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Routed {
    /// It is on its session's queue.
    Queued,
    /// Its session's queue was full.
    QueueFull,
    /// It is in the hold, waiting for its session to claim it.
    Held,
    /// No session claims it and none can still come to: dropped.
    Unroutable,
}

/// HTTP Datagrams held per connection for sessions that have not claimed their
/// Quarter Stream ID yet (D114).
///
/// A client may send the first payload of a tunnel in the same flight as the
/// CONNECT-UDP request (RFC 9298 §5 allows it), and the payload can reach the
/// router before the request has been decoded and authenticated. Without a
/// hold that payload is lost, and when it is a tunnelled QUIC Initial the
/// tunnelled handshake waits for its own retransmission, which is one second
/// at the start of a QUIC connection.
///
/// A client's first flight is one tunnelled Initial per tunnel, two when a
/// post-quantum key share does not fit in one, and a client may open a few
/// tunnels at once. Eight covers four tunnels opened together with two
/// Initials each. The hold is per connection and reachable before any request
/// has authenticated, so it is kept small: a full hold drops the newcomer and
/// never evicts a current entry, so a flood of datagrams cannot push out a
/// real first flight that arrived before it.
///
/// Each held payload is a copy of at most `max_udp_payload_size` bytes (1472
/// with quinn's default), never a slice of quinn's receive batch (see
/// `enqueue`), so the hold is at most 8 x 1472 = 11776 bytes of payload per
/// connection, about 11.5 KiB.
pub const EARLY_DATAGRAMS: usize = 8;

/// How long a datagram is held for a session that has not claimed it yet.
///
/// RFC 9297 §2.1 permits holding "on the order of a round trip". A connection
/// that has just been set up has no better figure for a round trip than the
/// one RFC 9002 §6.2.2 gives a QUIC handshake:
///
//= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.2
//# When no previous RTT is available, the initial RTT
//# SHOULD be set to 333 milliseconds.  This results in handshakes
//# starting with a PTO of 1 second, as recommended for TCP's initial
//# RTO; see Section 2 of [RFC6298].
///
/// The wait it has to cover is short. A session claims its Quarter Stream ID
/// as soon as its request is decoded, authenticated and known to be a
/// well-formed CONNECT-UDP request, before its target name is resolved. The
/// datagram and the request travel in the same flight, so the wait is that
/// processing, which takes about a millisecond, or one retransmission of the
/// request's packet if that packet was lost and the datagram's was not. 333 ms
/// covers the first with a wide margin and the second on a path whose round
/// trip is well below it. It is also well inside the 1 s after which a
/// tunnelled QUIC client resends its Initial itself, so a longer hold would
/// gain nothing.
///
/// This is how long a held datagram stays deliverable, not how long its memory
/// is kept. Expiry runs when the hold is touched, by another early datagram or
/// by a claim, and never on a timer, so on a connection where neither happens
/// an expired copy stays until the connection is dropped. What bounds the
/// memory in time is therefore the connection's own life, which for a peer
/// that has not authenticated is the bound `crate::conn` sets (D76).
///
/// A fixed figure rather than the connection's RTT estimate: the estimate is
/// quinn's, read per datagram, and the bound has to hold for a peer that has
/// not authenticated whatever its path does.
pub const EARLY_DATAGRAM_HOLD: Duration = Duration::from_millis(333);

// A session's queue takes everything held for it in one step.
const _: () = assert!(EARLY_DATAGRAMS <= INBOUND_QUEUE_DEPTH);

/// The connection's datagram routing table and its hold, which
/// [`Shared::lock`] guards together.
#[derive(Default)]
pub(super) struct Routes {
    /// Where an inbound HTTP Datagram goes, keyed by Quarter Stream ID.
    ///
    /// The whole of the connection's datagram routing: an entry is a live
    /// session's claim on one Quarter Stream ID, put there by
    /// [`Shared::register_datagrams`] and taken out again when the
    /// [`DatagramReceiver`] it belongs to is dropped. A request stream that
    /// never asks, such as every TCP tunnel, never appears here.
    sessions: HashMap<u64, mpsc::Sender<Bytes>>,
    /// Datagrams waiting for a claim, oldest first, at most
    /// [`EARLY_DATAGRAMS`].
    ///
    /// Arrival order is time order, because only the router adds to it and
    /// reads the clock under this lock, so expiry only ever looks at the
    /// front.
    early: VecDeque<Early>,
    /// The highest Quarter Stream ID any session on this connection has
    /// claimed.
    ///
    /// A datagram at or below it is never held. Its stream has been accepted
    /// already, because quinn hands out request streams in stream id order and
    /// a stream is claimed only after it was accepted. So the stream has
    /// claimed its id, and the datagram was routed, or it has closed, or it
    /// will never claim (a TCP tunnel, a refused request), or it is a
    /// CONNECT-UDP request still on its way to a claim that a later stream
    /// overtook. The last case is the one this mark gives up: such a datagram
    /// is dropped.
    ///
    /// The mark is the claimed one rather than the accepted one, because a
    /// datagram sent with its request can reach the router after the request
    /// was accepted and before it was claimed, and that is a case the hold is
    /// for (D114). The price is that a datagram for a TCP tunnel or a refused
    /// request above the mark is held, then dropped when its hold time ends,
    /// rather than dropped at once.
    highest_claimed: Option<u64>,
    /// Set when the connection is dropped; nothing is held after that.
    closed: bool,
}

/// One datagram in the hold.
struct Early {
    quarter_stream_id: u64,
    arrived: Instant,
    /// A copy, never a slice of quinn's receive batch.
    payload: Bytes,
}

impl Routes {
    /// Whether a datagram for `quarter_stream_id`, which no session claims,
    /// may be held for a session that has yet to claim it.
    fn may_hold(&self, quarter_stream_id: u64) -> bool {
        !self.closed
            && self
                .highest_claimed
                .is_none_or(|highest| quarter_stream_id > highest)
    }

    /// Records a claim, which moves the mark.
    fn claimed(&mut self, quarter_stream_id: u64) {
        // `None` orders below every `Some`.
        self.highest_claimed = self.highest_claimed.max(Some(quarter_stream_id));
    }

    /// Takes out every held datagram that has been held for
    /// [`EARLY_DATAGRAM_HOLD`] or longer, for the caller to count once the
    /// lock is released.
    fn expire(&mut self, now: Instant) -> Vec<Early> {
        let mut expired = Vec::new();
        while self.early.front().is_some_and(|early| {
            now.saturating_duration_since(early.arrived) >= EARLY_DATAGRAM_HOLD
        }) {
            expired.extend(self.early.pop_front());
        }
        expired
    }

    /// Holds a copy of `payload`, or reports that the hold is full.
    fn hold(&mut self, quarter_stream_id: u64, payload: &Bytes, now: Instant) -> Routed {
        if self.early.len() >= EARLY_DATAGRAMS {
            return Routed::Unroutable;
        }
        self.early.push_back(Early {
            quarter_stream_id,
            arrived: now,
            payload: Bytes::copy_from_slice(payload),
        });
        Routed::Held
    }

    /// Moves every datagram held for `quarter_stream_id` onto its session's
    /// queue, oldest first, and says how many there were.
    ///
    /// The queue was created with the claim and holds [`INBOUND_QUEUE_DEPTH`]
    /// payloads, more than the hold can, so every one fits. The payloads are
    /// copies already and go on as they are.
    fn release(&mut self, quarter_stream_id: u64) -> usize {
        let Some(inbound) = self.sessions.get(&quarter_stream_id) else {
            return 0;
        };
        let mut released = 0;
        self.early.retain_mut(|early| {
            if early.quarter_stream_id != quarter_stream_id {
                return true;
            }
            if inbound.try_send(std::mem::take(&mut early.payload)).is_ok() {
                released += 1;
            }
            false
        });
        released
    }
}

/// Puts one payload on a session's queue, and says whether it fit.
///
/// The payload is a slice of the buffer quinn received its whole batch into,
/// up to 64 packets with GRO, and a slice keeps that buffer allocated. So a
/// payload that will wait behind others is copied, at most
/// `max_udp_payload_size` bytes. One that goes into an empty queue is passed on
/// as it is: the copy would cost every datagram of a session that keeps up, and
/// the queue then holds at most one slice. A full queue refuses the payload
/// without a copy. The caller holds the routing lock, the only way into the
/// queue, so the capacity read here is still true at the send, except that the
/// session may take a payload in between, which only makes room.
fn enqueue(inbound: &mpsc::Sender<Bytes>, payload: Bytes) -> bool {
    match inbound.capacity() {
        0 => false,
        free if free == inbound.max_capacity() => inbound.try_send(payload).is_ok(),
        _ => inbound.try_send(Bytes::copy_from_slice(&payload)).is_ok(),
    }
}

/// Inbound datagrams buffered per session before packets start being dropped.
///
/// Bounded on purpose: UDP allows loss, whereas an unbounded queue would let a
/// slow target cause unbounded memory growth. The same queue serves both phases
/// of a session: before the target socket exists, where it holds what RFC 9298
/// §5 calls optimistically sent packets, and while it runs. So this constant is
/// the whole per-session bound on queued datagrams.
///
/// # What a session costs at the configured limits
///
/// A session holds three buffers, and this constant sizes only the first.
///
/// * The queue. A QUIC DATAGRAM frame cannot be fragmented, so a datagram never
///   exceeds the `max_udp_payload_size` this server advertises (quinn's
///   default, 1472 bytes): 64 of them are about 92 KiB. A payload that waits
///   behind others is a copy, and the one in an empty queue may be a slice
///   that keeps a whole GRO batch alive, at most 94208 bytes (`enqueue`), so
///   the worst case is 63 copies and one batch, about 183 KiB.
/// * The block a running session receives its *target's* packets into
///   ([`crate::tunnel`]'s UDP path), 16 KiB, allocated only once the target
///   first sends.
/// * The [`crate::capsule::CapsuleDecoder`] on the request stream, which holds
///   at most one DATAGRAM capsule value,
///   [`crate::capsule::MAX_DATAGRAM_CAPSULE_VALUE`], about 64 KiB, until the
///   session's idle timeout
///   (`tests/it_bounds.rs::a_session_holds_one_unfinished_capsule_and_no_more`
///   and `a_decoder_keeps_one_unfinished_capsule_of_a_large_chunk`).
///
/// A session therefore costs about 263 KiB at worst, 172 KiB without GRO (as
/// on macOS), and a server that times `max_targets_per_conn` times
/// `max_connections`: with the shipped defaults of 256 and 256, about 66 MiB
/// per connection and 16.4 GiB across a server saturated at both limits.
/// Lowering either limit lowers it proportionally. All three are released by
/// dropping what owns them, on every path a session ends by
/// (`tests/it_bounds.rs::a_connection_keeps_nothing_for_the_sessions_it_has_closed`).
///
/// Registering a session before its target socket exists does **not** raise
/// that ceiling: the queue is the same size in both phases, sessions are still
/// capped by the per-connection tunnel quota, and a full queue is already
/// reachable on a running session. It only bounds how long a full queue can
/// stay undrained by how long name resolution takes.
///
/// Beside the sessions, each connection has one hold of about 11.5 KiB for
/// datagrams that arrive before their session has claimed them
/// ([`EARLY_DATAGRAMS`]). It does not grow with the number of sessions, and it
/// is reachable before authentication: about 2.9 MiB across the default
/// `max_connections` of 256.
pub const INBOUND_QUEUE_DEPTH: usize = 64;

/// One session's inbound HTTP Datagrams, and its claim on a Quarter Stream ID.
///
/// Obtained from [`Stream::datagrams`](super::stream::Stream::datagrams) and
/// held for the life of the session. Dropping it takes the Quarter Stream ID
/// out of the connection's routing table, so the table does not leak entries.
/// A session can end on several paths (refused before it started, idle, reset,
/// its socket broken), and every one of them drops this.
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
    /// Never returns `None` while this receiver exists: the sending half is in
    /// the routing table under this receiver's own entry, which only the
    /// receiver's drop removes, and closing the connection leaves it there. So
    /// once the connection has ended this stays pending, and a session learns
    /// of the end from its request stream.
    ///
    /// Cancel-safe ([`tokio::sync::mpsc::Receiver::recv`] is), so a session may
    /// poll it inside a `select!` with a timeout. A UDP session does that with
    /// all three of its sources.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.inbound.recv().await
    }

    /// Takes the next payload routed to this session if one is already queued,
    /// without waiting.
    ///
    /// `None` means nothing is queued at this moment, so a caller that drains
    /// the queue with this goes back to [`Self::recv`] once it sees `None`.
    pub fn try_recv(&mut self) -> Option<Bytes> {
        self.inbound.try_recv().ok()
    }
}

impl Drop for DatagramReceiver {
    fn drop(&mut self) {
        self.shared.lock().sessions.remove(&self.quarter_stream_id);
    }
}

/// Decodes one QUIC datagram and delivers it, or ends the connection.
///
/// What happens to a datagram that cannot be delivered depends on *why*, and
/// RFC 9297 §2.1 draws the lines:
///
/// * a Quarter Stream ID that cannot be parsed, or one above 2^60-1, is a
///   **connection error** of type H3_DATAGRAM_ERROR. Neither can name a QUIC
///   stream, so there is nothing to drop it *for*;
/// * a Quarter Stream ID with no live session is **held** for a short time if
///   its session may still claim it, and **dropped** otherwise. The RFC permits
///   both for a datagram whose request stream does not exist yet, and permits
///   the drop for one whose stream has closed, which happens routinely when a
///   session closes with packets still in flight;
/// * a datagram whose Context ID is truncated or unknown is likewise dropped.
///
/// One SHOULD is deliberately not implemented: a Quarter Stream ID naming a
/// stream "that cannot be created due to client-initiated bidirectional stream
/// limits" SHOULD draw H3_ID_ERROR. Those are this endpoint's limits, not the
/// peer's, because `initial_max_streams_bidi` is a transport parameter a
/// receiver advertises. RFC 9297 §2.1 grants the exemption this router relies
/// on:
/// "Generating an error is not mandatory because the QUIC stream limit might be
/// unknown to the HTTP/3 layer". It is unknown to this one. The limit is set by
/// [`crate::quic`] from `[limits] max_streams_bidi` and nothing here reads it,
/// so a Quarter Stream ID past it cannot be told apart from a session that has
/// already closed. For the same reason the hold cannot refuse such an id: it
/// is bounded by its count and its hold time instead ([`EARLY_DATAGRAMS`]).
pub(super) fn route_datagram(handle: &Handle, datagram: Bytes) -> ControlFlow<()> {
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
        // disagree, and a datagram violation racing with a stream one ends the
        // connection once, with whichever was first.
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64};

    use bytes::{BufMut, BytesMut};

    use super::*;

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

    /// A datagram as it arrives on the wire: two varints and a payload.
    fn datagram(quarter_stream_id: u64, context_id: u64, payload: &[u8]) -> datagram::Datagram {
        datagram::decode(datagram::encode(quarter_stream_id, context_id, payload))
            .expect("a well-formed datagram")
    }

    /// The routing rule itself: a datagram reaches the session that claimed its
    /// Quarter Stream ID and no other.
    ///
    /// The bug class this guards against is silent: a session receiving
    /// another's traffic looks exactly like a session that works. So both
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

    /// `try_recv` hands out what is already queued, in order, and nothing
    /// more, without waiting.
    #[tokio::test]
    async fn try_recv_takes_what_is_queued_in_order() {
        let shared = Arc::new(Shared::default());
        let mut inbound = shared.register_datagrams(1).expect("a free id");

        assert_eq!(inbound.try_recv(), None, "nothing is queued yet");

        for payload in [&b"first"[..], b"second", b"third"] {
            shared.deliver(datagram(1, datagram::CONTEXT_ID_UDP_PAYLOAD, payload));
        }

        assert_eq!(inbound.try_recv().as_deref(), Some(b"first".as_slice()));
        assert_eq!(inbound.try_recv().as_deref(), Some(b"second".as_slice()));
        assert_eq!(inbound.try_recv().as_deref(), Some(b"third".as_slice()));
        assert_eq!(inbound.try_recv(), None, "three were queued");
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

        assert!(shared.lock().sessions.is_empty(), "the entry must be gone");

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

    /// A datagram that waits behind others in a session's queue is a copy, and
    /// one that goes into an empty queue is passed on as it is.
    ///
    /// A datagram's payload is a slice of the buffer quinn received its whole
    /// batch into, and a slice keeps that buffer allocated. With GRO on Linux a
    /// batch is up to 64 packets, so a queue of slices could hold up to 64
    /// batches. The copy is what keeps the queue at `INBOUND_QUEUE_DEPTH`
    /// payloads, and passing the first one uncopied is what keeps the copy off
    /// the path where the session keeps up.
    #[tokio::test]
    async fn a_datagram_that_waits_is_copied_out_of_its_batch() {
        /// A receive batch whose first packet is a datagram for session 1, and
        /// that datagram decoded as a slice of it.
        fn batch(payload: &[u8]) -> (Bytes, datagram::Datagram) {
            let packet = datagram::encode(1, datagram::CONTEXT_ID_UDP_PAYLOAD, payload);
            let mut batch = BytesMut::from(&packet[..]);
            batch.put_bytes(0, 16 * 1024);
            let batch = batch.freeze();
            let decoded = datagram::decode(batch.slice(..packet.len())).expect("well formed");
            (batch, decoded)
        }

        let shared = Arc::new(Shared::default());
        let mut inbound = shared.register_datagrams(1).expect("a free id");

        let (first_batch, first) = batch(b"first");
        let (second_batch, second) = batch(b"second");
        shared.deliver(first);
        shared.deliver(second);

        assert!(
            !first_batch.is_unique(),
            "a datagram delivered to an empty queue must not be copied"
        );
        assert!(
            second_batch.is_unique(),
            "a datagram queued behind another keeps its whole receive batch alive"
        );
        assert_eq!(inbound.try_recv().as_deref(), Some(b"first".as_slice()));
        assert_eq!(inbound.try_recv().as_deref(), Some(b"second".as_slice()));
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
                shared.lock().sessions.len(),
                2,
                "one held session and one live one, whatever id {id} we are on"
            );
            drop(inbound);
            assert_eq!(
                shared.lock().sessions.len(),
                1,
                "session {id} took its entry with it"
            );
        }

        drop(held);
        assert!(
            shared.lock().sessions.is_empty(),
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
    /// silent: a payload handed to the session next door, an entry left behind
    /// by a receiver that was being delivered to as it dropped, and an id a
    /// session cannot re-claim because its own entry outlived it. So all three
    /// are asserted rather than inferred from the table being the right size.
    ///
    /// Bounded on both sides: the sessions do a fixed number of rounds, and the
    /// router stops on their last one or on its own deadline, whichever comes
    /// first, so nothing here can spin. Each session also *waits* for its first
    /// delivery rather than sampling for one (`FIRST_DELIVERY` below says why),
    /// so that what the assertions judge is the table rather than how the
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
        /// fault, and it would fail the "nothing was ever routed" assertion.
        ///
        /// Waiting once per session fixes the shape rather than the symptom:
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
            shared.lock().sessions.is_empty(),
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
        drop(shared.register_datagrams(0).expect("a free id"));
        let mut inbound = shared.register_datagrams(1).expect("a free id");

        // A Quarter Stream ID no session owns: legitimate whenever a session
        // closes with packets still in flight. Session 0 has closed, so its
        // id is below the highest claimed one and is not held (D114).
        shared.deliver(datagram(0, datagram::CONTEXT_ID_UDP_PAYLOAD, b"nowhere"));
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
    /// must still be there when it does: once, in order, and without a consumer
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

        let depth = u8::try_from(INBOUND_QUEUE_DEPTH).expect("the depth fits a byte");
        for index in 0..depth {
            shared.deliver(datagram(9, datagram::CONTEXT_ID_UDP_PAYLOAD, &[index]));
        }
        shared.deliver(datagram(
            9,
            datagram::CONTEXT_ID_UDP_PAYLOAD,
            b"past the depth",
        ));

        for index in 0..depth {
            assert_eq!(
                recv_within(&mut inbound).await.as_deref(),
                Some([index].as_slice()),
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

    /// A datagram that arrives before its session claims its Quarter Stream ID
    /// is held and handed to the session when it does, ahead of anything that
    /// arrives after the claim (D114).
    #[tokio::test]
    async fn a_datagram_that_arrives_before_its_session_is_delivered_in_order() {
        let shared = Arc::new(Shared::default());

        shared.deliver(datagram(3, datagram::CONTEXT_ID_UDP_PAYLOAD, b"early"));
        shared.deliver(datagram(3, datagram::CONTEXT_ID_UDP_PAYLOAD, b"second"));
        let mut inbound = shared.register_datagrams(3).expect("a free id");
        shared.deliver(datagram(3, datagram::CONTEXT_ID_UDP_PAYLOAD, b"later"));

        assert_eq!(
            inbound.try_recv().as_deref(),
            Some(b"early".as_slice()),
            "a datagram held before the claim must be delivered by it"
        );
        assert_eq!(inbound.try_recv().as_deref(), Some(b"second".as_slice()));
        assert_eq!(inbound.try_recv().as_deref(), Some(b"later".as_slice()));
        assert_eq!(inbound.try_recv(), None, "each one once");
        assert_eq!(
            shared.dropped_datagrams.load(Ordering::Relaxed),
            0,
            "a delivered datagram is not a drop"
        );
        assert!(
            shared.lock().early.is_empty(),
            "the claim takes what was held for it"
        );
    }

    /// The hold keeps [`EARLY_DATAGRAMS`] and drops the newcomer past that,
    /// counted as unroutable, rather than evicting one it already has.
    #[test]
    fn the_hold_is_bounded_in_count_and_drops_the_newcomer() {
        let shared = Arc::new(Shared::default());
        let count = u8::try_from(EARLY_DATAGRAMS).expect("the count fits a byte");

        for index in 0..count {
            shared.deliver(datagram(5, datagram::CONTEXT_ID_UDP_PAYLOAD, &[index]));
        }
        shared.deliver(datagram(
            5,
            datagram::CONTEXT_ID_UDP_PAYLOAD,
            b"one too many",
        ));

        assert_eq!(shared.lock().early.len(), EARLY_DATAGRAMS);
        assert_eq!(
            shared.dropped_datagrams.load(Ordering::Relaxed),
            1,
            "the newcomer is dropped and counted"
        );

        let mut inbound = shared.register_datagrams(5).expect("a free id");
        for index in 0..count {
            assert_eq!(
                inbound.try_recv().as_deref(),
                Some([index].as_slice()),
                "the first ones are kept, in order"
            );
        }
        assert_eq!(inbound.try_recv(), None, "the newcomer was not kept");
    }

    /// A claim takes the datagrams held for its own Quarter Stream ID, in
    /// order, leaves the others held, and reports the number it moved.
    #[test]
    fn a_release_moves_only_its_own_session_and_says_how_many() {
        let shared = Arc::new(Shared::default());
        let start = Instant::now();
        shared.deliver_at(datagram(5, 0, b"one"), || start);
        shared.deliver_at(datagram(6, 0, b"other"), || start);
        shared.deliver_at(datagram(5, 0, b"two"), || start);

        let (sink, mut inbound) = mpsc::channel(INBOUND_QUEUE_DEPTH);
        let mut routes = shared.lock();
        routes.sessions.insert(5, sink);
        assert_eq!(routes.release(5), 2, "both datagrams held for session 5");
        assert_eq!(routes.early.len(), 1, "the one for session 6 stays held");
        assert_eq!(routes.release(5), 0, "nothing is left to release");
        drop(routes);

        assert_eq!(inbound.try_recv().ok().as_deref(), Some(b"one".as_slice()));
        assert_eq!(inbound.try_recv().ok().as_deref(), Some(b"two".as_slice()));
    }

    /// An unclaimed datagram is let go once it has been held for
    /// [`EARLY_DATAGRAM_HOLD`], when the hold is next touched, and counted.
    #[test]
    fn the_hold_is_bounded_in_time() {
        let shared = Arc::new(Shared::default());
        let start = Instant::now();
        let just_inside = EARLY_DATAGRAM_HOLD - Duration::from_millis(1);

        shared.deliver_at(datagram(5, 0, b"stale"), || start);
        shared.deliver_at(datagram(5, 0, b"fresh"), || start + just_inside);
        assert_eq!(
            shared.dropped_datagrams.load(Ordering::Relaxed),
            0,
            "neither has been held for the whole hold time yet"
        );

        let mut inbound = shared
            .register_datagrams_at(5, || start + EARLY_DATAGRAM_HOLD)
            .expect("a free id");
        assert_eq!(
            inbound.try_recv().as_deref(),
            Some(b"fresh".as_slice()),
            "only the datagram still inside its hold time is delivered"
        );
        assert_eq!(inbound.try_recv(), None);
        assert_eq!(
            shared.dropped_datagrams.load(Ordering::Relaxed),
            1,
            "the expired one is counted as a drop"
        );
        assert!(shared.lock().early.is_empty(), "nothing is left behind");
    }

    /// A full hold first lets go of what has expired, so expired entries never
    /// cost a current datagram its place.
    #[test]
    fn a_full_hold_makes_room_only_by_expiry() {
        let shared = Arc::new(Shared::default());
        let start = Instant::now();

        for _ in 0..EARLY_DATAGRAMS {
            shared.deliver_at(datagram(5, 0, b"old"), || start);
        }
        shared.deliver_at(datagram(6, 0, b"new"), || start + EARLY_DATAGRAM_HOLD);

        let early = &shared.lock().early;
        assert_eq!(
            early.len(),
            1,
            "the expired ones went and the newcomer stayed"
        );
        assert_eq!(early[0].quarter_stream_id, 6);
        assert_eq!(
            shared.dropped_datagrams.load(Ordering::Relaxed),
            u64::try_from(EARLY_DATAGRAMS).expect("small"),
            "each expired datagram is counted"
        );
    }

    /// Only a datagram whose stream may still claim it is held. A stream at or
    /// below the highest claimed id has been accepted already: it is a closed
    /// session, or a stream that never claimed (a TCP tunnel, a refused
    /// request), and its datagrams are dropped at once.
    #[test]
    fn a_datagram_for_a_stream_already_past_its_claim_is_not_held() {
        let shared = Arc::new(Shared::default());
        drop(shared.register_datagrams(4).expect("a free id"));

        // The session that claimed 4 has closed.
        shared.deliver(datagram(4, 0, b"after the close"));
        // 2 was accepted before 4 and never claimed.
        shared.deliver(datagram(2, 0, b"never claimed"));

        assert!(shared.lock().early.is_empty(), "neither may be held");
        assert_eq!(shared.dropped_datagrams.load(Ordering::Relaxed), 2);

        // Above the mark, the hold applies again.
        shared.deliver(datagram(5, 0, b"next request"));
        assert_eq!(shared.lock().early.len(), 1);
    }

    /// Only Context ID 0 is held. A datagram under any other Context ID is
    /// dropped at once even for a stream that may still claim its id, because
    /// no extension that could register that Context ID exists here (RFC 9298
    /// §5, the comment in [`Shared::deliver_at`]).
    #[test]
    fn an_unknown_context_id_is_never_held() {
        let shared = Arc::new(Shared::default());
        shared.deliver(datagram(5, 9, b"unknown context"));

        assert!(shared.lock().early.is_empty());
        assert_eq!(shared.dropped_datagrams.load(Ordering::Relaxed), 1);

        let mut inbound = shared.register_datagrams(5).expect("a free id");
        assert_eq!(inbound.try_recv(), None, "nothing was held for the claim");
    }

    /// What is held for one session is handed to that session and no other.
    #[test]
    fn a_held_datagram_reaches_only_its_own_session() {
        let shared = Arc::new(Shared::default());
        shared.deliver(datagram(6, 0, b"for six"));
        shared.deliver(datagram(7, 0, b"for seven"));
        shared.deliver(datagram(6, 0, b"for six again"));

        let mut seven = shared.register_datagrams(7).expect("a free id");
        assert_eq!(seven.try_recv().as_deref(), Some(b"for seven".as_slice()));
        assert_eq!(seven.try_recv(), None, "six's datagrams stay held");
        assert_eq!(shared.lock().early.len(), 2);

        // 6 is below the mark now, but what was held for it before 7 claimed
        // is still its own.
        let mut six = shared.register_datagrams(6).expect("a free id");
        assert_eq!(six.try_recv().as_deref(), Some(b"for six".as_slice()));
        assert_eq!(six.try_recv().as_deref(), Some(b"for six again".as_slice()));
        assert_eq!(six.try_recv(), None);
        assert_eq!(seven.try_recv(), None);
        assert!(shared.lock().early.is_empty());
        assert_eq!(shared.dropped_datagrams.load(Ordering::Relaxed), 0);
    }

    /// A held datagram is a copy, so the hold never keeps quinn's receive
    /// batch alive for the hold time.
    #[test]
    fn a_held_datagram_is_copied_out_of_its_batch() {
        let packet = datagram::encode(5, datagram::CONTEXT_ID_UDP_PAYLOAD, b"held");
        let mut batch = BytesMut::from(&packet[..]);
        batch.put_bytes(0, 16 * 1024);
        let batch = batch.freeze();
        let decoded = datagram::decode(batch.slice(..packet.len())).expect("well formed");

        let shared = Arc::new(Shared::default());
        shared.deliver(decoded);

        assert_eq!(shared.lock().early.len(), 1);
        assert!(
            batch.is_unique(),
            "a held datagram must not keep its receive batch alive"
        );
    }

    /// The hold does not outlive the connection: closing it lets go of and
    /// counts what was held, and nothing is held after.
    #[test]
    fn closing_the_connection_empties_the_hold() {
        let shared = Arc::new(Shared::default());
        shared.deliver(datagram(5, 0, b"one"));
        shared.deliver(datagram(6, 0, b"two"));

        shared.close_routes();
        assert!(shared.lock().early.is_empty());
        assert_eq!(
            shared.dropped_datagrams.load(Ordering::Relaxed),
            2,
            "what was held is counted before the closing line reads the count"
        );

        shared.deliver(datagram(7, 0, b"after the close"));
        assert!(shared.lock().early.is_empty(), "nothing is held after");
        assert_eq!(shared.dropped_datagrams.load(Ordering::Relaxed), 3);
    }

    /// Arbitrary interleavings of datagrams, claims, releases and clock steps,
    /// against the three bounds and the routing rule (D114).
    ///
    /// The standing check for code that runs before authentication. A
    /// cargo-fuzz target cannot reach [`Shared`], which is private to the
    /// crate, so the interleavings are generated here instead.
    ///
    /// Every payload names its Quarter Stream ID and its place in the sequence
    /// sent, so a datagram delivered to the wrong session, or out of order,
    /// is seen. At the end every datagram sent has been received or counted as
    /// a drop, exactly once.
    #[test]
    fn any_interleaving_keeps_the_hold_bounded_and_routes_nothing_astray() {
        use proptest::prelude::*;

        /// quinn's default `max_udp_payload_size`, which no datagram payload
        /// exceeds, so the byte bound is checked at its edge.
        const MAX_PAYLOAD: usize = 1472;

        #[derive(Debug, Clone)]
        enum Step {
            Datagram { id: u64, len: usize },
            Claim { id: u64 },
            Release { id: u64 },
            Wait { millis: u64 },
        }

        let step = prop_oneof![
            4 => (0u64..8, 9usize..=MAX_PAYLOAD).prop_map(|(id, len)| Step::Datagram { id, len }),
            2 => (0u64..8).prop_map(|id| Step::Claim { id }),
            1 => (0u64..8).prop_map(|id| Step::Release { id }),
            1 => (0u64..400).prop_map(|millis| Step::Wait { millis }),
        ];

        proptest!(|(steps in proptest::collection::vec(step, 0..120))| {
            let shared = Arc::new(Shared::default());
            let start = Instant::now();
            let mut now = start;
            let mut receivers: HashMap<u64, DatagramReceiver> = HashMap::new();
            let mut sent = 0u64;
            let mut received = 0u64;
            let mut last_seen: HashMap<u64, u64> = HashMap::new();

            for step in steps {
                let mut touched = false;
                match step {
                    Step::Datagram { id, len } => {
                        let mut payload = vec![0u8; len];
                        payload[..8].copy_from_slice(&sent.to_be_bytes());
                        payload[8] = u8::try_from(id).expect("small");
                        touched = {
                            let routes = shared.lock();
                            !routes.sessions.contains_key(&id) && routes.may_hold(id)
                        };
                        shared.deliver_at(datagram(id, 0, &payload), || now);
                        sent += 1;
                    }
                    Step::Claim { id } => {
                        if let Some(inbound) = shared.register_datagrams_at(id, || now) {
                            receivers.insert(id, inbound);
                            touched = true;
                        }
                    }
                    Step::Release { id } => {
                        receivers.remove(&id);
                    }
                    Step::Wait { millis } => now += Duration::from_millis(millis),
                }

                // Drain every live session, checking where each payload went.
                for (id, inbound) in &mut receivers {
                    while let Some(payload) = inbound.try_recv() {
                        prop_assert_eq!(u64::from(payload[8]), *id, "a payload reached another session");
                        let sequence = u64::from_be_bytes(payload[..8].try_into().expect("eight bytes"));
                        if let Some(previous) = last_seen.insert(*id, sequence) {
                            prop_assert!(previous < sequence, "session {} got its datagrams out of order", id);
                        }
                        received += 1;
                    }
                }

                let routes = shared.lock();
                prop_assert!(routes.early.len() <= EARLY_DATAGRAMS, "count bound");
                let bytes: usize = routes.early.iter().map(|early| early.payload.len()).sum();
                prop_assert!(bytes <= EARLY_DATAGRAMS * MAX_PAYLOAD, "byte bound");
                for early in &routes.early {
                    prop_assert!(
                        !routes.sessions.contains_key(&early.quarter_stream_id),
                        "a datagram is held for a session that has claimed it"
                    );
                }
                // Expiry is lazy, so an entry may stay past its hold time
                // until the hold is next touched, and no further. Every touch
                // that added or handed out an entry was at `now`.
                if touched {
                    for early in &routes.early {
                        prop_assert!(
                            now.saturating_duration_since(early.arrived) < EARLY_DATAGRAM_HOLD,
                            "an entry past its hold time survived a touch"
                        );
                    }
                }
            }

            drop(receivers);
            shared.close_routes();
            prop_assert!(shared.lock().early.is_empty());
            prop_assert_eq!(
                received + shared.dropped_datagrams.load(Ordering::Relaxed),
                sent,
                "every datagram is delivered or counted, once"
            );
        });
    }

    /// A drop shape speaks on the doubling schedule; every drop counts.
    ///
    /// Eight drops, because the schedule itself is the assertion: a report has
    /// to land on the 1st, 2nd, 4th and 8th drop and on none of the others, and
    /// each has to carry the running total. The two mutations a weaker test would let through, reporting always and
    /// reporting on every call but the first, both produce a sequence this one
    /// names as wrong.
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
}
