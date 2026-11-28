//! One server-side HTTP/3 connection: SETTINGS, the control stream, GOAWAY.
//!
//! # Shape
//!
//! A connection is three things:
//!
//! * the three unidirectional streams this endpoint opens and then holds open
//!   for its lifetime: control, QPACK encoder, QPACK decoder;
//! * a background task that serves everything the peer sends outside its
//!   request streams: its unidirectional streams, its control stream, and its
//!   HTTP Datagrams, and that watches this endpoint's three streams for a
//!   STOP_SENDING;
//! * [`Connection::accept`], which hands request streams to the caller.
//!
//! The background task reads the peer's control stream on its own, so the flag
//! the sessions hold ([`Connection::peer_settings`]) changes when SETTINGS is
//! read.
//!
//! A request can still be served before that reader has run, although the
//! peer sent its SETTINGS first: the request has a task of its own, and
//! nothing orders the two. A CONNECT-UDP session set up in that window would
//! send its first answers as capsules to a peer that asked for datagrams. So a
//! session waits for the frame to be read before it is set up, within a bound
//! that starts at the handshake ([`PeerSettings::read`],
//! [`PEER_SETTINGS_WAIT`], D119).
//!
//! # HTTP Datagrams
//!
//! That same task routes the peer's HTTP Datagrams (RFC 9297), because what a
//! datagram names is a request stream: the first varint of its payload is a
//! Quarter Stream ID, which is a request stream's id divided by four. A session
//! claims one by asking its stream for a [`DatagramReceiver`]
//! ([`Stream::datagrams`](super::stream::Stream::datagrams)) and holds the
//! claim for exactly as long as it holds the receiver. So a stream that ends,
//! on any path, removes its routing entry, and no code has to deregister it
//! (D79).
//!
//! A datagram can arrive before its session has claimed it: a client may send
//! the first payload in the same flight as the request, and the request still
//! has to be decoded and authenticated. Such a datagram is held, a few per
//! connection, and handed to the session if it claims its Quarter Stream ID
//! within a fraction of a second ([`EARLY_DATAGRAMS`], [`EARLY_DATAGRAM_HOLD`],
//! D114).
//!
//! # How a connection error is signalled
//!
//! RFC 9114 §8 defines an HTTP/3 connection error as a QUIC CONNECTION_CLOSE
//! carrying the HTTP/3 error code, which is what [`quinn::Connection::close`]
//! sends. So there is no error to propagate between tasks, because closing the
//! connection makes every operation on it fail on its own. Only the *reason*
//! has to be passed on, because quinn replaces it with "closed locally". It is
//! recorded when the connection is closed and read back by
//! [`Connection::accept`].

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::BytesMut;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tracing::debug;

use crate::varint::{VARINT_MAX_LEN, len_u64, put_varint, varint_len};

use super::control::{critical_stream_closed, serve_stream};
use super::error::{Code, ConnectionError, Violation};
use super::frame::{self, BufferBudget};
pub use super::router::{
    DatagramReceiver, EARLY_DATAGRAM_HOLD, EARLY_DATAGRAMS, INBOUND_QUEUE_DEPTH,
};
use super::router::{Router, route_datagram};
use super::stream::Resolver;
use super::varint;

/// Control stream (RFC 9114 §6.2.1).
pub(super) const STREAM_CONTROL: u64 = 0x00;
/// Push stream (RFC 9114 §6.2.2), which only a server may open.
pub(super) const STREAM_PUSH: u64 = 0x01;
/// QPACK encoder stream (RFC 9204 §4.2).
pub(super) const STREAM_QPACK_ENCODER: u64 = 0x02;
/// QPACK decoder stream (RFC 9204 §4.2).
pub(super) const STREAM_QPACK_DECODER: u64 = 0x03;

/// The distance between consecutive client-initiated bidirectional stream ids.
///
/// RFC 9000 §2.1: the two least significant bits of a stream id encode its
/// initiator and directionality, so each kind of stream is numbered in fours.
const REQUEST_STREAM_STEP: u64 = 4;

/// How long after the handshake a request that needs the peer's SETTINGS waits
/// for them to be read ([`PeerSettings::read`], D119).
///
/// The wait is for a frame the peer has to send before anything else:
///
//= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
//# Each side MUST initiate a single control stream at the beginning of
//# the connection and send its SETTINGS frame as the first frame on this
//# stream.
///
/// So in the usual case the frame is already here, or in the same flight as
/// the request, and the wait ends as soon as this endpoint's reader of the
/// control stream has run. The bound is for the two other cases. A peer that
/// sends no SETTINGS must not hold a request for good. And when the packet
/// that carried the frame was lost, the request is served without it after
/// the bound.
///
/// The figure is our own choice. It is the one RFC 9002 §6.2.2 gives for a
/// round trip that has not been measured, quoted on
/// [`EARLY_DATAGRAM_HOLD`], which bounds the mirror case of a datagram that
/// arrives ahead of its session.
///
/// The bound runs from the handshake and not from the request, because the
/// beginning of the connection is when the frame is due. A request that
/// arrives later than this after the handshake does not wait at all, so a
/// peer that never sends SETTINGS pays the wait once per connection and not
/// once per session.
pub const PEER_SETTINGS_WAIT: Duration = Duration::from_millis(333);

/// What the peer's SETTINGS say about HTTP Datagrams, and whether the frame
/// has been read.
///
/// A live view, not a copy: the reader of the peer's control stream writes
/// both halves, and every holder sees them change. The sessions in
/// `tunnel::udp` hold one through their connection's context.
#[derive(Clone, Debug)]
pub struct PeerSettings {
    /// Whether the peer advertised `SETTINGS_H3_DATAGRAM = 1`. The
    /// connection's own flag, [`Shared::peer_datagrams`].
    datagrams: Arc<AtomicBool>,
    /// True once the peer's SETTINGS frame has been read, whatever it said.
    read: watch::Receiver<bool>,
    /// When [`Self::read`] stops waiting: [`PEER_SETTINGS_WAIT`] after the
    /// handshake.
    wait_until: tokio::time::Instant,
}

impl PeerSettings {
    /// Whether the peer advertised `SETTINGS_H3_DATAGRAM = 1`.
    ///
    /// RFC 9297 §2.1.1 forbids sending HTTP Datagrams before this is true:
    ///
    //= https://www.rfc-editor.org/rfc/rfc9297#section-2.1.1
    //# QUIC DATAGRAM frames MUST NOT be sent until the SETTINGS_H3_DATAGRAM
    //# setting has been both sent and received with a value of 1.
    ///
    /// Until the peer's SETTINGS have been read it is `false`, which is the
    /// safe direction to be wrong in. One atomic load, because a session asks
    /// for every packet.
    pub fn datagrams(&self) -> bool {
        self.datagrams.load(Ordering::Relaxed)
    }

    /// Waits until the peer's SETTINGS frame has been read, or until
    /// [`PEER_SETTINGS_WAIT`] after the handshake, whichever comes first.
    ///
    /// Returns at once when either has already happened. It reports nothing:
    /// the caller reads [`Self::datagrams`] afterwards, which says `false`
    /// for SETTINGS that did not come in time just as it does for SETTINGS
    /// that do not allow datagrams, and the caller acts the same on both.
    pub async fn read(&self) {
        let mut read = self.read.clone();
        // The error is the sender dropped, which is the connection gone. The
        // caller finds that out from the stream it is about to write to.
        let _ = tokio::time::timeout_at(self.wait_until, read.wait_for(|read| *read)).await;
    }

    /// A view for tests that build a context without an HTTP/3 connection:
    /// the SETTINGS count as read, with `datagrams` as what they said.
    #[cfg(test)]
    pub(crate) fn for_tests(datagrams: bool) -> Self {
        let (_, read) = watch::channel(true);
        Self {
            datagrams: Arc::new(AtomicBool::new(datagrams)),
            read,
            wait_until: tokio::time::Instant::now(),
        }
    }

    /// Whether the peer's SETTINGS frame has been read, without waiting, for
    /// the tests of the control stream's reader.
    #[cfg(test)]
    pub(super) fn has_been_read(&self) -> bool {
        *self.read.borrow()
    }
}

/// Connection state that outlives any one stream or task.
#[derive(Default)]
pub(crate) struct Shared {
    /// Whether the peer's SETTINGS enabled HTTP Datagrams (RFC 9297 §2.1.1).
    ///
    /// Its own `Arc` because every [`PeerSettings`] holds it.
    peer_datagrams: Arc<AtomicBool>,
    /// Whether the peer's SETTINGS frame has been read, whatever it said.
    ///
    /// A watch and not a second flag, because a request waits on it
    /// ([`PeerSettings::read`]).
    settings_read: watch::Sender<bool>,
    /// What this connection may hold in half-received frames at once (D77).
    ///
    /// Its own `Arc` because every request stream's [`FrameReader`](frame::FrameReader) holds it,
    /// which makes the bound a property of the connection rather than of each
    /// stream separately. The peer's control stream is the one reader that
    /// does not: see [`BufferBudget::unshared`].
    buffered: Arc<BufferBudget>,
    /// The routing of the peer's HTTP Datagrams, with the hold and the drop
    /// counts ([`Router`]).
    ///
    /// Its own `Arc` because every [`DatagramReceiver`] holds it too, to take
    /// its entry out of the routing table when it is dropped.
    router: Arc<Router>,
    /// Why this endpoint closed the connection, if it did.
    local_error: OnceLock<Violation>,
    /// Whether a control stream has already been accepted (RFC 9114 §6.2.1).
    control_seen: AtomicBool,
    /// Whether a QPACK encoder stream has already been accepted.
    encoder_seen: AtomicBool,
    /// Whether a QPACK decoder stream has already been accepted.
    decoder_seen: AtomicBool,
}

impl Shared {
    /// Records why this endpoint is closing the connection, keeping the first
    /// reason, and reports the one that was kept.
    ///
    /// The return value is what the CONNECTION_CLOSE must carry. Two tasks can
    /// find a violation at the same moment, for example the control stream
    /// reader and a request stream, and only one of them sets the `OnceLock`.
    /// Closing with the other one's code would contradict the reason
    /// [`Connection::accept`] reports.
    fn record(&self, violation: Violation) -> Violation {
        self.local_error.get_or_init(|| violation).clone()
    }

    /// A view of the peer's SETTINGS whose [`PeerSettings::read`] waits until
    /// `wait_until` at the latest.
    pub(super) fn peer_settings(&self, wait_until: tokio::time::Instant) -> PeerSettings {
        PeerSettings {
            datagrams: self.peer_datagrams.clone(),
            read: self.settings_read.subscribe(),
            wait_until,
        }
    }

    /// Records that the peer's SETTINGS frame has been read, and whether it
    /// enabled HTTP Datagrams.
    ///
    /// The datagram flag starts false, so it is written only when `datagrams`
    /// is true.
    pub(super) fn settings_arrived(&self, datagrams: bool) {
        if datagrams {
            self.peer_datagrams.store(true, Ordering::Relaxed);
        }
        // After the flag, so a request this wakes reads the flag as the frame
        // set it.
        self.settings_read.send_replace(true);
    }

    /// Records that the peer opened a stream of `kind`, and says whether it
    /// had opened one before.
    ///
    /// One swap, so of two streams of one kind that arrive at once, exactly
    /// one is taken for the first.
    pub(super) fn opened_before(&self, kind: OnceStream) -> bool {
        let seen = match kind {
            OnceStream::Control => &self.control_seen,
            OnceStream::QpackEncoder => &self.encoder_seen,
            OnceStream::QpackDecoder => &self.decoder_seen,
        };
        seen.swap(true, Ordering::Relaxed)
    }
}

/// A kind of unidirectional stream the peer may open only once, for
/// [`Shared::opened_before`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OnceStream {
    /// The peer's control stream.
    Control,
    /// The peer's QPACK encoder stream.
    QpackEncoder,
    /// The peer's QPACK decoder stream.
    QpackDecoder,
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
    /// The bound for every wait on the peer that no protocol rule ends: the
    /// handshake, [`serve_stream`], a request's headers and every bounded
    /// response write ([`super::stream::Stream::respond_within`]). quinn's own
    /// idle timer does not end those waits, because [`crate::quic`] enables a
    /// keep-alive whose PINGs the peer's stack answers without any application
    /// involved. A peer that cannot finish within the time it may stay silent
    /// will not finish.
    pub(super) idle: Duration,
    pub(super) shared: Arc<Shared>,
}

#[cfg(test)]
impl Handle {
    /// A handle on `quic` with nothing registered on it, for the tests of the
    /// stream halves that hold one.
    pub(crate) fn for_tests(quic: quinn::Connection) -> Self {
        Self {
            quic,
            idle: Duration::from_secs(5),
            shared: Arc::new(Shared::default()),
        }
    }
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

    /// Claims a Quarter Stream ID for a session on this connection
    /// ([`Router::claim`]).
    ///
    /// When the claim takes datagrams that arrived before it, a debug line
    /// says how many, with the peer's address, which is the `remote` of the
    /// connection's other lines unless the peer has migrated since. The
    /// address is read only when that line is enabled and written.
    pub(crate) fn register_datagrams(&self, quarter_stream_id: u64) -> Option<DatagramReceiver> {
        let (inbound, released) = self
            .shared
            .router
            .claim(quarter_stream_id, tokio::time::Instant::now)?;
        if released > 0 {
            debug!(
                remote = %self.quic.remote_address(),
                quarter_stream_id,
                released,
                "delivering datagrams that arrived before their session"
            );
        }
        Some(inbound)
    }

    /// Ends the connection because the peer broke a rule (RFC 9114 §8).
    ///
    /// The reason is recorded before the close so that [`Connection::accept`],
    /// which will now fail with quinn's "closed locally", can report what
    /// actually happened rather than that this endpoint hung up.
    pub(crate) fn fail(&self, violation: Violation) -> ConnectionError {
        debug!(%violation, "closing the connection on a protocol violation");

        // The *stored* violation, not the one passed in ([`Shared::record`]),
        // is what goes on the wire and what this returns.
        let stored = self.shared.record(violation);
        self.quic
            .close(varint(stored.code()), stored.to_string().as_bytes());

        ConnectionError::Local(stored)
    }

    /// Ends the connection for a reason of this endpoint's own, and records it
    /// the way [`Self::fail`] records a violation.
    ///
    /// `code` and `reason` go on the wire as given. The record is what keeps
    /// the connection's error naming this close: quinn still hands out stream
    /// data it buffered before the close, a task can find a violation in it and
    /// call [`Self::fail`], and the first record is the one both keep. If a
    /// violation was recorded first, that one closed the connection, and its
    /// code and text are used here too, as [`Self::fail`] would use them.
    pub(crate) fn close_for(&self, code: Code, reason: &'static str) -> ConnectionError {
        let ours = Violation::connection(code, reason);
        let stored = self.shared.record(ours.clone());
        let text = if stored == ours {
            reason.to_owned()
        } else {
            stored.to_string()
        };
        self.quic.close(varint(stored.code()), text.as_bytes());

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
    /// breaking that rule, which is H3_CLOSED_CRITICAL_STREAM (quoted at
    /// [`stop_requested`], which watches for the same STOP_SENDING without a
    /// write).
    ///
    /// The same verdict covers the two QPACK streams this endpoint opens, on the
    /// strength of RFC 9204 §4.2 rather than this sentence (the reasoning is on
    /// [`Connection::_qpack`]); three of this endpoint's streams write through
    /// here and all three are critical.
    ///
    /// It goes through [`Self::fail`], so the CONNECTION_CLOSE carries the code
    /// (RFC 9114 §8); a returned violation would leave the wire to the
    /// H3_NO_ERROR of `Drop`.
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
    /// peer that grants neither blocks this forever, which is why
    /// [`Connection::handshake`] runs it under a deadline.
    async fn open_critical_streams(&self) -> Result<[quinn::SendStream; 3], ConnectionError> {
        // The control stream goes out first, so that a peer reading streams in
        // the order they arrive sees SETTINGS before anything else.
        let settings = super::settings::settings_payload();
        let mut preface = BytesMut::with_capacity(settings.len() + 2 * VARINT_MAX_LEN);
        put_varint(&mut preface, STREAM_CONTROL);
        frame::put_header(&mut preface, frame::SETTINGS, len_u64(settings.len()));
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
    /// the closure of either stream a connection error at the peer. A
    /// STOP_SENDING on either is seen by [`stop_requested`].
    _qpack: [quinn::SendStream; 2],
    /// The task reading the peer's unidirectional streams and datagrams.
    peer: JoinHandle<()>,
    /// When a request stops waiting for the peer's SETTINGS:
    /// [`PEER_SETTINGS_WAIT`] after [`Self::handshake`] began.
    settings_wait_until: tokio::time::Instant,
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
    /// will not be used"). Nothing is ever written to them. They are opened
    /// because every deployed stack opens them, and this server exists to
    /// interoperate with one particular client.
    ///
    /// # The deadline
    ///
    /// `within` bounds all of that, because the peer decides whether three
    /// unidirectional streams can be opened. Transport parameters that allow
    /// fewer than three of them, or no data on them, would otherwise hold a
    /// `max_connections` slot for as long as the peer keeps the socket open.
    /// The caller passes one idle timeout; `Handle::idle` says why the QUIC
    /// idle timeout alone does not end the wait.
    ///
    /// `dropped_datagrams` is where this connection counts every inbound HTTP
    /// Datagram it drops rather than delivers. The caller supplies it and keeps
    /// a clone, because the count is read for the connection's closing log
    /// line, which is written after everything constructed here is gone.
    pub async fn handshake(
        quic: quinn::Connection,
        within: Duration,
        dropped_datagrams: Arc<AtomicU64>,
    ) -> Result<Self, ConnectionError> {
        // The peer's SETTINGS are due from here on: its handshake was over
        // before this endpoint's was.
        let settings_wait_until = tokio::time::Instant::now() + PEER_SETTINGS_WAIT;

        let handle = Handle {
            quic,
            idle: within,
            shared: Arc::new(Shared {
                router: Arc::new(Router::new(dropped_datagrams)),
                ..Shared::default()
            }),
        };

        let opened = tokio::time::timeout(within, handle.open_critical_streams()).await;

        // A peer that does not let these streams be created breaks this MUST:
        //
        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
        //# Therefore, the transport parameters sent by both clients
        //# and servers MUST allow the peer to create at least three
        //# unidirectional streams.
        //
        // RFC 9114 names no code for it, so the code is our own choice.
        // §8.1 defines H3_STREAM_CREATION_ERROR for the other direction, a
        // stream the peer created that this endpoint will not accept (quoted
        // on `serve_stream`). It is used here because it is the registered
        // code about stream creation, so it tells the peer which half of the
        // handshake failed.
        let [control, encoder, decoder] = match opened {
            Ok(streams) => streams?,
            Err(_) => {
                return Err(handle.fail(Violation::connection(
                    Code::H3_STREAM_CREATION_ERROR,
                    "the HTTP/3 handshake did not complete within one idle timeout",
                )));
            }
        };

        let stopped = stop_requested(control.stopped(), encoder.stopped(), decoder.stopped());
        let peer = tokio::spawn(serve_peer(handle.clone(), stopped));

        Ok(Self {
            handle,
            control,
            _qpack: [encoder, decoder],
            peer,
            settings_wait_until,
            last_accepted: None,
            going_away: None,
        })
    }

    /// A live view of the peer's SETTINGS: whether they allow HTTP Datagrams,
    /// and whether they have been read yet.
    ///
    /// A CONNECT-UDP session falls back to capsules on the request stream
    /// while [`PeerSettings::datagrams`] is false. The view is handed out
    /// rather than sampled, for the reason the module documentation gives.
    pub fn peer_settings(&self) -> PeerSettings {
        self.handle.shared.peer_settings(self.settings_wait_until)
    }

    /// Waits for the next request stream.
    ///
    /// Cancel-safe: [`quinn::Connection::accept_bi`] leaves an unaccepted stream
    /// queued, so a caller may poll this inside a `select!`.
    ///
    /// There is no "the peer will send no further requests" outcome. Only a
    /// GOAWAY from the client could mean that, and it promises nothing about
    /// the requests already in flight, so reporting it would invite the caller
    /// to drop the connection and cut those requests off mid-tunnel. A
    /// connection therefore ends when the peer closes it or the idle timeout
    /// fires, both of which arrive here as `Err`.
    pub async fn accept(&mut self) -> Result<Resolver, ConnectionError> {
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
            return Ok(Resolver::new(self.handle.clone(), send, recv));
        }
    }

    /// Starts a graceful shutdown by sending GOAWAY (RFC 9114 §5.2).
    ///
    /// The identifier is the *first* request this connection will not serve:
    /// four past the last one accepted, or zero if none was. So everything
    /// already in flight is untouched and the client knows to take new work
    /// elsewhere. Requests arriving past it are rejected in [`Self::accept`]
    /// with H3_REQUEST_REJECTED, the code a client may safely retry on.
    ///
    /// It awaits the GOAWAY write, which the peer's flow control on the
    /// control stream can hold, so a caller bounds it. It is not cancel-safe:
    /// the identifier is recorded before the write, so a cancelled call still
    /// rejects later requests the peer may never have been told about, and may
    /// leave part of the frame on the control stream. Both are tolerable,
    /// because H3_REQUEST_REJECTED is safe to retry and nothing writes to the
    /// control stream again. The connection stays usable afterwards, and the
    /// caller decides when the existing tunnels are done.
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
        frame::put_header(&mut goaway, frame::GOAWAY, len_u64(varint_len(identifier)));
        put_varint(&mut goaway, identifier);

        // Written before the answer is judged, so the borrow of `self.control`
        // is over by the time `self.handle` is asked what a failure means.
        let written = self.control.write_all(&goaway).await;
        written.map_err(|error| self.handle.critical_write(error))
    }

    /// Ends the connection because this endpoint is done with it, not because
    /// anything went wrong.
    ///
    /// The counterpart of the violation close. It uses the same mechanism (RFC
    /// 9114 §8 makes a CONNECTION_CLOSE carrying an HTTP/3 code *be* the
    /// connection error) with the code §8.1 defines for having nothing to
    /// report:
    ///
    //= https://www.rfc-editor.org/rfc/rfc9114#section-8.1
    //# H3_NO_ERROR (0x0100):  No error.  This is used when the connection or
    //# stream needs to be closed, but there is no error to signal.
    ///
    /// `reason` reaches the peer in the CONNECTION_CLOSE frame and comes back
    /// in the returned error, which `quic::graded` grades as a routine ending
    /// rather than a fault. So the caller can `break` on it and the
    /// connection's closing line stays at the level an idle timeout gets.
    /// The error is returned rather than logged here to keep that grading in
    /// one place (D50).
    ///
    /// It is `Handle::close_for` with that code, so a violation recorded first
    /// is what goes on the wire and what is returned.
    pub fn close_quietly(&self, reason: &'static str) -> ConnectionError {
        self.handle.close_for(Code::H3_NO_ERROR, reason)
    }
}

impl Drop for Connection {
    /// Closes the QUIC connection and stops reading the peer's streams and
    /// datagrams.
    ///
    /// H3_NO_ERROR is RFC 9114 §8.1's code for when "the connection or stream
    /// needs to be closed, but there is no error to signal". `quic/mod.rs`
    /// depends on this happening: it is why `quinn::Connection::close_reason()`
    /// cannot be used to grade a connection's closing log line, and why the
    /// error *value* returned by `conn::handle` is graded instead.
    ///
    /// It also lets go of the datagrams held for sessions that never claimed
    /// them, and counts them, here rather than when the last handle goes:
    /// `quic/mod.rs` writes the closing line, with the drop count, right after
    /// this, while aborted request tasks may still hold a handle.
    fn drop(&mut self) {
        self.handle.quic.close(
            varint(Code::H3_NO_ERROR),
            b"connection closed by the server",
        );
        self.peer.abort();
        self.handle.shared.router.close_routes();
    }
}

/// The stream id four past `last_accepted`, or zero if nothing was accepted.
///
/// The GOAWAY identifier this server sends: the first request it will not
/// serve. Clamped to [`crate::varint::VARINT_MAX`] because the sum is written
/// as a QUIC varint and nothing above that is representable. RFC 9000 §2.1
/// bounds a stream id by the same value, so no legitimate peer can reach the
/// clamp, and a saturating `u64::MAX` would be an assertion failure rather than
/// a GOAWAY.
fn next_request_id(last_accepted: Option<u64>) -> u64 {
    last_accepted.map_or(0, |id| {
        id.saturating_add(REQUEST_STREAM_STEP)
            .min(crate::varint::VARINT_MAX)
    })
}

/// Serves what the peer sends outside its request streams, for the life of the
/// connection: its unidirectional streams and its HTTP Datagrams.
///
/// One task for both, because both are the connection's rather than any
/// stream's, both end when it does, and neither can be starved by the other:
/// [`quinn::Connection::accept_uni`] leaves an unaccepted stream queued and
/// [`quinn::Connection::read_datagram`] an undelivered datagram, so a branch
/// that loses the race here loses nothing but the poll. Handling is short: a
/// unidirectional stream gets a task of its own, and a datagram is a map lookup
/// and a `try_send` that never blocks. So a flood of one kind cannot hold the
/// other up.
///
/// `stopped` is [`stop_requested`] over this endpoint's three critical streams.
/// A STOP_SENDING found once the connection is already closing is not a
/// violation, for the reason `critical_stream_closed` gives.
async fn serve_peer(handle: Handle, stopped: impl Future<Output = String>) {
    let mut streams = JoinSet::new();
    let mut stopped = std::pin::pin!(stopped);

    loop {
        tokio::select! {
            detail = &mut stopped => {
                let closed = critical_stream_closed(detail, handle.quic.close_reason().as_ref());
                if let Some(violation) = closed {
                    handle.fail(violation);
                }
                return;
            }

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
                        datagrams_stopped(error);
                        return;
                    }
                };

                if let Err(violation) = route_datagram(&handle.shared.router, datagram) {
                    handle.fail(violation);
                    return;
                }
            }
        }
    }
}

/// Completes when the peer sends STOP_SENDING on one of this endpoint's three
/// critical streams, with the text of the violation.
///
/// A write would find the STOP_SENDING too ([`Handle::critical_write`]), but
/// the control stream is written once more at most, for GOAWAY, and the two
/// QPACK streams never are. So the three are watched for the life of the
/// connection.
///
//= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
//# The sender MUST NOT close the control stream, and the receiver
//# MUST NOT request that the sender close the control stream.  If either
//# control stream is closed at any point, this MUST be treated as a
//# connection error of type H3_CLOSED_CRITICAL_STREAM.
//
//= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
//# The sender MUST NOT close either of these streams, and the receiver
//# MUST NOT request that the sender close either of these streams.
//# Closure of either unidirectional stream type MUST be treated as a
//# connection error of type H3_CLOSED_CRITICAL_STREAM.
///
/// Each argument is the stream's `quinn::SendStream::stopped`. One that ends
/// without a STOP_SENDING never completes this: an error is the connection
/// ending, and `Ok(None)` needs a finish, which this endpoint never sends on
/// these streams.
async fn stop_requested<F>(control: F, encoder: F, decoder: F) -> String
where
    F: Future<Output = Result<Option<quinn::VarInt>, quinn::StoppedError>>,
{
    let watch = |name: &'static str, stopped: F| async move {
        match stopped.await {
            Ok(Some(code)) => format!("the peer stopped this endpoint's {name} stream ({code})"),
            Ok(None) | Err(_) => std::future::pending().await,
        }
    };

    tokio::select! {
        detail = watch("control", control) => detail,
        detail = watch("QPACK encoder", encoder) => detail,
        detail = watch("QPACK decoder", decoder) => detail,
    }
}

/// Logs why [`serve_peer`] stopped reading datagrams.
///
/// The error can carry the reason phrase of the peer's CONNECTION_CLOSE, so it
/// goes through [`crate::logfmt::peer_error`] like every other connection
/// error a peer may have written.
fn datagrams_stopped(error: quinn::ConnectionError) {
    debug!(
        error = %crate::logfmt::peer_error(error),
        "stopped reading QUIC datagrams"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Bytes, BytesMut};
    use std::sync::Mutex;

    /// The peer writes the reason phrase of its CONNECTION_CLOSE, and the line
    /// that reports the end of the datagram loop prints the error. A newline in
    /// the phrase must not start a second line in the log.
    #[test]
    fn a_peer_close_reason_cannot_split_the_datagram_line() {
        #[derive(Clone)]
        struct Sink(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("sink").extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let sink = Sink(Arc::new(Mutex::new(Vec::new())));
        let writer = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();

        let reason = Bytes::from_static(b"goodbye\nWARN forged line");
        tracing::subscriber::with_default(subscriber, || {
            datagrams_stopped(quinn::ConnectionError::ApplicationClosed(
                quinn::ApplicationClose {
                    error_code: quinn::VarInt::from_u32(0x100),
                    reason: reason.clone(),
                },
            ));
            datagrams_stopped(quinn::ConnectionError::ConnectionClosed(
                quinn::ConnectionClose {
                    error_code: quinn::TransportErrorCode::NO_ERROR,
                    frame_type: None,
                    reason,
                },
            ));
        });

        let logged = String::from_utf8(sink.0.lock().expect("sink").clone()).expect("utf-8");
        assert_eq!(
            logged.lines().count(),
            2,
            "one line per call, whatever the peer wrote: {logged:?}"
        );
        assert!(
            logged
                .lines()
                .all(|line| line.contains("stopped reading QUIC datagrams")),
            "{logged:?}"
        );
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
        let max = crate::varint::VARINT_MAX;

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

    /// The usual case, and the one that must cost nothing: the frame was read
    /// before the request asked.
    #[tokio::test(start_paused = true)]
    async fn settings_that_were_read_are_not_waited_for() {
        let shared = Shared::default();
        let start = tokio::time::Instant::now();
        let settings = shared.peer_settings(start + PEER_SETTINGS_WAIT);
        shared.settings_arrived(true);

        settings.read().await;

        assert_eq!(start.elapsed(), Duration::ZERO);
        assert!(settings.datagrams());
    }

    /// The case the wait exists for: the request is here first, and the frame
    /// is read a moment later. The wait ends then and not at the bound, and
    /// the flag already says what the frame said.
    #[tokio::test(start_paused = true)]
    async fn the_wait_ends_when_the_settings_are_read() {
        const LATER: Duration = Duration::from_millis(100);

        for datagrams in [true, false] {
            let shared = Arc::new(Shared::default());
            let start = tokio::time::Instant::now();
            let settings = shared.peer_settings(start + PEER_SETTINGS_WAIT);

            let reader = shared.clone();
            tokio::spawn(async move {
                tokio::time::sleep(LATER).await;
                reader.settings_arrived(datagrams);
            });
            settings.read().await;

            assert_eq!(start.elapsed(), LATER, "datagrams: {datagrams}");
            assert_eq!(settings.datagrams(), datagrams);
        }
    }

    /// A peer that sends no SETTINGS holds a request until the bound and no
    /// longer, and the request is then served without datagrams.
    #[tokio::test(start_paused = true)]
    async fn the_wait_ends_at_the_bound() {
        let shared = Shared::default();
        let start = tokio::time::Instant::now();
        let settings = shared.peer_settings(start + PEER_SETTINGS_WAIT);

        settings.read().await;

        assert_eq!(start.elapsed(), PEER_SETTINGS_WAIT);
        assert!(!settings.datagrams());
    }

    /// The bound runs from the handshake, so a request that arrives after it
    /// does not wait: a peer that never sends SETTINGS pays once per
    /// connection and not once per session.
    #[tokio::test(start_paused = true)]
    async fn a_request_after_the_bound_does_not_wait() {
        let shared = Shared::default();
        let settings = shared.peer_settings(tokio::time::Instant::now() + PEER_SETTINGS_WAIT);
        tokio::time::sleep(PEER_SETTINGS_WAIT * 2).await;

        let asked = tokio::time::Instant::now();
        settings.read().await;

        assert_eq!(asked.elapsed(), Duration::ZERO);
    }

    /// The connection ending ends the wait: nothing will read the frame.
    #[tokio::test(start_paused = true)]
    async fn the_wait_ends_with_the_connection() {
        let shared = Shared::default();
        let start = tokio::time::Instant::now();
        let settings = shared.peer_settings(start + PEER_SETTINGS_WAIT);
        drop(shared);

        settings.read().await;

        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    /// A quiet close after a violation reports the violation, as every other
    /// close for a reason of this endpoint's own does.
    ///
    /// The violation closed the connection first, and the quiet close graded
    /// as routine would otherwise hide it from the closing log line.
    #[tokio::test]
    async fn a_quiet_close_does_not_hide_an_earlier_violation() {
        let (_client, server) =
            crate::quic::tests::loopback_pair(quinn::TransportConfig::default()).await;
        let handle = Handle::for_tests(server.clone());
        let uni = || async { server.open_uni().await.expect("open a stream") };
        let connection = Connection {
            handle,
            control: uni().await,
            _qpack: [uni().await, uni().await],
            peer: tokio::spawn(async {}),
            settings_wait_until: tokio::time::Instant::now(),
            last_accepted: None,
            going_away: None,
        };

        let _ = connection.handle.fail(Violation::connection(
            Code::H3_FRAME_UNEXPECTED,
            "a frame the peer may not send",
        ));
        let ConnectionError::Local(reported) = connection.close_quietly("idle") else {
            panic!("the connection was closed by this endpoint");
        };
        assert_eq!(reported.code(), Code::H3_FRAME_UNEXPECTED, "{reported}");
    }

    /// A close for a reason of this endpoint's own is the reason reported, even
    /// when a task finds a violation afterwards.
    ///
    /// After a local close quinn still hands out stream data it had buffered,
    /// so a request stream can find a connection-level violation in it and
    /// call [`Handle::fail`]. The connection's error, which the closing log
    /// line prints, must still name the close that went out.
    #[tokio::test]
    async fn a_close_for_a_reason_of_our_own_is_not_renamed_by_a_later_violation() {
        let (client, server) =
            crate::quic::tests::loopback_pair(quinn::TransportConfig::default()).await;
        let handle = Handle::for_tests(server);

        let _ = handle.close_for(
            Code::H3_REQUEST_REJECTED,
            "too many authentication failures",
        );
        let _ = handle.fail(Violation::connection(
            Code::H3_FRAME_UNEXPECTED,
            "a frame found later in buffered data",
        ));

        let ConnectionError::Local(reported) =
            handle.interpret(quinn::ConnectionError::LocallyClosed)
        else {
            panic!("the connection was closed by this endpoint");
        };
        assert_eq!(reported.code(), Code::H3_REQUEST_REJECTED, "{reported}");

        // The wire carries the code and the reason phrase as they were given.
        let closed = tokio::time::timeout(Duration::from_secs(5), client.closed())
            .await
            .expect("the client must see the close");
        let quinn::ConnectionError::ApplicationClosed(close) = closed else {
            panic!("expected an application close, got {closed}");
        };
        assert_eq!(close.error_code.into_inner(), 0x10b);
        assert_eq!(&close.reason[..], b"too many authentication failures");
    }
}
