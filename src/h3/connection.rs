//! One server-side HTTP/3 connection: SETTINGS, the control stream, GOAWAY.
//!
//! # Shape
//!
//! A connection is three things:
//!
//! * the three unidirectional streams this endpoint opens and then holds open
//!   for its lifetime -- control, QPACK encoder, QPACK decoder;
//! * a background task that accepts the peer's unidirectional streams and reads
//!   its control stream for as long as the connection lasts;
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
//! # How a connection error is signalled
//!
//! RFC 9114 §8 defines an HTTP/3 connection error as a QUIC CONNECTION_CLOSE
//! carrying the HTTP/3 error code, which is precisely
//! [`quinn::Connection::close`]. So that call *is* the mechanism: there is no
//! error to propagate between tasks, because closing the connection makes every
//! operation on it fail on its own. The only thing that has to travel is the
//! *reason*, which quinn overwrites with "closed locally" -- so it is recorded
//! on the way past and read back by [`Connection::accept`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::BytesMut;
use tokio::task::{JoinHandle, JoinSet};
use tracing::debug;

use crate::datagram::{peek_varint, put_varint, varint_len};

use super::error::{Code, ConnectionError, StreamError, Violation};
use super::frame::{self, Frame, FrameReader, Item};
use super::stream::Resolver;
use super::{varint, MAX_VARINT};

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
    /// find a violation at the same moment -- the control stream reader and a
    /// request stream, say -- and only one of them wins the `OnceLock`; closing
    /// with the loser's code would then contradict the reason
    /// [`Connection::accept`] goes on to report.
    fn record(&self, violation: Violation) -> Violation {
        self.local_error.get_or_init(|| violation).clone()
    }
}

/// A cheap handle to the connection, held by every stream and task on it.
///
/// Cloning is two refcount bumps: `quinn::Connection` is itself a handle.
#[derive(Clone)]
pub(crate) struct Handle {
    /// The QUIC connection underneath.
    pub(crate) quic: quinn::Connection,
    shared: Arc<Shared>,
}

impl Handle {
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

    /// Opens a unidirectional stream and writes its type (RFC 9114 §6.2).
    async fn open_typed(&self, stream_type: u64) -> Result<quinn::SendStream, ConnectionError> {
        let mut send = self.quic.open_uni().await?;

        let mut header = BytesMut::with_capacity(varint_len(stream_type));
        put_varint(&mut header, stream_type);
        send.write_all(&header).await.map_err(critical_write)?;

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
        let mut preface = BytesMut::with_capacity(settings.len() + 2 * MAX_VARINT);
        put_varint(&mut preface, STREAM_CONTROL);
        frame::put_header(&mut preface, frame::SETTINGS, settings.len() as u64);
        preface.extend_from_slice(&settings);

        let mut control = self.quic.open_uni().await?;
        control.write_all(&preface).await.map_err(critical_write)?;

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
    /// The task reading the peer's unidirectional streams.
    unidirectional: JoinHandle<()>,
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
    pub async fn handshake(
        quic: quinn::Connection,
        within: Duration,
    ) -> Result<Self, ConnectionError> {
        let handle = Handle {
            quic,
            shared: Arc::default(),
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
                )))
            }
        };

        let unidirectional = tokio::spawn(serve_unidirectional(handle.clone()));

        Ok(Self {
            handle,
            control,
            _qpack: [encoder, decoder],
            unidirectional,
            last_accepted: None,
            going_away: None,
        })
    }

    /// A live view of whether the peer advertised `SETTINGS_H3_DATAGRAM = 1`.
    ///
    /// RFC 9297 §2.1.1 forbids sending HTTP Datagrams before this is true, and
    /// a CONNECT-UDP session falls back to capsules on the request stream while
    /// it is not. Handed out rather than sampled on purpose: the answer is
    /// written by the task that read the peer's control stream, so a session
    /// holding this flag starts using datagrams the instant the peer allows
    /// them -- with no window in which the setting is known here but not there.
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

        let mut goaway = BytesMut::with_capacity(2 * MAX_VARINT + varint_len(identifier));
        frame::put_header(&mut goaway, frame::GOAWAY, varint_len(identifier) as u64);
        put_varint(&mut goaway, identifier);

        self.control
            .write_all(&goaway)
            .await
            .map_err(critical_write)
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
    /// Closes the QUIC connection and stops reading the peer's streams.
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
        self.unidirectional.abort();
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

/// A write to one of this endpoint's critical streams failed.
///
/// RFC 9114 §6.2.1 forbids a peer from resetting or stopping the control
/// stream, so anything other than the connection going away is the peer
/// breaking that rule.
fn critical_write(error: quinn::WriteError) -> ConnectionError {
    match error {
        quinn::WriteError::ConnectionLost(error) => error.into(),
        other => ConnectionError::Local(Violation::connection(
            Code::H3_CLOSED_CRITICAL_STREAM,
            other.to_string(),
        )),
    }
}

/// Accepts the peer's unidirectional streams for the life of the connection.
async fn serve_unidirectional(handle: Handle) {
    let mut streams = JoinSet::new();

    loop {
        let Ok(recv) = handle.quic.accept_uni().await else {
            // The connection is gone; so is anything that could arrive on it.
            return;
        };

        // Reap the handlers that have finished, so a peer opening streams in a
        // loop cannot make this set grow without bound.
        while streams.try_join_next().is_some() {}

        streams.spawn(serve_stream(handle.clone(), recv));
    }
}

/// Dispatches one unidirectional stream by its type (RFC 9114 §6.2).
async fn serve_stream(handle: Handle, mut recv: quinn::RecvStream) {
    let stream_type = match read_stream_type(&mut recv).await {
        Ok(Some(stream_type)) => stream_type,

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
        //# A receiver MUST tolerate unidirectional streams being closed or reset
        //# prior to the reception of the unidirectional stream header.
        Ok(None) => return,
        Err(error) => {
            debug!(%error, "a unidirectional stream failed before its type arrived");
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
    let mut frames = FrameReader::new(recv);
    let mut control = Control::default();

    loop {
        let item = match frames.next().await {
            Ok(Some(item)) => item,

            Ok(None) => {
                if let Some(violation) = control_stream_finished(handle.quic.close_reason()) {
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
/// protect -- the same reasoning [`drain`] records for the QPACK streams.
fn control_stream_finished(close_reason: Option<quinn::ConnectionError>) -> Option<Violation> {
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
                })
            }

            //= https://www.rfc-editor.org/rfc/rfc9114#section-9
            //# Implementations MUST ignore unknown or unsupported values in all
            //# extensible protocol elements.
            //
            // Ignored -- but only after SETTINGS. A grease frame sent first is
            // still "any other frame type" below, and the greasing endpoint is
            // precisely the one testing whether this server enforces that.
            Item::Skipped { kind } => {
                if !self.settings {
                    return Err(missing_settings());
                }
                debug!(
                    frame_type = kind,
                    "ignoring a frame of an unknown type on the control stream"
                );
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
}

/// The most continuation bytes an instruction's prefixed integer may run to.
///
/// RFC 9204 §4.1.1 requires decoding integers "up to and including 62 bits
/// long", which a 5- or 6-bit prefix reaches in nine continuation bytes of
/// seven bits each. A tenth is a value no conformant encoder produces, and this
/// server's own rule is to end the stream there rather than read on forever.
const MAX_INTEGER_CONTINUATION: usize = 9;

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
///
/// RFC 9204 §4.2 also makes the *peer* closing one of these streams a
/// connection error of type H3_CLOSED_CRITICAL_STREAM. That is deliberately not
/// enforced: the streams carry nothing this server acts on, while a client
/// tearing a connection down may well finish its send streams a moment before
/// its CONNECTION_CLOSE arrives -- and answering an ordinary goodbye with a
/// protocol error would turn a race into a fault report in the operator's log.
async fn serve_qpack(handle: &Handle, mut recv: quinn::RecvStream, kind: QpackStream) {
    if kind.seen(&handle.shared).swap(true, Ordering::Relaxed) {
        handle.fail(duplicate("a second QPACK stream of the same kind"));
        return;
    }

    // Whether the last accepted instruction's integer is still running, and how
    // many continuation bytes of it have been read.
    let mut continuing = false;
    let mut continuation = 0usize;

    while let Ok(Some(chunk)) = recv.read_chunk(usize::MAX, true).await {
        for &byte in &chunk.bytes {
            if continuing {
                continuation += 1;
                if continuation > MAX_INTEGER_CONTINUATION {
                    handle.fail(Violation::connection(
                        kind.code(),
                        "an integer past 62 bits",
                    ));
                    return;
                }
                continuing = byte & 0b1000_0000 != 0;
                continue;
            }

            match qpack_instruction(kind, byte) {
                Ok(more) => {
                    continuing = more;
                    continuation = 0;
                }
                Err(violation) => {
                    handle.fail(violation);
                    return;
                }
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
    let mut buf = [0u8; MAX_VARINT];

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
                control_stream_finished(Some(closed.clone())).is_none(),
                "a connection already closed by {closed} needs no fault report"
            );
        }
    }
}
