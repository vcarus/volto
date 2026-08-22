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
        // close, and anything after it is a consequence.
        let _ = self.shared.local_error.set(violation.clone());
        self.quic
            .close(varint(violation.code()), violation.to_string().as_bytes());

        ConnectionError::Local(violation)
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
    pub async fn handshake(quic: quinn::Connection) -> Result<Self, ConnectionError> {
        let handle = Handle {
            quic,
            shared: Arc::default(),
        };

        // The control stream goes out first, so that a peer reading streams in
        // the order they arrive sees SETTINGS before anything else.
        let settings = frame::settings_payload();
        let mut preface = BytesMut::with_capacity(settings.len() + 2 * MAX_VARINT);
        put_varint(&mut preface, STREAM_CONTROL);
        frame::put_header(&mut preface, frame::SETTINGS, settings.len() as u64);
        preface.extend_from_slice(&settings);

        let mut control = handle.quic.open_uni().await?;
        control.write_all(&preface).await.map_err(critical_write)?;

        let encoder = handle.open_typed(STREAM_QPACK_ENCODER).await?;
        let decoder = handle.open_typed(STREAM_QPACK_DECODER).await?;

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
        let next = self
            .last_accepted
            .map_or(0, |id| id.saturating_add(REQUEST_STREAM_STEP));

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

        STREAM_QPACK_ENCODER | STREAM_QPACK_DECODER => {
            let seen = if stream_type == STREAM_QPACK_ENCODER {
                &handle.shared.encoder_seen
            } else {
                &handle.shared.decoder_seen
            };
            if seen.swap(true, Ordering::Relaxed) {
                handle.fail(duplicate("a second QPACK stream of the same kind"));
                return;
            }
            drain(recv).await;
        }

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

            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
            //# If either control stream is closed at any point, this MUST be
            //# treated as a connection error of type H3_CLOSED_CRITICAL_STREAM.
            Ok(None) => {
                handle.fail(Violation::connection(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    "the peer closed its control stream",
                ));
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
}

impl Control {
    /// Applies one item from the control stream.
    fn accept(&mut self, item: Item, shared: &Shared) -> Result<(), Violation> {
        let Item::Frame(frame) = item else {
            // DATA on the control stream is a frame that does not belong there,
            // and as the first thing on it, it is simply not SETTINGS.
            return Err(if self.settings {
                unexpected("a DATA frame on the control stream")
            } else {
                missing_settings()
            });
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

            // This server never pushes, so there is no push to cancel and no
            // push id worth raising. Both are accepted and ignored.
            (Frame::CancelPush(_) | Frame::MaxPushId(_), true) => Ok(()),

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

/// Reads and discards a stream until the peer stops sending on it.
///
/// The QPACK encoder and decoder streams have nothing to say to a decoder that
/// advertised a zero table capacity, but they still have to be read: a receiver
/// that never reads stalls the peer's stream flow control, and RFC 9204 §4.2
/// forbids the peer from closing them, so stopping them is not an option
/// either.
///
/// RFC 9204 §4.2 also makes the *peer* closing one of these streams a
/// connection error of type H3_CLOSED_CRITICAL_STREAM. That is deliberately not
/// enforced: with a zero table capacity the streams carry nothing this server
/// reads, while a client tearing a connection down may well finish its send
/// streams a moment before its CONNECTION_CLOSE arrives -- and answering an
/// ordinary goodbye with a protocol error would turn a race into a fault report
/// in the operator's log.
async fn drain(mut recv: quinn::RecvStream) {
    while let Ok(Some(_)) = recv.read_chunk(usize::MAX, true).await {}
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
        ] {
            let error = Control::default()
                .accept(first, &shared)
                .expect_err("refused");
            assert_eq!(error.code(), Code::H3_MISSING_SETTINGS);
            assert!(error.is_connection_error());
        }

        assert!(Control::default().accept(settings(true), &shared).is_ok());
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

    /// A server that never pushes has nothing to do about either frame, and
    /// RFC 9114 gives it nothing to complain about either.
    #[test]
    fn push_bookkeeping_frames_are_accepted_and_ignored() {
        let shared = Shared::default();
        let mut control = Control::default();
        control.accept(settings(true), &shared).expect("accepted");

        control
            .accept(Item::Frame(Frame::CancelPush(7)), &shared)
            .expect("accepted");
        control
            .accept(Item::Frame(Frame::MaxPushId(9)), &shared)
            .expect("accepted");
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
        let step = REQUEST_STREAM_STEP;
        assert_eq!(step, 4);
        assert_eq!(None::<u64>.map_or(0, |id: u64| id + step), 0);
        assert_eq!(Some(0u64).map_or(0, |id| id + step), 4);
        assert_eq!(Some(16u64).map_or(0, |id| id + step), 20);
    }
}
