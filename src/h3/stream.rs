//! One request stream, from its HEADERS frame to its last byte.
//!
//! # Reading
//!
//! A request stream carries HEADERS and then a body of DATA frames. Only the
//! first is buffered: the body is handed on in the chunks it arrived in, because
//! for this server the body *is* the tunnel and every copy of it would be paid
//! for per packet. A tunnel's reader takes several of those chunks from quinn
//! per read without copying them (`frame::READ_AHEAD_CHUNKS`), and
//! [`Reader::try_recv_data`] is how a caller gathers them into one write.
//! Nothing follows the body: RFC 9114 §4.4 permits only DATA on a stream whose
//! CONNECT has completed, so the trailer section §4.1 allows an ordinary
//! request is never accepted here.
//!
//! # Validating
//!
//! [`Resolver::resolve`] is where a request becomes a [`Request`], and where
//! RFC 9114 §4.1.2's "malformed" verdict is reached. A request that this server
//! accepts is one it will open a socket for.
//!
//! A malformed request is a *stream* error: the stream is reset and stopped with
//! H3_MESSAGE_ERROR and nothing else on the connection is disturbed. A frame
//! sequence that makes no sense is a *connection* error, because after one the
//! stream can no longer be parsed at all.
//!
//! # Writing
//!
//! A response is one HEADERS frame; body bytes are DATA frames, and the payload
//! is never copied to put a header in front of it. A relay block is read in
//! behind [`frame::DATA_HEADER_ROOM`] bytes of room, the header is written into
//! that room, and the frame reaches quinn as one chunk of the allocation it was
//! read into ([`Writer::send_data_in_place`]). Both tunnels send their body
//! this way: the TCP relay and the UDP capsule path.

use bytes::{Bytes, BytesMut};

use super::connection::{DatagramReceiver, Handle};
use super::error::{Code, StreamError, Violation};
use super::frame::{self, Frame, FrameReader, Item};
use super::message::{Fields, Request, Status};
use super::qpack;
pub use super::request::build_request;
use super::{MAX_FIELD_SECTION_SIZE, varint};
use crate::varint::VARINT_MAX_LEN;

/// An accepted request stream whose headers have not been read yet.
pub struct Resolver {
    handle: Handle,
    send: quinn::SendStream,
    frames: FrameReader,
}

impl Resolver {
    pub(crate) fn new(handle: Handle, send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        let frames = FrameReader::on_request_stream(recv, handle.budget());
        Self {
            handle,
            send,
            frames,
        }
    }

    /// Reads and validates the request headers, giving up after one QUIC idle
    /// timeout.
    ///
    /// On failure the stream has already been ended: reset and stopped for a
    /// malformed request, or the whole connection closed for a frame sequence
    /// that cannot be parsed. The caller only has to log it.
    ///
    /// # The deadline
    ///
    /// A peer opens a request stream by sending on it, and may then send one
    /// byte and stop. Nothing in HTTP/3 obliges it to finish the request.
    /// Without a deadline each such stream holds a task until the connection
    /// ends: `max_streams_bidi` of them per connection, at a byte apiece, from
    /// a peer that has not authenticated (D76). The bound is the connection's
    /// own idle timeout, for the reason `connection::Handle::idle` gives.
    ///
    /// The stream is the only thing a lapsed deadline ends: it is reset and
    /// stopped, and the connection carries on serving everything else on it.
    pub async fn resolve(self) -> Result<(Request, Stream), StreamError> {
        let Self {
            handle,
            mut send,
            mut frames,
        } = self;

        let read = match tokio::time::timeout(handle.idle, read_request(&mut frames)).await {
            Ok(read) => read,

            //= https://www.rfc-editor.org/rfc/rfc9114#section-8.1
            //# H3_REQUEST_INCOMPLETE (0x010d):  The client's stream terminated
            //# without containing a fully formed request.
            //
            // The stream has not terminated but stalled, which no code in §8.1
            // names. The answer is the same either way: the request will not be
            // served because it never finished arriving. `read_request` uses
            // the same code when the stream does end early.
            Err(_elapsed) => {
                let violation = Violation::stream(
                    Code::H3_REQUEST_INCOMPLETE,
                    "the request headers did not arrive within one idle timeout",
                );
                let _ = send.reset(varint(violation.code()));
                frames.stop(violation.code());
                return Err(StreamError::Local(violation));
            }
        };

        let mut stream = Stream {
            handle,
            writer: Writer { send },
            frames,
        };

        match read {
            Ok(request) => Ok((request, stream)),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
            //# A server that receives a larger header section than it is
            //# willing to handle can send an HTTP 431 (Request Header
            //# Fields Too Large) status code ([RFC6585]).
            //
            // A 431 tells a client that overshot the advertised limit which of
            // its requests to fix, where a bare RESET_STREAM leaves it guessing.
            // The receiving side is stopped, because the rest of the section is
            // what this server has declined to read. The answer then goes out
            // and that side is finished cleanly.
            //
            // The stop comes before the write, as in the other refusal writers
            // (`tunnel::status::refuse_with` and `accept_then_close`). A peer
            // that grants no window can hold the write for its whole idle
            // timeout, and until the stop goes out quinn holds everything that
            // peer sent on the stream, up to `STREAM_RECEIVE_WINDOW` per stream
            // and `CONNECTION_RECEIVE_WINDOW` in aggregate. Stopping first
            // limits that to the duration of the parse.
            //
            // `Violation::field_section_too_large` marks the violations that
            // get a 431 and lists their sources. Everything else falls through
            // to the bare reset `answer` gives it, H3_EXCESSIVE_LOAD from
            // `frame::MAX_SKIPPED_FRAMES` included. An escalated violation is
            // connection-class, and this test is then false.
            //
            // The write is bounded and, when the bound lapses, abandoned with
            // a reset; [`Stream::respond_within`] says why.
            Err(frame::Error::Protocol(violation)) if violation.is_field_section_too_large() => {
                stream.stop_receiving(violation.code());

                if stream
                    .respond_within(Status::REQUEST_HEADER_FIELDS_TOO_LARGE, Fields::new())
                    .await
                    .is_ok()
                {
                    let _ = stream.finish();
                }

                Err(StreamError::Local(violation))
            }

            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
            //# Malformed requests or responses that are detected MUST be
            //# treated as a stream error of type H3_MESSAGE_ERROR.
            //
            // The response side is reset as well as the request side stopped:
            // this request will never be answered, and a peer left waiting for
            // a response that is not coming learns nothing.
            Err(error) => Err(answer(
                &stream.handle,
                &mut stream.frames,
                Some(&mut stream.writer.send),
                error,
            )),
        }
    }
}

/// Answers a frame-layer failure and reports it as a stream error.
///
/// A violation that RFC 9114 makes a *connection* error closes the connection,
/// which is what makes every operation on it fail; a stream-class one stops the
/// receiving side, because the rest of what the peer is sending is precisely
/// what has been refused.
///
/// Whether the *sending* side is reset as well is the caller's, which is why it
/// is a parameter: a request that was never understood will never be answered,
/// while a [`Reader`] is only half a stream and the tunnels decide the other
/// half differently for a client abort than for a target failure.
///
/// A `frame::Error::Stream` is the transport already having decided: the peer
/// reset the request stream, or the connection is gone. It is returned as it
/// stands, and the receiving side needs no stop. A sending side passed in is
/// reset with H3_REQUEST_INCOMPLETE, because a request that ended this way
/// never arrived whole, and RFC 9114 §4.1 asks for that abort (quoted in
/// `read_request`). Left to its drop, `quinn::SendStream::drop` would finish
/// it cleanly, and the peer would read an empty response that ended normally.
/// On a lost connection the reset fails, which needs no reporting.
fn answer(
    handle: &Handle,
    frames: &mut FrameReader,
    send: Option<&mut quinn::SendStream>,
    error: frame::Error,
) -> StreamError {
    match error {
        frame::Error::Stream(error) => {
            if let Some(send) = send {
                let _ = send.reset(varint(Code::H3_REQUEST_INCOMPLETE));
            }
            error
        }
        frame::Error::Protocol(violation) if violation.is_connection_error() => {
            StreamError::Connection(handle.fail(violation))
        }
        frame::Error::Protocol(violation) => {
            if let Some(send) = send {
                let _ = send.reset(varint(violation.code()));
            }
            frames.stop(violation.code());
            StreamError::Local(violation)
        }
    }
}

/// Reads the first frame of a request stream and turns it into a request.
async fn read_request(frames: &mut FrameReader) -> Result<Request, frame::Error> {
    let block = loop {
        match frames.next().await? {
            Some(Item::Frame(Frame::Headers(block))) => break block,

            // RFC 9114 §9's rule that unknown values are ignored, quoted in
            // full in `super`. It applies before the request too: a grease
            // frame is skipped rather than counted as the stream's first.
            Some(Item::Skipped { .. }) => {}

            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# Receipt of an invalid sequence of frames MUST be treated as a
            //# connection error of type H3_FRAME_UNEXPECTED. In particular, a
            //# DATA frame before any HEADERS frame, or a HEADERS or DATA frame
            //# after the trailing HEADERS frame, is considered invalid.
            //
            // The first of those cases. What may follow the HEADERS is judged
            // by `Reader::recv_data`, under the stricter rule §4.4 gives a
            // stream whose CONNECT has completed.
            Some(_) => {
                return Err(Violation::connection(
                    Code::H3_FRAME_UNEXPECTED,
                    "a request stream that does not begin with HEADERS",
                )
                .into());
            }

            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# If a client-initiated stream terminates without enough of the
            //# HTTP message to provide a complete response, the server SHOULD
            //# abort its response stream with the error code
            //# H3_REQUEST_INCOMPLETE.
            //
            // A SHOULD, and this server takes it: the RESET_STREAM that
            // `Resolver::resolve` sends for a stream-class violation is that
            // abort.
            None => {
                return Err(Violation::stream(
                    Code::H3_REQUEST_INCOMPLETE,
                    "the request stream ended before its HEADERS frame",
                )
                .into());
            }
        }
    };

    Ok(build_request(qpack::decode(
        &block,
        MAX_FIELD_SECTION_SIZE,
    )?)?)
}

/// A frame header on its own, the first chunk of a two-chunk write.
///
/// A fresh buffer per frame. quinn keeps a chunk until the peer acknowledges
/// it, so a buffer kept for reuse would still be shared at the next frame and
/// would allocate again on every frame anyway.
fn frame_header(kind: u64, payload_len: usize) -> Bytes {
    let mut header = BytesMut::with_capacity(2 * VARINT_MAX_LEN);
    frame::put_header(&mut header, kind, crate::varint::len_u64(payload_len));
    header.freeze()
}

/// A bidirectional request stream.
pub struct Stream {
    handle: Handle,
    /// The sending side, already in the form [`Self::split`] hands out.
    writer: Writer,
    frames: FrameReader,
}

impl Stream {
    /// The QUIC stream id.
    ///
    /// The Quarter Stream ID of RFC 9297 is this value divided by four.
    pub fn id(&self) -> u64 {
        u64::from(self.writer.send.id())
    }

    /// Claims this stream's inbound HTTP Datagrams (RFC 9297 §2.1).
    ///
    /// Every datagram on the connection names a request stream by Quarter
    /// Stream ID, which is that stream's id divided by four; this is how the
    /// one stream that wants them says so. Until it is called nothing routes to
    /// this stream and it costs nothing, so a TCP tunnel, which has no use for a
    /// datagram, never enters the routing table.
    ///
    /// `None` if they have already been claimed. Only the first caller can be
    /// the session, because the [`DatagramReceiver`] deregisters the stream when
    /// it is dropped and a second one would take the first's entry with it.
    ///
    /// Called *before* the response, not after: RFC 9298 §5 lets a client start
    /// sending payloads before its request is answered, and a claim made here
    /// means those land in the session's queue rather than being dropped as
    /// belonging to no one.
    pub fn datagrams(&mut self) -> Option<DatagramReceiver> {
        self.handle
            .register_datagrams(crate::datagram::quarter_stream_id(self.id()))
    }

    /// Closes the whole connection with `code` and `reason`, for a reason of
    /// this server's own rather than a protocol violation by the peer.
    ///
    /// The same CONNECTION_CLOSE as `quinn::Connection::close` with this code
    /// and reason, except that the close is also recorded as the connection's
    /// reason. The connection's error then names this close, even if another
    /// task finds a violation afterwards in stream data buffered before it.
    pub fn close_connection(&self, code: Code, reason: &'static str) {
        let _ = self.handle.close_for(code, reason);
    }

    /// Sends a response with `fields` and no body.
    ///
    /// Only the field lines given are sent. Nothing synthesises a
    /// Content-Length or Content-Type, both of which RFC 9297 §3.2 forbids on a
    /// capsule-carrying response. A 2xx answer to CONNECT must carry neither
    /// Content-Length nor Transfer-Encoding, which a caller meets by passing an
    /// empty [`Fields`]. The two rules are in different places. RFC 9110 §8.6
    /// has the first: "A server MUST NOT send a Content-Length header field in any 2xx
    /// (Successful) response to a CONNECT request". The second is RFC
    /// 9114 §4.1's, and is about every HTTP/3 message rather than about CONNECT:
    /// transfer codings "are not defined for HTTP/3; the Transfer-Encoding
    /// header field MUST NOT be used".
    ///
    /// Private, and deliberately: it waits on the peer's flow-control window
    /// with nothing to end the wait, so [`Self::respond_within`] is the only way
    /// out of this module to answer a request.
    async fn respond_with(&mut self, status: Status, fields: Fields) -> Result<(), StreamError> {
        // RFC 9114 §4.3.2: `:status` is the one pseudo-header a response has,
        // and it comes before every regular field (§4.3).
        let mut block = BytesMut::new();
        qpack::encode(
            &mut block,
            std::iter::once((&b":status"[..], status.as_str().as_bytes())).chain(
                fields
                    .iter()
                    .map(|(name, value)| (name.as_bytes(), value.as_bytes())),
            ),
        );

        let mut chunks = [frame_header(frame::HEADERS, block.len()), block.freeze()];
        self.writer.send.write_all_chunks(&mut chunks).await?;
        Ok(())
    }

    /// Sends a response with `fields`, bounded by the connection's idle
    /// timeout.
    ///
    /// # The deadline
    ///
    /// The write is the one step in answering a request that depends on the
    /// peer. A client that grants no flow-control window never takes the
    /// fifty-odd bytes of a 407, and without a deadline the task waits for that
    /// window until the connection ends. Every such request leaves a task
    /// holding the whole decoded request, and the count of authentication
    /// failures that makes a guesser pay a handshake is recorded around one of
    /// these calls.
    ///
    /// The bound is the connection's own idle timeout, read from the
    /// connection rather than passed in (see `connection::Handle::idle`).
    ///
    /// The lapsed answer is abandoned with a reset rather than left to a FIN
    /// that cannot be sent either: the request will not be answered, which is
    /// what RFC 9114 §8.1 gives H3_REQUEST_CANCELLED for. "The request
    /// or its response (including pushed response) is cancelled." Only the
    /// stream ends; the connection carries on serving everything else on it.
    pub async fn respond_within(
        &mut self,
        status: Status,
        fields: Fields,
    ) -> Result<(), RespondError> {
        match tokio::time::timeout(self.handle.idle, self.respond_with(status, fields)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(RespondError::Failed(error)),
            Err(_elapsed) => {
                self.reset(Code::H3_REQUEST_CANCELLED);
                Err(RespondError::Expired)
            }
        }
    }

    /// Ends the sending side cleanly (a QUIC stream FIN).
    ///
    /// Not `async`: [`quinn::SendStream::finish`] records that the stream is
    /// over and returns, and the FIN travels with the bytes already queued.
    /// There is nothing to wait for, and a caller that wants the peer's
    /// acknowledgement is asking a different question.
    pub fn finish(&mut self) -> Result<(), StreamError> {
        self.writer.finish()
    }

    /// Asks the peer to stop sending on this stream.
    pub fn stop_receiving(&mut self, code: Code) {
        self.frames.stop(code);
    }

    /// Abruptly ends the sending side with an error code.
    ///
    /// The counterpart to [`Stream::finish`], and the only one of the two that
    /// gets through to a peer that has stopped granting flow-control credit: a
    /// FIN travels at the end of the bytes already queued and so waits for a
    /// window that may never come, while a reset is a frame of its own and
    /// leaves at once. So this is the way to abandon a response nobody is
    /// reading. Abandoning it ends the stream and returns the peer's stream
    /// allowance.
    pub fn reset(&mut self, code: Code) {
        self.writer.reset(code);
    }

    /// Splits the stream so each direction can be pumped independently.
    ///
    /// This is what makes TCP half-close expressible: one direction can finish
    /// while the other keeps flowing.
    ///
    /// Both tunnels call this immediately after answering the CONNECT with a
    /// 2xx, so this is also where "the CONNECT method has completed" happens:
    /// from here the reader applies RFC 9114 §4.4's rule that only DATA may
    /// follow, deciding it from each frame's header rather than after its
    /// payload.
    pub fn split(self) -> (Writer, Reader) {
        let mut frames = self.frames;
        frames.connect_completed();

        (
            self.writer,
            Reader {
                handle: self.handle,
                frames,
                deferred: None,
            },
        )
    }
}

/// Why a bounded response never reached the peer.
///
/// The two leave the stream in different states: a failed write is a stream
/// that has already ended, while a lapsed deadline is a peer that is still
/// there and will not read what it asked for.
#[derive(Debug)]
pub enum RespondError {
    /// The write failed: the peer reset or stopped the stream, or the
    /// connection ended under it.
    Failed(StreamError),
    /// The deadline lapsed with the response unwritten.
    ///
    /// The stream has already been reset with H3_REQUEST_CANCELLED, so there is
    /// nothing left to send or finish on it.
    Expired,
}

/// The sending half of a split request stream.
pub struct Writer {
    send: quinn::SendStream,
}

impl Writer {
    /// Sends `block` as one DATA frame, applying the peer's flow-control
    /// backpressure.
    ///
    /// `block` is [`frame::DATA_HEADER_ROOM`] bytes of room followed by a
    /// payload that is not empty; [`frame::seal_data`] writes the header into
    /// that room. The frame then reaches quinn as one chunk that shares the
    /// buffer the payload was read into: no second `Bytes`, no scratch block
    /// for the header, and no copy.
    ///
    /// Not cancel-safe, unlike [`Reader::recv_data`]. A peer that grants no
    /// flow-control credit can block this indefinitely, so both tunnels abandon
    /// it on a timeout in the states where nothing else ends the wait. A caller
    /// that does may not finish the stream afterwards. quinn may take a prefix
    /// of the frame and wait on the rest, so an abandoned call can leave a
    /// truncated DATA frame, and RFC 9114 §7.1 says what that costs: "When a
    /// stream terminates cleanly, if the last frame on the stream was
    /// truncated, this MUST be treated as a connection error of type
    /// H3_FRAME_ERROR. Streams that terminate abruptly may be reset at any
    /// point in a frame." So a reset behind an abandoned send is what makes the
    /// truncation legal, and a FIN in its place is the connection error that
    /// sentence names.
    ///
    /// # Panics
    ///
    /// If `block` holds nothing behind its room: a caller with no payload has
    /// reached EOF and has no frame to send.
    pub async fn send_data_in_place(&mut self, block: BytesMut) -> Result<(), StreamError> {
        self.send.write_chunk(frame::seal_data(block)).await?;
        Ok(())
    }

    /// Ends the sending side cleanly (a QUIC stream FIN), without awaiting.
    ///
    /// Synchronous for the reason [`Stream::finish`] gives.
    pub fn finish(&mut self) -> Result<(), StreamError> {
        self.send.finish()?;
        Ok(())
    }

    /// Resolves when the peer stops this stream, or the connection under it
    /// ends.
    ///
    /// The counterpart of [`Reader::reset_by_peer`] on the sending half.
    /// [`Self::send_data_in_place`] already reports a `STOP_SENDING` as the error a
    /// write fails with, but only to a caller that is writing. A CONNECT tunnel
    /// spends much of its life not writing: with the client's half of the
    /// tunnel finished and a target that has yet to send anything, the pump
    /// waits in a read of the *target*, and nothing there watches the request
    /// stream. Such a read can select on this.
    ///
    /// # Why this one may be held across writes
    ///
    /// The future borrows nothing: [`quinn::SendStream::stopped`] clones the
    /// connection handle and the stream id into an owned future. So a caller
    /// builds it once, before its loop, and keeps polling the same one while
    /// writing to the same stream through `&mut self`. A fresh future per
    /// iteration would take the connection lock on every pass, while one that
    /// is kept registers once and is a bare `Notified` poll afterwards.
    ///
    /// This is safe where `quinn::RecvStream::received_reset` is not (see
    /// [`Reader::reset_by_peer`]): quinn keeps a `Notify` per stream rather
    /// than a single-slot waker, and removes it only when the peer stops the
    /// stream, a finished stream's data is all acknowledged, or the connection
    /// ends. So a stream this endpoint resets keeps its entry, a map slot and
    /// an `Arc<Notify>`, until the connection closes, and the map grows by one
    /// for each such stream; that is quinn's bookkeeping and cannot be avoided
    /// without giving up the `STOP_SENDING` watch.
    ///
    /// Cancel-safe, so a `select!` may poll it and set it aside repeatedly.
    ///
    /// # What it resolves to
    ///
    /// Only endings. `Ok(Some(code))` is the peer's `STOP_SENDING` and is the
    /// case this exists for. A lost connection is reported as such. Quinn's
    /// `Ok(None)` means the stream is gone from the transport: this endpoint
    /// finished it and the peer acknowledged every byte, or this endpoint reset
    /// it and the peer acknowledged the reset. It is reported as this
    /// endpoint's own ending. All three mean the same thing to a caller:
    /// nothing more will be sent on this stream.
    pub fn stopped(
        &self,
    ) -> impl std::future::Future<Output = StreamError> + Send + 'static + use<> {
        let stopped = self.send.stopped();

        async move {
            match stopped.await {
                Ok(Some(code)) => StreamError::RemoteTerminate {
                    code: Code::new(code.into_inner()),
                },
                Ok(None) => StreamError::Local(Violation::stream(
                    Code::H3_NO_ERROR,
                    "the response stream is over",
                )),
                Err(quinn::StoppedError::ConnectionLost(error)) => {
                    StreamError::Connection(error.into())
                }
                // 0-RTT, which this server never accepts; see `error::internal`.
                Err(other) => StreamError::Local(Violation::stream(
                    Code::H3_INTERNAL_ERROR,
                    other.to_string(),
                )),
            }
        }
    }

    /// Abruptly resets the sending side with an error code.
    pub fn reset(&mut self, code: Code) {
        // Fails only if the stream is already finished or reset, which needs no
        // reporting: either way nothing more will be sent on it.
        let _ = self.send.reset(varint(code));
    }
}

/// The receiving half of a split request stream.
pub struct Reader {
    handle: Handle,
    frames: FrameReader,
    /// A frame-layer error [`Self::try_recv_data`] found and has not reported.
    ///
    /// Kept rather than acted on, because the pieces handed out before it may
    /// not have reached the far side of the tunnel yet. [`Self::recv_data`]
    /// reports it the next time it is called, which a caller does only once it
    /// has dealt with those pieces.
    deferred: Option<frame::Error>,
}

impl Reader {
    /// Reads the next chunk of body data.
    ///
    /// `Ok(None)` means the peer finished its sending side: for a CONNECT
    /// tunnel, the client's FIN.
    ///
    /// Cancel-safe: every byte read is accounted for in `self` before this
    /// returns, so a caller may poll it inside a `select!` with a timeout, as a
    /// UDP session does.
    pub async fn recv_data(&mut self) -> Result<Option<Bytes>, StreamError> {
        if let Some(error) = self.deferred.take() {
            return Err(self.report(error));
        }

        loop {
            let item = match self.frames.next().await {
                Ok(Some(item)) => item,
                Ok(None) => return Ok(None),
                Err(error) => return Err(self.report(error)),
            };

            match body_piece(item) {
                Ok(Some(data)) => return Ok(Some(data)),
                Ok(None) => {}
                Err(error) => return Err(self.report(error)),
            }
        }
    }

    /// The next chunk of body data if it can be decoded without waiting, from
    /// bytes this reader has already taken from quinn.
    ///
    /// The way to gather what one read took ([`frame::READ_AHEAD_CHUNKS`]) into
    /// one write: call [`Self::recv_data`] for the first piece, then this until
    /// it returns `None`.
    ///
    /// `None` means only that nothing more is ready. It never means the stream
    /// ended: the client's FIN, a reset and a lost connection are all reported
    /// by [`Self::recv_data`], after every piece that came before them. Like
    /// that method it never hands out an empty piece.
    ///
    /// A protocol violation found here is not reported here. It is kept and
    /// reported by the next [`Self::recv_data`], and this returns `None` until
    /// then. The pieces before the violation have been handed out by the time
    /// it is found, but the caller may not have written them yet; acting on the
    /// violation now, which can close the connection, would put it ahead of
    /// them.
    ///
    /// Does not take the connection's lock.
    pub fn try_recv_data(&mut self) -> Option<Bytes> {
        if self.deferred.is_some() {
            return None;
        }

        loop {
            let found = match self.frames.try_next() {
                Ok(Some(item)) => body_piece(item),
                Ok(None) => return None,
                Err(error) => Err(error),
            };

            match found {
                Ok(Some(data)) => return Some(data),
                Ok(None) => {}
                Err(error) => {
                    self.deferred = Some(error);
                    return None;
                }
            }
        }
    }

    /// How long [`Reader::reset_by_peer`] may take to notice a reset that
    /// arrived while quinn held bytes of the stream that no read had taken.
    ///
    /// Only that case costs anything: a zero-length read cannot wait on a
    /// stream that has bytes to give, so the watcher looks again on a timer
    /// instead. A reset that lands while quinn has nothing of the stream wakes
    /// the waiting read at once. Bytes in the read-ahead do not count either
    /// way (see `FrameReader::readable`).
    ///
    /// 250 ms is an order of magnitude under the bound the regression test
    /// holds the target's close to. Without a bound, a client that reset its
    /// request stream while its target had stopped reading would hold the
    /// target socket, its file descriptor and the tunnel slot for the life of
    /// the QUIC connection. A peer cannot stretch it: the timer is this
    /// server's, and sending more bytes only keeps the watcher on the same
    /// timer.
    const RESET_PEEK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

    /// Resolves when the peer resets this stream, with the reset as an error.
    ///
    /// [`Self::recv_data`] already reports a reset as the `Err` a read fails
    /// with, but only to a caller that is reading. A CONNECT tunnel spends much
    /// of its life not reading: with a chunk in hand and a target that has
    /// stopped taking bytes, the pump waits in a write instead, and nothing
    /// there watches the request stream. Such a write can select on this.
    ///
    /// It reports a reset and a lost connection, and never resolves for any
    /// other ending. A clean FIN and a stream this endpoint stopped both belong
    /// to the reading half, which is where a caller meets them; ending the wait
    /// here would turn one of them into an abort.
    ///
    /// # Why not `quinn::RecvStream::received_reset`
    ///
    /// Because it takes a slot it never gives back, and quinn asserts on that
    /// slot being empty. quinn keeps **one** waker per stream for whoever is
    /// waiting to read, and on a live connection three things take an entry
    /// out of it: a `StreamEvent::Readable` for that stream, a
    /// `RecvStream::stop` while the stream still exists at the protocol layer,
    /// and `RecvStream::drop` while `all_data_read` is still false. The end of
    /// the connection empties every slot. A read that *succeeds* takes nothing
    /// out, so an entry outlives every later read of the bytes it was waiting
    /// for. That call writes into the slot on every poll that finds no reset,
    /// and a `select!` which drops the arm leaves it behind.
    ///
    /// In release builds that is a leak of one waker per tunnel until the
    /// connection closes. In debug builds it is a panic, because
    /// `RecvStream::drop` debug-asserts the slot is empty once the stream has
    /// been read to its end, and an ordinary upload, whose pump waits in a
    /// write while later chunks and the FIN are already buffered, leaves such
    /// an entry behind.
    ///
    /// So the wait is built on the zero-length read alone, which registers only
    /// through quinn's own read path. That kind of entry is safe to abandon:
    /// quinn takes it out again when the stream becomes readable, and a stream
    /// cannot reach its end without becoming readable first, so there is never
    /// one left when the reading half meets the FIN.
    ///
    /// # What that costs
    ///
    /// A zero-length read waits only while the stream has nothing to give.
    /// With bytes already buffered it returns at once, and a stalled upload is
    /// in that state. So the wait there is a poll on a timer rather than a
    /// wake-up, and `RESET_PEEK_INTERVAL` bounds how late the reset is noticed.
    /// A reset that arrives while nothing is buffered needs no timer: it wakes
    /// the waiting read at once, as any read error would.
    ///
    /// # The read-ahead
    ///
    /// The zero-length read asks quinn alone (`FrameReader::readable` says
    /// what that leaves out). A reset found here is reported while the
    /// read-ahead may still hold bytes the client sent before it. The reading
    /// half would hand those out first; this reports only the reset, and a
    /// tunnel acting on it drops them with the rest of the stream. That matches
    /// quinn, which discards a reset stream's unread bytes.
    ///
    /// # A lost connection
    ///
    /// The end of the connection is reported too, as
    /// [`StreamError::Connection`], whatever state the stream is in. The
    /// zero-length read cannot be relied on for it: quinn reports the
    /// connection's error only to a read that finds nothing, so while bytes are
    /// waiting it keeps answering that they are, after the connection is gone.
    /// So every wait here also watches the connection's close. Without that, a
    /// tunnel whose write to its target is stalled outlives its connection
    /// until the tunnel's own stall bound, holding its target socket.
    ///
    /// Cancel-safe, so a `select!` may poll it and drop it repeatedly.
    pub async fn reset_by_peer(&mut self) -> StreamError {
        // Built once per call, so the connection's lock is taken for it once
        // and not on every pass of the timer below.
        let closed = self.handle.quic.closed();
        tokio::pin!(closed);

        loop {
            match self.frames.readable().await {
                // Bytes are waiting in quinn, so a read cannot wait on this
                // stream and nothing will wake it. Look again shortly.
                Ok(true) => tokio::select! {
                    () = tokio::time::sleep(Self::RESET_PEEK_INTERVAL) => {}
                    error = &mut closed => return StreamError::Connection(error.into()),
                },

                // The peer finished and quinn has handed over everything it
                // sent; the read-ahead may still hold the last of it. That is
                // not a reset and can no longer become one.
                Ok(false) => return StreamError::Connection(closed.await.into()),

                Err(quinn::ReadError::Reset(code)) => {
                    return StreamError::RemoteTerminate {
                        code: Code::new(code.into_inner()),
                    };
                }

                // The connection under the stream went away, which is an ending
                // this half can report: no reader is left to meet it either.
                Err(quinn::ReadError::ConnectionLost(error)) => {
                    return StreamError::Connection(error.into());
                }

                // A stream this endpoint has already stopped or finished with,
                // and the ordered/unordered mix-up that cannot happen here:
                // nothing a tunnel acts on, short of the connection's end.
                Err(_) => return StreamError::Connection(closed.await.into()),
            }
        }
    }

    /// Asks the peer to stop sending on this stream.
    pub fn stop_receiving(&mut self, code: Code) {
        self.frames.stop(code);
    }

    /// Answers a frame-layer failure and reports it as a stream error.
    ///
    /// Only the receiving half is here, so nothing resets the response side:
    /// that is the caller's decision, and the tunnels make it differently for a
    /// client abort than for a target failure.
    fn report(&mut self, error: frame::Error) -> StreamError {
        answer(&self.handle, &mut self.frames, None, error)
    }
}

/// The halves [`Stream::split`] hands a tunnel, over the request stream `send`
/// and `recv` of the live QUIC connection `quic`, for the tunnels' unit tests.
///
/// The stream's request is taken as read and answered, so the reader is in
/// the mode a split puts it in: only DATA may follow.
#[cfg(test)]
pub(crate) fn tunnel_halves(
    quic: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) -> (Writer, Reader) {
    let handle = Handle::for_tests(quic);
    let frames = FrameReader::on_request_stream(recv, handle.budget());
    Stream {
        handle,
        writer: Writer { send },
        frames,
    }
    .split()
}

/// What one decoded item of a tunnel's body is to a [`Reader`]: a piece to hand
/// out, nothing, or a violation.
///
/// One function for [`Reader::recv_data`] and [`Reader::try_recv_data`], so the
/// two cannot disagree about which items surface.
fn body_piece(item: Item) -> Result<Option<Bytes>, frame::Error> {
    match item {
        // RFC 9114 §9's rule that unknown values are ignored, quoted in full in
        // `super`.
        Item::Skipped { .. } => Ok(None),

        // An empty DATA frame is legal and says nothing, so it must not surface
        // as `Some(empty)`: a caller relaying the body would put a zero-length
        // packet on the far side of the tunnel, and a caller counting chunks
        // would count one that carried nothing.
        Item::Data(data) if data.is_empty() => Ok(None),

        Item::Data(data) => Ok(Some(data)),

        // RFC 9114 §4.4's rule that only DATA may follow a completed CONNECT is
        // applied a layer down, by `frame::misplaced`, so that it is decided
        // from a frame's header rather than after its payload has been buffered
        // and charged for. [`Stream::split`] puts a reader's decoder into that
        // mode, and a [`Reader`] exists only through it.
        //
        // So nothing reaches this arm. It repeats the verdict rather than
        // relaying an unexpected frame into a tunnel, because the type system
        // does not know which mode a decoder is in.
        Item::Frame(_) => Err(Violation::connection(
            Code::H3_FRAME_UNEXPECTED,
            frame::NON_DATA_FRAME_ON_A_TUNNEL,
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    // -----------------------------------------------------------------------
    // A tunnel's reader over a live QUIC stream
    // -----------------------------------------------------------------------

    use super::frame::loopback;

    /// The [`Reader`] a split request stream hands a tunnel, on the server
    /// side of `upload`.
    fn tunnel_reader(upload: &mut loopback::Upload) -> Reader {
        let handle = Handle::for_tests(upload.server.clone());
        let mut frames = FrameReader::on_request_stream(upload.take_recv(), handle.budget());
        frames.connect_completed();
        Reader {
            handle,
            frames,
            deferred: None,
        }
    }

    /// Appends one frame of `kind` carrying `payload` to `wire`.
    fn push_frame(wire: &mut BytesMut, kind: u64, payload: &[u8]) {
        // A test length, far inside a `u64`.
        #[allow(clippy::as_conversions)]
        frame::put_header(wire, kind, payload.len() as u64);
        wire.extend_from_slice(payload);
    }

    /// The value `future` has without waiting, or `None` if it would wait.
    fn poll_once<F: std::future::Future>(future: std::pin::Pin<&mut F>) -> Option<F::Output> {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match future.poll(&mut cx) {
            std::task::Poll::Ready(value) => Some(value),
            std::task::Poll::Pending => None,
        }
    }

    /// One awaited read and then `try_recv_data` hand out the whole body, in
    /// order, with no empty piece, and in far fewer awaits than there are
    /// frames.
    ///
    /// The body mixes empty DATA frames and reserved frame types among the
    /// ordinary ones, because both are items the decoder produces that must
    /// not reach the tunnel as a piece.
    #[tokio::test]
    async fn try_recv_data_gathers_what_one_read_took_and_no_empty_piece() {
        const FRAMES: u8 = 120;
        let mut wire = BytesMut::new();
        let mut payload = Vec::new();
        for index in 0..FRAMES {
            let body = vec![index; 700];
            push_frame(&mut wire, frame::DATA, &body);
            push_frame(&mut wire, frame::DATA, b"");
            // 0x21 is the first reserved type of RFC 9114 §7.2.8.
            push_frame(&mut wire, 0x21, b"grease");
            payload.extend_from_slice(&body);
        }

        let mut upload = loopback::Upload::start(&wire).await;
        upload.send.finish().expect("finish the request stream");
        let mut reader = tunnel_reader(&mut upload);

        let mut delivered = Vec::new();
        let mut awaits = 0;
        while let Some(first) = tokio::time::timeout(loopback::TIMEOUT, reader.recv_data())
            .await
            .expect("the body must arrive")
            .expect("the body is well formed")
        {
            awaits += 1;
            assert!(!first.is_empty(), "an empty piece surfaced");
            delivered.extend_from_slice(&first);
            while let Some(more) = reader.try_recv_data() {
                assert!(!more.is_empty(), "an empty piece surfaced");
                delivered.extend_from_slice(&more);
            }
        }

        assert_eq!(delivered, payload, "every byte, in order");
        assert!(
            awaits < usize::from(FRAMES) / 4,
            "{awaits} awaited reads for {FRAMES} frames"
        );
    }

    /// A violation found while gathering is reported only after the pieces
    /// before it, and by `recv_data`.
    ///
    /// A HEADERS frame on a tunnel is a connection error (RFC 9114 §4.4). It
    /// sits behind ten DATA frames in the same read. `try_recv_data` hands out
    /// all ten and then nothing, and the connection is still open at that
    /// point: closing it is what reporting the violation does, and that must
    /// wait until the caller has written the ten. The next `recv_data` reports
    /// it.
    #[tokio::test]
    async fn a_violation_behind_data_is_reported_after_that_data() {
        let mut wire = BytesMut::new();
        let mut payload = Vec::new();
        for index in 0..10u8 {
            let body = vec![index; 1000];
            push_frame(&mut wire, frame::DATA, &body);
            payload.extend_from_slice(&body);
        }
        push_frame(&mut wire, frame::HEADERS, b"trailer");
        push_frame(&mut wire, frame::DATA, b"never relayed");

        let mut upload = loopback::Upload::start(&wire).await;
        let mut reader = tunnel_reader(&mut upload);

        let mut delivered = Vec::new();
        let first = reader
            .recv_data()
            .await
            .expect("the first piece is well formed")
            .expect("the first piece");
        delivered.extend_from_slice(&first);
        while let Some(more) = reader.try_recv_data() {
            delivered.extend_from_slice(&more);
        }

        assert_eq!(delivered, payload, "the ten frames before the violation");
        assert!(
            upload.server.close_reason().is_none(),
            "the violation was acted on before the data ahead of it was handed back"
        );
        assert!(
            reader.try_recv_data().is_none(),
            "nothing follows a violation"
        );

        let error = tokio::time::timeout(loopback::TIMEOUT, reader.recv_data())
            .await
            .expect("the kept violation needs no read")
            .expect_err("the violation must be reported");
        assert_matches!(
            error,
            StreamError::Connection(_),
            "expected a connection error, got {error}"
        );
        assert!(
            upload.server.close_reason().is_some(),
            "reporting a connection error closes the connection"
        );
    }

    /// A reset that arrives while the read-ahead holds the rest of the body,
    /// and quinn holds nothing, wakes the watcher at once.
    ///
    /// The watcher asks quinn with a zero-length read. The first awaited read
    /// took everything quinn had, so that read parks rather than finding bytes
    /// and going on the 250 ms timer, and the reset completes it. Polled by
    /// hand: a watcher on the timer would still be asleep on the second poll,
    /// so the answer does not depend on how fast the host is.
    #[tokio::test]
    async fn the_watcher_wakes_for_a_reset_while_the_read_ahead_holds_bytes() {
        let (wire, _) = loopback::numbered_frames(10, 1000);
        let mut upload = loopback::Upload::start(&wire).await;
        let mut reader = tunnel_reader(&mut upload);

        reader
            .recv_data()
            .await
            .expect("the first piece is well formed")
            .expect("the first piece");

        let watcher = reader.reset_by_peer();
        tokio::pin!(watcher);
        assert!(
            poll_once(watcher.as_mut()).is_none(),
            "nothing has been reset yet"
        );

        upload
            .send
            .reset(quinn::VarInt::from_u32(0x10c))
            .expect("reset the request stream");
        upload.settle().await;

        let error = poll_once(watcher.as_mut())
            .expect("the reset must complete the parked read without a timer");
        assert_matches!(error, StreamError::RemoteTerminate { code } if code.value() == 0x10c,
            "expected the peer's reset, got {error}");
    }

    /// The watcher reports a lost connection while quinn still holds bytes of
    /// the stream that no read has taken.
    ///
    /// That is the state of a tunnel whose write to its target is stalled, and
    /// there the zero-length read keeps answering that bytes are waiting after
    /// the connection is gone, because quinn looks at the connection's error
    /// only when a read finds nothing. A watcher that only asked again on its
    /// timer never ended, and held the tunnel and its target socket until the
    /// tunnel's own stall bound.
    #[tokio::test]
    async fn the_watcher_reports_a_lost_connection_while_quinn_holds_bytes() {
        let (wire, _) = loopback::numbered_frames(10, 1000);
        let mut upload = loopback::Upload::start(&wire).await;
        let mut reader = tunnel_reader(&mut upload);

        let watcher = reader.reset_by_peer();
        tokio::pin!(watcher);
        assert!(
            poll_once(watcher.as_mut()).is_none(),
            "nothing has ended yet"
        );

        upload.server.close(quinn::VarInt::from_u32(0), b"gone");

        let error = tokio::time::timeout(loopback::TIMEOUT, watcher)
            .await
            .expect("the watcher must report the lost connection");
        assert_matches!(
            error,
            StreamError::Connection(_),
            "expected the lost connection, got {error}"
        );
    }
}
