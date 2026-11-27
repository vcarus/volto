//! The peer's unidirectional streams (RFC 9114 §6.2): dispatching each by its
//! type, the control stream's frame rules, and the checks on the two QPACK
//! streams (RFC 9204 §4.2).

use std::borrow::Cow;

use tracing::debug;

use crate::varint::{VARINT_MAX_LEN, peek_varint, varint_len_of_first};

use super::connection::{
    Handle, OnceStream, STREAM_CONTROL, STREAM_PUSH, STREAM_QPACK_DECODER, STREAM_QPACK_ENCODER,
    Shared,
};
use super::error::{Code, StreamError, Violation};
use super::frame::{self, BufferBudget, Frame, FrameReader, Item};
use super::varint;

/// Dispatches one unidirectional stream by its type (RFC 9114 §6.2).
///
/// # The deadline on the type
///
/// Until its type varint arrives, a stream cannot be classified as the control
/// stream, a QPACK stream, or something to abort. So reading the type is the
/// one wait here that no protocol rule ends. A peer that opens streams and
/// writes half a varint on each would hold a task apiece for as long as the
/// connection lives.
///
/// One idle timeout bounds it, as `Handle::idle` describes. What
/// follows is a `stop`, not a connection error: nothing was violated, and the
/// peer keeps every stream it has underway. The code is our own choice. A
/// stream that never declares its type is one this endpoint will not accept,
/// which is how RFC 9114 §8.1 defines it:
///
//= https://www.rfc-editor.org/rfc/rfc9114#section-8.1
//# H3_STREAM_CREATION_ERROR (0x0103):  The endpoint detected that its
//# peer created a stream that it will not accept.
///
/// It is also the code §6.2 recommends for aborting an unknown stream type,
/// three arms below.
pub(super) async fn serve_stream(handle: Handle, mut recv: quinn::RecvStream) {
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
            if handle.shared.opened_before(OnceStream::Control) {
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
        //# stream or discard incoming data without further processing.  If
        //# reading is aborted, the recipient SHOULD use the
        //# H3_STREAM_CREATION_ERROR error code or a reserved error code
        //# (Section 8.1).  The recipient MUST NOT consider unknown stream types
        //# to be a connection error of any kind.
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
    // Not the connection's budget; [`BufferBudget::unshared`] says why.
    let mut frames = FrameReader::on_server_control(recv, BufferBudget::unshared());
    let mut control = Control::default();

    // The two endings RFC 9114 §6.2.1 forbids, as a detail string for
    // [`critical_stream_closed`]. Both leave the loop rather than reporting on
    // the spot, so the exemption is checked once and is the same for a clean
    // finish and a reset:
    //
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
    //# The sender MUST NOT close the control stream, and the receiver
    //# MUST NOT request that the sender close the control stream.
    let ended: Cow<'static, str> = loop {
        // Read before `next`: the decoder records a SETTINGS when it returns
        // one, and `accept` needs the state from before this item.
        let settings_seen = frames.settings_seen();
        let item = match frames.next().await {
            Ok(Some(item)) => item,

            Ok(None) => break "the peer closed its control stream".into(),

            // Every framing rule is fatal here, whatever it would have been on
            // a request stream: the connection cannot go on without the stream
            // that carries SETTINGS and GOAWAY.
            Err(frame::Error::Protocol(violation)) => {
                handle.fail(violation.into_fatal());
                return;
            }
            // The connection ending under the control stream is not the
            // control stream failing. The caller waiting in `accept` already
            // has the real reason. A critical-stream error here would replace
            // an idle timeout, the ordinary ending, with a protocol violation
            // in the operator's log.
            Err(frame::Error::Stream(StreamError::Connection(_))) => return,

            Err(frame::Error::Stream(error)) => {
                break format!("the peer reset its control stream: {error}").into();
            }
        };

        if let Err(violation) = control.accept(item, settings_seen, &handle.shared) {
            handle.fail(violation);
            return;
        }
    };

    if let Some(violation) = critical_stream_closed(ended, handle.quic.close_reason().as_ref()) {
        handle.fail(violation);
    }
}

/// What an ending of one of the peer's critical streams means, given
/// `close_reason`.
///
/// One helper for the three streams and for both of the endings each of them
/// has, because the two RFCs state one verdict for all six: neither tells a
/// clean finish from a reset, and neither tells the control stream from a QPACK
/// stream. `detail` says which stream ended and how, for the message only.
///
/// `close_reason` is [`quinn::Connection::close_reason`]: `Some` once the
/// connection is over, whoever ended it.
///
/// The rule below always applies while the connection is live. Once it has
/// ended, there is nothing left to protect. A peer closing a connection
/// finishes or resets its send streams and sends CONNECTION_CLOSE at the same
/// time, and the two can be read here in either order. Answering an ordinary
/// close with a protocol error would log that race as a fault.
fn critical_stream_closed(
    detail: impl Into<Cow<'static, str>>,
    close_reason: Option<&quinn::ConnectionError>,
) -> Option<Violation> {
    if close_reason.is_some() {
        return None;
    }

    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
    //# If either control stream is closed at any point, this MUST be treated
    //# as a connection error of type H3_CLOSED_CRITICAL_STREAM.

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

/// The control stream's frame rules (RFC 9114 §6.2.1).
///
/// Separated from the reading loop so the rules can be tested as a table rather
/// than through a live connection. Whether SETTINGS has been seen is not stored
/// here: the stream's `FrameReader` records it, and [`Self::accept`] takes it as an
/// argument.
#[derive(Debug, Default)]
struct Control {
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
    /// 9114 §9 says to ignore it. So a peer may send them back to back for as
    /// long as the connection lives, and a log line apiece would be a large
    /// amplification. The line is a `debug!`, so it only reaches an operator
    /// who turned `debug` on to read what a client sends.
    ///
    /// The frames are not skipped silently, because greasing is how a peer
    /// checks that this server skips what it does not know, and a debug trace
    /// should show it. The doubling schedule keeps the first one and the size
    /// of the flood, and drops the repetition.
    skipped: crate::logfmt::Sampler,
}

impl Control {
    /// Applies one item from the control stream.
    ///
    /// `seen` is whether a SETTINGS frame came before this item.
    ///
    /// Through [`serve_control`] only these reach it: the first SETTINGS, and
    /// after it a GOAWAY, CANCEL_PUSH, MAX_PUSH_ID or skipped unknown frame.
    /// `frame::misplaced` refuses every other item from its frame header,
    /// before any payload is buffered, so that such a frame can neither hold
    /// the buffer budget nor run on unjudged. The other arms stay because the
    /// `match` has to cover every [`Frame`], and returning the same error is
    /// the safe answer if the rules in `frame::misplaced` ever change. They
    /// must not become a panic, because an unauthenticated peer writes this
    /// stream.
    fn accept(&mut self, item: Item, seen: bool, shared: &Shared) -> Result<(), Violation> {
        let frame = match item {
            Item::Frame(frame) => frame,

            // Unreachable, like every refusing arm below: `frame::misplaced`
            // decides these from the frame header and quotes the rules.
            Item::Data(_) => {
                return Err(if seen {
                    unexpected("a DATA frame on the control stream")
                } else {
                    missing_settings()
                });
            }

            // RFC 9114 §9's rule that unknown values are ignored, quoted in
            // full in `super`. A grease frame sent first never gets here.
            Item::Skipped { kind } => {
                if !seen {
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

        match (frame, seen) {
            (Frame::Settings(settings), false) => {
                shared.settings_arrived(settings.datagrams);
                Ok(())
            }

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

            // Unreachable through `serve_control`: `frame::misplaced` refuses
            // each of these from its header and quotes the rule it applies.
            (Frame::Settings(_), true) => Err(unexpected("a second SETTINGS frame")),
            (Frame::PushPromise, true) => Err(unexpected("a PUSH_PROMISE frame")),
            (Frame::Headers(_), true) => Err(unexpected("a HEADERS frame on the control stream")),
            (_, false) => Err(missing_settings()),
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
    /// This stream's kind among the ones the peer may open only once.
    fn once(self) -> OnceStream {
        match self {
            Self::Encoder => OnceStream::QpackEncoder,
            Self::Decoder => OnceStream::QpackDecoder,
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

/// The most continuation bytes an instruction's prefixed integer may run to.
///
/// RFC 9204 §4.1.1 requires decoding integers "up to and including 62 bits
/// long", which a 5- or 6-bit prefix reaches in nine continuation bytes of
/// seven bits each. A tenth is a value no conformant encoder produces, and this
/// server's own rule is to end the stream there rather than read on forever.
const MAX_INTEGER_CONTINUATION: usize = 9;

/// Where the peer's QPACK stream stands between two bytes.
///
/// The whole of [`serve_qpack`]'s per-byte state. The peer chooses where its
/// stream is cut into `read_chunk` results, and the verdict may not depend on
/// that. So the state lives across chunks, and the step that advances it is a
/// function of one byte and this state. That also lets the tests drive it
/// without a live [`quinn::RecvStream`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum QpackProgress {
    /// The next byte is the first byte of an instruction.
    #[default]
    Instruction,
    /// The next byte continues the prefixed integer that the last accepted
    /// instruction started. `continuation` is how many continuation bytes of
    /// that integer have been read so far.
    Integer { continuation: usize },
}

impl QpackProgress {
    /// Judges one byte of the peer's QPACK stream and advances the state.
    ///
    /// A byte is either a continuation of the integer the last instruction
    /// started, in which case only its top bit matters and the `continuation`
    /// count of [`Self::Integer`] counts it, or the first byte of a new
    /// instruction, which [`qpack_instruction`] judges.
    fn take(&mut self, kind: QpackStream, byte: u8) -> Result<(), Violation> {
        match *self {
            Self::Integer { continuation } => {
                let continuation = continuation + 1;
                if continuation > MAX_INTEGER_CONTINUATION {
                    return Err(Violation::connection(
                        kind.code(),
                        "an integer past 62 bits",
                    ));
                }
                *self = if byte & 0b1000_0000 != 0 {
                    Self::Integer { continuation }
                } else {
                    Self::Instruction
                };
            }
            Self::Instruction => {
                if qpack_instruction(kind, byte)? {
                    *self = Self::Integer { continuation: 0 };
                }
            }
        }
        Ok(())
    }
}

/// Reads one of the peer's QPACK streams for the life of the connection.
///
/// This decoder advertised a table capacity of zero and this encoder never
/// touches the dynamic table, so neither stream can carry an instruction that
/// changes anything here. They still have to be read: a receiver that never
/// reads stalls the peer's stream flow control, and RFC 9204 §4.2 forbids the
/// peer from closing them, so stopping them is not an option either. Reading
/// means checking: with no table, nearly every instruction is one the RFC makes
/// a connection error, and [`qpack_instruction`] says which. Only the first byte
/// of each is needed, so the rest of an accepted instruction is skipped, with
/// [`QpackProgress`] as the state.
///
/// RFC 9204 §4.2 also makes the *peer* closing one of these streams a
/// connection error; [`critical_stream_closed`] reports it, under the same
/// rules as for the control stream.
async fn serve_qpack(handle: &Handle, mut recv: quinn::RecvStream, kind: QpackStream) {
    if handle.shared.opened_before(kind.once()) {
        handle.fail(duplicate("a second QPACK stream of the same kind"));
        return;
    }

    let mut progress = QpackProgress::default();

    // The two endings §4.2 forbids, as a detail string for
    // [`critical_stream_closed`]. A read error that is the connection itself
    // ending needs no arm of its own: `close_reason` is `Some` by then, which
    // is exactly the exemption.
    let ended = loop {
        let chunk = match recv.read_chunk(usize::MAX, true).await {
            Ok(Some(chunk)) => chunk,

            Ok(None) => break format!("the peer closed its QPACK {} stream", kind.name()),
            Err(error) => {
                break format!("the peer reset its QPACK {} stream: {error}", kind.name());
            }
        };

        for &byte in &chunk.bytes {
            if let Err(violation) = progress.take(kind, byte) {
                handle.fail(violation);
                return;
            }
        }
    };

    if let Some(violation) = critical_stream_closed(ended, handle.quic.close_reason().as_ref()) {
        handle.fail(violation);
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
                // it sent had a non-zero Required Insert Count. On every stream,
                // all such sections (there are none) are already acknowledged.
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

    let length = varint_len_of_first(buf[0]);
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
    use bytes::Bytes;

    use super::*;

    fn settings(datagrams: bool) -> Item {
        Item::Frame(Frame::Settings(crate::h3::settings::Settings { datagrams }))
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
                .accept(first, false, &shared)
                .expect_err("refused");
            assert_eq!(error.code(), Code::H3_MISSING_SETTINGS);
            assert!(error.is_connection_error());
        }

        assert!(
            Control::default()
                .accept(settings(true), false, &shared)
                .is_ok()
        );
    }

    /// RFC 9114 §9 once the connection is up: an unknown frame type on the
    /// control stream is ignored, and greasing peers send them on purpose.
    #[test]
    fn an_unknown_frame_after_settings_is_ignored() {
        let shared = Shared::default();
        let mut control = Control::default();
        control
            .accept(settings(true), false, &shared)
            .expect("accepted");

        control
            .accept(
                Item::Skipped {
                    kind: 0x1f * 6 + 0x21,
                },
                true,
                &shared,
            )
            .expect("ignored");

        // And the stream carries on working afterwards.
        control
            .accept(Item::Frame(Frame::Goaway(4)), true, &shared)
            .expect("accepted");
    }

    /// A grease frame is two bytes on the wire and a peer may send them for as
    /// long as the connection lives, so a line apiece would be the highest
    /// ratio of journal to peer bytes in this server.
    ///
    /// What is asserted here is that every one of them reaches the sampler,
    /// which is the half the log cannot show: the schedule's whole point is that
    /// most occurrences produce no line, so a test reading lines could not tell
    /// "sampled" from "stopped counting". The schedule itself (1, 2, 4, 8, and
    /// seventeen lines for sixty-five thousand) is
    /// `logfmt::tests::a_sampler_turns_a_flood_into_a_handful_of_lines`.
    #[test]
    fn every_skipped_frame_is_counted_and_only_a_few_are_said_out_loud() {
        const FLOOD: u64 = 1000;

        let shared = Shared::default();
        let mut control = Control::default();
        control
            .accept(settings(true), false, &shared)
            .expect("accepted");

        for kind in 0..FLOOD {
            control
                .accept(
                    Item::Skipped {
                        kind: 0x1f * kind + 0x21,
                    },
                    true,
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
        control
            .accept(settings(true), false, &shared)
            .expect("accepted");

        let error = control
            .accept(Item::Data(Bytes::new()), true, &shared)
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
            let seen_by_a_session = shared.peer_settings(tokio::time::Instant::now());
            assert!(!seen_by_a_session.datagrams(), "nothing yet");
            assert!(!seen_by_a_session.has_been_read(), "nothing read yet");

            Control::default()
                .accept(settings(datagrams), false, &shared)
                .expect("accepted");

            assert_eq!(seen_by_a_session.datagrams(), datagrams);
            assert!(
                seen_by_a_session.has_been_read(),
                "the frame counts as read whatever it said, so a request that waits \
                 for it is not held by a peer that turns datagrams down"
            );
        }
    }

    #[test]
    fn a_second_settings_frame_is_refused() {
        let shared = Shared::default();
        let mut control = Control::default();
        control
            .accept(settings(true), false, &shared)
            .expect("accepted");

        let error = control
            .accept(settings(true), true, &shared)
            .expect_err("refused");
        assert_eq!(error.code(), Code::H3_FRAME_UNEXPECTED);
    }

    #[test]
    fn frames_that_belong_on_a_request_stream_are_refused() {
        let shared = Shared::default();
        for frame in [Frame::Headers(Bytes::new()), Frame::PushPromise] {
            let mut control = Control::default();
            control
                .accept(settings(true), false, &shared)
                .expect("accepted");

            let error = control
                .accept(Item::Frame(frame), true, &shared)
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
        control
            .accept(settings(true), false, &shared)
            .expect("accepted");

        let error = control
            .accept(Item::Frame(Frame::CancelPush(7)), true, &shared)
            .expect_err("refused");
        assert_eq!(error.code(), Code::H3_ID_ERROR);
    }

    #[test]
    fn a_max_push_id_may_grow_but_not_shrink() {
        let shared = Shared::default();
        let mut control = Control::default();
        control
            .accept(settings(true), false, &shared)
            .expect("accepted");

        for push_id in [9, 9, 12] {
            control
                .accept(Item::Frame(Frame::MaxPushId(push_id)), true, &shared)
                .expect("a push ID that does not shrink is allowed");
        }
        let error = control
            .accept(Item::Frame(Frame::MaxPushId(8)), true, &shared)
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

    /// Bytes a QPACK stream can be built from without ending at its first one.
    ///
    /// Unaimed bytes are no test of the state the property below is about: on
    /// the decoder stream only `0b01xxxxxx` is an instruction this server
    /// accepts, and on the encoder stream only `0b0010_0000`, so a generator
    /// that did not aim would compare two runs that had both refused byte one.
    ///
    /// `0x7f` is the Stream Cancellation whose 6-bit prefix is all ones, the
    /// one instruction in this server's vocabulary whose integer continues, and
    /// it is here twice so that continuations are common. `0xff` and `0x80`
    /// carry it on, `0x01` and `0x00` end it, and a long enough run of the
    /// first two reaches [`MAX_INTEGER_CONTINUATION`]. `0x40` and `0x20` are
    /// the two instructions that are complete in their first byte.
    const QPACK_ALPHABET: [u8; 8] = [0x7f, 0x7f, 0xff, 0x80, 0x01, 0x00, 0x40, 0x20];

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
        proptest::proptest!(|(shape: Vec<u8>, cuts: Vec<u8>, encoder: bool)| {
            let kind = if encoder {
                QpackStream::Encoder
            } else {
                QpackStream::Decoder
            };

            // Half the bytes are drawn from [`QPACK_ALPHABET`] and half are the
            // generator's own, so this covers both a stream that runs long
            // enough to have a state and one that ends at its first byte.
            let bytes: Vec<u8> = shape
                .iter()
                .map(|byte| {
                    if byte & 1 == 0 {
                        QPACK_ALPHABET[usize::from(byte >> 1) % QPACK_ALPHABET.len()]
                    } else {
                        *byte
                    }
                })
                .collect();

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

    /// The limit itself, which the property above cannot pin.
    ///
    /// That property compares one run of the bytes against a cut-up run of the
    /// same bytes, and the state step is per byte, so the two agree by
    /// construction however long the integer is: it pins determinism and
    /// nothing else. These two cases are what say where the limit falls.
    ///
    /// RFC 9204 §4.1.1 requires integers "up to and including 62 bits long",
    /// which a 6-bit prefix reaches in nine continuation bytes of seven bits
    /// each. A tenth is a value no conformant encoder produces.
    #[test]
    fn a_qpack_integer_past_the_continuation_limit_ends_the_connection() {
        // Stream Cancellation whose 6-bit prefix is all ones, so its stream id
        // continues, and then one continuation byte more than the limit allows,
        // none of them ending the integer.
        let mut stream = vec![0x7f];
        stream.extend_from_slice(&[0xff; MAX_INTEGER_CONTINUATION + 1]);

        let error = judge_qpack(QpackStream::Decoder, &[&stream])
            .expect_err("an integer past 62 bits is a connection error");

        assert_eq!(
            error.code(),
            Code::QPACK_DECODER_STREAM_ERROR,
            "the fault is on the peer's decoder stream, so it carries that stream's code"
        );
        assert!(
            format!("{error}").contains("an integer past 62 bits"),
            "the refusal must say what it refused: {error}"
        );
    }

    /// The other side of the same boundary: an integer that ends exactly at the
    /// limit is accepted, and leaves a stream ready for the next instruction.
    #[test]
    fn a_qpack_integer_that_ends_at_the_limit_is_accepted() {
        // The same instruction, carried on by nine continuation bytes that do
        // not end it, which is `MAX_INTEGER_CONTINUATION` exactly.
        let mut running = vec![0x7f];
        running.extend_from_slice(&[0xff; MAX_INTEGER_CONTINUATION]);

        let progress = judge_qpack(QpackStream::Decoder, &[&running])
            .expect("an integer of nine continuation bytes is inside the limit");
        assert_eq!(
            progress,
            QpackProgress::Integer {
                continuation: MAX_INTEGER_CONTINUATION
            },
            "the ninth continuation byte is counted and allowed"
        );

        // Carried on by eight continuation bytes and ended by a ninth.
        let mut ended = vec![0x7f];
        ended.extend_from_slice(&[0xff; MAX_INTEGER_CONTINUATION - 1]);
        let progress = judge_qpack(QpackStream::Decoder, &[&ended])
            .expect("an integer of eight continuation bytes is inside the limit");
        assert_eq!(
            progress,
            QpackProgress::Integer {
                continuation: MAX_INTEGER_CONTINUATION - 1
            },
            "eight continuation bytes are counted"
        );
        ended.push(0x00);

        let progress = judge_qpack(QpackStream::Decoder, &[&ended])
            .expect("an integer of nine continuation bytes is inside the limit");
        assert_eq!(
            progress,
            QpackProgress::Instruction,
            "a continuation byte with its top bit clear ends the integer"
        );
    }

    #[test]
    fn a_goaway_identifier_may_shrink_but_not_grow() {
        let shared = Shared::default();
        let mut control = Control::default();
        control
            .accept(settings(true), false, &shared)
            .expect("accepted");

        control
            .accept(Item::Frame(Frame::Goaway(12)), true, &shared)
            .expect("accepted");
        control
            .accept(Item::Frame(Frame::Goaway(8)), true, &shared)
            .expect("a smaller identifier is allowed");

        let error = control
            .accept(Item::Frame(Frame::Goaway(9)), true, &shared)
            .expect_err("refused");
        assert_eq!(error.code(), Code::H3_ID_ERROR);
    }

    /// RFC 9114 §6.2.1 and RFC 9204 §4.2 stand while the connection does; once
    /// it is over, the same ending is the peer saying goodbye a packet early.
    #[test]
    fn a_critical_stream_ending_is_a_fault_only_while_the_connection_lives() {
        let endings = [
            "the peer closed its control stream",
            "the peer reset its control stream: reset by peer: code 0",
            "the peer closed its QPACK encoder stream",
            "the peer reset its QPACK decoder stream: reset by peer: code 0",
        ];

        for ending in endings {
            let violation = critical_stream_closed(ending, None)
                .expect("a live connection must report every one of them");
            assert_eq!(violation.code(), Code::H3_CLOSED_CRITICAL_STREAM);
            assert!(violation.is_connection_error());
            assert!(
                violation.to_string().ends_with(ending),
                "the detail is carried into the message: {violation}"
            );
        }

        for closed in [
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(0),
                reason: Bytes::new(),
            }),
            quinn::ConnectionError::TimedOut,
            quinn::ConnectionError::LocallyClosed,
        ] {
            for ending in endings {
                assert!(
                    critical_stream_closed(ending, Some(&closed)).is_none(),
                    "a connection already closed by {closed} needs no fault report for \
                     {ending:?}"
                );
            }
        }
    }
}
