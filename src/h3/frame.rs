//! The HTTP/3 frame layer (RFC 9114 §7).
//!
//! Every HTTP/3 stream carries the same shape:
//!
//! ```text
//! Type (varint) | Length (varint) | Frame Payload (Length bytes)
//! ```
//!
//! Two properties decide the design of `FrameDecoder`, and they pull in
//! opposite directions:
//!
//! * **DATA must not be buffered.** A CONNECT tunnel's payload arrives as DATA
//!   frames, and this proxy exists to move them: a reader that accumulated a
//!   whole frame before handing it on would add a copy and a latency step to
//!   every packet. So DATA payload is handed out in exactly the chunks quinn
//!   delivered it in, as [`Bytes`] slices of those chunks.
//! * **Everything else must be buffered**, because it cannot be acted on
//!   piecewise, and its declared length is a varint that may claim 2^62 bytes.
//!   `MAX_BUFFERED_FRAME` is what stops a peer naming a length this server
//!   would then allocate for, and [`BufferBudget`] is what stops it naming an
//!   allowed length on every stream at once (D77).
//!
//! Unknown frame types are skipped by their declared length without being
//! buffered at all (RFC 9114 §9). That is what lets the protocol be extended,
//! and it is exercised on every connection: clients send reserved "grease"
//! types precisely to catch a peer that cannot skip them.
//!
//! The decoder is pure: it holds every byte of state, and [`FrameReader`]
//! feeds it from a QUIC stream. That split makes the frame layer testable a
//! byte at a time, and keeps every await in [`FrameReader`], whose rustdoc says
//! why it must be cancel-safe.
//!
//! # The one read-ahead
//!
//! DATA payload is never copied. Once a request stream carries a tunnel,
//! [`FrameReader`] holds up to [`READ_AHEAD_CHUNKS`] of quinn's own chunks
//! between reads; that constant says what this holds and why only a tunnel
//! gets it.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::varint::{TypeLength, len_u64, peek_varint, put_varint, take_from};

use super::error::{Code, StreamError, Violation};
use super::settings::{Settings, parse_settings};
use super::{HEADERS_BUFFER_BUDGET, MAX_FIELD_SECTION_SIZE};

mod reader;
mod seal;

#[cfg(test)]
pub(super) use reader::loopback;
pub use reader::{FrameReader, READ_AHEAD_CHUNKS};
pub use seal::{DATA_HEADER_ROOM, seal_data};

/// DATA (RFC 9114 §7.2.1).
pub const DATA: u64 = 0x00;
/// HEADERS (RFC 9114 §7.2.2).
pub const HEADERS: u64 = 0x01;
/// CANCEL_PUSH (RFC 9114 §7.2.3).
pub const CANCEL_PUSH: u64 = 0x03;
/// SETTINGS (RFC 9114 §7.2.4).
pub const SETTINGS: u64 = 0x04;
/// PUSH_PROMISE (RFC 9114 §7.2.5).
pub const PUSH_PROMISE: u64 = 0x05;
/// GOAWAY (RFC 9114 §7.2.6).
pub const GOAWAY: u64 = 0x07;
/// MAX_PUSH_ID (RFC 9114 §7.2.7).
pub const MAX_PUSH_ID: u64 = 0x0d;

/// The frame types this server parses, and so has to buffer whole.
///
/// The one place the three decisions that turn on it are written: what `begin`
/// puts in [`State::Buffering`], which types `misplaced` refuses once a stream
/// has become a tunnel (RFC 9114 §4.4's "any other known frame type"), and what
/// `parse` does with the payload once it is whole. DATA is not here because it
/// is never buffered, and a type this enum does not name is one §9 has this
/// server skip rather than judge.
///
/// A type rather than a list of codes, so that `parse` can be exhaustive over
/// it. A seventh buffered frame is then a compiler error at the one place that
/// would have to parse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BufferedKind {
    /// HEADERS (RFC 9114 §7.2.2).
    Headers,
    /// SETTINGS (RFC 9114 §7.2.4).
    Settings,
    /// GOAWAY (RFC 9114 §7.2.6).
    Goaway,
    /// CANCEL_PUSH (RFC 9114 §7.2.3).
    CancelPush,
    /// MAX_PUSH_ID (RFC 9114 §7.2.7).
    MaxPushId,
    /// PUSH_PROMISE (RFC 9114 §7.2.5).
    PushPromise,
}

impl BufferedKind {
    /// The buffered frame `kind` names, or `None` if that type is not one.
    fn from_type(kind: u64) -> Option<Self> {
        Some(match kind {
            HEADERS => Self::Headers,
            SETTINGS => Self::Settings,
            GOAWAY => Self::Goaway,
            CANCEL_PUSH => Self::CancelPush,
            MAX_PUSH_ID => Self::MaxPushId,
            PUSH_PROMISE => Self::PushPromise,
            _ => return None,
        })
    }

    /// The type code this frame carries on the wire.
    fn frame_type(self) -> u64 {
        match self {
            Self::Headers => HEADERS,
            Self::Settings => SETTINGS,
            Self::Goaway => GOAWAY,
            Self::CancelPush => CANCEL_PUSH,
            Self::MaxPushId => MAX_PUSH_ID,
            Self::PushPromise => PUSH_PROMISE,
        }
    }
}

/// Frame types RFC 9114 §11.2.1 reserves because HTTP/2 used them.
///
/// §7.2.8 makes their receipt a connection error rather than something to skip:
/// a peer sending one has mistaken this connection for an HTTP/2 one, and
/// nothing good follows from carrying on.
const RESERVED_HTTP2_TYPES: [u64; 4] = [0x02, 0x06, 0x08, 0x09];

/// Largest payload this reader will buffer for one non-DATA frame.
///
/// A policy bound on *encoded* bytes, and this server's own rule rather than
/// anything the RFC asks for. It applies to every buffered frame (HEADERS,
/// SETTINGS, GOAWAY, CANCEL_PUSH, MAX_PUSH_ID, PUSH_PROMISE), because each of
/// them declares its length as a varint that may claim 2^62 bytes. The declared
/// length is refused here before a single byte is allocated for it.
///
/// Its value is [`MAX_FIELD_SECTION_SIZE`], the same number as the advertised
/// field-section limit but not the same *rule*. RFC 9114 §4.2.2 sizes a field
/// section by the uncompressed name and value plus 32 bytes per field, while
/// this counts the octets that arrived. So a section inside the advertised
/// limit can be refused here, but only one whose Huffman-coded literals are
/// longer than the literals themselves. No encoder sends that, because Huffman
/// coding is optional per field.
const MAX_BUFFERED_FRAME: u64 = MAX_FIELD_SECTION_SIZE;

// D77's boundary, written as arithmetic rather than only as prose: the
// connection budget is a whole number of largest-allowed buffered frames, and
// at least sixteen of them, so sixteen concurrent full-size field sections fill
// it and the seventeenth is refused. The count is against this constant, the
// encoded-octet cap the budget is measured in, and deliberately not against
// `quic::INITIAL_BIDI_STREAMS`, which is also sixteen by coincidence and which
// D98 says must not be tied to it.
const _: () = assert!(
    len_u64(super::HEADERS_BUFFER_BUDGET).is_multiple_of(MAX_BUFFERED_FRAME)
        && len_u64(super::HEADERS_BUFFER_BUDGET) / MAX_BUFFERED_FRAME >= 16
);

/// Why a stream carrying a tunnel is closed when a frame that is not DATA
/// arrives on it.
///
/// Two places refuse that frame: [`misplaced`] here, which is the judgement a
/// request stream's reader acts on, and the arm in `super::stream` that repeats
/// the verdict for a decoder already in tunnel mode. Both name the same rule,
/// so both name it with the same words.
pub(super) const NON_DATA_FRAME_ON_A_TUNNEL: &str =
    "a frame other than DATA once the CONNECT method had completed";

/// How many reserved or unknown frames one request stream may make this server
/// skip before it is a stream error of type H3_EXCESSIVE_LOAD.
///
/// RFC 9114 §9 has this server ignore a frame type it does not know, and §7.2.8
/// makes the reserved "grease" types (0x1f * N + 0x21) padding a peer MAY send
/// "on any stream where frames are allowed to be sent". Both are legitimate:
/// §10.5 names "padding to increase resistance to traffic analysis" among the
/// uses that are "entirely legitimate". Their payload costs nothing here,
/// because it is discarded as it arrives and never buffered. The count is not
/// free: each skipped frame is a frame header to parse and an `Item::Skipped`
/// to hand back, so a peer that sends nothing but grease keeps a request
/// stream's reader busy without ever completing a request.
///
//= https://www.rfc-editor.org/rfc/rfc9114#section-10.5
//# Implementations SHOULD track the use of these features and set limits
//# on their use.  An endpoint MAY treat activity that is suspicious as a
//# connection error of type H3_EXCESSIVE_LOAD, but false positives will
//# result in disrupting valid connections and requests.
///
/// This is that limit for the frame skip. The count is of *frames*, not the
/// bytes they carry. A grease frame declaring a zero-length payload is two
/// bytes on the wire and would be charged nothing by a byte-counting bound, and
/// a flood of those is the cheapest form of this attack. It is per stream and
/// unshared, since §7.2.8 padding is legitimate on one stream and a
/// connection-wide total would let one stream's padding refuse another
/// stream's request. The value is generous on purpose: a real client greases
/// with a handful of small frames. The refusal is a *stream* error, so only the
/// one request is lost. §10.5's "false positives" caution is why this is not a
/// connection error and why the limit is far above what a client could reach.
const MAX_SKIPPED_FRAMES: u32 = 4096;

/// What one connection may hold in `FrameDecoder` payload buffers, as a
/// counter every request stream on it shares (D77).
///
/// `MAX_BUFFERED_FRAME` is per frame and so per stream; this is the sum over
/// the streams, which is the number a peer opening many of them actually
/// controls. [`super::HEADERS_BUFFER_BUDGET`] says why that distinction is
/// worth a counter and how the value was chosen.
///
/// Every request stream's decoder holds the same one, so a share taken on any
/// of them is a share the others cannot take. A share is a `Charge`, taken
/// when a decoder commits to buffering a frame and given back when it is
/// dropped, so the counter reads zero on a connection with nothing
/// half-received on it.
#[derive(Debug, Default)]
pub struct BufferBudget {
    /// Bytes announced by the frames currently being buffered.
    ///
    /// `Relaxed` throughout: nothing is published through this counter, and no
    /// other memory is ordered against it. Each charge is a single
    /// read-modify-write on the counter alone, and each release is a
    /// subtraction of what that charge added.
    held: AtomicUsize,
}

impl BufferBudget {
    /// A budget of its own, for a stream that shares one with nothing.
    ///
    /// The counter is shared because a peer chooses how many request streams to
    /// open. The control stream is one per connection and buffers one frame at
    /// a time, so the per-frame bound holds it on its own. Keeping it out of the
    /// shared counter also means a peer that has filled that counter with
    /// request streams cannot get its own well-formed SETTINGS or GOAWAY
    /// refused. A refusal there could not be the stream-class one a charge past
    /// the budget produces, since closing the control stream is itself a
    /// connection error (RFC 9114 §6.2.1, quoted in [`super::control`]).
    ///
    /// Not public: the one reader that needs it is in [`super::control`].
    pub(super) fn unshared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Takes `bytes` from the budget, or reports that the connection is past
    /// it.
    ///
    /// A *stream* error, on the stream whose frame is arriving: the bound is
    /// the connection's, every stream holding a share of it may be within
    /// [`MAX_BUFFERED_FRAME`], and the one that arrives last has done nothing
    /// the others did not. RFC 9114 §4.2.2 says what to do with a field
    /// section this server is unwilling to handle, and it concerns the one
    /// request: `stream::Resolver` answers this with the same 431 the
    /// per-frame bound gets, and the connection and its tunnels carry on.
    ///
    /// RFC 9114 §8.1 defines H3_EXCESSIVE_LOAD for a peer "exhibiting a
    /// behavior that might be generating excessive load". Holding a
    /// connection's whole buffering allowance in frames it never finishes is
    /// such a behavior. [`super::qpack`] reads the same code the same way.
    ///
    /// `try_update` rather than an add-then-check: a rejected charge must
    /// leave the counter untouched, or two streams failing at once would each
    /// see the other's rolled-back bytes and the bound would hold only on
    /// average.
    fn charge(self: &Arc<Self>, bytes: usize) -> Result<Charge, Violation> {
        self.held
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                let wanted = held.saturating_add(bytes);
                (wanted <= HEADERS_BUFFER_BUDGET).then_some(wanted)
            })
            .map_err(|held| {
                Violation::field_section_too_large(format!(
                    "buffering another {bytes} bytes would put this connection past the \
                     {HEADERS_BUFFER_BUDGET} it may hold in unfinished frames, of which \
                     {held} are already held"
                ))
            })?;
        Ok(Charge {
            budget: Arc::clone(self),
            bytes,
        })
    }

    /// Gives `bytes` back to the budget.
    ///
    /// Saturating, and asserted in debug builds. Nothing can return more than
    /// it took: only a [`Charge`] calls this, once, with what its own charge
    /// added. An underflow would wrap the counter to near `usize::MAX` and make
    /// the connection refuse every request from then on. A saturating
    /// subtraction limits that to a budget that is wrong, which is recoverable.
    fn release(&self, bytes: usize) {
        if bytes > 0 {
            let held = self
                .held
                .update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                    held.saturating_sub(bytes)
                });
            debug_assert!(
                held >= bytes,
                "released {bytes} bytes from a budget holding {held}"
            );
        }
    }

    /// Bytes currently charged to this connection, for the unit tests.
    #[cfg(test)]
    fn held(&self) -> usize {
        self.held.load(Ordering::Relaxed)
    }
}

/// One frame's share of a connection's [`BufferBudget`], given back when it is
/// dropped (D77).
///
/// It lives in [`State::Buffering`] beside the payload it pays for, so the
/// share ends when that state does: the frame completes, or the decoder is
/// dropped with it half-received. A stream can end at any point, mostly by
/// the peer's choice (a RESET_STREAM, a `STOP_SENDING` answered, the request
/// deadline of D76, the connection going away), and none of those reaches the
/// decoding loop. A share not returned on one of them would leak the
/// connection's allowance until a peer is refused a request it was entitled
/// to.
#[derive(Debug)]
struct Charge {
    budget: Arc<BufferBudget>,
    bytes: usize,
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

/// Why the frame reader stopped.
#[derive(Debug)]
pub enum Error {
    /// The QUIC stream failed under the reader: a peer reset, or the
    /// connection it belongs to.
    Stream(StreamError),
    /// The peer broke one of RFC 9114 §7's rules.
    Protocol(Violation),
}

impl From<StreamError> for Error {
    fn from(error: StreamError) -> Self {
        Self::Stream(error)
    }
}

impl From<Violation> for Error {
    fn from(violation: Violation) -> Self {
        Self::Protocol(violation)
    }
}

impl From<quinn::ReadError> for Error {
    fn from(error: quinn::ReadError) -> Self {
        Self::Stream(error.into())
    }
}

/// What [`FrameReader::next`] produces.
#[derive(Debug)]
pub enum Item {
    /// Payload of a DATA frame, in the chunk it arrived in.
    ///
    /// One frame may produce several of these, and a chunk never spans two
    /// frames. An empty DATA frame produces exactly one, carrying no bytes:
    /// a frame that arrived has to be reported even when it says nothing, or
    /// the rules about *which frame came first* cannot be applied to it.
    Data(Bytes),
    /// A complete frame of any other type this server acts on.
    Frame(Frame),
    /// A frame of an unknown type, skipped in full (RFC 9114 §9).
    ///
    /// Reported rather than swallowed so that a reader sees it arrive: the
    /// control stream's reader logs these on a sampled schedule. Every reader
    /// otherwise ignores it, which is what §9 requires.
    Skipped {
        /// The frame type that was skipped.
        kind: u64,
    },
}

/// A fully received non-DATA frame.
#[derive(Debug)]
pub enum Frame {
    /// An encoded field section (RFC 9114 §7.2.2), still QPACK-encoded.
    Headers(Bytes),
    /// The peer's settings, reduced to the one this server acts on.
    Settings(Settings),
    /// GOAWAY with the identifier the peer will not serve past.
    Goaway(u64),
    /// CANCEL_PUSH with its push ID, which a server that never pushes can only
    /// ever find unpromised (RFC 9114 §7.2.3).
    CancelPush(u64),
    /// MAX_PUSH_ID with its push ID, which may grow but never shrink
    /// (RFC 9114 §7.2.7).
    MaxPushId(u64),
    /// PUSH_PROMISE, which a server must never receive (RFC 9114 §7.2.5).
    PushPromise,
}

/// Which of this server's streams a decoder is reading.
///
/// RFC 9114 states most of its frame rules as "on any other stream" or "once
/// the CONNECT method has completed", so the same frame type is ordinary on one
/// stream and a connection error on the next. This is what a decoder knows about
/// which of the four it is serving, and the module-private `misplaced` is the
/// whole of the rule.
///
/// Public for the reason [`FrameDecoder`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// A stream on which every frame type this server parses may appear.
    ///
    /// The permissive kind, and the one a *client* wants for a response stream:
    /// the suite's client (`tests/common/h3client.rs`) is built on this module.
    /// Nothing is refused by type alone here; which frames are allowed *when* is
    /// the caller's to track.
    Control,
    /// The peer's control stream as this server reads it (RFC 9114 §6.2.1).
    ///
    /// Strict where [`Self::Control`] is permissive: the rules that turn on the
    /// frame type alone are applied from the frame header, before the buffered
    /// length is looked at, so a frame the connection must close on cannot get
    /// the stream error an oversized frame gets. Which of the rules applies
    /// depends on whether the decoder has already handed out a SETTINGS frame.
    ServerControl,
    /// A request stream whose request has not completed.
    Request,
    /// A request stream whose CONNECT has completed (RFC 9114 §4.4).
    Tunnel,
}

/// Where the decoder is in the frame sequence.
#[derive(Debug)]
enum State {
    /// Between frames, assembling a type and length.
    Header,
    /// Inside a DATA frame, with `remaining` payload bytes to hand out.
    Data {
        /// Payload bytes of this frame not yet delivered.
        remaining: u64,
    },
    /// Buffering the payload of a frame that has to be seen whole.
    Buffering {
        /// Which frame is being buffered.
        kind: BufferedKind,
        /// Payload bytes still to arrive.
        remaining: usize,
        /// What has arrived of the payload.
        payload: BytesMut,
        /// The budget share for the whole announced length, held for its
        /// `Drop`.
        _charge: Charge,
    },
    /// Discarding the payload of a frame type this server does not know.
    Skipping {
        /// Which frame is being skipped, kept so its end can be announced.
        kind: u64,
        /// Payload bytes still to discard.
        remaining: u64,
    },
}

/// An incremental frame decoder, fed chunks as they arrive.
///
/// Written the same way as [`crate::capsule::CapsuleDecoder`], and for the same
/// reason: frames do not align with stream chunks in either direction, so the
/// decoder has to be a state machine that can be fed a byte at a time. The
/// tests below feed it that way.
///
/// Public, though nothing outside this module constructs one at run time:
/// [`FrameReader`] is what the server uses, and `crate::h3api` deliberately
/// re-exports neither. `tests/it_fuzz.rs` needs it, to state the properties
/// about chunk boundaries and about which frame type belongs on which stream
/// against the state machine itself: a byte at a time, at chosen split points,
/// on a [`StreamKind`] the test picks. Over a loopback QUIC connection, quinn
/// would choose the packetisation.
#[derive(Debug)]
pub struct FrameDecoder {
    /// The chunk last pushed, with the consumed prefix removed.
    chunk: Bytes,
    /// Frame header bytes carried over from earlier chunks.
    ///
    /// Allocates nothing, so constructing a decoder allocates nothing: one is
    /// built per stream, and a peer opening streams should not cost a heap
    /// allocation each time.
    header: TypeLength,
    /// The connection's buffering budget, shared with every other decoder on
    /// it (D77).
    ///
    /// Held as an `Arc` rather than a borrow because a decoder outlives no
    /// scope in particular: it belongs to a stream, and the streams of a
    /// connection end in any order. Cloning one is a refcount bump, so
    /// [`Self::new`] still allocates nothing.
    budget: Arc<BufferBudget>,
    /// Which stream's rules this decoder applies to a frame type.
    ///
    /// Not fixed for the life of the decoder: a request stream becomes a tunnel
    /// the moment its CONNECT is answered, and RFC 9114 §4.4 narrows what may
    /// follow to DATA alone.
    stream: StreamKind,
    /// Whether this decoder has handed out a SETTINGS frame that parsed.
    ///
    /// Only [`StreamKind::ServerControl`] reads it. It is set when the frame is
    /// handed out, so the next frame header is judged against it. A SETTINGS
    /// whose payload was refused never sets it. A fresh decoder has not seen
    /// SETTINGS, which is the first-frame rule's starting point (RFC 9114
    /// §6.2.1).
    settings_seen: bool,
    /// Reserved or unknown frames skipped so far while this was a request
    /// stream (RFC 9114 §10.5).
    ///
    /// Counted only in [`StreamKind::Request`], and [`MAX_SKIPPED_FRAMES`] says
    /// why the unit is frames rather than bytes. A tunnel's skips are DATA's
    /// equals under §4.4 and have their own reader. The control stream's are
    /// deliberately not counted: greasing it is what §7.2.8 invites, and the
    /// cost there is bounded by the [`logfmt::Sampler`] in
    /// [`super::control`] on the *log line* each one produces. It only
    /// grows. A request stream that becomes a tunnel stops adding to it, and
    /// there is nothing to reset.
    ///
    /// [`logfmt::Sampler`]: crate::logfmt::Sampler
    skipped: u32,
    state: State,
}

impl FrameDecoder {
    /// A decoder positioned at the start of a `stream`'s frame sequence, drawing
    /// on `budget` for whatever it has to buffer.
    pub fn new(stream: StreamKind, budget: Arc<BufferBudget>) -> Self {
        Self {
            chunk: Bytes::new(),
            header: TypeLength::default(),
            budget,
            stream,
            settings_seen: false,
            skipped: 0,
            state: State::Header,
        }
    }

    /// Hands the decoder the next chunk of stream.
    ///
    /// Only legal once [`Self::next_item`] has asked for more, which is the only
    /// state in which the previous chunk is spent.
    pub fn push(&mut self, chunk: Bytes) {
        debug_assert!(self.chunk.is_empty(), "the previous chunk is not consumed");
        self.chunk = chunk;
    }

    /// Drops the unconsumed rest of the chunk last pushed, undecoded.
    ///
    /// Only the chunk changes. The frame state and any header bytes carried
    /// over stay as they were, so the decoder is no longer in step with the
    /// stream's bytes and is meant for a stream whose reading has stopped.
    /// The chunk is empty afterwards, which is the condition the assertion in
    /// [`Self::push`] checks, so a later push does not trip it.
    pub(super) fn discard_chunk(&mut self) {
        self.chunk = Bytes::new();
    }

    /// Narrows the frame rules to the ones RFC 9114 §4.4 gives a tunnel.
    ///
    /// Called once the 2xx answering a CONNECT has gone out, which is what
    /// "completed" means in that section. From here a HEADERS frame is a
    /// connection error like every other known type but DATA, refused from its
    /// header.
    pub fn connect_completed(&mut self) {
        self.stream = StreamKind::Tunnel;
    }

    /// Whether the stream could end here without truncating a frame.
    ///
    /// RFC 9114 §7.1: "When a stream terminates cleanly, if the last frame on
    /// the stream was truncated, this MUST be treated as a connection error of
    /// type H3_FRAME_ERROR."
    pub fn at_frame_boundary(&self) -> bool {
        matches!(self.state, State::Header) && self.header.held() == 0
    }

    /// The next item, or `None` when more bytes are needed.
    pub fn next_item(&mut self) -> Result<Option<Item>, Error> {
        loop {
            match self.state {
                State::Header => {
                    let Some((kind, length)) = self.header.take(&mut self.chunk) else {
                        return Ok(None);
                    };
                    self.state =
                        begin(self.stream, self.settings_seen, kind, length, &self.budget)?;
                }

                // A separate arm, so an empty DATA frame cannot be mistaken for
                // "no bytes have arrived yet", the same `take == 0` below. It
                // still produces an item (`Item::Data` says why).
                State::Data { remaining: 0 } => {
                    self.state = State::Header;
                    return Ok(Some(Item::Data(Bytes::new())));
                }

                State::Data { remaining } => {
                    let (take, left) = take_from(remaining, self.chunk.len());
                    if take == 0 {
                        return Ok(None);
                    }
                    // A slice of quinn's own buffer: a refcount bump, not a copy.
                    let data = self.chunk.split_to(take);
                    // Back to `Header` as soon as the frame is spent, so the end
                    // of a frame and the end of a stream agree about where a
                    // boundary is.
                    self.state = match left {
                        0 => State::Header,
                        left => State::Data { remaining: left },
                    };
                    return Ok(Some(Item::Data(data)));
                }

                State::Buffering {
                    kind,
                    ref mut remaining,
                    ref mut payload,
                    ..
                } => {
                    let take = (*remaining).min(self.chunk.len());
                    // Allocated once, at the announced length, when the first
                    // payload byte arrives: the allocation then equals what
                    // the budget was charged, where growth by doubling could
                    // reach nearly twice that.
                    if payload.is_empty() && take > 0 {
                        payload.reserve(*remaining);
                    }
                    payload.extend_from_slice(&self.chunk[..take]);
                    self.chunk.advance(take);
                    *remaining -= take;
                    if *remaining > 0 {
                        return Ok(None);
                    }

                    // The whole allocation goes with the frozen payload, and
                    // leaving the state drops the charge, before the parse,
                    // which may fail: the frame is held no longer either way,
                    // and this decoder holds nothing between frames.
                    let payload = std::mem::take(payload).freeze();
                    self.state = State::Header;
                    let frame = parse(kind, payload)?;
                    self.settings_seen |= matches!(frame, Frame::Settings(_));
                    return Ok(Some(Item::Frame(frame)));
                }

                State::Skipping { kind, remaining } => {
                    let (take, left) = take_from(remaining, self.chunk.len());
                    self.chunk.advance(take);

                    match left {
                        0 => {
                            self.state = State::Header;
                            self.count_skip()?;
                            return Ok(Some(Item::Skipped { kind }));
                        }
                        left => {
                            self.state = State::Skipping {
                                kind,
                                remaining: left,
                            };
                            return Ok(None);
                        }
                    }
                }
            }
        }
    }

    /// Counts one skipped frame against [`MAX_SKIPPED_FRAMES`], reporting a
    /// stream error once a request stream is past it (RFC 9114 §10.5).
    ///
    /// A plain stream error, so it gets a bare reset and not the 431
    /// ([`Violation::field_section_too_large`] says why).
    fn count_skip(&mut self) -> Result<(), Violation> {
        if self.stream == StreamKind::Request {
            self.skipped = self.skipped.saturating_add(1);
            if self.skipped > MAX_SKIPPED_FRAMES {
                return Err(Violation::stream(
                    Code::H3_EXCESSIVE_LOAD,
                    format!(
                        "more than {MAX_SKIPPED_FRAMES} reserved or unknown frames were skipped \
                         on this request stream before a request arrived"
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// Decides what to do with a frame that has just been announced on `stream`.
///
/// The order of the verdicts below matters. A frame type that may not appear on
/// this stream at all is a connection error whatever length it declares. So
/// the length check, which produces a *stream* error answered on a request
/// stream with a 431, must not reach it first: a 431 is a wrong reply to a
/// SETTINGS frame, and the connection would carry on after a MUST-close. The
/// control stream follows the same ordering with other codes; `misplaced`
/// states which of its rules are judged from the header.
///
/// A frame to be buffered is charged to `budget` here, on its announcement
/// rather than on arrival: the announcement is the moment the decoder commits
/// to holding that many bytes, and holding them is what the peer gets out of
/// never sending them (D77). A refused frame is charged nothing.
fn begin(
    stream: StreamKind,
    settings_seen: bool,
    kind: u64,
    length: u64,
    budget: &Arc<BufferBudget>,
) -> Result<State, Error> {
    if RESERVED_HTTP2_TYPES.contains(&kind) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
        //# These frame types MUST NOT be sent, and their receipt MUST be
        //# treated as a connection error of type H3_FRAME_UNEXPECTED.
        return Err(Violation::connection(
            Code::H3_FRAME_UNEXPECTED,
            format!("frame type {kind:#x} is reserved for HTTP/2"),
        )
        .into());
    }

    if let Some(violation) = misplaced(stream, settings_seen, kind) {
        return Err(violation.into());
    }

    if kind == DATA {
        return Ok(State::Data { remaining: length });
    }

    let Some(buffered) = BufferedKind::from_type(kind) else {
        // RFC 9114 §9's rule that unknown values are ignored, quoted in full in
        // `super`'s module comment. Ignoring is what every reader does with the
        // `Item::Skipped` this ends up producing; the payload is discarded here
        // and never buffered.
        return Ok(State::Skipping {
            kind,
            remaining: length,
        });
    };

    let Some(remaining) = usize::try_from(length)
        .ok()
        .filter(|_| length <= MAX_BUFFERED_FRAME)
    else {
        return Err(Violation::field_section_too_large(format!(
            "a {length}-byte frame is past what this server buffers"
        ))
        .into());
    };

    Ok(State::Buffering {
        kind: buffered,
        remaining,
        payload: BytesMut::new(),
        _charge: budget.charge(remaining)?,
    })
}

/// A frame that is not allowed where it appeared (RFC 9114 §7.2).
fn unexpected(detail: &'static str) -> Violation {
    Violation::connection(Code::H3_FRAME_UNEXPECTED, detail)
}

/// Why frame type `kind` may not appear on `stream` at all, or `None` if it may.
///
/// Every case is a MUST in RFC 9114 that turns on *where* the frame arrived
/// rather than on anything inside it, which is what makes the verdict reachable
/// from the frame header alone. Most are H3_FRAME_UNEXPECTED, but the control
/// stream's first-frame rule is H3_MISSING_SETTINGS, so the violation is
/// returned whole rather than as a reason phrase for the caller to wrap.
///
/// `settings_seen` is whether the decoder has already handed out a SETTINGS
/// frame. Only [`StreamKind::ServerControl`] reads it; the comments in its arm
/// state the ordering, which `it_frameseq` models.
fn misplaced(stream: StreamKind, settings_seen: bool, kind: u64) -> Option<Violation> {
    match stream {
        // Nothing: the permissive kind, built for a client's response stream.
        // The server reads its peer's control stream as
        // [`StreamKind::ServerControl`] instead.
        StreamKind::Control => None,

        StreamKind::ServerControl => {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
            //# If the first frame of the control stream is any other frame
            //# type, this MUST be treated as a connection error of type
            //# H3_MISSING_SETTINGS.
            //
            // The first frame's type is in its header, so this is decided
            // before the length cap and before any payload is parsed, for
            // every type. Otherwise an oversized HEADERS or PUSH_PROMISE sent
            // first would get the cap's stream error (a 431 where the
            // connection must close), a malformed first GOAWAY or MAX_PUSH_ID
            // would get its payload error where §6.2.1 has already decided the
            // frame, and an unknown first frame declaring 2^62-1 bytes would
            // be skipped for as long as the peer kept sending. The first
            // SETTINGS is the frame this stream is waiting for, so it is
            // exempt here and its payload is parsed.
            if !settings_seen && kind != SETTINGS {
                return Some(Violation::connection(
                    Code::H3_MISSING_SETTINGS,
                    format!("frame type {kind:#x} before SETTINGS on the control stream"),
                ));
            }

            // After SETTINGS, DATA, HEADERS, PUSH_PROMISE and a second
            // SETTINGS are refused from the header at every length: the type
            // is the offence, and charging the budget for them would let a
            // peer hold it with frames it may not send.
            match kind {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.1
                //# If a DATA frame is received on a control stream, the
                //# recipient MUST respond with a connection error of type
                //# H3_FRAME_UNEXPECTED.
                DATA => Some(unexpected("a DATA frame on the control stream")),

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.2
                //# HEADERS frames can only be sent on request streams or push
                //# streams. If a HEADERS frame is received on a control stream,
                //# the recipient MUST respond with a connection error of type
                //# H3_FRAME_UNEXPECTED.
                HEADERS => Some(unexpected("a HEADERS frame on the control stream")),

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
                //# A client MUST NOT send a PUSH_PROMISE frame. A server MUST
                //# treat the receipt of a PUSH_PROMISE frame as a connection
                //# error of type H3_FRAME_UNEXPECTED.
                PUSH_PROMISE => Some(unexpected("a PUSH_PROMISE frame")),

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
                //# If an endpoint receives a second SETTINGS frame on the
                //# control stream, the endpoint MUST respond with a connection
                //# error of type H3_FRAME_UNEXPECTED.
                SETTINGS if settings_seen => Some(unexpected("a second SETTINGS frame")),

                // GOAWAY, CANCEL_PUSH and MAX_PUSH_ID belong on this stream once
                // SETTINGS has opened it, and the cap is their only bound. The
                // first SETTINGS is allowed here, and an unknown type is
                // skipped under §9.
                _ => None,
            }
        }

        StreamKind::Request => match kind {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
            //# SETTINGS frames MUST NOT be sent on any stream other than the
            //# control stream. If an endpoint receives a SETTINGS frame on a
            //# different stream, the endpoint MUST respond with a connection
            //# error of type H3_FRAME_UNEXPECTED.
            SETTINGS => Some(unexpected("a SETTINGS frame on a request stream")),

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
            //# A CANCEL_PUSH frame is sent on the control stream. Receiving a
            //# CANCEL_PUSH frame on a stream other than the control stream MUST
            //# be treated as a connection error of type H3_FRAME_UNEXPECTED.
            CANCEL_PUSH => Some(unexpected("a CANCEL_PUSH frame on a request stream")),

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
            //# The MAX_PUSH_ID frame is always sent on the control stream.
            //# Receipt of a MAX_PUSH_ID frame on any other stream MUST be
            //# treated as a connection error of type H3_FRAME_UNEXPECTED.
            MAX_PUSH_ID => Some(unexpected("a MAX_PUSH_ID frame on a request stream")),

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
            //# A client MUST NOT send a PUSH_PROMISE frame. A server MUST treat
            //# the receipt of a PUSH_PROMISE frame as a connection error of type
            //# H3_FRAME_UNEXPECTED.
            //
            // The one rule here that is not about the stream: a server may not
            // receive this frame anywhere, so §7.2.5's separate sentence about
            // the control stream is addressed to a client and this is the
            // sentence that governs both places for us.
            PUSH_PROMISE => Some(unexpected(
                "a PUSH_PROMISE frame, which only a server may send",
            )),

            // GOAWAY is the one of the five whose "not on this stream" rule
            // RFC 9114 §7.2.6 states for a client only: "A client MUST treat a
            // GOAWAY frame on a stream other than the control stream as a
            // connection error of type H3_FRAME_UNEXPECTED". This endpoint is
            // not a client. The rule that applies here is §4.1's about the
            // sequence a request stream may carry, since a GOAWAY is no part of
            // any request message, and it names the same code:
            //
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# Receipt of an invalid sequence of frames MUST be treated as a
            //# connection error of type H3_FRAME_UNEXPECTED.
            GOAWAY => Some(unexpected("a GOAWAY frame on a request stream")),

            // DATA and HEADERS are what a request stream is made of; §4.1 judges
            // their *order*, which needs the frames themselves and is
            // `super::stream`'s. An unknown type is skipped under §9.
            _ => None,
        },

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
        //# Once the CONNECT method has completed, only DATA frames are
        //# permitted to be sent on the stream. Extension frames MAY be used if
        //# specifically permitted by the definition of the extension. Receipt
        //# of any other known frame type MUST be treated as a connection error
        //# of type H3_FRAME_UNEXPECTED.
        //
        // "Any other known frame type": DATA carries the tunnel, and a type this
        // server does not know is skipped under §9 rather than judged. That
        // covers the sentence's allowance for an extension frame, since this
        // server implements no such extension. Every other known type is
        // refused, a trailer section's HEADERS included: there is no
        // representation on a tunnel for a trailer to describe, and RFC 9220 §3
        // extends CONNECT to other protocols by pointing at this same section.
        StreamKind::Tunnel => match kind {
            DATA => None,
            _ if BufferedKind::from_type(kind).is_some() => {
                Some(unexpected(NON_DATA_FRAME_ON_A_TUNNEL))
            }
            _ => None,
        },
    }
}

/// Parses a buffered frame payload.
///
/// Exhaustive over [`BufferedKind`] and so total: only `begin` can put a frame
/// in [`State::Buffering`], and it can only put one of these there.
fn parse(kind: BufferedKind, payload: Bytes) -> Result<Frame, Violation> {
    match kind {
        BufferedKind::Headers => Ok(Frame::Headers(payload)),
        BufferedKind::Settings => parse_settings(&payload).map(Frame::Settings),
        BufferedKind::Goaway => single_varint(kind.frame_type(), &payload).map(Frame::Goaway),
        BufferedKind::CancelPush => {
            single_varint(kind.frame_type(), &payload).map(Frame::CancelPush)
        }
        BufferedKind::MaxPushId => single_varint(kind.frame_type(), &payload).map(Frame::MaxPushId),
        BufferedKind::PushPromise => Ok(Frame::PushPromise),
    }
}

/// Reads a payload that is exactly one varint (GOAWAY, CANCEL_PUSH,
/// MAX_PUSH_ID).
///
/// RFC 9114 §7.1: a payload with bytes left over, or one that ends early, is a
/// connection error of type H3_FRAME_ERROR.
fn single_varint(kind: u64, payload: &[u8]) -> Result<u64, Violation> {
    match peek_varint(payload) {
        Some((value, used)) if used == payload.len() => Ok(value),
        _ => Err(Violation::connection(
            Code::H3_FRAME_ERROR,
            format!("frame type {kind:#x} does not carry exactly one varint"),
        )),
    }
}

/// Writes a frame header: type and payload length.
pub fn put_header(out: &mut impl BufMut, kind: u64, length: u64) {
    put_varint(out, kind);
    put_varint(out, length);
}

#[cfg(test)]
mod tests {
    // A test writes the frame lengths and budget arithmetic it is asserting on,
    // and every one of those numbers is a literal or a constant of this module:
    // the package-wide `deny` is for the code that reads a peer's lengths.
    #![allow(clippy::as_conversions)]

    use super::*;
    use std::assert_matches;

    #[test]
    fn goaway_carries_exactly_one_varint() {
        assert_eq!(single_varint(GOAWAY, &[0x04]).expect("parses"), 4);
        // Trailing bytes and a truncated varint are both H3_FRAME_ERROR.
        for payload in [&[0x04, 0x00][..], &[][..], &[0xc0][..]] {
            let error = single_varint(GOAWAY, payload).expect_err("refused");
            assert_eq!(error.code(), Code::H3_FRAME_ERROR);
            assert!(error.is_connection_error());
        }
    }

    /// Encodes a frame with `kind` and `payload` for the decoder tests.
    fn frame(kind: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = BytesMut::new();
        put_header(&mut out, kind, payload.len() as u64);
        out.extend_from_slice(payload);
        out.to_vec()
    }

    /// A budget of its own, for the tests that are not about the budget.
    fn budget() -> Arc<BufferBudget> {
        Arc::new(BufferBudget::default())
    }

    /// A request stream's decoder with a budget of its own, for the tests that
    /// are not about the budget.
    fn fresh_decoder() -> FrameDecoder {
        FrameDecoder::new(StreamKind::Request, budget())
    }

    /// Feeds `wire` to a decoder one byte at a time and collects what comes out.
    ///
    /// A byte at a time on purpose: it is the worst case a real stream can
    /// produce, and the only way to prove a frame header straddling chunks is
    /// reassembled rather than mis-parsed.
    fn decode_bytewise(wire: &[u8]) -> Result<Vec<Item>, Error> {
        let mut decoder = fresh_decoder();
        let mut items = Vec::new();

        for byte in wire {
            decoder.push(Bytes::copy_from_slice(&[*byte]));
            while let Some(item) = decoder.next_item()? {
                items.push(item);
            }
        }
        Ok(items)
    }

    #[test]
    fn a_headers_frame_split_across_chunks_is_reassembled() {
        // A length that needs a two-byte varint, so the header itself straddles.
        let block = vec![0x5au8; 200];
        let items = decode_bytewise(&frame(HEADERS, &block)).expect("decodes");

        assert_eq!(items.len(), 1);
        let Item::Frame(Frame::Headers(decoded)) = &items[0] else {
            panic!("expected HEADERS, got {items:?}")
        };
        assert_eq!(&decoded[..], &block[..]);
    }

    /// DATA is handed out in the chunks it arrived in, never accumulated.
    #[test]
    fn data_payload_is_handed_out_as_it_arrives() {
        let items = decode_bytewise(&frame(DATA, b"hello")).expect("decodes");

        let payload: Vec<u8> = items
            .iter()
            .flat_map(|item| match item {
                Item::Data(chunk) => chunk.clone(),
                other => panic!("expected DATA, got {other:?}"),
            })
            .collect();
        assert_eq!(payload, b"hello");
        assert_eq!(items.len(), 5, "one item per arriving byte");
    }

    /// One chunk holding several frames must produce all of them, and a chunk
    /// never spans two frames.
    #[test]
    fn several_frames_in_one_chunk_all_come_out() {
        let mut wire = frame(DATA, b"abc");
        wire.extend_from_slice(&frame(HEADERS, b"block"));
        wire.extend_from_slice(&frame(DATA, b"de"));

        let mut decoder = fresh_decoder();
        decoder.push(Bytes::from(wire));

        let mut items = Vec::new();
        while let Some(item) = decoder.next_item().expect("decodes") {
            items.push(item);
        }

        assert_matches!(&items[0], Item::Data(chunk) if &chunk[..] == b"abc");
        assert_matches!(&items[1], Item::Frame(Frame::Headers(block)) if &block[..] == b"block");
        assert_matches!(&items[2], Item::Data(chunk) if &chunk[..] == b"de");
        assert_eq!(items.len(), 3);
    }

    /// RFC 9114 §9: unknown types, grease included, are skipped by their
    /// declared length and never buffered, and their arrival is announced.
    #[test]
    fn unknown_frame_types_are_skipped() {
        for kind in [0x21u64, 0x1f * 7 + 0x21, 0x4242] {
            let mut wire = frame(kind, b"whatever this is");
            wire.extend_from_slice(&frame(DATA, b"body"));

            let items = decode_bytewise(&wire).expect("decodes");
            let (skipped, body) = items.split_first().expect("at least the skipped frame");

            assert_matches!(skipped, Item::Skipped { kind: skipped } if *skipped == kind,
                "grease type {kind:#x} must be announced once, got {items:?}");
            let payload: Vec<u8> = body
                .iter()
                .flat_map(|item| match item {
                    Item::Data(chunk) => chunk.clone(),
                    other => panic!("expected only DATA after it, got {other:?}"),
                })
                .collect();
            assert_eq!(payload, b"body", "grease type {kind:#x}");
        }
    }

    /// RFC 9114 §10.5: a request stream may make this server skip only so many
    /// reserved or unknown frames before it is a stream error.
    ///
    /// The flood is zero-length grease frames, the input a byte-counting bound
    /// could never stop, since two wire bytes declaring no payload are charged
    /// nothing. So this proves the count is of frames. The first
    /// `MAX_SKIPPED_FRAMES` are skipped and announced; the one past the limit is
    /// the refusal.
    #[test]
    fn a_request_stream_flood_of_skipped_frames_is_refused() {
        let mut wire = BytesMut::new();
        for _ in 0..=MAX_SKIPPED_FRAMES {
            // 0x21 = 0x1f * 0 + 0x21, a reserved grease type, declaring no
            // payload: two bytes, and worth nothing to any byte budget.
            put_header(&mut wire, 0x21, 0);
        }

        let mut decoder = fresh_decoder();
        decoder.push(wire.freeze());

        let mut skipped = 0u32;
        let error = loop {
            match decoder.next_item() {
                Ok(Some(Item::Skipped { kind: 0x21 })) => skipped += 1,
                Ok(Some(other)) => panic!("expected only skips, got {other:?}"),
                Ok(None) => panic!("the flood was exhausted without a refusal"),
                Err(Error::Protocol(violation)) => break violation,
                Err(other) => panic!("expected a protocol violation, got {other:?}"),
            }
        };

        assert_eq!(
            skipped, MAX_SKIPPED_FRAMES,
            "every frame up to the limit is skipped and announced"
        );
        assert_eq!(error.code(), Code::H3_EXCESSIVE_LOAD);
        assert!(
            !error.is_connection_error(),
            "a grease flood costs one request, not the connection"
        );
        assert!(
            !error.is_field_section_too_large(),
            "a grease flood is answered by a bare reset, not the 431 a field \
             section too large gets"
        );
    }

    /// The generous limit does not touch a real client: a handful of grease
    /// frames before the HEADERS is exactly what a greasing client sends, and
    /// the request still arrives.
    #[test]
    fn a_few_skipped_frames_before_headers_are_harmless() {
        let mut wire = BytesMut::new();
        for _ in 0..8 {
            wire.extend_from_slice(&frame(0x1f * 3 + 0x21, b"pad"));
        }
        wire.extend_from_slice(&frame(HEADERS, b"the request"));

        let items = decode_bytewise(&wire).expect("a few greases then a request decodes");
        let headers = items
            .iter()
            .filter(|item| matches!(item, Item::Frame(Frame::Headers(_))))
            .count();
        assert_eq!(headers, 1, "the HEADERS frame still arrives, got {items:?}");
    }

    /// The count is a request stream's alone: a tunnel's grease is DATA's equal
    /// under RFC 9114 §4.4, and the control stream's is bounded elsewhere, so
    /// neither is counted here however much of it there is.
    #[test]
    fn skipped_frames_are_only_counted_on_a_request_stream() {
        for stream in [
            StreamKind::Tunnel,
            StreamKind::Control,
            StreamKind::ServerControl,
        ] {
            let mut wire = BytesMut::new();
            // The peer's control stream opens with SETTINGS, or its first
            // grease frame is refused (RFC 9114 §6.2.1).
            if stream == StreamKind::ServerControl {
                wire.extend_from_slice(&frame(SETTINGS, &[]));
            }
            for _ in 0..=MAX_SKIPPED_FRAMES {
                put_header(&mut wire, 0x21, 0);
            }

            let mut decoder = FrameDecoder::new(stream, Arc::new(BufferBudget::default()));
            decoder.push(wire.freeze());

            let mut skipped = 0u32;
            loop {
                match decoder.next_item() {
                    Ok(Some(Item::Skipped { .. })) => skipped += 1,
                    Ok(Some(Item::Frame(Frame::Settings(_))))
                        if stream == StreamKind::ServerControl => {}
                    Ok(Some(other)) => panic!("{stream:?}: unexpected {other:?}"),
                    Ok(None) => break,
                    Err(error) => panic!("{stream:?}: grease is not counted here, got {error:?}"),
                }
            }
            assert_eq!(
                skipped,
                MAX_SKIPPED_FRAMES + 1,
                "{stream:?}: every grease frame is skipped, none refused"
            );
        }
    }

    /// The skipped frame is announced once it is *spent*, not when it starts:
    /// a reader must not act on a frame whose payload is still arriving.
    #[test]
    fn a_skipped_frame_is_announced_only_once_it_is_complete() {
        // Type, length and all but the last payload byte: still nothing.
        let wire = frame(0x21, b"payload");
        let mut decoder = fresh_decoder();
        decoder.push(Bytes::copy_from_slice(&wire[..wire.len() - 1]));
        assert!(decoder.next_item().expect("decodes").is_none());
        assert!(!decoder.at_frame_boundary());

        decoder.push(Bytes::copy_from_slice(&wire[wire.len() - 1..]));
        assert_matches!(
            decoder.next_item().expect("decodes"),
            Some(Item::Skipped { kind: 0x21 })
        );
        assert!(decoder.at_frame_boundary());
    }

    /// An empty frame of either kind must not stall the decoder waiting for a
    /// payload that will never come, and must still be reported, so that a
    /// caller can tell "a DATA frame arrived" from "nothing arrived".
    #[test]
    fn zero_length_frames_do_not_stall_the_decoder() {
        let mut wire = frame(DATA, b"");
        wire.extend_from_slice(&frame(0x21, b""));
        wire.extend_from_slice(&frame(HEADERS, b""));

        let items = decode_bytewise(&wire).expect("decodes");
        assert_matches!(
                &items[..],
                [
                    Item::Data(empty),
                    Item::Skipped { kind: 0x21 },
                    Item::Frame(Frame::Headers(block))
                ] if empty.is_empty() && block.is_empty()
            ,
            "got {items:?}");
    }

    /// RFC 9114 §7.2.8: the types HTTP/2 used and HTTP/3 does not are a
    /// connection error, not something to skip.
    #[test]
    fn reserved_http2_frame_types_end_the_connection() {
        for kind in RESERVED_HTTP2_TYPES {
            let Err(Error::Protocol(violation)) =
                begin(StreamKind::Control, false, kind, 0, &budget())
            else {
                panic!("frame type {kind:#x} must be refused")
            };
            assert_eq!(violation.code(), Code::H3_FRAME_UNEXPECTED);
            assert!(violation.is_connection_error());
        }
    }

    #[test]
    fn a_frame_past_the_buffer_limit_is_refused_before_it_is_allocated() {
        let Err(Error::Protocol(violation)) = begin(
            StreamKind::Request,
            false,
            HEADERS,
            MAX_BUFFERED_FRAME + 1,
            &budget(),
        ) else {
            panic!("an oversized frame must be refused")
        };
        assert_eq!(violation.code(), Code::H3_EXCESSIVE_LOAD);
        assert!(
            !violation.is_connection_error(),
            "one oversized frame is a stream problem, not a connection one"
        );

        assert!(
            begin(
                StreamKind::Request,
                false,
                HEADERS,
                MAX_BUFFERED_FRAME,
                &budget()
            )
            .is_ok()
        );
        // DATA is never buffered, so no declared length can be too large.
        assert!(
            begin(
                StreamKind::Request,
                false,
                DATA,
                crate::varint::VARINT_MAX,
                &budget()
            )
            .is_ok()
        );
    }

    /// The whole of [`misplaced`], and the ordering it depends on: a frame type
    /// that may not appear on this stream is a connection error at *every*
    /// length, including the lengths the per-frame cap would otherwise refuse
    /// with a stream error.
    #[test]
    fn a_frame_types_verdict_comes_before_its_length() {
        /// Nothing, one byte, the largest buffered frame, and one past it.
        const LENGTHS: [u64; 4] = [0, 1, MAX_BUFFERED_FRAME, MAX_BUFFERED_FRAME + 1];

        for (stream, refused, allowed) in [
            (
                StreamKind::Request,
                &[SETTINGS, GOAWAY, CANCEL_PUSH, MAX_PUSH_ID, PUSH_PROMISE][..],
                &[DATA, HEADERS, 0x1f * 4 + 0x21][..],
            ),
            (
                StreamKind::Tunnel,
                &[
                    HEADERS,
                    SETTINGS,
                    GOAWAY,
                    CANCEL_PUSH,
                    MAX_PUSH_ID,
                    PUSH_PROMISE,
                ][..],
                &[DATA, 0x1f * 4 + 0x21][..],
            ),
            (
                StreamKind::Control,
                &[][..],
                &[
                    DATA,
                    HEADERS,
                    SETTINGS,
                    GOAWAY,
                    CANCEL_PUSH,
                    MAX_PUSH_ID,
                    PUSH_PROMISE,
                ][..],
            ),
        ] {
            for kind in refused {
                for length in LENGTHS {
                    let Err(Error::Protocol(violation)) =
                        begin(stream, false, *kind, length, &budget())
                    else {
                        panic!("{stream:?}: frame type {kind:#x} of {length} bytes must be refused")
                    };
                    assert_eq!(violation.code(), Code::H3_FRAME_UNEXPECTED, "{stream:?}");
                    assert!(
                        violation.is_connection_error(),
                        "{stream:?}: frame type {kind:#x} is a connection error, not a 431"
                    );
                }
            }

            for kind in allowed {
                assert!(
                    misplaced(stream, false, *kind).is_none(),
                    "{stream:?}: frame type {kind:#x} belongs here"
                );
            }
        }
    }

    /// The control stream's rules that `misplaced` decides from the header, at
    /// every length, and where the cap takes over. The comments in the body
    /// name each case.
    #[test]
    fn control_stream_type_rules_are_decided_before_the_cap() {
        /// Nothing, one byte, and the largest buffered frame.
        const BUFFERED: [u64; 3] = [0, 1, MAX_BUFFERED_FRAME];
        /// One past the largest buffered frame.
        const PAST: u64 = MAX_BUFFERED_FRAME + 1;

        // HEADERS and PUSH_PROMISE before SETTINGS: the first-frame rule, from
        // the header at every length.
        for kind in [HEADERS, PUSH_PROMISE] {
            for length in BUFFERED.iter().copied().chain([PAST]) {
                let Err(Error::Protocol(violation)) =
                    begin(StreamKind::ServerControl, false, kind, length, &budget())
                else {
                    panic!("{kind:#x} of {length} bytes before SETTINGS must be refused")
                };
                assert_eq!(violation.code(), Code::H3_MISSING_SETTINGS);
                assert!(violation.is_connection_error());
            }
        }

        // The same two after SETTINGS, at every length.
        for kind in [HEADERS, PUSH_PROMISE] {
            for length in BUFFERED.iter().copied().chain([PAST]) {
                let Err(Error::Protocol(violation)) =
                    begin(StreamKind::ServerControl, true, kind, length, &budget())
                else {
                    panic!("{kind:#x} of {length} bytes after SETTINGS must be refused")
                };
                assert_eq!(violation.code(), Code::H3_FRAME_UNEXPECTED);
                assert!(violation.is_connection_error());
            }
        }

        // A second SETTINGS is refused from the header at every length: the
        // type is the offence, so its payload is never parsed.
        for length in BUFFERED.iter().copied().chain([PAST]) {
            let Err(Error::Protocol(violation)) =
                begin(StreamKind::ServerControl, true, SETTINGS, length, &budget())
            else {
                panic!("a second SETTINGS of {length} bytes must be refused")
            };
            assert_eq!(violation.code(), Code::H3_FRAME_UNEXPECTED);
            assert!(violation.is_connection_error());
        }

        // A first GOAWAY, CANCEL_PUSH or MAX_PUSH_ID is the first frame too, so
        // §6.2.1 decides it from the header at every length: its payload is
        // never parsed, and a malformed one does not get a payload verdict.
        for kind in [GOAWAY, CANCEL_PUSH, MAX_PUSH_ID] {
            for length in BUFFERED.iter().copied().chain([PAST]) {
                let Err(Error::Protocol(violation)) =
                    begin(StreamKind::ServerControl, false, kind, length, &budget())
                else {
                    panic!("{kind:#x} of {length} bytes before SETTINGS must be refused")
                };
                assert_eq!(violation.code(), Code::H3_MISSING_SETTINGS);
                assert!(violation.is_connection_error());
            }
        }

        // Once SETTINGS has opened the stream, those three belong there: under
        // the cap they are buffered and parsed, and past it the cap is their
        // only bound. A payload error can then come before a state rule,
        // because RFC 9114 ranks neither (the ordering `it_frameseq` models).
        for kind in [GOAWAY, CANCEL_PUSH, MAX_PUSH_ID] {
            for length in BUFFERED {
                assert_matches!(
                    begin(StreamKind::ServerControl, true, kind, length, &budget()),
                    Ok(State::Buffering { .. }),
                    "{kind:#x} of {length} bytes after SETTINGS is parsed"
                );
            }
            assert!(misplaced(StreamKind::ServerControl, true, kind).is_none());
        }

        // The first SETTINGS is the one frame this stream is waiting for, so it
        // is not type-refused: under the cap it is buffered and parsed, and a
        // malformed one keeps its payload verdict; over the cap it keeps the
        // load answer.
        assert_matches!(
            begin(
                StreamKind::ServerControl,
                false,
                SETTINGS,
                MAX_BUFFERED_FRAME,
                &budget()
            ),
            Ok(State::Buffering { .. })
        );
        let Err(Error::Protocol(violation)) = begin(
            StreamKind::ServerControl,
            false,
            SETTINGS,
            MAX_BUFFERED_FRAME + 1,
            &budget(),
        ) else {
            panic!("a first SETTINGS past the cap keeps the load answer")
        };
        assert_eq!(violation.code(), Code::H3_EXCESSIVE_LOAD);
        assert!(!violation.is_connection_error());

        // The permissive kind applies no control-stream rule: a HEADERS frame
        // past the cap is still the stream error a 431 answers, which is what
        // the suite's client needs for its own response stream.
        let Err(Error::Protocol(violation)) = begin(
            StreamKind::Control,
            true,
            HEADERS,
            MAX_BUFFERED_FRAME + 1,
            &budget(),
        ) else {
            panic!("the permissive kind still applies the cap")
        };
        assert_eq!(violation.code(), Code::H3_EXCESSIVE_LOAD);
        assert!(!violation.is_connection_error());
    }

    /// RFC 9114 §6.2.1's first-frame rule turns on the type alone, so DATA and
    /// an unknown type sent first are refused from their header like every
    /// other type. An unknown first frame declaring 2^62-1 bytes would
    /// otherwise be skipped for as long as the peer kept sending, and the rule
    /// would never be applied. After SETTINGS, DATA is refused from its header
    /// too (§7.2.1), while an unknown type is still skipped (§9).
    #[test]
    fn a_first_frame_that_is_not_settings_is_refused_from_its_header() {
        fn control_decoder() -> FrameDecoder {
            FrameDecoder::new(StreamKind::ServerControl, Arc::new(BufferBudget::default()))
        }
        let endless = crate::varint::VARINT_MAX;

        for kind in [DATA, 0x21, 0x1f * 4 + 0x21, 0x4242] {
            for length in [0, 1, endless] {
                let mut decoder = control_decoder();
                let mut wire = BytesMut::new();
                put_header(&mut wire, kind, length);
                decoder.push(wire.freeze());

                let Err(Error::Protocol(violation)) = decoder.next_item() else {
                    panic!("a first frame of type {kind:#x} and {length} bytes must be refused")
                };
                assert_eq!(violation.code(), Code::H3_MISSING_SETTINGS);
                assert!(violation.is_connection_error());
            }
        }

        // After SETTINGS: DATA is refused with none of its payload sent, and an
        // unknown type is skipped.
        for (kind, refused) in [(DATA, true), (0x21, false)] {
            let mut decoder = control_decoder();
            let mut wire = BytesMut::from(&frame(SETTINGS, &[])[..]);
            put_header(&mut wire, kind, endless);
            decoder.push(wire.freeze());

            assert_matches!(
                decoder.next_item(),
                Ok(Some(Item::Frame(Frame::Settings(_))))
            );
            if refused {
                let Err(Error::Protocol(violation)) = decoder.next_item() else {
                    panic!("DATA on the control stream must be refused from its header")
                };
                assert_eq!(violation.code(), Code::H3_FRAME_UNEXPECTED);
                assert!(violation.is_connection_error());
            } else {
                assert_matches!(decoder.next_item(), Ok(None));
            }
        }
    }

    /// The transition the tunnels make: a stream that accepted a field section
    /// while its request was arriving refuses one afterwards.
    #[test]
    fn answering_the_connect_narrows_what_the_stream_may_carry() {
        let mut decoder = fresh_decoder();
        assert_matches!(
            begin(decoder.stream, false, HEADERS, 200, &budget()),
            Ok(State::Buffering { .. })
        );

        decoder.connect_completed();

        let mut wire = BytesMut::new();
        put_header(&mut wire, HEADERS, MAX_BUFFERED_FRAME);
        decoder.push(wire.freeze());

        let Err(Error::Protocol(violation)) = decoder.next_item() else {
            panic!("a field section after the CONNECT completed must be refused")
        };
        assert_eq!(violation.code(), Code::H3_FRAME_UNEXPECTED);
        assert!(violation.is_connection_error());
        assert_eq!(
            decoder.budget.held(),
            0,
            "a refused frame must not have been charged for"
        );
    }

    /// A buffered frame's payload is allocated once, at the length the frame
    /// announced, so the allocation equals what the D77 budget is charged.
    ///
    /// Grown by doubling instead, a peer that announces a length just past a
    /// doubling point and withholds the last byte makes each frame's
    /// allocation close to twice its charge.
    #[test]
    fn a_buffered_frame_is_allocated_at_its_announced_length() {
        let budget = Arc::new(BufferBudget::default());
        let mut decoder = FrameDecoder::new(StreamKind::Request, budget);

        let mut wire = BytesMut::new();
        put_header(&mut wire, HEADERS, 38402);
        wire.extend_from_slice(&[0x5a; 1200]);
        decoder.push(wire.freeze());
        assert!(decoder.next_item().expect("decodes").is_none());
        assert_eq!(buffered(&decoder).capacity(), 38402);

        for _ in 0..31 {
            decoder.push(Bytes::from(vec![0x5a; 1200]));
            assert!(decoder.next_item().expect("decodes").is_none());
        }
        assert_eq!(buffered(&decoder).len(), 38400);
        assert_eq!(
            buffered(&decoder).capacity(),
            38402,
            "the payload buffer grew past the announced length"
        );
    }

    /// The payload a decoder in the middle of a buffered frame holds.
    fn buffered(decoder: &FrameDecoder) -> &BytesMut {
        let State::Buffering { payload, .. } = &decoder.state else {
            panic!("the decoder is not buffering a frame: {:?}", decoder.state)
        };
        payload
    }

    /// D77: the connection's budget is charged for what a frame *announces*,
    /// and given back on both of the ways a frame stops being held: it
    /// completes, or the stream carrying it dies half-way through.
    #[test]
    fn a_buffered_frame_holds_budget_until_it_completes_or_is_dropped() {
        let budget = Arc::new(BufferBudget::default());
        let mut decoder = FrameDecoder::new(StreamKind::Request, budget.clone());

        // The header alone commits the connection to the whole length.
        let mut wire = BytesMut::new();
        put_header(&mut wire, HEADERS, 1000);
        wire.extend_from_slice(&[0x5a; 400]);
        decoder.push(wire.freeze());
        assert!(decoder.next_item().expect("decodes").is_none());
        assert_eq!(
            budget.held(),
            1000,
            "the announced length is charged, not the 400 bytes that have arrived"
        );

        // Completing it hands the payload on and returns every byte.
        decoder.push(Bytes::from(vec![0x5a; 600]));
        assert_matches!(
            decoder.next_item().expect("decodes"),
            Some(Item::Frame(Frame::Headers(block))) if block.len() == 1000
        );
        assert_eq!(budget.held(), 0);

        // A stream abandoned mid-frame returns its share as well, which is the
        // only thing standing between a peer that resets streams in a loop and
        // a connection that has spent its budget on nothing.
        let mut wire = BytesMut::new();
        put_header(&mut wire, HEADERS, 1000);
        decoder.push(wire.freeze());
        assert!(decoder.next_item().expect("decodes").is_none());
        assert_eq!(budget.held(), 1000);

        drop(decoder);
        assert_eq!(budget.held(), 0);
    }

    /// D77: frames each within [`MAX_BUFFERED_FRAME`] are still refused once
    /// their sum is past what one connection may hold.
    #[test]
    fn frames_past_the_connection_budget_are_refused_one_at_a_time() {
        /// A decoder that has announced a full-sized frame and sent none of it.
        fn announce(budget: &Arc<BufferBudget>) -> (FrameDecoder, Result<Option<Item>, Error>) {
            let mut decoder = FrameDecoder::new(StreamKind::Request, budget.clone());
            let mut wire = BytesMut::new();
            put_header(&mut wire, HEADERS, MAX_BUFFERED_FRAME);
            decoder.push(wire.freeze());
            let outcome = decoder.next_item();
            (decoder, outcome)
        }

        let budget = Arc::new(BufferBudget::default());
        let fits = HEADERS_BUFFER_BUDGET / MAX_BUFFERED_FRAME as usize;

        let mut streams = Vec::new();
        for stream in 0..fits {
            let (decoder, outcome) = announce(&budget);
            assert_matches!(outcome, Ok(None), "stream {stream} is within the budget");
            streams.push(decoder);
        }
        assert_eq!(budget.held(), fits * MAX_BUFFERED_FRAME as usize);

        // One more, and no stream has broken a rule of its own.
        let (_decoder, outcome) = announce(&budget);
        let Err(Error::Protocol(violation)) = outcome else {
            panic!("a frame past the connection budget must be refused")
        };
        assert_eq!(violation.code(), Code::H3_EXCESSIVE_LOAD);
        assert!(
            !violation.is_connection_error(),
            "the arriving request is refused, not the connection carrying it"
        );
        assert_eq!(
            budget.held(),
            fits * MAX_BUFFERED_FRAME as usize,
            "a refused charge must leave the counter where it was"
        );

        // And the connection is whole again once the streams are gone.
        drop(streams);
        assert_eq!(budget.held(), 0);
    }

    /// The same bound when every stream announces at the same instant.
    ///
    /// Every stream announces at once from a barrier, four times as many as
    /// fit, so the count must be exact however the threads interleave;
    /// `BufferBudget::charge` says why `try_update`.
    #[test]
    fn concurrent_charges_hold_the_budget_exactly() {
        let budget = Arc::new(BufferBudget::default());
        let fits = HEADERS_BUFFER_BUDGET / MAX_BUFFERED_FRAME as usize;
        let streams = 4 * fits;

        let start = std::sync::Barrier::new(streams);
        let charged = std::sync::Mutex::new(Vec::new());
        let refused = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            for _ in 0..streams {
                scope.spawn(|| {
                    // Everything but the charge itself happens before the
                    // barrier, so what the threads contend on is the counter.
                    let mut decoder = FrameDecoder::new(StreamKind::Request, budget.clone());
                    let mut wire = BytesMut::new();
                    put_header(&mut wire, HEADERS, MAX_BUFFERED_FRAME);
                    decoder.push(wire.freeze());

                    start.wait();
                    match decoder.next_item() {
                        // Charged, and the frame is still being held: the
                        // decoder goes in the pile rather than being dropped,
                        // which would give the share straight back.
                        Ok(None) => charged.lock().expect("collector").push(decoder),
                        Err(Error::Protocol(violation)) => {
                            assert_eq!(violation.code(), Code::H3_EXCESSIVE_LOAD);
                            assert!(!violation.is_connection_error());
                            refused.fetch_add(1, Ordering::Relaxed);
                        }
                        other => {
                            panic!("a frame that has not arrived cannot be complete: {other:?}")
                        }
                    }
                });
            }
        });

        let held = charged.into_inner().expect("collector");
        assert_eq!(
            held.len(),
            fits,
            "{} streams were charged where {fits} fit",
            held.len()
        );
        assert_eq!(refused.load(Ordering::Relaxed), streams - fits);
        assert_eq!(
            budget.held(),
            fits * MAX_BUFFERED_FRAME as usize,
            "the refused charges left bytes behind"
        );

        drop(held);
        assert_eq!(budget.held(), 0, "a share was not given back");
    }

    /// The counter the bound is read off is never seen above the bound.
    ///
    /// A sampler watches the counter while workers announce and drop frames at
    /// the boundary. An add-then-check charge would show a value past the bound
    /// for the instant before its rollback; `try_update` never publishes one.
    #[test]
    fn a_refused_charge_is_never_visible_to_another_stream() {
        /// Announces a full-sized frame, then lets the decoder go.
        fn churn(budget: &Arc<BufferBudget>) {
            let mut decoder = FrameDecoder::new(StreamKind::Request, budget.clone());
            let mut wire = BytesMut::new();
            put_header(&mut wire, HEADERS, MAX_BUFFERED_FRAME);
            decoder.push(wire.freeze());
            let _ = decoder.next_item();
        }

        const WORKERS: usize = 8;
        const ROUNDS: usize = 4096;

        let budget = Arc::new(BufferBudget::default());
        let fits = HEADERS_BUFFER_BUDGET / MAX_BUFFERED_FRAME as usize;

        // Most of the budget pinned, so the churn below sits on the boundary
        // rather than well inside it and every round is a real decision.
        let mut pinned = Vec::new();
        for _ in 0..fits - 1 {
            let mut decoder = FrameDecoder::new(StreamKind::Request, budget.clone());
            let mut wire = BytesMut::new();
            put_header(&mut wire, HEADERS, MAX_BUFFERED_FRAME);
            decoder.push(wire.freeze());
            assert_matches!(decoder.next_item(), Ok(None));
            pinned.push(decoder);
        }

        let stop = std::sync::atomic::AtomicBool::new(false);
        let seen = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            let sampler = scope.spawn(|| {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                let mut worst = 0;
                while !stop.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
                    worst = worst.max(budget.held());
                }
                seen.store(worst, Ordering::Relaxed);
            });

            let workers: Vec<_> = (0..WORKERS)
                .map(|_| {
                    scope.spawn(|| {
                        for _ in 0..ROUNDS {
                            churn(&budget);
                        }
                    })
                })
                .collect();

            for worker in workers {
                worker.join().expect("worker");
            }
            stop.store(true, Ordering::Relaxed);
            sampler.join().expect("sampler");
        });

        assert!(
            seen.load(Ordering::Relaxed) <= HEADERS_BUFFER_BUDGET,
            "the budget was seen holding {} bytes, past the {HEADERS_BUFFER_BUDGET} it may",
            seen.load(Ordering::Relaxed)
        );

        drop(pinned);
        assert_eq!(budget.held(), 0, "the churn left bytes behind");
    }

    /// RFC 9114 §7.1: a stream that ends inside a frame is an error, and one
    /// that ends between them is the ordinary end of a request body.
    #[test]
    fn a_frame_boundary_is_where_a_stream_may_end() {
        let mut decoder = fresh_decoder();
        assert!(decoder.at_frame_boundary());

        decoder.push(Bytes::from(frame(DATA, b"abcd")));
        assert_matches!(decoder.next_item().expect("decodes"), Some(Item::Data(_)));
        assert!(decoder.at_frame_boundary());

        // Half a frame header, then half a payload: neither is a place to stop.
        let mut decoder = fresh_decoder();
        decoder.push(Bytes::from_static(&[0x00]));
        assert!(decoder.next_item().expect("decodes").is_none());
        assert!(!decoder.at_frame_boundary());

        let mut decoder = fresh_decoder();
        decoder.push(Bytes::from_static(&[0x00, 0x04, b'a']));
        assert!(decoder.next_item().expect("decodes").is_some());
        assert!(!decoder.at_frame_boundary());
    }

    /// The decoder reads bytes from an unauthenticated peer, so it may reject
    /// anything but must never panic.
    #[test]
    fn arbitrary_bytes_never_panic_the_frame_decoder() {
        proptest::proptest!(|(wire: Vec<u8>)| {
            let mut decoder = fresh_decoder();
            decoder.push(Bytes::from(wire));
            while let Ok(Some(_)) = decoder.next_item() {}
        });
    }

    #[test]
    fn frame_headers_round_trip() {
        for (kind, length) in [(DATA, 0u64), (HEADERS, 63), (SETTINGS, 16_384), (0x1f21, 1)] {
            let mut buf = BytesMut::new();
            put_header(&mut buf, kind, length);

            let (decoded_kind, used) = peek_varint(&buf).expect("type");
            let (decoded_length, used_more) = peek_varint(&buf[used..]).expect("length");
            assert_eq!((decoded_kind, decoded_length), (kind, length));
            assert_eq!(used + used_more, buf.len());
        }
    }
}
