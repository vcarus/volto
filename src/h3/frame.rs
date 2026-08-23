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
//! A frame's *type* is judged before its length, and which verdict it earns
//! depends on the stream it arrived on. SETTINGS on a request
//! stream is a connection error at any size, so refusing it for being large
//! would be answering a question the peer did not ask -- and charging the
//! buffering budget for a frame that was never allowed there would let a peer
//! hold the budget with frames it is not entitled to send at all.
//!
//! The decoder is pure: it holds every byte of state, and [`FrameReader`] is
//! the twenty lines that feed it from a QUIC stream. That split is what makes
//! the frame layer testable a byte at a time, and what makes [`FrameReader`]
//! cancel-safe -- the only await is the read, and nothing it produces is lost
//! by dropping the future. `tunnel::udp` reads request streams inside a
//! `select!` with a timeout, so that property is load-bearing.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};

use crate::datagram::{peek_varint, put_varint};

use super::error::{Code, StreamError, Violation};
use super::{HEADERS_BUFFER_BUDGET, MAX_FIELD_SECTION_SIZE};

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

/// Frame types RFC 9114 §11.2.1 reserves because HTTP/2 used them.
///
/// §7.2.8 makes their receipt a connection error rather than something to skip:
/// a peer sending one has mistaken this connection for an HTTP/2 one, and
/// nothing good follows from carrying on.
const RESERVED_HTTP2_TYPES: [u64; 4] = [0x02, 0x06, 0x08, 0x09];

/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (RFC 9204 §5).
pub const SETTING_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114 §7.2.4.1).
pub const SETTING_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
/// `SETTINGS_QPACK_BLOCKED_STREAMS` (RFC 9204 §5).
pub const SETTING_QPACK_BLOCKED_STREAMS: u64 = 0x07;
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 9220 §3).
pub const SETTING_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
/// `SETTINGS_H3_DATAGRAM` (RFC 9297 §2.1.1).
pub const SETTING_H3_DATAGRAM: u64 = 0x33;

/// Setting identifiers RFC 9114 §11.2.2 reserves because HTTP/2 used them.
const RESERVED_HTTP2_SETTINGS: [u64; 5] = [0x00, 0x02, 0x03, 0x04, 0x05];

/// Largest payload this reader will buffer for one non-DATA frame.
///
/// A policy bound on *encoded* bytes, and this server's own rule rather than
/// anything the RFC asks for. It applies to every buffered frame -- HEADERS,
/// SETTINGS, GOAWAY, CANCEL_PUSH, MAX_PUSH_ID, PUSH_PROMISE -- because each of
/// them declares its length as a varint that may claim 2^62 bytes, and the
/// declared length is refused here before a single byte is allocated for it.
///
/// Its value is [`MAX_FIELD_SECTION_SIZE`], which makes it the same number as
/// the advertised field-section limit without being the same *rule*: RFC 9114
/// §4.2.2 sizes a field section by the uncompressed name and value plus 32
/// bytes per field, while this counts the octets that arrived. The two usually
/// run the same way round, since the static table and Huffman coding shrink a
/// real request -- but not always. A Huffman code is up to 30 bits wide
/// (RFC 7541 Appendix B), so a literal made of bytes the table codes poorly can
/// grow by up to 3.75x, and such a section can be inside the advertised limit
/// and still refused here. No encoder produces one, because Huffman coding is
/// optional per field and an encoder that would grow a literal sends it as it
/// is; what this bounds is what a peer that is *not* a real encoder can make an
/// unauthenticated connection hold.
const MAX_BUFFERED_FRAME: u64 = MAX_FIELD_SECTION_SIZE;

/// Longest frame header there can be: a type and a length, both varints.
const MAX_FRAME_HEADER: usize = 2 * super::MAX_VARINT;

/// What one connection may hold in `FrameDecoder` payload buffers, as a
/// counter every request stream on it shares (D77).
///
/// `MAX_BUFFERED_FRAME` is per frame and so per stream; this is the sum over
/// the streams, which is the number a peer opening many of them actually
/// controls. [`super::HEADERS_BUFFER_BUDGET`] says why that distinction is
/// worth a counter and how the value was chosen.
///
/// Every request stream's decoder holds the same one, so a share taken on any
/// of them is a share the others cannot take. Charging happens when a decoder
/// commits to buffering a frame and releasing when that frame completes or its
/// decoder is dropped, so the counter reads zero on a connection with nothing
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
    /// open; the control stream is one per connection and buffers one frame at a
    /// time, so the per-frame bound holds it on its own and it has nothing to
    /// share. Keeping it out of the shared counter is also what stops a peer
    /// that has filled that counter with request streams from making its own
    /// well-formed SETTINGS or GOAWAY the frame that is refused: a refusal there
    /// could not be the stream-class one a charge past the budget hands out,
    /// since closing the control stream is itself a connection error
    /// (RFC 9114 §6.2.1, quoted in [`super::connection`]).
    ///
    /// Not public: the one reader that needs it lives in [`super::connection`],
    /// and a budget shared with nothing is this layer's own arrangement rather
    /// than something a caller of the crate has any use for.
    pub(super) fn unshared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Takes `bytes` from the budget, or reports that the connection is past
    /// it.
    ///
    /// A *stream* error, on the stream whose frame is arriving. That stream is
    /// not the one at fault -- the bound is a connection's, every stream holding
    /// a share of it may be within [`MAX_BUFFERED_FRAME`], and the one that
    /// happens to arrive last has done nothing the others did not. But the
    /// alternative is to close a connection, and its tunnels, over a request
    /// that is merely the seventeenth largest one allowed at once, which a
    /// client breaking no rule can reach. RFC 9114 §4.2.2 says what to do with a
    /// field section this server is unwilling to handle, and it is about the one
    /// request: `stream::Resolver` answers this with the same 431 the per-frame
    /// bound gets, and the connection carries on.
    ///
    /// RFC 9114 §8.1 defines H3_EXCESSIVE_LOAD for a peer "exhibiting a
    /// behavior that might be generating excessive load", which is what holding
    /// a connection's whole buffering allowance in frames it never finishes is
    /// -- the same reading [`super::qpack`] takes of the same code.
    ///
    /// `fetch_update` rather than an add-then-check: a rejected charge must
    /// leave the counter untouched, or two streams failing at once would each
    /// see the other's rolled-back bytes and the bound would hold only on
    /// average.
    fn charge(&self, bytes: usize) -> Result<(), Violation> {
        self.held
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                let wanted = held.saturating_add(bytes);
                (wanted <= HEADERS_BUFFER_BUDGET).then_some(wanted)
            })
            .map_err(|held| {
                Violation::stream(
                    Code::H3_EXCESSIVE_LOAD,
                    format!(
                        "buffering another {bytes} bytes would put this connection past the \
                         {HEADERS_BUFFER_BUDGET} it may hold in unfinished frames, of which \
                         {held} are already held"
                    ),
                )
            })?;
        Ok(())
    }

    /// Gives `bytes` back to the budget.
    ///
    /// Saturating, and asserted in debug builds: nothing today can return more
    /// than it took -- `charged` is written only after a charge succeeds and
    /// zeroed by the `mem::take` that hands it here -- but an underflow would
    /// wrap the counter to somewhere near `usize::MAX` and leave the connection
    /// refusing every request from then on, with a reason line reporting a
    /// figure no machine has the memory for. A saturating subtraction turns that
    /// into a budget that is merely wrong, which is recoverable and legible.
    fn release(&self, bytes: usize) {
        if bytes > 0 {
            let held = self
                .held
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                    Some(held.saturating_sub(bytes))
                });
            debug_assert!(
                held.is_ok_and(|held| held >= bytes),
                "released {bytes} bytes from a budget holding {held:?}"
            );
        }
    }

    /// Bytes currently charged to this connection.
    ///
    /// For the unit tests that assert the accounting, and nothing else: what is
    /// charged and released is not visible on the wire until the budget is
    /// spent, and a share that is never returned would show up only as a
    /// connection that eventually refuses a request it should have served.
    #[cfg(test)]
    fn held(&self) -> usize {
        self.held.load(Ordering::Relaxed)
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
    /// Reported rather than swallowed for the same reason as an empty DATA
    /// frame: RFC 9114 §6.2.1 asks what the first frame on the control stream
    /// was, and a frame this server did not understand is still a frame. Every
    /// other reader ignores it, which is what §9 requires.
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

/// The peer's SETTINGS, reduced to what this server acts on.
///
/// Only one setting changes any behaviour here: RFC 9297 §2.1.1 forbids sending
/// HTTP Datagrams until the peer has advertised support for them, and a
/// CONNECT-UDP session falls back to capsules on the request stream until it
/// has. Everything else is validated as the RFC requires and then dropped,
/// because keeping a value nothing reads is how a setting silently stops being
/// honoured.
///
/// One of the dropped values carries a SHOULD this server knowingly does not
/// honour, so it is recorded here rather than left to be rediscovered:
///
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
//# An implementation that has received this parameter SHOULD NOT send an
//# HTTP message header that exceeds the indicated size, as the peer will
//# likely refuse to process it.
///
/// A peer's `SETTINGS_MAX_FIELD_SECTION_SIZE` is parsed -- so that a malformed
/// or duplicated one is still caught -- and then dropped. Every response this
/// server sends is a status line and at most two short fields, some 200 bytes
/// by §4.2.2's own accounting, so honouring the SHOULD would mean carrying the
/// value through the connection, the request and the response writer to change
/// nothing: the only peer it could affect is one advertising a limit small
/// enough to refuse a bare `407`, which has asked for a proxy it cannot use.
/// Trimming fields to fit would also mean choosing which of a `Proxy-Status`
/// explanation or a `Proxy-Authenticate` challenge to drop, and neither is
/// better sent truncated than in full.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Settings {
    /// `SETTINGS_H3_DATAGRAM = 1`.
    pub datagrams: bool,
}

/// Which of this server's streams a decoder is reading.
///
/// RFC 9114 states most of its frame rules as "on any other stream" or "once
/// the CONNECT method has completed", so the same frame type is ordinary on one
/// stream and a connection error on the next. This is what a decoder knows about
/// which of the three it is serving, and [`misplaced`] is the whole of the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StreamKind {
    /// The peer's control stream (RFC 9114 §6.2.1).
    ///
    /// Every frame type this server parses may legitimately arrive here, so
    /// nothing is refused by type alone: which of them is allowed *when* --
    /// a second SETTINGS, a CANCEL_PUSH, a HEADERS -- depends on what has
    /// already been seen, which is [`super::connection`]'s to track.
    Control,
    /// A request stream whose request has not completed.
    Request,
    /// A request stream whose CONNECT has completed (RFC 9114 §4.4).
    Tunnel,
}

/// Where the decoder is in the frame sequence.
#[derive(Debug, Clone, Copy)]
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
        kind: u64,
        /// Payload bytes still to arrive.
        remaining: usize,
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
/// decoder has to be a state machine that can be fed a byte at a time -- which
/// is exactly how the tests below feed it.
#[derive(Debug)]
pub(super) struct FrameDecoder {
    /// The chunk last pushed, with the consumed prefix removed.
    chunk: Bytes,
    /// Frame header bytes carried over from earlier chunks.
    ///
    /// A fixed array rather than a growable buffer, so that constructing a
    /// decoder allocates nothing: one is built per stream, and a peer opening
    /// streams is not otherwise paying for a heap allocation each time. It
    /// cannot overflow -- [`Self::take_frame_header`] stops as soon as two
    /// varints have arrived, and RFC 9000 §16 bounds each at eight bytes.
    header: [u8; MAX_FRAME_HEADER],
    /// How many bytes of [`Self::header`] have arrived.
    header_len: usize,
    /// Payload of the frame currently being buffered.
    payload: BytesMut,
    /// The connection's buffering budget, shared with every other decoder on
    /// it (D77).
    ///
    /// Held as an `Arc` rather than a borrow because a decoder outlives no
    /// scope in particular: it belongs to a stream, and the streams of a
    /// connection end in any order. Cloning one is a refcount bump, so
    /// [`Self::new`] still allocates nothing.
    budget: Arc<BufferBudget>,
    /// Bytes charged to that budget for the frame being buffered, if any.
    ///
    /// The full length the frame announced, which is what this decoder has
    /// committed to holding -- not what has arrived so far. Returned by
    /// [`Self::release`] on the two ways a commitment ends: the frame
    /// completes, or the decoder is dropped with it half-received.
    charged: usize,
    /// Which stream's rules this decoder applies to a frame type.
    ///
    /// Not fixed for the life of the decoder: a request stream becomes a tunnel
    /// the moment its CONNECT is answered, and RFC 9114 §4.4 narrows what may
    /// follow to DATA alone.
    stream: StreamKind,
    state: State,
}

impl FrameDecoder {
    /// A decoder positioned at the start of a `stream`'s frame sequence, drawing
    /// on `budget` for whatever it has to buffer.
    pub(super) fn new(stream: StreamKind, budget: Arc<BufferBudget>) -> Self {
        Self {
            chunk: Bytes::new(),
            header: [0; MAX_FRAME_HEADER],
            header_len: 0,
            payload: BytesMut::new(),
            budget,
            charged: 0,
            stream,
            state: State::Header,
        }
    }

    /// Hands the decoder the next chunk of stream.
    ///
    /// Only legal once [`Self::next_item`] has asked for more, which is the only
    /// state in which the previous chunk is spent.
    pub(super) fn push(&mut self, chunk: Bytes) {
        debug_assert!(self.chunk.is_empty(), "the previous chunk is not consumed");
        self.chunk = chunk;
    }

    /// Narrows the frame rules to the ones RFC 9114 §4.4 gives a tunnel.
    ///
    /// Called once the 2xx answering a CONNECT has gone out, which is what
    /// "completed" means in that section. From here a HEADERS frame is a
    /// connection error like every other known type but DATA, and it is refused
    /// from its header rather than after its payload -- so a peer cannot hold
    /// the connection's buffering budget with field sections it was never
    /// allowed to send.
    pub(super) fn connect_completed(&mut self) {
        self.stream = StreamKind::Tunnel;
    }

    /// Whether the stream could end here without truncating a frame.
    ///
    /// RFC 9114 §7.1: "When a stream terminates cleanly, if the last frame on
    /// the stream was truncated, this MUST be treated as a connection error of
    /// type H3_FRAME_ERROR."
    pub(super) fn at_frame_boundary(&self) -> bool {
        matches!(self.state, State::Header) && self.header_len == 0
    }

    /// The next item, or `None` when more bytes are needed.
    pub(super) fn next_item(&mut self) -> Result<Option<Item>, Error> {
        loop {
            match self.state {
                State::Header => {
                    let Some((kind, length)) = self.take_frame_header() else {
                        return Ok(None);
                    };
                    let next = begin(self.stream, kind, length)?;

                    // Charged on the announcement rather than on arrival: the
                    // announcement is the moment this decoder commits to
                    // holding that many bytes, and holding them is what the
                    // peer gets out of never sending them (D77). The state is
                    // entered only once the charge is in, so a refused frame
                    // leaves nothing to release.
                    if let State::Buffering { remaining, .. } = next {
                        self.budget.charge(remaining)?;
                        self.charged = remaining;
                    }
                    self.state = next;
                }

                // An empty DATA frame is legal and carries nothing; the two
                // arms are separate so it cannot be mistaken for "no bytes have
                // arrived yet", which is the same `take == 0` below. It still
                // produces an item, because a caller applying RFC 9114's rules
                // about frame *order* has to be told a DATA frame arrived.
                State::Data { remaining: 0 } => {
                    self.state = State::Header;
                    return Ok(Some(Item::Data(Bytes::new())));
                }

                State::Data { remaining } => {
                    let take = remaining.min(self.chunk.len() as u64) as usize;
                    if take == 0 {
                        return Ok(None);
                    }
                    // A slice of quinn's own buffer: a refcount bump, not a copy.
                    let data = self.chunk.split_to(take);
                    // Back to `Header` as soon as the frame is spent, so the end
                    // of a frame and the end of a stream agree about where a
                    // boundary is.
                    self.state = match remaining - take as u64 {
                        0 => State::Header,
                        left => State::Data { remaining: left },
                    };
                    return Ok(Some(Item::Data(data)));
                }

                State::Buffering { kind, remaining } => {
                    let take = remaining.min(self.chunk.len());
                    self.payload.extend_from_slice(&self.chunk[..take]);
                    self.chunk.advance(take);

                    if take < remaining {
                        self.state = State::Buffering {
                            kind,
                            remaining: remaining - take,
                        };
                        return Ok(None);
                    }
                    self.state = State::Header;
                    let payload = self.payload.split().freeze();
                    // Before the parse, which may fail: the frame is no longer
                    // being held either way.
                    self.release();
                    return Ok(Some(Item::Frame(parse(kind, payload)?)));
                }

                State::Skipping { kind, remaining } => {
                    let take = remaining.min(self.chunk.len() as u64) as usize;
                    self.chunk.advance(take);

                    match remaining - take as u64 {
                        0 => {
                            self.state = State::Header;
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

    /// Reads a frame type and length, or `None` if not all of it has arrived.
    ///
    /// Byte at a time because a header is at most [`MAX_FRAME_HEADER`] bytes and
    /// may straddle any number of chunks; the copy is into a fixed array of
    /// exactly that size.
    fn take_frame_header(&mut self) -> Option<(u64, u64)> {
        loop {
            let header = &self.header[..self.header_len];
            if let Some((kind, used)) = peek_varint(header) {
                if let Some((length, _)) = peek_varint(&header[used..]) {
                    self.header_len = 0;
                    return Some((kind, length));
                }
            }

            let byte = *self.chunk.first()?;
            self.chunk.advance(1);
            self.header[self.header_len] = byte;
            self.header_len += 1;
        }
    }

    /// Gives back whatever this decoder had charged to the connection's budget.
    ///
    /// Idempotent, because it is called from two places that can both be right:
    /// the end of a buffered frame, and [`Drop`].
    fn release(&mut self) {
        self.budget.release(std::mem::take(&mut self.charged));
    }
}

impl Drop for FrameDecoder {
    /// Returns the budget a half-received frame was holding (D77).
    ///
    /// The guard that makes the accounting sound: a stream can end at any
    /// point, and most of the ways it ends are the peer's to choose -- a
    /// RESET_STREAM, a `STOP_SENDING` answered, the request deadline of D76
    /// expiring, the connection going away. None of them reaches the decoding
    /// loop, and a share not returned on any one of them would be a slow leak
    /// of the connection's own allowance, ending in a peer being refused a
    /// request it was entitled to.
    fn drop(&mut self) {
        self.release();
    }
}

/// A `FrameDecoder` wired to a QUIC receive stream.
///
/// All of the awaiting happens in one place -- [`quinn::RecvStream::read_chunk`]
/// -- and every byte it produces is accounted for in the decoder before this
/// returns, which is what makes [`Self::next`] cancel-safe. `tunnel::udp` reads
/// request streams inside a `select!` with a timeout, so a dropped read future
/// must never lose a parsed frame header.
pub struct FrameReader {
    recv: quinn::RecvStream,
    decoder: FrameDecoder,
    /// Set once the peer has finished its sending side.
    finished: bool,
}

impl FrameReader {
    /// A reader for a stream on which every frame type this server parses may
    /// appear.
    ///
    /// That is the peer's control stream: RFC 9114 §6.2.1 makes it the stream
    /// SETTINGS, GOAWAY, CANCEL_PUSH and MAX_PUSH_ID belong on, and which of
    /// them may arrive *when* is [`super::connection`]'s to judge rather than
    /// the framing layer's. A request stream is read through the crate-internal
    /// `on_request_stream` instead, where those four -- and PUSH_PROMISE -- are
    /// refused from the frame header.
    ///
    /// It is also what a *client* wants for a response stream, which is why this
    /// is the constructor that stayed plain: the suite's client
    /// (`tests/common/h3client.rs`) is built on this module.
    ///
    /// `budget` is the connection's, not this stream's: see [`BufferBudget`].
    pub fn new(recv: quinn::RecvStream, budget: Arc<BufferBudget>) -> Self {
        Self::with_kind(recv, StreamKind::Control, budget)
    }

    /// A reader for a request stream whose request has not completed.
    ///
    /// Becomes a tunnel's reader once [`Self::connect_completed`] is called.
    pub(super) fn on_request_stream(recv: quinn::RecvStream, budget: Arc<BufferBudget>) -> Self {
        Self::with_kind(recv, StreamKind::Request, budget)
    }

    fn with_kind(recv: quinn::RecvStream, stream: StreamKind, budget: Arc<BufferBudget>) -> Self {
        Self {
            recv,
            decoder: FrameDecoder::new(stream, budget),
            finished: false,
        }
    }

    /// Narrows the frame rules to RFC 9114 §4.4's, once the CONNECT is answered.
    pub(super) fn connect_completed(&mut self) {
        self.decoder.connect_completed();
    }

    /// Asks the peer to stop sending on this stream.
    pub fn stop(&mut self, code: Code) {
        // Fails only if the stream is already closed, which needs no reporting.
        let _ = self.recv.stop(super::varint(code));
    }

    /// Reads the next item, or `None` once the peer has finished cleanly.
    pub async fn next(&mut self) -> Result<Option<Item>, Error> {
        loop {
            if let Some(item) = self.decoder.next_item()? {
                return Ok(Some(item));
            }
            if self.finished {
                return Ok(None);
            }

            match self.recv.read_chunk(usize::MAX, true).await? {
                Some(chunk) => self.decoder.push(chunk.bytes),
                None => {
                    self.finished = true;
                    if !self.decoder.at_frame_boundary() {
                        return Err(Violation::connection(
                            Code::H3_FRAME_ERROR,
                            "the stream ended part-way through a frame",
                        )
                        .into());
                    }
                    return Ok(None);
                }
            }
        }
    }
}

/// Decides what to do with a frame that has just been announced on `stream`.
///
/// The order of the two verdicts below is load-bearing. A frame type that may
/// not appear on this stream at all is a connection error whatever length it
/// declares, so the length check -- which hands out a *stream* error, and whose
/// answer on a request stream is a 431 -- must not reach it first: a 431 is a
/// nonsensical reply to a SETTINGS frame, and the connection would carry on
/// after a MUST-close.
fn begin(stream: StreamKind, kind: u64, length: u64) -> Result<State, Error> {
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

    if let Some(detail) = misplaced(stream, kind) {
        return Err(Violation::connection(Code::H3_FRAME_UNEXPECTED, detail).into());
    }

    Ok(match kind {
        DATA => State::Data { remaining: length },

        HEADERS | SETTINGS | GOAWAY | CANCEL_PUSH | MAX_PUSH_ID | PUSH_PROMISE => {
            if length > MAX_BUFFERED_FRAME {
                return Err(Violation::stream(
                    Code::H3_EXCESSIVE_LOAD,
                    format!("a {length}-byte frame is past what this server buffers"),
                )
                .into());
            }
            State::Buffering {
                kind,
                remaining: length as usize,
            }
        }

        // RFC 9114 §9's rule that unknown values are ignored, quoted in full in
        // `super`'s module comment. Ignoring is what every reader does with the
        // `Item::Skipped` this ends up producing; the payload is discarded here
        // and never buffered.
        _ => State::Skipping {
            kind,
            remaining: length,
        },
    })
}

/// Why frame type `kind` may not appear on `stream` at all, or `None` if it may.
///
/// Every case is a MUST in RFC 9114 that turns on *where* the frame arrived
/// rather than on anything inside it, which is what makes the verdict reachable
/// from the frame header alone. All of them are H3_FRAME_UNEXPECTED, so the code
/// is the caller's to supply and this returns only the reason phrase.
fn misplaced(stream: StreamKind, kind: u64) -> Option<&'static str> {
    match stream {
        // Nothing: RFC 9114 §6.2.1 makes this the stream the frames below belong
        // on, and the rules about which may arrive when need to know what has
        // already been seen -- `connection::Control` keeps that and this does
        // not. A HEADERS frame here is refused there (§7.2.2), after buffering,
        // because the control stream has a budget of its own and nothing on it
        // can be refused stream by stream.
        StreamKind::Control => None,

        StreamKind::Request => match kind {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
            //# SETTINGS frames MUST NOT be sent on any stream other than the
            //# control stream. If an endpoint receives a SETTINGS frame on a
            //# different stream, the endpoint MUST respond with a connection
            //# error of type H3_FRAME_UNEXPECTED.
            SETTINGS => Some("a SETTINGS frame on a request stream"),

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
            //# A CANCEL_PUSH frame is sent on the control stream. Receiving a
            //# CANCEL_PUSH frame on a stream other than the control stream MUST
            //# be treated as a connection error of type H3_FRAME_UNEXPECTED.
            CANCEL_PUSH => Some("a CANCEL_PUSH frame on a request stream"),

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
            //# The MAX_PUSH_ID frame is always sent on the control stream.
            //# Receipt of a MAX_PUSH_ID frame on any other stream MUST be
            //# treated as a connection error of type H3_FRAME_UNEXPECTED.
            MAX_PUSH_ID => Some("a MAX_PUSH_ID frame on a request stream"),

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
            //# A client MUST NOT send a PUSH_PROMISE frame. A server MUST treat
            //# the receipt of a PUSH_PROMISE frame as a connection error of type
            //# H3_FRAME_UNEXPECTED.
            //
            // The one rule here that is not about the stream: a server may not
            // receive this frame anywhere, so §7.2.5's separate sentence about
            // the control stream is addressed to a client and this is the
            // sentence that governs both places for us.
            PUSH_PROMISE => Some("a PUSH_PROMISE frame, which only a server may send"),

            // GOAWAY is the one of the five whose "not on this stream" rule
            // RFC 9114 §7.2.6 states for a client only -- "A client MUST treat a
            // GOAWAY frame on a stream other than the control stream as a
            // connection error of type H3_FRAME_UNEXPECTED" -- and this endpoint
            // is not a client. What reaches it here is §4.1's rule about the
            // sequence a request stream may carry, since a GOAWAY is no part of
            // any request message, and it names the same code:
            //
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# Receipt of an invalid sequence of frames MUST be treated as a
            //# connection error of type H3_FRAME_UNEXPECTED.
            GOAWAY => Some("a GOAWAY frame on a request stream"),

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
        // server does not know is skipped under §9 rather than judged -- which is
        // where the sentence's allowance for an extension frame lands, since an
        // extension this server does not implement is one it cannot be reading.
        // Everything in between is refused, a trailer section's HEADERS included:
        // there is no representation on a tunnel for a trailer to describe, and
        // RFC 9220 §3 extends CONNECT to other protocols by pointing at this
        // same section rather than by reopening it.
        StreamKind::Tunnel => match kind {
            DATA => None,
            HEADERS | SETTINGS | GOAWAY | CANCEL_PUSH | MAX_PUSH_ID | PUSH_PROMISE => {
                Some("a frame other than DATA once the CONNECT method had completed")
            }
            _ => None,
        },
    }
}

/// Parses a buffered frame payload.
fn parse(kind: u64, payload: Bytes) -> Result<Frame, Violation> {
    match kind {
        HEADERS => Ok(Frame::Headers(payload)),
        SETTINGS => parse_settings(&payload).map(Frame::Settings),
        GOAWAY => single_varint(GOAWAY, &payload).map(Frame::Goaway),
        CANCEL_PUSH => single_varint(CANCEL_PUSH, &payload).map(Frame::CancelPush),
        MAX_PUSH_ID => single_varint(MAX_PUSH_ID, &payload).map(Frame::MaxPushId),
        PUSH_PROMISE => Ok(Frame::PushPromise),
        // `begin` only buffers the types above.
        other => unreachable!("frame type {other:#x} is not buffered"),
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

/// Parses a SETTINGS payload (RFC 9114 §7.2.4).
fn parse_settings(mut payload: &[u8]) -> Result<Settings, Violation> {
    let mut settings = Settings::default();

    // A set rather than a list: the payload is bounded by `MAX_BUFFERED_FRAME`,
    // not by anything the peer has earned, and 64 KiB holds some sixteen
    // thousand distinct identifiers -- a quadratic scan over which is work an
    // unauthenticated peer can ask for on its control stream. (A SETTINGS frame
    // on a request stream is refused in `begin` from its header and never
    // reaches this parser.)
    let mut seen = HashSet::new();

    while !payload.is_empty() {
        let (identifier, used) = peek_varint(payload).ok_or_else(truncated_settings)?;
        payload = &payload[used..];
        let (value, used) = peek_varint(payload).ok_or_else(truncated_settings)?;
        payload = &payload[used..];

        if RESERVED_HTTP2_SETTINGS.contains(&identifier) {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
            //# These reserved settings MUST NOT be sent, and their receipt MUST
            //# be treated as a connection error of type H3_SETTINGS_ERROR.
            return Err(settings_error(format!(
                "setting {identifier:#x} is reserved for HTTP/2"
            )));
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
        //# The same setting identifier MUST NOT occur more than once in the
        //# SETTINGS frame.
        if !seen.insert(identifier) {
            return Err(settings_error(format!(
                "setting {identifier:#x} occurs more than once"
            )));
        }

        match identifier {
            //= https://www.rfc-editor.org/rfc/rfc9297#section-2.1.1
            //# If the SETTINGS_H3_DATAGRAM setting is received with a value
            //# that is neither 0 nor 1, the receiver MUST terminate the
            //# connection with error H3_SETTINGS_ERROR.
            SETTING_H3_DATAGRAM => settings.datagrams = boolean(identifier, value)?,

            // RFC 9220 §3 gives this setting the semantics it has in HTTP/2,
            // where RFC 8441 §3 constrains the value -- "The value of the
            // parameter MUST be 0 or 1" -- but says of the direction this
            // server receives it in:
            //
            //= https://www.rfc-editor.org/rfc/rfc8441#section-3
            //# Receipt of this parameter by a server does not have any impact.
            //
            // So a client sending it at all is already sending something with
            // no meaning here, and a value outside {0, 1} is that same nothing
            // spelled wrong. Nothing in RFC 9114 §7.2.4 makes a malformed
            // *value* of an otherwise ignored setting a connection error, and
            // closing on one would drop tunnels over a field this server does
            // not read. It is logged and ignored.
            SETTING_ENABLE_CONNECT_PROTOCOL if value > 1 => tracing::debug!(
                value,
                "ignoring SETTINGS_ENABLE_CONNECT_PROTOCOL with a value other \
                 than 0 or 1, which has no meaning at a server"
            ),
            // Everything else is ignored: RFC 9114 §7.2.4 for an identifier
            // this server does not understand, §7.2.4.1 for a reserved one.
            _ => {}
        }
    }

    Ok(settings)
}

/// Reads a setting whose value the RFC restricts to 0 or 1.
fn boolean(identifier: u64, value: u64) -> Result<bool, Violation> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(settings_error(format!(
            "setting {identifier:#x} must be 0 or 1, not {other}"
        ))),
    }
}

/// A SETTINGS payload that ends in the middle of a pair.
///
/// H3_FRAME_ERROR rather than H3_SETTINGS_ERROR: this is a frame whose payload
/// does not hold the fields its length promised, which §7.1 answers for every
/// frame type alike, before any of §7.2.4's rules about *which* settings are
/// allowed can apply.
fn truncated_settings() -> Violation {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.1
    //# A frame payload that contains additional bytes after the identified
    //# fields or a frame payload that terminates before the end of the
    //# identified fields MUST be treated as a connection error of type
    //# H3_FRAME_ERROR.
    Violation::connection(Code::H3_FRAME_ERROR, "the SETTINGS payload ends mid-pair")
}

/// A SETTINGS payload whose identifiers or values break RFC 9114 §7.2.4's
/// rules, as opposed to its layout.
fn settings_error(detail: impl Into<std::borrow::Cow<'static, str>>) -> Violation {
    Violation::connection(Code::H3_SETTINGS_ERROR, detail)
}

/// Writes a frame header: type and payload length.
pub fn put_header(out: &mut BytesMut, kind: u64, length: u64) {
    put_varint(out, kind);
    put_varint(out, length);
}

/// The SETTINGS frame this server sends, payload only.
///
/// The two that Surge validates and disconnects without --
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL` and `SETTINGS_H3_DATAGRAM` -- are the
/// reason this server exists at all. The two QPACK settings are sent as zeroes
/// on purpose: they are what makes a static-table-only decoder correct rather
/// than merely adequate (see [`super::qpack`]), and they bind the peer's
/// encoder: RFC 9204 §3.2.3 for the dynamic table capacity, §2.1.2 for the
/// number of streams it may let block.
///
/// Not public: [`super::connection`] is the one caller there will ever be, since
/// what a server sends in its SETTINGS is this layer's own business.
pub(super) fn settings_payload() -> BytesMut {
    /// One reserved identifier of the form 0x1f * N + 0x21, which RFC 9114
    /// §7.2.4.1 says endpoints SHOULD send so that peers keep exercising the
    /// rule that unknown identifiers are ignored.
    ///
    /// N is arbitrary: every value of it names a reserved identifier, and the
    /// test client and `it_settings` pick different ones only so that the three
    /// greases can be told apart in a packet capture.
    const GREASE: u64 = 0x1f * 8 + 0x21;

    let mut payload = BytesMut::new();
    for (identifier, value) in [
        (SETTING_QPACK_MAX_TABLE_CAPACITY, 0),
        (SETTING_QPACK_BLOCKED_STREAMS, 0),
        (SETTING_MAX_FIELD_SECTION_SIZE, MAX_FIELD_SECTION_SIZE),
        (SETTING_ENABLE_CONNECT_PROTOCOL, 1),
        (SETTING_H3_DATAGRAM, 1),
        (GREASE, 0),
    ] {
        put_varint(&mut payload, identifier);
        put_varint(&mut payload, value);
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(pairs: &[(u64, u64)]) -> Vec<u8> {
        let mut payload = BytesMut::new();
        for (identifier, value) in pairs {
            put_varint(&mut payload, *identifier);
            put_varint(&mut payload, *value);
        }
        payload.to_vec()
    }

    #[test]
    fn the_advertised_settings_are_the_ones_surge_checks_for() {
        let payload = settings_payload();
        let mut rest = &payload[..];
        let mut found = std::collections::HashMap::new();

        while !rest.is_empty() {
            let (identifier, used) = peek_varint(rest).expect("identifier");
            rest = &rest[used..];
            let (value, used) = peek_varint(rest).expect("value");
            rest = &rest[used..];
            assert!(found.insert(identifier, value).is_none(), "duplicate");
        }

        assert_eq!(found.get(&SETTING_ENABLE_CONNECT_PROTOCOL), Some(&1));
        assert_eq!(found.get(&SETTING_H3_DATAGRAM), Some(&1));
        assert_eq!(
            found.get(&SETTING_MAX_FIELD_SECTION_SIZE),
            Some(&MAX_FIELD_SECTION_SIZE)
        );
        assert_eq!(found.get(&SETTING_QPACK_MAX_TABLE_CAPACITY), Some(&0));
        assert_eq!(found.get(&SETTING_QPACK_BLOCKED_STREAMS), Some(&0));
    }

    /// What this server sends must survive its own parser, reserved-identifier
    /// and duplicate rules included.
    #[test]
    fn our_own_settings_parse() {
        let parsed = parse_settings(&settings_payload()).expect("parses");
        assert!(parsed.datagrams);
    }

    #[test]
    fn a_peer_that_enables_datagrams_is_recognised() {
        assert!(
            parse_settings(&settings(&[(SETTING_H3_DATAGRAM, 1)]))
                .expect("parses")
                .datagrams
        );
        assert!(
            !parse_settings(&settings(&[(SETTING_H3_DATAGRAM, 0)]))
                .expect("parses")
                .datagrams
        );
        // Absent means absent: RFC 9297 §2.1.1 defaults it to off.
        assert!(!parse_settings(&[]).expect("parses").datagrams);
    }

    #[test]
    fn unknown_and_grease_settings_are_ignored() {
        let parsed = parse_settings(&settings(&[
            (0x1f * 3 + 0x21, 0),
            (0x4242, 99),
            (SETTING_H3_DATAGRAM, 1),
        ]))
        .expect("parses");
        assert!(parsed.datagrams);
    }

    #[test]
    fn reserved_http2_setting_identifiers_are_refused() {
        for identifier in RESERVED_HTTP2_SETTINGS {
            let error = parse_settings(&settings(&[(identifier, 0)])).expect_err("refused");
            assert_eq!(error.code(), Code::H3_SETTINGS_ERROR);
            assert!(error.is_connection_error());
        }
    }

    #[test]
    fn a_repeated_setting_identifier_is_refused() {
        let error = parse_settings(&settings(&[
            (SETTING_H3_DATAGRAM, 1),
            (SETTING_H3_DATAGRAM, 1),
        ]))
        .expect_err("refused");
        assert_eq!(error.code(), Code::H3_SETTINGS_ERROR);
    }

    /// RFC 9297 §2.1.1 states the H3_DATAGRAM rule as a MUST on the receiver,
    /// so a value outside {0, 1} ends the connection.
    #[test]
    fn a_datagram_setting_with_another_value_is_refused() {
        let error = parse_settings(&settings(&[(SETTING_H3_DATAGRAM, 2)])).expect_err("refused");
        assert_eq!(error.code(), Code::H3_SETTINGS_ERROR);
        assert!(error.is_connection_error());

        // A setting whose value this server does not constrain is untouched.
        assert!(parse_settings(&settings(&[(SETTING_MAX_FIELD_SECTION_SIZE, 1 << 40)])).is_ok());
    }

    /// RFC 8441 §3: "Receipt of this parameter by a server does not have any
    /// impact." A value it never defined is ignored with the rest of it, rather
    /// than costing the peer its tunnels.
    #[test]
    fn enable_connect_protocol_is_ignored_whatever_its_value_is() {
        for value in [0, 1, 2, crate::datagram::VARINT_MAX] {
            let parsed = parse_settings(&settings(&[
                (SETTING_ENABLE_CONNECT_PROTOCOL, value),
                (SETTING_H3_DATAGRAM, 1),
            ]))
            .unwrap_or_else(|error| panic!("value {value} must be ignored, got {error}"));
            assert!(parsed.datagrams, "the rest of the frame must still apply");
        }
    }

    /// RFC 9114 §7.1 answers a payload that ends before its fields do, whatever
    /// the frame type; §7.2.4's H3_SETTINGS_ERROR is for what the settings say,
    /// not for a frame that was cut short.
    #[test]
    fn a_settings_payload_that_ends_mid_pair_is_a_frame_error() {
        let mut payload = settings(&[(SETTING_H3_DATAGRAM, 1)]);
        payload.pop();
        let error = parse_settings(&payload).expect_err("refused");
        assert_eq!(error.code(), Code::H3_FRAME_ERROR);
        assert!(error.is_connection_error());

        // An identifier with no value at all is the same fault.
        let error = parse_settings(&[0x33]).expect_err("refused");
        assert_eq!(error.code(), Code::H3_FRAME_ERROR);
    }

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

    /// A request stream's decoder with a budget of its own, for the tests that
    /// are not about the budget.
    fn fresh_decoder() -> FrameDecoder {
        FrameDecoder::new(StreamKind::Request, Arc::new(BufferBudget::default()))
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

        assert!(matches!(&items[0], Item::Data(chunk) if &chunk[..] == b"abc"));
        assert!(matches!(&items[1], Item::Frame(Frame::Headers(block)) if &block[..] == b"block"));
        assert!(matches!(&items[2], Item::Data(chunk) if &chunk[..] == b"de"));
        assert_eq!(items.len(), 3);
    }

    /// RFC 9114 §9: unknown types, grease included, are skipped by their
    /// declared length and never buffered -- but their arrival is announced,
    /// because a reader applying §6.2.1's "first frame" rule has to see them.
    #[test]
    fn unknown_frame_types_are_skipped() {
        for kind in [0x21u64, 0x1f * 7 + 0x21, 0x4242] {
            let mut wire = frame(kind, b"whatever this is");
            wire.extend_from_slice(&frame(DATA, b"body"));

            let items = decode_bytewise(&wire).expect("decodes");
            let (skipped, body) = items.split_first().expect("at least the skipped frame");

            assert!(
                matches!(skipped, Item::Skipped { kind: skipped } if *skipped == kind),
                "grease type {kind:#x} must be announced once, got {items:?}"
            );
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
        assert!(matches!(
            decoder.next_item().expect("decodes"),
            Some(Item::Skipped { kind: 0x21 })
        ));
        assert!(decoder.at_frame_boundary());
    }

    /// An empty frame of either kind must not stall the decoder waiting for a
    /// payload that will never come -- and must still be reported, so that a
    /// caller can tell "a DATA frame arrived" from "nothing arrived".
    #[test]
    fn zero_length_frames_do_not_stall_the_decoder() {
        let mut wire = frame(DATA, b"");
        wire.extend_from_slice(&frame(0x21, b""));
        wire.extend_from_slice(&frame(HEADERS, b""));

        let items = decode_bytewise(&wire).expect("decodes");
        assert!(
            matches!(
                &items[..],
                [
                    Item::Data(empty),
                    Item::Skipped { kind: 0x21 },
                    Item::Frame(Frame::Headers(block))
                ] if empty.is_empty() && block.is_empty()
            ),
            "got {items:?}"
        );
    }

    /// RFC 9114 §7.2.8: the types HTTP/2 used and HTTP/3 does not are a
    /// connection error, not something to skip.
    #[test]
    fn reserved_http2_frame_types_end_the_connection() {
        for kind in RESERVED_HTTP2_TYPES {
            let Err(Error::Protocol(violation)) = begin(StreamKind::Control, kind, 0) else {
                panic!("frame type {kind:#x} must be refused")
            };
            assert_eq!(violation.code(), Code::H3_FRAME_UNEXPECTED);
            assert!(violation.is_connection_error());
        }
    }

    #[test]
    fn a_frame_past_the_buffer_limit_is_refused_before_it_is_allocated() {
        let Err(Error::Protocol(violation)) =
            begin(StreamKind::Request, HEADERS, MAX_BUFFERED_FRAME + 1)
        else {
            panic!("an oversized frame must be refused")
        };
        assert_eq!(violation.code(), Code::H3_EXCESSIVE_LOAD);
        assert!(
            !violation.is_connection_error(),
            "one oversized frame is a stream problem, not a connection one"
        );

        assert!(begin(StreamKind::Request, HEADERS, MAX_BUFFERED_FRAME).is_ok());
        // DATA is never buffered, so no declared length can be too large.
        assert!(begin(StreamKind::Request, DATA, crate::datagram::VARINT_MAX).is_ok());
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
                    let Err(Error::Protocol(violation)) = begin(stream, *kind, length) else {
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
                    misplaced(stream, *kind).is_none(),
                    "{stream:?}: frame type {kind:#x} belongs here"
                );
            }
        }
    }

    /// The transition the tunnels make: a stream that accepted a field section
    /// while its request was arriving refuses one afterwards.
    #[test]
    fn answering_the_connect_narrows_what_the_stream_may_carry() {
        let mut decoder = fresh_decoder();
        assert!(matches!(
            begin(decoder.stream, HEADERS, 200),
            Ok(State::Buffering { .. })
        ));

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

    /// D77: the connection's budget is charged for what a frame *announces*,
    /// and given back on both of the ways a frame stops being held -- it
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
        assert!(matches!(
            decoder.next_item().expect("decodes"),
            Some(Item::Frame(Frame::Headers(block))) if block.len() == 1000
        ));
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
            assert!(
                matches!(outcome, Ok(None)),
                "stream {stream} is within the budget"
            );
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

    /// RFC 9114 §7.1: a stream that ends inside a frame is an error, and one
    /// that ends between them is the ordinary end of a request body.
    #[test]
    fn a_frame_boundary_is_where_a_stream_may_end() {
        let mut decoder = fresh_decoder();
        assert!(decoder.at_frame_boundary());

        decoder.push(Bytes::from(frame(DATA, b"abcd")));
        assert!(matches!(
            decoder.next_item().expect("decodes"),
            Some(Item::Data(_))
        ));
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

    /// The parser is fed bytes from an unauthenticated peer, so it may reject
    /// anything but must never panic.
    #[test]
    fn arbitrary_bytes_never_panic_the_settings_parser() {
        proptest::proptest!(|(payload: Vec<u8>)| {
            let _ = parse_settings(&payload);
        });
    }
}
