//! HTTP/3 (RFC 9114) for a proxy, implemented in the tree.
//!
//! This is the server half of HTTP/3 and nothing else: it accepts request
//! streams, decodes a request, sends a response, moves body bytes, and hands
//! each inbound HTTP Datagram to the request stream it names. There is
//! no client, no server push, no WebTransport, and no QPACK dynamic table --
//! every one of them is either unreachable for a CONNECT proxy or refused as a
//! protocol violation, so leaving them out costs no conformance.
//!
//! # Layout
//!
//! * [`error`] — the RFC 9114 §8.1 codes, and the two error types the rest of
//!   the crate sees.
//! * [`huffman`] — RFC 7541 Appendix B, decoding only.
//! * [`qpack`] — RFC 9204 field sections against the static table.
//! * [`frame`] — RFC 9114 §7 framing, incremental and copy-free for DATA.
//! * [`message`] — what a request and a response are made of: a status, a
//!   method, field lines.
//! * [`connection`] — the connection: SETTINGS, the control stream, GOAWAY,
//!   and inbound HTTP Datagram routing (RFC 9297).
//! * [`stream`] — one request stream, from its HEADERS to its last byte.
//!
//! # Why it exists
//!
//! It replaces the `h3` and `h3-quinn` crates, which are no longer in the tree
//! at all. They were pinned to a git revision because the published releases
//! carried bugs a proxy cannot live with, and being generic over any QUIC stack
//! cost this server -- which has exactly one -- more than it bought. What a
//! proxy asks of HTTP/3 turned out to be small enough to state in full, which is
//! what the modules above do.
//!
//! The integration suite's client is built on these same modules
//! (`tests/common/h3client.rs`), so the check that this server has not
//! misunderstood the wire in a way a peer would notice belongs entirely to the
//! `interop` CI job, which drives a real server with Go's masque-go.
//!
//! # What holds it together
//!
//! * **Nothing is generic over the QUIC layer.** The types are `quinn`'s, and
//!   the indirection a library needs in order to back any stack is gone.
//!   `quinn::SendStream` and `quinn::RecvStream` are held directly, which also
//!   means their `Drop` behaviour -- a finish on the send side, `STOP_SENDING`
//!   on the receive side -- is what `tunnel::tcp` reasons about, unmediated.
//! * **The peer's state is shared, not polled.** One background task per
//!   connection reads every unidirectional stream and every datagram, so the
//!   peer's SETTINGS take effect the moment they arrive rather than the next
//!   time a request is accepted.
//! * **A connection error is a `quinn::Connection::close`.** RFC 9114 §8 makes
//!   an HTTP/3 connection error a QUIC CONNECTION_CLOSE carrying the HTTP/3
//!   code, which is exactly what that call sends; every operation still in
//!   flight then fails on its own.

pub mod connection;
pub mod error;
pub mod frame;
pub mod huffman;
pub mod message;
pub mod qpack;
pub mod stream;

use error::Code;

// The one rule with no single owner among the modules above, so it is quoted
// here once and named rather than repeated at each place that obeys it: `frame`
// skips a frame type it does not know and ignores a SETTINGS identifier it has
// never seen, while `stream` and `connection` pass the `Item::Skipped` that
// produces straight over. The test client obeys the same rule for what this
// server sends.
//
//= https://www.rfc-editor.org/rfc/rfc9114#section-9
//# Implementations MUST ignore unknown or unsupported values in all
//# extensible protocol elements.

/// Longest a QUIC varint can be (RFC 9000 §16), for sizing scratch buffers.
const MAX_VARINT: usize = 8;

/// Largest field section this server will decode, in bytes.
///
/// Advertised as `SETTINGS_MAX_FIELD_SECTION_SIZE`, so a client that respects
/// SETTINGS never sends more, and enforced on receipt so one that does not gets
/// no further than this. A CONNECT request's fields are a couple of hundred
/// bytes, which leaves three hundred times the room anything legitimate needs.
///
/// The unit is the size formula of RFC 9114 §4.2.2: name plus value plus 32
/// bytes for each field.
///
/// # What a section costs once it is decoded, and for how long
///
/// This bounds what is *decoded*; [`HEADERS_BUFFER_BUDGET`] bounds what is being
/// decoded at one moment, in encoded bytes. Neither bounds what the decoded
/// product costs after that, so the arithmetic is worth stating here, since this
/// constant is the only knob in it.
///
/// A decoded section is a `message::Fields`: a vector of 32-byte entries with an
/// allocation per name. §4.2.2's 32 bytes a field exist to model exactly that
/// per-field cost, so a section at this limit costs about this much again once
/// decoded — measured at ~77 KiB for the widest conformant one, from a request
/// under 6 KiB on the wire
/// (`tests/it_bounds.rs::a_tunnel_holds_its_requests_field_section_for_its_whole_life`).
///
/// It is held for as long as the request is: `crate::conn::handle_request` keeps
/// the decoded [`message::Request`] for the whole life of the tunnel it opened,
/// not merely until the target has been named. So the multiplier is
/// `max_targets_per_conn` times `max_connections` — ~19 MiB per connection and
/// ~4.8 GiB across a server at the shipped defaults — with a further transient
/// while requests are being refused rather than served, where the multiplier is
/// `max_streams_bidi` instead and each refusal write is bounded by one
/// `max_idle_timeout`.
pub const MAX_FIELD_SECTION_SIZE: u64 = 64 * 1024;

/// Most encoded frame payload one connection may hold buffered at once, in
/// bytes (D77).
///
/// [`MAX_FIELD_SECTION_SIZE`] bounds one frame; this bounds their sum, and the
/// two are reached by different peers. A client held to the per-frame bound may
/// still open every request stream its transport parameters allow -- 1024 by
/// default -- announce a 64 KiB HEADERS frame on each and stop one byte short
/// of finishing any of them. Nothing in that is a rule broken on any single
/// stream, and the frames are held because they cannot be acted on piecewise:
/// 64 MiB of a connection's memory, from a peer that has not authenticated, for
/// as long as the transport is willing to call it alive, and available again
/// the moment the streams are reset. Multiplied by `limits.max_connections` it
/// is the whole of the machine. D76 bounds how long one stream may wait; this
/// bounds how much waiting costs.
///
/// A megabyte is sixteen frames of the largest size this server will buffer at
/// all, and some four thousand of the size a real one is -- a CONNECT request
/// carrying Basic credentials is under 300 bytes, so all 1024 request streams
/// the transport allows could be mid-HEADERS at once and still be using a tenth
/// of this.
///
/// The exact boundary is worth stating, because it is not "a client that
/// finishes what it starts": what is counted is the announced length of the
/// frames being buffered *at one moment*, so sixteen concurrent field sections
/// of the largest advertised size fill it and the seventeenth does not fit --
/// whether or not every one of them is completed a moment later. A peer that
/// reaches it loses that one request, which is answered with 431 and stopped
/// (`frame::BufferBudget::charge`); the connection and every tunnel on it carry
/// on. Bounding a moment rather than a rate is what makes the value a constant
/// here rather than a knob in `[limits]`: it is a ceiling on memory, and the
/// machine's is not configurable either.
///
/// The peer's control stream is not counted here. There is one of it per
/// connection and it buffers one frame at a time, so `frame::MAX_BUFFERED_FRAME`
/// bounds it on its own -- and a peer that had filled this budget with request
/// streams must not thereby have its own SETTINGS or GOAWAY refused, since
/// nothing on that stream can be refused stream by stream.
///
/// The unit is encoded octets as they arrived, the same count
/// `frame::MAX_BUFFERED_FRAME` applies per frame -- not RFC 9114 §4.2.2's
/// field-section size, which is what [`MAX_FIELD_SECTION_SIZE`] measures.
pub const HEADERS_BUFFER_BUDGET: usize = 1024 * 1024;

/// An HTTP/3 error code as the QUIC application error code that carries it.
///
/// RFC 9114 §8 defines the two to be the same number; every registered code is
/// far below the varint maximum, so the conversion cannot fail for anything
/// this server sends.
///
/// Public because the suite's client resets streams with the same codes and had
/// grown a byte-identical copy of this.
pub fn varint(code: Code) -> quinn::VarInt {
    quinn::VarInt::from_u64(code.value()).unwrap_or(quinn::VarInt::MAX)
}
