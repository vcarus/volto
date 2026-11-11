//! HTTP/3 (RFC 9114) for a proxy, implemented in the tree.
//!
//! This is the server half of HTTP/3 only. It accepts request streams, decodes
//! a request, sends a response, moves body bytes, and hands each inbound HTTP
//! Datagram to the request stream it names. There is no client, no server
//! push, no WebTransport, and no QPACK dynamic table. Each of them is either
//! unreachable for a CONNECT proxy or refused as a protocol violation, so
//! leaving them out costs no conformance. The reasons for an in-tree layer are
//! in D75.
//!
//! # Layout
//!
//! * [`error`]: the RFC 9114 §8.1 codes, and the two error types the rest of
//!   the crate sees.
//! * [`huffman`]: RFC 7541 Appendix B, decoding only.
//! * [`qpack`]: RFC 9204 field sections against the static table.
//! * [`frame`]: RFC 9114 §7 framing, incremental and copy-free for DATA, with
//!   one bounded read-ahead on a tunnel ([`frame::READ_AHEAD_CHUNKS`]).
//! * [`message`]: what a request and a response are made of: a status, a
//!   method, field lines.
//! * [`connection`]: the connection: SETTINGS, the control stream, GOAWAY,
//!   and inbound HTTP Datagram routing (RFC 9297).
//! * [`stream`]: one request stream, from its HEADERS to its last byte.
//!
//! The integration suite's client is built on these same modules
//! (`tests/common/h3client.rs`). Only the `interop` CI job, which drives the
//! server with independent clients, checks that this server reads the wire
//! the way a peer does.
//!
//! # Design rules
//!
//! * **Nothing is generic over the QUIC layer.** The types are `quinn`'s.
//!   `quinn::SendStream` and `quinn::RecvStream` are held directly, so their
//!   `Drop` behaviour (a finish on the send side, `STOP_SENDING` on the receive
//!   side) is what `tunnel::tcp` reasons about.
//! * **The peer's state is shared, not polled.** One background task per
//!   connection reads every unidirectional stream and every datagram, so the
//!   peer's SETTINGS take effect when they arrive rather than the next time a
//!   request is accepted.
//! * **A connection error is a `quinn::Connection::close`.** RFC 9114 §8 makes
//!   an HTTP/3 connection error a QUIC CONNECTION_CLOSE carrying the HTTP/3
//!   code, which is what that call sends. Every operation still in flight then
//!   fails on its own.

pub mod connection;
pub mod error;
pub mod frame;
pub mod huffman;
pub mod message;
pub mod qpack;
pub mod stream;

use error::Code;

// This rule has no single owner, so it is quoted here once. `frame` skips a
// frame type it does not know and ignores a SETTINGS identifier it has never
// seen. `stream` and `connection` pass over the resulting `Item::Skipped`.
//
//= https://www.rfc-editor.org/rfc/rfc9114#section-9
//# Implementations MUST ignore unknown or unsupported values in all
//# extensible protocol elements.

/// Longest a QUIC varint can be, in bytes (RFC 9000 §16), for sizing scratch
/// buffers. This is a length. The largest representable value is
/// [`crate::datagram::VARINT_MAX`].
const VARINT_MAX_LEN: usize = 8;

/// Largest field section this server will decode, in bytes.
///
/// Advertised as `SETTINGS_MAX_FIELD_SECTION_SIZE`, so a client that respects
/// SETTINGS never sends more, and enforced on receipt so one that does not gets
/// no further than this. A CONNECT request's fields are a couple of hundred
/// bytes, so this leaves three hundred times the room a legitimate request
/// needs.
///
/// The unit is the size formula of RFC 9114 §4.2.2: name plus value plus 32
/// bytes for each field.
///
/// # What a section costs once it is decoded, and for how long
///
/// This bounds what is *decoded*. [`HEADERS_BUFFER_BUDGET`] bounds what is
/// being decoded at one moment, in encoded bytes. Neither bounds what the
/// decoded product costs after that, and this constant is the only parameter
/// in that cost.
///
/// A decoded section is a `message::Fields`: a vector of 32-byte entries with an
/// allocation per name. The 32 bytes a field of §4.2.2 model that per-field
/// cost, so a section at this limit costs about 65 KiB once decoded. The cost
/// is about the same whichever way the peer spends the limit
/// (`tests/it_bounds.rs::a_tunnel_holds_its_requests_field_section_for_its_whole_life`).
///
/// It is held for as long as the request is: `crate::conn::handle_request` keeps
/// the decoded [`message::Request`] for the whole life of the tunnel it opened,
/// not merely until the target has been named. So the multiplier is
/// `max_targets_per_conn` times `max_connections`: about 19 MiB per connection
/// and 4.8 GiB across a server at the shipped defaults. While requests are
/// being refused rather than served, the multiplier is `max_streams_bidi`
/// instead, and each refusal write is bounded by one `max_idle_timeout`.
pub const MAX_FIELD_SECTION_SIZE: u64 = 64 * 1024;

/// Most encoded frame payload one connection may hold buffered at once, in
/// bytes (D77).
///
/// [`MAX_FIELD_SECTION_SIZE`] bounds one frame. This bounds their sum, and the
/// two are reached by different peers. A client held to the per-frame bound may
/// still open every request stream its transport parameters allow (1024 by
/// default), announce a 64 KiB HEADERS frame on each and stop one byte short
/// of finishing any of them. That breaks no rule on any single stream, and the
/// frames must be held because they cannot be acted on piecewise. Without this
/// bound that is 64 MiB of a connection's memory, from a peer that has not
/// authenticated, for as long as the transport keeps the connection alive.
/// Multiplied by `limits.max_connections` it is the whole of the machine. D76
/// bounds how long one stream may wait; this bounds how much waiting costs.
///
/// A megabyte is sixteen frames of the largest size this server will buffer at
/// all. A CONNECT request carrying Basic credentials is under 300 bytes, so all
/// 1024 request streams the transport allows could be mid-HEADERS at once and
/// still use a tenth of this.
///
/// What is counted is the announced length of the frames being buffered *at one
/// moment*. Sixteen concurrent field sections of the largest advertised size
/// fill it and the seventeenth does not fit, whether or not every one of them
/// is completed a moment later. A peer that reaches it loses that one request,
/// which is answered with 431 and stopped (`frame::BufferBudget::charge`). The
/// connection and every tunnel on it carry on. The value bounds memory at a
/// moment, not a rate, so it is a constant here and not a setting in
/// `[limits]`.
///
/// The peer's control stream is not counted here;
/// `frame::BufferBudget::unshared` says why.
///
/// The unit is encoded octets as they arrived, the same count
/// `frame::MAX_BUFFERED_FRAME` applies per frame. It is not RFC 9114 §4.2.2's
/// field-section size, which is what [`MAX_FIELD_SECTION_SIZE`] measures.
pub const HEADERS_BUFFER_BUDGET: usize = 1024 * 1024;

/// An HTTP/3 error code as the QUIC application error code that carries it.
///
/// RFC 9114 §8 defines the two to be the same number; every registered code is
/// far below the varint maximum, so the conversion cannot fail for anything
/// this server sends.
///
/// Public because the suite's client resets streams with the same codes.
pub fn varint(code: Code) -> quinn::VarInt {
    quinn::VarInt::from_u64(code.value()).unwrap_or(quinn::VarInt::MAX)
}
