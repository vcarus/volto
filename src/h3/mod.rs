//! HTTP/3 (RFC 9114) for a proxy, implemented in the tree.
//!
//! This is the server half of HTTP/3 and nothing else: it accepts request
//! streams, decodes a request, sends a response, and moves body bytes. There is
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
//! * [`connection`] — the connection: SETTINGS, the control stream, GOAWAY.
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
//!   connection reads every unidirectional stream, so the peer's SETTINGS take
//!   effect the moment they arrive rather than the next time a request is
//!   accepted.
//! * **A connection error is a `quinn::Connection::close`.** RFC 9114 §8 makes
//!   an HTTP/3 connection error a QUIC CONNECTION_CLOSE carrying the HTTP/3
//!   code, which is exactly what that call sends; every operation still in
//!   flight then fails on its own.

pub mod connection;
pub mod error;
pub mod frame;
pub mod huffman;
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
pub const MAX_FIELD_SECTION_SIZE: u64 = 64 * 1024;

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
