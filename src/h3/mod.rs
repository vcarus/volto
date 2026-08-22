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
//! It replaces the `h3` and `h3-quinn` crates, which remain in the tree as test
//! dependencies so the integration suite drives this server with an
//! independently written client. That is the point of the exercise: the tests
//! assert on-wire behaviour, and the client asserting it shares no code with the
//! server producing it.
//!
//! # What holds it together
//!
//! * **Nothing is generic over the QUIC layer.** `h3` is generic so that any
//!   QUIC stack can back it; this server has exactly one, so the types are
//!   `quinn`'s and the indirection is gone. `quinn::SendStream` and
//!   `quinn::RecvStream` are held directly, which also means their `Drop`
//!   behaviour -- a finish on the send side, `STOP_SENDING` on the receive side
//!   -- is what `tunnel::tcp` reasons about, unmediated.
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
fn varint(code: Code) -> quinn::VarInt {
    quinn::VarInt::from_u64(code.value()).unwrap_or(quinn::VarInt::MAX)
}
