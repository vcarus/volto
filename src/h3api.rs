//! The facade over the HTTP/3 layer.
//!
//! Everything the rest of the crate needs from HTTP/3 is named here, and only
//! here: `conn`, `quic` and the tunnels use `bytes` and `quinn` types plus the
//! handful of names below. It is the list of what a proxy asks of HTTP/3, and
//! it is short.
//!
//! The vocabulary of an HTTP message ([`Request`], [`Status`], [`Fields`]) is
//! [`crate::h3::message`]'s, re-exported unwrapped. Nothing outside
//! [`crate::h3`] reaches into it, so this module is the whole of what the crate
//! may assume about HTTP/3.
//!
//! Inbound HTTP Datagrams (RFC 9297) are named here too, because the routing
//! they need is *per request stream*: a datagram carries the Quarter Stream ID
//! of the stream it belongs to, so the layer that owns request streams is the
//! layer that can hand it to the right one. A session claims its share with
//! [`Stream::datagrams`] and holds it for as long as it holds the
//! [`DatagramReceiver`] (D79). Sending is the one half that stays outside:
//! `tunnel::udp` writes datagrams straight onto the `quinn::Connection` it
//! already holds for the send-buffer and datagram-size questions it asks.
//!
//! [`DATA_HEADER_ROOM`] is the one number about frame layout a caller needs:
//! the TCP relay leaves that many bytes in front of each read, and
//! [`Writer::send_data_in_place`] writes the DATA frame header there. What the
//! header holds stays inside [`crate::h3`].

pub use crate::h3::MAX_FIELD_SECTION_SIZE;
pub use crate::h3::connection::{Connection, DatagramReceiver, PeerSettings};
pub use crate::h3::error::{Code, ConnectionError, StreamError};
pub use crate::h3::frame::{DATA_HEADER_ROOM, READ_AHEAD_CHUNKS};
pub use crate::h3::message::{FieldValue, Fields, Method, Request, Status};
pub use crate::h3::stream::{Reader, Resolver, RespondError, Stream, Writer};

/// Connection close code used when a peer exhausts its authentication attempts.
///
/// It closes the whole connection rather than a stream. The code is
/// `H3_REQUEST_REJECTED` (0x10b), which is our own choice for this close, so
/// the peer reads a registered HTTP/3 code in the CONNECTION_CLOSE frame.
pub const AUTH_FAILURE_LIMIT_CODE: Code = Code::H3_REQUEST_REJECTED;

/// The code of the peer's RESET_STREAM or STOP_SENDING, if this error is one
/// of the two.
///
/// Both arrive as the same `RemoteTerminate`: a read meets the reset, and a
/// write or `Writer::stopped` meets the STOP_SENDING. The TCP tunnel relies on
/// the second when it reports that the client stopped reading.
pub fn peer_reset_code(error: &StreamError) -> Option<u64> {
    match error {
        StreamError::RemoteTerminate { code, .. } => Some(code.value()),
        _ => None,
    }
}

/// For `quic`'s tests of how a connection's end is graded, which build a
/// local close.
#[cfg(test)]
pub(crate) use crate::h3::error::Violation;

/// For the TCP tunnel's tests, which drive its two pumps over a live request
/// stream.
#[cfg(test)]
pub(crate) use crate::h3::stream::tunnel_halves;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_reset_is_told_apart_from_every_other_failure() {
        assert_eq!(
            peer_reset_code(&StreamError::RemoteTerminate {
                code: Code::H3_CONNECT_ERROR
            }),
            Some(0x10f)
        );
        assert_eq!(
            peer_reset_code(&StreamError::Connection(ConnectionError::Timeout)),
            None
        );
    }

    /// The close code is a number the peer reads, so its value on the wire is
    /// pinned here rather than left to the name it is defined by.
    #[test]
    fn the_auth_failure_close_code_is_the_one_documented() {
        assert_eq!(AUTH_FAILURE_LIMIT_CODE.value(), 0x10b);
    }
}
