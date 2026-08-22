//! The public face of the HTTP/3 layer.
//!
//! Everything the rest of the crate needs from HTTP/3 is named here, and only
//! here: `conn`, `quic` and the tunnels use `http`, `bytes` and `quinn` types
//! plus the handful of wrappers below. That boundary began as insulation from
//! the `h3` crate; it survives the move to [`crate::h3`] because it is worth
//! having on its own terms -- it is the list of what a proxy actually asks of
//! HTTP/3, and it is short.
//!
//! Types that are not HTTP/3-specific -- `http::Request`, `http::StatusCode`,
//! `bytes::Bytes` -- are passed through unchanged; isolating those would buy
//! nothing.
//!
//! One deliberate exception: HTTP Datagrams (RFC 9297) are sent and received
//! straight through `quinn::Connection`, not through this module. They are a
//! QUIC transport facility rather than an HTTP/3 one, and the routing they need
//! is per-session rather than per-connection, so the datagram task in `conn.rs`
//! owns them end to end.

use bytes::Bytes;
use http::Request;

pub use crate::h3::connection::Connection;
pub use crate::h3::error::{Code, ConnectionError, StreamError};
pub use crate::h3::stream::{Reader, Resolver, Stream, Writer};
pub use crate::h3::MAX_FIELD_SECTION_SIZE;

use crate::h3::stream::Protocol;

/// The buffer type carried over HTTP/3 streams.
pub type Buffer = Bytes;

/// No error -- a clean teardown.
pub const NO_ERROR: Code = Code::H3_NO_ERROR;

/// The proxy's connection to the target failed or was reset (RFC 9114 §8.1).
pub const CONNECT_ERROR: Code = Code::H3_CONNECT_ERROR;

/// The peer sent something malformed (RFC 9114 §8.1).
pub const MESSAGE_ERROR: Code = Code::H3_MESSAGE_ERROR;

/// The request or its response is cancelled (RFC 9114 §8.1).
///
/// The closest registered code for a response body this server gives up on
/// because the peer stopped reading it: nothing was malformed and nothing failed
/// upstream, the transfer simply cannot be completed.
pub const REQUEST_CANCELLED: Code = Code::H3_REQUEST_CANCELLED;

/// A datagram or capsule could not be parsed (RFC 9297 §5.2).
///
/// The registry entry for 0x33 is literally "Datagram or Capsule Protocol parse
/// error", which is more precise than H3_MESSAGE_ERROR for anything that went
/// wrong inside the payload rather than in the HTTP message itself.
pub const DATAGRAM_ERROR: Code = Code::H3_DATAGRAM_ERROR;

/// The same code as a QUIC application error, for closing the whole connection.
///
/// RFC 9297 §2.1 states two receiver obligations as *connection* errors of type
/// H3_DATAGRAM_ERROR, which a stream reset cannot express. Derived from
/// [`DATAGRAM_ERROR`] so the two cannot drift apart.
pub const DATAGRAM_ERROR_CLOSE: quinn::VarInt =
    quinn::VarInt::from_u32(DATAGRAM_ERROR.value() as u32);

/// Connection close code used when a peer exhausts its authentication attempts.
///
/// A QUIC application error code rather than an HTTP/3 one, because it closes the
/// whole connection rather than a stream. `H3_REQUEST_REJECTED`'s value is reused
/// so the peer sees something meaningful in the CONNECTION_CLOSE frame.
pub const AUTH_FAILURE_LIMIT_CODE: quinn::VarInt = quinn::VarInt::from_u32(0x10b);

/// The `:protocol` token of RFC 9298's CONNECT-UDP.
const CONNECT_UDP: &str = "connect-udp";

/// The value of the `:protocol` pseudo-header, classified.
///
/// [`ConnectProtocol::Unsupported`] borrows the token from the request, so the
/// name that reaches the log and the 501 is the one the client actually sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectProtocol<'a> {
    /// No `:protocol` pseudo-header: a classic CONNECT request (RFC 9114 §4.4).
    Absent,
    /// `connect-udp` -- a UDP tunnel (RFC 9298).
    ConnectUdp,
    /// A protocol this proxy does not implement. The payload is the wire name.
    Unsupported(&'a str),
}

/// Reads the `:protocol` pseudo-header of a request.
pub fn connect_protocol(req: &Request<()>) -> ConnectProtocol<'_> {
    match req.extensions().get::<Protocol>() {
        None => ConnectProtocol::Absent,
        Some(protocol) if protocol.as_str() == CONNECT_UDP => ConnectProtocol::ConnectUdp,
        Some(protocol) => ConnectProtocol::Unsupported(protocol.as_str()),
    }
}

/// The reset code the peer used, if this error is a peer-initiated reset.
pub fn peer_reset_code(error: &StreamError) -> Option<u64> {
    match error {
        StreamError::RemoteTerminate { code, .. } => Some(code.value()),
        _ => None,
    }
}

/// How a connection ended, when it ended with an error not worth a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenignClose {
    /// The peer went silent and the idle timeout expired.
    Idle,
    /// The peer closed the connection cleanly, without an error code.
    PeerClosed,
}

/// Classifies a connection-level error that is an ordinary goodbye rather than a
/// failure, or `None` if it deserves a warning.
///
/// The judgement is made on the error *value* on purpose. The obvious
/// alternative — asking `quinn::Connection::close_reason()` afterwards — cannot
/// work: dropping the HTTP/3 connection closes the QUIC connection with
/// H3_NO_ERROR, and quinn's close path unconditionally overwrites whatever
/// reason was stored with `LocallyClosed`. By the time a caller could ask, the
/// real reason is gone. An error value, by contrast, is immutable and independent
/// of drop order.
pub fn benign_close(error: &ConnectionError) -> Option<BenignClose> {
    match error {
        // The QUIC idle timeout, and nothing else. Clients that abandon a
        // connection without a CONNECTION_CLOSE — Surge does this on a network
        // switch or app exit — all end up here.
        ConnectionError::Timeout => Some(BenignClose::Idle),

        // 0x0 is the application error code Surge actually sends when it closes
        // a connection cleanly; H3_NO_ERROR (0x100) is what RFC 9114 §8.1
        // defines for the same intent. Both mean the peer simply left. Any other
        // code is the peer reporting a problem and stays a warning.
        ConnectionError::ApplicationClose { code } if code.value() == 0 || *code == NO_ERROR => {
            Some(BenignClose::PeerClosed)
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    fn request_with_protocol(protocol: Option<&str>) -> Request<()> {
        let mut req = Request::builder()
            .method(Method::CONNECT)
            .uri("https://example.com/")
            .body(())
            .expect("request");
        if let Some(protocol) = protocol {
            req.extensions_mut().insert(Protocol::new(protocol));
        }
        req
    }

    #[test]
    fn the_protocol_pseudo_header_is_classified() {
        assert_eq!(
            connect_protocol(&request_with_protocol(None)),
            ConnectProtocol::Absent
        );
        assert_eq!(
            connect_protocol(&request_with_protocol(Some("connect-udp"))),
            ConnectProtocol::ConnectUdp
        );
        // The wire name survives, which is what makes a truthful 501 possible.
        assert_eq!(
            connect_protocol(&request_with_protocol(Some("connect-ip"))),
            ConnectProtocol::Unsupported("connect-ip")
        );
        assert_eq!(
            connect_protocol(&request_with_protocol(Some("webtransport"))),
            ConnectProtocol::Unsupported("webtransport")
        );
    }

    #[test]
    fn a_peer_reset_is_told_apart_from_every_other_failure() {
        assert_eq!(
            peer_reset_code(&StreamError::RemoteTerminate {
                code: CONNECT_ERROR
            }),
            Some(0x10f)
        );
        assert_eq!(
            peer_reset_code(&StreamError::Connection(ConnectionError::Timeout)),
            None
        );
    }

    /// The grading `quic.rs` logs by: two endings are routine, the rest warn.
    #[test]
    fn routine_endings_are_graded_as_such() {
        assert_eq!(
            benign_close(&ConnectionError::Timeout),
            Some(BenignClose::Idle)
        );
        for code in [Code::new(0), NO_ERROR] {
            assert_eq!(
                benign_close(&ConnectionError::ApplicationClose { code }),
                Some(BenignClose::PeerClosed),
                "{code}"
            );
        }
    }

    #[test]
    fn a_reported_problem_still_warns() {
        assert_eq!(
            benign_close(&ConnectionError::ApplicationClose {
                code: Code::new(42)
            }),
            None
        );
        assert_eq!(
            benign_close(&ConnectionError::Transport(
                quinn::ConnectionError::LocallyClosed
            )),
            None
        );
    }

    /// The two derived constants must stay equal to what they are derived from.
    #[test]
    fn the_datagram_close_code_matches_the_stream_code() {
        assert_eq!(DATAGRAM_ERROR_CLOSE.into_inner(), DATAGRAM_ERROR.value());
        assert_eq!(AUTH_FAILURE_LIMIT_CODE.into_inner(), 0x10b);
    }
}
