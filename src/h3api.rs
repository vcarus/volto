//! The facade over the HTTP/3 layer.
//!
//! Everything the rest of the crate needs from HTTP/3 is named here, and only
//! here: `conn`, `quic` and the tunnels use `bytes` and `quinn` types plus the
//! handful of names below. That facade began as insulation from the `h3` crate;
//! it survives the move to [`crate::h3`] because it is worth having on its own
//! terms -- it is the list of what a proxy actually asks of HTTP/3, and it is
//! short.
//!
//! The vocabulary of an HTTP message -- [`Request`], [`Status`], [`Fields`] --
//! is [`crate::h3::message`]'s and is re-exported here rather than wrapped: a
//! status is a status, and a second type in front of it would say nothing the
//! first does not. The rule is about *where they are named*, and it is
//! unchanged: nothing outside [`crate::h3`] reaches into it, so this module is
//! the one place that has to be read to know what the rest of the crate may
//! assume about HTTP/3.
//!
//! Inbound HTTP Datagrams (RFC 9297) are named here too, because the routing
//! they need is *per request stream*: a datagram carries the Quarter Stream ID
//! of the stream it belongs to, so the layer that owns request streams is the
//! layer that can hand it to the right one. A session claims its share with
//! [`Stream::datagrams`] and holds it for as long as it holds the
//! [`DatagramReceiver`] (D79). Sending is the one half that stays outside:
//! `tunnel::udp` writes datagrams straight onto the `quinn::Connection` it
//! already holds for the send-buffer and datagram-size questions it asks per
//! packet.

pub use crate::h3::MAX_FIELD_SECTION_SIZE;
pub use crate::h3::connection::{Connection, DatagramReceiver};
pub use crate::h3::error::{Code, ConnectionError, StreamError};
pub use crate::h3::message::{FieldValue, Fields, Method, Request, Status};
pub use crate::h3::stream::{Reader, Resolver, RespondError, Stream, Writer};

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

/// Connection close code used when a peer exhausts its authentication attempts.
///
/// A QUIC application error code rather than an HTTP/3 one, because it closes the
/// whole connection rather than a stream. `H3_REQUEST_REJECTED`'s value is reused
/// so the peer sees something meaningful in the CONNECTION_CLOSE frame.
pub const AUTH_FAILURE_LIMIT_CODE: quinn::VarInt = quinn::VarInt::from_u32(0x10b);

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

        // This endpoint closed the connection with nothing to report, which is
        // what `Connection::close_quietly` does when a peer that never
        // authenticated has gone silent for too long (D76). The peer was idle;
        // that an application timer rather than the transport's own noticed it
        // does not make it a fault.
        ConnectionError::Local(violation) if violation.code() == NO_ERROR => {
            Some(BenignClose::Idle)
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h3::error::Violation;

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

    /// A close this endpoint makes with nothing to report is graded with the
    /// idle timeout it stands in for, not with the violations (D76).
    #[test]
    fn our_own_quiet_close_is_routine() {
        assert_eq!(
            benign_close(&ConnectionError::Local(Violation::connection(
                NO_ERROR,
                "no request within the timeout"
            ))),
            Some(BenignClose::Idle)
        );
    }

    #[test]
    fn a_reported_problem_still_warns() {
        assert_eq!(
            benign_close(&ConnectionError::ApplicationClose {
                code: Code::new(42)
            }),
            None
        );
        // A violation is still a violation, whatever its code says about us.
        assert_eq!(
            benign_close(&ConnectionError::Local(Violation::connection(
                Code::H3_FRAME_UNEXPECTED,
                "a frame that may not appear here"
            ))),
            None
        );
        assert_eq!(
            benign_close(&ConnectionError::Transport(
                quinn::ConnectionError::LocallyClosed
            )),
            None
        );
    }

    /// The close code is a number the peer reads, so it is pinned rather than
    /// left to whatever `quinn::VarInt::from_u32` was handed.
    #[test]
    fn the_auth_failure_close_code_is_the_one_documented() {
        assert_eq!(AUTH_FAILURE_LIMIT_CODE.into_inner(), 0x10b);
    }
}
