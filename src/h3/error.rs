//! HTTP/3 error codes and the two error types the rest of the crate sees.
//!
//! The split between them is the one RFC 9114 §8 makes: a *stream* error ends
//! one request and leaves the connection usable, while a *connection* error
//! takes everything down. Which of the two a given violation is, is a property
//! of the rule that was broken, so it is carried by [`Violation`] rather than
//! decided at the point the error is handled.

use std::borrow::Cow;
use std::fmt;

/// An HTTP/3 "application error code" (RFC 9114 §8.1).
///
/// A newtype rather than an enum: the registry is open, and a peer may close a
/// connection with a code this server has never heard of, which still has to be
/// logged rather than lost.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Code(u64);

impl Code {
    /// The code as it appears on the wire.
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Wraps a raw code, including ones outside the registry.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Defines the registered codes and makes `Debug`/`Display` print their names.
///
/// The name is what an operator reads in a log line; `H3_CONNECT_ERROR` says
/// what `0x10f` does not.
macro_rules! codes {
    ($( $(#[$doc:meta])* ($value:expr, $name:ident); )+) => {
        impl Code {
            $( $(#[$doc])* pub const $name: Code = Code($value); )+
        }

        impl fmt::Display for Code {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {
                    $( $value => f.write_str(stringify!($name)), )+
                    other => write!(f, "{other:#x}"),
                }
            }
        }
    };
}

codes! {
    /// A datagram or capsule could not be parsed (RFC 9297 §5.2).
    (0x33, H3_DATAGRAM_ERROR);
    /// No error: a close with nothing to report (RFC 9114 §8.1).
    (0x100, H3_NO_ERROR);
    /// A protocol violation with no more specific code (RFC 9114 §8.1).
    (0x101, H3_GENERAL_PROTOCOL_ERROR);
    /// A fault inside this HTTP/3 stack rather than in the peer's message.
    (0x102, H3_INTERNAL_ERROR);
    /// The peer created a stream this endpoint will not accept (RFC 9114 §6.2).
    (0x103, H3_STREAM_CREATION_ERROR);
    /// A stream the connection depends on was closed or reset (RFC 9114 §6.2.1).
    (0x104, H3_CLOSED_CRITICAL_STREAM);
    /// A frame arrived where it is not allowed (RFC 9114 §7.2).
    (0x105, H3_FRAME_UNEXPECTED);
    /// A frame's layout or size is invalid (RFC 9114 §7.1).
    (0x106, H3_FRAME_ERROR);
    /// The peer is behaving in a way that might generate excessive load.
    (0x107, H3_EXCESSIVE_LOAD);
    /// A stream or push id was used incorrectly (RFC 9114 §5.2).
    (0x108, H3_ID_ERROR);
    /// A SETTINGS payload broke one of RFC 9114 §7.2.4's rules.
    (0x109, H3_SETTINGS_ERROR);
    /// The control stream did not begin with SETTINGS (RFC 9114 §6.2.1).
    (0x10a, H3_MISSING_SETTINGS);
    /// The request was rejected without being processed (RFC 9114 §5.2).
    (0x10b, H3_REQUEST_REJECTED);
    /// The request or its response is cancelled (RFC 9114 §8.1).
    (0x10c, H3_REQUEST_CANCELLED);
    /// The request stream ended without a fully formed request (RFC 9114 §4.1).
    (0x10d, H3_REQUEST_INCOMPLETE);
    /// An HTTP message was malformed (RFC 9114 §4.1.2).
    (0x10e, H3_MESSAGE_ERROR);
    /// The connection made for a CONNECT request failed (RFC 9114 §4.4).
    (0x10f, H3_CONNECT_ERROR);
    /// The request cannot be served over HTTP/3 (RFC 9114 §8.1).
    (0x110, H3_VERSION_FALLBACK);
    /// An encoded field section could not be decoded (RFC 9204 §6).
    (0x200, QPACK_DECOMPRESSION_FAILED);
    /// An encoder-stream instruction could not be interpreted (RFC 9204 §6).
    (0x201, QPACK_ENCODER_STREAM_ERROR);
    /// A decoder-stream instruction could not be interpreted (RFC 9204 §6).
    (0x202, QPACK_DECODER_STREAM_ERROR);
}

impl fmt::Debug for Code {
    /// The same text as `Display`.
    ///
    /// Log fields recorded with tracing's `?` sigil go through `Debug`, and a
    /// code is worth just as much there as behind `%`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Something the peer did that RFC 9114 (or 9204, or 9297) forbids.
///
/// Carries both halves of the answer the RFC prescribes: the error code to send,
/// and whether the rule makes it a *connection* error rather than a stream one.
/// Keeping the second half here rather than at the handling site is what stops
/// the two from drifting apart — the same violation reported from a request
/// stream and from the control stream must end the same thing either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    code: Code,
    fatal: bool,
    detail: Cow<'static, str>,
}

impl Violation {
    /// A violation of a rule that only ends the stream it happened on.
    pub fn stream(code: Code, detail: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            fatal: false,
            detail: detail.into(),
        }
    }

    /// A violation of a rule the RFC states as a connection error.
    pub fn connection(code: Code, detail: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            fatal: true,
            detail: detail.into(),
        }
    }

    /// The error code to answer with.
    pub fn code(&self) -> Code {
        self.code
    }

    /// Whether the whole connection has to be closed.
    pub fn is_connection_error(&self) -> bool {
        self.fatal
    }

    /// The same violation, escalated to end the connection.
    ///
    /// Every stream the connection depends on takes this route: RFC 9114 §6.2.1
    /// makes any failure of a critical stream fatal, whatever the underlying
    /// rule would have been on a request stream.
    pub fn into_fatal(self) -> Self {
        Self {
            fatal: true,
            ..self
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

/// Error affecting the whole HTTP/3 connection.
///
/// The variants are the four endings that need telling apart downstream: two of
/// them are ordinary goodbyes ([`crate::h3api::benign_close`]), and two are
/// faults. Everything the QUIC layer reports that is neither an application
/// close nor the idle timeout stays in [`ConnectionError::Transport`] with
/// quinn's own error inside it, so nothing is flattened away before an operator
/// sees it.
#[derive(Debug, Clone)]
pub enum ConnectionError {
    /// The peer closed the connection with an HTTP/3 error code.
    ApplicationClose {
        /// The code the peer sent. `0` and `H3_NO_ERROR` both mean "goodbye".
        code: Code,
    },
    /// The peer went silent and the QUIC idle timeout expired.
    Timeout,
    /// This endpoint closed the connection because the peer broke a rule.
    Local(Violation),
    /// Anything else the QUIC layer reported, including our own local close.
    Transport(quinn::ConnectionError),
}

impl From<quinn::ConnectionError> for ConnectionError {
    /// Keeps exactly the two cases [`crate::h3api::benign_close`] grades on.
    ///
    /// `LocallyClosed` deliberately stays in `Transport`: this server closes a
    /// connection only for a reason worth reporting (a protocol violation, or
    /// the authentication-failure budget), so it must not be filed alongside a
    /// peer's clean goodbye.
    fn from(error: quinn::ConnectionError) -> Self {
        match error {
            quinn::ConnectionError::ApplicationClosed(close) => Self::ApplicationClose {
                code: Code::new(close.error_code.into_inner()),
            },
            quinn::ConnectionError::TimedOut => Self::Timeout,
            other => Self::Transport(other),
        }
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The variant name is spelled out because it is what an operator
            // greps a journal for: "the peer closed this, and with what".
            Self::ApplicationClose { code } => write!(f, "ApplicationClose: {code}"),
            Self::Timeout => f.write_str("Timeout"),
            Self::Local(violation) => write!(f, "closed by this server: {violation}"),
            Self::Transport(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

/// Error affecting a single request stream.
#[derive(Debug, Clone)]
pub enum StreamError {
    /// The peer reset its sending side, or stopped ours, with `code`.
    ///
    /// The two are one variant because a CONNECT tunnel treats them alike: the
    /// client has abandoned this direction and said why.
    RemoteTerminate {
        /// The code the peer sent in RESET_STREAM or STOP_SENDING.
        code: Code,
    },
    /// The connection under the stream ended.
    Connection(ConnectionError),
    /// This endpoint ended the stream, for the reason given.
    Local(Violation),
}

impl From<ConnectionError> for StreamError {
    fn from(error: ConnectionError) -> Self {
        Self::Connection(error)
    }
}

impl From<Violation> for StreamError {
    fn from(violation: Violation) -> Self {
        Self::Local(violation)
    }
}

impl From<quinn::ReadError> for StreamError {
    fn from(error: quinn::ReadError) -> Self {
        match error {
            quinn::ReadError::Reset(code) => Self::RemoteTerminate {
                code: Code::new(code.into_inner()),
            },
            quinn::ReadError::ConnectionLost(error) => Self::Connection(error.into()),
            // `IllegalOrderedRead` cannot occur: this stack only ever reads in
            // order. The other two are this endpoint having already finished
            // with the stream, which is a fault in this stack, not in the peer.
            other => Self::Local(Violation::stream(
                Code::H3_INTERNAL_ERROR,
                other.to_string(),
            )),
        }
    }
}

impl From<quinn::WriteError> for StreamError {
    fn from(error: quinn::WriteError) -> Self {
        match error {
            quinn::WriteError::Stopped(code) => Self::RemoteTerminate {
                code: Code::new(code.into_inner()),
            },
            quinn::WriteError::ConnectionLost(error) => Self::Connection(error.into()),
            other => Self::Local(Violation::stream(
                Code::H3_INTERNAL_ERROR,
                other.to_string(),
            )),
        }
    }
}

impl From<quinn::ClosedStream> for StreamError {
    fn from(error: quinn::ClosedStream) -> Self {
        Self::Local(Violation::stream(
            Code::H3_INTERNAL_ERROR,
            error.to_string(),
        ))
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemoteTerminate { code } => write!(f, "peer terminated the stream: {code}"),
            Self::Connection(error) => write!(f, "connection error: {error}"),
            Self::Local(violation) => write!(f, "stream reset by this server: {violation}"),
        }
    }
}

impl std::error::Error for StreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_codes_print_their_names() {
        assert_eq!(Code::H3_NO_ERROR.to_string(), "H3_NO_ERROR");
        assert_eq!(Code::H3_CONNECT_ERROR.to_string(), "H3_CONNECT_ERROR");
        assert_eq!(format!("{:?}", Code::H3_MESSAGE_ERROR), "H3_MESSAGE_ERROR");
    }

    /// The registry is open, so an unknown code has to survive as a number
    /// rather than be lost or panicked on.
    #[test]
    fn unregistered_codes_print_as_hex() {
        assert_eq!(Code::new(0x4242).to_string(), "0x4242");
        assert_eq!(Code::new(0).to_string(), "0x0");
    }

    /// The values as their defining documents register them: RFC 9114 §8.1
    /// for the H3_ codes, RFC 9297 §5.2 for H3_DATAGRAM_ERROR, and RFC 9204
    /// §8.3 for the QPACK ones.
    #[test]
    fn code_values_match_the_registries() {
        assert_eq!(Code::H3_DATAGRAM_ERROR.value(), 0x33);
        assert_eq!(Code::H3_NO_ERROR.value(), 0x100);
        assert_eq!(Code::H3_MESSAGE_ERROR.value(), 0x10e);
        assert_eq!(Code::QPACK_DECOMPRESSION_FAILED.value(), 0x200);
    }

    /// The grading in `quic.rs` reads the connection close log off this text,
    /// and `it_close_log` asserts the peer-close line names the variant.
    #[test]
    fn a_peer_application_close_names_itself() {
        let error = ConnectionError::from(quinn::ConnectionError::ApplicationClosed(
            quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(42),
                reason: bytes::Bytes::new(),
            },
        ));
        let text = error.to_string();
        assert!(text.contains("ApplicationClose"), "{text}");
        assert!(!text.contains("Timeout"), "{text}");
    }

    #[test]
    fn the_idle_timeout_is_its_own_variant() {
        assert!(matches!(
            ConnectionError::from(quinn::ConnectionError::TimedOut),
            ConnectionError::Timeout
        ));
    }

    /// Our own close must not be filed as the peer's goodbye.
    #[test]
    fn a_local_close_stays_a_transport_error() {
        assert!(matches!(
            ConnectionError::from(quinn::ConnectionError::LocallyClosed),
            ConnectionError::Transport(quinn::ConnectionError::LocallyClosed)
        ));
    }

    #[test]
    fn a_reset_carries_the_peers_code() {
        let error = StreamError::from(quinn::ReadError::Reset(quinn::VarInt::from_u32(0x10f)));
        assert!(matches!(
            error,
            StreamError::RemoteTerminate { code } if code == Code::H3_CONNECT_ERROR
        ));
    }

    #[test]
    fn a_stop_sending_carries_the_peers_code() {
        let error = StreamError::from(quinn::WriteError::Stopped(quinn::VarInt::from_u32(0x100)));
        assert!(matches!(
            error,
            StreamError::RemoteTerminate { code } if code == Code::H3_NO_ERROR
        ));
    }

    #[test]
    fn escalating_a_violation_keeps_its_code_and_text() {
        let violation = Violation::stream(Code::H3_FRAME_ERROR, "stream ended mid-frame");
        assert!(!violation.is_connection_error());

        let fatal = violation.clone().into_fatal();
        assert!(fatal.is_connection_error());
        assert_eq!(fatal.code(), violation.code());
        assert_eq!(fatal.to_string(), violation.to_string());
    }
}
