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
    /// A fault inside this HTTP/3 layer rather than in the peer's message.
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
    /// Whether the peer's fault is a field section this server would not hold,
    /// which is the one thing a 431 answers -- see
    /// [`Self::field_section_too_large`].
    field_section: bool,
    detail: Cow<'static, str>,
}

impl Violation {
    /// A violation of a rule that only ends the stream it happened on.
    pub fn stream(code: Code, detail: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            fatal: false,
            field_section: false,
            detail: detail.into(),
        }
    }

    /// A violation of a rule the RFC states as a connection error.
    pub fn connection(code: Code, detail: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            fatal: true,
            field_section: false,
            detail: detail.into(),
        }
    }

    /// An H3_EXCESSIVE_LOAD stream error a 431 is the right answer to.
    ///
    /// The 431 (Request Header Fields Too Large) that
    /// [`crate::h3::stream::Resolver::resolve`] sends is a *diagnosis*, not a
    /// consequence of the code: it tells a peer which part of its request to
    /// shrink (RFC 9114 §10.5.1). That is worth saying only when the fault
    /// really is a field section too large to hold -- the three sources being
    /// the per-frame buffering limit, the advertised
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`, and D77's connection-wide budget.
    ///
    /// It is stated here rather than inferred at the answering site because
    /// `H3_EXCESSIVE_LOAD` is a code, not a class: RFC 9114 §10.5's
    /// reserved-frame flood carries the same code and no header field was ever
    /// sent, so a peer told to shrink its field sections would be told to fix
    /// something it never did. Marking the three that mean it keeps a fourth
    /// source, added later, on the bare reset that is safe for anything.
    pub fn field_section_too_large(detail: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code: Code::H3_EXCESSIVE_LOAD,
            fatal: false,
            field_section: true,
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

    /// Whether a 431 is the right thing to tell the peer about this.
    ///
    /// True only for [`Self::field_section_too_large`], which says why. The one
    /// reader is [`crate::h3::stream::Resolver::resolve`]; every other
    /// stream-class violation, this code included, is answered by the bare reset
    /// that says nothing a peer could act on wrongly.
    pub fn is_field_section_too_large(&self) -> bool {
        self.field_section
    }

    /// The same violation, escalated to end the connection.
    ///
    /// Every stream the connection depends on takes this route: RFC 9114 §6.2.1
    /// makes any failure of a critical stream fatal, whatever the underlying
    /// rule would have been on a request stream.
    ///
    /// Not public: escalating someone else's verdict is a judgement only the
    /// reader of a critical stream is entitled to make, and all of those are in
    /// [`super::connection`].
    pub(super) fn into_fatal(self) -> Self {
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
    /// Keeps exactly the two cases [`crate::h3api::benign_close`] grades on, and
    /// takes the peer's prose apart from its verdict on the way.
    ///
    /// `LocallyClosed` deliberately stays in `Transport`: this server closes a
    /// connection only for a reason worth reporting (a protocol violation, or
    /// the authentication-failure budget), so it must not be filed alongside a
    /// peer's clean goodbye.
    ///
    /// # The reason phrase
    ///
    /// Both kinds of QUIC close carry a reason phrase (RFC 9000 §19.19), and it
    /// is whatever bytes the peer felt like sending -- bounded only by the
    /// packet that carried it, and reaching this endpoint from anybody who can
    /// complete a handshake, authenticated or not. It ends up in a production
    /// log line: [`crate::quic`] records the whole error with `%` on the `WARN`
    /// that closes a connection that ended badly, and `Display` escapes nothing.
    /// A newline in there is a journal entry of the peer's own composition,
    /// attributed to this server, and a kilobyte of prose is a kilobyte of
    /// journal per handshake.
    ///
    /// The application half never had the problem: only the code survives the
    /// conversion, because [`crate::h3api::benign_close`] grades on the code and
    /// nothing downstream wanted the text. The transport half keeps quinn's
    /// error whole, which is worth keeping -- a peer's QUIC stack says useful
    /// things there -- so the phrase is bounded and escaped in place instead,
    /// where the peer's bytes enter this type rather than where they are logged
    /// (the same point [`crate::auth`] cuts a claimed user-id at, and for the
    /// same reason). [`crate::logfmt::peer_error`] is that cut, and it is the
    /// same call [`crate::quic`] makes on the handshake that never got far
    /// enough to reach this conversion at all.
    fn from(error: quinn::ConnectionError) -> Self {
        match error {
            quinn::ConnectionError::ApplicationClosed(close) => Self::ApplicationClose {
                code: Code::new(close.error_code.into_inner()),
            },
            quinn::ConnectionError::TimedOut => Self::Timeout,
            other => Self::Transport(crate::logfmt::peer_error(other)),
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

    /// A peer's *transport* close carries prose the peer wrote, and this type's
    /// `Display` is what `quic.rs` records with `%error` on the `WARN` that ends
    /// a connection. `Display` escapes nothing, and systemd splits a service's
    /// stdout on `\n`, so a reason phrase reaching that line whole hands any peer
    /// that can complete a handshake a journal entry of its own -- forged,
    /// attributed to this server, and free.
    ///
    /// The peer's own words are still worth having, so they are kept: bounded and
    /// `Debug`-escaped where they enter this type, which is the same division of
    /// labour `logfmt` states and `auth` already applies to a claimed user-id.
    #[test]
    fn a_peer_transport_close_cannot_forge_a_log_line() {
        let forged = "bye\nINFO volto: authentication succeeded for admin";
        let error = ConnectionError::from(quinn::ConnectionError::ConnectionClosed(
            quinn::ConnectionClose {
                error_code: quinn::TransportErrorCode::PROTOCOL_VIOLATION,
                frame_type: None,
                reason: bytes::Bytes::from(forged),
            },
        ));

        let text = error.to_string();
        assert!(
            !text.contains('\n') && !text.contains('\r'),
            "a peer's reason phrase must not be able to start a journal line: {text:?}"
        );
        // The head survives, so the phrase is still a diagnostic.
        assert!(text.contains("bye"), "{text:?}");
    }

    /// The same phrase, at the length a peer may actually send: the reason is
    /// bounded only by the QUIC packet that carries it, so an unbounded copy is
    /// a kilobyte of journal per handshake as well as an injection.
    #[test]
    fn a_peer_transport_close_reason_is_bounded() {
        let error = ConnectionError::from(quinn::ConnectionError::ConnectionClosed(
            quinn::ConnectionClose {
                error_code: quinn::TransportErrorCode::PROTOCOL_VIOLATION,
                frame_type: None,
                reason: bytes::Bytes::from(vec![b'r'; 4096]),
            },
        ));

        let text = error.to_string();
        // The bulk of what is left is quinn's own prose for the error code,
        // which is a constant; what the peer chose is the part that has to stop
        // growing.
        assert!(
            !text.contains(&"r".repeat(33)),
            "the peer's phrase is unbounded: {text:?}"
        );
        assert!(
            text.len() < 256,
            "one close must not buy {} bytes of journal: {text:?}",
            text.len()
        );
        assert!(
            text.contains("4096"),
            "the real length is the fact: {text:?}"
        );
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
