//! One request stream, from its HEADERS frame to its last byte.
//!
//! # Reading
//!
//! A request stream carries HEADERS and then a body of DATA frames. Only the
//! first is buffered: the body is handed on in the chunks it arrived in, because
//! for this server the body *is* the tunnel and every copy of it would be paid
//! for per packet. Nothing follows the body -- RFC 9114 §4.4 permits only DATA
//! on a stream whose CONNECT has completed, so the trailer section §4.1 allows
//! an ordinary request is a frame this server never sees a use for.
//!
//! # Validating
//!
//! [`Resolver::resolve`] is where a request becomes a [`Request`], and where
//! RFC 9114 §4.1.2's "malformed" verdict is reached. The rules are worth
//! stating together because they are what a proxy is judged on: a request that
//! this server accepts is one it will open a socket for.
//!
//! A malformed request is a *stream* error: the stream is reset and stopped with
//! H3_MESSAGE_ERROR and nothing else on the connection is disturbed. A frame
//! sequence that makes no sense is a *connection* error, because after one the
//! stream can no longer be parsed at all.
//!
//! # Writing
//!
//! A response is one HEADERS frame; body bytes are DATA frames whose header is
//! written alongside the payload rather than copied in front of it, so a 16 KiB
//! relay chunk reaches the wire as the same allocation it was read into.

use std::borrow::Cow;

use bytes::{Bytes, BytesMut};

use super::connection::{DatagramReceiver, Handle};
use super::error::{Code, StreamError, Violation};
use super::frame::{self, Frame, FrameReader, Item};
use super::message::{self, FieldValue, Fields, Method, Request, Status};
use super::qpack::{self, Field};
use super::{varint, MAX_FIELD_SECTION_SIZE, MAX_VARINT};

/// An accepted request stream whose headers have not been read yet.
pub struct Resolver {
    handle: Handle,
    send: quinn::SendStream,
    frames: FrameReader,
}

impl Resolver {
    pub(crate) fn new(handle: Handle, send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        let frames = FrameReader::on_request_stream(recv, handle.budget());
        Self {
            handle,
            send,
            frames,
        }
    }

    /// Reads and validates the request headers, giving up after one QUIC idle
    /// timeout.
    ///
    /// On failure the stream has already been ended -- reset and stopped for a
    /// malformed request, or the whole connection closed for a frame sequence
    /// that cannot be parsed -- so the caller has nothing left to do but log it.
    ///
    /// # The deadline
    ///
    /// A peer opens a request stream by sending on it, and may then send one
    /// byte and stop. Nothing in HTTP/3 obliges it to finish the request, and
    /// the QUIC idle timeout is no backstop while [`crate::quic`]'s keep-alive
    /// PINGs are being answered by its stack, so without a deadline each such
    /// stream parks a task until the connection ends -- `max_streams_bidi` of
    /// them per connection, at a byte apiece, from a peer that has not
    /// authenticated (D76). The bound is the connection's own idle timeout,
    /// which is the same value [`crate::quic`] put in its transport parameters.
    ///
    /// The stream is the only thing a lapsed deadline ends: it is reset and
    /// stopped, and the connection carries on serving everything else on it.
    pub async fn resolve(self) -> Result<(Request, Stream), StreamError> {
        let Self {
            handle,
            mut send,
            mut frames,
        } = self;

        let read = match tokio::time::timeout(handle.idle, read_request(&mut frames)).await {
            Ok(read) => read,

            //= https://www.rfc-editor.org/rfc/rfc9114#section-8.1
            //# H3_REQUEST_INCOMPLETE (0x010d):  The client's stream terminated
            //# without containing a fully formed request.
            //
            // The stream has not terminated -- it has stopped, which no code in
            // §8.1 names -- but what the peer is owed is the same answer either
            // way: the request it began will not be served because it never
            // finished arriving. `read_request` reaches for the same code when
            // the stream really does end early, and a client cannot usefully
            // tell "you stopped" from "you stopped for good".
            Err(_elapsed) => {
                let violation = Violation::stream(
                    Code::H3_REQUEST_INCOMPLETE,
                    "the request headers did not arrive within one idle timeout",
                );
                let _ = send.reset(varint(violation.code()));
                frames.stop(violation.code());
                return Err(StreamError::Local(violation));
            }
        };

        let mut stream = Stream {
            handle,
            send,
            frames,
            header: BytesMut::with_capacity(2 * MAX_VARINT),
        };

        match read {
            Ok(request) => Ok((request, stream)),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
            //# A server that receives a larger header section than it is
            //# willing to handle can send an HTTP 431 (Request Header
            //# Fields Too Large) status code ([RFC6585]).
            //
            // Which is worth the two extra lines: a client that has overshot
            // the limit this server advertised is told which of its requests to
            // fix, where a bare RESET_STREAM leaves it guessing. The answer goes
            // out first and that side is finished cleanly; the receiving side is
            // then stopped with the code, because the rest of the section is
            // precisely what this server has declined to read.
            //
            // All three of this server's H3_EXCESSIVE_LOAD sources on a request
            // stream are stream-class and all three land here: the per-frame
            // buffering limit, a field section that decoded past what
            // `SETTINGS_MAX_FIELD_SECTION_SIZE` told the peer to send -- the
            // same 64 KiB either way -- and the connection-wide buffering budget
            // of D77, which refuses the request that would overrun it rather
            // than the connection holding it. The guard stays because
            // `is_connection_error` is what decides between answering and
            // closing everywhere else in this file, and a code is not a class.
            //
            // The write is bounded and, when the bound lapses, abandoned with
            // a reset: [`Stream::respond_within`] says why, and a peer that
            // grants no flow-control window never takes these fifty-odd bytes.
            Err(frame::Error::Protocol(violation))
                if violation.code() == Code::H3_EXCESSIVE_LOAD
                    && !violation.is_connection_error() =>
            {
                if stream
                    .respond_within(Status::REQUEST_HEADER_FIELDS_TOO_LARGE, Fields::new())
                    .await
                    .is_ok()
                {
                    let _ = stream.finish();
                }
                stream.stop_receiving(violation.code());
                Err(StreamError::Local(violation))
            }

            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
            //# Malformed requests or responses that are detected MUST be
            //# treated as a stream error of type H3_MESSAGE_ERROR.
            //
            // The response side is reset as well as the request side stopped:
            // this request will never be answered, and a peer left waiting for
            // a response that is not coming learns nothing.
            Err(error) => Err(answer(
                &stream.handle,
                &mut stream.frames,
                Some(&mut stream.send),
                error,
            )),
        }
    }
}

/// Answers a frame-layer failure and reports it as a stream error.
///
/// A violation that RFC 9114 makes a *connection* error closes the connection,
/// which is what makes every operation on it fail; a stream-class one stops the
/// receiving side, because the rest of what the peer is sending is precisely
/// what has been refused.
///
/// Whether the *sending* side is reset as well is the caller's, which is why it
/// is a parameter: a request that was never understood will never be answered,
/// while a [`Reader`] is only half a stream and the tunnels decide the other
/// half differently for a client abort than for a target failure.
fn answer(
    handle: &Handle,
    frames: &mut FrameReader,
    send: Option<&mut quinn::SendStream>,
    error: frame::Error,
) -> StreamError {
    match error {
        frame::Error::Stream(error) => error,
        frame::Error::Protocol(violation) if violation.is_connection_error() => {
            StreamError::Connection(handle.fail(violation))
        }
        frame::Error::Protocol(violation) => {
            if let Some(send) = send {
                let _ = send.reset(varint(violation.code()));
            }
            frames.stop(violation.code());
            StreamError::Local(violation)
        }
    }
}

/// Reads the first frame of a request stream and turns it into a request.
async fn read_request(frames: &mut FrameReader) -> Result<Request, frame::Error> {
    let block = loop {
        match frames.next().await? {
            Some(Item::Frame(Frame::Headers(block))) => break block,

            // RFC 9114 §9's rule that unknown values are ignored, quoted in
            // full in `super`. It applies before the request as much as during
            // it: a client greasing its request stream is testing exactly this,
            // and the frame is skipped rather than counted as the stream's
            // first.
            Some(Item::Skipped { .. }) => {}

            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# Receipt of an invalid sequence of frames MUST be treated as a
            //# connection error of type H3_FRAME_UNEXPECTED. In particular, a
            //# DATA frame before any HEADERS frame, or a HEADERS or DATA frame
            //# after the trailing HEADERS frame, is considered invalid.
            //
            // The first of those cases. What may follow the HEADERS is judged
            // by `Reader::recv_data`, under the stricter rule §4.4 gives a
            // stream whose CONNECT has completed.
            Some(_) => {
                return Err(Violation::connection(
                    Code::H3_FRAME_UNEXPECTED,
                    "a request stream that does not begin with HEADERS",
                )
                .into())
            }

            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# If a client-initiated stream terminates without enough of the
            //# HTTP message to provide a complete response, the server SHOULD
            //# abort its response stream with the error code
            //# H3_REQUEST_INCOMPLETE.
            //
            // A SHOULD, and this server takes it: the RESET_STREAM that
            // `Resolver::resolve` sends for a stream-class violation is that
            // abort.
            None => {
                return Err(Violation::stream(
                    Code::H3_REQUEST_INCOMPLETE,
                    "the request stream ended before its HEADERS frame",
                )
                .into())
            }
        }
    };

    Ok(build_request(qpack::decode(
        &block,
        MAX_FIELD_SECTION_SIZE,
    )?)?)
}

/// Turns a decoded field section into a request, or says why it cannot.
///
/// Every rejection here is RFC 9114 §4.1.2's "malformed", and the checks are in
/// the order the RFC states them: field syntax (§4.2, §10.3), pseudo-header
/// placement and identity (§4.3), then the per-method shape (§4.3.1, §4.4,
/// RFC 8441 §4).
///
/// Public, though [`Resolver::resolve`] is the only caller the server has and
/// `crate::h3api` re-exports neither: this is where every "malformed" verdict in
/// the module doc above is actually decided, and reaching it needs nothing but a
/// decoded field section -- so `tests/it_fuzz.rs` states properties over
/// arbitrary pseudo-header *combinations* against it, which through a live
/// request stream would be one QUIC connection per combination. Documented
/// rather than hidden for the same reason: the rules it holds are what this
/// module is about.
pub fn build_request(section: Vec<Field>) -> Result<Request, Violation> {
    let mut method = None;
    let mut scheme = None;
    let mut authority = None;
    let mut target = None;
    let mut protocol = None;
    let mut fields = Fields::new();
    let mut regular_field_seen = false;

    for Field { name, value } in section {
        if !name.starts_with(b":") {
            regular_field_seen = true;
            add_field(&mut fields, &name, &value)?;
            continue;
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //# All pseudo-header fields MUST appear in the header section before
        //# regular header fields.
        if regular_field_seen {
            return Err(malformed("a pseudo-header field after a regular field"));
        }

        let slot = match &name[..] {
            b":method" => &mut method,
            b":scheme" => &mut scheme,
            b":authority" => &mut authority,
            b":path" => &mut target,
            b":protocol" => &mut protocol,

            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
            //# Endpoints MUST NOT generate pseudo-header fields other than
            //# those defined in this document. [...] Endpoints MUST treat a
            //# request or response that contains undefined or invalid
            //# pseudo-header fields as malformed.
            _ => return Err(malformed("an undefined pseudo-header field")),
        };

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //# All HTTP/3 requests MUST include exactly one value for the :method,
        //# :scheme, and :path pseudo-header fields, unless the request is a
        //# CONNECT request; see Section 4.4.
        if slot.replace(value).is_some() {
            return Err(malformed("a repeated pseudo-header field"));
        }
    }

    let method = method.ok_or_else(|| malformed("a request without :method"))?;
    let method = Method::parse(&method).ok_or_else(|| malformed("an invalid :method"))?;

    // RFC 8441 §4 defines :protocol for the extended CONNECT method and for
    // nothing else, so on any other request it is a pseudo-header used outside
    // the context it was defined in.
    //
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
    //# Pseudo-header fields are only valid in the context in which they are
    //# defined. [...] Endpoints MUST treat a request or response that contains
    //# undefined or invalid pseudo-header fields as malformed.
    if protocol.is_some() && method != Method::Connect {
        return Err(malformed(":protocol on a request that is not CONNECT"));
    }

    let (scheme, authority, path, query) = if method == Method::Connect && protocol.is_none() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
        //# The :scheme and :path pseudo-header fields are omitted [...] The
        //# :authority pseudo-header field contains the host and port to
        //# connect to [...] A CONNECT request that does not conform to these
        //# restrictions is malformed.
        if scheme.is_some() || target.is_some() {
            return Err(malformed("a CONNECT request carrying :scheme or :path"));
        }
        let authority =
            authority.ok_or_else(|| malformed("a CONNECT request without :authority"))?;

        (None, Some(uri_authority(&authority)?.into()), None, None)
    } else {
        // Extended CONNECT and ordinary requests are built the same way; only
        // where the authority may come from differs.
        //
        //= https://www.rfc-editor.org/rfc/rfc8441#section-4
        //# On requests that contain the :protocol pseudo-header field, the
        //# :scheme and :path pseudo-header fields of the target URI [...]
        //# MUST also be included.
        let scheme = scheme.ok_or_else(|| malformed("a request without :scheme"))?;
        let target = target.ok_or_else(|| malformed("a request without :path"))?;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component [...] the request MUST contain
        //# either an :authority pseudo-header field or a Host header field.
        //# If these fields are present, they MUST NOT be empty. If both
        //# fields are present, they MUST contain the same value.
        //
        // One table for both request shapes, because §4.3.1's agreement rule is
        // the same rule either way -- an extended CONNECT is still an HTTP/3
        // request. RFC 8441 §4 changes one row of it and no more: on a request
        // carrying :protocol the authority is mandatory rather than one of two
        // ways to name the target, so a Host field cannot stand in for it.
        let named = match (authority.as_deref(), fields.get("host")) {
            (Some(authority), Some(host)) if authority != host.as_bytes() => {
                return Err(malformed(":authority and Host disagree"))
            }
            (Some(authority), _) => authority,
            (None, _) if protocol.is_some() => {
                return Err(malformed("an extended CONNECT request without :authority"))
            }
            (None, Some(host)) => host.as_bytes(),
            (None, None) => return Err(malformed("a request with neither :authority nor Host")),
        };

        let (path, query) = split_target(&target, protocol.is_some())?;
        (
            Some(uri_scheme(&scheme)?.into()),
            Some(uri_authority(named)?.into()),
            Some(path.into()),
            query.map(Into::into),
        )
    };

    let protocol = protocol
        .map(|protocol| {
            std::str::from_utf8(&protocol)
                .map(Into::into)
                .map_err(|_| malformed("a :protocol that is not valid UTF-8"))
        })
        .transpose()?;

    Ok(Request {
        method,
        scheme,
        authority,
        path,
        query,
        protocol,
        fields,
    })
}

/// Checks a `:scheme` value (RFC 3986 §3.1).
///
/// `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, which is the whole of the rule:
/// what the scheme *says* decides nothing here, and `tunnel::udp` gives the
/// reason a CONNECT-UDP request is not required to call itself `https`.
fn uri_scheme(scheme: &[u8]) -> Result<&str, Violation> {
    let invalid = || malformed("a :scheme that is not a URI scheme");

    if !scheme.first().is_some_and(u8::is_ascii_alphabetic)
        || !scheme
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return Err(invalid());
    }

    // ASCII by the check above, so the conversion cannot fail; it is written
    // fallibly rather than as an `expect` because these are a peer's bytes.
    std::str::from_utf8(scheme).map_err(|_| invalid())
}

/// Checks an authority (RFC 3986 §3.2).
///
/// The characters an authority is made of and no others: unreserved (§2.3),
/// percent-encoding, sub-delims (§2.2), and ":", "@", "[", "]" -- the union of
/// what a userinfo, a host and a port may contain. It is the *syntax* that is
/// judged here and not the shape: `tunnel::tcp` splits the host from the port
/// and refuses a userinfo, an unbracketed IPv6 literal and a port that is not a
/// port, and answers each of them with a 400 rather than a stream error, which
/// tells a client rather more.
fn uri_authority(authority: &[u8]) -> Result<&str, Violation> {
    let invalid = || malformed("an :authority that is not an authority");

    // RFC 9114 §4.3.1 requires a non-empty one, and this is the only pseudo-
    // header where emptiness has to be said: an empty :scheme is not a scheme
    // and an empty :path is not an absolute path, so the syntax below refuses
    // both on its own. Every character an authority may contain is optional, so
    // nothing here would refuse the empty string.
    if authority.is_empty() {
        return Err(malformed("an empty :authority"));
    }

    if !authority
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || AUTHORITY_PUNCTUATION.contains(byte))
    {
        return Err(invalid());
    }

    // ASCII by the check above; fallible for the reason `uri_scheme` gives.
    std::str::from_utf8(authority).map_err(|_| invalid())
}

/// Splits a `:path` into its path and its query, checking both.
///
/// RFC 9114 §4.3.1 makes `:path` an absolute path optionally followed by a "?"
/// and a query, which are the productions of RFC 3986 §3.3 and §3.4: a leading
/// "/", then `pchar` and "/", and after the "?" those and "?" again. A "#" is
/// refused along with everything else outside that set, because a fragment is
/// not part of a request target (RFC 9110 §7.1) and silently dropping one would
/// mean acting on a target the client did not send.
fn split_target(target: &[u8], extended: bool) -> Result<(&str, Option<&str>), Violation> {
    // §4.3.1's asterisk form, which belongs to OPTIONS. This server answers such
    // a request with the 501 every method it does not implement gets, and can
    // only do so if the request is not malformed first. It is not a path, so it
    // is refused on an extended CONNECT, where RFC 8441 §4 asks for the :path of
    // a target URI and the tunnel that follows has to parse one.
    if target == b"*" && !extended {
        return Ok(("*", None));
    }

    if target.first() != Some(&b'/') {
        return Err(malformed("a :path that is not an absolute path"));
    }

    let (path, query) = match target.iter().position(|byte| *byte == b'?') {
        Some(mark) => (&target[..mark], Some(&target[mark + 1..])),
        None => (target, None),
    };

    if !path.iter().all(|byte| is_pchar(*byte) || *byte == b'/') {
        return Err(malformed("a :path with a character no path may contain"));
    }
    if !query.is_none_or(|query| {
        query
            .iter()
            .all(|byte| is_pchar(*byte) || matches!(byte, b'/' | b'?'))
    }) {
        return Err(malformed("a :path with a character no query may contain"));
    }

    // ASCII by the checks above, so neither conversion can fail; written
    // fallibly for the reason `uri_scheme` gives.
    let invalid = || malformed("a :path that is not valid UTF-8");
    Ok((
        std::str::from_utf8(path).map_err(|_| invalid())?,
        query
            .map(|query| std::str::from_utf8(query).map_err(|_| invalid()))
            .transpose()?,
    ))
}

/// The punctuation an authority may contain, beside letters and digits.
///
/// Unreserved (RFC 3986 §2.3), the "%" of percent-encoding, sub-delims (§2.2),
/// and the delimiters §3.2 gives the authority itself.
const AUTHORITY_PUNCTUATION: &[u8] = b"-._~%!$&'()*+,;=:@[]";

/// Whether `byte` is an RFC 3986 §3.3 `pchar`, or the "%" one begins with.
///
/// `unreserved / pct-encoded / sub-delims / ":" / "@"`.
fn is_pchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~%!$&'()*+,;=:@".contains(&byte)
}

/// Adds one regular field, applying RFC 9114 §4.2's rules on the way.
fn add_field(fields: &mut Fields, name: &[u8], value: &[u8]) -> Result<(), Violation> {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
    //# A request or response containing uppercase characters in field names
    //# MUST be treated as malformed.
    let name = message::field_name(name)
        .ok_or_else(|| malformed("a field name that is uppercase or not a token"))?;

    //= https://www.rfc-editor.org/rfc/rfc9110#section-5.5
    //# A field value does not include leading or trailing whitespace. When a
    //# specific version of HTTP allows such whitespace to appear in a message,
    //# a field parsing implementation MUST exclude such whitespace prior to
    //# evaluating the field value.
    //
    // HTTP/3 is one of the versions that allows it: SP and HTAB are ordinary
    // field-value octets on the wire (`FieldValue::parse` accepts them, and
    // refusing a stray leading space would turn a request every other stack
    // serves into a stream error). Excluding it *here* is what makes every
    // reading below evaluate the same value the RFC says was sent -- the
    // agreement between `:authority` and Host, and `crate::auth`, which would
    // otherwise see " Basic ..." as a credential with no scheme and answer a
    // well-formed request with a 407 that costs the peer an attempt.
    //
    // Only SP and HTAB are stripped, and only from the ends. Trimming the wider
    // ASCII whitespace set would strip a leading CR or LF as well, and those are
    // exactly the octets §10.3 refuses below.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
    //# Any request or response that contains a character not permitted in a
    //# field value MUST be treated as malformed.
    let value = FieldValue::parse(trim_optional_whitespace(value))
        .ok_or_else(|| malformed("a field value with a forbidden character"))?;

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
    //# An endpoint MUST NOT generate an HTTP/3 field section containing
    //# connection-specific fields; any message containing connection-specific
    //# fields MUST be treated as malformed.
    //
    // Only the Connection field itself is refused here, with the stream reset
    // a malformed request gets. RFC 9110 §7.6.1's wider list is judged in
    // `crate::tunnel::connection_specific_field`, which says which fields it
    // covers and why TE is not among them; the answer there can be a 400
    // (RFC 9114 §4.1.2 allows a response before the stream is closed), which
    // tells the client rather more than a bare reset would.
    if name == "connection" {
        return Err(malformed(
            "the Connection field, which HTTP/3 has no use for",
        ));
    }

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
    //# The only exception to this is the TE header field, which MAY be
    //# present in an HTTP/3 request header; when it is, it MUST NOT contain
    //# any value other than "trailers".
    if name == "te" && value.as_bytes() != b"trailers" {
        return Err(malformed("a TE field with a value other than \"trailers\""));
    }

    //= https://www.rfc-editor.org/rfc/rfc9110#section-7.2
    //# Host = uri-host [ ":" port ] ; Section 4
    //
    // One host and one optional port: the grammar leaves no room for a list,
    // and RFC 9110 §7.2 states no rule for a repeated Host field. So this is
    // this server's own, and it is the strict reading, because the alternative
    // is worse than strict. RFC 9114 §4.3.1 requires :authority and Host to
    // "contain the same value", and the agreement check below reads one Host --
    // whichever came first. Two Host fields that disagree would then let the
    // second one say anything at all, which is the request-smuggling shape this
    // proxy least wants to be the first hop of.
    if name == "host" && fields.contains("host") {
        return Err(malformed("more than one Host field"));
    }

    fields.append(name, value);
    Ok(())
}

/// Drops the leading and trailing SP and HTAB RFC 9110 §5.5 excludes from a
/// field value.
///
/// A value that is nothing but whitespace becomes the empty string, which is a
/// field value like any other.
fn trim_optional_whitespace(value: &[u8]) -> &[u8] {
    let whitespace = |byte: &u8| matches!(byte, b' ' | b'\t');

    let start = value.iter().position(|byte| !whitespace(byte));
    let Some(start) = start else {
        return &[];
    };
    // There is a non-whitespace octet at `start`, so there is a last one too.
    let end = value
        .iter()
        .rposition(|byte| !whitespace(byte))
        .unwrap_or(start);

    &value[start..=end]
}

/// A message this server will not process (RFC 9114 §4.1.2).
fn malformed(detail: impl Into<Cow<'static, str>>) -> Violation {
    Violation::stream(Code::H3_MESSAGE_ERROR, detail)
}

/// A bidirectional request stream.
pub struct Stream {
    handle: Handle,
    send: quinn::SendStream,
    frames: FrameReader,
    /// Scratch for frame headers, reused rather than allocated per frame.
    header: BytesMut,
}

impl Stream {
    /// The QUIC stream id.
    ///
    /// The Quarter Stream ID of RFC 9297 is this value divided by four.
    pub fn id(&self) -> u64 {
        u64::from(self.send.id())
    }

    /// Claims this stream's inbound HTTP Datagrams (RFC 9297 §2.1).
    ///
    /// Every datagram on the connection names a request stream by Quarter
    /// Stream ID, which is that stream's id divided by four; this is how the
    /// one stream that wants them says so. Until it is called nothing routes to
    /// this stream and it costs nothing, which is what keeps a TCP tunnel --
    /// which has no use for a datagram -- out of the routing table entirely.
    ///
    /// `None` if they have already been claimed. Only the first caller can be
    /// the session, because the [`DatagramReceiver`] deregisters the stream when
    /// it is dropped and a second one would take the first's entry with it.
    ///
    /// Called *before* the response, not after: RFC 9298 §5 lets a client start
    /// sending payloads before its request is answered, and a claim made here
    /// means those land in the session's queue rather than being dropped as
    /// belonging to no one.
    pub fn datagrams(&mut self) -> Option<DatagramReceiver> {
        self.handle
            .register_datagrams(crate::datagram::quarter_stream_id(self.id()))
    }

    /// Sends a response with `fields` and no body.
    ///
    /// Only the field lines given are sent -- nothing synthesises a
    /// Content-Length or Content-Type, both of which RFC 9297 §3.2 forbids on a
    /// capsule-carrying response. A 2xx answer to CONNECT must carry neither
    /// Content-Length nor Transfer-Encoding, which a caller meets by passing an
    /// empty [`Fields`]. The two rules live apart: RFC 9110 §8.6 has the first
    /// -- "A server MUST NOT send a Content-Length header field in any 2xx
    /// (Successful) response to a CONNECT request" -- while the second is RFC
    /// 9114 §4.1's, and is about every HTTP/3 message rather than about CONNECT:
    /// transfer codings "are not defined for HTTP/3; the Transfer-Encoding
    /// header field MUST NOT be used".
    ///
    /// Private, and deliberately: it waits on the peer's flow-control window
    /// with nothing to end the wait, so [`Self::respond_within`] is the only way
    /// out of this module to answer a request.
    async fn respond_with(&mut self, status: Status, fields: Fields) -> Result<(), StreamError> {
        // RFC 9114 §4.3.2: `:status` is the one pseudo-header a response has,
        // and it comes before every regular field (§4.3).
        let mut block = BytesMut::new();
        qpack::encode(
            &mut block,
            std::iter::once((&b":status"[..], status.as_str().as_bytes())).chain(
                fields
                    .iter()
                    .map(|(name, value)| (name.as_bytes(), value.as_bytes())),
            ),
        );

        frame::put_header(&mut self.header, frame::HEADERS, block.len() as u64);
        let mut chunks = [self.header.split().freeze(), block.freeze()];
        self.send.write_all_chunks(&mut chunks).await?;
        Ok(())
    }

    /// Sends a response with `fields`, bounded by the connection's idle
    /// timeout.
    ///
    /// # The deadline
    ///
    /// The write is the one step in answering a request that depends on the
    /// peer: a client that grants no flow-control window never takes the
    /// fifty-odd bytes of a 407, and without a deadline the task waits for that
    /// window until the connection ends. Every such request leaves a task
    /// holding the whole decoded request behind it, and the count of
    /// authentication failures that is meant to cost a guesser a handshake is
    /// recorded around one of these calls (review H1/H2).
    ///
    /// The bound is the connection's own idle timeout, read from the
    /// connection rather than passed in: it is the same value [`crate::quic`]
    /// put in this connection's transport parameters, and quinn's idle timer is
    /// no backstop while the peer's stack answers our keep-alive PINGs.
    ///
    /// The lapsed answer is abandoned with a reset rather than left to a FIN
    /// that cannot be sent either: the request will not be answered, and RFC
    /// 9114 §8.1 gives H3_REQUEST_CANCELLED for "the request or its response
    /// (including pushed response) is cancelled", which is exactly what has
    /// happened. Only the stream ends; the connection carries on serving
    /// everything else on it.
    pub async fn respond_within(
        &mut self,
        status: Status,
        fields: Fields,
    ) -> Result<(), RespondError> {
        match tokio::time::timeout(self.handle.idle, self.respond_with(status, fields)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(RespondError::Failed(error)),
            Err(_elapsed) => {
                self.reset(Code::H3_REQUEST_CANCELLED);
                Err(RespondError::Expired)
            }
        }
    }

    /// Ends the sending side cleanly (a QUIC stream FIN).
    ///
    /// Not `async`: [`quinn::SendStream::finish`] records that the stream is
    /// over and returns, and the FIN travels with the bytes already queued.
    /// There is nothing to wait for, and a caller that wants the peer's
    /// acknowledgement is asking a different question.
    pub fn finish(&mut self) -> Result<(), StreamError> {
        self.send.finish()?;
        Ok(())
    }

    /// Asks the peer to stop sending on this stream.
    pub fn stop_receiving(&mut self, code: Code) {
        self.frames.stop(code);
    }

    /// Abruptly ends the sending side with an error code.
    ///
    /// The counterpart to [`Stream::finish`], and the only one of the two that
    /// gets through to a peer that has stopped granting flow-control credit: a
    /// FIN travels at the end of the bytes already queued and so waits for a
    /// window that may never come, while a reset is a frame of its own and
    /// leaves at once. That is what makes this the way to abandon a response
    /// nobody is reading -- and abandoning it is what ends the stream, and
    /// returns the peer's allowance of streams with it.
    pub fn reset(&mut self, code: Code) {
        // Fails only if the stream is already finished or reset, which needs no
        // reporting: either way nothing more will be sent on it.
        let _ = self.send.reset(varint(code));
    }

    /// Splits the stream so each direction can be pumped independently.
    ///
    /// This is what makes TCP half-close expressible: one direction can finish
    /// while the other keeps flowing.
    ///
    /// Both tunnels call this immediately after answering the CONNECT with a
    /// 2xx, so this is also where "the CONNECT method has completed" happens:
    /// from here the reader applies RFC 9114 §4.4's rule that only DATA may
    /// follow, deciding it from each frame's header rather than after its
    /// payload.
    pub fn split(self) -> (Writer, Reader) {
        let mut frames = self.frames;
        frames.connect_completed();

        (
            Writer {
                send: self.send,
                header: self.header,
            },
            Reader {
                handle: self.handle,
                frames,
            },
        )
    }
}

/// Why a bounded response never reached the peer.
///
/// The two are worth telling apart because they say different things about the
/// peer and leave the stream in different states: a failed write is a stream
/// that has already ended, while a lapsed deadline is a peer that is still
/// there and simply will not read what it asked for.
///
/// Its [`Display`](std::fmt::Display) and [`std::error::Error`] impls have no
/// caller in this tree and are kept anyway: they are what makes a public error
/// type usable at all -- `?` into a `Box<dyn Error>` or an `anyhow::Error`, and
/// a `source()` chain that reaches the [`StreamError`] underneath -- and a
/// caller outside the crate has no other way to add them.
#[derive(Debug)]
pub enum RespondError {
    /// The write failed: the peer reset or stopped the stream, or the
    /// connection ended under it.
    Failed(StreamError),
    /// The deadline lapsed with the response unwritten.
    ///
    /// The stream has already been reset with H3_REQUEST_CANCELLED, so there is
    /// nothing left to send or finish on it.
    Expired,
}

impl std::fmt::Display for RespondError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(error) => write!(f, "{error}"),
            Self::Expired => {
                f.write_str("the peer did not take the response within one idle timeout")
            }
        }
    }
}

impl std::error::Error for RespondError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failed(error) => Some(error),
            Self::Expired => None,
        }
    }
}

/// The sending half of a split request stream.
pub struct Writer {
    send: quinn::SendStream,
    /// Scratch for DATA frame headers, reused across frames.
    header: BytesMut,
}

impl Writer {
    /// Sends body data, applying the peer's flow-control backpressure.
    ///
    /// The frame header and the payload go out as two chunks of one write, so
    /// the payload is never copied: what arrives here as a `Bytes` is what
    /// quinn queues.
    pub async fn send_data(&mut self, data: Bytes) -> Result<(), StreamError> {
        frame::put_header(&mut self.header, frame::DATA, data.len() as u64);
        let mut chunks = [self.header.split().freeze(), data];
        self.send.write_all_chunks(&mut chunks).await?;
        Ok(())
    }

    /// Ends the sending side cleanly (a QUIC stream FIN), without awaiting.
    ///
    /// Synchronous for the reason [`Stream::finish`] gives.
    pub fn finish(&mut self) -> Result<(), StreamError> {
        self.send.finish()?;
        Ok(())
    }

    /// Resolves when the peer stops this stream, or the connection under it
    /// ends.
    ///
    /// The mirror of [`Reader::reset_by_peer`] on the sending half, and it
    /// exists for the mirror of that reason. [`Self::send_data`] already reports
    /// a `STOP_SENDING` -- it is the error a write fails with -- but only to a
    /// caller that is writing, and a CONNECT tunnel spends much of its life not
    /// writing: with the client's half of the tunnel finished and a target that
    /// has yet to say anything, the pump is parked in a read of the *target*,
    /// and nothing there watches the request stream. This is what such a read
    /// can select on.
    ///
    /// # Why this one may be held across writes
    ///
    /// The future borrows nothing -- [`quinn::SendStream::stopped`] clones the
    /// connection handle and the stream id into an owned future -- so a caller
    /// builds it once, before its loop, and keeps polling the same one while
    /// writing to the same stream through `&mut self`. That is the point: a
    /// fresh future per iteration would take the connection lock on every pass,
    /// where one that is kept registers once and is a bare `Notified` poll
    /// afterwards.
    ///
    /// It is also why this is safe where `quinn::RecvStream::received_reset` is
    /// not (that comparison, and the panic it caused, is on
    /// [`Reader::reset_by_peer`]): quinn keeps no single-slot waker for it, but
    /// a `Notify` per stream that the connection wakes and removes when the
    /// stream is stopped or finished.
    ///
    /// Cancel-safe, so a `select!` may poll it and set it aside repeatedly.
    ///
    /// # What it resolves to
    ///
    /// Only endings. `Ok(Some(code))` is the peer's `STOP_SENDING` and is the
    /// case this exists for; a lost connection is reported as such; and quinn's
    /// `Ok(None)` -- the stream gone from the transport, which on a live tunnel
    /// means this endpoint finished it and the peer acknowledged every byte --
    /// is reported as this endpoint's own clean ending, since no peer said
    /// anything. All three mean the same thing to a caller: nothing more will be
    /// sent on this stream.
    pub fn stopped(&self) -> impl std::future::Future<Output = StreamError> + Send + 'static {
        let stopped = self.send.stopped();

        async move {
            match stopped.await {
                Ok(Some(code)) => StreamError::RemoteTerminate {
                    code: Code::new(code.into_inner()),
                },
                Ok(None) => StreamError::Local(Violation::stream(
                    Code::H3_NO_ERROR,
                    "the response stream is over",
                )),
                Err(quinn::StoppedError::ConnectionLost(error)) => {
                    StreamError::Connection(error.into())
                }
                // 0-RTT, which this server never accepts (`quic::Server`
                // answers every `Incoming` with `accept`, never `retry` into a
                // 0-RTT acceptance), so there is no rejection to report.
                Err(other) => StreamError::Local(Violation::stream(
                    Code::H3_INTERNAL_ERROR,
                    other.to_string(),
                )),
            }
        }
    }

    /// Abruptly resets the sending side with an error code.
    pub fn reset(&mut self, code: Code) {
        // Fails only if the stream is already finished or reset, which needs no
        // reporting: either way nothing more will be sent on it.
        let _ = self.send.reset(varint(code));
    }
}

/// The receiving half of a split request stream.
pub struct Reader {
    handle: Handle,
    frames: FrameReader,
}

impl Reader {
    /// Reads the next chunk of body data.
    ///
    /// `Ok(None)` means the peer finished its sending side -- for a CONNECT
    /// tunnel, the client's FIN.
    ///
    /// Cancel-safe: every byte read is accounted for in `self` before this
    /// returns, so a caller may poll it inside a `select!` with a timeout, which
    /// is exactly what a UDP session does.
    pub async fn recv_data(&mut self) -> Result<Option<Bytes>, StreamError> {
        loop {
            let item = match self.frames.next().await {
                Ok(Some(item)) => item,
                Ok(None) => return Ok(None),
                Err(error) => return Err(self.report(error)),
            };

            match item {
                // RFC 9114 §9's rule that unknown values are ignored, quoted in
                // full in `super`.
                Item::Skipped { .. } => {}

                // An empty DATA frame is legal and says nothing, so it must not
                // surface as `Some(empty)`: a caller relaying the body would
                // put a zero-length packet on the far side of the tunnel, and a
                // caller counting chunks would count one that carried nothing.
                Item::Data(data) if data.is_empty() => {}

                Item::Data(data) => return Ok(Some(data)),

                // RFC 9114 §4.4's rule -- once the CONNECT method has completed
                // only DATA may follow, and any other known frame type is a
                // connection error of type H3_FRAME_UNEXPECTED -- is applied a
                // layer down, by `frame::misplaced`, so that it is decided from
                // a frame's header rather than after its payload has been
                // buffered and charged for. [`Stream::split`] is what puts this
                // reader's decoder into that mode, and a [`Reader`] exists only
                // through it.
                //
                // So nothing reaches this arm. It repeats the verdict rather
                // than relaying an unexpected frame into a tunnel, because
                // which mode a decoder is in is not something the type system
                // knows.
                Item::Frame(_) => {
                    return Err(self.report(
                        Violation::connection(
                            Code::H3_FRAME_UNEXPECTED,
                            "a frame other than DATA once the CONNECT method had completed",
                        )
                        .into(),
                    ))
                }
            }
        }
    }

    /// How long [`Reader::reset_by_peer`] may take to notice a reset that
    /// arrived while the peer's bytes were already buffered.
    ///
    /// Only that case costs anything: a zero-length read cannot park on a
    /// stream that has bytes to give, so the watcher has nothing to be woken by
    /// and looks again on a timer instead. A reset that lands while the stream
    /// is quiet wakes the parked read at once and never waits this long.
    ///
    /// 250 ms is an order of magnitude under the bound the regression test
    /// holds the target's close to, and the wait it replaces was unbounded: a
    /// client that reset its request stream while its target had stopped
    /// reading used to hold the target socket, its file descriptor and the
    /// tunnel slot for the life of the QUIC connection. A peer cannot stretch
    /// it -- the timer is this server's, and sending more bytes only keeps the
    /// watcher on the timer it is already on.
    const RESET_PEEK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

    /// Resolves when the peer resets this stream, with the reset as an error.
    ///
    /// [`Self::recv_data`] already reports a reset -- it is the `Err` a read
    /// fails with -- but only to a caller that is reading. A CONNECT tunnel
    /// spends much of its life not reading: with a chunk in hand and a target
    /// that has stopped taking bytes, the pump is parked in a write instead,
    /// and nothing there watches the request stream. This is what such a write
    /// can select on.
    ///
    /// It reports *only* a reset, and never resolves for any other ending. A
    /// clean FIN and a stream this endpoint stopped both belong to the reading
    /// half, which is where a caller meets them; ending the wait here would
    /// turn one of them into an abort.
    ///
    /// # Why not `quinn::RecvStream::received_reset`
    ///
    /// Because it borrows a slot it never gives back, and quinn asserts on that
    /// slot being empty. quinn keeps **one** waker per stream for whoever is
    /// waiting to read, and exactly three things take an entry out of it: a
    /// `StreamEvent::Readable` for that stream, a `RecvStream::stop` while the
    /// stream still exists at the protocol layer, and `RecvStream::drop` while
    /// `all_data_read` is still false. A read that *succeeds* does not, so an
    /// entry outlives every later read of the bytes it was waiting for. That
    /// call writes into the slot on every poll that finds no reset, and a
    /// `select!` which drops the arm leaves it behind.
    ///
    /// In release builds that is a leak -- one waker per tunnel, held until the
    /// connection closes, keeping the finished task's cell alive with it. In
    /// debug builds it is a panic, because `RecvStream::drop` debug-asserts the
    /// slot is empty once the stream has been read to its end. An ordinary
    /// upload trips it: the client sends chunk after chunk with its FIN behind
    /// them, the pump is parked writing chunk *k* while *k+1* onwards are
    /// already buffered, and every one of those iterations leaves another waker
    /// behind. Nothing becomes readable after the FIN, so the last one is never
    /// cleared, and the clean end of the stream then panics the tunnel's task
    /// inside a destructor.
    ///
    /// So the wait is built on the zero-length read alone, which registers only
    /// through quinn's own read path. That kind of entry is safe to abandon:
    /// quinn takes it out again the moment the stream becomes readable, and a
    /// stream cannot reach its end without becoming readable first, so there is
    /// never one left when the reading half meets the FIN.
    ///
    /// # What that costs
    ///
    /// A zero-length read parks only while the stream has nothing to give. With
    /// bytes already buffered it returns at once -- which is precisely the state
    /// a stalled upload sits in -- so the wait there is a poll on a timer rather
    /// than a wake-up, and `RESET_PEEK_INTERVAL` -- 250 ms, documented where it
    /// is defined -- bounds how late the reset is noticed. A reset that arrives
    /// while nothing is buffered needs no timer: it wakes the parked read at
    /// once, as any read error would.
    ///
    /// Cancel-safe, so a `select!` may poll it and drop it repeatedly.
    pub async fn reset_by_peer(&mut self) -> StreamError {
        loop {
            match self.frames.readable().await {
                // Bytes are waiting, so a read cannot park on this stream and
                // there is nothing here to be woken by. Look again shortly.
                Ok(true) => tokio::time::sleep(Self::RESET_PEEK_INTERVAL).await,

                // The peer finished and everything it sent has been read. That
                // is not a reset and can no longer become one.
                Ok(false) => std::future::pending().await,

                Err(quinn::ReadError::Reset(code)) => {
                    return StreamError::RemoteTerminate {
                        code: Code::new(code.into_inner()),
                    }
                }

                // The connection under the stream went away, which is an ending
                // this half can report: no reader is left to meet it either.
                Err(quinn::ReadError::ConnectionLost(error)) => {
                    return StreamError::Connection(error.into())
                }

                // A stream this endpoint has already stopped or finished with,
                // and the ordered/unordered mix-up that cannot happen here:
                // nothing a tunnel acts on.
                Err(_) => std::future::pending().await,
            }
        }
    }

    /// Asks the peer to stop sending on this stream.
    pub fn stop_receiving(&mut self, code: Code) {
        self.frames.stop(code);
    }

    /// Answers a frame-layer failure and reports it as a stream error.
    ///
    /// Only the receiving half is here, so nothing resets the response side:
    /// that is the caller's decision, and the tunnels make it differently for a
    /// client abort than for a target failure.
    fn report(&mut self, error: frame::Error) -> StreamError {
        answer(&self.handle, &mut self.frames, None, error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, value: &str) -> Field {
        Field {
            name: Cow::Owned(name.as_bytes().to_vec()),
            value: Cow::Owned(value.as_bytes().to_vec()),
        }
    }

    /// A classic CONNECT: authority only, exactly as RFC 9114 §4.4 requires.
    fn connect() -> Vec<Field> {
        vec![
            field(":method", "CONNECT"),
            field(":authority", "example.com:443"),
        ]
    }

    /// A CONNECT-UDP request, the shape RFC 9298 §3 and RFC 9220 §3 give it.
    fn connect_udp() -> Vec<Field> {
        vec![
            field(":method", "CONNECT"),
            field(":protocol", "connect-udp"),
            field(":scheme", "https"),
            field(":authority", "proxy.example:443"),
            field(":path", "/.well-known/masque/udp/192.0.2.1/443/"),
        ]
    }

    #[track_caller]
    fn refused(fields: Vec<Field>) {
        let error = build_request(fields).expect_err("malformed");
        assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
        assert!(
            !error.is_connection_error(),
            "a malformed message ends the stream, not the connection"
        );
    }

    #[test]
    fn a_classic_connect_becomes_an_authority_form_request() {
        let request = build_request(connect()).expect("accepted");

        assert_eq!(request.method, Method::Connect);
        assert_eq!(request.authority.as_deref(), Some("example.com:443"));
        assert_eq!(request.scheme, None);
        assert_eq!(request.path, None);
        assert_eq!(request.query, None);
        assert_eq!(request.protocol, None);
    }

    #[test]
    fn an_extended_connect_keeps_its_protocol_scheme_and_path() {
        let request = build_request(connect_udp()).expect("accepted");

        assert_eq!(request.scheme.as_deref(), Some("https"));
        assert_eq!(
            request.path.as_deref(),
            Some("/.well-known/masque/udp/192.0.2.1/443/")
        );
        assert_eq!(request.query, None);
        assert_eq!(request.protocol.as_deref(), Some("connect-udp"));
    }

    /// The point of decoding `:protocol` as bytes: an unimplemented protocol
    /// has to reach the router, which answers it with a 501, rather than being
    /// rejected as malformed before anyone can look at it.
    #[test]
    fn an_unknown_protocol_is_accepted_so_it_can_be_answered() {
        let mut fields = connect_udp();
        fields[1] = field(":protocol", "connect-ip");

        let request = build_request(fields).expect("accepted");
        assert_eq!(request.protocol.as_deref(), Some("connect-ip"));
    }

    #[test]
    fn an_ordinary_request_is_accepted() {
        let request = build_request(vec![
            field(":method", "GET"),
            field(":scheme", "https"),
            field(":authority", "example.com"),
            field(":path", "/"),
        ])
        .expect("accepted");

        assert_eq!(request.method, Method::Other("GET".into()));
        assert_eq!(request.path.as_deref(), Some("/"));
    }

    /// RFC 9114 §4.3.1 lets the authority arrive as a Host field instead.
    #[test]
    fn host_stands_in_for_an_absent_authority() {
        let request = build_request(vec![
            field(":method", "GET"),
            field(":scheme", "https"),
            field(":path", "/"),
            field("host", "example.com"),
        ])
        .expect("accepted");

        assert_eq!(request.authority.as_deref(), Some("example.com"));
    }

    #[test]
    fn authority_and_host_must_agree() {
        refused(vec![
            field(":method", "GET"),
            field(":scheme", "https"),
            field(":authority", "one.example"),
            field(":path", "/"),
            field("host", "other.example"),
        ]);

        // A Host field that says the same thing is not a disagreement, on an
        // ordinary request or an extended CONNECT.
        let mut agreeing = connect_udp();
        agreeing.push(field("host", "proxy.example:443"));
        assert!(build_request(agreeing).is_ok());
    }

    /// A second Host field is refused rather than resolved: the check above
    /// reads one of them, and the other would be free to say anything.
    #[test]
    fn a_repeated_host_field_is_refused() {
        for second in ["one.example", "other.example"] {
            refused(vec![
                field(":method", "GET"),
                field(":scheme", "https"),
                field(":path", "/"),
                field("host", "one.example"),
                field("host", second),
            ]);
        }

        // Repeating a field that is not Host is ordinary HTTP.
        let mut repeated = connect();
        repeated.push(field("x-volto-probe", "one"));
        repeated.push(field("x-volto-probe", "two"));
        assert!(build_request(repeated).is_ok());
    }

    /// The table of malformed requests, each naming the rule it breaks.
    #[test]
    fn malformed_requests_are_refused() {
        // RFC 9114 §4.4: a classic CONNECT omits :scheme and :path.
        let mut with_path = connect();
        with_path.push(field(":path", "/"));
        refused(with_path);

        let mut with_scheme = connect();
        with_scheme.push(field(":scheme", "https"));
        refused(with_scheme);

        // RFC 9114 §4.4: and it must carry :authority.
        refused(vec![field(":method", "CONNECT")]);

        // RFC 8441 §4: an extended CONNECT needs all three.
        for missing in [":scheme", ":path", ":authority"] {
            let fields = connect_udp()
                .into_iter()
                .filter(|f| f.name.as_ref() != missing.as_bytes())
                .collect();
            refused(fields);
        }

        // RFC 9114 §4.3.1: the agreement rule holds for an extended CONNECT
        // too, where :authority is mandatory rather than optional.
        let mut disagreeing = connect_udp();
        disagreeing.push(field("host", "other.example:443"));
        refused(disagreeing);

        // RFC 9114 §4.3 with RFC 8441 §4: :protocol is defined for the
        // extended CONNECT method only, so anywhere else it is an undefined
        // pseudo-header field.
        refused(vec![
            field(":method", "GET"),
            field(":protocol", "connect-udp"),
            field(":scheme", "https"),
            field(":authority", "example.com"),
            field(":path", "/"),
        ]);

        // RFC 9114 §4.3: only the five defined pseudo-headers, each once, all
        // before any regular field, and none defined for responses.
        let mut undefined = connect();
        undefined.insert(0, field(":volto", "1"));
        refused(undefined);

        let mut status = connect();
        status.insert(0, field(":status", "200"));
        refused(status);

        let mut repeated = connect();
        repeated.push(field(":authority", "example.com:443"));
        refused(repeated);

        refused(vec![
            field(":method", "CONNECT"),
            field("user-agent", "volto-test"),
            field(":authority", "example.com:443"),
        ]);

        // RFC 9114 §4.3.1: no request at all without :method.
        refused(vec![field(":authority", "example.com:443")]);

        // RFC 9114 §4.3.1: a present pseudo-header must not be empty.
        refused(vec![field(":method", "CONNECT"), field(":authority", "")]);

        // RFC 9114 §4.2: uppercase field names, and the Connection field.
        refused(vec![
            field(":method", "CONNECT"),
            field(":authority", "example.com:443"),
            field("User-Agent", "volto-test"),
        ]);

        let mut connection = connect();
        connection.push(field("connection", "keep-alive"));
        refused(connection);

        // RFC 9114 §4.2: TE may only say "trailers".
        let mut te = connect();
        te.push(field("te", "gzip"));
        refused(te);
    }

    /// RFC 9110 §5.5: the whitespace around a field value is not part of the
    /// value, so what every reading below sees is what was sent rather than how
    /// it was padded.
    #[test]
    fn optional_whitespace_is_excluded_from_a_field_value() {
        for (padded, value) in [
            (&b" \tvalue \t"[..], &b"value"[..]),
            (b"value", b"value"),
            (b" \t ", b""),
            (b"", b""),
            // Only the ends: whitespace inside a value is part of it.
            (b" a b ", b"a b"),
        ] {
            assert_eq!(trim_optional_whitespace(padded), value, "{padded:?}");
        }

        // The field this most matters for: `auth` reads a scheme and a token,
        // and a leading space would leave it reading a scheme that is empty.
        let mut padded = connect();
        padded.push(field("proxy-authorization", " Basic dXNlcjE6czNjcmV0\t"));
        let request = build_request(padded).expect("accepted");
        assert_eq!(
            request
                .fields
                .get("proxy-authorization")
                .map(FieldValue::as_bytes),
            Some(&b"Basic dXNlcjE6czNjcmV0"[..])
        );

        // And the :authority/Host agreement of RFC 9114 §4.3.1 is judged on the
        // values rather than on their padding.
        assert!(build_request(vec![
            field(":method", "GET"),
            field(":scheme", "https"),
            field(":authority", "example.com"),
            field(":path", "/"),
            field("host", "  example.com "),
        ])
        .is_ok());
    }

    /// The one exception §4.2 makes for TE.
    #[test]
    fn te_trailers_is_allowed() {
        let mut fields = connect();
        fields.push(field("te", "trailers"));
        assert!(build_request(fields).is_ok());
    }

    /// Ordinary fields survive intact -- this is how credentials reach `auth`.
    #[test]
    fn regular_fields_reach_the_request() {
        let mut fields = connect();
        fields.push(field("proxy-authorization", "Basic dXNlcjE6czNjcmV0"));

        let request = build_request(fields).expect("accepted");
        assert_eq!(
            request
                .fields
                .get("proxy-authorization")
                .map(FieldValue::as_bytes),
            Some(&b"Basic dXNlcjE6czNjcmV0"[..])
        );
    }

    /// The query is kept apart from the path, because the CONNECT-UDP template
    /// is a rule about each (RFC 9298 §2).
    #[test]
    fn a_path_carries_its_query_separately() {
        let with_query = |path: &str| {
            let mut fields = connect_udp();
            fields[4] = field(":path", path);
            let request = build_request(fields).expect("accepted");
            (request.path.clone().expect("a path"), request.query.clone())
        };

        let (path, query) = with_query("/a/b?x=1&y=2");
        assert_eq!(&*path, "/a/b");
        assert_eq!(query.as_deref(), Some("x=1&y=2"));

        // A trailing "?" is a query that is present and empty, which is not the
        // same as one that is absent.
        let (path, query) = with_query("/a/b?");
        assert_eq!(&*path, "/a/b");
        assert_eq!(query.as_deref(), Some(""));

        let (path, query) = with_query("/a/b");
        assert_eq!(&*path, "/a/b");
        assert_eq!(query, None);
    }

    /// The pseudo-headers that name a target are checked for the characters
    /// RFC 3986 allows them, since nothing downstream would refuse the rest
    /// as loudly.
    #[test]
    fn pseudo_headers_that_name_a_target_are_checked_for_syntax() {
        let replacing = |name: &str, value: &str| {
            let mut fields = connect_udp();
            for existing in &mut fields {
                if existing.name.as_ref() == name.as_bytes() {
                    *existing = field(name, value);
                }
            }
            fields
        };

        // A scheme is ALPHA then ALPHA / DIGIT / "+" / "-" / "." (RFC 3986 §3.1).
        assert!(build_request(replacing(":scheme", "coap+tcp")).is_ok());
        for scheme in ["1https", "http s", "http/1"] {
            refused(replacing(":scheme", scheme));
        }

        // An authority is unreserved / pct-encoded / sub-delims / ":@[]"
        // (RFC 3986 §3.2); its shape is `tunnel::tcp`'s to judge, not this.
        assert!(build_request(replacing(":authority", "[2001:db8::1]:443")).is_ok());
        assert!(build_request(replacing(":authority", "user@host:443")).is_ok());
        for authority in ["proxy example:443", "proxy.example:443/", "proxy\u{7f}:443"] {
            refused(replacing(":authority", authority));
        }

        // A path is an absolute path, and a fragment is not part of a target.
        for path in ["masque/udp/", "/a b", "/a#b", "/a\u{1}b"] {
            refused(replacing(":path", path));
        }

        // A query is pchar / "/" / "?" (RFC 3986 §3.4), and "#" opens a fragment
        // there as much as it does in a path.
        assert!(build_request(replacing(":path", "/a?b=c&d=%20e")).is_ok());
        for path in ["/a?b#c", "/a?b[c", "/a?b c", "/a?b\u{1}c"] {
            refused(replacing(":path", path));
        }

        // §4.3.1's asterisk form is OPTIONS's and is not a path: an ordinary
        // request may carry it so that the answer is the 501 an unimplemented
        // method gets, and an extended CONNECT may not, because RFC 8441 §4 asks
        // it for the :path of a target URI.
        let mut options = vec![
            field(":method", "OPTIONS"),
            field(":scheme", "https"),
            field(":authority", "proxy.example:443"),
            field(":path", "*"),
        ];
        assert!(build_request(options.clone()).is_ok());
        refused(replacing(":path", "*"));

        // And an ordinary request is not thereby excused a real path.
        options[3] = field(":path", "masque/udp/");
        refused(options);
    }
}
