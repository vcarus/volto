//! One request stream, from its HEADERS frame to its last byte.
//!
//! # Reading
//!
//! A request stream carries HEADERS, then a body of DATA frames, then an
//! optional trailer section (RFC 9114 §4.1). Only the first of those is
//! buffered: the body is handed on in the chunks it arrived in, because for this
//! server the body *is* the tunnel and every copy of it would be paid for per
//! packet.
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
        let frames = FrameReader::new(recv, handle.budget());
        Self {
            handle,
            send,
            frames,
        }
    }

    /// Reads and validates the request headers, giving up after `within`.
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
    /// PINGs are being answered by its stack, so without `within` each such
    /// stream parks a task until the connection ends -- `max_streams_bidi` of
    /// them per connection, at a byte apiece, from a peer that has not
    /// authenticated (D76).
    ///
    /// The stream is the only thing a lapsed deadline ends: it is reset and
    /// stopped, and the connection carries on serving everything else on it.
    pub async fn resolve(
        self,
        within: std::time::Duration,
    ) -> Result<(Request, Stream), StreamError> {
        let Self {
            handle,
            mut send,
            mut frames,
        } = self;

        let read = match tokio::time::timeout(within, read_request(&mut frames)).await {
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

        match read {
            Ok(request) => Ok((
                request,
                Stream {
                    handle,
                    send,
                    frames,
                    header: BytesMut::with_capacity(2 * MAX_VARINT),
                },
            )),
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
            // H3_EXCESSIVE_LOAD reaches this arm only as a stream-class
            // violation, which is what both of its stream-class sources are:
            // the per-frame buffering limit and a field section that decoded
            // past what `SETTINGS_MAX_FIELD_SECTION_SIZE` told the peer to
            // send, the same 64 KiB either way. The connection-wide buffering
            // budget (D77) carries the same code as a connection-class
            // violation, and that one is `answer`'s.
            Err(frame::Error::Protocol(violation))
                if violation.code() == Code::H3_EXCESSIVE_LOAD
                    && !violation.is_connection_error() =>
            {
                let mut stream = Stream {
                    handle,
                    send,
                    frames,
                    header: BytesMut::with_capacity(2 * MAX_VARINT),
                };
                let _ = stream
                    .respond(Status::REQUEST_HEADER_FIELDS_TOO_LARGE)
                    .await;
                let _ = stream.finish();
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
            Err(error) => Err(answer(&handle, &mut frames, Some(&mut send), error)),
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

            // RFC 9114 §4.1's rule about an invalid sequence of frames, quoted
            // in full on `Reader::recv_data`, where the rest of a request
            // stream's frame order is judged.
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
fn build_request(section: Vec<Field>) -> Result<Request, Violation> {
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

        (
            None,
            Some(uri_authority(nonempty(&authority, ":authority")?)?.into()),
            None,
            None,
        )
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

        let (path, query) = split_target(nonempty(&target, ":path")?)?;
        (
            Some(uri_scheme(nonempty(&scheme, ":scheme")?)?.into()),
            Some(uri_authority(nonempty(named, ":authority")?)?.into()),
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
fn split_target(target: &[u8]) -> Result<(&str, Option<&str>), Violation> {
    // §4.3.1's asterisk form, which belongs to OPTIONS. This server answers such
    // a request with the 501 every method it does not implement gets, and can
    // only do so if the request is not malformed first.
    if target == b"*" {
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

    //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
    //# Any request or response that contains a character not permitted in a
    //# field value MUST be treated as malformed.
    let value = FieldValue::parse(value)
        .ok_or_else(|| malformed("a field value with a forbidden character"))?;

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
    //# An endpoint MUST NOT generate an HTTP/3 field section containing
    //# connection-specific fields; any message containing connection-specific
    //# fields MUST be treated as malformed.
    //
    // Only the Connection field itself is refused here, with the stream reset
    // a malformed request gets. RFC 9110 §7.6.1's wider list -- Proxy-Connection,
    // Keep-Alive, Transfer-Encoding, Upgrade -- is judged in
    // `crate::tunnel::connection_specific_field`, where the answer can be a 400
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

/// Rejects an empty pseudo-header value (RFC 9114 §4.3.1).
fn nonempty<'a>(value: &'a [u8], field: &'static str) -> Result<&'a [u8], Violation> {
    if value.is_empty() {
        return Err(malformed(Cow::Owned(format!("an empty {field}"))));
    }
    Ok(value)
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

    /// Sends a response consisting of just a status line.
    ///
    /// A 2xx response to CONNECT must not carry Content-Length or
    /// Transfer-Encoding (RFC 9114 §4.4); this sends no field lines at all.
    pub async fn respond(&mut self, status: Status) -> Result<(), StreamError> {
        self.respond_with(status, Fields::new()).await
    }

    /// Sends a response with `fields` and no body.
    ///
    /// Only the field lines given are sent -- nothing synthesises a
    /// Content-Length or Content-Type, both of which RFC 9297 §3.2 forbids on a
    /// capsule-carrying response.
    pub async fn respond_with(
        &mut self,
        status: Status,
        fields: Fields,
    ) -> Result<(), StreamError> {
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

    /// Splits the stream so each direction can be pumped independently.
    ///
    /// This is what makes TCP half-close expressible: one direction can finish
    /// while the other keeps flowing.
    pub fn split(self) -> (Writer, Reader) {
        (
            Writer {
                send: self.send,
                header: self.header,
            },
            Reader {
                handle: self.handle,
                frames: self.frames,
                trailers: false,
            },
        )
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
    /// Whether a trailer section has been received (RFC 9114 §4.1).
    trailers: bool,
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
                // The frame is still a DATA frame for the rule below.
                Item::Data(data) if !self.trailers && data.is_empty() => {}

                Item::Data(data) if !self.trailers => return Ok(Some(data)),

                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                //# Receipt of an invalid sequence of frames MUST be treated as a
                //# connection error of type H3_FRAME_UNEXPECTED. In
                //# particular, a DATA frame before any HEADERS frame, or a
                //# HEADERS or DATA frame after the trailing HEADERS frame, is
                //# considered invalid.
                Item::Data(_) => {
                    return Err(self.report(
                        Violation::connection(
                            Code::H3_FRAME_UNEXPECTED,
                            "a DATA frame after the trailer section",
                        )
                        .into(),
                    ))
                }

                // The trailer section. Its fields are of no use to a tunnel --
                // there is no representation for them to describe -- so they are
                // accepted and dropped, and only the end of the stream may
                // follow.
                Item::Frame(Frame::Headers(_)) if !self.trailers => self.trailers = true,

                Item::Frame(Frame::Headers(_)) => {
                    return Err(self.report(
                        Violation::connection(
                            Code::H3_FRAME_UNEXPECTED,
                            "a second trailer section",
                        )
                        .into(),
                    ))
                }

                Item::Frame(_) => {
                    return Err(self.report(
                        Violation::connection(
                            Code::H3_FRAME_UNEXPECTED,
                            "a frame that may not appear on a request stream",
                        )
                        .into(),
                    ))
                }
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
        assert!(build_request(replacing(":path", "*")).is_ok());
        for path in ["masque/udp/", "/a b", "/a#b", "/a\u{1}b"] {
            refused(replacing(":path", path));
        }
    }
}
