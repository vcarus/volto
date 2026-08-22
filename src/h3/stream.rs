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
//! [`Resolver::resolve`] is where a request becomes an [`http::Request`], and
//! where RFC 9114 §4.1.2's "malformed" verdict is reached. The rules are worth
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
use http::uri::Uri;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};

use super::connection::{DatagramReceiver, Handle};
use super::error::{Code, StreamError, Violation};
use super::frame::{self, Frame, FrameReader, Item};
use super::qpack::{self, Field};
use super::{varint, MAX_FIELD_SECTION_SIZE, MAX_VARINT};

/// The value of the `:protocol` pseudo-header (RFC 9220 §3, RFC 8441 §4).
///
/// Kept as the bytes that arrived rather than mapped onto a fixed set, so a
/// protocol this server does not implement can be answered with the 501 that
/// RFC 9220 §3 calls for instead of being rejected as malformed before anything
/// can look at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protocol(Box<str>);

impl Protocol {
    /// Wraps a `:protocol` token.
    pub(crate) fn new(token: impl Into<Box<str>>) -> Self {
        Self(token.into())
    }

    /// The token as it arrived on the wire.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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
    ) -> Result<(Request<()>, Stream), StreamError> {
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
                    .respond(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
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
async fn read_request(frames: &mut FrameReader) -> Result<Request<()>, frame::Error> {
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
fn build_request(fields: Vec<Field>) -> Result<Request<()>, Violation> {
    let mut method = None;
    let mut scheme = None;
    let mut authority = None;
    let mut path = None;
    let mut protocol = None;
    let mut headers = HeaderMap::new();
    let mut regular_field_seen = false;

    for Field { name, value } in fields {
        if !name.starts_with(b":") {
            regular_field_seen = true;
            add_field(&mut headers, &name, &value)?;
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
            b":path" => &mut path,
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
    let method = Method::from_bytes(&method).map_err(|_| malformed("an invalid :method"))?;

    // RFC 8441 §4 defines :protocol for the extended CONNECT method and for
    // nothing else, so on any other request it is a pseudo-header used outside
    // the context it was defined in.
    //
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
    //# Pseudo-header fields are only valid in the context in which they are
    //# defined. [...] Endpoints MUST treat a request or response that contains
    //# undefined or invalid pseudo-header fields as malformed.
    if protocol.is_some() && method != Method::CONNECT {
        return Err(malformed(":protocol on a request that is not CONNECT"));
    }

    let uri = if method == Method::CONNECT && protocol.is_none() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
        //# The :scheme and :path pseudo-header fields are omitted [...] The
        //# :authority pseudo-header field contains the host and port to
        //# connect to [...] A CONNECT request that does not conform to these
        //# restrictions is malformed.
        if scheme.is_some() || path.is_some() {
            return Err(malformed("a CONNECT request carrying :scheme or :path"));
        }
        let authority =
            authority.ok_or_else(|| malformed("a CONNECT request without :authority"))?;

        Uri::builder()
            .authority(nonempty(&authority, ":authority")?)
            .build()
    } else {
        // Extended CONNECT and ordinary requests are built the same way; only
        // where the authority may come from differs.
        //
        //= https://www.rfc-editor.org/rfc/rfc8441#section-4
        //# On requests that contain the :protocol pseudo-header field, the
        //# :scheme and :path pseudo-header fields of the target URI [...]
        //# MUST also be included.
        let scheme = scheme.ok_or_else(|| malformed("a request without :scheme"))?;
        let path = path.ok_or_else(|| malformed("a request without :path"))?;

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
        let authority = match (authority.as_deref(), headers.get(http::header::HOST)) {
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

        Uri::builder()
            .scheme(&scheme[..])
            .authority(nonempty(authority, ":authority")?)
            .path_and_query(nonempty(&path, ":path")?)
            .build()
    };

    let uri = uri.map_err(|_| malformed("pseudo-header fields that are not a valid URI"))?;

    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(())
        .map_err(|_| malformed("a request that cannot be represented"))?;
    *request.headers_mut() = headers;

    if let Some(protocol) = protocol {
        let protocol = std::str::from_utf8(&protocol)
            .map_err(|_| malformed("a :protocol that is not valid UTF-8"))?;
        request.extensions_mut().insert(Protocol::new(protocol));
    }

    Ok(request)
}

/// Adds one regular field, applying RFC 9114 §4.2's rules on the way.
fn add_field(headers: &mut HeaderMap, name: &[u8], value: &[u8]) -> Result<(), Violation> {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
    //# A request or response containing uppercase characters in field names
    //# MUST be treated as malformed.
    let name = HeaderName::from_lowercase(name)
        .map_err(|_| malformed("a field name that is uppercase or not a token"))?;

    //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
    //# Any request or response that contains a character not permitted in a
    //# field value MUST be treated as malformed.
    let value = HeaderValue::from_bytes(value)
        .map_err(|_| malformed("a field value with a forbidden character"))?;

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
    //# An endpoint MUST NOT generate an HTTP/3 field section containing
    //# connection-specific fields; any message containing connection-specific
    //# fields MUST be treated as malformed.
    //
    // Only the Connection field itself is enforced. RFC 9110 §7.6.1's wider
    // list -- Proxy-Connection, Keep-Alive, Transfer-Encoding, Upgrade -- is
    // deliberately left out: this proxy already answers a CONNECT-UDP request
    // carrying content framing with a 400 (RFC 9297 §3.2), which tells the
    // client rather more than a bare stream reset would, and `it_udp` pins that
    // answer.
    if name == http::header::CONNECTION {
        return Err(malformed(
            "the Connection field, which HTTP/3 has no use for",
        ));
    }

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
    //# The only exception to this is the TE header field, which MAY be
    //# present in an HTTP/3 request header; when it is, it MUST NOT contain
    //# any value other than "trailers".
    if name == http::header::TE && value.as_bytes() != b"trailers" {
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
    if name == http::header::HOST && headers.contains_key(http::header::HOST) {
        return Err(malformed("more than one Host field"));
    }

    headers.append(name, value);
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
    pub async fn respond(&mut self, status: StatusCode) -> Result<(), StreamError> {
        self.respond_with(status, HeaderMap::new()).await
    }

    /// Sends a response with `headers` and no body.
    ///
    /// Only the field lines given are sent -- nothing synthesises a
    /// Content-Length or Content-Type, both of which RFC 9297 §3.2 forbids on a
    /// capsule-carrying response.
    pub async fn respond_with(
        &mut self,
        status: StatusCode,
        headers: HeaderMap,
    ) -> Result<(), StreamError> {
        // RFC 9114 §4.3.2: `:status` is the one pseudo-header a response has,
        // and it comes before every regular field (§4.3).
        let mut block = BytesMut::new();
        qpack::encode(
            &mut block,
            std::iter::once((&b":status"[..], status.as_str().as_bytes())).chain(
                headers
                    .iter()
                    .map(|(name, value)| (name.as_str().as_bytes(), value.as_bytes())),
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

        assert_eq!(request.method(), Method::CONNECT);
        assert_eq!(
            request.uri().authority().map(|a| a.as_str()),
            Some("example.com:443")
        );
        assert!(request.uri().scheme().is_none());
        assert!(request.extensions().get::<Protocol>().is_none());
    }

    #[test]
    fn an_extended_connect_keeps_its_protocol_scheme_and_path() {
        let request = build_request(connect_udp()).expect("accepted");

        assert_eq!(request.uri().scheme_str(), Some("https"));
        assert_eq!(
            request.uri().path(),
            "/.well-known/masque/udp/192.0.2.1/443/"
        );
        assert_eq!(
            request.extensions().get::<Protocol>().map(Protocol::as_str),
            Some("connect-udp")
        );
    }

    /// The point of decoding `:protocol` as bytes: an unimplemented protocol
    /// has to reach the router, which answers it with a 501, rather than being
    /// rejected as malformed before anyone can look at it.
    #[test]
    fn an_unknown_protocol_is_accepted_so_it_can_be_answered() {
        let mut fields = connect_udp();
        fields[1] = field(":protocol", "connect-ip");

        let request = build_request(fields).expect("accepted");
        assert_eq!(
            request.extensions().get::<Protocol>().map(Protocol::as_str),
            Some("connect-ip")
        );
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

        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.uri().path(), "/");
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

        assert_eq!(
            request.uri().authority().map(|a| a.as_str()),
            Some("example.com")
        );
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
                .headers()
                .get("proxy-authorization")
                .map(|v| v.as_bytes()),
            Some(&b"Basic dXNlcjE6czNjcmV0"[..])
        );
    }
}
