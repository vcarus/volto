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

use super::connection::Handle;
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
        Self {
            handle,
            send,
            frames: FrameReader::new(recv),
        }
    }

    /// Reads and validates the request headers.
    ///
    /// On failure the stream has already been ended -- reset and stopped for a
    /// malformed request, or the whole connection closed for a frame sequence
    /// that cannot be parsed -- so the caller has nothing left to do but log it.
    pub async fn resolve(self) -> Result<(Request<()>, Stream), StreamError> {
        let Self {
            handle,
            mut send,
            mut frames,
        } = self;

        match read_request(&mut frames).await {
            Ok(request) => Ok((
                request,
                Stream {
                    handle,
                    send,
                    frames,
                    header: BytesMut::with_capacity(2 * MAX_VARINT),
                },
            )),
            Err(error) => Err(match error {
                frame::Error::Stream(error) => error,
                frame::Error::Protocol(violation) if violation.is_connection_error() => {
                    StreamError::Connection(handle.fail(violation))
                }

                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
                //# Malformed requests or responses that are detected MUST be
                //# treated as a stream error of type H3_MESSAGE_ERROR.
                frame::Error::Protocol(violation) => {
                    let _ = send.reset(varint(violation.code()));
                    frames.stop(violation.code());
                    StreamError::Local(violation)
                }
            }),
        }
    }
}

/// Reads the first frame of a request stream and turns it into a request.
async fn read_request(frames: &mut FrameReader) -> Result<Request<()>, frame::Error> {
    let block = match frames.next().await? {
        Some(Item::Frame(Frame::Headers(block))) => block,

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
        //# Receipt of an invalid sequence of frames MUST be treated as a
        //# connection error of type H3_FRAME_UNEXPECTED.
        Some(_) => {
            return Err(Violation::connection(
                Code::H3_FRAME_UNEXPECTED,
                "a request stream that does not begin with HEADERS",
            )
            .into())
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
        //# If a client-initiated stream terminates without enough of the HTTP
        //# message to provide a complete response, the server SHOULD abort its
        //# response stream with the error code H3_REQUEST_INCOMPLETE.
        //
        // A SHOULD, and this server takes it: the RESET_STREAM that
        // `Resolver::resolve` sends for a stream-class violation is that abort.
        None => {
            return Err(Violation::stream(
                Code::H3_REQUEST_INCOMPLETE,
                "the request stream ended before its HEADERS frame",
            )
            .into())
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
        let scheme = scheme.ok_or_else(|| malformed("a request without :scheme"))?;
        let path = path.ok_or_else(|| malformed("a request without :path"))?;

        let authority = if protocol.is_some() {
            //= https://www.rfc-editor.org/rfc/rfc8441#section-4
            //# On requests that contain the :protocol pseudo-header field, the
            //# :scheme and :path pseudo-header fields of the target URI [...]
            //# MUST also be included.
            authority
                .as_deref()
                .ok_or_else(|| malformed("an extended CONNECT request without :authority"))?
        } else {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If the :scheme pseudo-header field identifies a scheme that has a
            //# mandatory authority component [...] the request MUST contain
            //# either an :authority pseudo-header field or a Host header field.
            //# If these fields are present, they MUST NOT be empty. If both
            //# fields are present, they MUST contain the same value.
            match (authority.as_deref(), headers.get(http::header::HOST)) {
                (Some(authority), None) => authority,
                (None, Some(host)) => host.as_bytes(),
                (Some(authority), Some(host)) if authority != host.as_bytes() => {
                    return Err(malformed(":authority and Host disagree"))
                }
                (Some(authority), Some(_)) => authority,
                (None, None) => {
                    return Err(malformed("a request with neither :authority nor Host"))
                }
            }
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
    pub async fn finish(&mut self) -> Result<(), StreamError> {
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

    /// Ends the sending side cleanly (a QUIC stream FIN).
    pub async fn finish(&mut self) -> Result<(), StreamError> {
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
    fn report(&mut self, error: frame::Error) -> StreamError {
        match error {
            frame::Error::Stream(error) => error,
            frame::Error::Protocol(violation) if violation.is_connection_error() => {
                StreamError::Connection(self.handle.fail(violation))
            }
            // Only the receiving half is here; whether the response side is also
            // reset is the caller's decision, and the tunnels make it
            // differently for a client abort than for a target failure.
            frame::Error::Protocol(violation) => {
                self.frames.stop(violation.code());
                StreamError::Local(violation)
            }
        }
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
