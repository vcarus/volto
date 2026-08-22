//! A minimal HTTP/3 client for driving the server under test.
//!
//! It replaces the `h3` / `h3-quinn` client the suite used until the HTTP/3
//! layer moved into this tree, and it is built on the same codec the server is:
//! [`volto::h3::frame`] for framing, [`volto::h3::qpack`] for field sections,
//! [`volto::h3::error`] for the codes. Only the client *behaviour* on top of
//! them is written here -- which pseudo-headers a request carries, what a
//! response is decoded into, which streams are opened on connection setup.
//!
//! # What this costs, and where it is paid back
//!
//! Sharing a codec with the server means the two ends can no longer disagree
//! about the bytes: a mistake in the frame or QPACK layer is a mistake both
//! sides make, and this suite would not see it. That check has one home, and it
//! is the `interop` job in CI, which starts a real `volto` process and drives it
//! with Go's [masque-go](https://github.com/quic-go/masque-go) on quic-go --
//! an implementation that shares neither code nor a reading of the RFCs with
//! this one. Removing the last independent client from `cargo test` makes that
//! job more load-bearing than it was, not less.
//!
//! What the suite still asserts with full force is everything *above* the
//! codec, which is where a proxy's behaviour lives: statuses, `Proxy-Status`,
//! half-close, which error code a reset carries, when a stream is finished
//! rather than reset. None of that is shared with the server -- the server
//! decides it and this client only observes it -- and `it_settings` still
//! decodes the server's SETTINGS from raw QUIC bytes with a varint reader of
//! its own, so the one frame Surge disconnects over is read independently even
//! here.
//!
//! # Wire behaviour that is deliberately h3's
//!
//! Several tests pin what happens to a stream that is abandoned, so this client
//! reproduces what the `h3` client did rather than what is tidiest:
//!
//! * [`ClientStream::stop_stream`] resets the **sending** side only, exactly as
//!   `h3::client::RequestStream::stop_stream` did (`self.stream.reset(code)`).
//! * [`ClientStream`] has no `Drop` of its own, because neither `h3` nor
//!   `h3-quinn` had one: what a dropped request stream puts on the wire was
//!   always plain quinn's doing -- the send side is finished (or, if the peer
//!   had stopped it, reset with the peer's code) and the receive side sends
//!   `STOP_SENDING(0)` unless every byte had already been read. Holding
//!   `quinn::SendStream` and `quinn::RecvStream` directly is what keeps that
//!   true without a line of code.
//! * A request whose field section is larger than the server's advertised
//!   `SETTINGS_MAX_FIELD_SECTION_SIZE` is refused *after* the stream has been
//!   opened, which is where `h3` refused it: the server sees a request stream
//!   that ends without a HEADERS frame, and must treat that as a stream error
//!   rather than a connection one.

#![allow(dead_code)] // Each integration test binary uses a subset of this.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use quinn::VarInt;
use rustls::pki_types::CertificateDer;
use tokio::task::{JoinHandle, JoinSet};

use volto::datagram::{peek_varint, put_varint};
use volto::h3::error::Violation;
use volto::h3::frame::{self, Frame, FrameReader, Item};
use volto::h3::qpack::{self, Field};
use volto::h3api::{Code, StreamError};

use super::{client_endpoint_with_stream_window, connect_quic, connect_quic_with_ca};
use super::{TestServer, TIMEOUT};

/// Unidirectional stream types this client opens (RFC 9114 §6.2, RFC 9204 §4.2).
const STREAM_CONTROL: u64 = 0x00;
const STREAM_QPACK_ENCODER: u64 = 0x02;
const STREAM_QPACK_DECODER: u64 = 0x03;

/// Largest control-stream frame payload this client will buffer.
///
/// The server's SETTINGS and GOAWAY are a few dozen bytes; anything claiming
/// more is not worth allocating for in a test harness.
const MAX_CONTROL_FRAME: u64 = 64 * 1024;

/// The value of the `:protocol` pseudo-header, as a request extension.
///
/// The same role `h3::ext::Protocol` played: `http::Request` has no field for a
/// pseudo-header, so extended CONNECT carries it in the extensions map and
/// [`SendRequest::send_request`] reads it back out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protocol(pub &'static str);

impl Protocol {
    /// The `:protocol` token of RFC 9298's CONNECT-UDP.
    pub const CONNECT_UDP: Self = Self("connect-udp");
}

/// What the server told this client in its SETTINGS and GOAWAY.
///
/// Written by the connection task, read by [`SendRequest::send_request`]. Both
/// values change the client's own behaviour, which is why they are kept at all:
/// everything else the server advertises is validated by the codec and dropped.
#[derive(Debug)]
struct Peer {
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`, or no limit until it arrives.
    ///
    /// RFC 9114 §4.2.2: "An implementation that has received this parameter
    /// SHOULD NOT send an HTTP message header that exceeds the indicated size."
    max_field_section_size: AtomicU64,
    /// Whether the server has sent GOAWAY (RFC 9114 §5.2).
    closing: AtomicBool,
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            max_field_section_size: AtomicU64::new(u64::MAX),
            closing: AtomicBool::new(false),
        }
    }
}

/// An HTTP/3 client with its connection driven in the background.
pub struct H3Client {
    /// Handle used to open requests.
    pub send: SendRequest,
    /// The underlying QUIC connection.
    ///
    /// HTTP Datagrams are a QUIC facility rather than an HTTP/3 one, so tests
    /// drive them through quinn directly, exactly as the server does.
    pub quic: quinn::Connection,
    // Both are kept alive for as long as the client is: dropping the endpoint or
    // stopping the driver would tear the connection down.
    _endpoint: quinn::Endpoint,
    /// This client's control and QPACK streams.
    ///
    /// Held, never written to again. RFC 9114 §6.2.1 makes closing the control
    /// stream a connection error of type H3_CLOSED_CRITICAL_STREAM, and a
    /// dropped [`quinn::SendStream`] finishes -- so letting go of this array is
    /// the same thing as breaking the connection.
    _streams: [quinn::SendStream; 3],
    driver: JoinHandle<()>,
}

impl H3Client {
    /// Connects and completes the HTTP/3 handshake, advertising datagram support.
    pub async fn connect(server: &TestServer) -> Self {
        Self::connect_with_datagrams(server, true).await
    }

    /// Connects while trusting `ca` rather than the server's original certificate.
    pub async fn connect_with_ca(server: &TestServer, ca: CertificateDer<'static>) -> Self {
        let (endpoint, connection) = connect_quic_with_ca(server, ca).await;
        Self::from_quic(endpoint, connection, true).await
    }

    /// Connects without advertising `SETTINGS_H3_DATAGRAM`.
    ///
    /// RFC 9297 §2.1.1 then forbids the server from sending QUIC datagrams, so
    /// the session has to fall back to DATAGRAM capsules on the request stream.
    pub async fn connect_without_datagrams(server: &TestServer) -> Self {
        Self::connect_with_datagrams(server, false).await
    }

    /// [`H3Client::connect_without_datagrams`] with a per-stream receive window
    /// of `window` bytes, so a server writing capsules blocks after that much.
    pub async fn connect_without_datagrams_with_stream_window(
        server: &TestServer,
        window: u32,
    ) -> Self {
        let endpoint = client_endpoint_with_stream_window(&server.ca, &["h3"], window);
        let connection = tokio::time::timeout(
            TIMEOUT,
            endpoint
                .connect(server.addr, "localhost")
                .expect("start connecting"),
        )
        .await
        .expect("handshake did not time out")
        .expect("handshake");

        Self::from_quic(endpoint, connection, false).await
    }

    async fn connect_with_datagrams(server: &TestServer, datagrams: bool) -> Self {
        let (endpoint, connection) = connect_quic(server).await;
        Self::from_quic(endpoint, connection, datagrams).await
    }

    /// Moves the client onto a fresh local socket while the connection lives
    /// on — the address change a phone produces when it hops networks. The
    /// server must treat it as a QUIC migration (RFC 9000 §9), not a new peer.
    pub fn rebind(&self) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a fresh client socket");
        self._endpoint
            .rebind(socket)
            .expect("rebind the client endpoint");
    }

    /// Opens a request stream and sends the request's HEADERS frame.
    ///
    /// The same shape as `client.send.send_request(..)`, for call sites that
    /// have the client rather than its sender.
    pub async fn send_request(
        &mut self,
        request: Request<()>,
    ) -> Result<ClientStream, StreamError> {
        self.send.send_request(request).await
    }

    /// Performs the client half of the HTTP/3 handshake on a live connection.
    async fn from_quic(
        endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        datagrams: bool,
    ) -> Self {
        // The control stream first, so a server reading streams in the order
        // they arrive sees SETTINGS before anything else.
        let mut control = connection
            .open_uni()
            .await
            .expect("open the client control stream");
        control
            .write_all(&control_preface(datagrams))
            .await
            .expect("send the client SETTINGS");

        // Nothing is ever written to these beyond their type: with a zero table
        // capacity there are no QPACK instructions to send. They exist because
        // every deployed client opens them, so the server is driven the way a
        // real one drives it.
        let encoder = open_typed(&connection, STREAM_QPACK_ENCODER).await;
        let decoder = open_typed(&connection, STREAM_QPACK_DECODER).await;

        let peer = Arc::new(Peer::default());
        let driver = tokio::spawn(drive(connection.clone(), peer.clone()));

        Self {
            send: SendRequest {
                quic: connection.clone(),
                peer,
            },
            quic: connection,
            _endpoint: endpoint,
            _streams: [control, encoder, decoder],
            driver,
        }
    }
}

impl Drop for H3Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// Opens requests on one connection.
///
/// Named for the `h3` handle it replaces, and reached the same way
/// (`client.send.send_request(..)`).
pub struct SendRequest {
    quic: quinn::Connection,
    peer: Arc<Peer>,
}

impl SendRequest {
    /// Opens a request stream and sends the request as one HEADERS frame.
    ///
    /// Fails without touching the network once the server has sent GOAWAY: RFC
    /// 9114 §5.2 says requests from there on are rejected, and a client that
    /// keeps sending them learns nothing.
    pub async fn send_request(
        &mut self,
        request: Request<()>,
    ) -> Result<ClientStream, StreamError> {
        if self.peer.closing.load(Ordering::Relaxed) {
            return Err(StreamError::Local(Violation::stream(
                Code::H3_REQUEST_REJECTED,
                "the server has sent GOAWAY",
            )));
        }

        let fields = request_fields(&request);

        let (mut send, recv) = self
            .quic
            .open_bi()
            .await
            .map_err(|error| StreamError::Connection(error.into()))?;
        let id = u64::from(send.id());

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //# An HTTP implementation MUST NOT send frames or requests that would be
        //# invalid based on its current understanding of the peer's settings.
        //
        // Checked after the stream is opened, which is where `h3` checked it:
        // the stream is then dropped unsent, and the server has to answer a
        // request stream that ends before its HEADERS frame.
        let size = section_size(&fields);
        let allowed = self.peer.max_field_section_size.load(Ordering::Relaxed);
        if size > allowed {
            return Err(StreamError::Local(Violation::stream(
                Code::H3_EXCESSIVE_LOAD,
                format!("a {size}-byte field section past the advertised {allowed}"),
            )));
        }

        let mut block = BytesMut::new();
        qpack::encode(
            &mut block,
            fields.iter().map(|(name, value)| (&name[..], &value[..])),
        );

        let mut header = BytesMut::new();
        frame::put_header(&mut header, frame::HEADERS, block.len() as u64);
        let mut chunks = [header.freeze(), block.freeze()];
        send.write_all_chunks(&mut chunks).await?;

        Ok(ClientStream {
            send,
            frames: FrameReader::new(recv),
            id,
            header: BytesMut::new(),
            trailers: false,
        })
    }
}

/// One request stream, from its HEADERS frame to its last byte.
///
/// Deliberately without a `Drop`: see the module documentation.
pub struct ClientStream {
    send: quinn::SendStream,
    frames: FrameReader,
    id: u64,
    /// Scratch for DATA frame headers, reused across frames.
    header: BytesMut,
    /// Whether a trailer section has been received (RFC 9114 §4.1).
    trailers: bool,
}

impl ClientStream {
    /// The QUIC stream id.
    ///
    /// The Quarter Stream ID of RFC 9297 is this value divided by four.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Reads the response, which is the first frame the server sends.
    pub async fn recv_response(&mut self) -> Result<Response<()>, StreamError> {
        let block = loop {
            match self.frames.next().await.map_err(convert)? {
                Some(Item::Frame(Frame::Headers(block))) => break block,

                //= https://www.rfc-editor.org/rfc/rfc9114#section-9
                //# Implementations MUST ignore unknown or unsupported values in
                //# all extensible protocol elements.
                Some(Item::Skipped { .. }) => {}

                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                //# Receipt of an invalid sequence of frames MUST be treated as a
                //# connection error of type H3_FRAME_UNEXPECTED.
                Some(_) => return Err(unexpected("a response that does not begin with HEADERS")),
                None => return Err(unexpected("a stream that ended before the response")),
            }
        };

        // No limit: this client advertises none, so nothing the server sends can
        // be too large for it. `MAX_FIELD_SECTION_SIZE` is the *server's* bound
        // and `it_settings` asserts it on the wire rather than through this.
        let fields = qpack::decode(&block, u64::MAX).map_err(StreamError::Local)?;
        build_response(fields)
    }

    /// Reads the next chunk of the response body, or `None` at its end.
    ///
    /// Cancel-safe, because [`FrameReader::next`] is: every byte read is
    /// accounted for before this returns, so the tests may poll it inside a
    /// `select!` or a timeout and try again.
    pub async fn recv_data(&mut self) -> Result<Option<Bytes>, StreamError> {
        loop {
            match self.frames.next().await.map_err(convert)? {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-9
                //# Implementations MUST ignore unknown or unsupported values in
                //# all extensible protocol elements.
                Some(Item::Skipped { .. }) => {}

                // An empty DATA frame carries nothing, and `Some(empty)` is not
                // how a reader of a tunnel spells that: it keeps reading. The
                // frame is still a DATA frame for the rule below.
                Some(Item::Data(data)) if !self.trailers && data.is_empty() => {}

                Some(Item::Data(data)) if !self.trailers => return Ok(Some(data)),
                Some(Item::Data(_)) => {
                    return Err(unexpected("a DATA frame after the trailer section"))
                }

                // The trailer section. A tunnel has no use for its fields --
                // there is no representation for them to describe -- so they are
                // accepted and dropped, and only the end of the stream may
                // follow.
                Some(Item::Frame(Frame::Headers(_))) if !self.trailers => self.trailers = true,
                Some(Item::Frame(Frame::Headers(_))) => {
                    return Err(unexpected("a second trailer section"))
                }
                Some(Item::Frame(_)) => {
                    return Err(unexpected(
                        "a frame that may not appear on a request stream",
                    ))
                }

                None => return Ok(None),
            }
        }
    }

    /// Sends body data as one DATA frame.
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
    ///
    /// The receiving side is left alone, which is what
    /// `h3::client::RequestStream::stop_stream` did: dropping the stream is
    /// what sends `STOP_SENDING`, and the tests that reset a tunnel drop it
    /// immediately afterwards.
    pub fn stop_stream(&mut self, code: Code) {
        // Fails only if the stream is already finished or reset, which needs no
        // reporting: either way nothing more will be sent on it.
        let _ = self.send.reset(varint(code));
    }

    /// Asks the server to stop sending on this stream.
    pub fn stop_sending(&mut self, code: Code) {
        self.frames.stop(code);
    }
}

/// Turns a request into the field lines that carry it (RFC 9114 §4.3).
///
/// Pseudo-headers first and in a fixed order, then the regular fields in the
/// order they were set. Which pseudo-headers appear depends on the request:
///
/// * classic CONNECT carries `:method` and `:authority` and nothing else
///   (RFC 9114 §4.4);
/// * extended CONNECT adds `:scheme`, `:path` and `:protocol` (RFC 8441 §4);
/// * every other method carries the usual four.
fn request_fields(request: &Request<()>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let uri = request.uri();
    let protocol = request.extensions().get::<Protocol>();
    let mut fields = vec![(
        b":method".to_vec(),
        request.method().as_str().as_bytes().to_vec(),
    )];

    let mut push = |name: &[u8], value: &[u8]| fields.push((name.to_vec(), value.to_vec()));

    if request.method() != Method::CONNECT || protocol.is_some() {
        // `https` unless the URI says otherwise: the tests address the proxy by
        // an origin-form URI, and a request with no `:scheme` is malformed.
        let scheme = uri.scheme_str().unwrap_or("https");
        push(b":scheme", scheme.as_bytes());
    }

    if let Some(authority) = uri.authority() {
        push(b":authority", authority.as_str().as_bytes());
    }

    if request.method() != Method::CONNECT || protocol.is_some() {
        let path = uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        push(b":path", path.as_bytes());
    }

    if let Some(Protocol(protocol)) = protocol {
        push(b":protocol", protocol.as_bytes());
    }

    for (name, value) in request.headers() {
        push(name.as_str().as_bytes(), value.as_bytes());
    }

    fields
}

/// The size of a field section as RFC 9114 §4.2.2 defines it.
///
/// "The size of a field list is calculated based on the uncompressed size of
/// fields, including the length of the name and value in bytes plus an overhead
/// of 32 bytes for each field."
fn section_size(fields: &[(Vec<u8>, Vec<u8>)]) -> u64 {
    fields
        .iter()
        .map(|(name, value)| name.len() as u64 + value.len() as u64 + 32)
        .sum()
}

/// Turns a decoded field section into a response.
fn build_response(fields: Vec<Field>) -> Result<Response<()>, StreamError> {
    let mut status = None;
    let mut headers = HeaderMap::new();

    for Field { name, value } in fields {
        if name.starts_with(b":") {
            if &name[..] != b":status" {
                return Err(malformed("a response pseudo-header other than :status"));
            }
            if status.is_some() {
                return Err(malformed("a repeated :status"));
            }
            status =
                Some(StatusCode::from_bytes(&value).map_err(|_| malformed("an invalid :status"))?);
            continue;
        }

        let name = HeaderName::from_bytes(&name).map_err(|_| malformed("an invalid field name"))?;
        let value =
            HeaderValue::from_bytes(&value).map_err(|_| malformed("an invalid field value"))?;
        headers.append(name, value);
    }

    let mut response = Response::new(());
    *response.status_mut() = status.ok_or_else(|| malformed("a response without :status"))?;
    *response.headers_mut() = headers;
    *response.version_mut() = http::Version::HTTP_3;
    Ok(response)
}

/// The bytes of this client's control stream: its type, then SETTINGS.
///
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL` is sent because the requests that follow
/// are extended CONNECT ones; the QPACK pair is sent as zeroes because this
/// client, like the server, has no dynamic table and so must forbid the peer's
/// encoder from using one (RFC 9204 §3.2.3, §2.1.2). The grease pair is there to
/// exercise RFC 9114 §7.2.4's rule that unknown identifiers are ignored on every
/// connection this suite opens.
fn control_preface(datagrams: bool) -> Vec<u8> {
    /// One reserved identifier of the form 0x1f * N + 0x21 (RFC 9114 §7.2.4.1).
    const GREASE: u64 = 0x1f * 5 + 0x21;

    let mut settings = BytesMut::new();
    for (identifier, value) in [
        (frame::SETTING_QPACK_MAX_TABLE_CAPACITY, 0),
        (frame::SETTING_QPACK_BLOCKED_STREAMS, 0),
        (frame::SETTING_ENABLE_CONNECT_PROTOCOL, 1),
        // Sent as an explicit 0 rather than left out: RFC 9297 §2.1.1 gives the
        // two the same meaning, and the explicit form also proves the server
        // reads the value rather than the identifier's presence.
        (frame::SETTING_H3_DATAGRAM, u64::from(datagrams)),
        (GREASE, 0),
    ] {
        put_varint(&mut settings, identifier);
        put_varint(&mut settings, value);
    }

    let mut preface = BytesMut::new();
    put_varint(&mut preface, STREAM_CONTROL);
    frame::put_header(&mut preface, frame::SETTINGS, settings.len() as u64);
    preface.extend_from_slice(&settings);
    preface.to_vec()
}

/// Opens a unidirectional stream and writes its type (RFC 9114 §6.2).
async fn open_typed(connection: &quinn::Connection, stream_type: u64) -> quinn::SendStream {
    let mut send = connection
        .open_uni()
        .await
        .expect("open a unidirectional stream");

    let mut header = BytesMut::new();
    put_varint(&mut header, stream_type);
    send.write_all(&header)
        .await
        .expect("write the stream type");

    send
}

/// Accepts the server's unidirectional streams for the life of the connection.
///
/// The control stream is read for as long as it lasts, which is not optional:
/// RFC 9114 §6.2.1 forbids a receiver from asking the sender to close it, and a
/// dropped [`quinn::RecvStream`] sends `STOP_SENDING`. It is also where the two
/// pieces of server state this client acts on come from.
async fn drive(quic: quinn::Connection, peer: Arc<Peer>) {
    let mut streams = JoinSet::new();

    while let Ok(recv) = quic.accept_uni().await {
        while streams.try_join_next().is_some() {}
        streams.spawn(serve_uni(recv, peer.clone()));
    }
}

/// Dispatches one of the server's unidirectional streams by its type.
async fn serve_uni(mut recv: quinn::RecvStream, peer: Arc<Peer>) {
    match read_varint(&mut recv).await {
        Some(STREAM_CONTROL) => read_control(recv, peer).await,
        // QPACK streams and anything else: drained rather than stopped, so the
        // server never sees this client refuse a stream it opened.
        Some(_) | None => drain(recv).await,
    }
}

/// Reads the server's control stream until the connection ends.
async fn read_control(mut recv: quinn::RecvStream, peer: Arc<Peer>) {
    loop {
        let (Some(kind), Some(length)) =
            (read_varint(&mut recv).await, read_varint(&mut recv).await)
        else {
            return;
        };
        if length > MAX_CONTROL_FRAME {
            return;
        }

        let mut payload = vec![0u8; length as usize];
        if recv.read_exact(&mut payload).await.is_err() {
            return;
        }

        match kind {
            frame::SETTINGS => {
                if let Some(size) = max_field_section_size(&payload) {
                    peer.max_field_section_size.store(size, Ordering::Relaxed);
                }
            }
            //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
            //# Requests or pushes with the indicated identifier or greater are
            //# rejected (Section 4.1.1) by the sender of the GOAWAY.
            //
            // Every request this client could still open would be past it: the
            // identifier is the next stream it has not used yet.
            frame::GOAWAY => peer.closing.store(true, Ordering::Relaxed),
            _ => {}
        }
    }
}

/// Reads `SETTINGS_MAX_FIELD_SECTION_SIZE` out of a SETTINGS payload.
///
/// Decoded here rather than through [`volto::h3::frame`], whose parser keeps
/// only the one setting the *server* acts on. Everything the server sends is
/// still validated by that parser -- on the server's own connections, and in
/// `it_settings`, which decodes these bytes independently of both.
fn max_field_section_size(mut payload: &[u8]) -> Option<u64> {
    while !payload.is_empty() {
        let (identifier, used) = peek_varint(payload)?;
        payload = &payload[used..];
        let (value, used) = peek_varint(payload)?;
        payload = &payload[used..];

        if identifier == frame::SETTING_MAX_FIELD_SECTION_SIZE {
            return Some(value);
        }
    }

    None
}

/// Reads one QUIC variable-length integer from a stream (RFC 9000 §16).
async fn read_varint(recv: &mut quinn::RecvStream) -> Option<u64> {
    let mut first = [0u8; 1];
    recv.read_exact(&mut first).await.ok()?;

    // The two most significant bits encode the length as a power of two.
    let length = 1usize << (first[0] >> 6);
    let mut value = u64::from(first[0] & 0x3f);

    let mut tail = vec![0u8; length - 1];
    recv.read_exact(&mut tail).await.ok()?;
    for byte in tail {
        value = (value << 8) | u64::from(byte);
    }

    Some(value)
}

/// Reads a stream to its end, discarding everything on it.
async fn drain(mut recv: quinn::RecvStream) {
    while let Ok(Some(_)) = recv.read_chunk(usize::MAX, true).await {}
}

/// An HTTP/3 error code as the QUIC application error code that carries it.
fn varint(code: Code) -> VarInt {
    VarInt::from_u64(code.value()).unwrap_or(VarInt::MAX)
}

/// Reports a frame-layer failure as a stream error.
fn convert(error: frame::Error) -> StreamError {
    match error {
        frame::Error::Stream(error) => error,
        frame::Error::Protocol(violation) => StreamError::Local(violation),
    }
}

/// A frame the server may not have sent here (RFC 9114 §4.1).
fn unexpected(detail: &'static str) -> StreamError {
    StreamError::Local(Violation::connection(Code::H3_FRAME_UNEXPECTED, detail))
}

/// A response this client will not accept (RFC 9114 §4.1.2).
fn malformed(detail: &'static str) -> StreamError {
    StreamError::Local(Violation::stream(Code::H3_MESSAGE_ERROR, detail))
}
