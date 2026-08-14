//! Convergence layer over `h3` / `h3-quinn`.
//!
//! This is the **only** module that may name types from `h3` or `h3-quinn`.
//! Everything else in the crate goes through the wrappers below, so swapping the
//! HTTP/3 implementation (the planned fallback is `quiche`) means rewriting this
//! file and nothing else.
//!
//! Types that are not HTTP/3-specific — `http::Request`, `http::StatusCode`,
//! `bytes::Bytes` — are passed through unchanged; isolating those would buy
//! nothing.
//!
//! One deliberate exception: HTTP Datagrams (RFC 9297) are sent and received
//! straight through `quinn::Connection`, not through this module. They are a QUIC
//! transport facility rather than an `h3` one, and `h3-datagram` is excluded on
//! purpose (see `Cargo.toml`). A backend swap therefore has to port the datagram
//! task in `conn.rs` as well as this file.

use bytes::{Buf, Bytes};
use http::{HeaderMap, Request, Response, StatusCode};

/// Largest header section this server will decode, in bytes.
///
/// `h3` defaults this to `VarInt::MAX`, i.e. no limit, which means an
/// unauthenticated peer's header block is buffered and QPACK-decoded in full
/// before we can look at it. A CONNECT request's headers are a couple of hundred
/// bytes, so 64 KiB is three hundred times the room anything legitimate needs.
///
/// The value is also advertised in SETTINGS, so a well-behaved client will not
/// send more in the first place.
const MAX_FIELD_SECTION_SIZE: u64 = 64 * 1024;

/// The buffer type carried over HTTP/3 streams.
pub type Buffer = Bytes;

/// Error affecting a single request stream.
pub type StreamError = h3::error::StreamError;

/// Error affecting the whole HTTP/3 connection.
pub type ConnectionError = h3::error::ConnectionError;

/// An HTTP/3 error code.
pub type Code = h3::error::Code;

/// No error — a clean teardown.
pub const NO_ERROR: Code = Code::H3_NO_ERROR;

/// The proxy's connection to the target failed or was reset (RFC 9114 §8.1).
pub const CONNECT_ERROR: Code = Code::H3_CONNECT_ERROR;

/// The peer sent something malformed (RFC 9114 §8.1).
pub const MESSAGE_ERROR: Code = Code::H3_MESSAGE_ERROR;

/// Connection close code used when a peer exhausts its authentication attempts.
///
/// A QUIC application error code rather than an HTTP/3 one, because it closes the
/// whole connection rather than a stream. `H3_REQUEST_REJECTED`'s value is reused
/// so the peer sees something meaningful in the CONNECTION_CLOSE frame.
pub const AUTH_FAILURE_LIMIT_CODE: quinn::VarInt = quinn::VarInt::from_u32(0x10b);

type QuicConnection = h3_quinn::Connection;
type BidiStream = h3_quinn::BidiStream<Buffer>;

/// The value of the `:protocol` pseudo-header, normalized away from `h3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectProtocol {
    /// No `:protocol` pseudo-header: a classic CONNECT request (RFC 9114 §4.4).
    Absent,
    /// `connect-udp` — a UDP tunnel (RFC 9298).
    ConnectUdp,
    /// A protocol this proxy does not implement. The payload is the wire name.
    Unsupported(&'static str),
}

/// Reads the `:protocol` pseudo-header of a request.
///
/// Note a limitation of the current `h3` revision: a `:protocol` value it does
/// not recognise is rejected as a malformed request (H3_MESSAGE_ERROR) before
/// the request ever reaches us, so [`ConnectProtocol::Unsupported`] can only
/// ever carry a protocol `h3` knows about.
pub fn connect_protocol(req: &Request<()>) -> ConnectProtocol {
    use h3::ext::Protocol;

    match req.extensions().get::<Protocol>() {
        None => ConnectProtocol::Absent,
        Some(p) if *p == Protocol::CONNECT_UDP => ConnectProtocol::ConnectUdp,
        Some(p) if *p == Protocol::CONNECT_IP => ConnectProtocol::Unsupported("connect-ip"),
        Some(p) if *p == Protocol::WEB_TRANSPORT => ConnectProtocol::Unsupported("webtransport"),
        Some(p) if *p == Protocol::WEBSOCKET => ConnectProtocol::Unsupported("websocket"),
        Some(_) => ConnectProtocol::Unsupported("unknown"),
    }
}

/// The reset code the peer used, if this error is a peer-initiated reset.
pub fn peer_reset_code(error: &StreamError) -> Option<u64> {
    match error {
        StreamError::RemoteTerminate { code, .. } => Some(code.value()),
        _ => None,
    }
}

/// An accepted HTTP/3 connection.
pub struct Connection {
    inner: h3::server::Connection<QuicConnection, Buffer>,
}

impl Connection {
    /// Performs the HTTP/3 handshake on an established QUIC connection.
    ///
    /// Both settings below are **required** for Surge to accept the server: it
    /// validates the SETTINGS frame and disconnects if either is missing. `h3`
    /// defaults both to false, so they must be set explicitly.
    pub async fn handshake(quic: quinn::Connection) -> Result<Self, ConnectionError> {
        let mut builder = h3::server::builder();
        builder
            // SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08) = 1
            .enable_extended_connect(true)
            // SETTINGS_H3_DATAGRAM (0x33) = 1
            .enable_datagram(true)
            // SETTINGS_MAX_FIELD_SECTION_SIZE (0x06)
            .max_field_section_size(MAX_FIELD_SECTION_SIZE);

        let inner = builder.build(h3_quinn::Connection::new(quic)).await?;
        Ok(Self { inner })
    }

    /// Whether the peer advertised `SETTINGS_H3_DATAGRAM = 1`.
    ///
    /// RFC 9297 §2.1.1 forbids sending HTTP Datagrams before this is known to be
    /// true. Until the peer's SETTINGS frame arrives this reports `false`, which
    /// is the safe direction to be wrong in.
    pub fn peer_datagrams_enabled(&self) -> bool {
        use h3::ConnectionState as _;
        self.inner.settings().enable_datagram()
    }

    /// Waits for the next request stream.
    ///
    /// `Ok(None)` means the peer will not send further requests.
    pub async fn accept(&mut self) -> Result<Option<Resolver>, ConnectionError> {
        Ok(self.inner.accept().await?.map(|inner| Resolver { inner }))
    }

    /// Starts a graceful shutdown by sending GOAWAY (RFC 9114 §5.2).
    ///
    /// The frame names the last request this connection will serve, so the client
    /// knows to take new ones elsewhere while the ones in flight are allowed to
    /// finish. Requests arriving after it are rejected by `h3` itself with
    /// H3_REQUEST_REJECTED, which is the signal a client may safely retry on.
    ///
    /// Note what this does *not* do: it does not wait for anything, and the
    /// connection stays usable afterwards. Deciding when the existing tunnels are
    /// done is the caller's job — `accept()` will not report it, because at this
    /// revision `h3` only reports completion once the *client* has sent a GOAWAY
    /// too.
    pub async fn shutdown(&mut self) -> Result<(), ConnectionError> {
        // Zero further requests beyond the last one already accepted.
        self.inner.shutdown(0).await
    }
}

/// An accepted request stream whose headers have not been read yet.
pub struct Resolver {
    inner: h3::server::RequestResolver<QuicConnection, Buffer>,
}

impl Resolver {
    /// Reads and decodes the request headers.
    pub async fn resolve(self) -> Result<(Request<()>, Stream), StreamError> {
        let (req, inner) = self.inner.resolve_request().await?;
        Ok((req, Stream { inner }))
    }
}

/// A bidirectional request stream.
pub struct Stream {
    inner: h3::server::RequestStream<BidiStream, Buffer>,
}

impl Stream {
    /// The QUIC stream id.
    ///
    /// M2 needs this for the Quarter Stream ID of RFC 9297, which is this value
    /// divided by four.
    pub fn id(&self) -> u64 {
        self.inner.id().into_inner()
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
    /// Only the field lines given are sent — nothing synthesises a
    /// Content-Length or Content-Type, both of which RFC 9297 §3.4 forbids on a
    /// capsule-carrying response.
    pub async fn respond_with(
        &mut self,
        status: StatusCode,
        headers: HeaderMap,
    ) -> Result<(), StreamError> {
        let mut response = Response::builder()
            .status(status)
            .body(())
            .expect("a status-only response is always valid");
        *response.headers_mut() = headers;
        self.inner.send_response(response).await
    }

    /// Ends the sending side cleanly (a QUIC stream FIN).
    pub async fn finish(&mut self) -> Result<(), StreamError> {
        self.inner.finish().await
    }

    /// Asks the peer to stop sending on this stream.
    pub fn stop_receiving(&mut self, code: Code) {
        self.inner.stop_sending(code);
    }

    /// Splits the stream so each direction can be pumped independently.
    ///
    /// This is what makes TCP half-close expressible: one direction can finish
    /// while the other keeps flowing.
    pub fn split(self) -> (Writer, Reader) {
        let (send, recv) = self.inner.split();
        (Writer { inner: send }, Reader { inner: recv })
    }
}

/// The sending half of a split request stream.
pub struct Writer {
    inner: h3::server::RequestStream<h3_quinn::SendStream<Buffer>, Buffer>,
}

impl Writer {
    /// Sends body data, applying the peer's flow-control backpressure.
    pub async fn send_data(&mut self, data: Buffer) -> Result<(), StreamError> {
        self.inner.send_data(data).await
    }

    /// Ends the sending side cleanly (a QUIC stream FIN).
    pub async fn finish(&mut self) -> Result<(), StreamError> {
        self.inner.finish().await
    }

    /// Abruptly resets the sending side with an error code.
    pub fn reset(&mut self, code: Code) {
        self.inner.stop_stream(code);
    }
}

/// The receiving half of a split request stream.
pub struct Reader {
    inner: h3::server::RequestStream<h3_quinn::RecvStream, Buffer>,
}

impl Reader {
    /// Reads the next chunk of body data.
    ///
    /// `Ok(None)` means the peer finished its sending side — for a CONNECT
    /// tunnel, the client's FIN.
    pub async fn recv_data(&mut self) -> Result<Option<Buffer>, StreamError> {
        match self.inner.recv_data().await? {
            // The backend hands us an opaque `Buf`. For h3-quinn it is already
            // `Bytes`, so taking all of it is a refcount bump, not a copy.
            Some(mut buf) => Ok(Some(buf.copy_to_bytes(buf.remaining()))),
            None => Ok(None),
        }
    }

    /// Asks the peer to stop sending on this stream.
    pub fn stop_receiving(&mut self, code: Code) {
        self.inner.stop_sending(code);
    }
}
