//! Scaffolding for the tests that drive raw QUIC streams.
//!
//! A test lands here when its subject is something the shared HTTP/3 client
//! cannot produce: a request on a stream that client would refuse to open, a
//! field section larger than it will build, a control stream that breaks a rule
//! it keeps. Those tests write frames by hand and read the server's answer off
//! `quinn` directly, and everything in this module is that plumbing -- opening a
//! stream and naming its type, building a frame, reading one back, waiting for
//! the connection to end.
//!
//! What is *not* here is any assertion about what the server chose. The five
//! this module does make are the ones that were written identically at every
//! call site: a response carries `:status` ([`status_of`]), a stream the server
//! refuses to read is stopped ([`stopped_code`]), a connection the server ends
//! is ended with a code the caller names ([`assert_closed_with`]), a connection
//! that needs more than the pre-authentication stream allowance gets itself
//! through the door first ([`authenticate`]), and a connection that survived
//! whatever was done to it is still answering ([`still_serving`]).
//!
//! D66 shape: helpers that assert are synchronous functions returning a future,
//! so `#[track_caller]` survives to the poll that panics.

#![allow(dead_code)] // Each integration test binary uses a subset of this.

use std::future::Future;
use std::panic::Location;
use std::time::Duration;

use bytes::BytesMut;
use volto::datagram;

use super::TIMEOUT;

// ---------------------------------------------------------------------------
// The wire vocabulary, spelled out rather than imported
// ---------------------------------------------------------------------------
//
// These are the bytes the server is asked to parse and the codes it is asked to
// answer with, transcribed from the RFCs rather than taken from `volto::h3`: a
// test that built them from the server's own constants would agree with it
// whatever it held.
//
// Shared between test binaries, which leaves that property intact -- what it
// asks for is that the wire side of a test not read the server's definition,
// not that every binary keep its own transcription. One copy is also one place
// to check a number against its registry, and the copies had already drifted
// apart in type and in name before they were gathered here.
//
// The three closed registries -- frame types, unidirectional stream types, and
// the error codes of RFC 9114 §8.1 with RFC 9204 §6's beside them -- are
// carried whole rather than only where a test happens to need one, so a reader
// looking a number up finds either the code or the fact that the RFC defines
// none. The SETTINGS identifiers cannot be: that registry is open, and any
// extension may add to it, so only the ones these tests send or inspect are
// here. A binary using a subset of any of it does not warn -- the
// `allow(dead_code)` above is there for exactly that reason.

/// DATA frame type (RFC 9114 §7.2.1).
pub const FRAME_DATA: u64 = 0x00;
/// HEADERS frame type (RFC 9114 §7.2.2).
pub const FRAME_HEADERS: u64 = 0x01;
/// CANCEL_PUSH frame type (RFC 9114 §7.2.3).
pub const FRAME_CANCEL_PUSH: u64 = 0x03;
/// SETTINGS frame type (RFC 9114 §7.2.4).
pub const FRAME_SETTINGS: u64 = 0x04;
/// PUSH_PROMISE frame type (RFC 9114 §7.2.5).
pub const FRAME_PUSH_PROMISE: u64 = 0x05;
/// GOAWAY frame type (RFC 9114 §7.2.6).
pub const FRAME_GOAWAY: u64 = 0x07;
/// MAX_PUSH_ID frame type (RFC 9114 §7.2.7).
pub const FRAME_MAX_PUSH_ID: u64 = 0x0d;

/// Frame types RFC 9114 §11.2.1 reserves because HTTP/2 used them.
///
/// §7.2.8: "Frame types that were used in HTTP/2 where there is no
/// corresponding HTTP/3 frame have also been reserved (Section 11.2.1). These
/// frame types MUST NOT be sent, and their receipt MUST be treated as a
/// connection error of type H3_FRAME_UNEXPECTED."
///
/// Transcribed from that section rather than shared with the server's own list:
/// what a test sends is what the RFC reserves, so a type the server has
/// forgotten fails the test instead of quietly agreeing with it. Same reasoning
/// as [`super::huffman`].
pub const RESERVED_HTTP2_TYPES: [u64; 4] = [0x02, 0x06, 0x08, 0x09];

/// A reserved "grease" frame or stream type of the form `0x1f * N + 0x21`.
///
/// RFC 9114 §7.2.8: "Frame types of the format `0x1f * N + 0x21` for
/// non-negative integer values of N are reserved to exercise the requirement
/// that unknown types be ignored (Section 9)."
///
/// `n` is the caller's, and deliberately so: the server, the shared HTTP/3
/// client and each raw-stream test pick different ones only so that the
/// greases can be told apart in a packet capture. What is shared here is the
/// formula, which is the part transcribed from the RFC.
pub const fn grease_type(n: u64) -> u64 {
    0x1f * n + 0x21
}

/// Control stream type (RFC 9114 §6.2.1).
pub const STREAM_CONTROL: u64 = 0x00;
/// Push stream type (RFC 9114 §6.2.2), which only a server may open.
pub const STREAM_PUSH: u64 = 0x01;
/// QPACK encoder stream type (RFC 9204 §4.2).
pub const STREAM_QPACK_ENCODER: u64 = 0x02;
/// QPACK decoder stream type (RFC 9204 §4.2).
pub const STREAM_QPACK_DECODER: u64 = 0x03;

/// SETTINGS_MAX_FIELD_SECTION_SIZE (RFC 9114 §7.2.4.1).
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
/// SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220 / RFC 8441 §3).
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
/// SETTINGS_H3_DATAGRAM (RFC 9297 §2.1.1), whose value must be 0 or 1.
pub const SETTINGS_H3_DATAGRAM: u64 = 0x33;

// The RFC 9114 §8.1 error codes, and the two QPACK stream ones beside them.
//
// All `u64`, which is what a code on the wire is. The few call sites that
// *send* one narrow it with `as u32` for the infallible
// `quinn::VarInt::from_u32`; they used to keep a second `u32` copy of the
// number instead, which is one of the drifts this block ends.

/// H3_NO_ERROR, RFC 9114 §8.1: "no error. This is used when the connection or
/// stream needs to be closed, but there is no error to signal."
pub const H3_NO_ERROR: u64 = 0x100;
/// H3_GENERAL_PROTOCOL_ERROR (RFC 9114 §8.1), the violation with no more
/// specific code.
pub const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x101;
/// H3_INTERNAL_ERROR (RFC 9114 §8.1).
pub const H3_INTERNAL_ERROR: u64 = 0x102;
/// H3_STREAM_CREATION_ERROR (RFC 9114 §8.1).
pub const H3_STREAM_CREATION_ERROR: u64 = 0x103;
/// H3_CLOSED_CRITICAL_STREAM (RFC 9114 §8.1).
pub const H3_CLOSED_CRITICAL_STREAM: u64 = 0x104;
/// H3_FRAME_UNEXPECTED (RFC 9114 §8.1), the answer to a frame out of place.
pub const H3_FRAME_UNEXPECTED: u64 = 0x105;
/// H3_FRAME_ERROR (RFC 9114 §8.1).
pub const H3_FRAME_ERROR: u64 = 0x106;
/// H3_EXCESSIVE_LOAD (RFC 9114 §8.1).
pub const H3_EXCESSIVE_LOAD: u64 = 0x107;
/// H3_ID_ERROR (RFC 9114 §8.1).
pub const H3_ID_ERROR: u64 = 0x108;
/// H3_SETTINGS_ERROR (RFC 9114 §8.1).
pub const H3_SETTINGS_ERROR: u64 = 0x109;
/// H3_MISSING_SETTINGS (RFC 9114 §8.1).
pub const H3_MISSING_SETTINGS: u64 = 0x10a;
/// H3_REQUEST_REJECTED, RFC 9114 §8.1: "A server rejected a request without
/// performing any application processing."
///
/// §4.1.1 is where it is asked for: "When the server cancels a request without
/// performing any application processing, the request is considered
/// 'rejected'. The server SHOULD abort its response stream with the error code
/// H3_REQUEST_REJECTED."
pub const H3_REQUEST_REJECTED: u64 = 0x10b;
/// H3_REQUEST_CANCELLED, RFC 9114 §8.1: "The request or its response (including
/// pushed response) is cancelled."
pub const H3_REQUEST_CANCELLED: u64 = 0x10c;
/// H3_REQUEST_INCOMPLETE (RFC 9114 §8.1).
pub const H3_REQUEST_INCOMPLETE: u64 = 0x10d;
/// H3_MESSAGE_ERROR (RFC 9114 §8.1), the answer to a malformed request.
pub const H3_MESSAGE_ERROR: u64 = 0x10e;
/// H3_CONNECT_ERROR (RFC 9114 §8.1).
pub const H3_CONNECT_ERROR: u64 = 0x10f;
/// H3_VERSION_FALLBACK (RFC 9114 §8.1): "The requested operation cannot be
/// served over HTTP/3. The peer should retry over HTTP/1.1."
pub const H3_VERSION_FALLBACK: u64 = 0x110;

/// H3_DATAGRAM_ERROR, the code RFC 9297 §2.1 names for an unusable datagram.
pub const H3_DATAGRAM_ERROR: u64 = 0x33;

/// QPACK_DECOMPRESSION_FAILED (RFC 9204 §6, registered in §8.3).
pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x200;
/// QPACK_ENCODER_STREAM_ERROR (RFC 9204 §6).
pub const QPACK_ENCODER_STREAM_ERROR: u64 = 0x201;
/// QPACK_DECODER_STREAM_ERROR (RFC 9204 §6).
pub const QPACK_DECODER_STREAM_ERROR: u64 = 0x202;

/// A frame with its type, length and payload, as RFC 9114 §7.1 lays it out.
pub fn frame(kind: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = BytesMut::new();
    datagram::put_varint(&mut out, kind);
    datagram::put_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    out.to_vec()
}

/// Encodes `fields` as a QPACK field section and wraps it in a HEADERS frame.
///
/// Only the static table and literals are used -- that is all
/// `volto::h3::qpack::encode` emits -- so no encoder stream is needed for the
/// server to read one of these.
pub fn headers_frame<'a, I>(fields: I) -> Vec<u8>
where
    I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
{
    let mut block = BytesMut::new();
    volto::h3::qpack::encode(&mut block, fields);
    frame(FRAME_HEADERS, &block)
}

/// A classic CONNECT request (RFC 9114 §4.4) as a HEADERS frame.
///
/// `:method` and `:authority`, and neither `:scheme` nor `:path`.
pub fn connect_headers_frame(authority: &str) -> Vec<u8> {
    headers_frame([
        (b":method".as_slice(), b"CONNECT".as_slice()),
        (b":authority", authority.as_bytes()),
    ])
}

/// [`connect_headers_frame`] carrying HTTP Basic credentials.
pub fn authenticated_connect_headers_frame(authority: &str, credentials: &str) -> Vec<u8> {
    headers_frame([
        (b":method".as_slice(), b"CONNECT".as_slice()),
        (b":authority", authority.as_bytes()),
        (b"proxy-authorization", credentials.as_bytes()),
    ])
}

/// A CONNECT-UDP request (RFC 9298 §3) as a HEADERS frame.
///
/// `host` is placed in the RFC 9298 §2 template as given, so a caller that
/// wants an escaped one escapes it.
pub fn connect_udp_headers_frame(authority: &str, host: &str, port: u16) -> Vec<u8> {
    let path = format!("/.well-known/masque/udp/{host}/{port}/");
    headers_frame([
        (b":method".as_slice(), b"CONNECT".as_slice()),
        (b":protocol", b"connect-udp"),
        (b":scheme", b"https"),
        (b":authority", authority.as_bytes()),
        (b":path", path.as_bytes()),
    ])
}

/// A target the default destination policy refuses before the resolver is
/// asked.
///
/// Port 25 is on the deny list and the port rule is checked before the resolver
/// runs, so a request for it is answered without a packet leaving this host.
/// That is what makes it the cheapest request a test can make when what it
/// wants is an *answer* rather than a tunnel — and the choice depends on two
/// facts about the server (the port is denied, and the port rule runs before
/// the resolver), so it is stated here once rather than at every call site.
pub const DENIED_TARGET: &str = "192.0.2.1:25";

/// Opens a request stream and asserts the server answers it.
///
/// The answer is a 403 rather than a 200 because the target is
/// [`DENIED_TARGET`]: nothing has to be listening, and the answer still proves
/// the connection is serving rather than merely unclosed -- which is the
/// difference most hostile cases turn on.
///
/// Written as a synchronous function returning a future so `#[track_caller]`
/// survives to the poll that panics (D66).
#[track_caller]
pub fn still_serving(connection: &quinn::Connection) -> impl Future<Output = ()> + '_ {
    expect_denied(
        connection,
        None,
        "the connection must still be serving requests",
        Location::caller(),
    )
}

/// Walks a raw-stream connection through the credentials check, and no further.
///
/// A connection is accepted on a small request-stream allowance and granted the
/// configured `[limits] max_streams_bidi` only once a request on it has
/// authenticated (`quic::INITIAL_BIDI_STREAMS`), so a test that needs more
/// streams open at once than that allowance has to walk through the door before
/// it opens them. Nothing else about it changes: the allowance is the only
/// thing this hands the connection.
///
/// The cheapest request that does it, which is why it is the same exchange
/// [`still_serving`] makes: what opens the door is the request being
/// *accepted*, not its outcome.
///
/// `credentials` is `None` for a server with no `[auth]` users, where any
/// completed request authenticates. A server that configures them is passed
/// them, because a 407 would leave the connection exactly where it was.
#[track_caller]
pub fn authenticate<'a>(
    connection: &'a quinn::Connection,
    credentials: Option<&'a str>,
) -> impl Future<Output = ()> + 'a {
    expect_denied(
        connection,
        credentials,
        "the request must be refused for its destination, which is the proof that \
         it got past the credentials check",
        Location::caller(),
    )
}

/// The exchange behind both, with `caller` already captured.
///
/// `what` says what the 403 proves for the caller that asked for it; the two
/// assertions themselves are the same either way.
async fn expect_denied(
    connection: &quinn::Connection,
    credentials: Option<&str>,
    what: &'static str,
    caller: &'static Location<'static>,
) {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .unwrap_or_else(|error| panic!("at {caller}: open a request stream: {error}"));

    let request = match credentials {
        Some(credentials) => authenticated_connect_headers_frame(DENIED_TARGET, credentials),
        None => connect_headers_frame(DENIED_TARGET),
    };
    send.write_all(&request)
        .await
        .unwrap_or_else(|error| panic!("at {caller}: send a CONNECT request: {error}"));

    let (kind, payload) = read_frame(&mut recv).await;
    assert_eq!(
        kind, FRAME_HEADERS,
        "at {caller}: the answer must be a response"
    );
    assert_eq!(status_of(&payload), "403", "at {caller}: {what}");
}

/// Opens a unidirectional stream, names its type, and writes `bytes` after it.
///
/// RFC 9114 §6.2: "The purpose is indicated by a stream type, which is sent as
/// a variable-length integer at the start of the stream." That varint is built
/// here rather than taken from the server's own stream-type constants, for the
/// reason the frame types above are spelled out: these are the bytes the
/// server is asked to read.
///
/// The type and `bytes` leave in a single `write_all`, which is how every call
/// site wrote it. A test whose subject is a type varint that arrives in pieces
/// -- or never arrives at all -- writes its own bytes instead.
///
/// The stream is handed back rather than dropped: dropping a
/// [`quinn::SendStream`] finishes it, and a peer that finishes its control
/// stream is told H3_CLOSED_CRITICAL_STREAM (RFC 9114 §6.2.1), which is a
/// different test from the one the caller is running.
pub async fn open_uni_stream(
    connection: &quinn::Connection,
    stream_type: u64,
    bytes: &[u8],
) -> quinn::SendStream {
    let mut stream = connection
        .open_uni()
        .await
        .expect("open a unidirectional stream");

    let mut wire = BytesMut::new();
    datagram::put_varint(&mut wire, stream_type);
    wire.extend_from_slice(bytes);
    stream.write_all(&wire).await.expect("send the stream");

    stream
}

/// Reads one HTTP/3 frame from a raw stream: type, length, payload.
pub async fn read_frame(recv: &mut quinn::RecvStream) -> (u64, Vec<u8>) {
    let frame_type = read_varint(recv).await;
    let length = read_varint(recv).await;

    let mut payload = vec![0u8; usize::try_from(length).expect("frame length")];
    tokio::time::timeout(TIMEOUT, recv.read_exact(&mut payload))
        .await
        .expect("frame payload arrived")
        .expect("frame payload");

    (frame_type, payload)
}

/// Reads one QUIC variable-length integer from a stream (RFC 9000 §16).
///
/// One byte at a time to start with, because a stream carries no framing that
/// would say how many are coming: the first byte's two most significant bits
/// give the length, and the rest follow.
pub async fn read_varint(recv: &mut quinn::RecvStream) -> u64 {
    let mut buf = [0u8; 8];
    tokio::time::timeout(TIMEOUT, recv.read_exact(&mut buf[..1]))
        .await
        .expect("varint arrived")
        .expect("varint first byte");

    let length = 1usize << (buf[0] >> 6);
    if length > 1 {
        tokio::time::timeout(TIMEOUT, recv.read_exact(&mut buf[1..length]))
            .await
            .expect("varint tail arrived")
            .expect("varint tail");
    }

    let mut value = u64::from(buf[0] & 0x3f);
    for byte in &buf[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    value
}

/// The `:status` of a response field section.
///
/// Decoded against the limit the server itself advertises, which is the only
/// section size a well-behaved peer may be asked to hold.
pub fn status_of(block: &[u8]) -> String {
    let fields = volto::h3::qpack::decode(block, volto::h3::MAX_FIELD_SECTION_SIZE)
        .expect("the server's field section must decode");
    let status = fields
        .iter()
        .find(|field| field.name.as_ref() == b":status")
        .expect("a response carries :status");
    String::from_utf8(status.value.to_vec()).expect("a numeric status")
}

/// Writes until the peer stops the stream, and reports the code it used.
///
/// Retried rather than written once: STOP_SENDING travels while the response is
/// being read here, so a single write can still succeed before it lands.
pub async fn stopped_code(send: &mut quinn::SendStream) -> u64 {
    let stopped = async {
        loop {
            match send.write_all(&[0u8; 256]).await {
                Ok(()) => continue,
                Err(quinn::WriteError::Stopped(code)) => return code.into_inner(),
                Err(other) => panic!("expected STOP_SENDING, got {other}"),
            }
        }
    };

    tokio::time::timeout(TIMEOUT, stopped)
        .await
        .expect("the server must stop the stream it refused to read")
}

/// Waits for the peer to close `connection`, returning the code and reason of
/// the CONNECTION_CLOSE it sent.
///
/// Asserted on the wire rather than through server state: that frame is exactly
/// what the RFC requires the peer to see. A connection that ends any other way
/// -- an idle timeout, a transport error -- fails here rather than being
/// reported as a code, since every test reaching for this is about a close the
/// server decided to send.
#[track_caller]
pub fn application_close(
    connection: &quinn::Connection,
    within: Duration,
) -> impl Future<Output = (u64, String)> + '_ {
    closed(connection, within, Location::caller())
}

/// [`application_close`], asserting the code and handing back the reason phrase.
#[track_caller]
pub fn close_reason(
    connection: &quinn::Connection,
    expected: u64,
    within: Duration,
) -> impl Future<Output = String> + '_ {
    closed_with(connection, expected, within, Location::caller())
}

/// Waits for the server to close `connection`, asserting the code it used.
#[track_caller]
pub fn assert_closed_with(
    connection: &quinn::Connection,
    expected: u64,
    within: Duration,
) -> impl Future<Output = ()> + '_ {
    let close = closed_with(connection, expected, within, Location::caller());
    async move {
        close.await;
    }
}

/// The body behind the two asserting helpers, with `caller` already captured.
async fn closed_with(
    connection: &quinn::Connection,
    expected: u64,
    within: Duration,
    caller: &'static Location<'static>,
) -> String {
    let (code, reason) = closed(connection, within, caller).await;
    assert_eq!(
        code, expected,
        "at {caller}: the server closed with the wrong code; reason was {reason:?}"
    );
    reason
}

/// The wait itself, with `caller` already captured.
async fn closed(
    connection: &quinn::Connection,
    within: Duration,
    caller: &'static Location<'static>,
) -> (u64, String) {
    let error = tokio::time::timeout(within, connection.closed())
        .await
        .unwrap_or_else(|_| panic!("the connection at {caller} was still open after {within:?}"));

    match error {
        quinn::ConnectionError::ApplicationClosed(close) => (
            close.error_code.into_inner(),
            String::from_utf8_lossy(&close.reason).into_owned(),
        ),
        // An idle timeout here would mean the keep-alive stopped working and
        // the test stopped testing what it says it does.
        other => panic!("at {caller}: expected the server to close, got {other}"),
    }
}
