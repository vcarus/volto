//! Extended CONNECT this server does not implement, and field sections it
//! cannot decode.
//!
//! Two paths that are one line each in the source and were reachable only from
//! unit tests: the 501 that RFC 9220 §3 asks for when `:protocol` names
//! something other than `connect-udp`, and the connection error QPACK requires
//! when a field section claims a dynamic-table entry this decoder can never
//! have. Both are about what a *peer* is told, so both belong on the wire.

mod common;

use bytes::{Bytes, BytesMut};
use common::rawstream::close_reason;
use common::{
    auth_section, authorize, basic_credentials, connect_request, read_at_least, respond_to,
    spawn_echo_target, H3Client, TestServer, ALLOW_PRIVATE, TIMEOUT,
};
use volto::h3::frame;
use volto::h3api::{Method, Request, Status};

/// QPACK_DECOMPRESSION_FAILED (RFC 9204 §6, registered in §8.3).
const QPACK_DECOMPRESSION_FAILED: u64 = 0x200;

/// The user the requests below authenticate as.
const USER: (&str, &str) = ("surge", "s3cret-p4ssw0rd");

/// A `:protocol` this proxy does not implement is answered 501, and the
/// connection carries on.
///
/// RFC 9220 §3: "If a server advertises support for Extended CONNECT but
/// receives an Extended CONNECT request with a ':protocol' value that is
/// unknown or is not supported, the server SHOULD respond to the request with a
/// 501 (Not Implemented) status code". This server advertises it, so the SHOULD
/// applies to every token but `connect-udp`.
///
/// The request is authenticated on purpose: authentication happens before
/// routing, so without credentials a 407 would hide whether the routing arm
/// under test was reached at all.
#[tokio::test]
async fn an_unimplemented_connect_protocol_is_answered_501() {
    let server = TestServer::start_with(&format!("{}{ALLOW_PRIVATE}", auth_section(&[USER]))).await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let response = respond_to(&mut client, connect_ip_request(&server.addr.to_string())).await;
    assert_eq!(
        response.status,
        Status::NOT_IMPLEMENTED,
        "an unsupported :protocol must be answered 501, not refused as malformed"
    );

    // One request this server will not serve is not a reason to drop the rest:
    // the same connection must still open an ordinary tunnel.
    let mut tunnel = open_tcp_tunnel_as_user(&mut client, &target.to_string()).await;
    tunnel
        .send_data(Bytes::from_static(b"after 501"))
        .await
        .expect("send through the tunnel");
    assert_eq!(&read_at_least(&mut tunnel, 9).await, b"after 501");
}

/// The whole connection ends when a field section references the dynamic table.
///
/// This server advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`, so a
/// non-zero Required Insert Count is not an unsupported feature but a count no
/// conformant encoder could have produced, and RFC 9204 §4.5.1.1 makes it a
/// connection error: "If the decoder encounters a value of EncodedInsertCount
/// that could not have been produced by a conformant encoder, it MUST treat
/// this as a connection error of type QPACK_DECOMPRESSION_FAILED."
#[tokio::test]
async fn a_dynamic_table_reference_closes_the_connection() {
    let server = TestServer::start().await;
    let client = H3Client::connect(&server).await;

    let (mut send, _recv) = client.quic.open_bi().await.expect("open a request stream");

    let block = [
        // Encoded Field Section Prefix (§4.5.1): Required Insert Count 1, which
        // is one more than a zero-capacity table can ever hold...
        0x01, //
        // ...and a Delta Base of zero, so the prefix itself is well formed.
        0x00, //
        // Indexed Field Line, T = 1: static entry 15, `:method: CONNECT`. A
        // line the decoder would accept, so nothing but the prefix is at fault.
        0xcf,
    ];
    let mut request = BytesMut::new();
    frame::put_header(&mut request, frame::HEADERS, block.len() as u64);
    request.extend_from_slice(&block);
    send.write_all(&request)
        .await
        .expect("send the HEADERS frame");

    // A dynamic table reference must end the connection, and the code has to say
    // why: this server advertises no dynamic table at all.
    let reason = close_reason(&client.quic, QPACK_DECOMPRESSION_FAILED, TIMEOUT).await;
    assert!(
        reason.contains("Required Insert Count"),
        "the close reason should say what was wrong, got {reason:?}"
    );
}

/// An extended CONNECT for `connect-ip`, authenticated.
///
/// RFC 8441 §4 makes `:scheme`, `:path` and `:authority` mandatory alongside
/// `:protocol`, so all three are here: a request missing one of them would be
/// malformed and never reach the routing arm under test.
fn connect_ip_request(proxy: &str) -> Request {
    let mut request = Request::new(Method::Connect);
    request.scheme = Some("https".into());
    request.authority = Some(proxy.into());
    request.path = Some("/.well-known/masque/ip/*/*/".into());
    request.protocol = Some("connect-ip".into());
    authorize_as_user(&mut request);
    request
}

/// `common::open_tcp_tunnel` for a server that requires credentials.
async fn open_tcp_tunnel_as_user(client: &mut H3Client, authority: &str) -> common::ClientStream {
    let mut request = connect_request(authority);
    authorize_as_user(&mut request);

    let (response, stream) = common::send_and_respond(client, request).await;
    assert_eq!(
        response.status,
        Status::OK,
        "the tunnel to {authority} was refused: proxy-status={:?}",
        response.fields.get("proxy-status")
    );
    stream
}

/// Adds this suite's credentials to a request.
fn authorize_as_user(request: &mut Request) {
    authorize(request, &basic_credentials(USER.0, USER.1));
}
