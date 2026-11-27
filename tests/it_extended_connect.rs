//! Extended CONNECT requests this server does not serve or cannot accept, and a
//! field section it cannot decode, judged on the wire.

mod common;

use std::net::SocketAddr;

use bytes::BytesMut;
use common::rawstream::{H3_MESSAGE_ERROR, QPACK_DECOMPRESSION_FAILED, close_reason};
use common::{
    ALLOW_PRIVATE, H3Client, TIMEOUT, TestServer, assert_peer_reset, auth_section, authorize,
    basic_credentials, echoes, respond_to, spawn_echo_target,
};
use volto::h3::frame;
use volto::h3api::{FieldValue, Method, Request, Status};

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
    let (server, target, mut client) = served().await;

    let response = respond_to(&mut client, connect_ip_request(&server.addr.to_string())).await;
    assert_eq!(
        response.status,
        Status::NOT_IMPLEMENTED,
        "an unsupported :protocol must be answered 501, not refused as malformed"
    );

    // One request this server will not serve is not a reason to drop the rest:
    // the same connection must still open an ordinary tunnel.
    still_tunnels(&mut client, target, b"after 501").await;
}

/// A `:protocol` that is not a token makes the request malformed.
///
/// RFC 8441 §4: "A new pseudo-header field :protocol MAY be included on request
/// HEADERS indicating the desired protocol to be spoken on the tunnel created by
/// CONNECT.  The pseudo-header field is single valued and contains a value from
/// the 'Hypertext Transfer Protocol (HTTP) Upgrade Token Registry'". RFC 9110
/// §16.7 says that registry "defines the namespace for protocol-name tokens" and
/// §7.8 defines `protocol-name = token`, so a value that is not an RFC 9110
/// §5.6.2 token names nothing the registry could hold. RFC 9114 §4.3:
/// "Endpoints MUST treat a request or response that contains undefined or
/// invalid pseudo-header fields as malformed."
///
/// CR LF because RFC 9114 §10.3 names carriage return and line feed among the
/// characters that "might be exploited by an attacker if they are translated
/// verbatim".
///
/// The credentials are here for the reason the 501 case gives: without them a
/// 407 would hide which verdict was reached.
#[tokio::test]
async fn a_connect_protocol_that_is_not_a_token_is_malformed() {
    let (server, target, mut client) = served().await;

    // A prefix that would have routed, followed by a field line of the peer's
    // own: the 501 arm compares the whole value, so nothing but the character
    // set stands between this and an answer.
    let mut request = connect_ip_request(&server.addr.to_string());
    request.protocol = Some("connect-udp\r\nx-injected: 1".into());

    refused_as_malformed(
        &mut client,
        request,
        "a request carrying a :protocol that is not a token",
    )
    .await;

    // A malformed request is a stream error, so the connection carries on.
    still_tunnels(&mut client, target, b"after the malformed :protocol").await;
}

/// A Host-only extended CONNECT for an unimplemented protocol is answered 501,
/// not refused as malformed.
///
/// RFC 8441 §4 requires `:scheme` and `:path` alongside `:protocol` and says
/// how `:authority` is interpreted when it is present; it does not make
/// `:authority` mandatory. RFC 9114 §4.3.1: "If the :scheme pseudo-header field
/// identifies a scheme that has a mandatory authority component (including
/// "http" and "https"), the request MUST contain either an :authority
/// pseudo-header field or a Host header field." The `:authority` requirement is
/// RFC 9298 §3.4's -- "The :authority pseudo-header field SHALL contain the
/// authority of the UDP proxy" -- and that section is about `connect-udp`
/// alone.
#[tokio::test]
async fn a_host_only_extended_connect_is_answered_501() {
    let (server, target, mut client) = served().await;

    let proxy = server.addr.to_string();
    let mut request = connect_ip_request(&proxy);
    request.authority = None;
    request.fields.append(
        "host",
        FieldValue::parse(proxy.as_bytes()).expect("a valid Host"),
    );

    let response = respond_to(&mut client, request).await;
    assert_eq!(
        response.status,
        Status::NOT_IMPLEMENTED,
        "an unsupported :protocol named through Host is still answered 501"
    );

    // One request this server will not serve is not a reason to drop the rest.
    still_tunnels(&mut client, target, b"after a Host-only 501").await;
}

/// `connect-udp` still requires `:authority`, even when Host names the proxy.
///
/// RFC 9298 §3.4: "The :authority pseudo-header field SHALL contain the
/// authority of the UDP proxy." RFC 9114 §4.3.1's either/or does not reach it,
/// so a Host field cannot stand in.
#[tokio::test]
async fn connect_udp_with_host_but_no_authority_is_malformed() {
    let (server, target, mut client) = served().await;

    let proxy = server.addr.to_string();
    let mut request = connect_ip_request(&proxy);
    request.protocol = Some("connect-udp".into());
    request.authority = None;
    request.fields.append(
        "host",
        FieldValue::parse(proxy.as_bytes()).expect("a valid Host"),
    );

    refused_as_malformed(
        &mut client,
        request,
        "a connect-udp request naming the proxy only through Host",
    )
    .await;

    // A malformed request is a stream error, so the connection carries on.
    still_tunnels(&mut client, target, b"after malformed connect-udp").await;
}

/// An extended CONNECT for another protocol with neither `:authority` nor Host
/// is malformed.
///
/// RFC 9114 §4.3.1 requires one of the two when the scheme has a mandatory
/// authority component, and with neither the request is malformed. The protocol
/// being unsupported does not make the request routable: the malformed verdict
/// comes first.
#[tokio::test]
async fn an_extended_connect_with_no_authority_and_no_host_is_malformed() {
    let (server, target, mut client) = served().await;

    let mut request = connect_ip_request(&server.addr.to_string());
    request.authority = None;

    refused_as_malformed(
        &mut client,
        request,
        "an extended CONNECT with neither :authority nor Host",
    )
    .await;

    // A malformed request is a stream error, so the connection carries on.
    still_tunnels(&mut client, target, b"after the authority-less request").await;
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
    frame::put_header(
        &mut request,
        frame::HEADERS,
        u64::try_from(block.len()).expect("a short block"),
    );
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

/// An extended CONNECT for `connect-ip`, authenticated, naming the proxy in
/// `:authority`.
fn connect_ip_request(proxy: &str) -> Request {
    let mut request = Request::new(Method::Connect);
    request.scheme = Some("https".into());
    request.authority = Some(proxy.into());
    request.path = Some("/.well-known/masque/ip/*/*/".into());
    request.protocol = Some("connect-ip".into());
    authorize(&mut request, &basic_credentials(USER.0, USER.1));
    request
}

/// A server with [`USER`] configured and private destinations open, a TCP echo
/// target, and a client connected to the server.
async fn served() -> (TestServer, SocketAddr, H3Client) {
    let server = TestServer::start_with(&format!("{}{ALLOW_PRIVATE}", auth_section(&[USER]))).await;
    let target = spawn_echo_target().await;
    let client = H3Client::connect(&server).await;
    (server, target, client)
}

/// Sends `request` and asserts that the server resets it with H3_MESSAGE_ERROR
/// within [`TIMEOUT`]. `what` names the request in a failure.
async fn refused_as_malformed(client: &mut H3Client, request: Request, what: &str) {
    let mut stream = client
        .send
        .send_request(request)
        .await
        .unwrap_or_else(|error| panic!("send {what}: {error:?}"));
    let answer = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .unwrap_or_else(|_| panic!("the server must answer {what} promptly"));
    match answer {
        Ok(response) => panic!("{what} must be refused as malformed, got {response:?}"),
        Err(error) => assert_peer_reset(&error, H3_MESSAGE_ERROR),
    }
}

/// Opens an ordinary tunnel to `target` on `client` and echoes `tag` through
/// it: the connection carries on after the request a test was about.
async fn still_tunnels(client: &mut H3Client, target: SocketAddr, tag: &[u8]) {
    let mut tunnel = common::open_tcp_tunnel_as(client, &target.to_string(), USER.0, USER.1).await;
    echoes(&mut tunnel, tag).await;
}
