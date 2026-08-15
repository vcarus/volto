//! M4: authentication, the destination policy, quotas and abuse mitigations.
//!
//! Everything here is asserted on the wire — status codes and response header
//! fields — rather than against internal state, so the tests keep their meaning
//! if the implementation behind them is rearranged.

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::{
    auth_section, basic_credentials, connect_request, connect_udp_request, read_at_least,
    spawn_echo_target, spawn_silent_udp_target, spawn_udp_echo_target, H3Client, TestServer,
    ALLOW_PRIVATE, TIMEOUT,
};
use http::{HeaderName, Request, Response, StatusCode};
use volto::datagram;

/// The credentials the test servers below are configured with.
const USER: (&str, &str) = ("user1", "s3cret");

/// Sends a request and waits for the response headers.
async fn respond_to(client: &mut H3Client, request: Request<()>) -> Response<()> {
    let mut stream = client
        .send
        .send_request(request)
        .await
        .expect("send request");

    tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("response arrived")
        .expect("response")
}

/// Sends a request and keeps the stream, for cases that then use the tunnel.
async fn open_tunnel(
    client: &mut H3Client,
    request: Request<()>,
) -> (Response<()>, common::ClientStream) {
    let mut stream = client
        .send
        .send_request(request)
        .await
        .expect("send request");

    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .expect("response arrived")
        .expect("response");

    (response, stream)
}

/// The `Proxy-Status` field of a response, if it has one.
fn proxy_status(response: &Response<()>) -> Option<&str> {
    response
        .headers()
        .get("proxy-status")
        .map(|value| value.to_str().expect("proxy-status is ASCII"))
}

/// Asserts a refusal carries the RFC 9209 reason it should.
fn assert_refused(response: &Response<()>, status: StatusCode, error: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(
        proxy_status(response),
        Some(format!("volto; error={error}").as_str()),
        "the refusal must say why in a Proxy-Status field"
    );
}

/// A CONNECT request carrying credentials in `header`.
fn authorized_connect(authority: &str, header: HeaderName, value: &str) -> Request<()> {
    let mut request = connect_request(authority);
    request
        .headers_mut()
        .insert(header, value.parse().expect("header value"));
    request
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// The default configuration has no users, which disables authentication. That
/// is the open-proxy case the startup warning is about, and it has to keep
/// working: it is how the server is run during interop debugging.
#[tokio::test]
async fn no_configured_users_means_no_authentication() {
    let server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let response = respond_to(&mut client, connect_request(&target.to_string())).await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// Both header names are accepted (decision D3): Surge's manual does not say
/// which one it uses, so neither may be the only one that works.
#[tokio::test]
async fn correct_credentials_are_accepted_in_either_header() {
    let server = TestServer::start_with(&format!("{}{ALLOW_PRIVATE}", auth_section(&[USER]))).await;
    let target = spawn_echo_target().await;
    let credentials = basic_credentials(USER.0, USER.1);

    for header in [
        HeaderName::from_static("proxy-authorization"),
        HeaderName::from_static("authorization"),
    ] {
        let mut client = H3Client::connect(&server).await;
        let response = respond_to(
            &mut client,
            authorized_connect(&target.to_string(), header.clone(), &credentials),
        )
        .await;

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "credentials in {header} must be accepted"
        );
    }
}

#[tokio::test]
async fn bad_or_missing_credentials_are_refused_with_a_challenge() {
    let server = TestServer::start_with(&format!("{}{ALLOW_PRIVATE}", auth_section(&[USER]))).await;
    let target = spawn_echo_target().await;

    // Wrong password, wrong user, well-formed but unknown, and every flavour of
    // malformed — none of them may open a tunnel.
    let bad = [
        basic_credentials(USER.0, "wrong"),
        basic_credentials("user2", USER.1),
        basic_credentials("", ""),
        "Basic not-base64".to_owned(),
        "Bearer sometoken".to_owned(),
        format!("Basic {}", "dXNlcjE="), // no colon inside
        "Basic ".to_owned(),
        String::from("garbage"),
    ];

    for credentials in &bad {
        let mut client = H3Client::connect(&server).await;
        let response = respond_to(
            &mut client,
            authorized_connect(
                &target.to_string(),
                HeaderName::from_static("proxy-authorization"),
                credentials,
            ),
        )
        .await;

        assert_eq!(
            response.status(),
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "{credentials:?} must not authenticate"
        );
        assert_eq!(
            response
                .headers()
                .get("proxy-authenticate")
                .map(|v| v.to_str().unwrap()),
            Some("Basic realm=\"masque\""),
            "RFC 9110 §11.7.1: a 407 must carry a challenge"
        );
    }

    // And no credentials at all.
    let mut client = H3Client::connect(&server).await;
    let response = respond_to(&mut client, connect_request(&target.to_string())).await;
    assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    assert!(response.headers().get("proxy-authenticate").is_some());
}

/// Surge sends credentials on *every* CONNECT, so CONNECT-UDP is checked exactly
/// like a TCP tunnel.
#[tokio::test]
async fn connect_udp_is_authenticated_too() {
    let server = TestServer::start_with(&format!("{}{ALLOW_PRIVATE}", auth_section(&[USER]))).await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let unauthenticated = respond_to(
        &mut client,
        connect_udp_request(server.addr, &target.ip().to_string(), target.port()),
    )
    .await;
    assert_eq!(
        unauthenticated.status(),
        StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );

    let mut request = connect_udp_request(server.addr, &target.ip().to_string(), target.port());
    request.headers_mut().insert(
        HeaderName::from_static("proxy-authorization"),
        basic_credentials(USER.0, USER.1)
            .parse()
            .expect("header value"),
    );
    let authenticated = respond_to(&mut client, request).await;
    assert_eq!(authenticated.status(), StatusCode::OK);
}

/// One user's password must not open another user's account.
#[tokio::test]
async fn credentials_are_not_interchangeable_between_users() {
    let server = TestServer::start_with(&format!(
        "{}{ALLOW_PRIVATE}",
        auth_section(&[("alice", "pw-alice"), ("bob", "pw-bob")])
    ))
    .await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mixed = respond_to(
        &mut client,
        authorized_connect(
            &target.to_string(),
            HeaderName::from_static("proxy-authorization"),
            &basic_credentials("alice", "pw-bob"),
        ),
    )
    .await;
    assert_eq!(mixed.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);

    // Both real users still work.
    for (username, password) in [("alice", "pw-alice"), ("bob", "pw-bob")] {
        let mut client = H3Client::connect(&server).await;
        let response = respond_to(
            &mut client,
            authorized_connect(
                &target.to_string(),
                HeaderName::from_static("proxy-authorization"),
                &basic_credentials(username, password),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{username} must pass");
    }
}

// ---------------------------------------------------------------------------
// Destination policy
// ---------------------------------------------------------------------------

/// The production default: loopback is out of reach. Note the server here is
/// started *without* the `ALLOW_PRIVATE` fragment every other test uses.
#[tokio::test]
async fn loopback_is_prohibited_by_default() {
    let server = TestServer::start_with("").await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let response = respond_to(&mut client, connect_request(&target.to_string())).await;
    assert_refused(
        &response,
        StatusCode::FORBIDDEN,
        "destination_ip_prohibited",
    );
}

/// `::ffff:127.0.0.1` is loopback in IPv6 clothing — the bypass the policy
/// normalizes for. The IPv6 loopback literal goes the same way.
#[tokio::test]
async fn ipv4_mapped_and_ipv6_loopback_are_prohibited() {
    let server = TestServer::start_with("").await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    for authority in [
        format!("[::ffff:127.0.0.1]:{}", target.port()),
        format!("[::ffff:7f00:1]:{}", target.port()),
        format!("[::1]:{}", target.port()),
        format!("[::127.0.0.1]:{}", target.port()),
    ] {
        let response = respond_to(&mut client, connect_request(&authority)).await;
        assert_refused(
            &response,
            StatusCode::FORBIDDEN,
            "destination_ip_prohibited",
        );
    }
}

#[tokio::test]
async fn connect_udp_to_a_prohibited_address_is_refused() {
    let server = TestServer::start_with("").await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    for host in ["127.0.0.1", "::ffff:127.0.0.1", "::1"] {
        let response = respond_to(
            &mut client,
            connect_udp_request(server.addr, host, target.port()),
        )
        .await;
        assert_refused(
            &response,
            StatusCode::FORBIDDEN,
            "destination_ip_prohibited",
        );
    }
}

/// A name whose every address is the unspecified one was blackholed by the
/// resolver upstream, not refused by this proxy, so it is not answered like a
/// refusal (decision D49): the tunnel is accepted and closed at once, which is
/// what a target that accepts and immediately hangs up looks like on the wire.
///
/// The address is in the never-allowed bucket, so `allow_private_networks` makes
/// no difference to it — it is on here to show that.
#[tokio::test]
async fn a_blackholed_tcp_target_is_accepted_then_closed() {
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let mut client = H3Client::connect(&server).await;

    let (response, mut stream) = open_tunnel(&mut client, connect_request("0.0.0.0:443")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        proxy_status(&response).is_none(),
        "an accepted request carries no refusal reason"
    );

    // Reading must reach end of stream rather than fail: the server finished its
    // sending side, and never reset the stream.
    let payload = common::read_to_end(&mut stream).await;
    assert!(
        payload.is_empty(),
        "nothing may be sent through a tunnel with no target"
    );
}

/// The same on the UDP path, where the 200 also has to keep the RFC 9297
/// `Capsule-Protocol` field that makes it a well-formed CONNECT-UDP response.
#[tokio::test]
async fn a_blackholed_udp_target_is_accepted_then_closed() {
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let mut client = H3Client::connect(&server).await;

    let (response, mut stream) = open_tunnel(
        &mut client,
        connect_udp_request(server.addr, "0.0.0.0", 443),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("capsule-protocol")
            .and_then(|value| value.to_str().ok()),
        Some("?1"),
        "a 2xx to connect-udp must still carry the capsule protocol field"
    );
    assert!(
        proxy_status(&response).is_none(),
        "an accepted request carries no refusal reason"
    );

    let capsules = common::read_to_end(&mut stream).await;
    assert!(
        capsules.is_empty(),
        "no capsule may precede the close of a session with no socket"
    );
}

/// Private space can be opened up deliberately — the deployments where reaching a
/// private network is the whole point.
#[tokio::test]
async fn private_addresses_are_reachable_when_allowed() {
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (response, mut stream) =
        open_tunnel(&mut client, connect_request(&target.to_string())).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(proxy_status(&response).is_none(), "a 200 needs no reason");

    // And the tunnel really works, rather than merely being answered.
    stream
        .send_data(Bytes::from_static(b"through the acl"))
        .await
        .expect("send payload");
    let echoed = read_at_least(&mut stream, b"through the acl".len()).await;
    assert_eq!(&echoed, b"through the acl");
}

/// Port 25 is closed by default; the refusal is about the port, not the address,
/// so it reports `http_request_denied` rather than an IP prohibition.
#[tokio::test]
async fn a_denied_port_is_refused_on_both_paths() {
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let mut client = H3Client::connect(&server).await;

    let tcp = respond_to(&mut client, connect_request("127.0.0.1:25")).await;
    assert_refused(&tcp, StatusCode::FORBIDDEN, "http_request_denied");

    let udp = respond_to(
        &mut client,
        connect_udp_request(server.addr, "127.0.0.1", 25),
    )
    .await;
    assert_refused(&udp, StatusCode::FORBIDDEN, "http_request_denied");
}

/// Surge's UDP availability test is a DNS query through the tunnel, so port 53
/// has to be reachable with a stock configuration. Nothing needs to be listening:
/// connecting a UDP socket is enough to answer.
#[tokio::test]
async fn udp_port_53_is_reachable_by_default() {
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let mut client = H3Client::connect(&server).await;

    let response = respond_to(
        &mut client,
        connect_udp_request(server.addr, "127.0.0.1", 53),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "denying UDP/53 would fail Surge's UDP test"
    );
}

/// A name that cannot be resolved is the proxy's problem to report, not the
/// client's fault: 502 with `dns_error`, not 400 (decision D9).
///
/// The name is longer than the 255 octets DNS permits, so the stub resolver
/// rejects it locally. A merely nonexistent name would not do: resolvers that
/// hijack NXDOMAIN — Surge does, from a fake-IP range — would resolve it and this
/// test would assert on the environment instead of on the server.
#[tokio::test]
async fn an_unresolvable_target_is_a_bad_gateway() {
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let mut client = H3Client::connect(&server).await;

    let label = "a".repeat(60);
    let host = vec![label; 5].join(".") + ".invalid";

    let tcp = respond_to(&mut client, connect_request(&format!("{host}:443"))).await;
    assert_refused(&tcp, StatusCode::BAD_GATEWAY, "dns_error");

    let udp = respond_to(&mut client, connect_udp_request(server.addr, &host, 443)).await;
    assert_refused(&udp, StatusCode::BAD_GATEWAY, "dns_error");
}

// ---------------------------------------------------------------------------
// Per-connection tunnel quota
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_tunnel_quota_is_enforced_per_connection() {
    let server = TestServer::start_with(&format!(
        "[limits]\nmax_targets_per_conn = 2\n{ALLOW_PRIVATE}"
    ))
    .await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    // Held open, so the slots stay occupied.
    let mut held = Vec::new();
    for _ in 0..2 {
        let (response, stream) =
            open_tunnel(&mut client, connect_request(&target.to_string())).await;
        assert_eq!(response.status(), StatusCode::OK);
        held.push(stream);
    }

    let refused = respond_to(&mut client, connect_request(&target.to_string())).await;
    assert_refused(
        &refused,
        StatusCode::SERVICE_UNAVAILABLE,
        "connection_limit_reached",
    );

    // A second connection has its own budget: the limit is per connection, not
    // per server.
    let mut other = H3Client::connect(&server).await;
    let response = respond_to(&mut other, connect_request(&target.to_string())).await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// TCP and UDP tunnels draw on one budget, because they cost the same thing: a
/// file descriptor.
#[tokio::test]
async fn tcp_and_udp_tunnels_share_the_quota() {
    let server = TestServer::start_with(&format!(
        "[limits]\nmax_targets_per_conn = 1\n{ALLOW_PRIVATE}"
    ))
    .await;
    let tcp_target = spawn_echo_target().await;
    let udp_target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (response, _held) =
        open_tunnel(&mut client, connect_request(&tcp_target.to_string())).await;
    assert_eq!(response.status(), StatusCode::OK);

    let refused = respond_to(
        &mut client,
        connect_udp_request(server.addr, &udp_target.ip().to_string(), udp_target.port()),
    )
    .await;
    assert_refused(
        &refused,
        StatusCode::SERVICE_UNAVAILABLE,
        "connection_limit_reached",
    );
}

/// The slot has to come back when a tunnel ends, or a long-lived connection
/// slowly dies. This is the leak test in miniature; `it_stress` runs it 500 times.
#[tokio::test]
async fn a_finished_tunnel_returns_its_slot() {
    let server = TestServer::start_with(&format!(
        "[limits]\nmax_targets_per_conn = 1\n{ALLOW_PRIVATE}"
    ))
    .await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (response, mut stream) =
        open_tunnel(&mut client, connect_request(&target.to_string())).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Close the tunnel from the client side and let it drain.
    stream.finish().await.expect("finish the request stream");
    common::read_to_end(&mut stream).await;

    // The slot is released when the server-side task ends, a moment after the
    // stream closes, so allow it to catch up rather than racing it.
    let mut last = None;
    for _ in 0..40 {
        let response = respond_to(&mut client, connect_request(&target.to_string())).await;
        if response.status() == StatusCode::OK {
            return;
        }
        last = Some(response.status());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!("the slot was never released, last status was {last:?}");
}

// ---------------------------------------------------------------------------
// Amplification mitigation
// ---------------------------------------------------------------------------

/// A session whose target never answers may not be used as a flood engine: only
/// the configured budget of packets gets through (RFC 9298 §7).
#[tokio::test]
async fn packets_to_a_silent_target_are_capped() {
    const BUDGET: u64 = 3;
    const SENT: u64 = 20;

    let server = TestServer::start_with(&format!(
        "[security]\nallow_private_networks = true\nunanswered_packet_budget = {BUDGET}\n"
    ))
    .await;
    let (target, received) = spawn_silent_udp_target().await;
    let mut client = H3Client::connect(&server).await;

    let (response, _stream) = open_tunnel(
        &mut client,
        connect_udp_request(server.addr, &target.ip().to_string(), target.port()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let qsid = datagram::quarter_stream_id(_stream.id().into_inner());
    for i in 0..SENT {
        client
            .quic
            .send_datagram(datagram::encode_udp_payload(
                qsid,
                format!("packet {i}").as_bytes(),
            ))
            .expect("send datagram");
    }

    // Wait for the budget to be spent, then keep waiting to catch any leak past
    // it. Without the cap all 20 packets would arrive.
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while received.load(std::sync::atomic::Ordering::Relaxed) < BUDGET {
        assert!(
            tokio::time::Instant::now() < deadline,
            "only {} of the {BUDGET} budgeted packets arrived",
            received.load(std::sync::atomic::Ordering::Relaxed)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        received.load(std::sync::atomic::Ordering::Relaxed),
        BUDGET,
        "no packet may pass the budget until the target answers"
    );
}

/// Once the target has answered, the conversation is consensual and the cap is
/// gone — a budget of one must not throttle a working flow.
#[tokio::test]
async fn the_cap_is_lifted_once_the_target_answers() {
    let server = TestServer::start_with(
        "[security]\nallow_private_networks = true\nunanswered_packet_budget = 1\n",
    )
    .await;
    let target = spawn_udp_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let (response, stream) = open_tunnel(
        &mut client,
        connect_udp_request(server.addr, &target.ip().to_string(), target.port()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let qsid = datagram::quarter_stream_id(stream.id().into_inner());

    // The one packet the budget allows, and its echo: that reply lifts the cap.
    client
        .quic
        .send_datagram(datagram::encode_udp_payload(qsid, b"first"))
        .expect("send datagram");
    let echoed = tokio::time::timeout(TIMEOUT, client.quic.read_datagram())
        .await
        .expect("the first packet is answered")
        .expect("datagram");
    let decoded = datagram::decode(echoed).expect("well formed");
    assert_eq!(&decoded.payload[..], b"first");

    // Everything after it flows normally.
    for i in 0..5u8 {
        let payload = [b'x', i];
        client
            .quic
            .send_datagram(datagram::encode_udp_payload(qsid, &payload))
            .expect("send datagram");

        let reply = tokio::time::timeout(TIMEOUT, client.quic.read_datagram())
            .await
            .expect("the cap must be lifted after the first reply")
            .expect("datagram");
        let decoded = datagram::decode(reply).expect("well formed");
        assert_eq!(&decoded.payload[..], &payload);
    }
}
