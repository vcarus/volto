//! M1: TCP CONNECT tunnels (RFC 9114 §4.4) and request dispatch.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use common::{
    assert_peer_reset, closed_address, connect_request, open_tcp_tunnel, read_at_least,
    read_to_end, respond_to, send_and_respond, spawn_drain_then_reply_target, spawn_echo_target,
    spawn_end_reporting_target, spawn_flood_then_reset_target, spawn_reset_after_read_target,
    ConnectionEnd, H3Client, TestServer, ALLOW_PRIVATE, TIMEOUT,
};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use volto::h3api::{Method, Request, Status};

/// H3_CONNECT_ERROR (RFC 9114 §8.1).
const H3_CONNECT_ERROR: u64 = 0x010f;

#[tokio::test]
async fn tunnels_bytes_to_an_echo_target() {
    let server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    stream
        .send_data(Bytes::from_static(b"hello volto"))
        .await
        .expect("send payload");

    let echoed = read_at_least(&mut stream, b"hello volto".len()).await;
    assert_eq!(&echoed, b"hello volto");

    // The tunnel stays usable for a second exchange on the same stream.
    stream
        .send_data(Bytes::from_static(b"again"))
        .await
        .expect("send again");
    let echoed = read_at_least(&mut stream, b"again".len()).await;
    assert_eq!(&echoed, b"again");
}

/// The half-close case: the client finishes its sending side first and must
/// still receive everything the target sends afterwards.
///
/// The target deliberately replies only after it has seen EOF, so it can answer
/// at all only if the client's stream FIN was translated into a shutdown of the
/// *write* side of the target socket rather than a full close.
#[tokio::test]
async fn client_half_close_still_receives_remaining_target_data() {
    let server = TestServer::start().await;
    let target = spawn_drain_then_reply_target("+TAIL").await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    stream
        .send_data(Bytes::from_static(b"ping"))
        .await
        .expect("send payload");

    // Client FIN. The target must see EOF, not a reset.
    stream.finish().expect("finish the sending side");

    // The target's remaining data must arrive, followed by a clean stream end
    // once the target closes (target EOF -> we finish our sending side).
    let received = read_to_end(&mut stream).await;
    assert_eq!(
        &received, b"ping+TAIL",
        "expected the target's post-EOF reply to survive the client's half-close"
    );
}

/// A target that resets after the tunnel is up must surface as a stream reset
/// with H3_CONNECT_ERROR, not as a clean end of stream.
///
/// This is the case the *read* pump notices, because the client is not uploading
/// and the write pump is parked reading from it. Its sibling below covers the
/// other order, where the write pump is the one that finds the target gone.
#[tokio::test]
async fn target_reset_becomes_h3_connect_error() {
    let server = TestServer::start().await;
    let target = spawn_reset_after_read_target().await;
    let mut client = H3Client::connect(&server).await;

    // The 200 goes out as soon as the TCP connection is established. The target
    // resets only after it has read, so this cannot be overtaken by the reset.
    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    // Triggers the target's reset.
    stream
        .send_data(Bytes::from_static(b"go"))
        .await
        .expect("send payload");

    // Matched rather than `expect_err`ed: the point is to name what a success
    // would have meant, which a panic message from `expect_err` cannot.
    let error = match tokio::time::timeout(TIMEOUT, stream.recv_data())
        .await
        .expect("the reset arrived")
    {
        Ok(_) => panic!("a target reset must not look like a clean end of stream"),
        Err(error) => error,
    };

    assert_peer_reset(&error, H3_CONNECT_ERROR);
}

/// The same target reset, noticed by the *write* pump instead.
///
/// The client keeps uploading and does not read the tunnel while it does, which
/// parks the write pump in `write_all` and the read pump in `send_data` — so
/// when the RST lands only the write pump is in a position to see it. It used to
/// stop the client's sending side and then simply return, dropping the writer,
/// and a dropped `quinn::SendStream` finishes rather than resets: the response
/// direction ended in a clean FIN. That is the truncation shape, and what an
/// upload-shaped protocol through the tunnel would read as a complete response.
/// RFC 9114 §4.4 rules it out — any error on the TCP connection, a received RST
/// included, is a stream error of type H3_CONNECT_ERROR.
#[tokio::test]
async fn target_reset_during_a_client_upload_becomes_h3_connect_error() {
    let server = TestServer::start().await;
    // Comfortably past the client's 1.25 MB stream flow-control window, so the
    // proxy still has unsent target data when the reset arrives.
    let target = spawn_flood_then_reset_target(8 * 1024 * 1024).await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    // Pushed from a task so the stream comes back afterwards for the response
    // direction, and deliberately without reading it in the meantime. The byte
    // bound is only a backstop: the upload parks on flow control long before it,
    // because the proxy has stopped reading the stream.
    let payload = Bytes::from(vec![0xa5u8; 64 * 1024]);
    let upload = tokio::spawn(async move {
        let mut sent = 0usize;
        loop {
            if let Err(error) = stream.send_data(payload.clone()).await {
                return (Some(error), stream);
            }
            sent += payload.len();
            if sent > 64 * 1024 * 1024 {
                return (None, stream);
            }
        }
    });

    let (send_error, mut stream) = tokio::time::timeout(TIMEOUT, upload)
        .await
        .expect("the upload must end")
        .expect("the upload task");

    let send_error = send_error.expect("the client's upload must be stopped by the target's reset");
    assert_peer_reset(&send_error, H3_CONNECT_ERROR);

    // Drain what the target managed to send before the reset; the flood is there
    // to pin the read pump, not to be checked. What matters is how it ends.
    let error = tokio::time::timeout(TIMEOUT, async {
        loop {
            match stream.recv_data().await {
                Ok(Some(_)) => continue,
                Ok(None) => panic!(
                    "a target reset reached the client as a clean end of stream: a truncated \
                     response is indistinguishable from a complete one"
                ),
                Err(error) => return error,
            }
        }
    })
    .await
    .expect("the reset arrived");

    assert_peer_reset(&error, H3_CONNECT_ERROR);
}

/// RFC 9114 §4.4: "if the underlying TCP implementation permits it, the proxy
/// SHOULD send a TCP segment with the RST bit set" when the client resets the
/// tunnel. Observable at the target as `ECONNRESET` on a read that would have
/// returned a clean EOF had the proxy closed with a FIN.
#[tokio::test]
async fn client_reset_aborts_the_target_connection() {
    let server = TestServer::start().await;
    let (target, mut ended) = spawn_end_reporting_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    // Abruptly reset the request stream instead of finishing it.
    stream.stop_stream(volto::h3api::Code::H3_REQUEST_CANCELLED);
    drop(stream);

    let end = tokio::time::timeout(TIMEOUT, ended.recv())
        .await
        .expect("the target connection must be closed after a client reset")
        .expect("close notification");

    assert_eq!(
        end,
        ConnectionEnd::Failed(std::io::ErrorKind::ConnectionReset),
        "an aborted tunnel must reach the target as a reset, not as a clean EOF"
    );
}

/// The counterpart, and the regression that stops the reset above from leaking
/// into the normal path: a client that finishes its sending side cleanly must
/// still reach the target as a FIN, i.e. as a clean EOF.
#[tokio::test]
async fn a_clean_client_close_still_reaches_the_target_as_eof() {
    let server = TestServer::start().await;
    let (target, mut ended) = spawn_end_reporting_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    stream
        .send_data(Bytes::from_static(b"hello"))
        .await
        .expect("send payload");
    stream.finish().expect("finish the sending side");

    let end = tokio::time::timeout(TIMEOUT, ended.recv())
        .await
        .expect("the target must see the client's FIN")
        .expect("close notification");

    assert_eq!(
        end,
        ConnectionEnd::Eof,
        "a clean half-close must stay a FIN: RFC 9114 §4.4 half-close semantics \
         depend on the target seeing an ordinary end of stream"
    );
}

#[tokio::test]
async fn refuses_a_target_that_is_not_listening() {
    let server = TestServer::start().await;
    let target = closed_address().await;
    let mut client = H3Client::connect(&server).await;

    let response = respond_to(&mut client, connect_request(&target.to_string())).await;

    // RFC 9114 §4.4: failure to establish the connection is reported with a
    // non-2xx status, not a stream reset.
    assert_eq!(response.status, Status::BAD_GATEWAY);

    // RFC 9209 §2.1.2: the refusal names the hop that refused it, as a
    // structured field String. Only failures to reach a target carry it.
    assert_eq!(
        response
            .fields
            .get("proxy-status")
            .map(|value| value.to_str().expect("proxy-status is ASCII")),
        Some(format!("volto; error=connection_refused; next-hop=\"{target}\"").as_str()),
        "the refusal must name the address that refused the connection"
    );
}

/// Arms an address that black-holes SYNs, in the only portable way there is.
///
/// A listening socket with the smallest possible backlog whose `accept` is never
/// called: once the accept queue is full the kernel simply drops further SYNs,
/// which is exactly what a target behind a silently discarding firewall looks
/// like from here — the connect neither completes nor fails, it just never
/// finishes. Filling the queue is done by connecting until an attempt stops
/// completing, which is also the proof that the arming worked.
///
/// Returns the address, the connections holding the queue full, and the listener
/// — all three must stay alive for the address to keep black-holing. `None`
/// means this kernel does not behave that way, and the caller should skip rather
/// than fail: a differently tuned host must not make the suite red.
async fn arm_a_blackholed_address() -> Option<(SocketAddr, Vec<TcpStream>, TcpListener)> {
    let socket = TcpSocket::new_v4().ok()?;
    socket
        .bind("127.0.0.1:0".parse().expect("bind address"))
        .ok()?;
    let listener = socket.listen(1).ok()?;
    let addr = listener.local_addr().ok()?;

    let mut holding = Vec::new();
    for _ in 0..20 {
        match tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(addr)).await {
            // The queue has room still; keep the connection so it stays taken.
            Ok(Ok(held)) => holding.push(held),
            // Refused rather than dropped: this kernel does not black-hole.
            Ok(Err(_)) => return None,
            // A SYN that draws no answer at all: the queue is full.
            Err(_) => return Some((addr, holding, listener)),
        }
    }

    None
}

/// A target that swallows SYNs must cost the client its connect budget and then
/// a refusal, rather than holding the tunnel slot for the operating system's own
/// retry schedule — around two minutes on Linux.
#[tokio::test]
async fn a_black_holed_target_is_refused_when_the_connect_budget_expires() {
    let Some((blackhole, _holding, _listener)) = arm_a_blackholed_address().await else {
        eprintln!(
            "skipping: this kernel does not drop SYNs for a full accept queue, so no \
             black-holed address can be arranged"
        );
        return;
    };

    let server =
        TestServer::start_with(&format!("[limits]\nconnect_timeout = 1\n{ALLOW_PRIVATE}")).await;
    let mut client = H3Client::connect(&server).await;

    let started = std::time::Instant::now();
    let response = respond_to(&mut client, connect_request(&blackhole.to_string())).await;
    let elapsed = started.elapsed();

    // RFC 9209: a target that never answered is a timeout, not an unreachable
    // one, and the status follows the registered type.
    assert_eq!(response.status, Status::GATEWAY_TIMEOUT);
    let proxy_status = response
        .fields
        .get("proxy-status")
        .map(|value| value.to_str().expect("proxy-status is ASCII"))
        .expect("a refusal must say why");
    assert!(
        proxy_status.contains("error=connection_timeout"),
        "{proxy_status}"
    );
    // And it names the hop it gave up on.
    assert!(
        proxy_status.contains(&blackhole.to_string()),
        "{proxy_status}"
    );

    // The budget, not the kernel, decided when to give up.
    assert!(
        elapsed >= Duration::from_millis(800),
        "answered before the budget expired, after {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the connect was not bounded by the budget: {elapsed:?}"
    );

    // And the tunnel slot went back: the same connection still serves a target
    // that does answer.
    let target = spawn_echo_target().await;
    let mut good = open_tcp_tunnel(&mut client, &target.to_string()).await;

    good.send_data(Bytes::from_static(b"after the timeout"))
        .await
        .expect("send payload");
    let echoed = read_at_least(&mut good, b"after the timeout".len()).await;
    assert_eq!(&echoed, b"after the timeout");
}

/// A request this proxy will not serve is answered and *finished*, never reset.
///
/// Decision D40, and the reason the second half of this test exists: a status
/// that is immediately followed by a RESET_STREAM is worse than useless, because
/// the client is entitled to read the reset as "the proxy broke" and may retry or
/// fail over instead of surfacing the 400. Only reading past the response to a
/// clean end of stream tells the two apart — `recv_response` succeeds either way.
#[tokio::test]
async fn refuses_an_authority_without_a_port() {
    let server = TestServer::start().await;
    let mut client = H3Client::connect(&server).await;

    let (response, mut stream) =
        send_and_respond(&mut client, connect_request("example.com")).await;

    assert_eq!(response.status, Status::BAD_REQUEST);

    let end = tokio::time::timeout(TIMEOUT, stream.recv_data())
        .await
        .expect("the stream ended promptly")
        .expect("a refusal must end cleanly, not with a stream error");
    assert!(
        end.is_none(),
        "a 400 carries no body: the next read is the end of the stream"
    );
}

/// A proxy is not an origin server: ordinary requests are refused, not panicked
/// on.
#[tokio::test]
async fn plain_get_is_not_implemented() {
    let server = TestServer::start().await;
    let mut client = H3Client::connect(&server).await;

    let mut req = Request::new(Method::Other("GET".into()));
    req.scheme = Some("https".into());
    req.authority = Some(server.addr.to_string().into());
    req.path = Some("/".into());

    let response = respond_to(&mut client, req).await;

    assert_eq!(response.status, Status::NOT_IMPLEMENTED);
}

/// Several tunnels multiplexed on one QUIC connection must stay independent.
#[tokio::test]
async fn concurrent_tunnels_on_one_connection_stay_independent() {
    let server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut streams = Vec::new();
    for i in 0..5u8 {
        let stream = open_tcp_tunnel(&mut client, &target.to_string()).await;
        streams.push((i, stream));
    }

    // Write a distinct payload per tunnel, then check each one got its own back.
    for (i, stream) in &mut streams {
        stream
            .send_data(Bytes::from(vec![*i; 8]))
            .await
            .expect("send payload");
    }
    for (i, stream) in &mut streams {
        let echoed = read_at_least(stream, 8).await;
        assert_eq!(echoed, vec![*i; 8], "tunnel {i} received another's bytes");
    }
}
