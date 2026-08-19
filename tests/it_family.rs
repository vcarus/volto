//! D58: which address family a dual-stack target name is tried on first.
//!
//! Asserted from outside the proxy, in the only way that is observable there:
//! two targets listening on the *same port*, one on `127.0.0.1` and one on
//! `::1`, and a CONNECT to `localhost` on that port. Whichever target answers is
//! the family the proxy chose, so the assertion is on-wire behaviour rather than
//! on the ordering helper the tunnels happen to call.
//!
//! The environment decides whether this is testable at all: `localhost` must
//! resolve to both families and `::1` must be bindable. Both hold on the macOS
//! development host; some Linux CI images ship neither, so the tests skip with a
//! reason instead of failing there.

mod common;

use std::collections::HashSet;
use std::net::SocketAddr;

use common::{
    open_tcp_tunnel, open_udp_session_to, read_at_least, H3Client, TestServer, ALLOW_PRIVATE,
    TIMEOUT,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use volto::datagram;

/// Selects the non-default preference, so the same targets prove both branches.
const IPV6_FIRST: &str = "[limits]\nip_family_preference = \"ipv6\"\n";

/// What the target on each family answers with.
const V4_TAG: &[u8] = b"v4";
const V6_TAG: &[u8] = b"v6";

/// How many ephemeral ports to try before giving up on finding one that is free
/// on both loopback addresses.
const PORT_ATTEMPTS: usize = 32;

/// Whether `localhost` resolves to both families on this host.
///
/// The whole premise of these tests: with only one family behind the name there
/// is no choice for the preference to make.
async fn localhost_is_dual_stack() -> bool {
    let Ok(addresses) = tokio::net::lookup_host(("localhost", 443)).await else {
        return false;
    };
    let families: HashSet<bool> = addresses.map(|address| address.is_ipv6()).collect();
    families.len() == 2
}

/// A pair of TCP listeners on the same port, one per loopback family.
///
/// `None` means this host cannot host the experiment — either `::1` is not
/// bindable, or every ephemeral port tried was already taken on the IPv6 side.
async fn dual_stack_tcp_listeners() -> Option<(TcpListener, TcpListener, u16)> {
    if TcpListener::bind("[::1]:0").await.is_err() {
        return None;
    }

    for _ in 0..PORT_ATTEMPTS {
        let v4 = TcpListener::bind("127.0.0.1:0").await.ok()?;
        let port = v4.local_addr().ok()?.port();
        if let Ok(v6) = TcpListener::bind(("::1", port)).await {
            return Some((v4, v6, port));
        }
    }

    None
}

/// The same pair for UDP.
async fn dual_stack_udp_sockets() -> Option<(UdpSocket, UdpSocket, u16)> {
    if UdpSocket::bind("[::1]:0").await.is_err() {
        return None;
    }

    for _ in 0..PORT_ATTEMPTS {
        let v4 = UdpSocket::bind("127.0.0.1:0").await.ok()?;
        let port = v4.local_addr().ok()?.port();
        if let Ok(v6) = UdpSocket::bind(("::1", port)).await {
            return Some((v4, v6, port));
        }
    }

    None
}

/// Answers every accepted connection with `tag` and then holds it open.
fn announce_tcp(listener: TcpListener, tag: &'static [u8]) {
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                if socket.write_all(tag).await.is_err() {
                    return;
                }
                // Held open so the proxy does not see an EOF that could be
                // mistaken for the target being unusable.
                let mut buf = [0u8; 64];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                }
            });
        }
    });
}

/// Answers every datagram with `tag`.
fn announce_udp(socket: UdpSocket, tag: &'static [u8]) {
    common::spawn_udp_target_on(socket, |_| Some(tag.to_vec()));
}

/// CONNECTs to `localhost:port` through `server` and returns the target's tag.
async fn tag_through_tcp_tunnel(server: &TestServer, port: u16) -> Vec<u8> {
    let mut client = H3Client::connect(server).await;
    let mut stream = open_tcp_tunnel(&mut client, &format!("localhost:{port}")).await;

    read_at_least(&mut stream, V4_TAG.len()).await
}

/// Opens a CONNECT-UDP session to `localhost:port` and returns the target's tag.
async fn tag_through_udp_tunnel(server: &TestServer, port: u16) -> Vec<u8> {
    let mut client = H3Client::connect(server).await;
    let (quarter_stream_id, _stream) =
        open_udp_session_to(&mut client, server, "localhost", port).await;

    client
        .quic
        .send_datagram(datagram::encode_udp_payload(quarter_stream_id, b"which?"))
        .expect("send datagram");

    loop {
        let raw = tokio::time::timeout(TIMEOUT, client.quic.read_datagram())
            .await
            .expect("a datagram arrived")
            .expect("datagram");
        let decoded = datagram::decode(raw).expect("server datagrams must be well formed");
        if decoded.quarter_stream_id == quarter_stream_id {
            return decoded.payload.to_vec();
        }
    }
}

/// Why the environment cannot run these tests.
///
/// One message per reason, so a skip in CI says which half was missing.
fn skip_reason(dual_stack: bool) -> &'static str {
    if dual_stack {
        "could not bind the same port on both 127.0.0.1 and ::1 (no IPv6 loopback, or every \
         port tried was already taken)"
    } else {
        "`localhost` does not resolve to both address families here, so there is no family \
         choice for the proxy to make"
    }
}

/// The TCP tunnel walks the resolved list in order, so the preference decides
/// which family is dialled first and — both targets being up — which answers.
#[tokio::test]
async fn connect_dials_the_preferred_family_first() {
    let dual_stack = localhost_is_dual_stack().await;
    let listeners = if dual_stack {
        dual_stack_tcp_listeners().await
    } else {
        None
    };

    let Some((v4, v6, port)) = listeners else {
        eprintln!(
            "skipping connect_dials_the_preferred_family_first: {}",
            skip_reason(dual_stack)
        );
        return;
    };

    announce_tcp(v4, V4_TAG);
    announce_tcp(v6, V6_TAG);

    // The default is IPv4-first, which is *not* what RFC 6724 would have ordered
    // for a dual-stack name.
    let server = TestServer::start().await;
    assert_eq!(
        tag_through_tcp_tunnel(&server, port).await,
        V4_TAG,
        "the default preference must reach the IPv4 target"
    );
    drop(server);

    let server = TestServer::start_with(&format!("{IPV6_FIRST}{ALLOW_PRIVATE}")).await;
    assert_eq!(
        tag_through_tcp_tunnel(&server, port).await,
        V6_TAG,
        "ip_family_preference = \"ipv6\" must reach the IPv6 target"
    );
}

/// The CONNECT-UDP path has no failover at all — the socket is connected to the
/// first address with a route — so on that path the ordering is the whole
/// decision, which makes this the more important of the two.
#[tokio::test]
async fn connect_udp_binds_a_socket_to_the_preferred_family() {
    let dual_stack = localhost_is_dual_stack().await;
    let sockets = if dual_stack {
        dual_stack_udp_sockets().await
    } else {
        None
    };

    let Some((v4, v6, port)) = sockets else {
        eprintln!(
            "skipping connect_udp_binds_a_socket_to_the_preferred_family: {}",
            skip_reason(dual_stack)
        );
        return;
    };

    announce_udp(v4, V4_TAG);
    announce_udp(v6, V6_TAG);

    let server = TestServer::start().await;
    assert_eq!(
        tag_through_udp_tunnel(&server, port).await,
        V4_TAG,
        "the default preference must bind a socket to the IPv4 target"
    );
    drop(server);

    let server = TestServer::start_with(&format!("{IPV6_FIRST}{ALLOW_PRIVATE}")).await;
    assert_eq!(
        tag_through_udp_tunnel(&server, port).await,
        V6_TAG,
        "ip_family_preference = \"ipv6\" must bind a socket to the IPv6 target"
    );
}

/// A sanity check on the premise rather than on the proxy: if this fails, the
/// two tests above are skipping for a reason that is no longer true.
#[tokio::test]
async fn the_environment_probe_agrees_with_the_resolver() {
    let addresses: Vec<SocketAddr> = match tokio::net::lookup_host(("localhost", 443)).await {
        Ok(addresses) => addresses.collect(),
        Err(_) => Vec::new(),
    };
    let dual_stack = localhost_is_dual_stack().await;
    assert_eq!(
        dual_stack,
        addresses.iter().any(SocketAddr::is_ipv4) && addresses.iter().any(SocketAddr::is_ipv6),
        "the probe and the resolver must agree: {addresses:?}"
    );
}
