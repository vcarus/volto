//! Client address migration (RFC 9000 §9): the server must carry a connection
//! and its tunnels across a mid-life change of the peer's address — what a
//! phone produces when it hops from cellular onto Wi-Fi. Field-verified
//! against Surge iOS (2026-08-14); these tests pin that behavior against
//! upstream bumps or a stray `migration(false)` in the transport config.

mod common;

use bytes::Bytes;
use common::{open_tcp_tunnel, read_at_least, spawn_echo_target, H3Client, TestServer};

#[tokio::test]
async fn a_tcp_tunnel_survives_the_client_changing_address() {
    let server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    stream
        .send_data(Bytes::from_static(b"before the move"))
        .await
        .expect("send before rebinding");
    let echoed = read_at_least(&mut stream, b"before the move".len()).await;
    assert_eq!(&echoed, b"before the move");

    client.rebind();

    // The same stream keeps carrying bytes across the address change; a server
    // that resets or drops the connection on migration fails here.
    stream
        .send_data(Bytes::from_static(b"after the move"))
        .await
        .expect("send after rebinding");
    let echoed = read_at_least(&mut stream, b"after the move".len()).await;
    assert_eq!(&echoed, b"after the move");
}

#[tokio::test]
async fn new_tunnels_open_after_the_client_changed_address() {
    let server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    client.rebind();

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    stream
        .send_data(Bytes::from_static(b"fresh tunnel"))
        .await
        .expect("send on the fresh tunnel");
    let echoed = read_at_least(&mut stream, b"fresh tunnel".len()).await;
    assert_eq!(&echoed, b"fresh tunnel");
}
