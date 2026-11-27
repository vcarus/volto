//! Client address migration (RFC 9000 §9): the server must carry a connection
//! and its tunnels across a mid-life change of the peer's address — what a
//! phone produces when it hops from cellular onto Wi-Fi. This test fails if
//! the server config disables migration.

mod common;

use common::{H3Client, TestServer, echoes, open_tcp_tunnel, spawn_echo_target};

/// A tunnel open before the move keeps carrying bytes after it, and a new
/// tunnel opens on the moved connection.
#[tokio::test]
async fn a_tcp_tunnel_survives_the_client_changing_address() {
    let server = TestServer::start().await;
    let target = spawn_echo_target().await;
    let mut client = H3Client::connect(&server).await;

    let mut stream = open_tcp_tunnel(&mut client, &target.to_string()).await;

    echoes(&mut stream, b"before the move").await;

    client.rebind();

    // The same stream keeps carrying bytes across the address change; a server
    // that resets or drops the connection on migration fails here.
    echoes(&mut stream, b"after the move").await;

    let mut fresh = open_tcp_tunnel(&mut client, &target.to_string()).await;
    echoes(&mut fresh, b"fresh tunnel").await;
}
