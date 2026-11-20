//! The server's TLS end to end: TCP CONNECT and CONNECT-UDP with and without
//! ECH, the ECH key at startup and on reload, and the lines that report it.
//!
//! The client is quinn on rustls, an independent TLS implementation with
//! client-side ECH. On the server side, "ECH accepted" comes from the
//! provider's debug line, read back through `SharedBuffer`. On the client side
//! it is the handshake itself: rustls in `EchMode::Enable` never completes a
//! handshake that the server answered on the outer ClientHello; it fails with
//! `ServerRejectedEncryptedClientHello`, which the reload scenario shows.
//!
//! One test function, because the log subscriber is process-wide (see
//! `SharedBuffer`).

mod common;

use std::sync::Arc;

use common::{
    ALLOW_PRIVATE, H3Client, SharedBuffer, TempDir, TestServer, finish_connect, open_tcp_tunnel,
    open_udp_session, spawn_echo_target, spawn_udp_echo_target, udp_round_trip,
};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::{EchConfig, EchMode};
use rustls::pki_types::{CertificateDer, EchConfigListBytes};
use volto::config::Config;
use volto::tls::EchKey;

const PUBLIC_NAME: &str = "public.example";

/// A quinn client on rustls with ECH enabled for `list`, X25519MLKEM768 first
/// as Surge orders its groups.
fn ech_endpoint(ca: &CertificateDer<'static>, list: &[u8]) -> quinn::Endpoint {
    ech_endpoint_idle(ca, list, None)
}

/// How long a client that is meant to hear nothing waits before it gives up,
/// which turns the silence into `ConnectionError::TimedOut`.
const CLIENT_IDLE: std::time::Duration = std::time::Duration::from_secs(2);

/// [`ech_endpoint`] with its idle timeout set to `idle`, when given.
fn ech_endpoint_idle(
    ca: &CertificateDer<'static>,
    list: &[u8],
    idle: Option<std::time::Duration>,
) -> quinn::Endpoint {
    use rustls::crypto::aws_lc_rs::kx_group;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).expect("trust the test CA");
    let provider = Arc::new(rustls::crypto::CryptoProvider {
        kx_groups: vec![
            kx_group::X25519MLKEM768,
            kx_group::X25519,
            kx_group::SECP256R1,
            kx_group::SECP384R1,
        ],
        ..rustls::crypto::aws_lc_rs::default_provider()
    });
    let ech = EchConfig::new(
        EchConfigListBytes::from(list.to_vec()),
        rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
    )
    .expect("rustls accepts the server's ECHConfigList");
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_ech(EchMode::from(ech))
        .expect("ECH with TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto).expect("quic tls"),
    ));
    if let Some(idle) = idle {
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(idle.try_into().expect("a legal idle timeout")));
        transport.keep_alive_interval(None);
        client_config.transport_config(Arc::new(transport));
    }
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("bind address")).expect("client");
    endpoint.set_default_client_config(client_config);
    endpoint
}

/// One TCP CONNECT and one CONNECT-UDP echo through `client`.
async fn tcp_and_udp(client: &mut H3Client, server: &TestServer) {
    let target = spawn_echo_target().await;
    let mut stream = open_tcp_tunnel(client, &target.to_string()).await;
    stream
        .send_data(bytes::Bytes::from_static(b"over tcp"))
        .await
        .expect("send through the tunnel");
    let echoed = stream
        .recv_data()
        .await
        .expect("read the tunnel")
        .expect("the echo answers");
    assert_eq!(&echoed[..], b"over tcp");

    let udp_target = spawn_udp_echo_target().await;
    let (qsid, _session) = open_udp_session(client, server, udp_target).await;
    let answer = udp_round_trip(client, qsid, b"over udp").await;
    assert_eq!(&answer[..], b"over udp");
}

/// The one line containing `needle` since `mark`.
#[track_caller]
fn one_line(buffer: &SharedBuffer, mark: usize, needle: &str) -> String {
    let lines = buffer.lines_since(mark, &[needle]);
    assert_eq!(
        lines.len(),
        1,
        "one {needle:?} line expected; log was:\n{}",
        buffer.since(mark)
    );
    lines[0].clone()
}

/// A new ECH key file in `dir`, written the way `volto ech-keygen` writes it.
fn key_file(dir: &TempDir, name: &str, config_id: u8) -> (std::path::PathBuf, EchKey) {
    let key = EchKey::generate(PUBLIC_NAME, config_id, 0).expect("generate an ECH key");
    let path = dir.path().join(name);
    volto::tls::write_new_key_file(&path, &key).expect("write the key file");
    (path, key)
}

#[tokio::test]
async fn tunnels_run_over_the_servers_tls_with_and_without_ech() {
    let buffer = SharedBuffer::install("volto=debug");

    // Without ECH: plain TLS 1.3, and the startup line says so.
    let mark = buffer.mark();
    let server = TestServer::start_with(ALLOW_PRIVATE).await;
    let mut client = H3Client::connect(&server).await;
    tcp_and_udp(&mut client, &server).await;
    let start = one_line(&buffer, mark, "accepting QUIC connections");
    assert!(
        start.contains("ech=false ech_config_id=- ech_public_name=-"),
        "{start}"
    );
    let line = one_line(&buffer, mark, "TLS handshake complete");
    assert!(line.contains("ech_accepted=false"), "{line}");
    assert!(line.contains("outer_sni=localhost"), "{line}");
    // The common test client lists X25519 first (rustls's default order), and
    // the server takes the client's first choice.
    assert!(line.contains("group=X25519 "), "{line}");
    drop(client);
    drop(server);

    // With ECH.
    let keys = TempDir::new("ech");
    let (key_path, key) = key_file(&keys, "ech.pem", 7);
    let list = key.config_list();
    let mark = buffer.mark();
    let server = TestServer::start_with(&format!(
        "ech_key = \"{}\"\n{ALLOW_PRIVATE}",
        key_path.display()
    ))
    .await;
    // The server was started from the file, and the file prints the list the
    // client holds.
    let config = Config::load(&server.dir().join("config.toml")).expect("the config loads");
    assert_eq!(
        EchKey::load(config.server.ech_key.as_deref().expect("ech_key is set"))
            .expect("the key file loads")
            .config_list(),
        list
    );

    let mut client = H3Client::connect_on(ech_endpoint(&server.ca, &list), &server).await;
    tcp_and_udp(&mut client, &server).await;
    let start = one_line(&buffer, mark, "accepting QUIC connections");
    assert!(
        start.contains(&format!(
            "ech=true ech_config_id=7 ech_public_name={PUBLIC_NAME}"
        )),
        "{start}"
    );
    let line = one_line(&buffer, mark, "TLS handshake complete");
    assert!(line.contains("ech_accepted=true"), "{line}");
    assert!(line.contains("inner_sni=localhost"), "{line}");
    assert!(line.contains(&format!("outer_sni={PUBLIC_NAME}")), "{line}");
    assert!(line.contains("ech_config_id=7"), "{line}");
    assert!(line.contains("group=X25519MLKEM768"), "{line}");
    // The access path saw the inner name.
    let established = one_line(&buffer, mark, "connection established");
    assert!(
        established.contains("server_name=localhost"),
        "{established}"
    );
    drop(client);

    // A plain client still gets in: ECH is accepted, not required.
    let mark = buffer.mark();
    let mut client = H3Client::connect(&server).await;
    tcp_and_udp(&mut client, &server).await;
    assert!(one_line(&buffer, mark, "TLS handshake complete").contains("ech_accepted=false"));
    drop(client);

    // A reload with a new key file puts the new key in force: the old list no
    // longer opens, so the socket gate drops its handshake without any reply
    // (D115, batch 2), and the new list is accepted.
    let (new_path, new_key) = key_file(&keys, "ech-new.pem", 9);
    server.rewrite_config(&format!(
        "ech_key = \"{}\"\n{ALLOW_PRIVATE}",
        new_path.display()
    ));
    let mark = buffer.mark();
    server.reload().expect("the reload applies");
    let reloaded = one_line(&buffer, mark, "configuration reloaded");
    assert!(
        reloaded.contains(&format!(
            "ech=true ech_config_id=9 ech_public_name={PUBLIC_NAME}"
        )),
        "{reloaded}"
    );
    let error = finish_connect(
        &ech_endpoint_idle(&server.ca, &list, Some(CLIENT_IDLE)),
        server.addr,
    )
    .await
    .expect_err("an ECH extension the key does not open completes no handshake");
    assert!(
        matches!(error, quinn::ConnectionError::TimedOut),
        "the old list must get silence, not a reply: {error:?}"
    );
    let mut client =
        H3Client::connect_on(ech_endpoint(&server.ca, &new_key.config_list()), &server).await;
    tcp_and_udp(&mut client, &server).await;
    drop(client);

    // A reload with a damaged key file changes nothing: the new key stays in
    // force, and the error names the key.
    let broken = keys.path().join("broken.pem");
    std::fs::write(
        &broken,
        "-----BEGIN ECHCONFIG-----\nAAAA\n-----END ECHCONFIG-----\n",
    )
    .expect("write a broken key file");
    server.rewrite_config(&format!(
        "ech_key = \"{}\"\n{ALLOW_PRIVATE}",
        broken.display()
    ));
    let error = server.reload().expect_err("a broken key file is refused");
    assert!(format!("{error:#}").contains("server.ech_key"), "{error:#}");
    let mut client =
        H3Client::connect_on(ech_endpoint(&server.ca, &new_key.config_list()), &server).await;
    tcp_and_udp(&mut client, &server).await;
}
