//! Shared test harness: a self-signed Volto instance, HTTP/3 clients and
//! cooperating TCP targets.
//!
//! The test client is built from the same pinned `h3` revision as the server, so
//! these tests exercise exactly the code path a real client drives.

#![allow(dead_code)] // Each integration test binary uses a subset of this.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Method, Request, Uri};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use volto::config::Config;
use volto::quic::ReloadHandle;
use volto::quic::Server;
use volto::shutdown::Trigger;

/// Upper bound for anything that should complete promptly on loopback.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// Config fragment opening up private address space.
///
/// Every target in these tests is on loopback, which the destination policy
/// refuses by default — as it must, since that default is what stops a client
/// from reaching services that trust `127.0.0.1`. Tests that are *about* the
/// policy build their own `[security]` section instead; see `it_policy`.
pub const ALLOW_PRIVATE: &str = "[security]\nallow_private_networks = true\n";

/// One second of idle timeout, with keep-alives off so nothing refreshes it.
///
/// Keep-alives have to be disabled explicitly: the default 20s interval would both
/// fail validation against a 1s timeout and, if it did not, keep the connection
/// alive forever. A client that connects and then says nothing is timed out by the
/// server after about a second.
pub const IMPATIENT: &str = "[limits]\nmax_idle_timeout = 1\nkeep_alive_interval = 0\n";

/// Generous upper bound for a shutdown that should take about as long as its
/// grace period. Failing this means the grace period is not being enforced.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(20);

/// The client-side request stream type produced by [`H3Client::connect`].
pub type ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// A directory that deletes itself when dropped.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "volto-test-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A running Volto server on an ephemeral loopback port.
pub struct TestServer {
    /// The address the server is listening on.
    pub addr: SocketAddr,
    /// The self-signed certificate clients must trust.
    pub ca: CertificateDer<'static>,
    /// Kept alive: it holds the certificate, key and configuration file.
    dir: TempDir,
    /// The configuration file on disk, which `reload` re-reads.
    config_path: PathBuf,
    /// Certificate and key paths, so a rewritten config can point at them again.
    cert: PathBuf,
    key: PathBuf,
    /// Fires the graceful shutdown, exactly as the SIGTERM handler does.
    trigger: Trigger,
    /// Replaces the running configuration, exactly as the SIGHUP handler does.
    reload: ReloadHandle,
    /// `None` once the accept loop has been awaited by `wait_until_stopped`.
    task: Option<JoinHandle<()>>,
}

impl TestServer {
    /// Generates a certificate, binds the server and starts its accept loop.
    ///
    /// Loopback targets are reachable and authentication is off, which is what
    /// every test that is not about the security policy wants.
    pub async fn start() -> Self {
        Self::start_with(ALLOW_PRIVATE).await
    }

    /// Starts a server whose UDP sessions time out after `seconds`.
    ///
    /// Well below the RFC 9298 §3.1 recommendation, which the config layer warns
    /// about; tests cannot wait out a realistic timeout.
    pub async fn start_with_udp_timeout(seconds: u64) -> Self {
        Self::start_with(&format!(
            "[limits]\nudp_session_timeout = {seconds}\n{ALLOW_PRIVATE}"
        ))
        .await
    }

    /// Starts a server with `extra` spliced into its configuration file.
    ///
    /// `extra` is inserted directly after the `[server]` keys, so bare keys land
    /// in `[server]` and anything starting with a table header opens its own
    /// section.
    pub async fn start_with(extra: &str) -> Self {
        Self::start_with_log(extra, "").await
    }

    /// Starts a server with `extra` after the `[server]` keys and `log_extra`
    /// appended inside the `[log]` section.
    pub async fn start_with_log(extra: &str, log_extra: &str) -> Self {
        let dir = TempDir::new("server");
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate self-signed certificate");

        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, issued.cert.pem()).expect("write cert");
        std::fs::write(&key, issued.signing_key.serialize_pem()).expect("write key");
        let ca = issued.cert.der().clone();

        // Built through the real TOML path so the tests exercise config
        // parsing and stay unaffected by newly added optional sections.
        // Written to disk rather than parsed from a string, so the tests go
        // through the same `Config::load` path production does -- and so `reload`
        // has a file to re-read.
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, config_text(&cert, &key, extra, log_extra))
            .expect("write config");

        let config = Config::load(&config_path).expect("the test config must load");

        let server = Server::bind(Arc::new(config)).expect("bind server");
        let addr = server.local_addr().expect("local address");
        // Taken before the server moves into its task.
        let trigger = server.shutdown_trigger();
        let reload = server.reload_handle();
        let task = tokio::spawn(async move { server.run().await });

        Self {
            addr,
            ca,
            dir,
            config_path,
            cert,
            key,
            trigger,
            reload,
            task: Some(task),
        }
    }

    /// Rewrites the configuration file with a new `extra` section.
    ///
    /// Does not apply it: call [`Self::reload`], which is what `SIGHUP` does.
    pub fn rewrite_config(&self, extra: &str) {
        std::fs::write(
            &self.config_path,
            config_text(&self.cert, &self.key, extra, ""),
        )
        .expect("rewrite config");
    }

    /// Writes a deliberately broken configuration file.
    pub fn write_invalid_config(&self, text: &str) {
        std::fs::write(&self.config_path, text).expect("write invalid config");
    }

    /// Applies the configuration file, exactly as the `SIGHUP` handler does.
    pub fn reload(&self) -> anyhow::Result<()> {
        self.reload.reload(&self.config_path).map(|_| ())
    }

    /// The directory holding this server's certificate, key and config.
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// Starts the graceful shutdown, as SIGTERM does in production.
    pub fn shutdown(&self) {
        self.trigger.fire();
    }

    /// Waits for the accept loop to return, i.e. for shutdown to complete.
    ///
    /// Panics if it takes longer than `within`, which is how the grace period is
    /// asserted to be an upper bound rather than a suggestion.
    pub async fn wait_until_stopped(&mut self, within: Duration) {
        let task = self.task.take().expect("the server is only awaited once");
        tokio::time::timeout(within, task)
            .await
            .expect("the server stopped within the timeout")
            .expect("the server task did not panic");
    }
}

/// A `[auth]` section granting `users` access.
pub fn auth_section(users: &[(&str, &str)]) -> String {
    let mut section = String::from("[auth]\nusers = [\n");
    for (username, password) in users {
        section.push_str(&format!(
            "  {{ username = \"{username}\", password = \"{password}\" }},\n"
        ));
    }
    section.push_str("]\n");
    section
}

/// An HTTP Basic credentials field value.
///
/// Encoded here rather than through the server's own decoder, so a bug in that
/// decoder cannot make these tests agree with it.
pub fn basic_credentials(username: &str, password: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let plain = format!("{username}:{password}").into_bytes();
    let mut token = String::new();

    for quantum in plain.chunks(3) {
        let mut bits: u32 = 0;
        for i in 0..3 {
            bits = (bits << 8) | u32::from(quantum.get(i).copied().unwrap_or(0));
        }
        for i in 0..quantum.len() + 1 {
            token.push(char::from(
                ALPHABET[((bits >> (18 - 6 * i)) & 0x3f) as usize],
            ));
        }
        for _ in quantum.len() + 1..4 {
            token.push('=');
        }
    }

    format!("Basic {token}")
}

/// Renders a test configuration file.
///
/// `extra` is inserted directly after the `[server]` keys, so bare keys land in
/// `[server]` and anything starting with a table header opens its own section.
/// Written unindented: a TOML table header must start its own line.
fn config_text(cert: &Path, key: &Path, extra: &str, log_extra: &str) -> String {
    format!(
        "[server]\n\
         listen = \"127.0.0.1:0\"\n\
         cert = \"{cert}\"\n\
         key = \"{key}\"\n\
         {extra}\n\
         [log]\n\
         level = \"debug\"\n\
         {log_extra}\n",
        cert = cert.display(),
        key = key.display(),
    )
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// A QUIC client endpoint that trusts `ca` and offers `alpn`.
pub fn client_endpoint(ca: &CertificateDer<'static>, alpn: &[&str]) -> quinn::Endpoint {
    client_endpoint_with(ca, alpn, None)
}

/// [`client_endpoint`] with a per-stream receive window of `window` bytes.
///
/// quinn's default is 1.25 MB, which is a lot of data to push through a tunnel
/// before a server's write to the client blocks on it. Tests that need the
/// server *parked* on flow control shrink it instead of flooding.
pub fn client_endpoint_with_stream_window(
    ca: &CertificateDer<'static>,
    alpn: &[&str],
    window: u32,
) -> quinn::Endpoint {
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(window.into());
    client_endpoint_with(ca, alpn, Some(transport))
}

fn client_endpoint_with(
    ca: &CertificateDer<'static>,
    alpn: &[&str],
    transport: Option<quinn::TransportConfig>,
) -> quinn::Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).expect("trust the test CA");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto).expect("quic tls"),
    ));
    if let Some(transport) = transport {
        client_config.transport_config(Arc::new(transport));
    }

    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("bind address")).expect("client");
    endpoint.set_default_client_config(client_config);
    endpoint
}

/// Opens a raw QUIC connection to the server, without HTTP/3 on top.
pub async fn connect_quic(server: &TestServer) -> (quinn::Endpoint, quinn::Connection) {
    connect_quic_with_ca(server, server.ca.clone()).await
}

/// Opens a raw QUIC connection, trusting `ca` instead of the server's original.
///
/// Used to prove a reloaded certificate really took effect.
pub async fn connect_quic_with_ca(
    server: &TestServer,
    ca: CertificateDer<'static>,
) -> (quinn::Endpoint, quinn::Connection) {
    let endpoint = client_endpoint(&ca, &["h3"]);
    let connection = tokio::time::timeout(
        TIMEOUT,
        endpoint
            .connect(server.addr, "localhost")
            .expect("start connecting"),
    )
    .await
    .expect("handshake did not time out")
    .expect("handshake");

    (endpoint, connection)
}

/// An HTTP/3 client with its connection driven in the background.
pub struct H3Client {
    /// Handle used to open requests.
    pub send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    /// The underlying QUIC connection.
    ///
    /// HTTP Datagrams are not exposed by `h3` (this crate deliberately excludes
    /// `h3-datagram`), so tests drive them through quinn directly, exactly as the
    /// server does.
    pub quic: quinn::Connection,
    // Both are kept alive for as long as the client is: dropping the endpoint or
    // stopping the driver would tear the connection down.
    _endpoint: quinn::Endpoint,
    driver: JoinHandle<()>,
}

impl H3Client {
    /// Connects and completes the HTTP/3 handshake, advertising datagram support.
    pub async fn connect(server: &TestServer) -> Self {
        Self::connect_with_datagrams(server, true).await
    }

    /// Connects while trusting `ca` rather than the server's original certificate.
    pub async fn connect_with_ca(server: &TestServer, ca: CertificateDer<'static>) -> Self {
        let (endpoint, connection) = connect_quic_with_ca(server, ca).await;
        Self::from_quic(endpoint, connection, true).await
    }

    /// Connects without advertising `SETTINGS_H3_DATAGRAM`.
    ///
    /// RFC 9297 §2.1.1 then forbids the server from sending QUIC datagrams, so
    /// the session has to fall back to DATAGRAM capsules on the request stream.
    pub async fn connect_without_datagrams(server: &TestServer) -> Self {
        Self::connect_with_datagrams(server, false).await
    }

    /// [`H3Client::connect_without_datagrams`] with a per-stream receive window
    /// of `window` bytes, so a server writing capsules blocks after that much.
    pub async fn connect_without_datagrams_with_stream_window(
        server: &TestServer,
        window: u32,
    ) -> Self {
        let endpoint = client_endpoint_with_stream_window(&server.ca, &["h3"], window);
        let connection = tokio::time::timeout(
            TIMEOUT,
            endpoint
                .connect(server.addr, "localhost")
                .expect("start connecting"),
        )
        .await
        .expect("handshake did not time out")
        .expect("handshake");

        Self::from_quic(endpoint, connection, false).await
    }

    async fn connect_with_datagrams(server: &TestServer, datagrams: bool) -> Self {
        let (endpoint, connection) = connect_quic(server).await;
        Self::from_quic(endpoint, connection, datagrams).await
    }

    /// Moves the client onto a fresh local socket while the connection lives
    /// on — the address change a phone produces when it hops networks. The
    /// server must treat it as a QUIC migration (RFC 9000 §9), not a new peer.
    pub fn rebind(&self) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a fresh client socket");
        self._endpoint
            .rebind(socket)
            .expect("rebind the client endpoint");
    }

    async fn from_quic(
        endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        datagrams: bool,
    ) -> Self {
        let mut builder = h3::client::builder();
        builder
            .enable_extended_connect(true)
            .enable_datagram(datagrams);

        let (mut driver, send) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .expect("http/3 handshake");

        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        Self {
            send,
            quic: connection,
            _endpoint: endpoint,
            driver,
        }
    }
}

impl Drop for H3Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// Builds a classic CONNECT request: authority-form URI, no `:protocol`.
pub fn connect_request(authority: &str) -> Request<()> {
    let uri = Uri::builder()
        .authority(authority)
        .build()
        .expect("authority-form URI");

    Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .body(())
        .expect("CONNECT request")
}

/// Builds a CONNECT-UDP request for `target` using the RFC 9298 §2 template.
///
/// `target_host` is percent-encoded per RFC 9298 §3.1, so an IPv6 literal
/// arrives with escaped colons and no brackets.
pub fn connect_udp_request(proxy: SocketAddr, host: &str, port: u16) -> Request<()> {
    let encoded_host: String = host
        .chars()
        .map(|c| match c {
            ':' => "%3A".to_owned(),
            '[' => "%5B".to_owned(),
            ']' => "%5D".to_owned(),
            other => other.to_string(),
        })
        .collect();

    let uri: Uri = format!("https://{proxy}/.well-known/masque/udp/{encoded_host}/{port}/")
        .parse()
        .expect("connect-udp uri");

    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .body(())
        .expect("connect-udp request");
    request
        .extensions_mut()
        .insert(h3::ext::Protocol::CONNECT_UDP);
    request
}

/// A UDP target on an ephemeral loopback port that answers with `reply`.
///
/// `reply` is handed each packet as it arrives and decides what goes back:
/// `Some(bytes)` is sent to the sender, `None` leaves the packet unanswered. A
/// send that fails is dropped, since the loopback losing a reply is not what any
/// test built on this is about.
pub async fn spawn_udp_target(
    reply: impl FnMut(&[u8]) -> Option<Vec<u8>> + Send + 'static,
) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp target");
    let addr = socket.local_addr().expect("udp target address");
    spawn_udp_target_on(socket, reply);
    addr
}

/// [`spawn_udp_target`] on a socket that is already bound.
///
/// The variant a caller needs when the address is the point: `it_family` binds
/// the same port on both loopback families, which no `bind` inside a helper can
/// arrange.
pub fn spawn_udp_target_on(
    socket: UdpSocket,
    mut reply: impl FnMut(&[u8]) -> Option<Vec<u8>> + Send + 'static,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((length, from)) => {
                    if let Some(answer) = reply(&buf[..length]) {
                        let _ = socket.send_to(&answer, from).await;
                    }
                }
                Err(_) => return,
            }
        }
    });
}

/// A UDP target that echoes each packet back to its sender.
pub async fn spawn_udp_echo_target() -> SocketAddr {
    spawn_udp_target(|packet| Some(packet.to_vec())).await
}

/// A UDP target that echoes each packet back with `tag` prepended.
///
/// The tag makes it possible to tell which target answered, which is how
/// cross-talk between concurrent sessions is detected.
pub async fn spawn_tagged_udp_target(tag: u8) -> SocketAddr {
    spawn_udp_target(move |packet| {
        let mut reply = Vec::with_capacity(packet.len() + 1);
        reply.push(tag);
        reply.extend_from_slice(packet);
        Some(reply)
    })
    .await
}

/// A UDP target that counts the packets it receives and never answers.
///
/// This is the shape of an amplification victim: the proxy keeps forwarding, the
/// target never consents to the conversation. The counter is what the outbound
/// budget is measured against.
pub async fn spawn_silent_udp_target() -> (SocketAddr, Arc<AtomicU64>) {
    let received = Arc::new(AtomicU64::new(0));
    let counter = received.clone();

    let addr = spawn_udp_target(move |_| {
        counter.fetch_add(1, Ordering::Relaxed);
        None
    })
    .await;

    (addr, received)
}

/// A UDP target that always answers with `size` bytes, whatever it receives.
///
/// Used to produce a packet too large for a QUIC datagram.
pub async fn spawn_large_reply_udp_target(size: usize) -> SocketAddr {
    let reply = vec![0x5au8; size];
    spawn_udp_target(move |_| Some(reply.clone())).await
}

/// A UDP target that answers the first packet with `count` replies of `size`.
///
/// Enough of them to fill a client's stream flow-control window, so a proxy
/// relaying them over DATAGRAM capsules ends up parked in its write to the
/// client. Sent as fast as the socket takes them, with an occasional yield so
/// the runtime is not starved; a send that fails is left dropped, since UDP loss
/// is not what any test built on this is about.
pub async fn spawn_flooding_udp_target(count: usize, size: usize) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp target");
    let addr = socket.local_addr().expect("udp target address");

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let reply = vec![0x5au8; size];
        let Ok((_, from)) = socket.recv_from(&mut buf).await else {
            return;
        };
        for sent in 0..count {
            let _ = socket.send_to(&reply, from).await;
            if sent % 32 == 31 {
                tokio::task::yield_now().await;
            }
        }
    });

    addr
}

/// Reads from a client stream until `enough` accepts what has arrived, or until
/// the server finishes its sending side.
///
/// Returns the bytes read and whether the stream ended before `enough` did.
async fn read_while(
    stream: &mut ClientStream,
    mut enough: impl FnMut(usize) -> bool,
) -> (Vec<u8>, bool) {
    use bytes::Buf;

    let mut out = Vec::new();
    while !enough(out.len()) {
        let chunk = tokio::time::timeout(TIMEOUT, stream.recv_data())
            .await
            .expect("read did not time out")
            .expect("read succeeded");

        match chunk {
            Some(mut buf) => out.extend_from_slice(buf.copy_to_bytes(buf.remaining()).as_ref()),
            None => return (out, true),
        }
    }

    (out, false)
}

/// Reads from a client stream until at least `n` bytes have arrived.
pub async fn read_at_least(stream: &mut ClientStream, n: usize) -> Vec<u8> {
    let (out, ended) = read_while(stream, |read| read >= n).await;
    assert!(!ended, "stream ended after {} of {n} bytes", out.len());
    out
}

/// Reads from a client stream until the server finishes its sending side.
pub async fn read_to_end(stream: &mut ClientStream) -> Vec<u8> {
    read_while(stream, |_| false).await.0
}

/// A TCP target that echoes every chunk straight back.
pub async fn spawn_echo_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo address");

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });

    addr
}

/// A TCP target that reads until EOF and only *then* replies.
///
/// It can only answer if the client's stream FIN was translated into a TCP FIN
/// on the write side alone — which is exactly the half-close behaviour under
/// test. It appends `suffix` so the reply is distinguishable from an echo.
pub async fn spawn_drain_then_reply_target(suffix: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target address");

    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut socket: TcpStream = socket;
                let mut received = Vec::new();
                if socket.read_to_end(&mut received).await.is_err() {
                    return;
                }
                received.extend_from_slice(suffix.as_bytes());
                let _ = socket.write_all(&received).await;
                // Dropping the socket signals EOF to the proxy.
            });
        }
    });

    addr
}

/// A TCP target that sends a TCP RST once it has received some data.
///
/// `SO_LINGER` at zero turns the close into a reset instead of a FIN, which is
/// what drives the proxy's `H3_CONNECT_ERROR` path. Waiting for data first makes
/// the ordering deterministic: the client only writes after it has seen the 200,
/// so the reset cannot overtake the response.
pub async fn spawn_reset_after_read_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target address");

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                if socket.read(&mut buf).await.is_err() {
                    return;
                }
                // Deprecated because SO_LINGER can block the thread on drop
                // while the send buffer drains. Nothing is ever written to this
                // socket, so the buffer is empty and the close cannot block.
                #[allow(deprecated)]
                let _ = socket.set_linger(Some(Duration::ZERO));
                drop(socket);
            });
        }
    });

    addr
}

/// A TCP target that floods `flood` bytes, never reads, and then sends a RST.
///
/// The sibling of [`spawn_reset_after_read_target`] for the other order of
/// events: the reset has to be noticed by the proxy's *write* pump rather than
/// its read pump, and the two used to disagree about what the client is told.
///
/// Both halves of the proxy have to be pinned for that to be deterministic,
/// because an RST makes the socket fail in both directions at once:
///
/// * the flood — larger than the client's stream flow-control window, and the
///   client under test does not read the tunnel while it lasts — parks the read
///   pump inside `send_data`, where it cannot see the socket fail at all;
/// * never reading parks the write pump inside `write_all`, once the client's
///   upload has filled every buffer in between.
///
/// The flood is bounded by time as well as size because the target's own writes
/// block as soon as that pipeline is full, and it still has to reach the reset.
pub async fn spawn_flood_then_reset_target(flood: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target address");

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let payload = vec![0x5au8; 64 * 1024];
                let _ = tokio::time::timeout(Duration::from_millis(500), async {
                    let mut written = 0usize;
                    while written < flood {
                        if socket.write_all(&payload).await.is_err() {
                            return;
                        }
                        written += payload.len();
                    }
                    // Written out, and still not reading: let the proxy's write
                    // pump block until the timeout above ends this.
                    std::future::pending::<()>().await;
                })
                .await;

                // Deprecated because a non-zero linger can block the thread on
                // drop; at zero the close is immediate by definition, which is
                // what turns it into a reset.
                #[allow(deprecated)]
                let _ = socket.set_linger(Some(Duration::ZERO));
                drop(socket);
            });
        }
    });

    addr
}

/// How a target connection ended, as seen by the target.
///
/// `Eof` is a clean FIN; `Failed(kind)` is the error a read failed with, which is
/// `ConnectionReset` when the peer aborted the connection with an RST. Telling
/// the two apart from outside the proxy is the only way to observe RFC 9114
/// §4.4's "SHOULD send a TCP segment with the RST bit set".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEnd {
    Eof,
    Failed(std::io::ErrorKind),
}

/// A TCP target that reports **how** its connection ended.
///
/// Used to prove the proxy really closes the target socket instead of leaking it
/// — nothing arrives on the receiver if the connection is never torn down — and,
/// beyond that, to tell a clean end of stream from an abortive one rather than
/// collapsing both into "closed".
pub async fn spawn_end_reporting_target() -> (SocketAddr, tokio::sync::mpsc::Receiver<ConnectionEnd>)
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target address");
    let (tx, rx) = tokio::sync::mpsc::channel(1);

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let end = loop {
                    match socket.read(&mut buf).await {
                        Ok(0) => break ConnectionEnd::Eof,
                        Ok(_) => {}
                        Err(error) => break ConnectionEnd::Failed(error.kind()),
                    }
                };
                let _ = tx.send(end).await;
            });
        }
    });

    (addr, rx)
}

/// A UDP address with nothing bound to it.
///
/// Sending here draws an ICMP port-unreachable, which a connected socket reports
/// as `ECONNREFUSED` — the OS-level "socket is unusable" that RFC 9298 §3.1
/// requires the request stream to be closed for.
pub async fn closed_udp_address() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let addr = socket.local_addr().expect("address");
    drop(socket);
    addr
}

/// An address with nothing listening on it.
pub async fn closed_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    drop(listener);
    addr
}

/// A writer that accumulates everything logged into a shared buffer.
///
/// Installed as the subscriber's `MakeWriter` by the test binaries that assert on
/// log output. Each of those is a binary of its own because
/// `tracing_subscriber::fmt().init()` may run once per process.
#[derive(Clone, Default)]
pub struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    /// Everything logged so far.
    pub fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("buffer lock")).into_owned()
    }

    /// How much has been logged so far, as an offset for [`Self::since`].
    ///
    /// Lines are written whole, so this is always a line boundary. Taking one
    /// before each scenario is what stops a scenario from being satisfied by an
    /// earlier scenario's line — two of them may close for the same reason.
    pub fn mark(&self) -> usize {
        self.0.lock().expect("buffer lock").len()
    }

    /// Everything logged after `mark`.
    pub fn since(&self, mark: usize) -> String {
        let buffer = self.0.lock().expect("buffer lock");
        String::from_utf8_lossy(&buffer[mark.min(buffer.len())..]).into_owned()
    }

    /// The lines logged after `mark` that contain every one of `needles`.
    pub fn lines_since(&self, mark: usize, needles: &[&str]) -> Vec<String> {
        self.since(mark)
            .lines()
            .filter(|line| needles.iter().all(|needle| line.contains(needle)))
            .map(str::to_owned)
            .collect()
    }

    /// Waits for a line logged after `mark` containing every one of `needles`.
    ///
    /// Polled rather than slept through: the server logs from its own task, so
    /// the line lands some unpredictable moment after the client sees a result.
    pub async fn wait_for_line(&self, mark: usize, needles: &[&str]) -> String {
        let deadline = Instant::now() + TIMEOUT;

        loop {
            if let Some(line) = self.lines_since(mark, needles).into_iter().next() {
                return line;
            }

            assert!(
                Instant::now() < deadline,
                "no line containing {needles:?} within {TIMEOUT:?}; log was:\n{}",
                self.since(mark)
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

impl std::io::Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
    type Writer = SharedBuffer;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
