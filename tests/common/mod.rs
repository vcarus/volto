//! Shared test harness: a self-signed Volto instance, HTTP/3 clients and
//! cooperating TCP targets.
//!
//! The HTTP/3 client, [`h3client`], is built on `volto::h3`; its module
//! documentation says what that costs.
//!
//! Helpers that assert are synchronous `#[track_caller]` functions returning a
//! future, so a failure names the test rather than the helper (D66). A public
//! `*_at` variant takes the caller already captured, for a test file's own
//! asserting helper.

#![allow(dead_code)]
// Each integration test binary uses a subset of this.

// The package-wide default is `deny` (`Cargo.toml`); this file argues for its
// allow: the scaffolding counts numbers these binaries chose themselves.
#![allow(clippy::as_conversions)]

pub mod h3client;
pub mod huffman;
pub mod rawstream;
// Also loaded by `scripts.rs`, and `it_cli` and `it_reload` load both.
#[allow(clippy::duplicate_mod)]
#[path = "server_table.rs"]
mod server_table;

pub use h3client::{CONNECT_UDP, ClientStream, H3Client, Response};

use std::net::SocketAddr;
use std::panic::Location;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::{EchConfig, EchGreaseConfig, EchMode};
use rustls::crypto::SupportedKxGroup;
use rustls::crypto::aws_lc_rs::hpke;
use rustls::pki_types::{CertificateDer, EchConfigListBytes};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use volto::config::Config;
use volto::datagram;
use volto::h3api::{FieldValue, Method, Request, Status};
use volto::quic::ReloadHandle;
use volto::quic::{Server, Stopped};
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

/// The SNI gate on, naming only `localhost`, with loopback targets reachable.
pub const GATE_LOCALHOST: &str =
    "[security]\nallow_private_networks = true\nexpected_sni = [\"localhost\"]\n";

/// One second of idle timeout, with keep-alives off so nothing refreshes it.
///
/// Keep-alives have to be disabled explicitly: the default 20s interval would both
/// fail validation against a 1s timeout and, if it did not, keep the connection
/// alive forever. A client that connects and then says nothing is timed out by the
/// server after about a second.
pub const IMPATIENT: &str = "[limits]\nmax_idle_timeout = 1\nkeep_alive_interval = 0\n";

/// A 2s idle timeout, which is also how long any one response may take.
///
/// Long enough that a deadline lapsing is a deliberate act rather than a slow
/// machine, and short enough for a test to wait out — twice, where it has to
/// be: the connection-level bound of D76 is two of these, so a test can tell
/// one deadline from the other.
pub const DELIBERATE: &str = "[limits]\nmax_idle_timeout = 2\nkeep_alive_interval = 0\n";

/// Generous upper bound for a shutdown that should take about as long as its
/// grace period. Failing this means the grace period is not being enforced.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(20);

/// A path under the system temp directory, named for this process.
///
/// The pid is what keeps two `cargo test` runs at once from writing to the same
/// path; `name` is what tells one caller's scratch from another's in a directory
/// listing after a crash.
///
/// Leaf modules have their own (`scripts::scratch_tree`), since they may not
/// use this module (D66).
pub fn scratch_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("volto-{name}-{}", std::process::id()))
}

/// A directory that deletes itself when dropped.
///
/// However the test ends, including a panic: the run somebody is about to go and
/// look at is exactly the run whose scratch would otherwise be left behind, and
/// what one of these holds may be TLS secrets.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = scratch_path(&format!(
            "test-{tag}-{}",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
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
    /// The `[log]` additions the server started with, which a rewritten config
    /// keeps.
    log_extra: String,
    /// Fires the graceful shutdown, exactly as the SIGTERM handler does.
    trigger: Trigger,
    /// Replaces the running configuration, exactly as the SIGHUP handler does.
    reload: ReloadHandle,
    /// How many connections the endpoint holds; see
    /// [`TestServer::open_connections`].
    open_connections: Box<dyn Fn() -> usize + Send + Sync>,
    /// The bound server, until its accept loop is started.
    ///
    /// `Some` only between [`TestServer::bind_with`] and [`TestServer::serve`].
    /// Every other constructor starts the loop before it returns, so for every
    /// other test this is `None` from the first line.
    unserved: Option<Server>,
    /// `None` until the accept loop is started, and again once it has been
    /// awaited by `wait_until_stopped`.
    task: Option<JoinHandle<Stopped>>,
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
        Self::start_named(extra, log_extra, &[]).await
    }

    /// [`TestServer::start_with`] with a certificate that also covers `names`.
    ///
    /// The escape hatch for the SNI gate (`it_sni_gate`), which is the one
    /// subject that needs *two* names a client can complete a handshake under:
    /// with a single-name certificate, "the gate let this through" and "the
    /// certificate did not match" are the same outcome from the client's side.
    pub async fn start_with_certificate_names(extra: &str, names: &[&str]) -> Self {
        Self::start_named(extra, "", names).await
    }

    /// [`TestServer::start_with`], with the server bound and served on `runtime`.
    ///
    /// The endpoint, its driver task and the accept loop are all created while
    /// `runtime` is the current runtime, and quinn's tokio runtime spawns with a
    /// bare `tokio::spawn`, so the endpoint driver, every connection driver and
    /// every task the server spawns run on `runtime`'s threads. The caller's
    /// runtime keeps only the client and the targets. `it_bench` uses this to
    /// count the proxy's CPU apart from theirs.
    pub fn start_on(runtime: &tokio::runtime::Handle, extra: &str) -> Self {
        let _entered = runtime.enter();
        let mut server = Self::bind_named(extra, "", &[]);
        server.serve();
        server
    }

    /// Binds the server and leaves its accept loop unstarted.
    ///
    /// The endpoint is live from here: quinn spawns its driver task when the
    /// endpoint is built, so a client's first Initial is received and queued as
    /// an `Incoming` with nothing to accept it. That is the only way a test can
    /// put a reload between a handshake's arrival and its acceptance, which is
    /// the window `Incoming::accept_with` exists to cover. Call [`Self::serve`]
    /// to start the loop.
    pub async fn bind_with(extra: &str) -> Self {
        Self::bind_named(extra, "", &[])
    }

    /// Starts the accept loop of a server bound by [`Self::bind_with`].
    pub fn serve(&mut self) {
        let server = self
            .unserved
            .take()
            .expect("the accept loop is only started once");
        self.task = Some(tokio::spawn(async move { server.run().await }));
    }

    /// The body behind all of the constructors above.
    async fn start_named(extra: &str, log_extra: &str, extra_names: &[&str]) -> Self {
        let mut server = Self::bind_named(extra, log_extra, extra_names);
        server.serve();
        server
    }

    /// Everything [`Self::start_named`] does except starting the accept loop.
    fn bind_named(extra: &str, log_extra: &str, extra_names: &[&str]) -> Self {
        let dir = TempDir::new("server");
        let mut subject = vec!["localhost".to_owned()];
        subject.extend(extra_names.iter().map(|name| (*name).to_owned()));
        let issued =
            rcgen::generate_simple_self_signed(subject).expect("generate self-signed certificate");

        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, issued.cert.pem()).expect("write cert");
        std::fs::write(&key, issued.signing_key.serialize_pem()).expect("write key");
        let ca = issued.cert.der().clone();

        // Written to disk and read with `Config::load`, as production does, so
        // `reload` has a file to re-read.
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, config_text(&cert, &key, extra, log_extra))
            .expect("write config");
        // Private, as an installed file is: a file every local user can read
        // draws a warning on every reload. A rewrite below keeps the mode.
        std::fs::set_permissions(
            &config_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .expect("make the config private");

        let config = Config::load(&config_path).expect("the test config must load");

        let server = Server::bind(Arc::new(config)).expect("bind server");
        let addr = server.local_addr().expect("local address");
        // Taken before the server moves into its task.
        let trigger = server.shutdown_trigger();
        let reload = server.reload_handle();
        let open_connections = Box::new(server.open_connections());

        Self {
            addr,
            ca,
            dir,
            config_path,
            cert,
            key,
            log_extra: log_extra.to_owned(),
            trigger,
            reload,
            open_connections,
            unserved: Some(server),
            task: None,
        }
    }

    /// Rewrites the configuration file with a new `extra` section and the
    /// `[log]` additions the server started with.
    ///
    /// Does not apply it: call [`Self::reload`], which is what `SIGHUP` does.
    pub fn rewrite_config(&self, extra: &str) {
        std::fs::write(
            &self.config_path,
            config_text(&self.cert, &self.key, extra, &self.log_extra),
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

    /// How many connections the server's endpoint holds now, those in their
    /// draining period included. Zero once quinn has forgotten every
    /// connection it had.
    pub fn open_connections(&self) -> usize {
        (self.open_connections)()
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
    /// asserted to be an upper bound rather than a suggestion. The loop has to
    /// end as a shutdown: an endpoint lost on the way is a failure (D124).
    pub async fn wait_until_stopped(&mut self, within: Duration) {
        let task = self.task.take().expect("the server is only awaited once");
        let stopped = tokio::time::timeout(within, task)
            .await
            .expect("the server stopped within the timeout")
            .expect("the server task did not panic");
        assert_eq!(stopped, Stopped::Shutdown, "the accept loop's ending");
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
/// See [`TestServer::start_with`] for where `extra` lands. Written unindented: a TOML table header must start its own line.
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

/// ALPN identifiers padded until a ClientHello cannot fit in one Initial packet.
///
/// A first flight larger than an Initial packet is what the SNI gate's
/// socket-level check deliberately lets through, so this is the way to reach
/// the branch behind it. `h3` stays on the list and is what gets negotiated:
/// the server offers only `h3`, so its ALPN callback can choose nothing else.
pub fn bulk_alpn() -> Vec<String> {
    let mut alpn = vec!["h3".to_owned()];
    alpn.extend((0..8).map(|i| format!("{i}{}", "padding-".repeat(31))));
    alpn
}

/// A bare quinn server endpoint on a loopback port, with a self-signed
/// certificate for `localhost` and the `h3` ALPN, and quinn's default
/// endpoint configuration.
///
/// [`TestServer`] is the whole proxy and hands nothing of its connections
/// back. A test that needs the server side of a connection in its own hands,
/// or a server that is quinn's and not volto's, builds it here. TLS 1.3, the
/// `h3` ALPN and a loopback port are what `volto::tls` and `volto::quic`
/// would have produced.
pub fn h3_server_endpoint() -> (quinn::Endpoint, CertificateDer<'static>) {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate a self-signed certificate");
    let certificate = issued.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(issued.signing_key.serialize_der().into());

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .expect("a usable certificate and key");
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).expect("quic tls"),
    ));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().expect("bind address"))
        .expect("bind the server endpoint");

    (endpoint, certificate)
}

/// A rustls TLS configuration with no identity at all, as a source of Initial
/// keys for building packets.
///
/// Initial keys depend on the client's Destination Connection ID alone
/// (RFC 9001 §5.2), never on the server's certificate. So a configuration
/// with no certificate derives the keys the server derives. The resolver is
/// never asked for anything: nothing here starts a TLS session. The packets
/// are built by rustls and opened by the server's own code
/// (`tls::awslc::keys`).
pub fn nameless_crypto() -> Arc<dyn quinn::crypto::ServerConfig> {
    /// A resolver with nothing to present.
    #[derive(Debug)]
    struct NoIdentity;

    impl rustls::server::ResolvesServerCert for NoIdentity {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("the aws-lc-rs crypto provider supports TLS 1.3")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(NoIdentity));

    Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
            .expect("a TLS 1.3 configuration carries an initial cipher suite"),
    )
}

/// How long a probing socket stays bound after its probe has returned.
///
/// A server that answered a probe retransmits its flight to the probe's port
/// for several seconds (the last at about 5 s with the default limits). The
/// operating system may hand that port to a later probe, which would then hear
/// those datagrams, so the port is held twelve times as long. The task holding
/// it belongs to the test's runtime and ends with the test.
const PROBE_PORT_HELD: Duration = Duration::from_secs(60);

/// Keeps `socket` bound for [`PROBE_PORT_HELD`] and reads nothing from it.
fn hold_port(socket: UdpSocket) {
    tokio::spawn(async move {
        tokio::time::sleep(PROBE_PORT_HELD).await;
        drop(socket);
    });
}

/// Sends `bytes` once from a fresh socket and returns the first datagram back,
/// or `None` if nothing arrives within `patience`.
///
/// Returns as soon as one datagram lands, so a server that answers is a fast
/// answer; only a server that does not costs the whole wait. The socket's
/// port stays taken afterwards ([`PROBE_PORT_HELD`]).
pub async fn udp_answer(addr: SocketAddr, bytes: &[u8], patience: Duration) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a probing socket");
    socket.send_to(bytes, addr).await.expect("send the probe");

    let mut answer = vec![0u8; 2048];
    let answered = match tokio::time::timeout(patience, socket.recv(&mut answer)).await {
        Ok(Ok(read)) => {
            answer.truncate(read);
            Some(answer)
        }
        Ok(Err(error)) => panic!("the probing socket failed: {error}"),
        Err(_elapsed) => None,
    };
    hold_port(socket);
    answered
}

/// A 1200-byte long-header packet naming a QUIC version nobody speaks.
///
/// The version is one RFC 9000 §15 sets aside for this: "Versions that follow
/// the pattern 0x?a?a?a?a are reserved for use in forcing version negotiation
/// to be exercised -- that is, any version number where the low four bits of
/// all bytes is 1010 (in binary)." The size is the 1200 bytes below which
/// quinn-proto drops an unsupported version without an answer, and RFC 9000
/// §5.2.2 says of a packet that size: "If a server receives a packet that
/// indicates an unsupported version and if the packet is large enough to
/// initiate a new connection for any supported version, the server SHOULD send
/// a Version Negotiation packet as described in Section 6.1." Everything before
/// the version field is well formed, because quinn reads the connection IDs
/// out before it looks at the version.
pub fn version_probe() -> Vec<u8> {
    let mut packet = vec![0xc0]; // long header, fixed bit, Initial type
    packet.extend_from_slice(&0x1a2a_3a4au32.to_be_bytes());
    packet.push(8); // Destination Connection ID length
    packet.extend_from_slice(&[0xab; 8]);
    packet.push(0); // Source Connection ID length
    packet.resize(1200, 0);
    packet
}

/// Whether `datagram` is a Version Negotiation packet: RFC 9000 §17.2.1 gives
/// it a long header and a Version field of zero.
pub fn is_version_negotiation(datagram: &[u8]) -> bool {
    matches!(datagram.first(), Some(first) if first & 0x80 != 0)
        && matches!(datagram.get(1..5), Some([0, 0, 0, 0]))
}

/// Sends each of `datagrams` once, in order, from a fresh socket and collects
/// every datagram that arrives within `patience`.
///
/// Every datagram rather than the first, because "the server answered" and
/// "the server answered twice" are different facts about how loud a shape is —
/// and because proving silence takes the whole wait. The socket's port stays
/// taken afterwards ([`PROBE_PORT_HELD`]), so that a later probe is not given
/// it and does not hear what a server still sends to this one.
pub async fn udp_answers(
    addr: SocketAddr,
    datagrams: &[Vec<u8>],
    patience: Duration,
) -> Vec<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a probing socket");
    let heard = udp_answers_on(&socket, addr, datagrams, patience).await;
    hold_port(socket);
    heard
}

/// [`udp_answers`] from `socket`, so that a test can send more than once from
/// one address, or from an address the server already knows.
pub async fn udp_answers_on(
    socket: &UdpSocket,
    addr: SocketAddr,
    datagrams: &[Vec<u8>],
    patience: Duration,
) -> Vec<Vec<u8>> {
    for datagram in datagrams {
        socket
            .send_to(datagram, addr)
            .await
            .expect("send the probe");
    }

    let deadline = Instant::now() + patience;
    let mut heard = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        let mut buffer = vec![0u8; usize::from(u16::MAX)];
        match tokio::time::timeout(left, socket.recv(&mut buffer)).await {
            Ok(Ok(read)) => {
                buffer.truncate(read);
                heard.push(buffer);
            }
            Ok(Err(error)) => panic!("the probing socket failed: {error}"),
            Err(_elapsed) => break,
        }
    }
    heard
}

/// Which way a datagram is crossing a [`udp_relay`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leg {
    /// From the client, on its way to the server.
    FromClient,
    /// From the server, on its way to the client.
    FromServer,
}

/// What a [`udp_relay`]'s hook does with one datagram.
pub enum Relayed {
    /// Carries it on.
    Forward,
    /// Drops it.
    Drop,
    /// Carries it on, then sends these bytes to the server from the same
    /// socket, right behind it.
    ForwardThenToServer(Vec<u8>),
}

/// A running [`udp_relay`].
pub struct Relay {
    /// Where the client sends.
    pub addr: SocketAddr,
    /// The relay's one socket: the server sees the client at its address, so a
    /// test can send from there once `task` has stopped.
    pub socket: Arc<UdpSocket>,
    /// The loop carrying datagrams.
    pub task: JoinHandle<()>,
}

/// A UDP relay between one client and `server`, on one loopback socket, with
/// `hook` deciding the fate of every datagram.
///
/// The direction is decided by the source address: a datagram from `server` is
/// on its way to the client, and any other is the client's. The client is the
/// source of the latest datagram that was not the server's, so nothing from the
/// server goes anywhere before the client has sent once.
pub async fn udp_relay(
    server: SocketAddr,
    mut hook: impl FnMut(Leg, &[u8]) -> Relayed + Send + 'static,
) -> Relay {
    let socket = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind the relay socket"),
    );
    let addr = socket.local_addr().expect("the relay's address");
    let task = tokio::spawn({
        let socket = socket.clone();
        async move {
            let mut buffer = vec![0u8; usize::from(u16::MAX)];
            let mut client: Option<SocketAddr> = None;
            while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
                let datagram = &buffer[..read];
                let (leg, to) = if from == server {
                    (Leg::FromServer, client)
                } else {
                    client = Some(from);
                    (Leg::FromClient, Some(server))
                };
                let then = match hook(leg, datagram) {
                    Relayed::Drop => continue,
                    Relayed::Forward => None,
                    Relayed::ForwardThenToServer(bytes) => Some(bytes),
                };
                if let Some(to) = to {
                    let _ = socket.send_to(datagram, to).await;
                }
                if let Some(bytes) = then {
                    let _ = socket.send_to(&bytes, server).await;
                }
            }
        }
    });
    Relay { addr, socket, task }
}

/// A QUIC client endpoint that trusts `ca` and offers `alpn`.
pub fn client_endpoint(ca: &CertificateDer<'static>, alpn: &[&str]) -> quinn::Endpoint {
    client_endpoint_with(ca, alpn, None)
}

/// [`client_endpoint`] built on transport parameters the caller chose.
///
/// The escape hatch for tests whose subject is what the *peer's* transport
/// parameters do to the server — a client that grants no unidirectional
/// streams, say, which is a legal QUIC peer and an impossible HTTP/3 one.
pub fn client_endpoint_with_transport(
    ca: &CertificateDer<'static>,
    alpn: &[&str],
    transport: quinn::TransportConfig,
) -> quinn::Endpoint {
    client_endpoint_with(ca, alpn, Some(transport))
}

/// Transport parameters for a peer that leaves no room for an answer.
///
/// 24 bytes of connection-level allowance. The server's control stream takes
/// 19 of them (its type byte and an 18-byte SETTINGS frame), and its two QPACK
/// streams take one type byte each, so 3 are left, less than any response.
/// Nothing that uses this reads the server's unidirectional streams, so those
/// 21 bytes are never credited back. One more SETTINGS pair would leave no
/// room for the QPACK stream types.
///
/// The keep-alive is what makes such a test about the application's deadline:
/// with it, the transport's own idle timeout can never be the thing that ends
/// anything.
pub fn windowless_transport() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.receive_window(24u32.into());
    transport.stream_receive_window(24u32.into());
    transport.keep_alive_interval(Some(Duration::from_millis(100)));
    transport
}

fn client_endpoint_with(
    ca: &CertificateDer<'static>,
    alpn: &[&str],
    transport: Option<quinn::TransportConfig>,
) -> quinn::Endpoint {
    endpoint_from(
        rustls_client(&Offer::Plain, None, roots_of(ca), alpn),
        transport,
    )
}

/// How a test client offers ECH.
#[derive(Clone, Debug)]
pub enum Offer {
    /// No ECH extension.
    Plain,
    /// ECH under this ECHConfigList.
    Ech(Vec<u8>),
    /// A GREASE ECH extension, which no key opens.
    Grease,
}

/// The rustls `EchMode` for `offer`, or none.
fn ech_mode(offer: &Offer) -> Option<EchMode> {
    match offer {
        Offer::Plain => None,
        Offer::Ech(list) => Some(EchMode::from(
            EchConfig::new(
                EchConfigListBytes::from(list.clone()),
                hpke::ALL_SUPPORTED_SUITES,
            )
            .expect("rustls reads the list"),
        )),
        Offer::Grease => {
            let suite = hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
            let (placeholder, _) =
                rustls::crypto::hpke::Hpke::generate_key_pair(suite).expect("a GREASE key");
            Some(EchMode::from(EchGreaseConfig::new(suite, placeholder)))
        }
    }
}

/// A store of trust roots holding `ca` alone.
pub fn roots_of(ca: &CertificateDer<'static>) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).expect("trust the test CA");
    roots
}

/// A rustls client configuration on aws-lc-rs: TLS 1.3, offering `offer`,
/// with the key exchange `groups` in that order (the provider's own list when
/// `None`), trusting `roots` and offering `alpn`.
///
/// rustls, not the server's TLS (AWS-LC's libssl), so the client end of every
/// handshake is an independent implementation.
pub fn rustls_client(
    offer: &Offer,
    groups: Option<&[&'static dyn SupportedKxGroup]>,
    roots: rustls::RootCertStore,
    alpn: &[&str],
) -> rustls::ClientConfig {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if let Some(groups) = groups {
        provider.kx_groups = groups.to_vec();
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider));
    let builder = match ech_mode(offer) {
        Some(mode) => builder.with_ech(mode).expect("ECH with TLS 1.3"),
        None => builder
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3"),
    };
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    config
}

/// A quinn client endpoint on loopback using `crypto`, with `transport` when
/// given and quinn's defaults otherwise.
pub fn endpoint_from(
    crypto: rustls::ClientConfig,
    transport: Option<quinn::TransportConfig>,
) -> quinn::Endpoint {
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
    let endpoint = client_endpoint(&server.ca, &["h3"]);
    let connection = finish_connect(&endpoint, server.addr)
        .await
        .expect("handshake");

    (endpoint, connection)
}

/// Drives one QUIC handshake to `addr` to whatever end it reaches.
///
/// The handshake's *outcome* is returned rather than asserted, because several
/// tests are about one that must fail — a connection past `max_connections`, a
/// client left trusting a certificate that has been replaced. Only taking longer
/// than [`TIMEOUT`] is a failure of the test rather than a result, and that is
/// what panics.
#[track_caller]
pub fn finish_connect(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
) -> impl Future<Output = Result<quinn::Connection, quinn::ConnectionError>> + '_ {
    finish_connect_as(endpoint, addr, "localhost")
}

/// [`finish_connect`] asking for `server_name` instead of `localhost`.
///
/// The name goes into the ClientHello's `server_name` extension and is also what
/// the client verifies the certificate against, so a test using this is choosing
/// both at once — which is what makes it the way to drive the SNI gate.
#[track_caller]
pub fn finish_connect_as<'a>(
    endpoint: &'a quinn::Endpoint,
    addr: SocketAddr,
    server_name: &'a str,
) -> impl Future<Output = Result<quinn::Connection, quinn::ConnectionError>> + 'a {
    let caller = Location::caller();
    async move {
        let connecting = endpoint
            .connect(addr, server_name)
            .expect("start connecting");

        tokio::time::timeout(TIMEOUT, connecting)
            .await
            .unwrap_or_else(|_| {
                panic!("the handshake to {addr} started at {caller} took longer than {TIMEOUT:?}")
            })
    }
}

/// Opens a QUIC connection that keeps itself alive and never says anything.
///
/// The keep-alive is what makes a test using this about an *application* bound
/// rather than about the transport's: with it, every ACK restarts the server's
/// idle timer, so the transport can never be the thing that closes the
/// connection and only an application bound can be.
#[track_caller]
pub fn silent_peer(
    server: &TestServer,
) -> impl Future<Output = (quinn::Endpoint, quinn::Connection)> + use<> {
    let caller = Location::caller();
    let ca = server.ca.clone();
    let addr = server.addr;

    async move {
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_millis(100)));

        let endpoint = client_endpoint_with_transport(&ca, &["h3"], transport);
        let connection = finish_connect(&endpoint, addr)
            .await
            .unwrap_or_else(|error| panic!("the handshake at {caller} failed: {error}"));

        (endpoint, connection)
    }
}

/// Asserts that `error` is the peer resetting the stream, with `code`.
#[track_caller]
pub fn assert_peer_reset(error: &volto::h3api::StreamError, code: u64) {
    assert_eq!(
        volto::h3api::peer_reset_code(error),
        Some(code),
        "expected the peer to reset the stream with {code:#x}, got {error:?}"
    );
}

/// Builds a classic CONNECT request: `:authority` and no more (RFC 9114 §4.4).
pub fn connect_request(authority: &str) -> Request {
    let mut request = Request::new(Method::Connect);
    request.authority = Some(authority.into());
    request
}

/// A hostname no resolver anywhere can answer for.
///
/// Five 60-octet labels and `.invalid`: 5*60 + 4 dots + 8 = 312 octets, past
/// the 255 DNS allows, so the stub resolver refuses it locally and no
/// NXDOMAIN-hijacking resolver can answer it (D16). `volto::net`'s unit test
/// uses the same name.
pub fn unresolvable_host() -> String {
    let label = "a".repeat(60);
    vec![label; 5].join(".") + ".invalid"
}

/// A field value from text a test authored.
#[track_caller]
pub fn field_value(value: &str) -> FieldValue {
    FieldValue::parse(value.as_bytes()).expect("a valid field value")
}

/// Adds credentials to a request, in the field decision D3 treats as primary.
///
/// Kept separate from `authorized_connect` for the requests that are not a
/// classic CONNECT -- a CONNECT-UDP one, or a credential no `basic_credentials`
/// call could have produced.
#[track_caller]
pub fn authorize(request: &mut Request, credentials: &str) {
    request
        .fields
        .append("proxy-authorization", field_value(credentials));
}

/// A classic CONNECT carrying HTTP Basic credentials.
#[track_caller]
pub fn authorized_connect(authority: &str, username: &str, password: &str) -> Request {
    let mut request = connect_request(authority);
    authorize(&mut request, &basic_credentials(username, password));
    request
}

/// Builds a CONNECT-UDP request for `target` using the RFC 9298 §2 template.
///
/// `target_host` is percent-encoded per RFC 9298 §3, so an IPv6 literal
/// arrives with escaped colons and no brackets.
pub fn connect_udp_request(proxy: SocketAddr, host: &str, port: u16) -> Request {
    let encoded_host: String = host
        .chars()
        .map(|c| match c {
            ':' => "%3A".to_owned(),
            '[' => "%5B".to_owned(),
            ']' => "%5D".to_owned(),
            other => other.to_string(),
        })
        .collect();

    let mut request = Request::new(Method::Connect);
    request.scheme = Some("https".into());
    request.authority = Some(proxy.to_string().into());
    request.path = Some(format!("/.well-known/masque/udp/{encoded_host}/{port}/").into());
    request.protocol = Some(CONNECT_UDP.into());
    request
}

/// Sends `request` and waits for the response headers, asserting nothing about
/// the answer.
///
/// For the tests whose subject *is* the answer: they assert on the status, or on
/// a `Proxy-Status` field, themselves. What is asserted here is only that an
/// answer arrived within [`TIMEOUT`], and a failure names the caller (D66).
#[track_caller]
pub fn respond_to(client: &mut H3Client, request: Request) -> impl Future<Output = Response> + '_ {
    let caller = Location::caller();
    async move { exchange(client, request, caller).await.0 }
}

/// [`respond_to`], keeping the request stream for cases that then use it.
#[track_caller]
pub fn send_and_respond(
    client: &mut H3Client,
    request: Request,
) -> impl Future<Output = (Response, ClientStream)> + '_ {
    exchange(client, request, Location::caller())
}

/// The body behind every helper that sends a request, with `caller` already
/// captured.
///
/// Both halves are bounded: opening the stream waits for the server's stream
/// credit, which a server can withhold, and the response waits for the server.
async fn exchange(
    client: &mut H3Client,
    request: Request,
    caller: &'static Location<'static>,
) -> (Response, ClientStream) {
    let mut stream = tokio::time::timeout(TIMEOUT, client.send.send_request(request))
        .await
        .unwrap_or_else(|_| panic!("the request sent at {caller} was not sent within {TIMEOUT:?}"))
        .unwrap_or_else(|error| panic!("the request sent at {caller} failed: {error:?}"));

    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .unwrap_or_else(|_| {
            panic!("no response to the request sent at {caller} within {TIMEOUT:?}")
        })
        .unwrap_or_else(|error| {
            panic!("the response to the request sent at {caller} failed: {error:?}")
        });

    (response, stream)
}

/// The `Proxy-Status` (RFC 9209) a response carries, if it carries one.
///
/// The one spelling of the field name, and of the "a header value is text"
/// step every reader of it repeats. A value that is not ASCII text panics
/// rather than reading as absent: this server writes the field itself, so a
/// value that cannot be read is a bug in it and not a refusal without a
/// reason.
#[track_caller]
pub fn proxy_status(response: &Response) -> Option<&str> {
    response
        .fields
        .get("proxy-status")
        .map(|value| value.to_str().expect("Proxy-Status is ASCII"))
}

/// Opens a CONNECT tunnel to `authority` and asserts it was accepted.
#[track_caller]
pub fn open_tcp_tunnel<'a>(
    client: &'a mut H3Client,
    authority: &'a str,
) -> impl Future<Output = ClientStream> + 'a {
    open_tcp_tunnel_at(client, authority, Location::caller())
}

/// The body behind [`open_tcp_tunnel`], with `caller` already captured.
pub async fn open_tcp_tunnel_at(
    client: &mut H3Client,
    authority: &str,
    caller: &'static Location<'static>,
) -> ClientStream {
    let (response, stream) = exchange(client, connect_request(authority), caller).await;
    assert_eq!(
        response.status,
        Status::OK,
        "the tunnel to {authority} opened at {caller} was refused: proxy-status={:?}",
        proxy_status(&response)
    );
    stream
}

/// [`open_tcp_tunnel`] against a server that requires credentials.
///
/// The same judgement, on a request built by [`authorized_connect`]: a server
/// with `[auth]` users answers an anonymous CONNECT with a 407, so a test that
/// wants a tunnel there has to present the pair it configured.
#[track_caller]
pub fn open_tcp_tunnel_as<'a>(
    client: &'a mut H3Client,
    authority: &'a str,
    username: &'a str,
    password: &'a str,
) -> impl Future<Output = ClientStream> + 'a {
    open_tcp_tunnel_as_at(client, authority, username, password, Location::caller())
}

/// The body behind [`open_tcp_tunnel_as`], with `caller` already captured.
pub async fn open_tcp_tunnel_as_at(
    client: &mut H3Client,
    authority: &str,
    username: &str,
    password: &str,
    caller: &'static Location<'static>,
) -> ClientStream {
    let request = authorized_connect(authority, username, password);
    let (response, stream) = exchange(client, request, caller).await;
    assert_eq!(
        response.status,
        Status::OK,
        "the tunnel to {authority} opened at {caller} as {username} was refused: \
         proxy-status={:?}",
        proxy_status(&response)
    );
    stream
}

/// Opens a CONNECT-UDP session to `target` and returns its Quarter Stream ID.
#[track_caller]
pub fn open_udp_session<'a>(
    client: &'a mut H3Client,
    server: &'a TestServer,
    target: SocketAddr,
) -> impl Future<Output = (u64, ClientStream)> + 'a {
    let caller = Location::caller();
    udp_session(
        client,
        server,
        target.ip().to_string(),
        target.port(),
        caller,
    )
}

/// [`open_udp_session`] for a target named rather than addressed.
///
/// The RFC 9298 template carries a host, so a name is as legitimate a target as
/// an address, and the only way to let the proxy choose the family or to reach
/// a name the resolver refuses.
#[track_caller]
pub fn open_udp_session_to<'a>(
    client: &'a mut H3Client,
    server: &'a TestServer,
    host: &str,
    port: u16,
) -> impl Future<Output = (u64, ClientStream)> + 'a + use<'a> {
    let caller = Location::caller();
    udp_session(client, server, host.to_owned(), port, caller)
}

/// The body behind both session helpers, with `caller` already captured.
pub async fn udp_session(
    client: &mut H3Client,
    server: &TestServer,
    host: String,
    port: u16,
    caller: &'static Location<'static>,
) -> (u64, ClientStream) {
    let (response, stream) = exchange(
        client,
        connect_udp_request(server.addr, &host, port),
        caller,
    )
    .await;

    assert_eq!(
        response.status,
        Status::OK,
        "the session to {host}:{port} opened at {caller} was refused: proxy-status={:?}",
        proxy_status(&response)
    );
    // RFC 9297 §3.4: the response should announce the capsule protocol, and §3.2
    // forbids Content-Length, Content-Type and Transfer-Encoding on it. Protocol requirements rather than
    // scaffolding, so they belong to every session this helper opens.
    assert_eq!(
        response
            .fields
            .get("capsule-protocol")
            .and_then(FieldValue::to_str),
        Some("?1"),
        "the 2xx to the session opened at {caller} must carry Capsule-Protocol: ?1"
    );
    assert!(
        !response.fields.contains("content-length"),
        "a CONNECT-UDP response frames no content; session opened at {caller}"
    );
    assert!(
        !response.fields.contains("content-type"),
        "a CONNECT-UDP response frames no content; session opened at {caller}"
    );
    assert!(
        !response.fields.contains("transfer-encoding"),
        "a CONNECT-UDP response frames no content; session opened at {caller}"
    );

    let quarter_stream_id = datagram::quarter_stream_id(stream.id());
    (quarter_stream_id, stream)
}

/// Queues one UDP payload for `quarter_stream_id` as an HTTP/3 datagram.
///
/// The outbound half of a CONNECT-UDP exchange. Queuing is asserted rather than the round trip:
/// what comes back — a reply, nothing, a drop counted somewhere — is what each
/// caller is about, and only failing to hand the datagram to quinn at all is a
/// failure of the test rather than a result.
///
/// Takes the connection rather than an [`H3Client`] because the raw-stream
/// tests have no client to take it from.
#[track_caller]
pub fn send_udp_payload(quic: &quinn::Connection, quarter_stream_id: u64, payload: &[u8]) {
    let caller = Location::caller();
    quic.send_datagram(datagram::encode_udp_payload(quarter_stream_id, payload))
        .unwrap_or_else(|error| panic!("the datagram sent at {caller} was not queued: {error}"));
}

/// Sends one datagram into a CONNECT-UDP session and returns what comes back.
///
/// The round trip every UDP test opens with: a payload out on
/// `quarter_stream_id`, the target's answer back on the same one. That the
/// answer really is on the same one is asserted here rather than left to each
/// caller -- a payload delivered under another session's id is the Quarter
/// Stream ID class of bug this suite exists to catch, and no caller means to
/// allow it.
#[track_caller]
pub fn udp_round_trip<'a>(
    client: &'a H3Client,
    quarter_stream_id: u64,
    payload: &'a [u8],
) -> impl Future<Output = Bytes> + 'a {
    udp_round_trip_at(client, quarter_stream_id, payload, Location::caller())
}

/// The body behind [`udp_round_trip`], with `caller` already captured.
pub async fn udp_round_trip_at(
    client: &H3Client,
    quarter_stream_id: u64,
    payload: &[u8],
    caller: &'static Location<'static>,
) -> Bytes {
    client
        .quic
        .send_datagram(datagram::encode_udp_payload(quarter_stream_id, payload))
        .unwrap_or_else(|error| panic!("the datagram sent at {caller} was not queued: {error}"));

    let answer = read_datagram(&client.quic, caller).await;
    assert_eq!(
        answer.quarter_stream_id, quarter_stream_id,
        "the answer to the datagram sent at {caller} arrived on another session"
    );
    answer.payload
}

/// Reads one HTTP/3 datagram off `quic` and decodes it.
///
/// The context id is checked here because RFC 9298 §5 gives a UDP payload
/// exactly one: a datagram under any other context is not a packet from the
/// target, whatever else it may be. Which session it belongs to is left to the
/// caller, for the tests that interleave several.
#[track_caller]
pub fn recv_datagram(quic: &quinn::Connection) -> impl Future<Output = datagram::Datagram> + '_ {
    read_datagram(quic, Location::caller())
}

/// The body behind both, with `caller` already captured.
pub async fn read_datagram(
    quic: &quinn::Connection,
    caller: &'static Location<'static>,
) -> datagram::Datagram {
    let raw = tokio::time::timeout(TIMEOUT, quic.read_datagram())
        .await
        .unwrap_or_else(|_| panic!("no datagram reached {caller} within {TIMEOUT:?}"))
        .unwrap_or_else(|error| {
            panic!("the connection read at {caller} carries no datagrams: {error}")
        });

    let decoded = datagram::decode(raw).expect("server datagrams must be well formed");
    assert_eq!(
        decoded.context_id,
        datagram::CONTEXT_ID_UDP_PAYLOAD,
        "a UDP payload must use context 0; read at {caller}"
    );
    decoded
}

/// The payload of the next DATAGRAM capsule `decoder` can produce, if it has
/// one.
///
/// The capsule fallback's counterpart to [`recv_datagram`], and it checks the
/// same thing for the same reason: RFC 9298 §4 reserves Context ID 0 for UDP
/// payloads and §5 encodes them under it, so a capsule under any other context
/// is not a packet from the target.
///
/// `None` means the decoder needs more bytes, not that the stream ended, so a
/// caller reads more and asks again. Reading is left to the caller, which reads
/// from a [`ClientStream`] or from a raw `quinn::RecvStream`.
#[track_caller]
pub fn next_udp_payload(decoder: &mut volto::capsule::CapsuleDecoder) -> Option<Bytes> {
    let capsule = decoder.next_capsule().expect("well-formed capsules")?;
    let volto::capsule::Capsule::Datagram {
        context_id,
        payload,
    } = capsule;

    assert_eq!(
        context_id,
        datagram::CONTEXT_ID_UDP_PAYLOAD,
        "a UDP payload must travel under context 0"
    );
    Some(payload)
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

/// A UDP target that answers the first packet with `count` replies on its own
/// clock, one every `period`.
///
/// The shape of a subscription: one request, then traffic the target
/// originates. It exists so a test can hold a session open with *inbound*
/// progress alone — the client sends exactly once, and everything after that
/// crosses the proxy in the other direction.
pub async fn spawn_pushing_udp_target(period: Duration, count: usize) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp target");
    let addr = socket.local_addr().expect("udp target address");

    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let Ok((_, from)) = socket.recv_from(&mut buf).await else {
            return;
        };
        for index in 0..count {
            tokio::time::sleep(period).await;
            let payload = [b"push".as_slice(), &[index as u8]].concat();
            if socket.send_to(&payload, from).await.is_err() {
                return;
            }
        }
    });

    addr
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

/// A UDP target that answers the first packet with `count` numbered replies of
/// `size` bytes, sent from a thread of its own with no await between them.
///
/// The replies queue on the proxy's socket faster than a session forwards one
/// per wake, which is the shape that makes a session take several per wake.
/// Each reply starts with its index as a big-endian `u32`. The thread waits
/// [`TIMEOUT`] for the first packet and then ends, so a failed test leaves
/// nothing behind.
pub async fn spawn_bursting_udp_target(count: u32, size: usize) -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp target");
    socket
        .set_read_timeout(Some(TIMEOUT))
        .expect("udp target read timeout");
    let addr = socket.local_addr().expect("udp target address");

    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let Ok((_, from)) = socket.recv_from(&mut buf) else {
            return;
        };
        let mut reply = vec![0x5au8; size];
        for index in 0..count {
            reply[..4].copy_from_slice(&index.to_be_bytes());
            let _ = socket.send_to(&reply, from);
        }
    });

    addr
}

/// Reads from a client stream until `enough` accepts what has arrived, or until
/// the server finishes its sending side.
///
/// Returns the bytes read and whether the stream ended before `enough` did.
/// The whole read is bounded by [`TIMEOUT`], not each chunk, so a stream that
/// keeps delivering and never ends fails here too. `caller` is the test's
/// location, captured by the public helper that called this (D66).
async fn read_while(
    stream: &mut ClientStream,
    mut enough: impl FnMut(usize) -> bool,
    caller: &'static Location<'static>,
) -> (Vec<u8>, bool) {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut out = Vec::new();
    while !enough(out.len()) {
        let chunk = tokio::time::timeout_at(deadline, stream.recv_data())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the read at {caller} timed out after {} bytes and {TIMEOUT:?}",
                    out.len()
                )
            })
            .unwrap_or_else(|error| {
                panic!(
                    "the read at {caller} failed after {} bytes: {error:?}",
                    out.len()
                )
            });

        match chunk {
            Some(chunk) => out.extend_from_slice(&chunk),
            None => return (out, true),
        }
    }

    (out, false)
}

/// Reads from a client stream until at least `n` bytes have arrived.
#[track_caller]
pub fn read_at_least(stream: &mut ClientStream, n: usize) -> impl Future<Output = Vec<u8>> + '_ {
    at_least(stream, n, Location::caller())
}

/// The body behind [`read_at_least`] and [`echoes`], with `caller` already
/// captured.
pub async fn at_least(
    stream: &mut ClientStream,
    n: usize,
    caller: &'static Location<'static>,
) -> Vec<u8> {
    let (out, ended) = read_while(stream, |read| read >= n, caller).await;
    assert!(
        !ended,
        "the stream read at {caller} ended after {} of {n} bytes",
        out.len()
    );
    out
}

/// Reads from a client stream until the server finishes its sending side.
#[track_caller]
pub fn read_to_end(stream: &mut ClientStream) -> impl Future<Output = Vec<u8>> + '_ {
    let caller = Location::caller();
    async move { read_while(stream, |_| false, caller).await.0 }
}

/// Sends `payload` through an open tunnel and asserts the target echoes it.
///
/// Proves a tunnel is established rather than only answered, against a target
/// spawned by [`spawn_echo_target`].
#[track_caller]
pub fn echoes<'a>(
    stream: &'a mut ClientStream,
    payload: &'a [u8],
) -> impl Future<Output = ()> + 'a {
    echoes_at(stream, payload, Location::caller())
}

/// The body behind [`echoes`], with `caller` already captured.
pub async fn echoes_at(
    stream: &mut ClientStream,
    payload: &[u8],
    caller: &'static Location<'static>,
) {
    stream
        .send_data(Bytes::copy_from_slice(payload))
        .await
        .unwrap_or_else(|error| {
            panic!("the payload sent at {caller} did not reach the tunnel: {error}")
        });

    let echoed = at_least(stream, payload.len(), caller).await;
    assert_eq!(
        echoed, payload,
        "the tunnel used at {caller} echoed the wrong bytes"
    );
}

/// Half-closes `stream` and reads until the server finishes its own side.
///
/// The tail of a tunnel's life, and the shape of RFC 9114 §4.4's half-close as
/// a client sees it: the FIN reaches the target as a write shutdown, the target
/// answers its own EOF, and the server finishes the response stream. Returning
/// only once that has happened is what makes a caller's next assertion — a slot
/// given back, a file descriptor closed — about a tunnel that is really over.
///
/// Whatever arrived after the FIN is handed back, for the callers that assert
/// nothing did.
#[track_caller]
pub fn close_and_drain(stream: &mut ClientStream) -> impl Future<Output = Vec<u8>> + '_ {
    close_and_drain_at(stream, Location::caller())
}

/// The body behind [`close_and_drain`], with `caller` already captured.
pub async fn close_and_drain_at(
    stream: &mut ClientStream,
    caller: &'static Location<'static>,
) -> Vec<u8> {
    stream
        .finish()
        .unwrap_or_else(|error| panic!("the stream finished at {caller} was gone: {error}"));
    read_while(stream, |_| false, caller).await.0
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
                // A zero linger turns the close into a reset.
                let _ = socket.set_zero_linger();
                drop(socket);
            });
        }
    });

    addr
}

/// A TCP target that floods `flood` bytes, never reads, and sends a RST once
/// the client's upload has stalled behind it.
///
/// The sibling of [`spawn_reset_after_read_target`] for the other order of
/// events: the reset has to be noticed by the proxy's *write* pump rather than
/// its read pump.
///
/// Both halves of the proxy have to be pinned for that to be deterministic,
/// because an RST makes the socket fail in both directions at once:
///
/// * the flood — larger than the client's stream flow-control window, and the
///   client under test does not read the tunnel while it lasts — parks the read
///   pump inside `send_data_in_place`, where it cannot see the socket fail at
///   all;
/// * never reading parks the write pump inside `write_all`, once the client's
///   upload has filled every buffer in between.
///
/// The reset waits for that state rather than for a timer: see
/// [`until_stalled`].
pub async fn spawn_flood_then_reset_target(flood: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target address");

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let written = AtomicU64::new(0);
                {
                    let (mut reader, mut writer) = socket.split();
                    let flooding = async {
                        let payload = vec![0x5au8; 64 * 1024];
                        while written.load(Ordering::Relaxed) < flood as u64 {
                            if writer.write_all(&payload).await.is_err() {
                                return;
                            }
                            written.fetch_add(payload.len() as u64, Ordering::Relaxed);
                        }
                        // Written out, and still not reading.
                        std::future::pending::<()>().await;
                    };
                    tokio::select! {
                        () = flooding => {}
                        () = until_stalled(&mut reader, &written) => {}
                    }
                }

                // A zero linger turns the close into a reset.
                let _ = socket.set_zero_linger();
                drop(socket);
            });
        }
    });

    addr
}

/// Resolves once neither direction of the target's socket has moved for
/// 250 ms: the bytes waiting unread in its receive buffer, and `written`.
///
/// Bytes that wait unread and stop growing mean the target's receive window is
/// shut, so the proxy's writes to it queue in its send buffer and then park.
/// `written` standing still means the flood is blocked, so the proxy has
/// stopped reading the target. The unread bytes are counted with `peek`, which
/// reads without consuming and so keeps the window shut. The buffer is larger
/// than any receive buffer either host grants, so the count is never capped by
/// it.
async fn until_stalled(reader: &mut tokio::net::tcp::ReadHalf<'_>, written: &AtomicU64) {
    const QUIET: Duration = Duration::from_millis(250);
    const SAMPLE: Duration = Duration::from_millis(50);

    let mut unread = vec![0u8; 16 * 1024 * 1024];
    let mut last = (0, 0);
    let mut since = Instant::now();
    loop {
        tokio::time::sleep(SAMPLE).await;
        let Ok(waiting) = reader.peek(&mut unread).await else {
            return;
        };
        let now = (waiting, written.load(Ordering::Relaxed));
        if waiting == 0 || now != last {
            last = now;
            since = Instant::now();
        } else if since.elapsed() >= QUIET {
            return;
        }
    }
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
/// log output.
#[derive(Clone, Default)]
pub struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    /// The buffer of the process-wide subscriber, which the first call installs
    /// at `filter`.
    ///
    /// `init` panics on a second call in a process, so every later call
    /// returns that same buffer and its filter stays the first caller's. Every
    /// caller in a binary passes the same filter. Lines from every test of the
    /// binary land in it, so a test finds its own by a field only its own
    /// server or client can produce.
    pub fn shared(filter: &str) -> Self {
        static SHARED: std::sync::OnceLock<SharedBuffer> = std::sync::OnceLock::new();
        SHARED
            .get_or_init(|| {
                let buffer = Self::default();
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_writer(buffer.clone())
                    .with_ansi(false)
                    .init();
                buffer
            })
            .clone()
    }

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

/// Reads a numeric field's value off a formatted log line.
///
/// The field is found by its whole name: `name=` at the start of the line or
/// after whitespace, the rule `tests/replay/shape_extract.py` reads fields by.
/// A field whose name merely ends with `name`, `udp_tx_bytes=` for
/// `tx_bytes`, is not it.
#[track_caller]
pub fn numeric_field(line: &str, name: &str) -> u64 {
    field_text(line, name)
        .parse()
        .unwrap_or_else(|_| panic!("{name}= is not a number in:\n{line}"))
}

/// Reads a field's value off a formatted log line as text: everything after
/// `name=` up to the next whitespace.
///
/// For a value written with `%`, such as an address, which the line carries
/// without quotes. The field is found by its whole name, as in
/// [`numeric_field`].
#[track_caller]
pub fn field_text<'a>(line: &'a str, name: &str) -> &'a str {
    let key = format!("{name}=");
    let rest = line
        .match_indices(&key)
        .find(|(at, _)| {
            line[..*at]
                .chars()
                .next_back()
                .is_none_or(char::is_whitespace)
        })
        .map(|(at, _)| &line[at + key.len()..])
        .unwrap_or_else(|| panic!("no {name}= in:\n{line}"));
    rest.split(char::is_whitespace).next().unwrap_or("")
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

/// How long a client that is meant to hear nothing waits before it gives up.
///
/// The client's own idle timeout, which turns silence into
/// `ConnectionError::TimedOut` rather than into quinn's 30-second default. Two
/// seconds, so a loaded machine cannot pass a slow reply off as no reply.
pub const CLIENT_IDLE: Duration = Duration::from_secs(2);

/// Client transport parameters that give up on a silent server after
/// [`CLIENT_IDLE`]. Keep-alives are off, or the client would keep alive a
/// connection the server never opened.
pub fn impatient_transport() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(CLIENT_IDLE.try_into().expect("a legal idle timeout")));
    transport.keep_alive_interval(None);
    transport
}

/// A raw QUIC connection to `server` on [`windowless_transport`], for a test
/// whose subject is a response the server cannot deliver.
#[track_caller]
pub fn windowless_connection(
    server: &TestServer,
) -> impl Future<Output = (quinn::Endpoint, quinn::Connection)> + '_ {
    windowless_connection_at(server, Location::caller())
}

/// [`windowless_connection`] with `caller` already captured.
pub async fn windowless_connection_at(
    server: &TestServer,
    caller: &'static Location<'static>,
) -> (quinn::Endpoint, quinn::Connection) {
    let endpoint = client_endpoint_with_transport(&server.ca, &["h3"], windowless_transport());
    let connection = finish_connect(&endpoint, server.addr)
        .await
        .unwrap_or_else(|error| panic!("the handshake at {caller} failed: {error}"));

    (endpoint, connection)
}

/// Waits until `counter` has reached `n`, within [`TIMEOUT`].
///
/// For a target that counts what reaches it, such as the one
/// [`spawn_silent_udp_target`] returns. The sends that feed it are
/// fire-and-forget, so the count is waited for rather than read once. A count
/// past `n` is not a failure here; a caller that means exactly `n` asserts that
/// afterwards.
#[track_caller]
pub fn counted_at_least(counter: &AtomicU64, n: u64) -> impl Future<Output = ()> + '_ {
    let caller = Location::caller();
    async move {
        let deadline = Instant::now() + TIMEOUT;
        while counter.load(Ordering::Relaxed) < n {
            assert!(
                Instant::now() < deadline,
                "at {caller}: the count was {} of {n} after {TIMEOUT:?}",
                counter.load(Ordering::Relaxed)
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// Sends a CONNECT to `authority` until one is answered with a 200, for at most
/// `within`.
///
/// For a tunnel slot the server gives back a moment after a tunnel ends: the
/// slot returns when the server-side task does, which the client cannot see,
/// so the request is repeated every 50 ms rather than sent once. A failure
/// names the caller, the number of refusals and the last status.
#[track_caller]
pub fn connect_until_accepted<'a>(
    client: &'a mut H3Client,
    authority: &'a str,
    within: Duration,
) -> impl Future<Output = ()> + 'a {
    let caller = Location::caller();
    async move {
        let deadline = Instant::now() + within;
        let mut refusals = 0u32;
        loop {
            let (response, _) = exchange(client, connect_request(authority), caller).await;
            if response.status == Status::OK {
                return;
            }
            refusals += 1;
            assert!(
                Instant::now() < deadline,
                "at {caller}: {refusals} CONNECTs to {authority} were refused in {within:?}, \
                 the last with {:?}",
                response.status
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// The names of the fields on a formatted log line, in the order they appear.
///
/// A field is `name=` at the start of the line or after whitespace, the rule
/// [`field_text`] finds one by, with a name of lowercase letters, digits and
/// underscores. A value written with `%` is not quoted, so a `word=` inside
/// such a value is read as a field too, and a comparison of two lines reports
/// it as a difference.
pub fn field_names(line: &str) -> Vec<&str> {
    line.split_whitespace()
        .filter_map(|word| word.split_once('=').map(|(name, _)| name))
        .filter(|name| {
            !name.is_empty()
                && name
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        })
        .collect()
}

impl TestServer {
    /// The `[server]` table of this server's own file: loopback on any port,
    /// and its certificate pair. For a test that writes a whole file with
    /// [`Self::write_invalid_config`].
    pub fn server_section(&self) -> String {
        server_table::server_section(&self.cert, &self.key, "127.0.0.1:0")
    }
}
