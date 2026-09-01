//! Shared test harness: a self-signed Volto instance, HTTP/3 clients and
//! cooperating TCP targets.
//!
//! The HTTP/3 client lives in [`h3client`] and is built on the same codec as the
//! server -- `volto::h3` -- so the two ends of every test here share a reading
//! of the framing and of QPACK. What that costs, and why the cross-implementation
//! check now belongs entirely to the `interop` CI job (a real `volto` process
//! driven by Go's masque-go), is spelled out in that module's documentation.

#![allow(dead_code)] // Each integration test binary uses a subset of this.

pub mod h3client;
pub mod huffman;
pub mod rawstream;

pub use h3client::{CONNECT_UDP, ClientStream, H3Client, Response};

use std::net::SocketAddr;
use std::panic::Location;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use volto::config::Config;
use volto::datagram;
use volto::h3api::{FieldValue, Method, Request, Status};
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
/// 24 bytes of connection-level allowance is over the 19-byte SETTINGS frame
/// the handshake needs and under what the handshake plus any response costs. A
/// short response would fit in any per-stream window big enough for that
/// SETTINGS frame, so what has to be exhausted is the *connection* window:
/// nothing in a test reaching for this reads the server's control stream, so
/// those 19 bytes stay charged to that window and leave less than a response
/// behind them.
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
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).expect("trust the test CA");

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
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
///
/// Written as a synchronous function returning a future so that
/// `#[track_caller]` survives to the poll that panics (D66).
#[track_caller]
pub fn finish_connect(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
) -> impl Future<Output = Result<quinn::Connection, quinn::ConnectionError>> + '_ {
    let caller = Location::caller();
    async move {
        let connecting = endpoint
            .connect(addr, "localhost")
            .expect("start connecting");

        tokio::time::timeout(TIMEOUT, connecting)
            .await
            .unwrap_or_else(|_| {
                panic!("the handshake to {addr} started at {caller} took longer than {TIMEOUT:?}")
            })
    }
}

/// Asserts that `error` is the peer resetting the stream, with `code`.
///
/// The failure worth describing is the one where a stream ended the wrong way
/// altogether — cleanly, or with a local error — which is why this reports what
/// arrived rather than only that the code differed. Which code a reset carries
/// is what most of the tests reaching for this are about.
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

/// Sends `request` and waits for the response headers, asserting nothing.
///
/// For the tests whose subject *is* the answer: they assert on the status, or on
/// a `Proxy-Status` field, themselves.
pub async fn respond_to(client: &mut H3Client, request: Request) -> Response {
    send_and_respond(client, request).await.0
}

/// [`respond_to`], keeping the request stream for cases that then use it.
pub async fn send_and_respond(client: &mut H3Client, request: Request) -> (Response, ClientStream) {
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
///
/// Written as a synchronous function returning a future rather than as an `async
/// fn` so that `#[track_caller]` works: on an `async fn` the attribute applies to
/// the call that builds the future, not to the poll that panics, and rustc warns
/// that it is a no-op there. Taking the location up front and putting it in the
/// message is what keeps a failure attributable to the test that opened the
/// tunnel rather than to this line.
#[track_caller]
pub fn open_tcp_tunnel<'a>(
    client: &'a mut H3Client,
    authority: &'a str,
) -> impl Future<Output = ClientStream> + 'a {
    let caller = Location::caller();
    async move {
        let (response, stream) = send_and_respond(client, connect_request(authority)).await;
        assert_eq!(
            response.status,
            Status::OK,
            "the tunnel to {authority} opened at {caller} was refused: proxy-status={:?}",
            proxy_status(&response)
        );
        stream
    }
}

/// Opens a CONNECT-UDP session to `target` and returns its Quarter Stream ID.
///
/// Same shape as [`open_tcp_tunnel`], and for the same reason.
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
/// an address — and the only way to reach one whose family the proxy is left to
/// choose (`it_family`) or one the resolver blackholes (`it_udp`).
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
async fn udp_session(
    client: &mut H3Client,
    server: &TestServer,
    host: String,
    port: u16,
    caller: &'static Location<'static>,
) -> (u64, ClientStream) {
    let (response, stream) =
        send_and_respond(client, connect_udp_request(server.addr, &host, port)).await;

    assert_eq!(
        response.status,
        Status::OK,
        "the session to {host}:{port} opened at {caller} was refused: proxy-status={:?}",
        proxy_status(&response)
    );
    // RFC 9297 §3.4: the response should announce the capsule protocol, and §3.2
    // forbids it from describing a body. Protocol requirements rather than
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

    let quarter_stream_id = datagram::quarter_stream_id(stream.id());
    (quarter_stream_id, stream)
}

/// Queues one UDP payload for `quarter_stream_id` as an HTTP/3 datagram.
///
/// The outbound half of every CONNECT-UDP exchange, written out at ~40 sites
/// before it was gathered here. Queuing is asserted rather than the round trip:
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
///
/// Written as a synchronous function returning a future so `#[track_caller]`
/// survives to the poll that panics (D66).
#[track_caller]
pub fn udp_round_trip<'a>(
    client: &'a H3Client,
    quarter_stream_id: u64,
    payload: &'a [u8],
) -> impl Future<Output = Bytes> + 'a {
    let caller = Location::caller();
    async move {
        client
            .quic
            .send_datagram(datagram::encode_udp_payload(quarter_stream_id, payload))
            .unwrap_or_else(|error| {
                panic!("the datagram sent at {caller} was not queued: {error}")
            });

        let answer = read_datagram(&client.quic, caller).await;
        assert_eq!(
            answer.quarter_stream_id, quarter_stream_id,
            "the answer to the datagram sent at {caller} arrived on another session"
        );
        answer.payload
    }
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
async fn read_datagram(
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

/// Sends `payload` through an open tunnel and asserts the target echoes it.
///
/// The exchange that proves a tunnel is *established* rather than merely
/// answered, written out at some forty sites before it was gathered here.
/// Every one of them sent a short payload to a target spawned by
/// [`spawn_echo_target`] and compared what came back with what went out; that
/// pair of steps is all this is.
///
/// Written as a synchronous function returning a future so `#[track_caller]`
/// survives to the poll that panics (D66) — which is what replaces the
/// bespoke `expect` text each call site used to carry.
#[track_caller]
pub fn echoes<'a>(
    stream: &'a mut ClientStream,
    payload: &'a [u8],
) -> impl Future<Output = ()> + 'a {
    let caller = Location::caller();
    async move {
        stream
            .send_data(Bytes::copy_from_slice(payload))
            .await
            .unwrap_or_else(|error| {
                panic!("the payload sent at {caller} did not reach the tunnel: {error}")
            });

        let echoed = read_at_least(stream, payload.len()).await;
        assert_eq!(
            echoed, payload,
            "the tunnel used at {caller} echoed the wrong bytes"
        );
    }
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
    let caller = Location::caller();
    async move {
        stream
            .finish()
            .unwrap_or_else(|error| panic!("the stream finished at {caller} was gone: {error}"));
        read_to_end(stream).await
    }
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
    /// Installs a process-wide subscriber at `filter`, writing into a new buffer.
    ///
    /// Once per test binary, because `init` panics on the second call in a
    /// process -- which is why every binary that reads log lines runs all its
    /// scenarios inside one `#[tokio::test]`.
    pub fn install(filter: &str) -> Self {
        let buffer = Self::default();
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(buffer.clone())
            .with_ansi(false)
            .init();
        buffer
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
/// Most assertions on a log line pin a field's presence, which is enough for a
/// counter whose value the test cannot arrange. The ones a test *can* arrange —
/// this connection did send packets — are read instead, because a field wired
/// to the wrong source is present and zero rather than absent, and presence
/// alone would pass.
///
/// Beside [`SharedBuffer::lines_since`] and [`SharedBuffer::wait_for_line`],
/// which produce the lines this parses.
#[track_caller]
pub fn numeric_field(line: &str, name: &str) -> u64 {
    let rest = line
        .split_once(&format!("{name}="))
        .unwrap_or_else(|| panic!("no {name}= in:\n{line}"))
        .1;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("{name}= is not a number in:\n{line}"))
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
