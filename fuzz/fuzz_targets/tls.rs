//! The server's TLS (`tls::awslc`, D115): CRYPTO bytes a peer chose, at each
//! encryption level, into a server session on AWS-LC's libssl.
//!
//! The provider runs on every unauthenticated Initial, so the bytes here are
//! what a stranger can send. The first input byte picks a mode:
//!
//! * 0 and 1: arbitrary bytes at the Initial level, cut into fuzzer-chosen
//!   chunks, against a server without and with an ECH key.
//! * 2 and 3: a real ClientHello from a rustls client (plain, and ECH for the
//!   server's own key) with fuzzer-chosen bytes flipped, so the mutations land
//!   deep in a ClientHello and in the ECH decryption rather than at its first
//!   length field.
//! * 4: a real ClientHello, then arbitrary bytes at the Handshake level, where
//!   the client's Finished belongs.
//! * 5: a whole handshake with a rustls client, then arbitrary bytes at the
//!   1-RTT level, where post-handshake messages belong.
//! * 6 and 7: a real ClientHello that draws a HelloRetryRequest, then the
//!   client's real second ClientHello with fuzzer-chosen bytes flipped (plain,
//!   and ECH for the server's own key), so the mutations reach libssl's reader
//!   of a second ClientHello and, with ECH, its second decryption.
//!
//! The oracles besides "no panic and no abort": after every read the provider
//! holds at most `PROBE_HELD_LIMIT` bytes of its own, and a session never moves
//! back a level.

#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{EchConfig, EchMode};
use rustls::crypto::SupportedKxGroup;
use rustls::crypto::aws_lc_rs::kx_group;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, EchConfigListBytes, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use rustls::quic::{ClientConnection, Version};
use rustls::{DigitallySignedStruct, SignatureScheme};
use volto::tls::{EchKey, PROBE_HELD_LIMIT, ProbeSession, ServerConfig, probe_server_config};

/// A self-signed ECDSA P-256 certificate for `localhost` and its key, made with
/// openssl for this target alone. The key protects nothing: it exists so the
/// server has something to sign with, and the client here accepts any
/// certificate. Fixed rather than generated, so the fuzz workspace needs no
/// certificate generator of its own.
const CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIIBljCCATugAwIBAgIUaVW8ZEODp7XiqsYkchOYekhFE6gwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTEyMDA0NTMwNloYDzIxMjYxMDI3
MDQ1MzA2WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQZWobKJJ+7wmF/xnK5TekKAyaO+Zsv++aSLDV+4a7Kvn87UUp3754g
la/GNj32bLujPy9KpAlqI/h0wFxBSKkvo2kwZzAdBgNVHQ4EFgQU0Wdz9FQntxRb
IKdHIhnUKSdnCx0wHwYDVR0jBBgwFoAU0Wdz9FQntxRbIKdHIhnUKSdnCx0wDwYD
VR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwID
SQAwRgIhALkceqECOk0ueKq0+QJLWmpCKSnqfPqvhhZBDT7/ZNpwAiEAiB/OnCU8
1NqMA5oVzNnIS3TDyhKn4p7KLCLGs0E0e1I=
-----END CERTIFICATE-----
";
const KEY: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZNWZ2RuhbP989oBy
rDM3szM8Woz1meTw3/d4huYERaahRANCAAQZWobKJJ+7wmF/xnK5TekKAyaO+Zsv
++aSLDV+4a7Kvn87UUp3754gla/GNj32bLujPy9KpAlqI/h0wFxBSKkv
-----END PRIVATE KEY-----
";

/// max_idle_timeout = 0, a valid transport parameter list.
const PARAMS: [u8; 3] = [0x01, 0x01, 0x00];

struct Fixture {
    plain: Arc<ServerConfig>,
    ech: Arc<ServerConfig>,
    plain_client: Arc<rustls::ClientConfig>,
    plain_hello: Vec<u8>,
    ech_hello: Vec<u8>,
    /// A first ClientHello that draws a HelloRetryRequest, and the second
    /// ClientHello the same client sent after it.
    plain_retry: (Vec<u8>, Vec<u8>),
    ech_retry: (Vec<u8>, Vec<u8>),
}

/// Accepts any certificate: the fuzz target is about the server's parsing.
#[derive(Debug)]
struct AnyCertificate;

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Groups that draw a HelloRetryRequest from the server: SecP256r1MLKEM768,
/// which it does not accept, with the only key share, then X25519.
fn retry_groups() -> Vec<&'static dyn SupportedKxGroup> {
    vec![kx_group::SECP256R1MLKEM768, kx_group::X25519]
}

fn client_config(
    ech: Option<&[u8]>,
    groups: Option<Vec<&'static dyn SupportedKxGroup>>,
) -> Arc<rustls::ClientConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if let Some(groups) = groups {
        provider.kx_groups = groups;
    }
    let provider = Arc::new(provider);
    let builder = rustls::ClientConfig::builder_with_provider(provider);
    let builder = match ech {
        Some(list) => builder
            .with_ech(EchMode::from(
                EchConfig::new(
                    EchConfigListBytes::from(list.to_vec()),
                    rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
                )
                .expect("rustls reads the list"),
            ))
            .expect("ECH"),
        None => builder
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3"),
    };
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(config)
}

fn client(config: &Arc<rustls::ClientConfig>) -> ClientConnection {
    ClientConnection::new(
        config.clone(),
        Version::V1,
        ServerName::try_from("localhost").expect("a name"),
        PARAMS.to_vec(),
    )
    .expect("a client")
}

/// The client's first flight, its ClientHello.
fn first_flight(config: &Arc<rustls::ClientConfig>) -> Vec<u8> {
    let mut buf = Vec::new();
    client(config).write_hs(&mut buf);
    buf
}

/// A first ClientHello that `server` answers with a HelloRetryRequest, and the
/// client's second ClientHello after reading it.
fn retry_pair(
    server: &Arc<ServerConfig>,
    config: &Arc<rustls::ClientConfig>,
) -> (Vec<u8>, Vec<u8>) {
    let mut client = client(config);
    let mut first = Vec::new();
    client.write_hs(&mut first);
    let mut session = ProbeSession::new(server.clone(), &PARAMS).expect("a session");
    assert!(
        session.read(&first),
        "the server reads the first ClientHello"
    );
    for (level, bytes) in session.write() {
        assert_eq!(level, 0, "a HelloRetryRequest is at the Initial level");
        client
            .read_hs(&bytes)
            .expect("the client reads the HelloRetryRequest");
    }
    let mut second = Vec::new();
    client.write_hs(&mut second);
    assert!(!second.is_empty(), "the client sent a second ClientHello");
    (first, second)
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let cert = CertificateDer::from_pem_slice(CERT.as_bytes())
            .expect("the certificate")
            .to_vec();
        let key = PrivatePkcs8KeyDer::from_pem_slice(KEY.as_bytes())
            .expect("the key")
            .secret_pkcs8_der()
            .to_vec();
        let ech_key = Arc::new(EchKey::generate("public.example", 1, 0).expect("an ECH key"));
        let plain = probe_server_config(&cert, &key, None).expect("a server");
        let ech = probe_server_config(&cert, &key, Some(&ech_key)).expect("an ECH server");
        let plain_client = client_config(None, None);
        let ech_list = ech_key.config_list();
        let ech_client = client_config(Some(&ech_list), None);
        Fixture {
            plain_hello: first_flight(&plain_client),
            ech_hello: first_flight(&ech_client),
            plain_retry: retry_pair(&plain, &client_config(None, Some(retry_groups()))),
            ech_retry: retry_pair(&ech, &client_config(Some(&ech_list), Some(retry_groups()))),
            plain,
            ech,
            plain_client,
        }
    })
}

/// A session that checks the two oracles after every step.
struct Checked {
    session: ProbeSession,
    level: u8,
}

impl Checked {
    fn new(config: &Arc<ServerConfig>) -> Self {
        Self {
            session: ProbeSession::new(config.clone(), &PARAMS).expect("a session"),
            level: 0,
        }
    }

    /// Reads, writes, checks. `false` once the session refused the bytes.
    ///
    /// What the session holds is checked between the read and the write,
    /// while the handshake bytes libssl queued are still in the session, and
    /// again after the write, which leaves only the outer ClientHello copy.
    fn step(&mut self, bytes: &[u8]) -> (bool, Vec<(u8, Vec<u8>)>) {
        let ok = self.session.read(bytes);
        self.check_held();
        let out = if ok { self.session.write() } else { Vec::new() };
        self.check_held();
        let level = self.session.level();
        assert!(
            level >= self.level,
            "the level moved back from {} to {level}",
            self.level
        );
        self.level = level;
        (ok, out)
    }

    fn check_held(&self) {
        let held = self.session.held_bytes();
        assert!(held <= PROBE_HELD_LIMIT, "the provider holds {held} bytes");
    }
}

/// Feeds `data` in chunks whose sizes come from `sizes`, until a refusal.
fn chunked(session: &mut Checked, sizes: &[u8], mut data: &[u8]) {
    let mut sizes = sizes.iter().cycle();
    while !data.is_empty() {
        let size = usize::from(*sizes.next().unwrap_or(&255))
            .max(1)
            .min(data.len());
        let (head, tail) = data.split_at(size);
        if !session.step(head).0 {
            return;
        }
        data = tail;
    }
}

/// Splits `rest` into a chunk-size prefix and the payload.
fn split(rest: &[u8]) -> (&[u8], &[u8]) {
    let n = usize::from(rest.first().copied().unwrap_or(0) % 8);
    let rest = rest.get(1..).unwrap_or_default();
    rest.split_at(n.min(rest.len()))
}

/// A real ClientHello with bytes flipped: `rest` is (offset hi, offset lo,
/// xor) triples.
fn mutated(hello: &[u8], rest: &[u8]) -> Vec<u8> {
    let mut hello = hello.to_vec();
    for flip in rest.as_chunks::<3>().0.iter().take(16) {
        if hello.is_empty() {
            break;
        }
        let at = usize::from(u16::from_be_bytes([flip[0], flip[1]])) % hello.len();
        hello[at] ^= flip[2];
    }
    hello
}

/// Runs a client and the session against each other until both stop, and
/// returns the session and whether the handshake completed.
fn complete(f: &Fixture) -> (Checked, bool) {
    let mut session = Checked::new(&f.plain);
    let mut client = client(&f.plain_client);
    let mut to_server = Vec::new();
    client.write_hs(&mut to_server);
    for _ in 0..8 {
        if to_server.is_empty() {
            break;
        }
        let (ok, out) = session.step(&to_server);
        if !ok {
            return (session, false);
        }
        to_server.clear();
        for (_, bytes) in out {
            if client.read_hs(&bytes).is_err() {
                return (session, false);
            }
            loop {
                let mut buf = Vec::new();
                let change = client.write_hs(&mut buf);
                let empty = buf.is_empty();
                to_server.extend_from_slice(&buf);
                if change.is_none() && empty {
                    break;
                }
            }
        }
    }
    let done = !session.session.is_handshaking();
    (session, done)
}

/// Feeds the real first ClientHello of `pair`, which draws a HelloRetryRequest,
/// and then its second ClientHello with the flips in `rest`. An unchanged second
/// ClientHello moves the session to Handshake, which shows that the mode reaches
/// the reader it is for.
fn after_retry(config: &Arc<ServerConfig>, pair: &(Vec<u8>, Vec<u8>), rest: &[u8]) {
    let mut session = Checked::new(config);
    let (ok, out) = session.step(&pair.0);
    assert!(
        ok && !out.is_empty(),
        "a real ClientHello draws a HelloRetryRequest"
    );
    assert_eq!(
        session.session.level(),
        0,
        "a HelloRetryRequest keeps the Initial level"
    );
    let second = mutated(&pair.1, rest);
    let (ok, _) = session.step(&second);
    if second == pair.1 {
        assert!(
            ok && session.session.level() == 2,
            "the real second ClientHello moves to Handshake"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let f = fixture();
    match mode % 8 {
        0 | 1 => {
            let config = if mode % 8 == 0 { &f.plain } else { &f.ech };
            let (sizes, payload) = split(rest);
            chunked(&mut Checked::new(config), sizes, payload);
        }
        2 => {
            Checked::new(&f.plain).step(&mutated(&f.plain_hello, rest));
        }
        3 => {
            Checked::new(&f.ech).step(&mutated(&f.ech_hello, rest));
        }
        4 => {
            let mut session = Checked::new(&f.plain);
            if session.step(&f.plain_hello).0 {
                assert_eq!(
                    session.session.level(),
                    2,
                    "a real ClientHello moves to Handshake"
                );
                let (sizes, payload) = split(rest);
                chunked(&mut session, sizes, payload);
            }
        }
        6 => after_retry(&f.plain, &f.plain_retry, rest),
        7 => after_retry(&f.ech, &f.ech_retry, rest),
        // 5.
        _ => {
            let (mut session, done) = complete(f);
            assert!(
                done,
                "a rustls client completes a handshake with the server"
            );
            assert_eq!(session.session.level(), 3);
            let (sizes, payload) = split(rest);
            chunked(&mut session, sizes, payload);
        }
    }
});
