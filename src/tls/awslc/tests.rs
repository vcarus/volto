//! Behaviour tests: rustls clients against this provider.
//!
//! Most of these run the TLS handshake in memory: a `rustls::quic` client and
//! a [`Session`] hand CRYPTO bytes to each other directly, without packets.
//! That gives the tests the plaintext of every handshake message: whether the
//! server answered the outer ClientHello, which certificate it sent, whether
//! its EncryptedExtensions carry `retry_configs`, whether it issued a session
//! ticket. On the wire the Handshake-level messages are protected with keys
//! derived from the transcript, so a client whose ClientHello was altered in
//! flight could not read them; the tests say so where it matters.
//!
//! The ECH rows are the behaviour table of the 2026-11-20 spike, kept as
//! regression tests: AWS-LC never refuses a handshake for an ECH reason. The
//! last test is on real sockets: a quinn client on rustls sends its first
//! flight to a bare UDP socket, which decrypts the Initial packets and checks
//! how the ClientHello falls across them.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_sys as sys;
use bytes::BytesMut;
use quinn::crypto::rustls::HandshakeData;
use quinn_proto::crypto::Session as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{EchConfig, EchGreaseConfig, EchMode};
use rustls::crypto::aws_lc_rs::{self as provider, hpke, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, EchConfigListBytes, ServerName, UnixTime};
use rustls::quic::KeyChange;
use rustls::{DigitallySignedStruct, PeerIncompatible, SignatureScheme};
use zeroize::Zeroizing;

use super::ech::pem_block;
use super::ffi::{self, OpensslBytes};
use super::hello::{self, EXT_ECH};
use super::{Builder, EchKey, GROUPS, Names, OP_NO_TICKET, ServerConfig, Session, Version, keys};

/// A certificate for `localhost` and its key, as DER.
struct Identity {
    cert: Vec<u8>,
    key: Vec<u8>,
}

/// A self-signed ECDSA P-256 certificate for `localhost`, the shape every
/// test server in the suite uses.
fn identity() -> Identity {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate a certificate");
    Identity {
        cert: issued.cert.der().to_vec(),
        key: issued.signing_key.serialize_der(),
    }
}

/// A self-signed certificate for `localhost` on a key of the given algorithm.
fn identity_for(key: &rcgen::KeyPair) -> Vec<u8> {
    rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .expect("certificate parameters")
        .self_signed(key)
        .expect("sign the certificate")
        .der()
        .to_vec()
}

const PUBLIC_NAME: &str = "public.example";

fn ech_key(config_id: u8) -> EchKey {
    EchKey::generate(PUBLIC_NAME, config_id, 32).expect("generate an ECH key")
}

/// A server on `id`, with ECH under `ech` and the second gate's list `names`.
fn server(
    id: &Identity,
    ech: Option<&EchKey>,
    groups: &[u16],
    names: &[&str],
) -> Arc<ServerConfig> {
    Arc::new(
        Builder {
            certs: vec![id.cert.clone()],
            key: Zeroizing::new(id.key.clone()),
            alpn: vec![b"h3".to_vec()],
            names: Names::new(&names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>()),
            ech,
            groups,
            keylog: None,
        }
        .build()
        .expect("build the provider"),
    )
}

/// Accepts any certificate after checking its signature, and records what it
/// was shown.
#[derive(Debug, Default)]
struct Recorder {
    seen: Mutex<Vec<(String, Vec<u8>)>>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.seen
            .lock()
            .expect("recorder lock")
            .push((server_name.to_str().into_owned(), end_entity.to_vec()));
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// X25519MLKEM768 first, as Surge orders its groups.
fn pq_first() -> Vec<&'static dyn SupportedKxGroup> {
    vec![
        kx_group::X25519MLKEM768,
        kx_group::X25519,
        kx_group::SECP256R1,
        kx_group::SECP384R1,
    ]
}

fn client_config(
    ech: Option<EchMode>,
    groups: Vec<&'static dyn SupportedKxGroup>,
    recorder: Arc<Recorder>,
) -> rustls::ClientConfig {
    let provider = Arc::new(CryptoProvider {
        kx_groups: groups,
        ..provider::default_provider()
    });
    let builder = rustls::ClientConfig::builder_with_provider(provider);
    let builder = match ech {
        Some(mode) => builder.with_ech(mode).expect("ECH with TLS 1.3"),
        None => builder
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3"),
    };
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(recorder)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    config
}

fn enable(list: &[u8]) -> EchMode {
    EchMode::from(
        EchConfig::new(
            EchConfigListBytes::from(list.to_vec()),
            hpke::ALL_SUPPORTED_SUITES,
        )
        .expect("rustls reads the list"),
    )
}

/// A GREASE ECH extension, which no server key opens.
fn grease() -> EchMode {
    let suite = hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
    let (placeholder, _) = rustls::crypto::hpke::Hpke::generate_key_pair(suite).expect("a key");
    EchMode::from(EchGreaseConfig::new(suite, placeholder))
}

/// Placeholder transport parameters: max_idle_timeout = 0.
const PARAMS: [u8; 3] = [0x01, 0x01, 0x00];

/// The SHA-256 of "HelloRetryRequest", which a HelloRetryRequest carries as its
/// random. RFC 8446 §4.1.3: "CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
/// C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C".
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Handshake message types (RFC 8446 §4).
const SERVER_HELLO: u8 = 2;
const NEW_SESSION_TICKET: u8 = 4;
const ENCRYPTED_EXTENSIONS: u8 = 8;
const CERTIFICATE: u8 = 11;
/// The `early_data` extension type (RFC 8446 §4.2).
const EXT_EARLY_DATA: u16 = 42;
/// The `pre_shared_key` extension type (RFC 8446 §4.2).
const EXT_PRE_SHARED_KEY: u16 = 41;

/// What one in-memory handshake showed.
#[derive(Debug, Default)]
struct Outcome {
    /// Every ClientHello the client sent, after any tampering.
    client_hellos: Vec<Vec<u8>>,
    /// Whether the server answered with a HelloRetryRequest.
    hello_retry: bool,
    /// The handshake messages the server wrote: (level index, type, length).
    server_messages: Vec<(usize, u8, usize)>,
    /// The bodies of the NewSessionTicket messages the server wrote.
    tickets: Vec<Vec<u8>>,
    /// Whether the server's EncryptedExtensions carried an ECH extension
    /// (the `retry_configs`).
    retry_configs_sent: bool,
    /// Whether the server sent a Certificate message.
    certificate_sent: bool,
    server_error: Option<String>,
    client_error: Option<rustls::Error>,
    ech_accepted: bool,
    server_done: bool,
    client_done: bool,
    /// The names rustls verified the certificate against, and the certificate.
    verified: Vec<(String, Vec<u8>)>,
    group: u16,
    /// What `handshake_data` reported, once there was any.
    handshake_data: Option<(Option<Vec<u8>>, Option<String>)>,
}

/// Splits a run of handshake messages into (type, body).
fn messages(bytes: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= bytes.len() {
        let len = usize::from(bytes[at + 1]) << 16
            | usize::from(bytes[at + 2]) << 8
            | usize::from(bytes[at + 3]);
        let Some(body) = bytes.get(at + 4..at + 4 + len) else {
            break;
        };
        out.push((bytes[at], body));
        at += 4 + len;
    }
    out
}

/// The extension types in an extension block `<0..2^16-1>` at `block`.
fn extension_types(block: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    let mut at = 2;
    while at + 4 <= block.len() {
        out.push(u16::from_be_bytes([block[at], block[at + 1]]));
        at += 4 + usize::from(u16::from_be_bytes([block[at + 2], block[at + 3]]));
    }
    out
}

/// The extensions of a NewSessionTicket body: ticket_lifetime (4),
/// ticket_age_add (4), ticket_nonce<0..255>, ticket<1..2^16-1>, extensions
/// (RFC 8446 §4.6.1).
fn ticket_extensions(body: &[u8]) -> Vec<u16> {
    let nonce_len = usize::from(body[8]);
    let at = 9 + nonce_len;
    let ticket_len = usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
    extension_types(&body[at + 2 + ticket_len..])
}

/// Runs one handshake in memory. `tamper` may rewrite each ClientHello before
/// the server reads it.
fn handshake(
    server: Arc<ServerConfig>,
    client: Arc<rustls::ClientConfig>,
    recorder: &Recorder,
    tamper: &dyn Fn(&mut [u8]),
) -> Outcome {
    let mut out = Outcome::default();
    let mut session = Session::new(server, Version::V1, &PARAMS).expect("start a session");
    let mut rustls = rustls::quic::ClientConnection::new(
        client,
        rustls::quic::Version::V1,
        ServerName::try_from("localhost").expect("a name"),
        PARAMS.to_vec(),
    )
    .expect("start a client");
    // Each side runs its write loop right after each read, as quinn does, so
    // the bytes a write returns ahead of a key change belong to the old level.
    let mut client_level = 0usize;
    let mut server_level = 0usize;
    let mut to_server: std::collections::VecDeque<(usize, Vec<u8>)> = Default::default();
    let mut to_client: std::collections::VecDeque<(usize, Vec<u8>)> = Default::default();

    fn drain_client(
        rustls: &mut rustls::quic::ClientConnection,
        level: &mut usize,
        queue: &mut std::collections::VecDeque<(usize, Vec<u8>)>,
    ) {
        loop {
            let mut buf = Vec::new();
            let change = rustls.write_hs(&mut buf);
            let empty = buf.is_empty();
            if !empty {
                queue.push_back((*level, buf));
            }
            match change {
                Some(KeyChange::Handshake { .. }) => *level = 2,
                Some(KeyChange::OneRtt { .. }) => *level = 3,
                None if empty => return,
                None => {}
            }
        }
    }

    fn drain_server(
        session: &mut Session,
        level: &mut usize,
        queue: &mut std::collections::VecDeque<(usize, Vec<u8>)>,
    ) {
        loop {
            let mut buf = Vec::new();
            let keys = session.write_handshake(&mut buf);
            let empty = buf.is_empty();
            if !empty {
                queue.push_back((*level, buf));
            }
            match keys {
                Some(_) => *level = if *level == 0 { 2 } else { 3 },
                None if empty => return,
                None => {}
            }
        }
    }

    drain_client(&mut rustls, &mut client_level, &mut to_server);
    for _step in 0..64 {
        if let Some((level, mut buf)) = to_server.pop_front() {
            if level == 0 {
                tamper(&mut buf);
                out.client_hellos.push(buf.clone());
            }
            let result = session.read_handshake(&buf);
            if out.handshake_data.is_none()
                && let Some(data) = session.handshake_data()
            {
                let data = data.downcast::<HandshakeData>().expect("quinn's type");
                out.handshake_data = Some((data.protocol, data.server_name));
            }
            if let Err(error) = result {
                out.server_error = Some(format!("{error}"));
                break;
            }
            drain_server(&mut session, &mut server_level, &mut to_client);
            continue;
        }
        if let Some((level, buf)) = to_client.pop_front() {
            for (kind, body) in messages(&buf) {
                out.server_messages.push((level, kind, body.len()));
                if kind == SERVER_HELLO && body.get(2..34) == Some(&HRR_RANDOM[..]) {
                    out.hello_retry = true;
                }
                if kind == ENCRYPTED_EXTENSIONS && extension_types(body).contains(&EXT_ECH) {
                    out.retry_configs_sent = true;
                }
                if kind == CERTIFICATE {
                    out.certificate_sent = true;
                }
                if kind == NEW_SESSION_TICKET {
                    out.tickets.push(body.to_vec());
                }
            }
            if let Err(error) = rustls.read_hs(&buf) {
                out.client_error = Some(error);
                break;
            }
            drain_client(&mut rustls, &mut client_level, &mut to_server);
            continue;
        }
        break;
    }

    out.ech_accepted = session.ech_accepted();
    out.server_done = !session.is_handshaking();
    out.client_done = !rustls.is_handshaking();
    out.verified = recorder.seen.lock().expect("recorder lock").clone();
    // SAFETY: the session's SSL is valid; the getter only reads.
    out.group = unsafe { sys::SSL_get_group_id(session.ssl.as_ptr()) };
    out
}

fn retry_configs_in(error: &Option<rustls::Error>) -> Option<bool> {
    match error {
        Some(rustls::Error::PeerIncompatible(
            PeerIncompatible::ServerRejectedEncryptedClientHello(configs),
        )) => Some(configs.as_ref().is_some_and(|c| !c.is_empty())),
        _ => None,
    }
}

fn untouched(_: &mut [u8]) {}

/// A plain handshake: no ECH, no gate, the common test identity.
fn plain(client: rustls::ClientConfig, recorder: &Recorder) -> Outcome {
    let id = identity();
    handshake(
        server(&id, None, &GROUPS, &[]),
        Arc::new(client),
        recorder,
        &untouched,
    )
}

/// (a) The right ECHConfig: accepted, the inner name, our certificate, no
/// retry_configs, and X25519MLKEM768.
#[test]
fn ech_with_the_right_config_is_accepted() {
    let id = identity();
    let key = ech_key(1);
    let recorder = Arc::new(Recorder::default());
    let client = client_config(
        Some(enable(&key.config_list())),
        pq_first(),
        recorder.clone(),
    );
    let outcome = handshake(
        server(&id, Some(&key), &GROUPS, &[]),
        Arc::new(client),
        &recorder,
        &untouched,
    );
    assert!(
        outcome.ech_accepted && outcome.server_done && outcome.client_done,
        "{outcome:?}"
    );
    assert!(!outcome.retry_configs_sent);
    assert_eq!(outcome.group, 0x11ec);
    assert_eq!(outcome.verified[0].0, "localhost");
    assert_eq!(outcome.verified[0].1, id.cert);
    // The inner name is what quinn's handshake data and the log line carry.
    assert_eq!(
        outcome.handshake_data.and_then(|(_, name)| name).as_deref(),
        Some("localhost")
    );
}

/// (b) No ECH extension: an ordinary handshake on the only ClientHello, and no
/// ECH extension in the answer, although the server holds a key.
#[test]
fn a_client_without_ech_gets_an_ordinary_handshake() {
    let id = identity();
    let key = ech_key(1);
    let recorder = Arc::new(Recorder::default());
    let client = client_config(None, pq_first(), recorder.clone());
    let outcome = handshake(
        server(&id, Some(&key), &GROUPS, &[]),
        Arc::new(client),
        &recorder,
        &untouched,
    );
    assert!(
        !outcome.ech_accepted && outcome.server_done && outcome.client_done,
        "{outcome:?}"
    );
    assert!(!outcome.retry_configs_sent);
    let body = hello::client_hello_body(&outcome.client_hellos[0]).expect("a ClientHello");
    assert!(hello::ech_outer(body).is_none());
}

/// (c) GREASE ECH: not accepted, answered on the outer ClientHello with
/// retry_configs, which rustls ignores in GREASE mode, so it completes.
#[test]
fn grease_ech_is_answered_on_the_outer_hello_with_retry_configs() {
    let id = identity();
    let key = ech_key(1);
    let recorder = Arc::new(Recorder::default());
    let client = client_config(Some(grease()), pq_first(), recorder.clone());
    let outcome = handshake(
        server(&id, Some(&key), &GROUPS, &[]),
        Arc::new(client),
        &recorder,
        &untouched,
    );
    assert!(
        !outcome.ech_accepted && outcome.server_done && outcome.client_done,
        "{outcome:?}"
    );
    assert!(outcome.retry_configs_sent);
}

/// (d) ECH under a config_id the server does not hold: answered on the outer
/// ClientHello, with our certificate and our retry_configs, and the client
/// gives up.
#[test]
fn ech_under_another_key_is_answered_on_the_outer_hello() {
    let id = identity();
    let key = ech_key(1);
    let other = ech_key(2);
    let recorder = Arc::new(Recorder::default());
    let client = client_config(
        Some(enable(&other.config_list())),
        pq_first(),
        recorder.clone(),
    );
    let outcome = handshake(
        server(&id, Some(&key), &GROUPS, &[]),
        Arc::new(client),
        &recorder,
        &untouched,
    );
    // The client aborts after reading the server's flight, so the server never
    // sees a Finished.
    assert!(
        !outcome.ech_accepted && outcome.certificate_sent,
        "{outcome:?}"
    );
    assert!(outcome.retry_configs_sent);
    assert_eq!(retry_configs_in(&outcome.client_error), Some(true));
    // A rejected client checks the certificate against the public name.
    assert_eq!(outcome.verified[0].0, PUBLIC_NAME);
}

/// Flips the last byte of the outer ECH payload, which is inside the AEAD tag.
fn corrupt_ech_payload(message: &mut [u8]) {
    let Some(body) = hello::client_hello_body(message) else {
        return;
    };
    let exts = hello::extensions(body).expect("extensions");
    let (_, range) = exts
        .into_iter()
        .find(|(kind, _)| *kind == EXT_ECH)
        .expect("an ECH extension");
    // The body starts four bytes into the message.
    message[4 + range.end - 1] ^= 0x01;
}

/// (e) The right config_id with a damaged payload: not told apart from GREASE.
#[test]
fn a_damaged_ech_payload_is_answered_on_the_outer_hello() {
    let id = identity();
    let key = ech_key(1);
    let recorder = Arc::new(Recorder::default());
    let client = client_config(
        Some(enable(&key.config_list())),
        pq_first(),
        recorder.clone(),
    );
    let outcome = handshake(
        server(&id, Some(&key), &GROUPS, &[]),
        Arc::new(client),
        &recorder,
        &corrupt_ech_payload,
    );
    assert!(
        !outcome.ech_accepted && outcome.certificate_sent && outcome.retry_configs_sent,
        "{outcome:?}"
    );
}

/// The client lists X25519 first and sends only its share; a server that does
/// not offer X25519 picks X25519MLKEM768, the first group both support, and
/// asks for its share with a HelloRetryRequest.
fn x25519_first() -> Vec<&'static dyn SupportedKxGroup> {
    vec![
        kx_group::X25519,
        kx_group::X25519MLKEM768,
        kx_group::SECP256R1,
    ]
}

/// (f) A HelloRetryRequest with the right ECHConfig: ECH is kept across both
/// ClientHellos.
#[test]
fn a_hello_retry_request_keeps_ech() {
    let id = identity();
    let key = ech_key(1);
    let recorder = Arc::new(Recorder::default());
    let client = client_config(
        Some(enable(&key.config_list())),
        x25519_first(),
        recorder.clone(),
    );
    let outcome = handshake(
        server(&id, Some(&key), &[0x11ec, 0x0017], &[]),
        Arc::new(client),
        &recorder,
        &untouched,
    );
    assert!(outcome.hello_retry);
    assert_eq!(outcome.client_hellos.len(), 2);
    assert!(
        outcome.ech_accepted && outcome.server_done && outcome.client_done,
        "{outcome:?}"
    );
}

/// (f') The same HelloRetryRequest with an ECHConfig the server does not hold.
#[test]
fn a_hello_retry_request_keeps_a_rejection() {
    let id = identity();
    let key = ech_key(1);
    let other = ech_key(2);
    let recorder = Arc::new(Recorder::default());
    let client = client_config(
        Some(enable(&other.config_list())),
        x25519_first(),
        recorder.clone(),
    );
    let outcome = handshake(
        server(&id, Some(&key), &[0x11ec, 0x0017], &[]),
        Arc::new(client),
        &recorder,
        &untouched,
    );
    assert!(outcome.hello_retry && !outcome.ech_accepted, "{outcome:?}");
    assert_eq!(retry_configs_in(&outcome.client_error), Some(true));
}

/// The second gate with ECH: the inner name when accepted, the outer name
/// otherwise. The list names `localhost` only.
#[test]
fn the_second_gate_judges_the_inner_name_when_ech_is_accepted() {
    let id = identity();
    let key = ech_key(1);
    let other = ech_key(2);
    let gated = server(&id, Some(&key), &GROUPS, &["localhost"]);

    // Accepted: inner `localhost` is judged, although the outer name is the
    // public name, which is not on the list.
    let recorder = Arc::new(Recorder::default());
    let client = client_config(
        Some(enable(&key.config_list())),
        pq_first(),
        recorder.clone(),
    );
    let outcome = handshake(gated.clone(), Arc::new(client), &recorder, &untouched);
    assert!(outcome.ech_accepted && outcome.server_done, "{outcome:?}");

    // GREASE keeps the real name in the outer ClientHello, which is on the
    // list.
    let recorder = Arc::new(Recorder::default());
    let client = client_config(Some(grease()), pq_first(), recorder.clone());
    let outcome = handshake(gated.clone(), Arc::new(client), &recorder, &untouched);
    assert!(outcome.server_done, "{outcome:?}");

    // Another key: the outer ClientHello carries the public name, which is off
    // the list, so the handshake is refused before any certificate.
    let recorder = Arc::new(Recorder::default());
    let client = client_config(
        Some(enable(&other.config_list())),
        pq_first(),
        recorder.clone(),
    );
    let outcome = handshake(gated, Arc::new(client), &recorder, &untouched);
    assert!(!outcome.certificate_sent, "{outcome:?}");
    assert!(
        outcome
            .server_error
            .as_deref()
            .is_some_and(|e| e.contains("error 112")),
        "{outcome:?}"
    );
}

/// The second gate without ECH: a name off the list gets
/// `unrecognized_name(112)` and no handshake message at all.
#[test]
fn the_second_gate_refuses_a_name_off_the_list_without_a_certificate() {
    let id = identity();
    let recorder = Arc::new(Recorder::default());
    let client = client_config(None, pq_first(), recorder.clone());
    let outcome = handshake(
        server(&id, None, &GROUPS, &["other.example"]),
        Arc::new(client),
        &recorder,
        &untouched,
    );
    assert!(!outcome.certificate_sent);
    assert!(
        outcome.server_messages.is_empty(),
        "{:?}",
        outcome.server_messages
    );
    // QUIC carries the alert as CRYPTO_ERROR 0x100 + 112.
    assert!(
        outcome
            .server_error
            .as_deref()
            .is_some_and(|e| e.contains("error 112")),
        "{outcome:?}"
    );
}

/// Rewrites one byte of the `host_name` in a ClientHello's `server_name`.
fn sni_byte(to: u8) -> impl Fn(&mut [u8]) {
    move |message: &mut [u8]| {
        let Some(body) = hello::client_hello_body(message) else {
            return;
        };
        let (_, range) = hello::extensions(body)
            .expect("extensions")
            .into_iter()
            .find(|(kind, _)| *kind == 0)
            .expect("a server_name extension");
        // list length (2), name type (1), name length (2), then the name.
        message[4 + range.start + 5 + 1] = to;
    }
}

/// A `host_name` that is not a DNS name is no name, as rustls's server took it:
/// the gate refuses it, and with the gate off it never reaches quinn's
/// handshake data, which the `connection established` line prints unescaped.
#[test]
fn a_server_name_that_is_not_a_dns_name_counts_as_none() {
    let id = identity();

    let recorder = Arc::new(Recorder::default());
    let client = client_config(None, pq_first(), recorder.clone());
    let outcome = handshake(
        server(&id, None, &GROUPS, &[]),
        Arc::new(client),
        &recorder,
        &sni_byte(b'\n'),
    );
    let (alpn, name) = outcome.handshake_data.expect("the ClientHello was read");
    assert_eq!(alpn.as_deref(), Some(&b"h3"[..]));
    assert_eq!(name, None, "a newline must never reach the log line");

    // `lxcalhost` is a DNS name, so the same rewrite with a letter is read.
    let recorder = Arc::new(Recorder::default());
    let client = client_config(None, pq_first(), recorder.clone());
    let outcome = handshake(
        server(&id, None, &GROUPS, &[]),
        Arc::new(client),
        &recorder,
        &sni_byte(b'x'),
    );
    assert_eq!(
        outcome.handshake_data.and_then(|(_, name)| name).as_deref(),
        Some("lxcalhost")
    );

    // With the gate on, no name is not a name on the list.
    let recorder = Arc::new(Recorder::default());
    let client = client_config(None, pq_first(), recorder.clone());
    let outcome = handshake(
        server(&id, None, &GROUPS, &["localhost", "l\ncalhost"]),
        Arc::new(client),
        &recorder,
        &sni_byte(b'\n'),
    );
    assert!(
        outcome
            .server_error
            .as_deref()
            .is_some_and(|e| e.contains("error 112")),
        "{outcome:?}"
    );
}

/// ALPN: a client offering none of the server's protocols, or no ALPN at all,
/// is refused with `no_application_protocol(120)`, as the rustls server
/// refused it.
#[test]
fn a_client_without_a_common_alpn_protocol_is_refused() {
    for offered in [vec![b"h2".to_vec()], Vec::new()] {
        let recorder = Arc::new(Recorder::default());
        let mut client = client_config(None, pq_first(), recorder.clone());
        client.alpn_protocols = offered.clone();
        let outcome = plain(client, &recorder);
        assert!(!outcome.certificate_sent, "{offered:?}: {outcome:?}");
        assert!(
            outcome
                .server_error
                .as_deref()
                .is_some_and(|e| e.contains("error 120")),
            "{offered:?}: {outcome:?}"
        );
    }

    // The server's first protocol that the client offered, in the server's
    // order.
    let recorder = Arc::new(Recorder::default());
    let mut client = client_config(None, pq_first(), recorder.clone());
    client.alpn_protocols = vec![b"h2".to_vec(), b"h3".to_vec()];
    let outcome = plain(client, &recorder);
    assert!(outcome.server_done, "{outcome:?}");
    assert_eq!(
        outcome.handshake_data.and_then(|(alpn, _)| alpn).as_deref(),
        Some(&b"h3"[..])
    );
}

/// The three TLS 1.3 suites the rustls server offered are the three this one
/// offers, and each completes with a client that offers only it.
#[test]
fn each_of_the_three_cipher_suites_completes() {
    for suite in [
        provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
        provider::cipher_suite::TLS13_AES_256_GCM_SHA384,
        provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ] {
        let recorder = Arc::new(Recorder::default());
        let provider = Arc::new(CryptoProvider {
            cipher_suites: vec![suite],
            ..provider::default_provider()
        });
        let mut client = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(recorder.clone())
            .with_no_client_auth();
        client.alpn_protocols = vec![b"h3".to_vec()];
        let outcome = plain(client, &recorder);
        assert!(
            outcome.server_done && outcome.client_done,
            "{suite:?}: {outcome:?}"
        );
    }
}

/// Each group the rustls server accepted is accepted here, from a client that
/// offers only it.
#[test]
fn each_of_the_four_groups_completes() {
    for group in [
        kx_group::X25519MLKEM768,
        kx_group::X25519,
        kx_group::SECP256R1,
        kx_group::SECP384R1,
    ] {
        let recorder = Arc::new(Recorder::default());
        let client = client_config(None, vec![group], recorder.clone());
        let outcome = plain(client, &recorder);
        assert!(
            outcome.server_done && outcome.client_done,
            "{:?}: {outcome:?}",
            group.name()
        );
        assert_eq!(outcome.group, u16::from(group.name()));
    }
}

/// No session ticket is issued (D115 item 3).
#[test]
fn no_session_ticket_is_issued() {
    let recorder = Arc::new(Recorder::default());
    let mut client = client_config(None, pq_first(), recorder.clone());
    client.enable_early_data = true;
    let outcome = plain(client, &recorder);
    assert!(outcome.server_done && outcome.client_done, "{outcome:?}");
    assert!(outcome.tickets.is_empty(), "{:?}", outcome.server_messages);
}

/// With tickets forced on, which this server never does, a ticket still
/// carries no `early_data` extension: the early-data switch is off on its own
/// and not only because there is no ticket to resume with.
#[test]
fn a_ticket_would_not_offer_early_data_either() {
    let id = identity();
    let server = server(&id, None, &GROUPS, &[]);
    // SAFETY: the context has not been shared and no SSL has been made from
    // it; these two calls undo the two ticket settings `Builder::build` made.
    unsafe {
        sys::SSL_CTX_clear_options(server.ctx.as_ptr(), OP_NO_TICKET);
        ffi::check(
            sys::SSL_CTX_set_num_tickets(server.ctx.as_ptr(), 2),
            "SSL_CTX_set_num_tickets",
        )
        .expect("tickets on");
    }
    let recorder = Arc::new(Recorder::default());
    let mut client = client_config(None, pq_first(), recorder.clone());
    client.enable_early_data = true;
    let client = Arc::new(client);

    let first = handshake(server.clone(), client.clone(), &recorder, &untouched);
    assert!(first.server_done && first.client_done, "{first:?}");
    assert_eq!(first.tickets.len(), 2, "the forced tickets were sent");
    for ticket in &first.tickets {
        assert!(
            !ticket_extensions(ticket).contains(&EXT_EARLY_DATA),
            "a ticket allowed early data"
        );
    }

    // The client resumes with one of them and, since the ticket allows no
    // early data, offers none.
    let second = handshake(server, client, &recorder, &untouched);
    let body = hello::client_hello_body(&second.client_hellos[0]).expect("a ClientHello");
    let offered: Vec<u16> = hello::extensions(body)
        .expect("extensions")
        .into_iter()
        .map(|(kind, _)| kind)
        .collect();
    assert!(
        offered.contains(&EXT_PRE_SHARED_KEY),
        "the ticket was used: {offered:?}"
    );
    assert!(
        !offered.contains(&EXT_EARLY_DATA),
        "early data was offered: {offered:?}"
    );
}

/// Key update through the trait: three generations sealed by the provider and
/// opened by rustls.
#[test]
fn next_1rtt_keys_follow_quic_ku() {
    let id = identity();
    let config = server(&id, None, &GROUPS, &[]);
    let recorder = Arc::new(Recorder::default());
    let client_cfg = Arc::new(client_config(None, pq_first(), recorder));
    let mut session = Session::new(config, Version::V1, &PARAMS).expect("session");
    let mut client = rustls::quic::ClientConnection::new(
        client_cfg,
        rustls::quic::Version::V1,
        ServerName::try_from("localhost").expect("name"),
        PARAMS.to_vec(),
    )
    .expect("client");
    let mut client_next = None;
    let mut server_one_rtt = false;
    for _ in 0..4 {
        loop {
            let mut buf = Vec::new();
            let change = client.write_hs(&mut buf);
            if !buf.is_empty() {
                session.read_handshake(&buf).expect("server reads");
            }
            if let Some(KeyChange::OneRtt { next, .. }) = change {
                client_next = Some(next);
            } else if change.is_none() && buf.is_empty() {
                break;
            }
        }
        loop {
            let mut buf = Vec::new();
            let keys = session.write_handshake(&mut buf);
            if !buf.is_empty() {
                client.read_hs(&buf).expect("client reads");
            }
            if keys.is_some() {
                server_one_rtt = !session.is_handshaking();
            } else if buf.is_empty() {
                break;
            }
        }
    }
    assert!(server_one_rtt);
    let mut client_next = client_next.expect("client 1-RTT secrets");
    for generation in 1..=3 {
        let server_keys = session.next_1rtt_keys().expect("server key update");
        let client_keys = client_next.next_packet_keys();
        let mut packet = vec![0x40, 1, 2, 3, 0xaa, 0xbb];
        packet.extend_from_slice(&[0u8; 16]);
        server_keys.local.encrypt(generation, &mut packet, 4);
        let (header, body) = packet.split_at_mut(4);
        let plain = rustls::quic::PacketKey::decrypt_in_place(
            client_keys.remote.as_ref(),
            generation,
            header,
            body,
        )
        .unwrap_or_else(|_| panic!("the client opens generation {generation}"))
        .to_vec();
        assert_eq!(plain, [0xaa, 0xbb]);
    }
}

/// A private key in `der` written as one PEM block and read back through
/// `tls::load_key`, the path `server.key` takes.
fn through_load_key(label: &str, der: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut text = String::new();
    pem_block(&mut text, label, der);
    let dir = std::env::temp_dir().join(format!(
        "volto-tls-key-{}-{}",
        std::process::id(),
        label.replace(' ', "-")
    ));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join(format!("{:p}.pem", der.as_ptr()));
    std::fs::write(&path, text).expect("write the key");
    let key = super::super::load_key(&path).expect("load_key reads it");
    let _ = std::fs::remove_file(&path);
    Zeroizing::new(key.secret_der().to_vec())
}

/// An RSA key's PKCS#1 `RSAPrivateKey` form.
fn pkcs1(pkcs8: &[u8]) -> Vec<u8> {
    let pkey = ffi::private_key_from_der(pkcs8).expect("an RSA key");
    let mut out = std::ptr::null_mut();
    let mut len = 0usize;
    // SAFETY: `pkey` is a parsed RSA key owned here; EVP_PKEY_get0_RSA borrows
    // its RSA without a new reference, and RSA_private_key_to_bytes allocates
    // the output that `OpensslBytes` frees.
    let rc = unsafe {
        let rsa = sys::EVP_PKEY_get0_RSA(pkey.as_ptr());
        sys::RSA_private_key_to_bytes(&mut out, &mut len, rsa)
    };
    ffi::check(rc, "RSA_private_key_to_bytes").expect("marshal PKCS#1");
    OpensslBytes::from_raw(out, len, "RSA_private_key_to_bytes")
        .expect("a buffer")
        .as_slice()
        .to_vec()
}

/// Every key type and every key format `docs/configuration.md` promises for
/// `server.key` (PKCS#8, PKCS#1 and SEC1) signs a handshake the client
/// verifies: ECDSA P-256, P-384 and P-521, Ed25519, RSA 2048.
#[test]
fn every_promised_key_type_and_format_signs_a_handshake() {
    let p256 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("P-256");
    let p384 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).expect("P-384");
    let p521 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P521_SHA512).expect("P-521");
    let ed25519 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("Ed25519");
    let rsa = rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
        .expect("RSA");

    let sec1 = |key: &rcgen::KeyPair, alg| {
        aws_lc_rs::signature::EcdsaKeyPair::from_pkcs8(alg, &key.serialize_der())
            .expect("an ECDSA key")
            .private_key()
            .as_der()
            .expect("SEC1")
            .as_ref()
            .to_vec()
    };
    let cases: Vec<(&str, &rcgen::KeyPair, &str, Vec<u8>)> = vec![
        ("P-256 PKCS#8", &p256, "PRIVATE KEY", p256.serialize_der()),
        (
            "P-256 SEC1",
            &p256,
            "EC PRIVATE KEY",
            sec1(&p256, &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING),
        ),
        ("P-384 PKCS#8", &p384, "PRIVATE KEY", p384.serialize_der()),
        (
            "P-384 SEC1",
            &p384,
            "EC PRIVATE KEY",
            sec1(&p384, &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1_SIGNING),
        ),
        ("P-521 PKCS#8", &p521, "PRIVATE KEY", p521.serialize_der()),
        (
            "Ed25519 PKCS#8",
            &ed25519,
            "PRIVATE KEY",
            ed25519.serialize_der(),
        ),
        ("RSA PKCS#8", &rsa, "PRIVATE KEY", rsa.serialize_der()),
        (
            "RSA PKCS#1",
            &rsa,
            "RSA PRIVATE KEY",
            pkcs1(&rsa.serialize_der()),
        ),
    ];
    for (what, key, label, der) in cases {
        let id = Identity {
            cert: identity_for(key),
            key: through_load_key(label, &der).to_vec(),
        };
        let recorder = Arc::new(Recorder::default());
        let client = client_config(None, pq_first(), recorder.clone());
        let outcome = handshake(
            server(&id, None, &GROUPS, &[]),
            Arc::new(client),
            &recorder,
            &untouched,
        );
        assert!(
            outcome.server_done && outcome.client_done,
            "{what}: {outcome:?}"
        );
        assert_eq!(outcome.verified[0].1, id.cert, "{what}");
    }
}

/// A key that is not the certificate's is refused at build, in the wording the
/// rustls server used.
#[test]
fn a_key_that_does_not_match_the_certificate_is_refused_by_that_name() {
    let id = identity();
    let stray = identity();
    let error = Builder {
        certs: vec![id.cert],
        key: Zeroizing::new(stray.key),
        alpn: vec![b"h3".to_vec()],
        names: Names::new(&[]),
        ech: None,
        groups: &GROUPS,
        keylog: None,
    }
    .build()
    .expect_err("a mismatched pair");
    assert!(
        format!("{error:#}")
            .contains("server.cert and server.key do not form a usable certificate/key pair"),
        "{error:#}"
    );
}

/// QUIC varint (RFC 9000 §16).
fn varint(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let first = *bytes.get(*at)?;
    let len = 1usize << (first >> 6);
    let raw = bytes.get(*at..*at + len)?;
    *at += len;
    let mut value = u64::from(raw[0] & 0x3f);
    for byte in &raw[1..] {
        value = value << 8 | u64::from(*byte);
    }
    Some(value)
}

/// One client Initial, decrypted: the CRYPTO ranges it carried.
fn crypto_ranges(datagram: &[u8], dcid_keys: &quinn_proto::crypto::Keys) -> Vec<(u64, Vec<u8>)> {
    let mut packet = datagram.to_vec();
    let mut at = 5;
    let dcid_len = usize::from(packet[at]);
    at += 1 + dcid_len;
    let scid_len = usize::from(packet[at]);
    at += 1 + scid_len;
    let token_len = usize::try_from(varint(&packet, &mut at).expect("token length")).expect("len");
    at += token_len;
    let length = usize::try_from(varint(&packet, &mut at).expect("length")).expect("len");
    let pn_offset = at;
    let end = pn_offset + length;
    dcid_keys
        .header
        .remote
        .decrypt(pn_offset, &mut packet[..end]);
    let pn_len = usize::from(packet[0] & 0x03) + 1;
    let mut pn = 0u64;
    for byte in &packet[pn_offset..pn_offset + pn_len] {
        pn = pn << 8 | u64::from(*byte);
    }
    let header = packet[..pn_offset + pn_len].to_vec();
    let mut payload = BytesMut::from(&packet[pn_offset + pn_len..end]);
    dcid_keys
        .packet
        .remote
        .decrypt(pn, &header, &mut payload)
        .expect("a client Initial opens under its DCID's keys");
    let mut out = Vec::new();
    let mut at = 0;
    while at < payload.len() {
        match payload[at] {
            0x00 | 0x01 => at += 1,
            0x06 => {
                at += 1;
                let offset = varint(&payload, &mut at).expect("offset");
                let len = usize::try_from(varint(&payload, &mut at).expect("len")).expect("len");
                out.push((offset, payload[at..at + len].to_vec()));
                at += len;
            }
            other => panic!("unexpected frame {other:#04x} in a first flight"),
        }
    }
    out
}

/// The first flight of a quinn client on rustls, read off the wire: the
/// datagram sizes, which datagram each CRYPTO range came in, and the
/// reassembled ClientHello.
async fn first_flight(
    crypto: rustls::ClientConfig,
) -> (Vec<usize>, Vec<(usize, u64, usize)>, Vec<u8>) {
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = sink.local_addr().expect("addr");
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("client endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic"),
    )));
    let connecting = endpoint.connect(addr, "localhost").expect("connect");
    let mut datagrams = Vec::new();
    let mut buf = vec![0u8; 65536];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(150);
    while let Ok(Ok((n, _))) = tokio::time::timeout_at(deadline, sink.recv_from(&mut buf)).await {
        datagrams.push(buf[..n].to_vec());
    }
    drop(connecting);
    endpoint.close(0u32.into(), b"");

    let first = &datagrams[0];
    let dcid_len = usize::from(first[5]);
    let dcid = &first[6..6 + dcid_len];
    let (client, server) = keys::initial_secrets(Version::V1, dcid);
    let keys = keys::keys(&server, &client);
    let mut sizes = Vec::new();
    let mut ranges = Vec::new();
    let mut hello = Vec::new();
    for (index, datagram) in datagrams.iter().enumerate() {
        sizes.push(datagram.len());
        for (offset, data) in crypto_ranges(datagram, &keys) {
            ranges.push((index, offset, data.len()));
            let start = usize::try_from(offset).expect("offset");
            let end = start + data.len();
            if hello.len() < end {
                hello.resize(end, 0);
            }
            hello[start..end].copy_from_slice(&data);
        }
    }
    (sizes, ranges, hello)
}

/// With an X25519MLKEM768 key share, the outer ClientHello of an ECH client
/// does not fit one Initial packet, so whether ECH opens under our key cannot
/// be judged from the first packet: the ECH AEAD authenticates the whole outer
/// ClientHello (RFC 9849 §5.2). D115 rests on this; the 2026-11-20 spike
/// measured it, and this keeps it measured.
#[tokio::test]
async fn an_ech_client_hello_with_a_post_quantum_share_spans_two_initials() {
    let key = ech_key(1);
    for ech in [None, Some(enable(&key.config_list()))] {
        let with_ech = ech.is_some();
        let crypto = client_config(ech, pq_first(), Arc::new(Recorder::default()));
        let (sizes, ranges, hello) = first_flight(crypto).await;
        let body = hello::client_hello_body(&hello).expect("a whole ClientHello");
        assert_eq!(hello::ech_outer(body).is_some(), with_ech);
        assert!(
            sizes.len() >= 2 && sizes.iter().all(|size| *size >= 1200),
            "{sizes:?}"
        );
        let in_first: usize = ranges
            .iter()
            .filter(|(index, _, _)| *index == 0)
            .map(|(_, _, len)| *len)
            .sum();
        assert!(
            in_first < hello.len(),
            "the ClientHello ({} bytes) fit the first Initial ({in_first} CRYPTO bytes)",
            hello.len()
        );
    }
}
