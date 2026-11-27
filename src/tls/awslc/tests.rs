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
//! The ECH rows pin that AWS-LC never refuses a handshake for an ECH reason
//! (D115). The last test is on real sockets: a quinn client on rustls sends
//! its first flight to a bare UDP socket, which decrypts the Initial packets
//! and checks how the ClientHello falls across them.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_sys as sys;
use bytes::BytesMut;
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
use super::{
    Builder, EchKey, EchKeySet, GROUPS, HandshakeData, Names, OP_NO_TICKET, ProbeSession,
    ServerConfig, Session, Version, keys,
};
use crate::hello::{self, EXT_ECH};

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

fn ech_key(config_id: u8) -> Arc<EchKey> {
    Arc::new(EchKey::generate(PUBLIC_NAME, config_id, 32).expect("generate an ECH key"))
}

/// The key set of `key` alone.
fn alone(key: &Arc<EchKey>) -> Arc<EchKeySet> {
    Arc::new(EchKeySet::new(key.clone()))
}

/// The key set of `current` with `previous` beside it.
fn rotating(current: &Arc<EchKey>, previous: &Arc<EchKey>) -> Arc<EchKeySet> {
    Arc::new(
        EchKeySet::new(current.clone())
            .with_previous(previous.clone())
            .expect("two config_ids"),
    )
}

/// A server on `id`, with ECH under `ech` and the second gate's list `names`,
/// built as `server_config` builds one: with a key, the second ECH line on.
fn server(
    id: &Identity,
    ech: Option<&Arc<EchKey>>,
    groups: &[u16],
    names: &[&str],
) -> Arc<ServerConfig> {
    built(id, ech.map(alone), groups, names, ech.is_some(), false)
}

/// The same server with `require_ech` on.
fn requiring(id: &Identity, ech: &Arc<EchKey>) -> Arc<ServerConfig> {
    built(id, Some(alone(ech)), &GROUPS, &[], true, true)
}

/// A server whose second ECH line is off, which is libssl's own ECH behaviour
/// with nothing of this provider's in front of it.
///
/// What AWS-LC does with an ECH extension it cannot use: it never refuses, and
/// answers on the outer ClientHello with `retry_configs`, which the socket
/// gate and the second line exist to keep from anybody without the key.
fn libssl_alone(
    id: &Identity,
    ech: &Arc<EchKey>,
    groups: &[u16],
    names: &[&str],
) -> Arc<ServerConfig> {
    built(id, Some(alone(ech)), groups, names, false, false)
}

fn built(
    id: &Identity,
    ech: Option<Arc<EchKeySet>>,
    groups: &[u16],
    names: &[&str],
    refuse_unaccepted_ech: bool,
    require_ech: bool,
) -> Arc<ServerConfig> {
    Arc::new(
        Builder {
            names: Names::new(&names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>()),
            refuse_unaccepted_ech,
            require_ech,
            groups,
            ..Builder::new(vec![id.cert.clone()], Zeroizing::new(id.key.clone()), ech)
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
    /// That extension's body, which is the ECHConfigList the server sent.
    retry_configs: Option<Vec<u8>>,
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

/// The body of the extension of type `wanted` in an extension block
/// `<0..2^16-1>` at `block`.
fn extension_body(block: &[u8], wanted: u16) -> Option<&[u8]> {
    let mut at = 2;
    while at + 4 <= block.len() {
        let kind = u16::from_be_bytes([block[at], block[at + 1]]);
        let len = usize::from(u16::from_be_bytes([block[at + 2], block[at + 3]]));
        let body = block.get(at + 4..at + 4 + len)?;
        if kind == wanted {
            return Some(body);
        }
        at += 4 + len;
    }
    None
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

/// One in-memory handshake: what it showed, the server session after it, and
/// the client's next 1-RTT secrets, for the tests that go on from there.
struct Ran {
    outcome: Outcome,
    session: Session,
    client_next: Option<rustls::quic::Secrets>,
}

/// Runs one handshake in memory. `tamper` may rewrite each ClientHello before
/// the server reads it.
fn handshake(
    server: Arc<ServerConfig>,
    client: Arc<rustls::ClientConfig>,
    recorder: &Recorder,
    tamper: &dyn Fn(&mut [u8]),
) -> Ran {
    let mut out = Outcome::default();
    // `ProbeSession::write` takes what the server has to send as quinn does.
    let mut session =
        ProbeSession(Session::new(server, Version::V1, &PARAMS).expect("start a session"));
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
    let mut client_next = None;
    let mut to_server: std::collections::VecDeque<(usize, Vec<u8>)> = Default::default();
    let mut to_client: std::collections::VecDeque<(usize, Vec<u8>)> = Default::default();

    fn drain_client(
        rustls: &mut rustls::quic::ClientConnection,
        level: &mut usize,
        next: &mut Option<rustls::quic::Secrets>,
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
                Some(KeyChange::OneRtt { next: secrets, .. }) => {
                    *level = 3;
                    *next = Some(secrets);
                }
                None if empty => return,
                None => {}
            }
        }
    }

    drain_client(
        &mut rustls,
        &mut client_level,
        &mut client_next,
        &mut to_server,
    );
    for _step in 0..64 {
        if let Some((level, mut buf)) = to_server.pop_front() {
            if level == 0 {
                tamper(&mut buf);
                out.client_hellos.push(buf.clone());
            }
            let result = session.0.read_handshake(&buf);
            if out.handshake_data.is_none()
                && let Some(data) = session.0.handshake_data()
            {
                let data = data
                    .downcast::<HandshakeData>()
                    .expect("the provider's type");
                out.handshake_data = Some((data.protocol, data.server_name));
            }
            if let Err(error) = result {
                out.server_error = Some(format!("{error}"));
                break;
            }
            for (level, buf) in session.write() {
                to_client.push_back((usize::from(level), buf));
            }
            continue;
        }
        if let Some((level, buf)) = to_client.pop_front() {
            for (kind, body) in messages(&buf) {
                out.server_messages.push((level, kind, body.len()));
                if kind == SERVER_HELLO && body.get(2..34) == Some(&HRR_RANDOM[..]) {
                    out.hello_retry = true;
                }
                if kind == ENCRYPTED_EXTENSIONS
                    && let Some(list) = extension_body(body, EXT_ECH)
                {
                    out.retry_configs_sent = true;
                    out.retry_configs = Some(list.to_vec());
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
            drain_client(
                &mut rustls,
                &mut client_level,
                &mut client_next,
                &mut to_server,
            );
            continue;
        }
        break;
    }

    let session = session.0;
    out.ech_accepted = session.ech_accepted();
    out.server_done = !session.is_handshaking();
    out.client_done = !rustls.is_handshaking();
    out.verified = recorder.seen.lock().expect("recorder lock").clone();
    // SAFETY: the session's SSL is valid; the getter only reads.
    out.group = unsafe { sys::SSL_get_group_id(session.ssl.as_ptr()) };
    Ran {
        outcome: out,
        session,
        client_next,
    }
}

/// One handshake against `server` from a fresh client with `ech`, `groups` and
/// ALPN `h3`.
fn run(
    server: Arc<ServerConfig>,
    ech: Option<EchMode>,
    groups: Vec<&'static dyn SupportedKxGroup>,
) -> Outcome {
    run_tampered(server, ech, groups, &untouched)
}

/// [`run`], with `tamper` rewriting each ClientHello before the server reads it.
fn run_tampered(
    server: Arc<ServerConfig>,
    ech: Option<EchMode>,
    groups: Vec<&'static dyn SupportedKxGroup>,
    tamper: &dyn Fn(&mut [u8]),
) -> Outcome {
    let recorder = Arc::new(Recorder::default());
    let client = client_config(ech, groups, recorder.clone());
    handshake(server, Arc::new(client), &recorder, tamper).outcome
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
    .outcome
}

/// (a) The right ECHConfig: accepted, the inner name, our certificate, no
/// retry_configs, and X25519MLKEM768.
#[test]
fn ech_with_the_right_config_is_accepted() {
    let id = identity();
    let key = ech_key(1);
    let outcome = run(
        server(&id, Some(&key), &GROUPS, &[]),
        Some(enable(&key.config_list())),
        pq_first(),
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
    let outcome = run(server(&id, Some(&key), &GROUPS, &[]), None, pq_first());
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
    let outcome = run(
        libssl_alone(&id, &key, &GROUPS, &[]),
        Some(grease()),
        pq_first(),
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
    let outcome = run(
        libssl_alone(&id, &key, &GROUPS, &[]),
        Some(enable(&other.config_list())),
        pq_first(),
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
    let outcome = run_tampered(
        libssl_alone(&id, &key, &GROUPS, &[]),
        Some(enable(&key.config_list())),
        pq_first(),
        &corrupt_ech_payload,
    );
    assert!(
        !outcome.ech_accepted && outcome.certificate_sent && outcome.retry_configs_sent,
        "{outcome:?}"
    );
}

/// The outer ClientHello body and its ECH extension, from the first ClientHello
/// an in-memory handshake carried.
fn outer_hello(outcome: &Outcome) -> (Vec<u8>, hello::EchOuter) {
    let body = hello::client_hello_body(&outcome.client_hellos[0])
        .expect("a whole ClientHello")
        .to_vec();
    let ech = hello::ech_outer(&body).expect("an outer ECH extension");
    (body, ech)
}

/// `EchKey::opens` says yes to exactly the ClientHellos libssl accepts ECH on.
///
/// A ClientHello that libssl took the inner ClientHello from is one the
/// function opens, and the same ClientHello with any one byte changed is one it
/// does not: a byte of the payload fails the AEAD tag, a byte of `enc` changes
/// the HPKE shared secret, the config_id or the suite fails the checks ahead of
/// HPKE, a length field changes what the extension is, and every other byte is
/// part of the associated data. GREASE and an ECHConfig the server does not
/// hold are not opened either.
#[test]
fn ech_opens_exactly_when_libssl_accepts_it() {
    let id = identity();
    let key = ech_key(1);
    let other = ech_key(2);
    let outcome = run(
        server(&id, Some(&key), &GROUPS, &[]),
        Some(enable(&key.config_list())),
        pq_first(),
    );
    assert!(outcome.ech_accepted, "libssl accepted ECH: {outcome:?}");
    let (body, ech) = outer_hello(&outcome);
    assert!(
        key.opens(&body, &ech),
        "the ClientHello libssl accepted opens"
    );
    assert!(
        !ech_key(1).opens(&body, &ech),
        "another key under the same config_id does not open it"
    );

    for at in 0..body.len() {
        let mut changed = body.clone();
        changed[at] ^= 0x01;
        // A change to a length field can move the extension or make it
        // unreadable; either way the ClientHello does not open.
        let opens = hello::ech_outer(&changed).is_some_and(|ech| key.opens(&changed, &ech));
        assert!(
            !opens,
            "byte {at} of {} changed and it still opens",
            body.len()
        );
    }

    // GREASE: an extension under a key nobody holds.
    let outcome = run(
        server(&id, Some(&key), &GROUPS, &[]),
        Some(grease()),
        pq_first(),
    );
    assert!(!outcome.ech_accepted, "{outcome:?}");
    let (body, ech) = outer_hello(&outcome);
    assert!(!key.opens(&body, &ech), "GREASE does not open");

    // A list for another key, which libssl does not accept either.
    let outcome = run(
        server(&id, Some(&key), &GROUPS, &[]),
        Some(enable(&other.config_list())),
        pq_first(),
    );
    assert!(!outcome.ech_accepted, "{outcome:?}");
    let (body, ech) = outer_hello(&outcome);
    assert!(!key.opens(&body, &ech), "another key's ECH does not open");
    assert!(other.opens(&body, &ech), "but it opens under its own key");
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
    let outcome = run(
        server(&id, Some(&key), &[0x11ec, 0x0017], &[]),
        Some(enable(&key.config_list())),
        x25519_first(),
    );
    assert!(outcome.hello_retry);
    assert_eq!(outcome.client_hellos.len(), 2);
    assert!(
        outcome.ech_accepted && outcome.server_done && outcome.client_done,
        "{outcome:?}"
    );
}

/// One client of the test below: what it is, its ECH mode, its groups, and
/// the groups the server offers.
type Case = (
    &'static str,
    Option<EchMode>,
    Vec<&'static dyn SupportedKxGroup>,
    &'static [u16],
);

/// The second ECH line: with a key configured, a ClientHello whose ECH
/// extension libssl did not accept is refused with `handshake_failure(40)`
/// before the server writes anything, so neither EncryptedExtensions nor its
/// `retry_configs` leave the server. GREASE, another key, another key under
/// our config_id, a damaged payload, and the same across a HelloRetryRequest
/// are each refused; the right list and no ECH extension at all are not.
///
/// The socket gate drops every one of these before libssl sees it, so this is
/// the line that holds if the gate is wrong.
#[test]
fn the_second_ech_line_refuses_ech_it_did_not_accept_before_anything_is_sent() {
    let id = identity();
    let key = ech_key(1);
    const HRR_GROUPS: [u16; 2] = [0x11ec, 0x0017];
    let cases: Vec<Case> = vec![
        ("GREASE", Some(grease()), pq_first(), &GROUPS),
        (
            "another key",
            Some(enable(&ech_key(2).config_list())),
            pq_first(),
            &GROUPS,
        ),
        (
            "another key under our config_id",
            Some(enable(&ech_key(1).config_list())),
            pq_first(),
            &GROUPS,
        ),
        (
            "another key across a HelloRetryRequest",
            Some(enable(&ech_key(2).config_list())),
            x25519_first(),
            &HRR_GROUPS,
        ),
    ];
    for (what, ech, groups, server_groups) in cases {
        let outcome = run(server(&id, Some(&key), server_groups, &[]), ech, groups);
        refused_before_anything(&outcome, what);
    }

    // A damaged payload under the right key.
    let outcome = run_tampered(
        server(&id, Some(&key), &GROUPS, &[]),
        Some(enable(&key.config_list())),
        pq_first(),
        &corrupt_ech_payload,
    );
    refused_before_anything(&outcome, "a damaged payload");

    // The right list, and no ECH extension at all, are not refused.
    for (what, ech) in [
        ("the right list", Some(enable(&key.config_list()))),
        ("no ECH", None),
    ] {
        let outcome = run(server(&id, Some(&key), &GROUPS, &[]), ech, pq_first());
        assert!(
            outcome.server_done && outcome.client_done,
            "{what}: {outcome:?}"
        );
        assert!(!outcome.retry_configs_sent, "{what}");
    }
}

/// With a previous key beside the current one, libssl accepts ECH under
/// either, and the retry configs it sends to a ClientHello that neither key
/// opens are the current key's ECHConfigList and nothing else, because the
/// previous key is added with `is_retry_config = 0`.
///
/// The last row runs libssl with the second ECH line off, which is the only
/// way to see the retry configs: with it on, that ClientHello is refused
/// before anything is sent.
#[test]
fn a_previous_key_is_accepted_and_is_never_sent_as_a_retry_config() {
    let id = identity();
    let previous = ech_key(1);
    let current = ech_key(2);
    let keys = rotating(&current, &previous);
    for (what, key) in [
        ("the current key", &current),
        ("the previous key", &previous),
    ] {
        let outcome = run(
            built(&id, Some(keys.clone()), &GROUPS, &[], true, false),
            Some(enable(&key.config_list())),
            pq_first(),
        );
        assert!(
            outcome.ech_accepted && outcome.server_done && outcome.client_done,
            "{what}: {outcome:?}"
        );
        assert!(!outcome.retry_configs_sent, "{what}");
    }

    let outcome = run(
        built(&id, Some(keys), &GROUPS, &[], false, false),
        Some(enable(&ech_key(3).config_list())),
        pq_first(),
    );
    assert!(!outcome.ech_accepted, "{outcome:?}");
    assert_eq!(
        outcome.retry_configs.as_deref(),
        Some(&current.config_list()[..]),
        "the retry configs are the current key's list alone"
    );
}

/// Under `require_ech` the second line also refuses a ClientHello with no ECH
/// extension, and GREASE, before anything is sent; the right list completes.
#[test]
fn under_require_ech_the_second_line_refuses_a_client_hello_without_ech() {
    let id = identity();
    let key = ech_key(1);
    for (what, ech) in [("no ECH", None), ("GREASE", Some(grease()))] {
        let outcome = run(requiring(&id, &key), ech, pq_first());
        refused_before_anything(&outcome, what);
    }
    let outcome = run(
        requiring(&id, &key),
        Some(enable(&key.config_list())),
        pq_first(),
    );
    assert!(
        outcome.ech_accepted && outcome.server_done && outcome.client_done,
        "{outcome:?}"
    );
}

/// Asserts that the server refused with `handshake_failure(40)` and wrote no
/// handshake message at all: no ServerHello, so no EncryptedExtensions and no
/// `retry_configs`.
#[track_caller]
fn refused_before_anything(outcome: &Outcome, what: &str) {
    assert!(!outcome.ech_accepted, "{what}: {outcome:?}");
    assert!(
        outcome.server_messages.is_empty(),
        "{what}: the server wrote {:?}",
        outcome.server_messages
    );
    assert!(
        !outcome.retry_configs_sent && !outcome.certificate_sent,
        "{what}"
    );
    assert!(
        outcome
            .server_error
            .as_deref()
            .is_some_and(|e| e.contains("error 40")),
        "{what}: {outcome:?}"
    );
}

/// The client shape `it_gate_shapes::a_hello_retry_request_under_ech_completes_through_the_hold`
/// uses draws a HelloRetryRequest from the production group list: it offers
/// SecP256r1MLKEM768 first, which this server does not accept, and X25519
/// second, for which it sent no share.
#[test]
fn a_client_offering_secp256r1mlkem768_first_draws_a_hello_retry_request() {
    let id = identity();
    let key = ech_key(1);
    let outcome = run(
        server(&id, Some(&key), &GROUPS, &[]),
        Some(enable(&key.config_list())),
        vec![kx_group::SECP256R1MLKEM768, kx_group::X25519],
    );
    assert!(outcome.hello_retry, "{outcome:?}");
    assert_eq!(outcome.group, 0x001d, "X25519 after the retry");
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
    let outcome = run(
        libssl_alone(&id, &key, &[0x11ec, 0x0017], &[]),
        Some(enable(&other.config_list())),
        x25519_first(),
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
    let gated = libssl_alone(&id, &key, &GROUPS, &["localhost"]);

    // Accepted: inner `localhost` is judged, although the outer name is the
    // public name, which is not on the list.
    let outcome = run(gated.clone(), Some(enable(&key.config_list())), pq_first());
    assert!(outcome.ech_accepted && outcome.server_done, "{outcome:?}");

    // GREASE keeps the real name in the outer ClientHello, which is on the
    // list.
    let outcome = run(gated.clone(), Some(grease()), pq_first());
    assert!(outcome.server_done, "{outcome:?}");

    // Another key: the outer ClientHello carries the public name, which is off
    // the list, so the handshake is refused before any certificate.
    let outcome = run(gated, Some(enable(&other.config_list())), pq_first());
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
    let outcome = run(
        server(&id, None, &GROUPS, &["other.example"]),
        None,
        pq_first(),
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

    let outcome = run_tampered(
        server(&id, None, &GROUPS, &[]),
        None,
        pq_first(),
        &sni_byte(b'\n'),
    );
    let (alpn, name) = outcome.handshake_data.expect("the ClientHello was read");
    assert_eq!(alpn.as_deref(), Some(&b"h3"[..]));
    assert_eq!(name, None, "a newline must never reach the log line");

    // `lxcalhost` is a DNS name, so the same rewrite with a letter is read.
    let outcome = run_tampered(
        server(&id, None, &GROUPS, &[]),
        None,
        pq_first(),
        &sni_byte(b'x'),
    );
    assert_eq!(
        outcome.handshake_data.and_then(|(_, name)| name).as_deref(),
        Some("lxcalhost")
    );

    // With the gate on, no name is not a name on the list.
    let outcome = run_tampered(
        server(&id, None, &GROUPS, &["localhost", "l\ncalhost"]),
        None,
        pq_first(),
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

    let first = handshake(server.clone(), client.clone(), &recorder, &untouched).outcome;
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
    let second = handshake(server, client, &recorder, &untouched).outcome;
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

/// Key update through the trait: in each of three generations, a packet
/// sealed by the provider is opened by rustls, and one sealed by rustls is
/// opened by the provider.
#[test]
fn next_1rtt_keys_follow_quic_ku() {
    let id = identity();
    let config = server(&id, None, &GROUPS, &[]);
    let recorder = Arc::new(Recorder::default());
    let client = Arc::new(client_config(None, pq_first(), recorder.clone()));
    let Ran {
        outcome,
        mut session,
        client_next,
    } = handshake(config, client, &recorder, &untouched);
    // The server holds its 1-RTT keys once its handshake is done.
    assert!(outcome.server_done, "{outcome:?}");
    // libssl freed the handshake configuration when the handshake completed,
    // and the calls made after it still work.
    // SAFETY: the session's SSL is valid. With a length of 0 the call copies
    // nothing; it returns 0 only when the SSL holds no configuration.
    let shed =
        unsafe { sys::SSL_set_session_id_context(session.ssl.as_ptr(), [0u8; 0].as_ptr(), 0) } == 0;
    assert!(shed, "the handshake configuration is still held");
    session
        .export_keying_material(&mut [0u8; 32], b"EXPORTER-volto-test", b"")
        .expect("the exporter works after the handshake");
    assert!(session.handshake_data().is_some());
    assert!(session.transport_parameters().expect("readable").is_some());
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

        // The other direction: sealed by rustls, opened by the provider.
        let header = [0x40, 4, 5, 6];
        let mut body = BytesMut::from(&[0xcc, 0xdd][..]);
        let tag = rustls::quic::PacketKey::encrypt_in_place(
            client_keys.local.as_ref(),
            generation,
            &header,
            &mut body,
        )
        .expect("the client seals");
        body.extend_from_slice(tag.as_ref());
        server_keys
            .remote
            .decrypt(generation, &header, &mut body)
            .unwrap_or_else(|_| panic!("the server opens generation {generation}"));
        assert_eq!(&body[..], [0xcc, 0xdd]);
    }
}

/// A private key in `der` written as one PEM block and read back through
/// `tls::load_key`, the path `server.key` takes.
fn through_load_key(label: &str, der: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut text = String::new();
    pem_block(&mut text, label, der);
    let dir = super::super::tests::scratch();
    let path = dir.join("server.key");
    std::fs::write(&path, text).expect("write the key");
    let key = super::super::load_key(&path).expect("load_key reads it");
    std::fs::remove_dir_all(&dir).expect("clean up");
    key
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
        let outcome = run(server(&id, None, &GROUPS, &[]), None, pq_first());
        assert!(
            outcome.server_done && outcome.client_done,
            "{what}: {outcome:?}"
        );
        assert_eq!(outcome.verified[0].1, id.cert, "{what}");
    }
}

/// An X.509 version 1 certificate for `localhost` (no extensions, so no
/// subjectAltName either) and its P-256 key, made once with LibreSSL 3.3.6:
/// `openssl x509 -req -sha256 -in req.csr -signkey key.pem -days 36500`.
/// webpki refuses a version 1 certificate (`UnsupportedCertVersion`) and
/// AWS-LC's `d2i_X509` reads it. The key protects nothing.
const V1_CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIIBGjCBwAIJALKFNYcyBwe7MAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCWxvY2Fs
aG9zdDAgFw0yNjExMjAwODM5NDJaGA8yMTI2MTAyNzA4Mzk0MlowFDESMBAGA1UE
AwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd7BPf1SU7GG7
dAQRZRjFZsj/C///uZeAv/6dllF2WSOg0jx3a541t309Kry8QDHHGyjrPD5rYAMI
z29KVavRaDAKBggqhkjOPQQDAgNJADBGAiEApJ4xsVnqSsULDQU0wPoviHYfBitq
6gQhlG7+L/OETTICIQDgqTmvSvGJzQnKePJ8SYZzY3x0uWrIqAE2NcuIKjbeeQ==
-----END CERTIFICATE-----
";
const V1_KEY: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7FpxDT+FSsvFUCih
yShn4Z4G7F1ocW9wTR/1r9ZRugOhRANCAAR3sE9/VJTsYbt0BBFlGMVmyP8L//+5
l4C//p2WUXZZI6DSPHdrnjW3fT0qvLxAMccbKOs8PmtgAwjPb0pVq9Fo
-----END PRIVATE KEY-----
";

/// A leaf webpki cannot parse is refused at build, in the wording the rustls
/// server used: that server parsed the leaf with webpki in `with_single_cert`,
/// and without the refusal the certificate binds while the `expected_sni`
/// coverage warning, which parses it the same way, says nothing. The cause
/// after that wording names the leaf and webpki's reason. rustls is the
/// oracle here, so the refusal is judged by the parse a rustls client runs.
#[test]
fn a_leaf_webpki_cannot_parse_is_refused_at_build() {
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::pki_types::pem::PemObject as _;
    let cert = CertificateDer::from_pem_slice(V1_CERT.as_bytes()).expect("the certificate");
    let key = PrivatePkcs8KeyDer::from_pem_slice(V1_KEY.as_bytes()).expect("the key");
    assert!(
        rustls::server::ParsedCertificate::try_from(&cert).is_err(),
        "webpki refuses a version 1 certificate"
    );
    let x509 = ffi::x509_from_der(&cert).expect("AWS-LC reads it");
    drop(x509);
    let error = Builder::new(
        vec![cert.to_vec()],
        Zeroizing::new(key.secret_pkcs8_der().to_vec()),
        None,
    )
    .build()
    .expect_err("a leaf webpki cannot parse");
    assert_eq!(
        format!("{error:#}"),
        "server.cert and server.key do not form a usable certificate/key pair: \
         invalid leaf certificate: UnsupportedCertVersion"
    );
}

/// A key that is not the certificate's is refused at build, in the operator's
/// wording. A key of the leaf's type is refused by `SSL_CTX_use_PrivateKey`;
/// a key of another type goes to another certificate slot and is refused by
/// `SSL_CTX_check_private_key`, so that call is not redundant.
#[test]
fn a_key_that_does_not_match_the_certificate_is_refused_by_that_name() {
    let id = identity();
    let ed25519 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("Ed25519");
    let rsa = rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
        .expect("RSA");
    for (what, key, (call, reason)) in [
        (
            "another P-256 key",
            identity().key,
            ("SSL_CTX_use_PrivateKey failed", "KEY_VALUES_MISMATCH"),
        ),
        (
            "an Ed25519 key",
            ed25519.serialize_der(),
            (
                "SSL_CTX_check_private_key failed",
                "NO_CERTIFICATE_ASSIGNED",
            ),
        ),
        (
            "an RSA key",
            rsa.serialize_der(),
            (
                "SSL_CTX_check_private_key failed",
                "NO_CERTIFICATE_ASSIGNED",
            ),
        ),
    ] {
        let error = Builder::new(vec![id.cert.clone()], Zeroizing::new(key), None)
            .build()
            .expect_err(what);
        let message = format!("{error:#}");
        assert!(
            message.starts_with(super::UNUSABLE_PAIR)
                && message.contains(call)
                && message.contains(reason),
            "{what}: {message}"
        );
    }
}

/// `Builder::new`'s defaults, which `server_config` and `probe_server_config`
/// build on: with an ECH key the second ECH line is on, so GREASE is refused
/// before anything is sent, and ALPN `h3` completes a handshake.
#[test]
fn the_builder_defaults_keep_the_second_ech_line_on() {
    let id = identity();
    let key = ech_key(1);
    let config = super::probe_server_config(&id.cert, &id.key, Some(&key)).expect("a server");
    refused_before_anything(&run(config.clone(), Some(grease()), pq_first()), "GREASE");
    let outcome = run(config, Some(enable(&key.config_list())), pq_first());
    assert!(
        outcome.ech_accepted && outcome.server_done && outcome.client_done,
        "{outcome:?}"
    );
}

/// A probe configuration built with an ECH key reports the key libssl holds.
#[test]
fn a_probe_configuration_reports_its_ech_key() {
    let id = identity();
    let key = ech_key(7);
    let config = super::probe_server_config(&id.cert, &id.key, Some(&key)).expect("a server");
    assert!(
        config
            .ech()
            .is_some_and(|held| Arc::ptr_eq(held.current(), &key))
    );
    assert!(config.ech().is_some_and(|held| held.previous().is_none()));
}

/// The first ClientHello of a plain client with X25519MLKEM768 first.
fn client_hello() -> Vec<u8> {
    let client = Arc::new(client_config(
        None,
        pq_first(),
        Arc::new(Recorder::default()),
    ));
    let mut rustls = rustls::quic::ClientConnection::new(
        client,
        rustls::quic::Version::V1,
        ServerName::try_from("localhost").expect("a name"),
        PARAMS.to_vec(),
    )
    .expect("start a client");
    let mut hello = Vec::new();
    rustls.write_hs(&mut hello);
    hello
}

/// The server's flight is handed to quinn's empty buffer rather than copied
/// into it, so the session's queues keep no allocation once quinn has taken
/// the bytes.
#[test]
fn the_server_flight_is_handed_over_without_a_copy() {
    let id = identity();
    let mut session =
        Session::new(server(&id, None, &GROUPS, &[]), Version::V1, &PARAMS).expect("a session");
    session
        .read_handshake(&client_hello())
        .expect("the server reads the ClientHello");
    let mut taken = 0;
    loop {
        let mut buf = Vec::new();
        let keys = session.write_handshake(&mut buf);
        taken += buf.len();
        if keys.is_none() && buf.is_empty() {
            break;
        }
    }
    assert!(taken > 0, "the server wrote its flight");
    let capacities: Vec<usize> = session.lock().out.iter().map(Vec::capacity).collect();
    assert_eq!(capacities, [0; 4]);
}

/// The handshake data is reported ready by the read that completes the first
/// ClientHello, and by no read before it.
#[test]
fn the_handshake_data_is_ready_after_the_first_client_hello() {
    let id = identity();
    let mut session =
        Session::new(server(&id, None, &GROUPS, &[]), Version::V1, &PARAMS).expect("a session");
    let hello = client_hello();
    let (head, tail) = hello.split_at(hello.len() / 2);
    assert_eq!(session.read_handshake(head).ok(), Some(false));
    assert!(session.handshake_data().is_none());
    assert_eq!(session.read_handshake(tail).ok(), Some(true));
    assert!(session.handshake_data().is_some());
}

/// The outer ClientHello is copied only when the debug line that reports it
/// is enabled, which it is not in production.
#[test]
fn the_outer_client_hello_is_kept_only_for_the_debug_line() {
    let id = identity();
    let config = server(&id, None, &GROUPS, &[]);
    let hello = client_hello();
    let half = &hello[..hello.len() / 2];
    let held = || {
        let mut session = Session::new(config.clone(), Version::V1, &PARAMS).expect("a session");
        session
            .read_handshake(half)
            .expect("half a ClientHello is read");
        session.initial.len()
    };
    let off = tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), held);
    let debug = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(std::io::sink)
        .finish();
    let on = tracing::subscriber::with_default(debug, held);
    assert_eq!((off, on), (0, half.len()));
}

thread_local! {
    /// Makes `session_index` see what `SSL_get_ex_new_index` returns when its
    /// allocation fails, on this test's thread only.
    pub(super) static EX_INDEX_FAILS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A failed ex_data index is an error from `Session::new` and from
/// `Builder::build`, and never reaches `SSL_set_ex_data`, which aborts the
/// process on a negative index (`CRYPTO_set_ex_data`). The next call, with the
/// allocation back, succeeds.
#[test]
fn a_failed_ex_data_index_is_an_error_and_not_an_abort() {
    let id = identity();
    let config = server(&id, None, &GROUPS, &[]);
    EX_INDEX_FAILS.set(true);
    let session = Session::new(config.clone(), Version::V1, &PARAMS).err();
    let build = Builder::new(vec![id.cert.clone()], Zeroizing::new(id.key.clone()), None)
        .build()
        .err();
    EX_INDEX_FAILS.set(false);
    for (what, error) in [("Session::new", session), ("Builder::build", build)] {
        let error = error.unwrap_or_else(|| panic!("{what} succeeded without an index"));
        assert!(
            format!("{error:#}").contains("SSL_get_ex_new_index failed"),
            "{what}: {error:#}"
        );
    }
    assert!(Session::new(config, Version::V1, &PARAMS).is_ok());
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

/// The first flight of a quinn client on rustls, read off the wire up to the
/// datagram that completes its ClientHello: the datagram sizes, which
/// datagram each CRYPTO range came in, and the reassembled ClientHello.
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
    let mut buf = vec![0u8; 65536];
    let mut keys = None;
    let mut sizes = Vec::new();
    let mut ranges = Vec::new();
    let mut hello = Vec::new();
    // Which bytes of `hello` a CRYPTO range filled, so a gap is not read as
    // part of the ClientHello.
    let mut filled = Vec::new();
    // Until the CRYPTO bytes hold a whole ClientHello. The ceiling is far
    // above any first flight on loopback and only fails the test.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while hello::client_hello_body(&hello).is_none() || filled.contains(&false) {
        let (n, _) = tokio::time::timeout_at(deadline, sink.recv_from(&mut buf))
            .await
            .expect("the client's ClientHello was not whole within 5 s")
            .expect("receive a datagram");
        let datagram = &buf[..n];
        let keys = keys.get_or_insert_with(|| {
            let dcid = &datagram[6..6 + usize::from(datagram[5])];
            let (client, server) = keys::initial_secrets(Version::V1, dcid);
            keys::keys(&server, &client)
        });
        for (offset, data) in crypto_ranges(datagram, keys) {
            ranges.push((sizes.len(), offset, data.len()));
            let start = usize::try_from(offset).expect("offset");
            let end = start + data.len();
            if hello.len() < end {
                hello.resize(end, 0);
                filled.resize(end, false);
            }
            hello[start..end].copy_from_slice(&data);
            filled[start..end].fill(true);
        }
        sizes.push(n);
    }
    drop(connecting);
    endpoint.close(0u32.into(), b"");
    (sizes, ranges, hello)
}

/// With an X25519MLKEM768 key share, the outer ClientHello of an ECH client
/// does not fit one Initial packet, so whether ECH opens under our key cannot
/// be judged from the first packet: the ECH AEAD authenticates the whole outer
/// ClientHello (RFC 9849 §5.2). D115 rests on this.
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
