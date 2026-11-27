//! Shapes the SNI gate has to get right (D106).
//!
//! `it_sni_gate` asks whether the gate admits the right *names*, with real
//! clients. This binary spells Initial packets by hand and asks three questions
//! around that, all through the [`judgement`] seam the socket path itself calls,
//! which opens each packet with the server's own Initial key code.
//! [`nameless_crypto`], rustls's Initial key code, only builds the packets.
//!
//! **Is a first flight judged by its name and by nothing else?** A client has a
//! great deal of freedom in how its first packet is laid out, and none of it may
//! move the verdict; and a later Initial of an admitted handshake, keyed by the
//! first packet rather than by the connection ID it now carries, must not be
//! mistaken for a stranger — the defect of 2026-09-03, when refusing those cost
//! every handshake a probe timeout.
//!
//! **Does a first flight from a real stack read the way the builders say it
//! does?** A parser can agree with its own builder while disagreeing with the
//! wire. So a real quinn client's first datagram is captured off a socket that
//! never answers and judged, and a real aioquic first flight — a different stack
//! again, and the one whose habit of coalescing packets found that defect — is
//! pinned here as bytes.
//!
//! **What still answers a stranger with the gate on?** The gate judges a
//! datagram's first packet, and one thing it refuses is decided without a name:
//! since only a first Initial is keyed by the connection ID written in it, a
//! Destination Connection ID shorter than the eight bytes RFC 9000 §7.2
//! requires, which quinn answers with a CONNECTION_CLOSE before a single frame
//! is read. (The other nameless refusal, a version in the long header, is probed
//! in `it_sni_gate`.) Everything else it passes reaches quinn, and an Initial
//! carrying an ack-eliciting frame draws an acknowledgement whether or not it
//! names anybody. The probes below send each of those shapes at a server with
//! the gate on and record what comes back; the ones still answered are
//! `#[ignore]`d rather than deleted, so the shape and its evidence stay in the
//! tree. Every probe is paired with the same datagram sent at a server with the
//! gate *off*, which is what proves the probe is well formed enough to be
//! answered at all: a probe that draws nothing either way has tested nothing.
//!
//! The seed corpus of `fuzz/fuzz_targets/gate.rs` is written from here too,
//! with the same builders, so that a verdict a seed was built for is a red test
//! rather than a corpus that quietly stops covering anything.

mod common;

use std::assert_matches;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use common::{
    ALLOW_PRIVATE, GATE_LOCALHOST, Leg, Offer, Relayed, SharedBuffer, TIMEOUT, TempDir, TestServer,
    bulk_alpn, client_endpoint, endpoint_from, is_version_negotiation, nameless_crypto, roots_of,
    rustls_client, udp_answer, udp_answers, udp_relay,
};
use quinn::ConnectionId;
use rustls::crypto::SupportedKxGroup;
use rustls::crypto::aws_lc_rs::kx_group;
use volto::gate::{
    Dropped, FirstFlight, HOLD_FLIGHT_BYTES, HOLD_FLIGHTS, HOLD_HELLO_BYTES, HOLD_LIFETIME,
    HOLD_TOTAL_BYTES, HoldInput, HoldStep, Names, Policy, REPLAY_ENTRIES, Refusal, Screened,
    Screening, Verdict, first_flight, hold_input_key, hold_input_previous_key, judgement,
    sealed_initial,
};
use volto::tls::{EchKey, EchKeySet};
use volto::varint::{peek_varint, put_varint};

/// How long a server is given to prove it is not answering.
///
/// Long enough that a loaded machine cannot pass a probe by being slow, short
/// enough that the probes here stay well inside the harness timeout.
const PATIENCE: Duration = Duration::from_secs(2);

/// The QUIC version this server speaks.
const QUIC_V1: u32 = 0x0000_0001;

/// Header Form bit: set on a long header (RFC 9000 §17).
const LONG_HEADER_FORM: u8 = 0x80;

/// The smallest UDP payload that may carry an Initial packet (RFC 9000 §14.1).
const MIN_INITIAL_DATAGRAM: usize = 1200;

/// The longest connection ID QUIC version 1 allows (RFC 9000 §17.2).
const MAX_CONNECTION_ID: usize = 20;

/// The shortest Destination Connection ID a client's first Initial may carry
/// (RFC 9000 §7.2).
const MIN_CLIENT_CONNECTION_ID: usize = 8;

/// The TLS `client_hello` handshake message type (RFC 8446 §4).
const CLIENT_HELLO: u8 = 1;

/// The TLS `server_name` extension type (RFC 6066 §3).
const SERVER_NAME_EXTENSION: u16 = 0;

/// The `host_name` NameType of a `server_name` entry (RFC 6066 §3).
const HOST_NAME: u8 = 0;

/// The connection ID a client chooses for its first packet, and the one the
/// server answers with.
const CLIENT_CID: [u8; 8] = [0xaa; 8];
const SERVER_CID: [u8; 8] = [0xbb; 8];

/// A name the list holds, and one it does not.
const LISTED: &str = "listed.example";
const UNLISTED: &str = "other.example";

// ---------------------------------------------------------------------------
// Building an Initial packet by hand
// ---------------------------------------------------------------------------

/// A QUIC variable-length integer, in the shortest encoding that holds it.
fn varint(value: usize) -> Vec<u8> {
    let mut bytes = BytesMut::new();
    put_varint(
        &mut bytes,
        u64::try_from(value).expect("a length that fits a varint"),
    );
    bytes.to_vec()
}

/// A CRYPTO frame carrying `data` at `offset` in the handshake stream.
fn crypto_frame_at(offset: usize, data: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x06];
    frame.extend_from_slice(&varint(offset));
    frame.extend_from_slice(&varint(data.len()));
    frame.extend_from_slice(data);
    frame
}

/// A TLS extension of `kind` carrying `body`.
fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = kind.to_be_bytes().to_vec();
    bytes.extend_from_slice(
        &u16::try_from(body.len())
            .expect("a short extension")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(body);
    bytes
}

/// A `server_name` extension naming `host`.
fn sni_extension(host: &str) -> Vec<u8> {
    let host = host.as_bytes();
    let mut entry = vec![HOST_NAME];
    entry.extend_from_slice(
        &u16::try_from(host.len())
            .expect("a short name")
            .to_be_bytes(),
    );
    entry.extend_from_slice(host);

    let mut list = u16::try_from(entry.len())
        .expect("a short list")
        .to_be_bytes()
        .to_vec();
    list.extend_from_slice(&entry);
    extension(SERVER_NAME_EXTENSION, &list)
}

/// A ClientHello message with the fields a real client varies ahead of its
/// extensions: the middlebox-compatibility `legacy_session_id` Chrome sends 32
/// bytes of (RFC 8446 §4.1.2), and the cipher suites it offers.
fn client_hello_with(session_id: usize, ciphers: &[u16], extensions: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&[0x00; 32]); // random
    body.push(u8::try_from(session_id).expect("a session id of at most 255 bytes"));
    body.extend_from_slice(&vec![0x5a; session_id]);
    let suites: Vec<u8> = ciphers.iter().flat_map(|c| c.to_be_bytes()).collect();
    body.extend_from_slice(
        &u16::try_from(suites.len())
            .expect("a short suite list")
            .to_be_bytes(),
    );
    body.extend_from_slice(&suites);
    body.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods
    body.extend_from_slice(
        &u16::try_from(extensions.len())
            .expect("short extensions")
            .to_be_bytes(),
    );
    body.extend_from_slice(extensions);

    let mut message = vec![CLIENT_HELLO];
    let length = body.len();
    message.extend_from_slice(&[
        u8::try_from(length >> 16).expect("a short message"),
        u8::try_from((length >> 8) & 0xff).expect("a byte"),
        u8::try_from(length & 0xff).expect("a byte"),
    ]);
    message.extend_from_slice(&body);
    message
}

/// The plainest ClientHello: no session id, one cipher suite, `extensions`.
fn client_hello(extensions: &[u8]) -> Vec<u8> {
    client_hello_with(0, &[0x1301], extensions)
}

/// The plainest ClientHello naming `host`.
fn named_hello(host: &str) -> Vec<u8> {
    client_hello(&sni_extension(host))
}

/// The parts of an Initial header a legitimate client chooses for itself.
struct Shape {
    /// The Destination Connection ID.
    dcid: Vec<u8>,
    /// What keys the packet, if not `dcid`.
    ///
    /// `None` is a client's first packet, keyed by its own Destination
    /// Connection ID (RFC 9001 §5.2) — and still so after a Retry, since the
    /// keys are recomputed from the connection ID the Retry supplied. `Some` is
    /// the shape of every client Initial after the server has answered: the
    /// Destination Connection ID is now the server's, while the keys stay
    /// those of the first packet (RFC 9000 §7.2).
    keyed_by: Option<Vec<u8>>,
    /// The Source Connection ID, which may be empty.
    scid: Vec<u8>,
    /// A `NEW_TOKEN` or Retry token, or nothing.
    token: Vec<u8>,
    /// How many bytes the Packet Number field takes, one to four.
    number_length: usize,
    /// How long the Initial packet itself is, before anything coalesced.
    packet_length: usize,
    /// The packet number, below 256 so that it fits the last byte of the field.
    number: u8,
}

impl Default for Shape {
    fn default() -> Self {
        Self {
            dcid: CLIENT_CID.to_vec(),
            keyed_by: None,
            scid: vec![0xcc; 8],
            token: Vec::new(),
            number_length: 1,
            packet_length: MIN_INITIAL_DATAGRAM,
            number: 0,
        }
    }
}

/// A QUIC v1 Initial of `shape`, carrying `frames` and PADDING to its length.
fn shaped_initial(
    crypto: &dyn quinn::crypto::ServerConfig,
    shape: &Shape,
    frames: &[u8],
) -> Vec<u8> {
    let keyed_by = shape.keyed_by.as_deref().unwrap_or(&shape.dcid);
    let keys = crypto
        .initial_keys(QUIC_V1, &ConnectionId::new(keyed_by))
        .expect("Initial keys for QUIC v1");
    let tag_len = keys.packet.remote.tag_len();
    assert!(
        (1..=4).contains(&shape.number_length),
        "a packet number is one to four bytes"
    );

    let mut packet =
        vec![0xc0 | u8::try_from(shape.number_length - 1).expect("two bits of length")];
    packet.extend_from_slice(&QUIC_V1.to_be_bytes());
    packet.push(u8::try_from(shape.dcid.len()).expect("a legal connection id"));
    packet.extend_from_slice(&shape.dcid);
    packet.push(u8::try_from(shape.scid.len()).expect("a legal connection id"));
    packet.extend_from_slice(&shape.scid);
    packet.extend_from_slice(&varint(shape.token.len()));
    packet.extend_from_slice(&shape.token);

    // A two-byte Length field, which is what every real Initial uses.
    let number_offset = packet.len() + 2;
    let payload_len = shape
        .packet_length
        .checked_sub(number_offset + shape.number_length + tag_len)
        .expect("a packet long enough to hold its own header");
    assert!(frames.len() <= payload_len, "frames do not fit one Initial");
    let length = u16::try_from(shape.number_length + payload_len + tag_len)
        .expect("a length that fits two bytes");
    packet.extend_from_slice(&(0x4000 | length).to_be_bytes());

    packet.resize(number_offset + shape.number_length, 0);
    *packet.last_mut().expect("a packet number field") = shape.number;
    packet.extend_from_slice(frames);
    packet.resize(number_offset + shape.number_length + payload_len, 0); // PADDING
    packet.resize(shape.packet_length, 0); // room for the tag

    keys.packet.remote.encrypt(
        u64::from(shape.number),
        &mut packet,
        number_offset + shape.number_length,
    );
    keys.header.remote.encrypt(number_offset, &mut packet);
    packet
}

/// A 1200-byte first Initial addressed to, and keyed by, `dcid`.
fn initial(crypto: &dyn quinn::crypto::ServerConfig, dcid: &[u8], frames: &[u8]) -> Vec<u8> {
    let shape = Shape {
        dcid: dcid.to_vec(),
        ..Shape::default()
    };
    shaped_initial(crypto, &shape, frames)
}

/// A 1200-byte version-1 Initial addressed to `dcid` whose payload was never
/// sealed.
///
/// Every other builder here encrypts what it makes, so this is the one shape
/// that reaches the gate without authenticating under any key. The layout is a
/// long header with the Initial type, an empty Source Connection ID, an empty
/// token, a two-byte Length field, and filler to 1200 bytes.
fn unsealed_initial(dcid: &[u8]) -> Vec<u8> {
    let mut datagram = vec![0xc0];
    datagram.extend_from_slice(&QUIC_V1.to_be_bytes());
    datagram.push(u8::try_from(dcid.len()).expect("a legal connection id"));
    datagram.extend_from_slice(dcid);
    datagram.push(0); // no Source Connection ID
    datagram.extend_from_slice(&varint(0)); // no token
    let length = MIN_INITIAL_DATAGRAM - datagram.len() - 2;
    let encoded = varint(length);
    assert_eq!(
        encoded.len(),
        2,
        "a two-byte Length field, as an Initial uses"
    );
    datagram.extend_from_slice(&encoded);
    datagram.resize(MIN_INITIAL_DATAGRAM, 0x5a); // the payload, sealed by nobody
    datagram
}

/// A quinn crypto configuration around a throwaway certificate.
///
/// The one builder here that carries a certificate, for the one test whose
/// point is that a certificate is not an input to Initial keys.
fn certified_crypto() -> Arc<dyn quinn::crypto::ServerConfig> {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("a self-signed certificate");
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(issued.signing_key.serialize_der().into());
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![issued.cert.der().clone()], key)
        .expect("a usable certificate/key pair");
    Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
            .expect("a QUIC-capable configuration"),
    )
}

// ---------------------------------------------------------------------------
// (a) Hand-spelled first flights, judged through the seam the socket uses
// ---------------------------------------------------------------------------

/// The CRYPTO-side seam over a ClientHello this binary spells itself, so that a
/// change in the hand-written builder above shows up here rather than only in
/// the datagram tests that use it.
#[test]
fn the_hand_written_client_hello_reads_back_as_its_name() {
    assert_eq!(
        first_flight(&named_hello("localhost")),
        FirstFlight::Named(b"localhost")
    );
}

/// The control: a first packet, keyed by its own Destination Connection ID, is
/// opened and judged by the name it carries.
#[test]
fn a_first_initial_is_opened_under_its_own_keys() {
    let crypto = nameless_crypto();
    let names = Names::new(&["localhost".to_owned()]);

    let stranger = initial(
        &*crypto,
        &CLIENT_CID,
        &crypto_frame_at(0, &named_hello("other.example")),
    );
    assert_eq!(
        judgement(&stranger, &names),
        Verdict::Refuse(Refusal::OtherName(b"other.example".to_vec()))
    );

    let ours = initial(
        &*crypto,
        &CLIENT_CID,
        &crypto_frame_at(0, &named_hello("localhost")),
    );
    assert_eq!(judgement(&ours, &names), Verdict::Pass);
}

/// A packet [`sealed_initial`] builds opens under rustls's Initial keys.
///
/// `sealed_initial` seals with the server's own key code, the code the gate
/// opens with, so the `hold` fuzz target and its seeds would pass whatever
/// that code derived. Here rustls's code, through [`nameless_crypto`], removes
/// the header protection and opens the payload, which judges the seal with a
/// second implementation.
#[test]
fn a_sealed_initial_opens_under_rustls_initial_keys() {
    let frames = crypto_frame_at(0, &named_hello("localhost"));
    let number = 3;
    let mut packet = sealed_initial(&CLIENT_CID, number, &frames);
    assert_eq!(packet.len(), MIN_INITIAL_DATAGRAM);

    let keys = nameless_crypto()
        .initial_keys(QUIC_V1, &ConnectionId::new(&CLIENT_CID))
        .expect("Initial keys for QUIC v1");
    // The first byte, the version, the connection ID with its length, the
    // empty Source Connection ID and token, and the two-byte Length field.
    let number_offset = 1 + 4 + 1 + CLIENT_CID.len() + 1 + 1 + 2;
    keys.header.remote.decrypt(number_offset, &mut packet);
    assert_eq!(
        packet[0], 0xc0,
        "a long-header Initial with a one-byte packet number"
    );
    assert_eq!(packet[number_offset], number);

    let header = packet[..=number_offset].to_vec();
    let mut payload = BytesMut::from(&packet[number_offset + 1..]);
    keys.packet
        .remote
        .decrypt(u64::from(number), &header, &mut payload)
        .expect("rustls's keys open the packet");
    assert_eq!(&payload[..frames.len()], &frames[..]);
    assert!(
        payload[frames.len()..].iter().all(|&byte| byte == 0),
        "PADDING after the frames"
    );
}

/// A later Initial of an admitted handshake cannot be opened here, and must
/// not be refused for it: the Handshake packet carrying the client's Finished
/// rides in the same datagram, and blinding it costs the handshake a probe
/// timeout. Seen on a production host on 2026-09-03 as every handshake's RTT
/// stuck at the configured initial estimate.
#[test]
fn a_later_initial_keyed_by_the_first_packet_is_not_a_stranger() {
    let crypto = nameless_crypto();
    let names = Names::new(&["localhost".to_owned()]);
    let later = Shape {
        dcid: SERVER_CID.to_vec(),
        keyed_by: Some(CLIENT_CID.to_vec()),
        ..Shape::default()
    };

    // An acknowledgement of the server's Initial: ACK frame for packet 0.
    let ack = [0x02, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        judgement(&shaped_initial(&*crypto, &later, &ack), &names),
        Verdict::Pass
    );

    // Even one that looks like a stranger's ClientHello once opened under the
    // wrong keys cannot be told from an acknowledgement without the
    // connection's state; quinn, which has it, is the one to judge.
    let hello = crypto_frame_at(0, &named_hello("other.example"));
    assert_eq!(
        judgement(&shaped_initial(&*crypto, &later, &hello), &names),
        Verdict::Pass
    );
}

/// A first Initial whose Destination Connection ID is under eight bytes.
///
/// That it opens at all is what makes it a first Initial rather than a later
/// packet of a flight already admitted, and a first Initial has a floor of
/// eight bytes (RFC 9000 §7.2). quinn answers this one with
/// CONNECTION_CLOSE(PROTOCOL_VIOLATION) before it reads a frame, which is one
/// of the three replies the gate exists to take away — so the header is judged
/// ahead of anything the packet carries, and the two witnesses here carry
/// nothing and carry a name on the list.
#[test]
fn a_first_initial_with_a_short_connection_id_is_refused() {
    let crypto = nameless_crypto();
    let names = Names::new(&["localhost".to_owned()]);

    let short = [0x11; 4];
    let padding_only = initial(&*crypto, &short, &[]);
    assert_eq!(padding_only.len(), MIN_INITIAL_DATAGRAM);
    assert_eq!(
        judgement(&padding_only, &names),
        Verdict::Refuse(Refusal::ShortConnectionId(short.len())),
        "a PADDING-only Initial behind a four-byte connection ID"
    );

    let named = initial(
        &*crypto,
        &short,
        &crypto_frame_at(0, &named_hello("localhost")),
    );
    assert_eq!(
        judgement(&named, &names),
        Verdict::Refuse(Refusal::ShortConnectionId(short.len())),
        "a name on the list does not buy a connection ID no client may choose"
    );
}

/// The same packet behind a connection ID a client may actually choose.
///
/// The sibling of the test above and the half that says the rule is about the
/// length rather than about the shape: eight bytes is the floor, and a datagram
/// carrying nothing to judge is passed through as it always was.
#[test]
fn a_first_initial_with_a_full_connection_id_is_not_refused_for_its_length() {
    let crypto = nameless_crypto();
    let names = Names::new(&["localhost".to_owned()]);

    assert_eq!(CLIENT_CID.len(), MIN_CLIENT_CONNECTION_ID);
    assert_eq!(
        judgement(&initial(&*crypto, &CLIENT_CID, &[]), &names),
        Verdict::Pass,
        "an eight-byte connection ID is the shortest one a client may choose"
    );
}

/// A short connection ID is refused whether or not the packet authenticates.
///
/// The length is read off the header, ahead of the decryption, because quinn
/// reads it ahead of its own decryption: `early_validate_first_packet` runs
/// before `first_decode.finish` and answers a Destination Connection ID under
/// eight bytes with CONNECTION_CLOSE(PROTOCOL_VIOLATION) without opening the
/// packet. So an Initial nobody sealed, which costs its sender no cryptography
/// at all, drew that reply through the gate until 2026-09-07. The two other
/// witnesses for this rule both seal their payloads, which is why this one is
/// built by hand.
#[test]
fn an_unsealed_initial_with_a_short_connection_id_is_refused() {
    let names = Names::new(&["localhost".to_owned()]);

    let short = [0x11; 4];
    let refused = unsealed_initial(&short);
    assert_eq!(refused.len(), MIN_INITIAL_DATAGRAM);
    assert_eq!(
        judgement(&refused, &names),
        Verdict::Refuse(Refusal::ShortConnectionId(short.len())),
        "an Initial nobody sealed, behind a four-byte connection ID"
    );

    // The same shape behind a connection ID a client may choose is passed
    // through, which is what says this payload authenticates under no key: an
    // Initial the gate cannot open is one it passes.
    assert_eq!(
        judgement(&unsealed_initial(&CLIENT_CID), &names),
        Verdict::Pass,
        "an unsealed payload opens under no key, so the length is all there is"
    );
}

/// A refused name is carried as the bytes the extension spelled, so a build
/// that is not logging at DEBUG formats nothing for a flood of refused
/// handshakes. `a_refused_name_is_logged_escaped_by_both_gates` reads the line
/// that escapes it.
#[test]
fn a_refused_name_is_carried_as_the_bytes_the_peer_sent() {
    let crypto = nameless_crypto();
    let names = Names::new(&[LISTED.to_owned()]);
    let datagram = initial(
        &*crypto,
        &CLIENT_CID,
        &crypto_frame_at(0, &named_hello(HOSTILE)),
    );

    assert_eq!(
        judgement(&datagram, &names),
        Verdict::Refuse(Refusal::OtherName(HOSTILE.as_bytes().to_vec())),
        "the refusal must carry the bytes the peer sent, unrendered"
    );
}

/// The filter of the one log subscriber this binary installs. The first
/// caller of [`SharedBuffer::shared`] sets it, so every caller passes this.
const LOG_FILTER: &str = "volto::tls=debug,volto::gate=debug";

/// A name with the characters log escaping exists for: a quote, a newline, a
/// carriage return and an escape byte. Any of them raw in a log line would let
/// an unauthenticated peer forge a journal entry or a terminal sequence.
const HOSTILE: &str = "a\"b\nc\r\u{1b}.example";

/// The field the gate's log lines carry for [`HOSTILE`], written out here
/// rather than computed with `logfmt::escaped_bytes`, so that the lines are
/// judged against a second spelling.
const HOSTILE_LOGGED: &str = r#"server_name="a\"b\nc\r\u{1b}.example""#;

/// Both gates log a refused name escaped: the stateless gate's refusal
/// (`log_refusal`) and the hold's drop (`log_drop`). Each line is found by
/// the probe's own address and must carry the escaped name whole, which a raw
/// newline would cut in two, and the log must hold no raw carriage return or
/// escape byte.
#[tokio::test]
async fn a_refused_name_is_logged_escaped_by_both_gates() {
    let log = SharedBuffer::shared(LOG_FILTER);
    let crypto = nameless_crypto();
    let datagram = initial(
        &*crypto,
        &CLIENT_CID,
        &crypto_frame_at(0, &named_hello(HOSTILE)),
    );
    let stateless = TestServer::start_with(GATE_LOCALHOST).await;
    let (holding, _keys) = ech_server(&ech_key(45), false, &["localhost"]).await;

    for (server, text) in [
        (
            &stateless,
            "dropping a handshake: its server_name is not one this server answers to",
        ),
        (
            &holding,
            "dropping a first flight: its server_name is not one this server answers to",
        ),
    ] {
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind a probe");
        let remote = format!(
            "remote={}",
            probe.local_addr().expect("the probe's address")
        );
        let mark = log.mark();
        probe
            .send_to(&datagram, server.addr)
            .await
            .expect("send the probe");
        let line = log.wait_for_line(mark, &[text, &remote]).await;
        assert!(line.contains(HOSTILE_LOGGED), "{text}: {line}");
        assert!(
            !log.since(mark).contains(['\r', '\u{1b}']),
            "{text}: a raw control byte reached the log"
        );
    }
}

/// An Initial whose Length field leaves no room for a packet number is passed
/// through, and is answered before any key is derived.
///
/// RFC 9001 §5.4.2 samples header protection from four bytes past the packet
/// number offset, so a packet declaring fewer bytes than that after the offset
/// cannot be opened under any cipher. `gate::initial::decrypt` asks that half
/// of the length test above `tls::client_initial_keys`, which is nearly the
/// whole cost of judging
/// an Initial, and the verdict is the same on both sides of the move: a packet
/// that does not open is one quinn tells apart with state this gate does not
/// have, so it reaches quinn.
#[test]
fn an_initial_too_short_for_a_packet_number_is_passed_through() {
    let crypto = nameless_crypto();
    let names = Names::new(&[LISTED.to_owned()]);

    let mut datagram = initial(
        &*crypto,
        &CLIENT_CID,
        &crypto_frame_at(0, &named_hello(UNLISTED)),
    );
    assert_eq!(
        judgement(&datagram, &names),
        Verdict::Refuse(Refusal::OtherName(UNLISTED.as_bytes().to_vec())),
        "the packet must be refused for its name before it is shortened"
    );

    // Where `shaped_initial` writes the Length: the first byte, the version,
    // each connection ID behind its own length byte, then a one-byte token
    // length of zero. The packet number follows the two bytes of it.
    let shape = Shape::default();
    assert!(shape.token.is_empty(), "the default shape carries no token");
    let length_offset = 1 + 4 + 1 + shape.dcid.len() + 1 + shape.scid.len() + 1;
    let declared = u16::from_be_bytes([datagram[length_offset], datagram[length_offset + 1]]);
    assert_eq!(
        declared & 0xc000,
        0x4000,
        "the Length field is a two-byte varint at {length_offset}"
    );

    // Three bytes of packet, where the sample alone needs four past the offset.
    datagram[length_offset..length_offset + 2].copy_from_slice(&(0x4000u16 | 3).to_be_bytes());
    assert_eq!(
        judgement(&datagram, &names),
        Verdict::Pass,
        "a packet that cannot be opened is quinn's to tell apart"
    );
}

// Shape metamorphism: an unusual but legal first flight is judged by its name
// and by nothing else.
//
// Everything below is one property with many witnesses. A first flight has a
// great deal of freedom in how it is laid out -- how many CRYPTO frames carry
// it and in what order, what else rides in front of them, how long the
// connection IDs and the packet number are, whether a token is there, whether
// a second packet is coalesced behind it, and how the ClientHello itself is
// spelled -- and none of that freedom may move the verdict. So each shape is
// built twice, once naming a host on the list and once naming a host that is
// not, and both halves are asserted: a shape that turns a listed name into a
// refusal is a client this server has become unreachable to, and a shape that
// turns an unlisted name into a pass is the gate gone blind. A parser that
// gives up reads as the second.

/// How a first flight's bytes are spread over the frames of one payload.
type Layout = fn(&[u8]) -> Vec<u8>;

/// How a ClientHello naming a host is written out.
type Spelling = fn(&str) -> Vec<u8>;

/// Asserts that a datagram laid out by `build` is judged by its name alone.
///
/// Written as a plain function taking a builder rather than two datagrams so
/// that the listed and the unlisted half can never drift apart: they are the
/// same shape twice.
#[track_caller]
fn judged_by_its_name_alone(shape: &str, build: impl Fn(&str) -> Vec<u8>) {
    let names = Names::new(&[LISTED.to_owned()]);

    assert_eq!(
        judgement(&build(LISTED), &names),
        Verdict::Pass,
        "{shape}: a first flight naming {LISTED} must reach quinn"
    );
    let refusal = judgement(&build(UNLISTED), &names);
    assert_matches!(
        refusal,
        Verdict::Refuse(Refusal::OtherName(_)),
        "{shape}: a first flight naming {UNLISTED} must be refused for its name, not {refusal:?}"
    );
}

/// How a first flight's bytes are distributed over the frames of one packet.
///
/// Every one of these is a legal Initial payload that a client is free to
/// send, and RFC 9000 §19.6 puts no order on CRYPTO frames within a packet.
#[test]
fn the_frames_a_first_flight_is_laid_out_in_do_not_change_the_verdict() {
    let crypto = nameless_crypto();

    let layouts: [(&str, Layout); 10] = [
        ("one CRYPTO frame", |hello| crypto_frame_at(0, hello)),
        ("two CRYPTO frames in order", |hello| {
            let (head, tail) = hello.split_at(hello.len() / 2);
            let mut frames = crypto_frame_at(0, head);
            frames.extend_from_slice(&crypto_frame_at(head.len(), tail));
            frames
        }),
        ("two CRYPTO frames in reverse order", |hello| {
            let (head, tail) = hello.split_at(hello.len() / 2);
            let mut frames = crypto_frame_at(head.len(), tail);
            frames.extend_from_slice(&crypto_frame_at(0, head));
            frames
        }),
        ("three CRYPTO frames, middle one first", |hello| {
            let third = hello.len() / 3;
            let mut frames = crypto_frame_at(third, &hello[third..third * 2]);
            frames.extend_from_slice(&crypto_frame_at(third * 2, &hello[third * 2..]));
            frames.extend_from_slice(&crypto_frame_at(0, &hello[..third]));
            frames
        }),
        ("PADDING before the CRYPTO frame", |hello| {
            let mut frames = vec![0x00; 32];
            frames.extend_from_slice(&crypto_frame_at(0, hello));
            frames
        }),
        ("PING before the CRYPTO frame", |hello| {
            let mut frames = vec![0x01];
            frames.extend_from_slice(&crypto_frame_at(0, hello));
            frames
        }),
        ("an ACK frame before the CRYPTO frame", |hello| {
            // Largest Acknowledged 10, delay 27, no further ranges, first
            // range 3. Every field is distinct and non-zero on purpose: an ACK
            // of zeroes is indistinguishable from PADDING, so a walk that
            // lands one varint out still finds the CRYPTO frame and the shape
            // proves nothing.
            let mut frames = vec![0x02, 0x0a, 0x1b, 0x00, 0x03];
            frames.extend_from_slice(&crypto_frame_at(0, hello));
            frames
        }),
        ("a two-range ACK frame before the CRYPTO frame", |hello| {
            // Largest 10, delay 27, two further ranges, first range 1, then
            // the gap and length of each of them.
            let mut frames = vec![0x02, 0x0a, 0x1b, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05];
            frames.extend_from_slice(&crypto_frame_at(0, hello));
            frames
        }),
        ("an ACK_ECN frame before the CRYPTO frame", |hello| {
            // The same, with the three ECN counts an ACK_ECN carries.
            let mut frames = vec![0x03, 0x0a, 0x1b, 0x00, 0x03, 0x11, 0x12, 0x13];
            frames.extend_from_slice(&crypto_frame_at(0, hello));
            frames
        }),
        ("PADDING, PING and ACK around two CRYPTO frames", |hello| {
            let (head, tail) = hello.split_at(hello.len() / 2);
            let mut frames = vec![0x00; 8];
            frames.push(0x01);
            frames.extend_from_slice(&[0x02, 0x0a, 0x1b, 0x00, 0x03]);
            frames.extend_from_slice(&crypto_frame_at(head.len(), tail));
            frames.push(0x01);
            frames.extend_from_slice(&crypto_frame_at(0, head));
            frames.extend_from_slice(&[0x00; 8]);
            frames
        }),
    ];

    for (shape, lay_out) in layouts {
        judged_by_its_name_alone(shape, |name| {
            shaped_initial(&*crypto, &Shape::default(), &lay_out(&named_hello(name)))
        });
    }
}

/// The header fields a client picks, none of which the name depends on.
#[test]
fn the_header_a_first_flight_wears_does_not_change_the_verdict() {
    let crypto = nameless_crypto();

    let mut shapes = vec![
        ("the baseline header".to_owned(), Shape::default()),
        (
            "a 20-byte Destination Connection ID".to_owned(),
            Shape {
                dcid: vec![0xa1; MAX_CONNECTION_ID],
                ..Shape::default()
            },
        ),
        (
            "an empty Source Connection ID".to_owned(),
            Shape {
                scid: Vec::new(),
                ..Shape::default()
            },
        ),
        (
            "a 20-byte Source Connection ID".to_owned(),
            Shape {
                scid: vec![0xc5; MAX_CONNECTION_ID],
                ..Shape::default()
            },
        ),
        (
            "a token, as a client returning a NEW_TOKEN sends".to_owned(),
            Shape {
                token: vec![0x7e; 64],
                ..Shape::default()
            },
        ),
        (
            "a token, the longest connection IDs and a four-byte number".to_owned(),
            Shape {
                dcid: vec![0xa1; MAX_CONNECTION_ID],
                scid: vec![0xc5; MAX_CONNECTION_ID],
                token: vec![0x7e; 200],
                number_length: 4,
                ..Shape::default()
            },
        ),
        (
            "a datagram larger than the minimum".to_owned(),
            Shape {
                packet_length: 1500,
                ..Shape::default()
            },
        ),
    ];
    shapes.extend((1..=4).map(|number_length| {
        (
            format!("a {number_length}-byte packet number"),
            Shape {
                number_length,
                ..Shape::default()
            },
        )
    }));

    for (shape, header) in shapes {
        judged_by_its_name_alone(&shape, |name| {
            shaped_initial(&*crypto, &header, &crypto_frame_at(0, &named_hello(name)))
        });
    }
}

/// A packet coalesced behind the Initial is not what the gate judges.
///
/// RFC 9000 §12.2 lets a receiver route on the first packet of a datagram
/// alone, and this gate does. The witness is a second packet that names the
/// *other* host: if any of it were read, both halves of the property would
/// come out inverted rather than merely wrong.
#[test]
fn a_packet_coalesced_behind_the_initial_is_not_what_is_judged() {
    let crypto = nameless_crypto();
    let head = Shape {
        packet_length: 700,
        ..Shape::default()
    };

    // A long header of each type a client may coalesce behind an Initial, and
    // a short header, which RFC 9000 §12.2 allows only last.
    let followers: [(&str, u8); 3] = [
        ("a 0-RTT packet", 0xd0),
        ("a Handshake packet", 0xe0),
        ("a short-header packet", 0x40),
    ];

    for (shape, first_byte) in followers {
        judged_by_its_name_alone(shape, |name| {
            let mut datagram =
                shaped_initial(&*crypto, &head, &crypto_frame_at(0, &named_hello(name)));

            // The bait: everything the judge would find if it read on.
            let theirs = named_hello(if name == LISTED { UNLISTED } else { LISTED });
            let mut follower = vec![first_byte];
            if first_byte & LONG_HEADER_FORM != 0 {
                follower.extend_from_slice(&QUIC_V1.to_be_bytes());
                follower.push(u8::try_from(head.dcid.len()).expect("a legal length"));
                follower.extend_from_slice(&head.dcid);
                follower.push(0); // Source Connection ID
                follower.extend_from_slice(&varint(400)); // Length
                follower.push(0); // packet number
            }
            follower.extend_from_slice(&crypto_frame_at(0, &theirs));
            follower.resize(500, 0);
            datagram.extend_from_slice(&follower);
            datagram
        });
    }
}

/// The length of the ClientHello a Surge beta sent on 2026-11-13, once it
/// offered an ML-KEM key share (D101 addendum of that day).
const LARGE_HELLO: usize = 1468;

/// The length of each Initial packet that client sent.
const LARGE_FLIGHT_PACKET: usize = 1350;

/// Where the CRYPTO stream of a large first flight is cut.
///
/// Modelled on that capture and not copied from it: small pieces across the
/// start of the message, a few large ones, and small ones again near the end,
/// about thirty in all.
const LARGE_FLIGHT_CUTS: [usize; 31] = [
    16, 32, 48, 56, 60, 64, 65, 67, 71, 78, 81, 82, 83, 84, 85, 92, 236, 381, 671, 961, 1251, 1278,
    1306, 1333, 1361, 1388, 1395, 1402, 1416, 1430, 1444,
];

/// The stream offset at which the second packet of a large first flight begins.
const SECOND_PACKET_FROM: usize = 961;

/// A ClientHello naming `host`, `length` bytes long.
///
/// The length is made up by a `key_share` extension (51) of filler behind the
/// `server_name`, which is where the size of a real one comes from.
fn hello_of_length(host: &str, length: usize) -> Vec<u8> {
    let with_share = |share: usize| {
        let mut extensions = sni_extension(host);
        extensions.extend_from_slice(&extension(51, &vec![0x5a; share]));
        client_hello(&extensions)
    };
    let share = length
        .checked_sub(with_share(0).len())
        .expect("a length that holds the name");
    let hello = with_share(share);
    assert_eq!(hello.len(), length);
    hello
}

/// The pieces of `hello` between consecutive `cuts`, as (offset, bytes).
fn fragments<'a>(hello: &'a [u8], cuts: &[usize]) -> Vec<(usize, &'a [u8])> {
    let mut bounds = vec![0];
    bounds.extend(cuts.iter().copied().filter(|cut| *cut < hello.len()));
    bounds.push(hello.len());
    bounds
        .windows(2)
        .map(|pair| (pair[0], &hello[pair[0]..pair[1]]))
        .collect()
}

/// CRYPTO frames for `pieces` in a fixed order that is not offset order, with
/// a PING after every third and PADDING after every fifth.
fn shuffled_frames(pieces: &[(usize, &[u8])]) -> Vec<u8> {
    let mut order: Vec<usize> = (0..pieces.len()).collect();
    order.sort_by_key(|index| (index * 11 + 5) % pieces.len().max(1));

    let mut frames = Vec::new();
    for (written, index) in order.into_iter().enumerate() {
        let (offset, bytes) = pieces[index];
        frames.extend_from_slice(&crypto_frame_at(offset, bytes));
        if written % 3 == 2 {
            frames.push(0x01);
        }
        if written % 5 == 4 {
            frames.extend_from_slice(&[0x00; 2]);
        }
    }
    frames
}

/// The two Initial packets of a first flight too large for one, naming `host`.
///
/// `held_back` is a range of stream offsets whose pieces travel in the second
/// packet although they belong before [`SECOND_PACKET_FROM`]. An empty range
/// leaves the first packet with one contiguous run from offset 0.
fn large_first_flight(
    crypto: &dyn quinn::crypto::ServerConfig,
    host: &str,
    held_back: std::ops::Range<usize>,
) -> (Vec<u8>, Vec<u8>) {
    let hello = hello_of_length(host, LARGE_HELLO);
    let (first, second): (Vec<_>, Vec<_>) = fragments(&hello, &LARGE_FLIGHT_CUTS)
        .into_iter()
        .partition(|(offset, _)| *offset < SECOND_PACKET_FROM && !held_back.contains(offset));

    let packet = |number: u8, pieces: &[(usize, &[u8])]| {
        let shape = Shape {
            packet_length: LARGE_FLIGHT_PACKET,
            number,
            ..Shape::default()
        };
        shaped_initial(crypto, &shape, &shuffled_frames(pieces))
    };
    (packet(0, &first), packet(1, &second))
}

/// A first flight that needs two Initial packets is passed whatever it names.
///
/// This is the shape every handshake of a Surge beta has had since it offered
/// an ML-KEM key share: a ClientHello of 1468 bytes in two Initial packets of
/// 1350, the CRYPTO stream cut into about thirty pieces and sent out of order
/// with PING and PADDING between them. The gate keeps no state between
/// datagrams, so it never holds the whole message, and a message that is not
/// whole is not judged. The name starts in the first packet in every case below
/// and is still not judged. The TLS layer refuses the unlisted name
/// (`it_sni_gate`).
#[test]
fn a_first_flight_over_two_packets_is_passed_whatever_it_names() {
    let crypto = nameless_crypto();
    let names = Names::new(&[LISTED.to_owned()]);

    for host in [LISTED, UNLISTED] {
        // Both packets in one datagram: only the first is read.
        let (first, second) = large_first_flight(&*crypto, host, 0..0);
        let mut coalesced = first.clone();
        coalesced.extend_from_slice(&second);
        assert_eq!(coalesced.len(), 2 * LARGE_FLIGHT_PACKET);

        // The stretch at offsets 64 to 85 sent in the second packet, so the
        // first has a hole in its stream.
        let (holed, filling) = large_first_flight(&*crypto, host, 64..86);

        for (shape, datagram) in [
            ("two packets in one datagram", &coalesced),
            ("the first packet by itself", &first),
            ("the second packet by itself", &second),
            ("a first packet with a hole in its stream", &holed),
            ("the packet that fills the hole", &filling),
        ] {
            assert_eq!(
                judgement(datagram, &names),
                Verdict::Pass,
                "{shape}, naming {host}"
            );
        }
    }
}

/// The same cuts and the same order on a ClientHello that fits one packet.
///
/// The control for the test above: with the whole message in the packet, about
/// twenty out-of-order pieces are joined and the name decides. So the passes
/// above come from the message being unfinished and not from a frame walk that
/// gave up.
#[test]
fn a_whole_client_hello_in_many_shuffled_pieces_is_judged_by_its_name() {
    let crypto = nameless_crypto();
    let shape = Shape {
        packet_length: LARGE_FLIGHT_PACKET,
        ..Shape::default()
    };

    judged_by_its_name_alone("one packet, many shuffled CRYPTO frames", |name| {
        let hello = hello_of_length(name, 1200);
        let pieces = fragments(&hello, &LARGE_FLIGHT_CUTS);
        assert!(pieces.len() >= 20, "enough pieces to be the shape");
        shaped_initial(&*crypto, &shape, &shuffled_frames(&pieces))
    });
}

/// How the ClientHello itself is spelled, which is where a real stack's
/// idiosyncrasies live: Chrome's 32-byte session id, the GREASE values RFC
/// 8701 has clients scatter through it, and where in the extension list
/// `server_name` happens to fall.
#[test]
fn the_way_a_client_hello_is_spelled_does_not_change_the_verdict() {
    let crypto = nameless_crypto();

    /// A GREASE extension, which carries nothing and means nothing.
    fn grease(kind: u16) -> Vec<u8> {
        extension(kind, &[])
    }

    /// `supported_versions`, offering TLS 1.3.
    fn supported_versions() -> Vec<u8> {
        extension(0x002b, &[0x02, 0x03, 0x04])
    }

    let spellings: [(&str, Spelling); 10] = [
        ("server_name as the only extension", named_hello),
        ("server_name first of three", |name| {
            let mut extensions = sni_extension(name);
            extensions.extend_from_slice(&supported_versions());
            extensions.extend_from_slice(&grease(0x1a1a));
            client_hello(&extensions)
        }),
        ("server_name last of three", |name| {
            let mut extensions = grease(0x0a0a);
            extensions.extend_from_slice(&supported_versions());
            extensions.extend_from_slice(&sni_extension(name));
            client_hello(&extensions)
        }),
        ("a 32-byte legacy_session_id", |name| {
            client_hello_with(32, &[0x1301], &sni_extension(name))
        }),
        ("GREASE cipher suites around the real one", |name| {
            client_hello_with(32, &[0x0a0a, 0x1301, 0x1302, 0x5a5a], &sni_extension(name))
        }),
        ("GREASE extensions on both sides of server_name", |name| {
            let mut extensions = grease(0x0a0a);
            extensions.extend_from_slice(&sni_extension(name));
            extensions.extend_from_slice(&grease(0x3a3a));
            client_hello_with(32, &[0x0a0a, 0x1301], &extensions)
        }),
        ("an unknown name_type ahead of the host_name", |name| {
            let host = name.as_bytes();
            // An entry of some other NameType, then the host_name.
            let mut list = vec![0x42, 0x00, 0x03, b'x', b'y', b'z'];
            list.push(HOST_NAME);
            list.extend_from_slice(
                &u16::try_from(host.len())
                    .expect("a short name")
                    .to_be_bytes(),
            );
            list.extend_from_slice(host);
            let mut body = u16::try_from(list.len())
                .expect("a short list")
                .to_be_bytes()
                .to_vec();
            body.extend_from_slice(&list);
            client_hello(&extension(SERVER_NAME_EXTENSION, &body))
        }),
        ("the name in upper case", |name| {
            named_hello(&name.to_ascii_uppercase())
        }),
        ("the name with its root dot", |name| {
            named_hello(&format!("{name}."))
        }),
        ("everything a Chrome-shaped hello does at once", |name| {
            let mut extensions = grease(0x0a0a);
            extensions.extend_from_slice(&supported_versions());
            extensions.extend_from_slice(&sni_extension(&name.to_ascii_uppercase()));
            extensions.extend_from_slice(&extension(0x0010, &[0x00, 0x03, 0x02, b'h', b'3']));
            extensions.extend_from_slice(&grease(0x5a5a));
            client_hello_with(32, &[0x0a0a, 0x1301, 0x1302, 0x1303], &extensions)
        }),
    ];

    for (shape, spell) in spellings {
        judged_by_its_name_alone(shape, |name| {
            shaped_initial(
                &*crypto,
                &Shape::default(),
                &crypto_frame_at(0, &spell(name)),
            )
        });
    }
}

// ---------------------------------------------------------------------------
// (b) A first flight from a real stack, judged by the seam the socket uses
// ---------------------------------------------------------------------------

/// The name every real first flight here asks for.
const REAL_NAME: &str = "localhost";

/// A real quinn client's first datagram reads as the name it asked for.
///
/// Captured off a UDP socket that never answers, so what is judged is exactly
/// the bytes quinn put on the wire and nothing the harness shaped. Both halves
/// are asserted: the name on the list passes, and the same datagram judged
/// against a list that does not hold it is refused *for its name*, which is what
/// says the ClientHello was read rather than given up on.
#[tokio::test]
async fn a_real_quinn_first_flight_is_judged_by_the_name_it_carries() {
    let datagram = quinn_first_flight(REAL_NAME, &["h3"]).await;

    assert_eq!(
        judgement(&datagram, &Names::new(&[REAL_NAME.to_owned()])),
        Verdict::Pass,
        "a real quinn first flight naming {REAL_NAME} must reach quinn"
    );
    let refusal = judgement(&datagram, &Names::new(&["other.example".to_owned()]));
    assert_eq!(
        refusal,
        Verdict::Refuse(Refusal::OtherName(REAL_NAME.as_bytes().to_vec())),
        "the same datagram must be refused for the name it carries"
    );
}

/// A real quinn first flight too large for one packet is passed through.
///
/// The documented hole, seen on the wire rather than argued: the padded ALPN
/// list of `it_sni_gate`'s large-ClientHello tests pushes the extensions past
/// the end of the first Initial, and the gate's answer to a first packet it
/// cannot finish reading is to let it by whatever the list says.
#[tokio::test]
async fn a_real_first_flight_larger_than_one_packet_is_passed_by_both_lists() {
    let alpn = bulk_alpn();
    let alpn: Vec<&str> = alpn.iter().map(String::as_str).collect();
    let datagram = quinn_first_flight(REAL_NAME, &alpn).await;

    for list in [REAL_NAME, "other.example"] {
        assert_eq!(
            judgement(&datagram, &Names::new(&[list.to_owned()])),
            Verdict::Pass,
            "a first flight the gate cannot finish reading must pass whatever {list} says"
        );
    }
}

/// A real quinn client asked for an IP literal sends no `server_name`, and the
/// gate refuses its first flight as anonymous.
///
/// This is the premise of `it_sni_gate`'s test of a handshake carrying no
/// server name. That test sees only silence, which a name off the list draws
/// too, so the ClientHello is read here.
#[tokio::test]
async fn a_real_quinn_first_flight_to_an_ip_literal_carries_no_name() {
    let datagram = quinn_first_flight("127.0.0.1", &["h3"]).await;
    assert_eq!(
        judgement(&datagram, &Names::new(&[REAL_NAME.to_owned()])),
        Verdict::Refuse(Refusal::Anonymous)
    );
}

/// The first datagram a quinn client sends when asking for `name`, under a
/// certificate for [`REAL_NAME`].
async fn quinn_first_flight(name: &str, alpn: &[&str]) -> Vec<u8> {
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a socket that never answers");
    let addr = sink.local_addr().expect("the sink's address");

    let issued = rcgen::generate_simple_self_signed(vec![REAL_NAME.to_owned()])
        .expect("a self-signed certificate");
    let endpoint = client_endpoint(&issued.cert.der().clone(), alpn);
    let handshake = tokio::spawn(endpoint.connect(addr, name).expect("start connecting"));

    let mut buffer = vec![0u8; 2048];
    let read = tokio::time::timeout(PATIENCE, sink.recv(&mut buffer))
        .await
        .expect("a quinn client sends its first flight at once")
        .expect("receive the first flight");
    handshake.abort();
    buffer.truncate(read);
    buffer
}

/// A first flight from aioquic, pinned as the bytes it put on the wire.
///
/// A second stack, and the one whose habit of coalescing packets exposed the
/// later-Initial defect on 2026-09-03, so what it does differently from quinn
/// is exactly what this gate has already been wrong about once. Captured with
/// aioquic 1.3.0 asking for `localhost`, and kept as bytes because generating it
/// needs a Python interpreter the `cargo test` jobs do not have.
///
/// Two things about it are worth reading off the hex before the assertions: the
/// Initial packet is 518 bytes and the remaining 682 of the datagram are zero
/// bytes *after* the packet rather than PADDING frames inside it, and the whole
/// first flight still fits one packet.
const AIOQUIC_FIRST_FLIGHT: &str = concat!(
    "ce00000001085f1c8df9350ecb1a0872ce3016cd1496a70041ec72a9f6efbd599129dea2038047cf2dc2a7623c060992",
    "86315b062a38b6ce90758e495a37fd1567f23f79b4d9ceaaaecb037de0b5f00fbcdec75e2a34c6b85a36ffa5a2fdb97a",
    "dd217ac7c866f3b21a7522d9c7101615149484e832bb73a448c40c58be49171ca81a9f7ded432ff40dbd4a5e1fad4521",
    "8d3d51a130cdd66eb5d0a5ccbef70b11ba894d90049ee8189c55044daab7bdd3422ff88b32f87ebc61c0d099c0edd9d2",
    "f44b1dea9481e15191bf2185e9af617c1099db8fc2111c2b28ac8148d695e79b0610457eec1c4af647bb939855f0901f",
    "02f6b3ab2affd0bd0705ff5c5074cf69a33d5a0311897ddc36d3a25906dbf957b0cb324f48c101824542c0eb4d7ddf54",
    "2033c2734e627f6d16bc7279465fe3f74196c5186313ef0703b3cefb063b57607f4283d9471f3c1c0184a926498f1ace",
    "6707d08fff793c675084024148203ba4c956dbd9c838b9d85345c3f5f850446e4d5b830c3c5edbaa559736d30a00af31",
    "6d0add59ab8dc73fd892badb844d1d305023fd2c588dcbfa03a91df50591cbb20c5941a2afbe1a2ee0df2a072892e297",
    "db01675f74c34d8dd50b6e47263059b53a7e89fb8041ed80e6cbe632d7b59f19a599270a4d603dbffeefe87b7dac1daa",
    "662d1dcb5c76759ec1f5b152333507ff119e51b74f8c512fd25e376ec26bf47c17c387f4a951",
);

#[test]
fn a_real_aioquic_first_flight_is_judged_by_the_name_it_carries() {
    let mut datagram: Vec<u8> = (0..AIOQUIC_FIRST_FLIGHT.len() / 2)
        .map(|i| {
            u8::from_str_radix(&AIOQUIC_FIRST_FLIGHT[i * 2..i * 2 + 2], 16).expect("a hex byte")
        })
        .collect();
    assert_eq!(datagram.len(), 518, "the Initial packet aioquic sent");
    datagram.resize(MIN_INITIAL_DATAGRAM, 0); // the zero bytes it padded with

    assert_eq!(
        judgement(&datagram, &Names::new(&[REAL_NAME.to_owned()])),
        Verdict::Pass,
        "an aioquic first flight naming {REAL_NAME} must reach quinn"
    );
    assert_eq!(
        judgement(&datagram, &Names::new(&["other.example".to_owned()])),
        Verdict::Refuse(Refusal::OtherName(REAL_NAME.as_bytes().to_vec())),
        "the same datagram must be refused for the name it carries"
    );
}

// ---------------------------------------------------------------------------
// (c) The fuzz target's seed corpus
// ---------------------------------------------------------------------------

/// Writes the seed corpus for `fuzz/fuzz_targets/gate.rs`, and pins it.
///
/// A fuzzer cannot spell an Initial packet that authenticates, so without seeds
/// the target would explore the header parser and nothing behind it. These are
/// whole datagrams, covering every branch the judgement can end on and the
/// first-flight shapes a ClientHello split across packets takes, and bare
/// CRYPTO bytes for the ClientHello reader, written where `cargo fuzz run gate`
/// looks for them.
/// `fuzz/corpus/` is machine-local and gitignored (D83), so this runs with
/// every `cargo test` rather than leaving the corpus to a step somebody has to
/// remember; each file carries the target's mode byte in front of the bytes
/// under test.
///
/// The assertions are the other half of it. They pin what each seed is a seed
/// *for*, so a verdict that moves is a red test rather than a corpus that
/// quietly stops covering anything. They also pin the claim [`nameless_crypto`]
/// rests on. These packets are built under a real self-signed certificate
/// (`certified_crypto`) and opened by [`judgement`], which derives Initial keys
/// with the server's own key code and no certificate at all, as it does for the
/// packets the other tests build with [`nameless_crypto`]. Initial keys do not
/// depend on the certificate; if they ever did, every refusal below
/// that is decided behind the packet protection would fall through to
/// [`Verdict::Pass`]. And each seed is judged twice,
/// which is the fuzz target's "a verdict is a function of the bytes and the
/// list alone" checked once here rather than on every fuzz iteration.
#[test]
fn the_fuzz_seed_corpus_is_written_with_the_verdicts_it_was_built_for() {
    /// The target's mode byte for a whole datagram.
    const AS_A_DATAGRAM: u8 = 0x00;
    /// The target's mode byte for bare CRYPTO bytes.
    const AS_CRYPTO_BYTES: u8 = 0x01;

    let crypto = certified_crypto();
    // The list the target configures for mode byte `AS_A_DATAGRAM`.
    let names = Names::new(&["localhost".to_owned()]);

    let ours = named_hello("localhost");
    let stranger = named_hello("other.example");
    let anonymous = client_hello(&[]);
    let cut = ours[..ours.len() - 4].to_vec();
    // An acknowledgement of the server's Initial, keyed by the client's first
    // packet: the shape v0.9.1 stopped refusing.
    let ack = [0x02, 0x00, 0x00, 0x00, 0x00];
    let later = Shape {
        dcid: SERVER_CID.to_vec(),
        keyed_by: Some(CLIENT_CID.to_vec()),
        ..Shape::default()
    };

    let datagrams = [
        (
            "a-name-we-answer-to",
            initial(&*crypto, &CLIENT_CID, &crypto_frame_at(0, &ours)),
            Verdict::Pass,
        ),
        (
            "a-name-we-do-not",
            initial(&*crypto, &CLIENT_CID, &crypto_frame_at(0, &stranger)),
            Verdict::Refuse(Refusal::OtherName(b"other.example".to_vec())),
        ),
        (
            "no-server-name",
            initial(&*crypto, &CLIENT_CID, &crypto_frame_at(0, &anonymous)),
            Verdict::Refuse(Refusal::Anonymous),
        ),
        (
            "a-client-hello-cut-short",
            initial(&*crypto, &CLIENT_CID, &crypto_frame_at(0, &cut)),
            Verdict::Pass,
        ),
        (
            "a-second-flight-initial",
            shaped_initial(&*crypto, &later, &ack),
            Verdict::Pass,
        ),
        (
            "a-first-flight-over-two-packets",
            {
                let (mut first, second) = large_first_flight(&*crypto, "localhost", 0..0);
                first.extend_from_slice(&second);
                first
            },
            Verdict::Pass,
        ),
        (
            "a-first-flight-over-two-packets-for-another-name",
            large_first_flight(&*crypto, "other.example", 64..86).0,
            Verdict::Pass,
        ),
        (
            "many-shuffled-pieces-of-a-name-we-do-not",
            {
                let hello = hello_of_length("other.example", 1200);
                let shape = Shape {
                    packet_length: LARGE_FLIGHT_PACKET,
                    ..Shape::default()
                };
                let pieces = fragments(&hello, &LARGE_FLIGHT_CUTS);
                shaped_initial(&*crypto, &shape, &shuffled_frames(&pieces))
            },
            Verdict::Refuse(Refusal::OtherName(b"other.example".to_vec())),
        ),
    ];

    let crypto_bytes = [
        (
            "crypto-a-whole-client-hello",
            ours,
            FirstFlight::Named(b"localhost"),
        ),
        (
            "crypto-a-client-hello-cut-short",
            cut,
            FirstFlight::Truncated,
        ),
        (
            "crypto-the-first-packet-of-a-large-client-hello",
            hello_of_length("localhost", LARGE_HELLO)[..SECOND_PACKET_FROM].to_vec(),
            FirstFlight::Truncated,
        ),
    ];

    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/gate");
    std::fs::create_dir_all(&directory).expect("a corpus directory to write seeds into");
    let seed = |name: &str, mode: u8, body: &[u8]| {
        let mut file = Vec::with_capacity(1 + body.len());
        file.push(mode);
        file.extend_from_slice(body);
        std::fs::write(directory.join(name), file).expect("a seed file");
    };

    for (name, datagram, verdict) in datagrams {
        assert_eq!(judgement(&datagram, &names), verdict, "the seed {name}");
        assert_eq!(
            judgement(&datagram, &names),
            verdict,
            "the seed {name}, judged a second time"
        );
        seed(name, AS_A_DATAGRAM, &datagram);
    }
    for (name, bytes, flight) in crypto_bytes {
        assert_eq!(first_flight(&bytes), flight, "the seed {name}");
        seed(name, AS_CRYPTO_BYTES, &bytes);
    }
}

// ---------------------------------------------------------------------------
// (d) Shapes with no name in them at all, sent at a running server
// ---------------------------------------------------------------------------

/// What a reply is, in as much detail as the Initial keys allow.
///
/// The keys a server uses to answer come from the Destination Connection ID the
/// probe chose (RFC 9001 §5.2), so a probe can read its own answers: an Initial
/// is opened and its first frame named, which is what turns "the server said
/// something" into "the server said PROTOCOL_VIOLATION" in the log. Nothing is
/// asserted on the description; it is the evidence a probe leaves behind.
fn describe(crypto: &dyn quinn::crypto::ServerConfig, reply: &[u8], dcid: &[u8]) -> String {
    let Some(&first) = reply.first() else {
        return "an empty datagram".to_owned();
    };
    if first & LONG_HEADER_FORM == 0 {
        return format!("a short-header packet of {} bytes", reply.len());
    }
    if reply.len() < 5 {
        return format!("a long header of {} bytes, cut short", reply.len());
    }
    if is_version_negotiation(reply) {
        return format!("a Version Negotiation packet of {} bytes", reply.len());
    }
    let kind = match first & 0x30 {
        0x00 => "Initial",
        0x10 => "0-RTT",
        0x20 => "Handshake",
        _ => "Retry",
    };
    if kind != "Initial" {
        return format!("a {kind} packet of {} bytes", reply.len());
    }

    match first_frame(crypto, reply, dcid) {
        Some(frame) => format!("an Initial of {} bytes opening with {frame}", reply.len()),
        None => format!("an Initial of {} bytes this probe cannot open", reply.len()),
    }
}

/// Opens a server's Initial packet and names the first frame in it that is not
/// PADDING.
fn first_frame(
    crypto: &dyn quinn::crypto::ServerConfig,
    reply: &[u8],
    dcid: &[u8],
) -> Option<String> {
    let keys = crypto
        .initial_keys(QUIC_V1, &ConnectionId::new(dcid))
        .ok()?;

    let mut at = 5usize;
    let dcid_length = usize::from(*reply.get(at)?);
    at = at.checked_add(1 + dcid_length)?;
    let scid_length = usize::from(*reply.get(at)?);
    at = at.checked_add(1 + scid_length)?;
    let (token, read) = peek_varint(reply.get(at..)?)?;
    at = at
        .checked_add(read)?
        .checked_add(usize::try_from(token).ok()?)?;
    let (length, read) = peek_varint(reply.get(at..)?)?;
    let number_offset = at.checked_add(read)?;
    let packet_end = number_offset.checked_add(usize::try_from(length).ok()?)?;
    if packet_end > reply.len() {
        return None;
    }

    // The server writes with the `local` half of the key pair; a probe reading
    // its answers is the peer that half is written for.
    let mut packet = reply[..packet_end].to_vec();
    if number_offset + 4 + keys.header.local.sample_size() > packet_end {
        return None;
    }
    keys.header.local.decrypt(number_offset, &mut packet);
    let number_length = usize::from(packet[0] & 0x03) + 1;
    let number_end = number_offset.checked_add(number_length)?;
    let mut number = 0u64;
    for byte in packet.get(number_offset..number_end)? {
        number = (number << 8) | u64::from(*byte);
    }
    let mut frames = BytesMut::from(packet.get(number_end..)?);
    keys.packet
        .local
        .decrypt(number, packet.get(..number_end)?, &mut frames)
        .ok()?;

    let mut at = 0usize;
    while at < frames.len() {
        let (kind, read) = peek_varint(&frames[at..])?;
        at += read;
        if kind == 0x00 {
            continue;
        }
        return Some(match kind {
            0x01 => "PING".to_owned(),
            0x02 | 0x03 => "ACK".to_owned(),
            0x06 => "CRYPTO".to_owned(),
            0x1c | 0x1d => {
                let (code, _) = peek_varint(&frames[at..])?;
                format!("CONNECTION_CLOSE({code:#x})")
            }
            other => format!("a frame of type {other:#x}"),
        });
    }
    Some("PADDING only".to_owned())
}

/// Sends a first Initial addressed to `dcid` and carrying `frames` at a server
/// with the gate off, then at one with it on, and asserts the second one says
/// nothing.
///
/// The control is part of the probe rather than a separate test that could rot
/// away from it: a probe nobody answers proves nothing, so the gate-off server
/// has to answer. Its first reply is enough for that and is described into the
/// log; the gate-on server gets the whole of [`PATIENCE`], because proving
/// silence takes the full wait.
async fn draws_no_reply(what: &str, dcid: &[u8], frames: &[u8]) {
    let crypto = nameless_crypto();
    let shape = initial(&*crypto, dcid, frames);

    let off = TestServer::start_with(ALLOW_PRIVATE).await;
    let control = udp_answer(off.addr, &shape, PATIENCE)
        .await
        .unwrap_or_else(|| {
            panic!("{what}: with the gate off this shape must draw a reply, or it tests nothing")
        });
    eprintln!(
        "{what}: with the gate off, the server sent {}",
        describe(&*crypto, &control, dcid)
    );

    let on = TestServer::start_with(GATE_LOCALHOST).await;
    let heard = udp_answers(on.addr, std::slice::from_ref(&shape), PATIENCE).await;
    let described: Vec<String> = heard
        .iter()
        .map(|reply| describe(&*crypto, reply, dcid))
        .collect();
    assert!(
        heard.is_empty(),
        "{what}: with the gate on, a datagram carrying no name must draw no reply, not {described:?}"
    );
}

/// An Initial with nothing in it but PADDING, and a connection ID too short.
///
/// There is no name in this datagram anywhere, and it is still refused: the
/// packet opens, which says its keys came from the connection ID written in it
/// and therefore that it is a client's first Initial, and a first Initial's
/// Destination Connection ID is at least eight bytes (RFC 9000 §7.2). quinn
/// answers a shorter one with a CONNECTION_CLOSE before it looks at a single
/// frame (`early_validate_first_packet`), which is what
/// the gate-off half of this probe records.
#[tokio::test]
async fn a_padding_only_initial_with_a_short_connection_id_is_silent() {
    draws_no_reply("a PADDING-only Initial, DCID 4 bytes", &[0x11; 4], &[]).await;
}

/// An Initial carrying the first half of a ClientHello, cut before its
/// extensions.
///
/// This is the fail-open branch reached deliberately: the gate cannot tell a
/// first flight that is merely large from one that is hiding its name, so it
/// passes both, and a CRYPTO frame is ack-eliciting.
///
/// FAILS: this shape is answered with the gate on. Left `#[ignore]`d so the
/// probe and its evidence stay in the tree; see the report on this branch.
#[tokio::test]
#[ignore = "the shape is answered: a truncated ClientHello is ack-eliciting and draws an Initial"]
async fn an_initial_carrying_half_a_client_hello_is_silent() {
    let hello = named_hello("localhost");
    // Cut inside the message, before the extensions block the name lives in.
    let half = &hello[..hello.len() / 2];
    assert_eq!(
        first_flight(half),
        FirstFlight::Truncated,
        "the probe must be the fail-open shape, not a complete hello"
    );

    draws_no_reply("half a ClientHello", &[0x33; 8], &crypto_frame_at(0, half)).await;
}

/// An Initial whose only CRYPTO frame starts past the beginning of the stream.
///
/// The gate reads this as a later fragment of a flight it already judged and
/// passes it; to quinn it is a new connection whose handshake stream has a hole
/// at the front, and it is ack-eliciting all the same.
///
/// FAILS: this shape is answered with the gate on. Left `#[ignore]`d so the
/// probe and its evidence stay in the tree; see the report on this branch.
#[tokio::test]
#[ignore = "the shape is answered: a CRYPTO frame at a non-zero offset is ack-eliciting"]
async fn an_initial_whose_crypto_starts_past_the_beginning_is_silent() {
    draws_no_reply(
        "a CRYPTO frame at offset 64",
        &[0x44; 8],
        &crypto_frame_at(64, &named_hello("localhost")),
    )
    .await;
}

/// An Initial carrying one PING frame and nothing else.
///
/// The cheapest of these shapes and the one that says most about the gate's
/// reach: no ClientHello, no name, no truncation argument — just the smallest
/// ack-eliciting frame there is, behind a Destination Connection ID long enough
/// for quinn to accept. The gate finds no CRYPTO frame at offset 0 and passes
/// it, because from the socket that is indistinguishable from a later packet of
/// a flight already admitted, and quinn acknowledges it.
///
/// FAILS: this shape is answered with the gate on. Left `#[ignore]`d so the
/// probe and its evidence stay in the tree; see the report on this branch.
#[tokio::test]
#[ignore = "the shape is answered: a PING-only Initial draws an ACK with no name anywhere in it"]
async fn an_initial_carrying_only_a_ping_is_silent() {
    draws_no_reply("a PING-only Initial, DCID 8 bytes", &[0x55; 8], &[0x01]).await;
}

/// An Initial carrying a STREAM frame, a type no Initial packet may carry.
///
/// quinn closes such a connection with a CONNECTION_CLOSE, which the gate-off
/// half of this probe records. No client sends this shape, so the gate
/// refuses it, as the hold does.
#[tokio::test]
async fn an_initial_carrying_a_frame_no_initial_may_carry_is_silent() {
    draws_no_reply(
        "a STREAM frame in an Initial, DCID 8 bytes",
        &[0x56; 8],
        &[0x08, 0x00, 0x00],
    )
    .await;
}

/// Without a key, a first Initial whose frames do not parse, or carry a type
/// no Initial packet may carry, is refused whatever else it holds: alone, and
/// beside a ClientHello naming a listed host. The hold drops the same shapes
/// as `Dropped::Frames`.
#[test]
fn a_first_initial_whose_frames_no_initial_may_carry_is_refused() {
    let crypto = nameless_crypto();
    let names = Names::new(&[LISTED.to_owned()]);
    let named = crypto_frame_at(0, &named_hello(LISTED));
    assert_eq!(
        judgement(&initial(&*crypto, &CLIENT_CID, &named), &names),
        Verdict::Pass,
        "the ClientHello alone passes"
    );

    let mut beside = named.clone();
    // STREAM with its LEN bit (0x0a): stream 0, one byte of data.
    beside.extend_from_slice(&[0x0a, 0x00, 0x01, 0x5a]);
    // A CRYPTO frame whose length runs past the payload.
    let mut overrun = named.clone();
    overrun.extend_from_slice(&[0x06, 0x00, 0x80, 0x01, 0x00, 0x00]);
    for (what, frames) in [
        ("a STREAM frame alone", vec![0x08, 0x00, 0x00]),
        ("a STREAM frame beside a listed name", beside),
        ("a CRYPTO frame that runs past the payload", overrun),
    ] {
        assert_eq!(
            judgement(&initial(&*crypto, &CLIENT_CID, &frames), &names),
            Verdict::Refuse(Refusal::Frames),
            "{what}"
        );
    }
}

/// Without a key, a first Initial's CRYPTO frames are joined by the
/// reassembly the hold uses, so the two paths read one packet alike: two
/// frames that carry different bytes at one offset are refused, whichever
/// comes first and whichever name each carries, and so is a frame that ends
/// past the 16 KiB libssl reads at the Initial level. A duplicate that agrees
/// is joined.
#[test]
fn a_first_initial_is_reassembled_as_the_hold_reassembles_it() {
    let crypto = nameless_crypto();
    let names = Names::new(&[LISTED.to_owned()]);
    let listed = named_hello(LISTED);
    let mut unlisted = named_hello(LISTED);
    let at = unlisted.len() - 1;
    unlisted[at] ^= 0x01;

    let mut agreeing = crypto_frame_at(0, &listed);
    agreeing.extend_from_slice(&crypto_frame_at(0, &listed));
    assert_eq!(
        judgement(&initial(&*crypto, &CLIENT_CID, &agreeing), &names),
        Verdict::Pass,
        "a duplicate that agrees"
    );
    for (first, second) in [(&listed, &unlisted), (&unlisted, &listed)] {
        let mut frames = crypto_frame_at(0, first);
        frames.extend_from_slice(&crypto_frame_at(0, second));
        assert_eq!(
            judgement(&initial(&*crypto, &CLIENT_CID, &frames), &names),
            Verdict::Refuse(Refusal::Conflict),
        );
    }

    let mut past = crypto_frame_at(0, &listed);
    past.extend_from_slice(&crypto_frame_at(HOLD_HELLO_BYTES, b"x"));
    assert_eq!(
        judgement(&initial(&*crypto, &CLIENT_CID, &past), &names),
        Verdict::Refuse(Refusal::TooLong),
        "a frame past the limit"
    );
    let mut up_to = crypto_frame_at(0, &listed);
    up_to.extend_from_slice(&crypto_frame_at(HOLD_HELLO_BYTES - 1, b"x"));
    assert_eq!(
        judgement(&initial(&*crypto, &CLIENT_CID, &up_to), &names),
        Verdict::Pass,
        "a frame that ends at the limit"
    );
}

// ---------------------------------------------------------------------------
// (e) The hold, with an ECH key (D115, batch 2)
// ---------------------------------------------------------------------------
//
// With an ECH key configured the gate holds the first packets of a new
// handshake until its ClientHello is whole, then releases every one of them
// to quinn or drops them all. The seam tests below drive `Screening`, which
// runs the receive path's own classification and hold under a clock the test
// moves; the on-wire tests send the same flights at a real server and assert
// that a dropped one draws nothing at all. The ClientHellos are written by
// rustls, an independent TLS implementation with client-side ECH, so what is
// judged is a real ClientHello and not one this binary spelled to agree with
// the parser.

/// The public name every test ECH key carries.
const PUBLIC_NAME: &str = "public.example";

/// A new ECH key under `config_id`.
fn ech_key(config_id: u8) -> Arc<EchKey> {
    Arc::new(EchKey::generate(PUBLIC_NAME, config_id, 0).expect("generate an ECH key"))
}

/// The gate's policy with `key` alone, the name list `names` and
/// `require_ech`.
fn hold_policy(key: &Arc<EchKey>, names: &[&str], require_ech: bool) -> Policy {
    keys_policy(EchKeySet::new(key.clone()), names, require_ech)
}

/// The gate's policy with the key set `keys`, the name list `names` and
/// `require_ech`.
fn keys_policy(keys: EchKeySet, names: &[&str], require_ech: bool) -> Policy {
    let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
    Policy::new(Names::new(&names), Some(Arc::new(keys)), require_ech)
}

/// The key set of a rotation: `current`, with `previous` still accepted.
fn rotation(current: &Arc<EchKey>, previous: &Arc<EchKey>) -> EchKeySet {
    EchKeySet::new(current.clone())
        .with_previous(previous.clone())
        .expect("the two keys have different config_ids")
}

/// X25519MLKEM768 first, as Surge orders its groups. An ECH ClientHello with
/// this share does not fit one Initial packet.
fn surge_groups() -> Vec<&'static dyn SupportedKxGroup> {
    vec![
        kx_group::X25519MLKEM768,
        kx_group::X25519,
        kx_group::SECP256R1,
    ]
}

/// X25519 alone, for an ECH ClientHello that fits one Initial packet.
fn small_groups() -> Vec<&'static dyn SupportedKxGroup> {
    vec![kx_group::X25519]
}

/// The client's QUIC transport parameters: `initial_source_connection_id`
/// (RFC 9000 §18.2, id 0x0f) and nothing else. quinn checks it against the
/// Source Connection ID of the Initial header, so with it the server goes on
/// with the handshake and answers.
fn client_parameters(scid: &[u8]) -> Vec<u8> {
    let mut parameters = vec![0x0f, u8::try_from(scid.len()).expect("a short id")];
    parameters.extend_from_slice(scid);
    parameters
}

/// The first CRYPTO bytes a rustls QUIC client writes, which is its
/// ClientHello, asking for `name`.
fn rustls_hello(offer: &Offer, groups: &[&'static dyn SupportedKxGroup], name: &str) -> Vec<u8> {
    let config = rustls_client(offer, Some(groups), rustls::RootCertStore::empty(), &["h3"]);
    let mut client = rustls::quic::ClientConnection::new(
        Arc::new(config),
        rustls::quic::Version::V1,
        rustls::pki_types::ServerName::try_from(name.to_owned()).expect("a name"),
        client_parameters(&Shape::default().scid),
    )
    .expect("start a rustls client");
    let mut hello = Vec::new();
    client.write_hs(&mut hello);
    assert_eq!(
        hello.first(),
        Some(&CLIENT_HELLO),
        "rustls wrote a ClientHello"
    );
    hello
}

/// The Initial packets of a first flight carrying `hello` as `pieces`
/// consecutive runs, one run to a packet, packet numbers from 0, addressed to
/// and keyed by `dcid`, carrying `token`.
fn hold_flight(
    crypto: &dyn quinn::crypto::ServerConfig,
    dcid: &[u8],
    token: &[u8],
    hello: &[u8],
    pieces: usize,
) -> Vec<Vec<u8>> {
    let run = hello.len().div_ceil(pieces);
    hello
        .chunks(run)
        .enumerate()
        .map(|(index, part)| {
            let shape = Shape {
                dcid: dcid.to_vec(),
                token: token.to_vec(),
                number: u8::try_from(index).expect("a few packets"),
                packet_length: MIN_INITIAL_DATAGRAM.max(part.len() + token.len() + 64),
                ..Shape::default()
            };
            shaped_initial(crypto, &shape, &crypto_frame_at(index * run, part))
        })
        .collect()
}

/// An address on loopback, told apart by its port.
fn from(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Feeds `datagrams` to `screening` from `peer`, all at `after`, and returns
/// what became of each and every drop on the way.
///
/// After every datagram the hold's byte count is checked against the bytes it
/// holds, summed again from its contents, so every test that feeds the hold
/// also checks that the count has not drifted.
#[track_caller]
fn feed(
    screening: &mut Screening,
    after: Duration,
    peer: SocketAddr,
    datagrams: &[Vec<u8>],
) -> (Vec<Screened>, Vec<(SocketAddr, Dropped)>) {
    let mut screened = Vec::new();
    let mut drops = Vec::new();
    for datagram in datagrams {
        let (verdict, dropped) = screening.receive(after, peer, datagram);
        assert_eq!(
            screening.recounted_bytes(),
            screening.held_bytes(),
            "the byte count is what the hold holds"
        );
        screened.push(verdict);
        drops.extend(dropped);
    }
    (screened, drops)
}

/// Asserts that feeding `datagrams` holds every one but the last, which
/// releases them all, in arrival order, with nothing dropped and nothing left
/// held.
#[track_caller]
fn released_whole(screening: &mut Screening, peer: SocketAddr, datagrams: &[Vec<u8>], what: &str) {
    let (screened, drops) = feed(screening, Duration::ZERO, peer, datagrams);
    let mut expected = vec![Screened::Held; datagrams.len() - 1];
    expected.push(Screened::Released);
    assert_eq!(screened, expected, "{what}");
    assert!(drops.is_empty(), "{what}: {drops:?}");
    let released: Vec<Vec<u8>> = screening
        .released()
        .into_iter()
        .map(|(source, bytes)| {
            assert_eq!(source, peer, "{what}: released for its own address");
            bytes
        })
        .collect();
    assert_eq!(
        released, datagrams,
        "{what}: every datagram, in arrival order"
    );
    assert_eq!(screening.flights(), 0, "{what}: nothing left held");
    assert_eq!(screening.held_bytes(), 0, "{what}: no byte left held");
}

/// Asserts that feeding `datagrams` drops their flight for `why` and releases
/// nothing.
#[track_caller]
fn dropped_whole(
    screening: &mut Screening,
    peer: SocketAddr,
    datagrams: &[Vec<u8>],
    why: &Dropped,
    what: &str,
) {
    let (screened, drops) = feed(screening, Duration::ZERO, peer, datagrams);
    assert_eq!(
        screened.last(),
        Some(&Screened::Dropped),
        "{what}: {screened:?}"
    );
    assert_eq!(drops, vec![(peer, why.clone())], "{what}");
    assert!(screening.released().is_empty(), "{what}: nothing released");
    assert_eq!(screening.flights(), 0, "{what}: nothing left held");
}

/// An ECH first flight is held until its ClientHello is whole and then
/// released in the order it arrived, however it is laid out: in one packet,
/// two, three, in order or not, with a duplicate, or with both of its packets
/// in one datagram. The outer name, the public name, is off the list and is
/// not looked at; `require_ech` is on and changes nothing for a flight whose
/// ECH opens.
#[test]
fn an_ech_flight_is_held_until_its_client_hello_is_whole_and_released_in_order() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    let offer = Offer::Ech(key.config_list());
    let small = rustls_hello(&offer, &small_groups(), "localhost");
    let large = rustls_hello(&offer, &surge_groups(), "localhost");
    assert!(
        small.len() < 1100 && large.len() > 1300,
        "one ClientHello fits a packet and one does not: {} and {}",
        small.len(),
        large.len()
    );

    let one = hold_flight(&*crypto, &CLIENT_CID, &[], &small, 1);
    let two = hold_flight(&*crypto, &CLIENT_CID, &[], &large, 2);
    let three = hold_flight(&*crypto, &CLIENT_CID, &[], &large, 3);
    let reversed: Vec<Vec<u8>> = two.iter().rev().cloned().collect();
    let middle_first = vec![three[1].clone(), three[2].clone(), three[0].clone()];
    let duplicate = vec![two[0].clone(), two[0].clone(), two[1].clone()];
    let coalesced = {
        let small_packets: Vec<Vec<u8>> = large
            .chunks(large.len().div_ceil(2))
            .enumerate()
            .map(|(index, part)| {
                let shape = Shape {
                    number: u8::try_from(index).expect("two"),
                    packet_length: part.len() + 64,
                    ..Shape::default()
                };
                shaped_initial(
                    &*crypto,
                    &shape,
                    &crypto_frame_at(index * large.len().div_ceil(2), part),
                )
            })
            .collect();
        vec![small_packets.concat()]
    };
    assert!(coalesced[0].len() >= MIN_INITIAL_DATAGRAM);

    for (what, datagrams) in [
        ("one packet", &one),
        ("two packets in order", &two),
        ("three packets in order", &three),
        ("two packets reversed", &reversed),
        ("three packets, middle first", &middle_first),
        ("a duplicate of the first packet", &duplicate),
        ("both packets coalesced in one datagram", &coalesced),
    ] {
        let mut screening = Screening::new(hold_policy(&key, &["localhost"], true));
        released_whole(&mut screening, from(1), datagrams, what);
        assert_eq!(screening.replay_entries(), 1, "{what}: its enc is recorded");
    }
}

/// The flight after a Retry: the same ClientHello, so the same `enc`, from
/// the same address, but addressed to the connection ID the Retry chose,
/// carrying its token, and keyed by that connection ID (RFC 9001 §5.2), so
/// every byte of every packet differs from the first flight's.
#[test]
fn the_flight_after_a_retry_is_admitted() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    let hello = rustls_hello(&Offer::Ech(key.config_list()), &surge_groups(), "localhost");
    let first = hold_flight(&*crypto, &CLIENT_CID, &[], &hello, 2);
    let after_retry = hold_flight(&*crypto, &SERVER_CID, &[0x7e; 40], &hello, 2);
    assert_ne!(first, after_retry);

    let mut screening = Screening::new(hold_policy(&key, &[], true));
    released_whole(&mut screening, from(1), &first, "the first flight");
    released_whole(
        &mut screening,
        from(1),
        &after_retry,
        "the flight after a Retry",
    );
    assert_eq!(screening.replay_entries(), 1, "one ClientHello, one entry");
}

/// The same flight from another address is a copy of somebody else's, and is
/// dropped; the copy cannot be told from the original by anything but where
/// it came from. A client that sends its first flight again, after a loss or
/// because the server's answer was lost, keeps its ClientHello and so its HPKE
/// `enc`, from the same address, and is admitted again, with one entry in the
/// replay record for both.
#[test]
fn the_same_ech_from_another_address_is_a_replay() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    let hello = rustls_hello(&Offer::Ech(key.config_list()), &surge_groups(), "localhost");
    let flight = hold_flight(&*crypto, &CLIENT_CID, &[], &hello, 2);
    let rewrapped = hold_flight(&*crypto, &[0x5c; 8], &[], &hello, 2);

    for require_ech in [false, true] {
        let mut screening = Screening::new(hold_policy(&key, &[], require_ech));
        released_whole(&mut screening, from(1), &flight, "the original");
        dropped_whole(
            &mut screening,
            from(2),
            &flight,
            &Dropped::Replayed,
            "the copy from another port",
        );
        dropped_whole(
            &mut screening,
            from(2),
            &rewrapped,
            &Dropped::Replayed,
            "its ClientHello under a new connection ID from another port",
        );
        // The original's address is still admitted.
        released_whole(&mut screening, from(1), &flight, "the original again");
        assert_eq!(screening.replay_entries(), 1, "one ClientHello, one entry");
    }
}

/// One ClientHello of a given kind, two packets of it.
struct Row {
    what: &'static str,
    hello: Vec<u8>,
    /// The name list, and what becomes of the flight with `require_ech` off
    /// and on: `None` admitted, `Some` dropped for that reason.
    names: &'static [&'static str],
    off: Option<Dropped>,
    on: Option<Dropped>,
}

/// The ClientHello `hello` with its ECH payload's last byte changed, which is
/// inside the AEAD tag.
fn damaged_ech(hello: &[u8]) -> Vec<u8> {
    let mut hello = hello.to_vec();
    let body = volto::hello::client_hello_body(&hello).expect("a whole ClientHello");
    let ech = volto::hello::ech_outer(body).expect("an ECH extension");
    hello[4 + ech.payload.end - 1] ^= 0x01;
    hello
}

/// Every row of the rule table, with `require_ech` off and on. A dropped
/// flight releases nothing, which on the socket is a flight quinn never sees.
#[test]
fn every_row_of_the_rule_table_is_what_the_hold_does() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    let copied_id = ech_key(7);
    let other = ech_key(9);
    let groups = surge_groups();
    let ours = rustls_hello(&Offer::Ech(key.config_list()), &groups, "localhost");
    let inner_only = client_hello(&extension(0xfe0d, &[0x01]));

    let rows = [
        Row {
            what: "no ECH, a name on the list",
            hello: rustls_hello(&Offer::Plain, &groups, "localhost"),
            names: &["localhost"],
            off: None,
            on: Some(Dropped::EchRequired),
        },
        Row {
            what: "no ECH, a name off the list",
            hello: rustls_hello(&Offer::Plain, &groups, UNLISTED),
            names: &["localhost"],
            off: Some(Dropped::OtherName(UNLISTED.as_bytes().to_vec())),
            on: Some(Dropped::EchRequired),
        },
        Row {
            what: "no ECH, no list",
            hello: rustls_hello(&Offer::Plain, &groups, UNLISTED),
            names: &[],
            off: None,
            on: Some(Dropped::EchRequired),
        },
        Row {
            what: "no ECH, no server_name, the list on",
            hello: client_hello(&[]),
            names: &["localhost"],
            off: Some(Dropped::Anonymous),
            on: Some(Dropped::EchRequired),
        },
        Row {
            what: "ECH the key opens, the public name off the list",
            hello: ours.clone(),
            names: &["localhost"],
            off: None,
            on: None,
        },
        Row {
            what: "GREASE ECH",
            hello: rustls_hello(&Offer::Grease, &groups, "localhost"),
            names: &["localhost"],
            off: Some(Dropped::EchNotOpened),
            on: Some(Dropped::EchNotOpened),
        },
        Row {
            what: "ECH under another key with our config_id",
            hello: rustls_hello(&Offer::Ech(copied_id.config_list()), &groups, "localhost"),
            names: &["localhost"],
            off: Some(Dropped::EchNotOpened),
            on: Some(Dropped::EchNotOpened),
        },
        Row {
            what: "ECH under another key and config_id",
            hello: rustls_hello(&Offer::Ech(other.config_list()), &groups, "localhost"),
            names: &[],
            off: Some(Dropped::EchNotOpened),
            on: Some(Dropped::EchNotOpened),
        },
        Row {
            what: "ECH under our key with a damaged payload",
            hello: damaged_ech(&ours),
            names: &[],
            off: Some(Dropped::EchNotOpened),
            on: Some(Dropped::EchNotOpened),
        },
        Row {
            what: "an ECH extension of the inner type",
            hello: inner_only,
            names: &[],
            off: Some(Dropped::EchNotOpened),
            on: Some(Dropped::EchNotOpened),
        },
        Row {
            what: "a first message that is not a ClientHello",
            hello: vec![0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00],
            names: &[],
            off: Some(Dropped::NotClientHello),
            on: Some(Dropped::NotClientHello),
        },
    ];

    for row in rows {
        let pieces = if row.hello.len() > 1000 { 2 } else { 1 };
        let flight = hold_flight(&*crypto, &CLIENT_CID, &[], &row.hello, pieces);
        for (require_ech, expected) in [(false, &row.off), (true, &row.on)] {
            let what = format!("{}, require_ech = {require_ech}", row.what);
            let mut screening = Screening::new(hold_policy(&key, row.names, require_ech));
            match expected {
                None => released_whole(&mut screening, from(1), &flight, &what),
                Some(why) => dropped_whole(&mut screening, from(1), &flight, why, &what),
            }
        }
    }
}

/// The two drops of the hold that are outside the rule table, each beside the
/// same flight without its defect, which is released.
///
/// A packet carrying a frame no Initial may carry: a STREAM frame, which
/// RFC 9000 §12.4 Table 3 marks `__01`, 0-RTT and 1-RTT only, beside the
/// CRYPTO frame of a whole ClientHello. And a whole ClientHello whose
/// extension block's length runs one byte past the end of the message.
#[test]
fn a_frame_no_initial_may_carry_or_an_unreadable_extension_block_drops_the_flight() {
    let crypto = nameless_crypto();
    let key = ech_key(7);

    let ech = rustls_hello(&Offer::Ech(key.config_list()), &small_groups(), "localhost");
    let mut with_stream = crypto_frame_at(0, &ech);
    // STREAM with its LEN bit (0x0a): stream 0, one byte of data.
    with_stream.extend_from_slice(&[0x0a, 0x00, 0x01, 0x5a]);
    let mut screening = Screening::new(hold_policy(&key, &[], false));
    released_whole(
        &mut screening,
        from(1),
        &[initial(&*crypto, &CLIENT_CID, &crypto_frame_at(0, &ech))],
        "the CRYPTO frame alone",
    );
    let mut screening = Screening::new(hold_policy(&key, &[], false));
    dropped_whole(
        &mut screening,
        from(1),
        &[initial(&*crypto, &CLIENT_CID, &with_stream)],
        &Dropped::Frames,
        "a STREAM frame beside it",
    );

    let extensions = sni_extension("localhost");
    let named = client_hello(&extensions);
    let mut overrun = named.clone();
    let at = named.len() - extensions.len() - 2;
    let length = u16::from_be_bytes([named[at], named[at + 1]]);
    overrun[at..at + 2].copy_from_slice(&(length + 1).to_be_bytes());
    let mut screening = Screening::new(hold_policy(&key, &["localhost"], false));
    released_whole(
        &mut screening,
        from(1),
        &[initial(&*crypto, &CLIENT_CID, &crypto_frame_at(0, &named))],
        "the extension block as written",
    );
    let mut screening = Screening::new(hold_policy(&key, &["localhost"], false));
    dropped_whole(
        &mut screening,
        from(1),
        &[initial(
            &*crypto,
            &CLIENT_CID,
            &crypto_frame_at(0, &overrun),
        )],
        &Dropped::UnreadableExtensions,
        "an extension block one byte longer than the message",
    );
}

/// A flight whose ClientHello never completes is held for its lifetime and
/// then dropped, and nothing of it is ever released. That covers the first
/// packet of a flight whose second is lost, and the three shapes that draw an
/// acknowledgement from the stateless gate (an Initial with a PING alone, half
/// a ClientHello, a CRYPTO frame past offset 0), which with a key are silent.
#[test]
fn a_flight_that_never_completes_is_dropped_when_its_time_is_up() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    let hello = rustls_hello(&Offer::Ech(key.config_list()), &surge_groups(), "localhost");
    let flight = hold_flight(&*crypto, &CLIENT_CID, &[], &hello, 2);
    let named = named_hello("localhost");

    for (what, datagram) in [
        ("the first packet of two", flight[0].clone()),
        (
            "a PING and nothing else",
            initial(&*crypto, &CLIENT_CID, &[0x01]),
        ),
        (
            "half a ClientHello",
            initial(
                &*crypto,
                &CLIENT_CID,
                &crypto_frame_at(0, &named[..named.len() / 2]),
            ),
        ),
        (
            "a CRYPTO frame at offset 64",
            initial(&*crypto, &CLIENT_CID, &crypto_frame_at(64, &named)),
        ),
    ] {
        let mut screening = Screening::new(hold_policy(&key, &[], false));
        let (screened, drops) = feed(&mut screening, Duration::ZERO, from(1), &[datagram]);
        assert_eq!(screened, vec![Screened::Held], "{what}");
        assert!(drops.is_empty(), "{what}");

        // Just inside the lifetime, another flight's packet changes nothing
        // for this one.
        let inside = HOLD_LIFETIME - Duration::from_millis(1);
        let other = initial(&*crypto, &[0x99; 8], &[0x01]);
        let (_, drops) = feed(
            &mut screening,
            inside,
            from(2),
            std::slice::from_ref(&other),
        );
        assert!(drops.is_empty(), "{what}: still within its lifetime");
        assert_eq!(screening.flights(), 2, "{what}");

        // At the lifetime, the next packet that reaches the hold frees it.
        let (_, drops) = feed(&mut screening, HOLD_LIFETIME, from(3), &[other]);
        assert_eq!(drops, vec![(from(1), Dropped::Expired)], "{what}");
        assert!(screening.released().is_empty(), "{what}: nothing released");
    }

    // The missing second packet, arriving after its flight was dropped, starts
    // a flight of its own that has no beginning and is never released.
    let mut screening = Screening::new(hold_policy(&key, &[], false));
    feed(&mut screening, Duration::ZERO, from(1), &flight[..1]);
    let (screened, _) = feed(&mut screening, HOLD_LIFETIME, from(1), &flight[1..]);
    assert_eq!(screened, vec![Screened::Held]);
    assert!(screening.released().is_empty());
}

/// With the table full, a new flight evicts the oldest one, which is dropped,
/// and the new flight completes as it would have.
#[test]
fn a_full_hold_evicts_its_oldest_flight() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    let hello = rustls_hello(&Offer::Ech(key.config_list()), &surge_groups(), "localhost");
    let mut screening = Screening::new(hold_policy(&key, &[], true));

    let stuck: Vec<Vec<Vec<u8>>> = (0..HOLD_FLIGHTS)
        .map(|index| {
            let mut dcid = [0x10u8; 8];
            dcid[..2].copy_from_slice(&u16::try_from(index).expect("small").to_be_bytes());
            hold_flight(&*crypto, &dcid, &[], &hello, 2)
        })
        .collect();
    for flight in &stuck {
        let (screened, drops) = feed(&mut screening, Duration::ZERO, from(1), &flight[..1]);
        assert_eq!(screened, vec![Screened::Held]);
        assert!(drops.is_empty());
    }
    assert_eq!(screening.flights(), HOLD_FLIGHTS);

    let newcomer = hold_flight(&*crypto, &CLIENT_CID, &[], &hello, 2);
    let (screened, drops) = feed(&mut screening, Duration::ZERO, from(2), &newcomer);
    assert_eq!(screened, vec![Screened::Held, Screened::Released]);
    assert_eq!(
        drops,
        vec![(from(1), Dropped::Evicted)],
        "the oldest made way"
    );
    assert_eq!(screening.released().len(), 2);
    assert_eq!(screening.flights(), HOLD_FLIGHTS - 1);

    // The evicted flight's second packet finds no flight to complete.
    let (screened, _) = feed(&mut screening, Duration::ZERO, from(1), &stuck[0][1..]);
    assert_eq!(screened, vec![Screened::Held]);
    assert!(screening.released().is_empty());
}

/// Two packets of one flight that carry different bytes at one offset drop
/// the flight: the ClientHello judged has to be the one quinn would hand
/// libssl, and with two versions of a byte there is no such ClientHello.
#[test]
fn fragments_that_disagree_drop_the_flight() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    let hello = rustls_hello(&Offer::Ech(key.config_list()), &surge_groups(), "localhost");
    let flight = hold_flight(&*crypto, &CLIENT_CID, &[], &hello, 2);
    let mut changed = hello.clone();
    changed[10] ^= 0x01;
    let liar = initial(&*crypto, &CLIENT_CID, &crypto_frame_at(0, &changed[..64]));

    let mut screening = Screening::new(hold_policy(&key, &[], false));
    feed(&mut screening, Duration::ZERO, from(1), &flight[..1]);
    dropped_whole(
        &mut screening,
        from(1),
        &[liar],
        &Dropped::Conflict,
        "a second version of a byte",
    );
}

/// One packet whose own fragments cannot all join the stream drops its flight,
/// and the hold's byte count ends where it started.
///
/// Two shapes, each sent once into an empty hold and once beside a held flight
/// from another address. Two CRYPTO frames at offset 0 that disagree reach
/// `Hold::write`, where the first fragment has grown the stream before the
/// second is refused, so the count has to give that growth back. An
/// underflow of the count in the empty hold would panic under `poll_recv`. A
/// fragment that fits followed by an empty CRYPTO frame at an offset past
/// `HOLD_HELLO_BYTES` is dropped before anything is written, because the
/// limit is checked on every fragment ahead of the write; it is kept as a
/// check that this early drop leaves the count alone too.
#[test]
fn a_packet_whose_own_fragments_disagree_drops_its_flight_and_every_byte_of_it() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    let hello = rustls_hello(&Offer::Ech(key.config_list()), &surge_groups(), "localhost");
    let other = hold_flight(&*crypto, &[0x61; 8], &[], &hello, 2);

    let mut disagree = crypto_frame_at(0, b"abcd");
    disagree.extend_from_slice(&crypto_frame_at(0, b"Xbcd"));
    let mut past_the_limit = crypto_frame_at(15_000, &[0x5a; 64]);
    past_the_limit.push(0x06);
    past_the_limit.extend_from_slice(&varint(HOLD_HELLO_BYTES + 1));
    past_the_limit.extend_from_slice(&varint(0));

    for (what, frames, why) in [
        (
            "two CRYPTO frames at offset 0 that disagree",
            disagree,
            Dropped::Conflict,
        ),
        (
            "a fragment, then an empty CRYPTO frame past the limit",
            past_the_limit,
            Dropped::TooLong,
        ),
    ] {
        let datagram = initial(&*crypto, &CLIENT_CID, &frames);

        let mut screening = Screening::new(hold_policy(&key, &[], false));
        dropped_whole(
            &mut screening,
            from(1),
            std::slice::from_ref(&datagram),
            &why,
            what,
        );
        assert_eq!(screening.held_bytes(), 0, "{what}: an empty hold");

        let mut screening = Screening::new(hold_policy(&key, &[], false));
        feed(&mut screening, Duration::ZERO, from(2), &other[..1]);
        let before = screening.held_bytes();
        assert!(before > 0);
        let (screened, drops) = feed(&mut screening, Duration::ZERO, from(1), &[datagram]);
        assert_eq!(screened, vec![Screened::Dropped], "{what}");
        assert_eq!(drops, vec![(from(1), why.clone())], "{what}");
        assert_eq!(
            screening.held_bytes(),
            before,
            "{what}: beside another flight"
        );
        // The other flight is untouched and still completes.
        let (screened, drops) = feed(&mut screening, Duration::ZERO, from(2), &other[1..]);
        assert_eq!(screened, vec![Screened::Released], "{what}");
        assert!(drops.is_empty(), "{what}");
        assert_eq!(screening.released().len(), 2, "{what}");
        assert_eq!(screening.held_bytes(), 0, "{what}");
    }
}

/// The hold's bounds, by value.
///
/// Every other hold test reads these constants from the code they bound, so
/// they stay green whatever the values are. These are what an unauthenticated
/// peer can make the server keep, in time, in flights and in bytes, so a change
/// to any of them has to be a deliberate edit of this test, with its reason in
/// the commit.
#[test]
fn the_hold_bounds_are_the_values_they_are_documented_as() {
    assert_eq!(HOLD_LIFETIME, Duration::from_secs(8));
    assert_eq!(HOLD_FLIGHTS, 64);
    assert_eq!(HOLD_HELLO_BYTES, 16 * 1024);
    assert_eq!(HOLD_FLIGHT_BYTES, 64 * 1024);
    assert_eq!(HOLD_TOTAL_BYTES, 4 << 20);
    assert_eq!(REPLAY_ENTRIES, 1 << 20);
}

/// Whatever is sent, the hold stays inside its bounds: no more flights than
/// the table holds, a flight that grows past its own budget dropped, and a
/// ClientHello longer than libssl reads dropped as soon as its length says
/// so.
///
/// Nothing here completes, so no released datagram waits, and the held flights
/// alone cannot pass `HOLD_TOTAL_BYTES`, which is `HOLD_FLIGHTS` flights of
/// `HOLD_FLIGHT_BYTES`. The byte bound is reached in
/// `released_datagrams_that_wait_make_the_hold_evict_its_oldest_flights`.
#[test]
fn the_hold_stays_inside_its_bounds_under_a_flood() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    let mut screening = Screening::new(hold_policy(&key, &[], false));

    // A ClientHello header claiming just under 16 KiB, so the flight waits
    // for the rest of it, and then runs of its body.
    let mut header = vec![CLIENT_HELLO, 0x00, 0x3f, 0xf0];
    header.extend_from_slice(&[0x03, 0x03]);
    let body = vec![0x5a; 1400];
    let packet = |dcid: &[u8], number: usize, frames: &[u8]| {
        let shape = Shape {
            dcid: dcid.to_vec(),
            packet_length: 1500,
            number: u8::try_from(number % 200).expect("small"),
            ..Shape::default()
        };
        shaped_initial(&*crypto, &shape, frames)
    };
    let bounded = |screening: &Screening| {
        assert!(screening.flights() <= HOLD_FLIGHTS, "the table bound");
        assert!(screening.held_bytes() <= HOLD_TOTAL_BYTES, "the byte bound");
        assert_eq!(
            screening.recounted_bytes(),
            screening.held_bytes(),
            "the byte bound is checked against what is held"
        );
    };

    // One flight sent its header and then the same run again and again:
    // nothing new for the stream, 1500 more bytes of datagram each time.
    let opening = packet(&[0x21; 8], 0, &crypto_frame_at(0, &header));
    let again = packet(&[0x21; 8], 1, &crypto_frame_at(header.len(), &body));
    feed(&mut screening, Duration::ZERO, from(1), &[opening]);
    let mut outgrown = None;
    for round in 0..(HOLD_FLIGHT_BYTES / 1500 + 2) {
        let (_, drops) = screening.receive(Duration::ZERO, from(1), &again);
        bounded(&screening);
        if drops.contains(&(from(1), Dropped::TooBig)) {
            outgrown = Some(round);
            break;
        }
    }
    // Round `r` would make the flight count its opening datagram, `r + 1`
    // runs and the stream up to the end of the run, which counts its length
    // and a bitmap of one bit per byte in 64-bit words. The drop comes at the
    // first round past the budget.
    let end = header.len() + body.len();
    let stream = end + end.div_ceil(64) * 8;
    let expected = (HOLD_FLIGHT_BYTES - stream) / again.len() - 1;
    assert_eq!(
        outgrown.expect("the flight outgrew HOLD_FLIGHT_BYTES"),
        expected,
        "dropped at the first datagram past the budget"
    );

    // Twice as many flights as the table holds, each sending runs of its body.
    for round in 0..12usize {
        for flight in 0..(2 * HOLD_FLIGHTS) {
            let mut dcid = [0x20u8; 8];
            dcid[..2].copy_from_slice(&u16::try_from(flight).expect("small").to_be_bytes());
            let frames = if round == 0 {
                crypto_frame_at(0, &header)
            } else {
                crypto_frame_at(header.len() + (round - 1) * body.len(), &body)
            };
            screening.receive(Duration::ZERO, from(2), &packet(&dcid, round, &frames));
            bounded(&screening);
        }
    }
    assert_eq!(
        screening.flights(),
        HOLD_FLIGHTS,
        "the table is full and no fuller"
    );
    assert!(
        screening.released().is_empty(),
        "nothing in it was a ClientHello"
    );

    // A ClientHello whose length is past what libssl reads is dropped at once,
    // and so is a CRYPTO frame that reaches past it.
    let mut screening = Screening::new(hold_policy(&key, &[], false));
    let long = [CLIENT_HELLO, 0x00, 0x40, 0x00];
    const { assert!(HOLD_HELLO_BYTES < 0x4000 + 4) };
    let datagram = initial(&*crypto, &[0x33; 8], &crypto_frame_at(0, &long));
    dropped_whole(
        &mut screening,
        from(9),
        &[datagram],
        &Dropped::TooLong,
        "a length past libssl's",
    );
    let mut frame = vec![0x06];
    frame.extend_from_slice(&varint(HOLD_HELLO_BYTES));
    frame.extend_from_slice(&varint(1));
    frame.push(0x00);
    let datagram = initial(&*crypto, &[0x34; 8], &frame);
    dropped_whole(
        &mut screening,
        from(9),
        &[datagram],
        &Dropped::TooLong,
        "an offset past libssl's",
    );
}

/// Released datagrams count against `HOLD_TOTAL_BYTES` until the next receive
/// call hands them to quinn. With the bound nearly spent by them, a flight that
/// grows evicts the oldest flights ahead of it, one at a time, until it fits,
/// and a flight with none ahead of it left to evict is dropped itself. The
/// released datagrams are never evicted, and the count never passes the
/// bound.
///
/// On the socket the released queue fills within one receive batch, since
/// `screen_one` runs for every datagram of the batch before `deliver` takes
/// the queue.
#[test]
fn released_datagrams_that_wait_make_the_hold_evict_its_oldest_flights() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    // No list and no `require_ech`, so a whole ClientHello without ECH is
    // admitted and released at once.
    let mut screening = Screening::new(hold_policy(&key, &[], false));
    let admitted = initial(
        &*crypto,
        &CLIENT_CID,
        &crypto_frame_at(0, &named_hello("localhost")),
    );
    // A flight that never completes, one datagram at a time.
    let ping = |dcid: u8| initial(&*crypto, &[dcid; 8], &[0x01]);
    let step = MIN_INITIAL_DATAGRAM;
    let receive = |screening: &mut Screening, from: SocketAddr, datagram: &[u8]| {
        let outcome = screening.receive(Duration::ZERO, from, datagram);
        assert!(
            screening.held_bytes() <= HOLD_TOTAL_BYTES,
            "the byte bound: {} counted",
            screening.held_bytes()
        );
        assert_eq!(screening.recounted_bytes(), screening.held_bytes());
        outcome
    };

    // Admitted flights nobody takes, until less than three datagrams of room
    // is left.
    let mut waiting = 0;
    while screening.held_bytes() + 3 * step <= HOLD_TOTAL_BYTES {
        assert_eq!(
            receive(&mut screening, from(1), &admitted),
            (Screened::Released, Vec::new())
        );
        waiting += 1;
    }
    let room = HOLD_TOTAL_BYTES - screening.held_bytes();
    assert!((2 * step..3 * step).contains(&room), "{room} bytes of room");
    assert_eq!(screening.flights(), 0);

    // Two flights fit, oldest first.
    for (port, dcid) in [(2, 0x61), (3, 0x62)] {
        assert_eq!(
            receive(&mut screening, from(port), &ping(dcid)),
            (Screened::Held, Vec::new())
        );
    }
    // A third flight has no room, and the oldest makes way for it, though the
    // table has room for sixty-one more.
    assert_eq!(
        receive(&mut screening, from(4), &ping(0x63)),
        (Screened::Held, vec![(from(2), Dropped::Evicted)])
    );
    assert_eq!(screening.flights(), 2);
    // Its next datagram has none either, and the next oldest makes way.
    assert_eq!(
        receive(&mut screening, from(4), &ping(0x63)),
        (Screened::Held, vec![(from(3), Dropped::Evicted)])
    );
    assert_eq!(screening.flights(), 1);
    // With no flight ahead of it, it is the one dropped.
    assert_eq!(
        receive(&mut screening, from(4), &ping(0x63)),
        (Screened::Dropped, vec![(from(4), Dropped::Evicted)])
    );
    assert_eq!(screening.flights(), 0);

    // Every released datagram is still there, in order, and taking them
    // empties the hold.
    let released = screening.released();
    assert_eq!(released.len(), waiting);
    assert!(
        released
            .iter()
            .all(|(source, bytes)| *source == from(1) && *bytes == admitted)
    );
    assert_eq!(screening.held_bytes(), 0);
}

/// No reload empties the replay record: not one that keeps the key, not one
/// to a key that was not accepted before, and not one that brings a removed
/// key back, after which a flight recorded under it is still a replay. A
/// policy without a key empties the hold. `a_rotation_keeps_the_replay_record`
/// covers a reload that keeps the old key as the previous one.
#[test]
fn no_reload_empties_the_replay_record_and_no_key_empties_the_hold() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    let hello = rustls_hello(&Offer::Ech(key.config_list()), &surge_groups(), "localhost");
    let flight = hold_flight(&*crypto, &CLIENT_CID, &[], &hello, 2);

    let mut screening = Screening::new(hold_policy(&key, &[], false));
    released_whole(&mut screening, from(1), &flight, "admitted");
    assert_eq!(screening.replay_entries(), 1);

    // The same key read again, as a reload of an unchanged file does.
    let same = Arc::new(EchKey::from_pem(key.to_pem().as_bytes()).expect("the same key"));
    screening.set(hold_policy(&same, &[], false));
    assert_eq!(
        screening.replay_entries(),
        1,
        "the same key keeps its record"
    );
    dropped_whole(
        &mut screening,
        from(2),
        &flight,
        &Dropped::Replayed,
        "still a replay",
    );

    screening.set(hold_policy(&ech_key(7), &[], false));
    assert_eq!(
        screening.replay_entries(),
        1,
        "a new key keeps the record of the old one"
    );
    dropped_whole(
        &mut screening,
        from(2),
        &flight,
        &Dropped::EchNotOpened,
        "a flight under the removed key",
    );
    screening.set(hold_policy(&same, &[], false));
    dropped_whole(
        &mut screening,
        from(2),
        &flight,
        &Dropped::Replayed,
        "the removed key is back, and its recorded flight is still a replay",
    );

    let mut screening = Screening::new(hold_policy(&key, &[], false));
    feed(&mut screening, Duration::ZERO, from(1), &flight[..1]);
    assert_eq!(screening.flights(), 1);
    screening.set(Names::new(&[]));
    assert_eq!(screening.flights(), 0, "no key, nothing held");
    assert_eq!(screening.held_bytes(), 0);
}

/// During a rotation the gate opens an ECH extension with the key whose
/// config_id it names. A flight under the previous key is admitted, as is one
/// under the current key. A flight that names the previous key's config_id and
/// was sealed to another key is dropped, and so is one that names neither
/// config_id. With `require_ech` off and on.
#[test]
fn during_a_rotation_ech_is_opened_with_the_key_its_config_id_names() {
    let crypto = nameless_crypto();
    let previous = ech_key(7);
    let current = ech_key(9);
    let groups = surge_groups();
    let flight = |list: Vec<u8>| {
        let hello = rustls_hello(&Offer::Ech(list), &groups, "localhost");
        hold_flight(&*crypto, &CLIENT_CID, &[], &hello, 2)
    };
    let under_previous = flight(previous.config_list());
    let under_current = flight(current.config_list());
    let previous_id_other_key = flight(ech_key(7).config_list());
    let neither_id = flight(ech_key(8).config_list());

    for require_ech in [false, true] {
        let policy = || keys_policy(rotation(&current, &previous), &["localhost"], require_ech);
        let what = |what: &str| format!("{what}, require_ech = {require_ech}");

        let mut screening = Screening::new(policy());
        released_whole(
            &mut screening,
            from(1),
            &under_previous,
            &what("ECH under the previous key"),
        );
        assert_eq!(screening.replay_entries(), 1, "its enc is recorded");

        let mut screening = Screening::new(policy());
        released_whole(
            &mut screening,
            from(1),
            &under_current,
            &what("ECH under the current key"),
        );

        for (shape, datagrams) in [
            (
                "ECH that names the previous config_id, sealed to another key",
                &previous_id_other_key,
            ),
            ("ECH that names neither config_id", &neither_id),
        ] {
            let mut screening = Screening::new(policy());
            dropped_whole(
                &mut screening,
                from(1),
                datagrams,
                &Dropped::EchNotOpened,
                &what(shape),
            );
            assert_eq!(screening.replay_entries(), 0, "{}", what(shape));
        }
    }
}

/// A flight under the previous key, sent again from another address, is a
/// replay and is dropped, as it is under the current key; from its own
/// address it is admitted again.
#[test]
fn the_same_ech_under_the_previous_key_from_another_address_is_a_replay() {
    let crypto = nameless_crypto();
    let previous = ech_key(7);
    let current = ech_key(9);
    let hello = rustls_hello(
        &Offer::Ech(previous.config_list()),
        &surge_groups(),
        "localhost",
    );
    let flight = hold_flight(&*crypto, &CLIENT_CID, &[], &hello, 2);
    let rewrapped = hold_flight(&*crypto, &[0x5c; 8], &[], &hello, 2);

    let mut screening = Screening::new(keys_policy(rotation(&current, &previous), &[], false));
    released_whole(&mut screening, from(1), &flight, "the original");
    dropped_whole(
        &mut screening,
        from(2),
        &flight,
        &Dropped::Replayed,
        "the copy from another port",
    );
    dropped_whole(
        &mut screening,
        from(2),
        &rewrapped,
        &Dropped::Replayed,
        "its ClientHello under a new connection ID from another port",
    );
    released_whole(&mut screening, from(1), &flight, "the original again");
    assert_eq!(screening.replay_entries(), 1, "one ClientHello, one entry");
}

/// The usual rotation, where the old current key becomes the previous key,
/// keeps the replay record: an `enc` recorded under the old key before the
/// reload is still a replay from another address after it, and its own
/// address is still admitted. The reload reads the old key from its file
/// again, as a real reload does. A reload that then removes the previous key
/// keeps the record too.
#[test]
fn a_rotation_keeps_the_replay_record() {
    let crypto = nameless_crypto();
    let old = ech_key(7);
    let new = ech_key(9);
    let hello = rustls_hello(&Offer::Ech(old.config_list()), &surge_groups(), "localhost");
    let flight = hold_flight(&*crypto, &CLIENT_CID, &[], &hello, 2);
    let rewrapped = hold_flight(&*crypto, &[0x5c; 8], &[], &hello, 2);
    let new_hello = rustls_hello(&Offer::Ech(new.config_list()), &surge_groups(), "localhost");
    let new_flight = hold_flight(&*crypto, &[0x5d; 8], &[], &new_hello, 2);

    let mut screening = Screening::new(hold_policy(&old, &[], false));
    released_whole(
        &mut screening,
        from(1),
        &flight,
        "admitted under the old key",
    );
    assert_eq!(screening.replay_entries(), 1);

    let reread = Arc::new(EchKey::from_pem(old.to_pem().as_bytes()).expect("the old key"));
    screening.set(keys_policy(rotation(&new, &reread), &[], false));
    assert_eq!(
        screening.replay_entries(),
        1,
        "the rotation keeps the record"
    );
    dropped_whole(
        &mut screening,
        from(2),
        &rewrapped,
        &Dropped::Replayed,
        "the recorded enc from another address after the rotation",
    );
    released_whole(
        &mut screening,
        from(1),
        &flight,
        "the recorded flight from its own address after the rotation",
    );
    released_whole(
        &mut screening,
        from(3),
        &new_flight,
        "a flight under the new key",
    );
    assert_eq!(screening.replay_entries(), 2);

    screening.set(hold_policy(&new, &[], false));
    assert_eq!(
        screening.replay_entries(),
        2,
        "removing the previous key keeps the record of the current one"
    );
    dropped_whole(
        &mut screening,
        from(4),
        &new_flight,
        &Dropped::Replayed,
        "the new key's recorded enc from another address",
    );
}

/// After a reload that removes the previous key, its list gets silence: a
/// flight under it is dropped, including one whose first packet was held
/// before the reload and whose second arrived after it, because the hold
/// judges a flight under the policy in force when it completes.
#[test]
fn after_a_reload_that_removes_the_previous_key_its_list_gets_silence() {
    let crypto = nameless_crypto();
    let previous = ech_key(7);
    let current = ech_key(9);
    let hello = rustls_hello(
        &Offer::Ech(previous.config_list()),
        &surge_groups(),
        "localhost",
    );
    let flight = hold_flight(&*crypto, &CLIENT_CID, &[], &hello, 2);
    let straddling = hold_flight(&*crypto, &[0x5e; 8], &[], &hello, 2);

    let mut screening = Screening::new(keys_policy(rotation(&current, &previous), &[], false));
    let (screened, drops) = feed(&mut screening, Duration::ZERO, from(2), &straddling[..1]);
    assert_eq!(screened, vec![Screened::Held]);
    assert!(drops.is_empty());

    screening.set(hold_policy(&current, &[], false));
    dropped_whole(
        &mut screening,
        from(2),
        &straddling[1..],
        &Dropped::EchNotOpened,
        "a flight that was held under the previous key and completed after the reload",
    );
    dropped_whole(
        &mut screening,
        from(1),
        &flight,
        &Dropped::EchNotOpened,
        "a flight under the removed key",
    );
}

/// Without an ECH key the gate keeps no state: a first packet is judged on its
/// own and passed or refused, exactly as `judgement` judges it.
#[test]
fn without_an_ech_key_the_gate_holds_nothing() {
    let crypto = nameless_crypto();
    let (first, _) = large_first_flight(&*crypto, UNLISTED, 0..0);
    let names = Names::new(&[LISTED.to_owned()]);
    let mut screening = Screening::new(Names::new(&[LISTED.to_owned()]));
    let (screened, drops) = feed(
        &mut screening,
        Duration::ZERO,
        from(1),
        std::slice::from_ref(&first),
    );
    assert_eq!(screened, vec![Screened::Passed]);
    assert_eq!(judgement(&first, &names), Verdict::Pass);
    assert!(drops.is_empty());
    let named = initial(
        &*crypto,
        &CLIENT_CID,
        &crypto_frame_at(0, &named_hello(UNLISTED)),
    );
    let (screened, _) = feed(&mut screening, Duration::ZERO, from(1), &[named]);
    assert_eq!(
        screened,
        vec![Screened::Refused(Refusal::OtherName(
            UNLISTED.as_bytes().to_vec()
        ))]
    );
    assert_eq!(screening.flights(), 0);
    assert_eq!(screening.held_bytes(), 0);
}

// On the wire: a real server with an ECH key, a raw UDP socket, and the whole
// of `PATIENCE` to prove that a dropped flight draws nothing. Every silence is
// paired with an answer from the same server to a flight it admits, which is
// what says the flights are well formed enough to be answered at all.

/// A server with an ECH key, `require_ech` and the name list `names`, and the
/// directory holding its key file, which has to outlive it.
async fn ech_server(key: &EchKey, require_ech: bool, names: &[&str]) -> (TestServer, TempDir) {
    let keys = TempDir::new("ech-gate");
    let path = keys.path().join("ech.pem");
    volto::tls::write_new_key_file(&path, key).expect("write the key file");
    let names: Vec<String> = names.iter().map(|name| format!("\"{name}\"")).collect();
    let server = TestServer::start_with(&format!(
        "ech_key = \"{}\"\n[security]\nallow_private_networks = true\n\
         require_ech = {require_ech}\nexpected_sni = [{}]\n",
        path.display(),
        names.join(", ")
    ))
    .await;
    (server, keys)
}

/// Sends every flight of `shapes` from a socket of its own, all at once, and
/// asserts that none of them draws a single datagram.
#[track_caller]
fn all_silent<'a>(
    addr: SocketAddr,
    shapes: Vec<(&'static str, Vec<Vec<u8>>)>,
) -> impl Future<Output = ()> + 'a {
    let caller = std::panic::Location::caller();
    async move {
        let mut probes = tokio::task::JoinSet::new();
        for (what, datagrams) in shapes {
            probes.spawn(async move { (what, udp_answers(addr, &datagrams, PATIENCE).await) });
        }
        while let Some(done) = probes.join_next().await {
            let (what, heard) = done.expect("a probe task");
            assert!(
                heard.is_empty(),
                "{what} (at {caller}) must draw nothing, and drew {} datagrams",
                heard.len()
            );
        }
    }
}

/// An ECH flight the key opens is answered, and its ClientHello copied into a
/// new flight from another address draws nothing. With `require_ech` on,
/// which changes nothing for a flight whose ECH opens.
///
/// The copy is wrapped under a connection ID of its own, which is what a
/// replay does: Initial keys come from the connection ID the sender picks
/// (RFC 9001 §5.2), so anybody who saw a first flight can re-send its
/// ClientHello as a new one. Sent under the original connection ID instead,
/// quinn would route it to the connection the original opened and answer
/// nothing, whether or not the gate dropped it, so the test would prove
/// nothing about the gate.
#[tokio::test]
async fn an_ech_flight_is_answered_and_its_copy_from_elsewhere_draws_nothing() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    let (server, _keys) = ech_server(&key, true, &["localhost"]).await;
    let hello = rustls_hello(&Offer::Ech(key.config_list()), &surge_groups(), "localhost");
    let flight = hold_flight(&*crypto, &CLIENT_CID, &[], &hello, 2);
    let rewrapped = hold_flight(&*crypto, &[0x5c; 8], &[], &hello, 2);

    let heard = udp_answers(server.addr, &flight, PATIENCE).await;
    assert!(!heard.is_empty(), "a flight whose ECH opens is answered");

    let copy = udp_answers(server.addr, &rewrapped, PATIENCE).await;
    assert!(
        copy.is_empty(),
        "its copy from another port drew {} datagrams",
        copy.len()
    );
}

/// Every flight the rule table drops draws nothing on the wire, with
/// `require_ech` off and on, while the same server answers an ECH flight its
/// key opens.
#[tokio::test]
async fn every_flight_the_rule_table_drops_draws_nothing_either_way() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    let groups = surge_groups();
    let ours = rustls_hello(&Offer::Ech(key.config_list()), &groups, "localhost");
    // Each flight under a connection ID of its own, so that quinn would open a
    // new connection for any of them the gate let through, and answer it.
    let next = std::cell::Cell::new(0x40u8);
    let flight = |hello: &[u8]| {
        next.set(next.get() + 1);
        hold_flight(&*crypto, &[next.get(); 8], &[], hello, 2)
    };

    for require_ech in [false, true] {
        let (server, _keys) = ech_server(&key, require_ech, &["localhost"]).await;
        assert!(
            !udp_answers(server.addr, &flight(&ours), PATIENCE)
                .await
                .is_empty(),
            "require_ech = {require_ech}: the control flight is answered"
        );
        let mut shapes = vec![
            (
                "GREASE ECH",
                flight(&rustls_hello(&Offer::Grease, &groups, "localhost")),
            ),
            (
                "ECH under another key with our config_id",
                flight(&rustls_hello(
                    &Offer::Ech(ech_key(7).config_list()),
                    &groups,
                    "localhost",
                )),
            ),
            (
                "ECH under another key",
                flight(&rustls_hello(
                    &Offer::Ech(ech_key(9).config_list()),
                    &groups,
                    "localhost",
                )),
            ),
            ("ECH with a damaged payload", flight(&damaged_ech(&ours))),
            (
                "no ECH, a name off the list",
                flight(&rustls_hello(&Offer::Plain, &groups, UNLISTED)),
            ),
        ];
        if require_ech {
            shapes.push((
                "no ECH, a name on the list",
                flight(&rustls_hello(&Offer::Plain, &groups, "localhost")),
            ));
        }
        all_silent(server.addr, shapes).await;
    }
}

/// Without `require_ech`, a flight with no ECH extension naming a host on the
/// list is answered: a client that has no list is not dropped for it.
#[tokio::test]
async fn without_require_ech_a_flight_without_ech_is_judged_by_its_name() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    let (server, _keys) = ech_server(&key, false, &["localhost"]).await;
    let hello = rustls_hello(&Offer::Plain, &surge_groups(), "localhost");
    let heard = udp_answers(
        server.addr,
        &hold_flight(&*crypto, &CLIENT_CID, &[], &hello, 2),
        PATIENCE,
    )
    .await;
    assert!(
        !heard.is_empty(),
        "a plain flight naming a listed host is answered"
    );
}

/// A flight that never completes draws nothing: the first packet of two, and
/// the three shapes that draw an acknowledgement from the stateless gate,
/// which with a key are held and dropped like any other incomplete flight.
/// The controls send the same three to a server without the gate, which
/// acknowledges them, and the whole flight to the server with the key, which
/// answers it.
#[tokio::test]
async fn a_flight_that_never_completes_draws_nothing() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    let hello = rustls_hello(&Offer::Ech(key.config_list()), &surge_groups(), "localhost");
    let named = named_hello("localhost");
    let residue = || {
        vec![
            (
                "a PING and nothing else",
                vec![initial(&*crypto, &[0x55; 8], &[0x01])],
            ),
            (
                "half a ClientHello",
                vec![initial(
                    &*crypto,
                    &[0x33; 8],
                    &crypto_frame_at(0, &named[..named.len() / 2]),
                )],
            ),
            (
                "a CRYPTO frame at offset 64",
                vec![initial(&*crypto, &[0x44; 8], &crypto_frame_at(64, &named))],
            ),
        ]
    };

    let off = TestServer::start_with(ALLOW_PRIVATE).await;
    for (what, datagrams) in residue() {
        assert!(
            !udp_answers(off.addr, &datagrams, PATIENCE).await.is_empty(),
            "{what}: without the gate this draws a reply, or it tests nothing"
        );
    }

    let (server, _keys) = ech_server(&key, false, &[]).await;
    assert!(
        !udp_answers(
            server.addr,
            &hold_flight(&*crypto, &[0x77; 8], &[], &hello, 2),
            PATIENCE
        )
        .await
        .is_empty(),
        "the same server answers the whole flight"
    );
    let mut shapes = residue();
    shapes.push((
        "the first packet of two",
        hold_flight(&*crypto, &CLIENT_CID, &[], &hello, 2)[..1].to_vec(),
    ));
    all_silent(server.addr, shapes).await;
}

/// A first flight of three datagrams whose third is lost completes through
/// the hold.
///
/// The client is quinn, with an ECH ClientHello padded by a long ALPN list
/// until it takes three Initial datagrams. A relay drops the client's third
/// datagram and carries everything else. The hold sends nothing back, so the
/// client learns of no loss and sends two datagrams at each probe timeout
/// (RFC 9002 §6.2.4: "An endpoint MAY send up to two full-sized datagrams
/// containing ack-eliciting packets to avoid an expensive consecutive PTO
/// expiration due to a single lost datagram."). quinn fills them from its
/// oldest packets that still carry data, so the first probe repeats the
/// first two datagrams and the lost bytes come only with the second probe,
/// about three seconds after the flight began. The flight has to be held
/// that long.
#[tokio::test]
async fn a_three_datagram_first_flight_that_loses_its_third_completes_through_the_hold() {
    let key = ech_key(44);
    let (server, _keys) = ech_server(&key, false, &[]).await;
    let begun = std::time::Instant::now();
    let sent = Arc::new(std::sync::Mutex::new(Vec::<Duration>::new()));
    let relay = udp_relay(server.addr, {
        let sent = sent.clone();
        move |leg, _| {
            if leg != Leg::FromClient {
                return Relayed::Forward;
            }
            let mut sent = sent.lock().expect("the send times");
            sent.push(begun.elapsed());
            if sent.len() == 3 {
                Relayed::Drop
            } else {
                Relayed::Forward
            }
        }
    })
    .await;

    let mut alpn = vec!["h3".to_owned()];
    alpn.extend((0..4).map(|i| format!("{i}{}", "padding-".repeat(31))));
    let alpn: Vec<&str> = alpn.iter().map(String::as_str).collect();
    let crypto = rustls_client(
        &Offer::Ech(key.config_list()),
        Some(&surge_groups()),
        roots_of(&server.ca),
        &alpn,
    );
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(10)
            .try_into()
            .expect("a legal idle timeout"),
    ));
    let endpoint = endpoint_from(crypto, Some(transport));
    let connecting = endpoint
        .connect(relay.addr, "localhost")
        .expect("start connecting");
    let outcome = tokio::time::timeout(Duration::from_secs(12), connecting)
        .await
        .expect("a handshake ends one way or the other");

    let sent = sent.lock().expect("the send times").clone();
    let first = sent
        .iter()
        .take_while(|at| **at < Duration::from_millis(500))
        .count();
    assert_eq!(first, 3, "the first flight takes three datagrams: {sent:?}");
    let connection = outcome.unwrap_or_else(|error| {
        panic!("the handshake failed with {error:?}; client datagrams at {sent:?}")
    });
    drop(connection);
    relay.task.abort();
}

/// A quinn client on rustls with `offer`, `groups` in that order, and an idle
/// timeout of two seconds, so that silence is a fast `TimedOut`.
fn quick_client(
    ca: &rustls::pki_types::CertificateDer<'static>,
    offer: &Offer,
    groups: &[&'static dyn SupportedKxGroup],
) -> quinn::Endpoint {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(PATIENCE.try_into().expect("a legal idle timeout")));
    transport.keep_alive_interval(None);
    endpoint_from(
        rustls_client(offer, Some(groups), roots_of(ca), &["h3"]),
        Some(transport),
    )
}

/// What one quinn handshake with `offer` came to.
async fn handshake_with(
    server: &TestServer,
    offer: &Offer,
    groups: &[&'static dyn SupportedKxGroup],
) -> Result<quinn::Connection, quinn::ConnectionError> {
    let endpoint = quick_client(&server.ca, offer, groups);
    let connecting = endpoint
        .connect(server.addr, "localhost")
        .expect("start connecting");
    tokio::time::timeout(PATIENCE * 3, connecting)
        .await
        .expect("a handshake ends one way or the other")
}

/// With `require_ech` on, a real client holding the list connects, and one
/// without it, or with another key's list, hears nothing. With it off, the
/// client without a list connects too.
#[tokio::test]
async fn require_ech_admits_a_client_with_the_list_and_nothing_else() {
    let key = ech_key(7);
    let groups = surge_groups();
    let (server, _keys) = ech_server(&key, true, &["localhost"]).await;

    handshake_with(&server, &Offer::Ech(key.config_list()), &groups)
        .await
        .expect("a client with the list connects");
    for (what, offer) in [
        ("no list", Offer::Plain),
        ("another key's list", Offer::Ech(ech_key(9).config_list())),
        ("GREASE", Offer::Grease),
    ] {
        let error = handshake_with(&server, &offer, &groups)
            .await
            .expect_err("no handshake without the key");
        assert_matches!(
            error,
            quinn::ConnectionError::TimedOut,
            "a client with {what} must hear nothing: {error:?}"
        );
    }

    let (open, _keys) = ech_server(&key, false, &["localhost"]).await;
    handshake_with(&open, &Offer::Plain, &groups)
        .await
        .expect("without require_ech a client with no list connects");
}

/// One unauthenticated datagram whose CRYPTO frames disagree with each other
/// draws nothing, and the server goes on answering: a client with the list
/// connects after it.
///
/// Before the fix of the hold's byte count this datagram underflowed that
/// count inside `poll_recv`, under quinn's endpoint driver, and the panic
/// took the endpoint with it.
#[tokio::test]
async fn a_datagram_that_disagrees_with_itself_leaves_the_server_answering() {
    let crypto = nameless_crypto();
    let key = ech_key(7);
    let (server, _keys) = ech_server(&key, true, &["localhost"]).await;
    let mut frames = crypto_frame_at(0, b"abcd");
    frames.extend_from_slice(&crypto_frame_at(0, b"Xbcd"));
    let heard = udp_answers(
        server.addr,
        &[initial(&*crypto, &[0x71; 8], &frames)],
        PATIENCE,
    )
    .await;
    assert!(heard.is_empty(), "drew {} datagrams", heard.len());
    handshake_with(&server, &Offer::Ech(key.config_list()), &surge_groups())
        .await
        .expect("a client with the list still connects");
}

/// A HelloRetryRequest under ECH: the client offers SecP256r1MLKEM768 first
/// and sends only that share, which this server does not accept, so libssl
/// asks for an X25519 share with a HelloRetryRequest. The second ClientHello
/// travels in Initial packets addressed to the server's connection ID, which
/// the gate cannot open and passes, and ECH is kept across both (the
/// provider's `a_hello_retry_request_keeps_ech`). Under `require_ech`.
///
/// The server's "TLS handshake complete" line says the retry happened: the
/// group it names is X25519, which the client sent no share of in its first
/// ClientHello. The key's config_id, 43, is used by no other test here, which
/// is how the line is told apart from the lines of the tests beside it.
#[tokio::test]
async fn a_hello_retry_request_under_ech_completes_through_the_hold() {
    let log = SharedBuffer::shared(LOG_FILTER);
    let key = ech_key(43);
    let (server, _keys) = ech_server(&key, true, &["localhost"]).await;
    let groups = [kx_group::SECP256R1MLKEM768, kx_group::X25519];
    let mark = log.mark();
    handshake_with(&server, &Offer::Ech(key.config_list()), &groups)
        .await
        .expect("a handshake with a HelloRetryRequest completes under the hold");
    let line = log
        .wait_for_line(mark, &["TLS handshake complete", "ech_config_id=43 "])
        .await;
    assert!(line.contains("group=X25519 "), "{line}");
    assert!(line.contains("ech_accepted=true"), "{line}");
}

/// `require_ech` is reloadable, like `expected_sni`: turning it on drops a
/// client without the list from the next handshake on, and a reload that
/// would set it without a key is refused and changes nothing.
#[tokio::test]
async fn require_ech_is_reloadable_and_refused_without_a_key() {
    let key = ech_key(7);
    let groups = surge_groups();
    let (server, keys) = ech_server(&key, false, &[]).await;
    handshake_with(&server, &Offer::Plain, &groups)
        .await
        .expect("require_ech off: a client without the list connects");

    let path = keys.path().join("ech.pem");
    server.rewrite_config(&format!(
        "ech_key = \"{}\"\n[security]\nallow_private_networks = true\nrequire_ech = true\n",
        path.display()
    ));
    server.reload().expect("the reload applies");
    let error = handshake_with(&server, &Offer::Plain, &groups)
        .await
        .expect_err("require_ech on: no handshake without the list");
    assert_matches!(error, quinn::ConnectionError::TimedOut, "{error:?}");
    handshake_with(&server, &Offer::Ech(key.config_list()), &groups)
        .await
        .expect("a client with the list still connects");

    server.rewrite_config("[security]\nallow_private_networks = true\nrequire_ech = true\n");
    let refused = server
        .reload()
        .expect_err("require_ech without a key is refused");
    assert!(
        format!("{refused:#}").contains("security.require_ech"),
        "{refused:#}"
    );
    let error = handshake_with(&server, &Offer::Plain, &groups)
        .await
        .expect_err("the refused reload left require_ech on");
    assert_matches!(error, quinn::ConnectionError::TimedOut, "{error:?}");
}

/// A server holding a previous key beside its current one, on the wire: a
/// flight under either key is answered, a flight that names the previous
/// key's config_id and was sealed to another key draws nothing, and after a
/// reload that removes the previous key a flight under it draws nothing
/// either. Each flight has a connection ID of its own, so quinn would answer
/// any of them the gate let through.
#[tokio::test]
async fn a_previous_key_is_answered_until_a_reload_removes_it() {
    let crypto = nameless_crypto();
    let previous = ech_key(7);
    let current = ech_key(9);
    let groups = surge_groups();
    let next = std::cell::Cell::new(0x60u8);
    let flight = |list: Vec<u8>| {
        next.set(next.get() + 1);
        let hello = rustls_hello(&Offer::Ech(list), &groups, "localhost");
        hold_flight(&*crypto, &[next.get(); 8], &[], &hello, 2)
    };

    let keys = TempDir::new("ech-rotation");
    let current_path = keys.path().join("ech.pem");
    let previous_path = keys.path().join("ech-old.pem");
    volto::tls::write_new_key_file(&current_path, &current).expect("write the current key");
    volto::tls::write_new_key_file(&previous_path, &previous).expect("write the previous key");
    let rotating = format!(
        "ech_key = \"{}\"\nech_previous_key = \"{}\"\n[security]\nallow_private_networks = true\n",
        current_path.display(),
        previous_path.display()
    );
    let server = TestServer::start_with(&rotating).await;

    for (what, list) in [
        ("a flight under the previous key", previous.config_list()),
        ("a flight under the current key", current.config_list()),
    ] {
        assert!(
            !udp_answers(server.addr, &flight(list), PATIENCE)
                .await
                .is_empty(),
            "{what} is answered"
        );
    }
    all_silent(
        server.addr,
        vec![(
            "ECH that names the previous config_id, sealed to another key",
            flight(ech_key(7).config_list()),
        )],
    )
    .await;

    server.rewrite_config(&format!(
        "ech_key = \"{}\"\n[security]\nallow_private_networks = true\n",
        current_path.display()
    ));
    server.reload().expect("the reload applies");
    all_silent(
        server.addr,
        vec![(
            "a flight under the removed previous key",
            flight(previous.config_list()),
        )],
    )
    .await;
    assert!(
        !udp_answers(server.addr, &flight(current.config_list()), PATIENCE)
            .await
            .is_empty(),
        "a flight under the current key is still answered"
    );
}

// ---------------------------------------------------------------------------
// (f) The seed corpus of `fuzz/fuzz_targets/hold.rs`
// ---------------------------------------------------------------------------

/// The record header bit that makes a record's body frames to seal, in the
/// format `volto::gate::HoldInput` reads. Written out here rather than taken
/// from the reader, so that the seeds below are written by a second
/// implementation of the format and read by the one the target uses.
const HOLD_FUZZ_SEALED: u8 = 0x04;

/// What one record of a hold fuzz input carries.
enum Body {
    /// A datagram, as it arrived.
    Raw(Vec<u8>),
    /// A reload to the policy this byte selects: a raw body of one byte.
    Reload(u8),
    /// Frames for `volto::gate::sealed_initial`, addressed to the connection
    /// ID `selector & 3` picks (0 is [`CLIENT_CID`]) with packet number
    /// `selector >> 2`.
    Sealed { selector: u8, frames: Vec<u8> },
}

/// One record of a hold fuzz input: the source address index, the time that
/// passes before it in 100 ms steps, and its body.
struct Record {
    source: u8,
    steps: u8,
    body: Body,
}

/// Encodes `records` under the policy byte `policy` in the target's format.
fn hold_input(policy: u8, records: &[Record]) -> Vec<u8> {
    let mut input = vec![policy];
    for record in records {
        assert!(record.steps < 32, "five bits of time");
        let (sealed, body) = match &record.body {
            Body::Raw(datagram) => {
                assert_ne!(datagram.len(), 1, "a one-byte body is a reload");
                (0, datagram.clone())
            }
            Body::Reload(policy) => (0, vec![*policy]),
            Body::Sealed { selector, frames } => {
                let mut body = vec![*selector];
                body.extend_from_slice(frames);
                (HOLD_FUZZ_SEALED, body)
            }
        };
        input.push((record.steps << 3) | sealed | (record.source & 0x03));
        let length = u16::try_from(body.len()).expect("a body under 64 KiB");
        input.extend_from_slice(&length.to_be_bytes());
        input.extend_from_slice(&body);
    }
    input
}

/// Runs a hold fuzz input through `volto::gate::HoldInput`, the reader the
/// target uses, with the target's current key `key` and previous key
/// `previous`, and returns what became of its last datagram and the flights
/// it dropped, checking the byte count against the hold's contents and the
/// byte bound after every step as the target does.
fn run_hold_input(
    key: &Arc<EchKey>,
    previous: &Arc<EchKey>,
    input: &[u8],
) -> (Screened, Vec<(SocketAddr, Dropped)>) {
    let input = HoldInput::new(input).expect("a policy byte");
    let keep_released = input.keep_released;
    let mut screening = Screening::new(input.policy.policy(key, previous));
    let mut last = (Screened::Passed, Vec::new());
    for step in input {
        match step {
            HoldStep::Datagram(record) => {
                last = screening.receive(record.after, record.from, &record.datagram);
            }
            HoldStep::Reload(policy) => screening.set(policy.policy(key, previous)),
        }
        assert_eq!(screening.recounted_bytes(), screening.held_bytes());
        assert!(screening.held_bytes() <= HOLD_TOTAL_BYTES, "the byte bound");
        if !keep_released {
            screening.released();
        }
    }
    last
}

/// Writes the seed corpus for `fuzz/fuzz_targets/hold.rs`, and pins what each
/// seed was built to reach.
///
/// The target cannot spell an ECH extension that opens, so without these it
/// would never reach the HPKE check, the replay record or a release. Each seed
/// is a whole input, read here by `volto::gate::HoldInput` under
/// `volto::gate::hold_input_key` and `volto::gate::hold_input_previous_key`,
/// the reader and the keys the target uses; the assertion is the outcome of
/// its last record. Bit 2 of the policy byte puts the previous key beside the
/// current one, and the `previous-` seeds carry ECH under it, with and without
/// that bit. The `sealed-` seeds carry the
/// same flights as frames for the target to seal, which is how the fuzzer
/// edits what the hold reads rather than ciphertext. `fuzz/corpus/` is
/// machine-local and gitignored (D83), so this runs with every `cargo test`.
#[test]
fn the_hold_fuzz_seed_corpus_is_written_with_the_outcomes_it_was_built_for() {
    let crypto = nameless_crypto();
    let key = Arc::new(hold_input_key());
    let previous = Arc::new(hold_input_previous_key());
    let groups = surge_groups();
    let ours = rustls_hello(&Offer::Ech(key.config_list()), &groups, "localhost");
    let older = rustls_hello(&Offer::Ech(previous.config_list()), &groups, "localhost");
    let older_two = hold_flight(&*crypto, &CLIENT_CID, &[], &older, 2);
    let small = rustls_hello(&Offer::Ech(key.config_list()), &small_groups(), "localhost");
    let plain_hello = rustls_hello(&Offer::Plain, &groups, "localhost");
    let two = hold_flight(&*crypto, &CLIENT_CID, &[], &ours, 2);
    let three = hold_flight(&*crypto, &CLIENT_CID, &[], &ours, 3);
    let plain = hold_flight(&*crypto, &CLIENT_CID, &[], &plain_hello, 2);
    let grease = hold_flight(
        &*crypto,
        &CLIENT_CID,
        &[],
        &rustls_hello(&Offer::Grease, &groups, "localhost"),
        2,
    );
    let record = |source: u8, steps: u8, datagram: &Vec<u8>| Record {
        source,
        steps,
        body: Body::Raw(datagram.clone()),
    };
    let reload = |policy: u8| Record {
        source: 0,
        steps: 0,
        body: Body::Reload(policy),
    };
    // An empty datagram, which never reaches the hold: a record that only
    // moves the clock, 100 ms a step.
    let pause = |steps: u8| Record {
        source: 0,
        steps,
        body: Body::Raw(Vec::new()),
    };
    // `hello` in two packets of one CRYPTO frame each, as frames to seal, to
    // the first connection ID with packet numbers 0 and 1.
    let sealed_two = |source: u8, hello: &[u8]| -> Vec<Record> {
        let run = hello.len().div_ceil(2);
        hello
            .chunks(run)
            .enumerate()
            .map(|(index, part)| Record {
                source,
                steps: 0,
                body: Body::Sealed {
                    selector: u8::try_from(index << 2).expect("two packets"),
                    frames: crypto_frame_at(index * run, part),
                },
            })
            .collect()
    };
    // A ClientHello that fits one packet, as two CRYPTO frames of that one
    // packet: the layout a disagreement inside one packet is made from.
    let mut two_frames = crypto_frame_at(0, &small[..small.len() / 2]);
    two_frames.extend_from_slice(&crypto_frame_at(small.len() / 2, &small[small.len() / 2..]));
    let mut replayed = sealed_two(0, &ours);
    replayed.extend(sealed_two(1, &ours));
    let mut older_replayed = sealed_two(0, &older);
    older_replayed.extend(sealed_two(1, &older));

    let seeds: Vec<(&str, Vec<u8>, Screened)> = vec![
        (
            "ech-in-two-packets",
            hold_input(0x01, &[record(0, 0, &two[0]), record(0, 0, &two[1])]),
            Screened::Released,
        ),
        (
            "ech-in-three-packets-reversed",
            hold_input(
                0x01,
                &[
                    record(0, 0, &three[2]),
                    record(0, 0, &three[1]),
                    record(0, 0, &three[0]),
                ],
            ),
            Screened::Released,
        ),
        (
            "ech-replayed-from-another-address",
            hold_input(
                0x00,
                &[
                    record(0, 0, &two[0]),
                    record(0, 0, &two[1]),
                    record(1, 1, &two[0]),
                    record(1, 0, &two[1]),
                ],
            ),
            Screened::Dropped,
        ),
        (
            "ech-retransmitted-from-its-own-address",
            hold_input(
                0x01,
                &[
                    record(0, 0, &two[0]),
                    record(0, 0, &two[1]),
                    record(0, 5, &two[0]),
                    record(0, 0, &two[1]),
                ],
            ),
            Screened::Released,
        ),
        (
            "plain-with-the-name-listed",
            hold_input(0x02, &[record(0, 0, &plain[0]), record(0, 0, &plain[1])]),
            Screened::Released,
        ),
        (
            "plain-under-require-ech",
            hold_input(0x03, &[record(0, 0, &plain[0]), record(0, 0, &plain[1])]),
            Screened::Dropped,
        ),
        (
            "grease",
            hold_input(0x00, &[record(0, 0, &grease[0]), record(0, 0, &grease[1])]),
            Screened::Dropped,
        ),
        (
            "a-first-packet-that-expires",
            hold_input(
                0x00,
                &[
                    record(0, 0, &two[0]),
                    pause(31),
                    pause(31),
                    record(0, 31, &two[1]),
                ],
            ),
            Screened::Held,
        ),
        (
            "sealed-ech-in-two-packets",
            hold_input(0x01, &sealed_two(0, &ours)),
            Screened::Released,
        ),
        (
            "sealed-ech-in-two-frames-of-one-packet",
            hold_input(
                0x01,
                &[Record {
                    source: 0,
                    steps: 0,
                    body: Body::Sealed {
                        selector: 0,
                        frames: two_frames,
                    },
                }],
            ),
            Screened::Released,
        ),
        (
            "sealed-ech-replayed-from-another-address",
            hold_input(0x00, &replayed),
            Screened::Dropped,
        ),
        (
            "sealed-plain-with-the-name-listed",
            hold_input(0x02, &sealed_two(0, &plain_hello)),
            Screened::Released,
        ),
        (
            "previous-ech-with-the-previous-key",
            hold_input(
                0x04,
                &[record(0, 0, &older_two[0]), record(0, 0, &older_two[1])],
            ),
            Screened::Released,
        ),
        (
            "previous-ech-without-the-previous-key",
            hold_input(
                0x00,
                &[record(0, 0, &older_two[0]), record(0, 0, &older_two[1])],
            ),
            Screened::Dropped,
        ),
        (
            "previous-sealed-ech-under-require-ech",
            hold_input(0x05, &sealed_two(0, &older)),
            Screened::Released,
        ),
        (
            "previous-sealed-ech-replayed-from-another-address",
            hold_input(0x04, &older_replayed),
            Screened::Dropped,
        ),
        // Reloads. 0x0c is the rotation: the previous key becomes the
        // current one and the old current one stays beside it. 0x08 then
        // removes the old current key, and 0x10 removes every key.
        (
            "reload-rotation-between-two-packets",
            hold_input(
                0x00,
                &[record(0, 0, &two[0]), reload(0x0c), record(0, 0, &two[1])],
            ),
            Screened::Released,
        ),
        (
            "reload-removes-the-key-between-two-packets",
            hold_input(
                0x04,
                &[record(0, 0, &two[0]), reload(0x08), record(0, 0, &two[1])],
            ),
            Screened::Dropped,
        ),
        (
            "reload-replay-after-the-rotation",
            hold_input(
                0x00,
                &[
                    record(0, 0, &two[0]),
                    record(0, 0, &two[1]),
                    reload(0x0c),
                    record(1, 0, &two[0]),
                    record(1, 0, &two[1]),
                ],
            ),
            Screened::Dropped,
        ),
        (
            "reload-replay-after-the-key-comes-back",
            hold_input(
                0x00,
                &[
                    record(0, 0, &two[0]),
                    record(0, 0, &two[1]),
                    reload(0x08),
                    reload(0x0c),
                    record(1, 0, &two[0]),
                    record(1, 0, &two[1]),
                ],
            ),
            Screened::Dropped,
        ),
        (
            "reload-to-no-key-passes-the-second-packet",
            hold_input(
                0x00,
                &[record(0, 0, &two[0]), reload(0x10), record(0, 0, &two[1])],
            ),
            Screened::Passed,
        ),
        (
            "sealed-a-ping",
            hold_input(
                0x00,
                &[Record {
                    source: 0,
                    steps: 0,
                    body: Body::Sealed {
                        selector: 0,
                        frames: vec![0x01],
                    },
                }],
            ),
            Screened::Held,
        ),
    ];

    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/hold");
    std::fs::create_dir_all(&directory).expect("a corpus directory to write seeds into");
    for (name, input, outcome) in seeds {
        assert_eq!(
            run_hold_input(&key, &previous, &input).0,
            outcome,
            "the seed {name}"
        );
        std::fs::write(directory.join(name), &input).expect("a seed file");
    }

    // Released datagrams that wait (bit 5 of the policy byte) until the hold
    // has to evict for its byte bound. A sealed PING is five bytes of input
    // and a datagram of 1200, which is what lets an input of about 22 KB fill
    // 4 MiB. Each admitted flight is fifty PINGs and a whole ClientHello
    // without ECH, which the empty list of policy 0x20 admits; then flight A
    // sends two PINGs and flight B sends PINGs until one more does not fit.
    let sealed = |source: u8, frames: Vec<u8>| Record {
        source,
        steps: 0,
        body: Body::Sealed {
            selector: 0,
            frames,
        },
    };
    let ping = |source: u8| sealed(source, vec![0x01]);
    let per_flight = 51 * MIN_INITIAL_DATAGRAM;
    let flights = HOLD_TOTAL_BYTES / per_flight;
    let room = HOLD_TOTAL_BYTES - flights * per_flight;
    let b_fits = room / MIN_INITIAL_DATAGRAM - 2;
    let mut records = Vec::new();
    for _ in 0..flights {
        records.extend((0..50).map(|_| ping(0)));
        records.push(sealed(0, crypto_frame_at(0, &named_hello("localhost"))));
    }
    records.extend([ping(1), ping(1)]);
    records.extend((0..=b_fits).map(|_| ping(2)));
    let input = hold_input(0x20, &records);
    let source = |index: u16| SocketAddr::from(([127, 0, 0, 1], 40_000 + index));
    assert_eq!(
        run_hold_input(&key, &previous, &input),
        (Screened::Held, vec![(source(1), Dropped::Evicted)]),
        "the seed released-datagrams-wait-at-the-byte-bound"
    );
    std::fs::write(
        directory.join("released-datagrams-wait-at-the-byte-bound"),
        &input,
    )
    .expect("a seed file");
}

/// The port a probe sent from stays taken after the probe has returned.
///
/// A server that answered a probe sends its flight again to that port for
/// seconds after the probe stopped listening. If the next probe's socket were
/// given the same port, it would hear those datagrams and a test of silence
/// would count them as an answer ([`common::udp_answers`] says how it keeps
/// the port).
#[tokio::test]
async fn the_port_of_a_finished_probe_is_not_free_for_the_next_one() {
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a target");
    let addr = target.local_addr().expect("the target's address");
    let brief = Duration::from_millis(50);
    let mut probe = vec![0u8; 16];

    assert!(udp_answers(addr, &[vec![1u8; 8]], brief).await.is_empty());
    let (_, many) = tokio::time::timeout(TIMEOUT, target.recv_from(&mut probe))
        .await
        .expect("udp_answers sends its probe")
        .expect("the probe");
    assert!(udp_answer(addr, &[2u8; 8], brief).await.is_none());
    let (_, one) = tokio::time::timeout(TIMEOUT, target.recv_from(&mut probe))
        .await
        .expect("udp_answer sends its probe")
        .expect("the probe");

    for (helper, from) in [("udp_answers", many), ("udp_answer", one)] {
        let again = tokio::net::UdpSocket::bind(from).await;
        assert_eq!(
            again.as_ref().err().map(std::io::Error::kind),
            Some(std::io::ErrorKind::AddrInUse),
            "{helper} sent from {from}, and that port must still be taken"
        );
    }
}
