//! Shapes the SNI gate has to get right (D106).
//!
//! `it_sni_gate` asks whether the gate admits the right *names*, with real
//! clients. This binary spells Initial packets by hand and asks three questions
//! around that, all through the [`judgement`] seam the socket path itself calls
//! and the [`nameless_crypto`] it derives Initial keys from.
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

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use common::{
    ALLOW_PRIVATE, GATE_LOCALHOST, TestServer, bulk_alpn, client_endpoint, udp_answer, udp_answers,
};
use quinn::ConnectionId;
use volto::datagram::{peek_varint, put_varint};
use volto::gate::{FirstFlight, Names, Refusal, Verdict, first_flight, judgement, nameless_crypto};

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

    packet.resize(number_offset + shape.number_length, 0); // packet number 0
    packet.extend_from_slice(frames);
    packet.resize(number_offset + shape.number_length + payload_len, 0); // PADDING
    packet.resize(shape.packet_length, 0); // room for the tag

    keys.packet
        .remote
        .encrypt(0, &mut packet, number_offset + shape.number_length);
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
        FirstFlight::Named(b"localhost".to_vec())
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
        Verdict::Refuse(Refusal::OtherName("\"other.example\"".to_owned()))
    );

    let ours = initial(
        &*crypto,
        &CLIENT_CID,
        &crypto_frame_at(0, &named_hello("localhost")),
    );
    assert_eq!(judgement(&ours, &names), Verdict::Pass);
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
    assert!(
        matches!(refusal, Verdict::Refuse(Refusal::OtherName(_))),
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
    let datagram = quinn_first_flight(&["h3"]).await;

    assert_eq!(
        judgement(&datagram, &Names::new(&[REAL_NAME.to_owned()])),
        Verdict::Pass,
        "a real quinn first flight naming {REAL_NAME} must reach quinn"
    );
    let refusal = judgement(&datagram, &Names::new(&["other.example".to_owned()]));
    assert_eq!(
        refusal,
        Verdict::Refuse(Refusal::OtherName(format!("{REAL_NAME:?}"))),
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
    let datagram = quinn_first_flight(&alpn).await;

    for list in [REAL_NAME, "other.example"] {
        assert_eq!(
            judgement(&datagram, &Names::new(&[list.to_owned()])),
            Verdict::Pass,
            "a first flight the gate cannot finish reading must pass whatever {list} says"
        );
    }
}

/// The first datagram a quinn client sends when asking for [`REAL_NAME`].
async fn quinn_first_flight(alpn: &[&str]) -> Vec<u8> {
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a socket that never answers");
    let addr = sink.local_addr().expect("the sink's address");

    let issued = rcgen::generate_simple_self_signed(vec![REAL_NAME.to_owned()])
        .expect("a self-signed certificate");
    let endpoint = client_endpoint(&issued.cert.der().clone(), alpn);
    let handshake = tokio::spawn(endpoint.connect(addr, REAL_NAME).expect("start connecting"));

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
/// needs a Python interpreter no CI job here has.
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
        Verdict::Refuse(Refusal::OtherName(format!("{REAL_NAME:?}"))),
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
/// five datagrams — one per branch the judgement can end on — and two bare
/// ClientHellos, written where `cargo fuzz run gate` looks for them.
/// `fuzz/corpus/` is machine-local and gitignored (D83), so this runs with
/// every `cargo test` rather than leaving the corpus to a step somebody has to
/// remember; each file carries the target's mode byte in front of the bytes
/// under test.
///
/// The assertions are the other half of it. They pin what each seed is a seed
/// *for*, so a verdict that moves is a red test rather than a corpus that
/// quietly stops covering anything — and they pin the claim [`nameless_crypto`]
/// rests on, since these packets are built under a real self-signed certificate
/// and opened by the nameless configuration behind [`judgement`]. Initial keys
/// do not depend on the certificate; if they ever did, both of the refusals
/// below would fall through to [`Verdict::Pass`]. And each seed is judged twice,
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
            Verdict::Refuse(Refusal::OtherName("\"other.example\"".to_owned())),
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
    ];

    let crypto_bytes = [
        (
            "crypto-a-whole-client-hello",
            ours,
            FirstFlight::Named(b"localhost".to_vec()),
        ),
        (
            "crypto-a-client-hello-cut-short",
            cut,
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
    let Some(version) = reply.get(1..5) else {
        return format!("a long header of {} bytes, cut short", reply.len());
    };
    let version = u32::from_be_bytes([version[0], version[1], version[2], version[3]]);
    if version == 0 {
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
    let heard = udp_answers(on.addr, &shape, PATIENCE).await;
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
/// frame (`early_validate_first_packet`, quinn-proto `48455d3`), which is what
/// the gate-off half of this probe records.
#[tokio::test]
async fn a_padding_only_initial_with_a_short_connection_id_is_silent() {
    draws_no_reply("a PADDING-only Initial, DCID 4 bytes", &[0x11; 4], &[]).await;
}

/// The same with a connection ID quinn accepts, which gets as far as a
/// connection rather than a rejection.
///
/// Nothing in it is ack-eliciting, so with the gate off this shape is not
/// answered either: there is no control to assert, and the gate-on server is
/// the only measurement.
#[tokio::test]
async fn a_padding_only_initial_with_a_full_connection_id_is_silent() {
    let crypto = nameless_crypto();
    let dcid = [0x22; 8];
    let shape = initial(&*crypto, &dcid, &[]);

    let on = TestServer::start_with(GATE_LOCALHOST).await;
    let heard = udp_answers(on.addr, &shape, PATIENCE).await;
    let described: Vec<String> = heard
        .iter()
        .map(|reply| describe(&*crypto, reply, &dcid))
        .collect();
    assert!(
        heard.is_empty(),
        "with the gate on, a PADDING-only Initial must draw no reply: {described:?}"
    );
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
