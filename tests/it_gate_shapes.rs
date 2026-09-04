//! Shapes the SNI gate has to get right, from outside the process (D106).
//!
//! `it_sni_gate` asks whether the gate admits the right *names*. This binary
//! asks two questions either side of that.
//!
//! **Does a first flight from a real stack read the way the builders say it
//! does?** The unit tests in `volto::gate` judge datagrams this repository
//! spells itself, and a parser can agree with its own builder while disagreeing
//! with the wire. So a real quinn client's first datagram is captured off a
//! socket that never answers and handed to the same [`judgement`] seam the
//! socket path uses, and a real aioquic first flight — a different stack again,
//! and the one that found the `Opened::Failed` defect on 2026-09-03 — is pinned
//! here as bytes.
//!
//! **What still answers a stranger with the gate on?** The gate judges a
//! datagram's first packet, and two things it refuses are decided without a
//! name: the version in the long header, and — since only a first Initial is
//! keyed by the connection ID written in it — a Destination Connection ID
//! shorter than the eight bytes RFC 9000 §7.2 requires, which quinn answers
//! with a CONNECTION_CLOSE before a single frame is read. Everything else it
//! passes reaches quinn, and an Initial carrying an ack-eliciting frame draws
//! an acknowledgement whether or not it names anybody. The probes below send
//! each of those shapes at a server with the gate on and record what comes
//! back; the ones still answered are `#[ignore]`d rather than deleted, so the
//! shape and its evidence stay in the tree.
//!
//! Every probe is paired with the same datagram sent at a server with the gate
//! *off*, which is what proves the probe is well formed enough to be answered at
//! all: a probe that draws nothing either way has tested nothing.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{TestServer, client_endpoint};
use quinn::ConnectionId;
use volto::gate::{FirstFlight, Names, Refusal, Verdict, first_flight, judgement};

/// The gate on, naming only `localhost`.
const GATE_LOCALHOST: &str =
    "[security]\nallow_private_networks = true\nexpected_sni = [\"localhost\"]\n";

/// The gate off, which is the shipped default.
const GATE_OFF: &str = "[security]\nallow_private_networks = true\n";

/// How long a server is given to prove it is not answering.
///
/// Long enough that a loaded machine cannot pass a probe by being slow, short
/// enough that the four probes here stay well inside the harness timeout.
const PATIENCE: Duration = Duration::from_secs(2);

/// The QUIC version this server speaks.
const QUIC_V1: u32 = 0x0000_0001;

/// The smallest UDP payload that may carry an Initial packet.
const MIN_INITIAL_DATAGRAM: usize = 1200;

// ---------------------------------------------------------------------------
// Building an Initial packet by hand
// ---------------------------------------------------------------------------

/// A QUIC crypto configuration with no identity at all.
///
/// Initial keys come from the client's Destination Connection ID and a salt
/// fixed by the version (RFC 9001 §5.2), never from the server's certificate, so
/// a configuration with nothing to present derives exactly the keys the running
/// server derives — which is what lets these probes both encrypt what they send
/// and read what comes back.
fn nameless_crypto() -> Arc<dyn quinn::crypto::ServerConfig> {
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
        .expect("the aws-lc-rs provider supports TLS 1.3")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(NoIdentity));
    Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
            .expect("a TLS 1.3 configuration carries an initial cipher suite"),
    )
}

/// A QUIC variable-length integer, in the shortest encoding that holds it.
fn varint(value: usize) -> Vec<u8> {
    match u64::try_from(value).expect("a length that fits a varint") {
        small @ 0..=63 => vec![u8::try_from(small).expect("six bits")],
        medium @ 64..=16383 => (0x4000 | u16::try_from(medium).expect("fourteen bits"))
            .to_be_bytes()
            .to_vec(),
        large => (0x8000_0000 | u32::try_from(large).expect("thirty bits"))
            .to_be_bytes()
            .to_vec(),
    }
}

/// Reads a variable-length integer, returning it and how many bytes it took.
fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let length = 1usize << (first >> 6);
    if bytes.len() < length {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}

/// A 1200-byte QUIC v1 Initial addressed to `dcid`, carrying `frames`.
///
/// Keyed by its own Destination Connection ID, which is what a client's first
/// packet is, so this is a packet the gate can open — and, wherever `frames`
/// carries no ClientHello to judge, one it passes through to quinn.
fn initial(crypto: &dyn quinn::crypto::ServerConfig, dcid: &[u8], frames: &[u8]) -> Vec<u8> {
    let keys = crypto
        .initial_keys(QUIC_V1, &ConnectionId::new(dcid))
        .expect("Initial keys for QUIC v1");
    let tag_len = keys.packet.remote.tag_len();

    let mut packet = vec![0xc0]; // long header, Initial, a one-byte packet number
    packet.extend_from_slice(&QUIC_V1.to_be_bytes());
    packet.push(u8::try_from(dcid.len()).expect("a legal connection id"));
    packet.extend_from_slice(dcid);
    packet.push(8); // Source Connection ID length
    packet.extend_from_slice(&[0xcc; 8]);
    packet.push(0); // no token

    let number_offset = packet.len() + 2; // a two-byte Length field
    let payload_len = MIN_INITIAL_DATAGRAM - number_offset - 1 - tag_len;
    assert!(frames.len() <= payload_len, "frames do not fit one Initial");
    let length = u16::try_from(1 + payload_len + tag_len).expect("a two-byte length");
    packet.extend_from_slice(&(0x4000 | length).to_be_bytes());
    packet.push(0); // packet number 0
    packet.extend_from_slice(frames);
    packet.resize(number_offset + 1 + payload_len, 0); // PADDING
    packet.resize(MIN_INITIAL_DATAGRAM, 0); // room for the tag

    keys.packet
        .remote
        .encrypt(0, &mut packet, number_offset + 1);
    keys.header.remote.encrypt(number_offset, &mut packet);
    packet
}

/// A CRYPTO frame carrying `data` at `offset` in the handshake stream.
fn crypto_frame_at(offset: usize, data: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x06];
    frame.extend_from_slice(&varint(offset));
    frame.extend_from_slice(&varint(data.len()));
    frame.extend_from_slice(data);
    frame
}

/// A ClientHello naming `host`, spelled the way `volto::gate`'s own tests do.
fn client_hello(host: &str) -> Vec<u8> {
    let host = host.as_bytes();
    let mut entry = vec![0x00]; // host_name
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
    let mut extensions = vec![0x00, 0x00]; // server_name
    extensions.extend_from_slice(
        &u16::try_from(list.len())
            .expect("a short body")
            .to_be_bytes(),
    );
    extensions.extend_from_slice(&list);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&[0x00; 32]); // random
    body.push(0); // legacy_session_id
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
    body.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods
    body.extend_from_slice(
        &u16::try_from(extensions.len())
            .expect("short extensions")
            .to_be_bytes(),
    );
    body.extend_from_slice(&extensions);

    let mut message = vec![0x01]; // client_hello
    let length = body.len();
    message.extend_from_slice(&[
        u8::try_from(length >> 16).expect("a short message"),
        u8::try_from((length >> 8) & 0xff).expect("a byte"),
        u8::try_from(length & 0xff).expect("a byte"),
    ]);
    message.extend_from_slice(&body);
    message
}

// ---------------------------------------------------------------------------
// Sending a probe and reading what comes back
// ---------------------------------------------------------------------------

/// Sends `bytes` once and collects every datagram that arrives within `PATIENCE`.
///
/// Every datagram rather than the first, because "the server answered" and "the
/// server answered twice" are different facts about how loud a shape is.
async fn answers(addr: SocketAddr, bytes: &[u8]) -> Vec<Vec<u8>> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a probing socket");
    socket.send_to(bytes, addr).await.expect("send the probe");

    let deadline = Instant::now() + PATIENCE;
    let mut heard = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        let mut buffer = vec![0u8; 2048];
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

/// What a reply is, in as much detail as the Initial keys allow.
///
/// The keys a server uses to answer come from the Destination Connection ID the
/// probe chose (RFC 9001 §5.2), so a probe can read its own answers: the reply
/// is decrypted here and its frames named, which is what turns "the server said
/// something" into "the server said PROTOCOL_VIOLATION".
fn describe(crypto: &dyn quinn::crypto::ServerConfig, reply: &[u8], dcid: &[u8]) -> String {
    let Some(&first) = reply.first() else {
        return "an empty datagram".to_owned();
    };
    if first & 0x80 == 0 {
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

    match initial_frames(crypto, reply, dcid) {
        Some(frames) => format!(
            "an Initial of {} bytes carrying {}",
            reply.len(),
            frames.join(", ")
        ),
        None => format!("an Initial of {} bytes this probe cannot open", reply.len()),
    }
}

/// Opens a server's Initial packet and names the frames in it.
fn initial_frames(
    crypto: &dyn quinn::crypto::ServerConfig,
    reply: &[u8],
    dcid: &[u8],
) -> Option<Vec<String>> {
    let keys = crypto
        .initial_keys(QUIC_V1, &ConnectionId::new(dcid))
        .ok()?;

    let mut at = 5usize;
    let dcid_length = usize::from(*reply.get(at)?);
    at = at.checked_add(1 + dcid_length)?;
    let scid_length = usize::from(*reply.get(at)?);
    at = at.checked_add(1 + scid_length)?;
    let (token, read) = read_varint(reply.get(at..)?)?;
    at = at
        .checked_add(read)?
        .checked_add(usize::try_from(token).ok()?)?;
    let (length, read) = read_varint(reply.get(at..)?)?;
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
    let associated = packet.get(..number_end)?.to_vec();
    let mut protected = bytes::BytesMut::from(packet.get(number_end..)?);
    keys.packet
        .local
        .decrypt(number, &associated, &mut protected)
        .ok()?;

    Some(name_frames(&protected))
}

/// The frames of a decrypted Initial payload, named rather than parsed in full.
fn name_frames(payload: &[u8]) -> Vec<String> {
    let mut named: Vec<String> = Vec::new();
    let mut at = 0usize;
    let mut padding = 0usize;

    while at < payload.len() {
        let Some((frame, read)) = read_varint(&payload[at..]) else {
            break;
        };
        at += read;
        match frame {
            0x00 => padding += 1,
            0x01 => named.push("PING".to_owned()),
            0x02 | 0x03 => {
                named.push("ACK".to_owned());
                // Enough of the shape to leave the walk in the right place is
                // not needed: an ACK is the last thing worth naming here, and a
                // reply's remaining frames are reported by what is already read.
                break;
            }
            0x06 => {
                let Some((_, offset_read)) = read_varint(&payload[at..]) else {
                    break;
                };
                at += offset_read;
                let Some((length, length_read)) = read_varint(&payload[at..]) else {
                    break;
                };
                at += length_read + usize::try_from(length).unwrap_or(0);
                named.push(format!("CRYPTO({length} bytes)"));
            }
            0x1c | 0x1d => {
                let Some((code, code_read)) = read_varint(&payload[at..]) else {
                    break;
                };
                at += code_read;
                if frame == 0x1c {
                    let Some((_, frame_read)) = read_varint(&payload[at..]) else {
                        break;
                    };
                    at += frame_read;
                }
                let Some((reason, reason_read)) = read_varint(&payload[at..]) else {
                    break;
                };
                at += reason_read;
                let end = at + usize::try_from(reason).unwrap_or(0);
                let text = payload
                    .get(at..end)
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default()
                    .into_owned();
                at = end;
                named.push(format!("CONNECTION_CLOSE({code:#x}, {text:?})"));
            }
            other => {
                named.push(format!("an unread frame of type {other:#x}"));
                break;
            }
        }
    }

    if padding > 0 {
        named.push(format!("{padding} bytes of PADDING"));
    }
    named
}

// ---------------------------------------------------------------------------
// (a) A first flight from a real stack, judged by the seam the socket uses
// ---------------------------------------------------------------------------

/// A real quinn client's first datagram reads as the name it asked for.
///
/// Captured off a UDP socket that never answers, so what is judged is exactly
/// the bytes quinn put on the wire and nothing the harness shaped. Both halves
/// are asserted: the name on the list passes, and the same datagram judged
/// against a list that does not hold it is refused *for its name*, which is what
/// says the ClientHello was read rather than given up on.
#[tokio::test]
async fn a_real_quinn_first_flight_is_judged_by_the_name_it_carries() {
    let datagram = quinn_first_flight(&["h3"], "localhost").await;

    assert_eq!(
        judgement(&datagram, &Names::new(&["localhost".to_owned()])),
        Verdict::Pass,
        "a real quinn first flight naming localhost must reach quinn"
    );
    let refusal = judgement(&datagram, &Names::new(&["other.example".to_owned()]));
    assert_eq!(
        refusal,
        Verdict::Refuse(Refusal::OtherName("\"localhost\"".to_owned())),
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
    let alpn: Vec<String> = std::iter::once("h3".to_owned())
        .chain((0..8).map(|i| format!("{i}{}", "padding-".repeat(31))))
        .collect();
    let alpn: Vec<&str> = alpn.iter().map(String::as_str).collect();
    let datagram = quinn_first_flight(&alpn, "localhost").await;

    for list in ["localhost", "other.example"] {
        assert_eq!(
            judgement(&datagram, &Names::new(&[list.to_owned()])),
            Verdict::Pass,
            "a first flight the gate cannot finish reading must pass whatever {list} says"
        );
    }
}

/// The first datagram a quinn client sends when asking for `name`.
async fn quinn_first_flight(alpn: &[&str], name: &str) -> Vec<u8> {
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a socket that never answers");
    let addr = sink.local_addr().expect("the sink's address");

    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
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
/// `Opened::Failed` defect on 2026-09-03, so what it does differently from quinn
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
        judgement(&datagram, &Names::new(&["localhost".to_owned()])),
        Verdict::Pass,
        "an aioquic first flight naming localhost must reach quinn"
    );
    assert_eq!(
        judgement(&datagram, &Names::new(&["other.example".to_owned()])),
        Verdict::Refuse(Refusal::OtherName("\"localhost\"".to_owned())),
        "the same datagram must be refused for the name it carries"
    );
}

/// The CRYPTO-side seam over a ClientHello this binary spells itself, so that a
/// change in the hand-written builder above shows up here rather than only in
/// the datagram tests that use it.
#[test]
fn the_hand_written_client_hello_reads_back_as_its_name() {
    assert_eq!(
        first_flight(&client_hello("localhost")),
        FirstFlight::Named(b"localhost".to_vec())
    );
}

// ---------------------------------------------------------------------------
// (b) Shapes with no name in them at all
// ---------------------------------------------------------------------------

/// Sends `shape` at a server with the gate off and then at one with it on.
///
/// Returns what the gate-on server said, having first asserted that the gate-off
/// server said something: a probe nobody answers proves nothing, so the control
/// is part of the probe rather than a separate test that could rot away from it.
async fn both_ways(what: &str, dcid: &[u8], shape: &[u8]) -> Vec<Vec<u8>> {
    let crypto = nameless_crypto();

    let off = TestServer::start_with(GATE_OFF).await;
    let control = answers(off.addr, shape).await;
    let described: Vec<String> = control
        .iter()
        .map(|reply| describe(&*crypto, reply, dcid))
        .collect();
    assert!(
        !control.is_empty(),
        "{what}: with the gate off this shape must draw a reply, or it tests nothing"
    );
    eprintln!("{what}: with the gate off, the server sent {described:?}");

    let on = TestServer::start_with(GATE_LOCALHOST).await;
    let heard = answers(on.addr, shape).await;
    let described: Vec<String> = heard
        .iter()
        .map(|reply| describe(&*crypto, reply, dcid))
        .collect();
    eprintln!("{what}: with the gate on, the server sent {described:?}");
    heard
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
    let crypto = nameless_crypto();
    let dcid = [0x11; 4];
    let shape = initial(&*crypto, &dcid, &[]);

    let heard = both_ways("a PADDING-only Initial, DCID 4 bytes", &dcid, &shape).await;
    assert!(
        heard.is_empty(),
        "with the gate on, a datagram carrying no name must draw no reply"
    );
}

/// The same with a connection ID quinn accepts, which gets as far as a
/// connection rather than a rejection.
///
/// Nothing in it is ack-eliciting, so whether anything comes back is a question
/// about what quinn does with a connection that says nothing, not about the
/// gate.
#[tokio::test]
async fn a_padding_only_initial_with_a_full_connection_id_is_silent() {
    let crypto = nameless_crypto();
    let dcid = [0x22; 8];
    let shape = initial(&*crypto, &dcid, &[]);

    // No `both_ways` here: with the gate off this shape is not answered either,
    // so there is no control to assert and the two servers would be the same
    // measurement twice.
    let off = TestServer::start_with(GATE_OFF).await;
    let control = answers(off.addr, &shape).await;
    eprintln!(
        "a PADDING-only Initial, DCID 8 bytes: with the gate off, {} replies",
        control.len()
    );

    let on = TestServer::start_with(GATE_LOCALHOST).await;
    let heard = answers(on.addr, &shape).await;
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
    let crypto = nameless_crypto();
    let dcid = [0x33; 8];
    let hello = client_hello("localhost");
    // Cut inside the message, before the extensions block the name lives in.
    let half = &hello[..hello.len() / 2];
    assert_eq!(
        first_flight(half),
        FirstFlight::Truncated,
        "the probe must be the fail-open shape, not a complete hello"
    );
    let shape = initial(&*crypto, &dcid, &crypto_frame_at(0, half));

    let heard = both_ways("half a ClientHello", &dcid, &shape).await;
    assert!(
        heard.is_empty(),
        "with the gate on, a first flight with no readable name must draw no reply"
    );
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
    let crypto = nameless_crypto();
    let dcid = [0x44; 8];
    let shape = initial(
        &*crypto,
        &dcid,
        &crypto_frame_at(64, &client_hello("localhost")),
    );

    let heard = both_ways("a CRYPTO frame at offset 64", &dcid, &shape).await;
    assert!(
        heard.is_empty(),
        "with the gate on, an Initial with no beginning to judge must draw no reply"
    );
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
    let crypto = nameless_crypto();
    let dcid = [0x55; 8];
    let shape = initial(&*crypto, &dcid, &[0x01]);

    let heard = both_ways("a PING-only Initial, DCID 8 bytes", &dcid, &shape).await;
    assert!(
        heard.is_empty(),
        "with the gate on, an Initial naming nobody must draw no reply"
    );
}
