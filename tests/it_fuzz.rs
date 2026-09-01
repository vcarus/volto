//! Property-based fuzzing of the protocol codec: frames, QPACK, Huffman.
//!
//! `it_props` already fuzzes the three parsers that were hand-rolled before the
//! HTTP/3 layer moved in-tree -- `datagram`, `capsule` and the CONNECT-UDP path
//! template. This file is the other half, aimed at what D75 brought with it:
//! `h3::frame`, `h3::qpack`, `h3::huffman` and `h3::message`. Nothing here
//! repeats a property `it_props` states; where the two touch the same module the
//! comment says which property over there already covers it and what this one
//! adds.
//!
//! Three things shape it.
//!
//! * **Both kinds of input.** Every property is driven by a structured
//!   generator -- something a real encoder could have produced -- *and* by
//!   arbitrary bytes, usually through a `prop_oneof!` that mixes well-formed
//!   sequences, mutated well-formed sequences, and pure noise. A generator that
//!   only builds valid input never reaches an error path; one that only emits
//!   noise practically never reaches a success path.
//! * **Chunk boundaries where the API is incremental.** The frame layer is fed
//!   by a QUIC stream, and a frame does not align with a stream read in either
//!   direction, so the answer must not depend on where the reads fall. The
//!   frame properties below therefore write the same bytes twice -- once whole,
//!   once split at generated points -- and compare.
//! * **The pure functions, called directly.** `frame::FrameDecoder` and
//!   `stream::build_request` are `pub` so that the properties can feed the
//!   decoder a chosen chunk sequence on a chosen `StreamKind`, and hand the
//!   request validator a field section built pseudo-header by pseudo-header.
//!   Reaching either through a live connection costs exactly what a property
//!   wants to vary: quinn decides where the chunk boundaries fall, and a QUIC
//!   stream per pseudo-header combination is not a thing to generate thousands
//!   of. The properties that do put bytes on a real stream stay alongside them,
//!   because that is where a peer meets this code.
//!
//! Run it as a fuzzer with:
//!
//! ```sh
//! PROPTEST_CASES=300000 cargo test --release --test it_fuzz
//! ```
//!
//! `PROPTEST_CASES` is honoured by every property here; the per-property counts
//! below are CI defaults, applied only when the variable is unset. The defaults
//! run in about a second, and almost all of a long run is spent in the five
//! properties that put bytes on a QUIC stream, which is why their defaults are
//! the low ones.

mod common;

#[path = "common/proptest_support.rs"]
mod props;

use std::borrow::Cow;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use proptest::prelude::*;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

use props::{config, pattern, payload, put_varint_in};

use volto::capsule::{self, CapsuleDecoder};
use volto::datagram::{self, DecodeError, VARINT_MAX};
use volto::h3::error::Code;
use volto::h3::frame::{self, BufferBudget, Frame, FrameDecoder, FrameReader, Item, StreamKind};
use volto::h3::message::{self, FieldValue, Fields, Method, Request, Status};
use volto::h3::qpack::{self, Field};
use volto::h3::stream::build_request;
use volto::h3::{MAX_FIELD_SECTION_SIZE, huffman};

/// The per-field overhead in RFC 9114 §4.2.2's field-section size formula.
///
/// Written out here rather than reached for in `qpack`, where it is private
/// anyway: a test that computed the limit with the same constant the code
/// enforces it with would agree with the code whatever the constant held.
///
//= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
//# The size of a field list is calculated based on the uncompressed size
//# of fields, including the length of the name and value in bytes plus an
//# overhead of 32 bytes for each field.
const FIELD_OVERHEAD: u64 = 32;

/// Varints across all four length classes, with the boundaries oversampled.
fn any_varint() -> impl Strategy<Value = u64> {
    prop_oneof![
        2 => 0u64..=0x3f,
        2 => 0x40u64..=0x3fff,
        2 => 0x4000u64..=0x3fff_ffff,
        2 => 0x4000_0000u64..=VARINT_MAX,
        1 => prop::sample::select(vec![
            0, 1, 0x3f, 0x40, 0x3fff, 0x4000, 0x3fff_ffff, 0x4000_0000, VARINT_MAX,
        ]),
    ]
}

/// Splits `bytes` at the offsets in `cuts`, clamped into range and deduplicated.
fn split_at(bytes: &[u8], cuts: &[u16]) -> Vec<Vec<u8>> {
    let mut offsets: Vec<usize> = cuts
        .iter()
        .map(|cut| usize::from(*cut) % (bytes.len() + 1))
        .collect();
    offsets.push(0);
    offsets.push(bytes.len());
    offsets.sort_unstable();
    offsets.dedup();

    offsets
        .windows(2)
        .map(|pair| bytes[pair[0]..pair[1]].to_vec())
        .filter(|chunk| !chunk.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// QUIC varints
// ---------------------------------------------------------------------------
//
// The varint codec lives in `volto::datagram`, not in a `volto::h3::varint`
// module: `src/h3/frame.rs` imports `peek_varint`/`put_varint` from there and
// there is no second implementation.
//
// `it_props` already states the two properties that matter most about it:
// `a_varint_round_trips_and_leaves_the_remainder_alone` (encode then decode is
// the identity, in exactly `varint_len` bytes, with the tail untouched) and
// `every_proper_prefix_of_a_varint_needs_more_bytes` (a truncated encoding is
// always "need more", never a value, and a failed `take_varint` consumes
// nothing). Neither is repeated. What is added is the other direction: what
// `peek_varint` does with bytes that were never an encoding, and the fact that
// an encoding *longer than necessary* -- which RFC 9000 §16 permits and no
// encoder in this tree emits -- decodes to the value it spells.

proptest! {
    #![proptest_config(config(2048))]

    /// Arbitrary bytes: `peek_varint` never panics, and whatever it answers
    /// agrees with the self-description of the first byte.
    ///
    /// RFC 9000 §16 puts the length in the two most significant bits of the
    /// first byte, so the length is knowable before the value is. A decoder that
    /// returned a value having consumed a different number of bytes has gone out
    /// of step with the peer's writer, and every field after it is misread --
    /// which is exactly how a frame length becomes a frame type. Stated over
    /// noise rather than over encodings, because the bytes this runs on are a
    /// peer's.
    #[test]
    fn peeking_at_arbitrary_bytes_agrees_with_the_length_prefix(
        raw in prop_oneof![
            3 => prop::collection::vec(any::<u8>(), 0..12),
            2 => prop::collection::vec(
                prop_oneof![
                    Just(0x00u8), Just(0x3f), Just(0x40),
                    Just(0x80), Just(0xc0), Just(0xff), any::<u8>(),
                ],
                0..12,
            ),
            1 => prop::collection::vec(any::<u8>(), 0..600),
        ],
    ) {
        match datagram::peek_varint(&raw) {
            None => {
                // The only reason to need more is that the length the first
                // byte announced has not all arrived.
                prop_assert!(
                    raw.is_empty() || raw.len() < 1usize << (raw[0] >> 6),
                    "refused {} bytes announcing {}",
                    raw.len(),
                    1usize << (raw[0] >> 6)
                );
            }
            Some((value, used)) => {
                prop_assert_eq!(used, 1usize << (raw[0] >> 6));
                prop_assert!(used <= raw.len());

                // The value is the announced bytes with the two length bits
                // masked off, big-endian -- computed here rather than taken from
                // the module under test.
                let mut expected = u64::from(raw[0] & 0x3f);
                for byte in &raw[1..used] {
                    expected = (expected << 8) | u64::from(*byte);
                }
                prop_assert_eq!(value, expected);
                prop_assert!(value <= VARINT_MAX);
            }
        }
    }

    /// A varint written longer than it needs to be still decodes to its value,
    /// in every length that can hold it.
    ///
    /// `varint_len` gives the shortest and `put_varint` only ever writes that
    /// one, so no test built out of `put_varint` alone can reach this: the
    /// non-minimal forms are what a *peer* may send. `it_props` pins the same
    /// permission one layer up, through `datagram::decode`; this pins it at the
    /// varint itself, where a length-class bug would actually live.
    #[test]
    fn a_varint_written_longer_than_it_needs_decodes_to_the_same_value(
        value in any_varint(),
        tail in payload(16),
    ) {
        let minimum = datagram::varint_len(value);
        for length in [1usize, 2, 4, 8] {
            if length < minimum {
                continue;
            }

            let mut buf = BytesMut::new();
            put_varint_in(&mut buf, value, length);
            buf.put_slice(&tail);

            let (decoded, used) = datagram::peek_varint(&buf).expect("a whole varint");
            prop_assert_eq!(decoded, value, "in {} bytes", length);
            prop_assert_eq!(used, length);

            let mut taking = buf.freeze();
            prop_assert_eq!(datagram::take_varint(&mut taking), Some(value));
            prop_assert_eq!(&taking[..], &tail[..]);
        }
    }
}

/// Every one-byte varint, and every boundary of the other three classes.
///
/// "Round-trips for every u62" is not something a generator can state, so the
/// class small enough to enumerate is checked exhaustively and the three that
/// are not are checked where an off-by-one would live: each power of two, each
/// value one below it, and each length-class boundary either side.
#[test]
fn every_short_varint_and_every_class_boundary_round_trips() {
    let mut values: Vec<u64> = (0..=0x3fu64).collect();
    for boundary in [
        0x3fu64,
        0x40,
        0x3fff,
        0x4000,
        0x3fff_ffff,
        0x4000_0000,
        VARINT_MAX,
    ] {
        values.push(boundary.saturating_sub(1));
        values.push(boundary);
        values.push(boundary.saturating_add(1).min(VARINT_MAX));
    }
    for shift in 0..62 {
        values.push(1u64 << shift);
        values.push((1u64 << shift) - 1);
    }

    for value in values {
        let mut buf = BytesMut::new();
        datagram::put_varint(&mut buf, value);
        assert_eq!(buf.len(), datagram::varint_len(value), "{value:#x}");
        assert_eq!(
            datagram::peek_varint(&buf),
            Some((value, buf.len())),
            "{value:#x}"
        );

        let mut taking = buf.freeze();
        assert_eq!(
            datagram::take_varint(&mut taking),
            Some(value),
            "{value:#x}"
        );
        assert!(taking.is_empty(), "{value:#x}");
    }
}

// ---------------------------------------------------------------------------
// The frame layer
// ---------------------------------------------------------------------------
//
// Two ways in, and the properties below use both.
//
// `frame::FrameDecoder` is the pure state machine: it holds every byte of its
// own state, so a property can hand it a chunk sequence it chose -- one byte at
// a time, or cut at generated offsets -- and can build it for any of the three
// `StreamKind`s this server reads. Those are the two things a loopback
// connection cannot give. quinn decides how a write is packetised, so a
// *write*-splitting property only ever states that the answer survived whatever
// chunking quinn picked; and `FrameReader::new` is the permissive constructor,
// the one the peer's control stream gets, so the request-stream and tunnel
// verdicts -- SETTINGS, GOAWAY, CANCEL_PUSH, MAX_PUSH_ID, PUSH_PROMISE and a
// post-CONNECT HEADERS, each refused from the frame header alone -- are out of
// its reach entirely.
//
// The properties that put bytes on a real QUIC stream stay. The decoder is only
// half of what a peer meets: `FrameReader` is the other half, and it is what
// turns the end of a stream into RFC 9114 §7.1's verdict. That the in-process
// half really is the half the wire runs is itself a property --
// `a_stream_reader_adds_only_the_end_of_stream_rule_to_the_decoder` -- so
// neither side is trusted on its own.

/// ALPN for the bare QUIC pair below; it speaks no protocol quinn knows about.
const FUZZ_ALPN: &str = "volto-fuzz";

/// Upper bound for one case on the loopback pair.
const WIRE_TIMEOUT: Duration = Duration::from_secs(20);

/// Frame types RFC 9114 §7.2 defines.
const KNOWN_TYPES: [u64; 7] = [
    frame::DATA,
    frame::HEADERS,
    frame::CANCEL_PUSH,
    frame::SETTINGS,
    frame::PUSH_PROMISE,
    frame::GOAWAY,
    frame::MAX_PUSH_ID,
];

/// Frame types RFC 9114 §11.2.1 reserves because HTTP/2 used them.
const RESERVED_TYPES: [u64; 4] = [0x02, 0x06, 0x08, 0x09];

/// The types `begin` buffers, and so the ones a declared length can be refused
/// for.
const BUFFERED_TYPES: [u64; 6] = [
    frame::HEADERS,
    frame::SETTINGS,
    frame::GOAWAY,
    frame::CANCEL_PUSH,
    frame::MAX_PUSH_ID,
    frame::PUSH_PROMISE,
];

/// A connected pair of QUIC endpoints, built once and shared by every wire
/// property.
///
/// One connection, one stream per case: a handshake per case would dominate the
/// run time, and nothing here is about the handshake.
struct Wire {
    runtime: tokio::runtime::Runtime,
    /// The writing half, which opens the stream each case runs on.
    writer: quinn::Connection,
    /// The reading half, where `FrameReader` sits.
    reader: quinn::Connection,
    /// One case at a time on the shared connection.
    ///
    /// `cargo test` runs the properties in this file on several threads at
    /// once, and `accept_bi` hands out whichever stream arrived -- not the one
    /// the calling thread opened. Without this, two cases running together each
    /// read the other's bytes. Serialising costs nothing that matters: what is
    /// slow here is the round trip, and the round trips would have queued behind
    /// each other on one connection anyway.
    gate: Mutex<()>,
    /// Kept alive: dropping an endpoint closes its connections.
    _endpoints: (quinn::Endpoint, quinn::Endpoint),
}

fn wire() -> &'static Wire {
    static WIRE: OnceLock<Wire> = OnceLock::new();
    WIRE.get_or_init(build_wire)
}

fn build_wire() -> Wire {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime");

    let (writer, reader, endpoints) = runtime.block_on(async {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate self-signed certificate");
        let certificate = issued.cert.der().clone();
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der()));

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .expect("server certificate");
        crypto.alpn_protocols = vec![FUZZ_ALPN.as_bytes().to_vec()];

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(crypto).expect("quic tls"),
        ));
        server_config.transport_config(Arc::new(transport()));

        let server_endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().expect("bind address"))
                .expect("server endpoint");
        let addr = server_endpoint.local_addr().expect("local address");

        let client_endpoint =
            common::client_endpoint_with_transport(&certificate, &[FUZZ_ALPN], transport());

        // Both halves of the accept in one future: an `Incoming` that is never
        // awaited is a handshake that never finishes, so joining on `accept()`
        // alone would leave the client waiting for a peer that has stopped.
        let accepting = async {
            server_endpoint
                .accept()
                .await
                .expect("an incoming connection")
                .await
                .expect("server handshake")
        };
        let connecting = async {
            client_endpoint
                .connect(addr, "localhost")
                .expect("start connecting")
                .await
                .expect("client handshake")
        };
        let (client, server) = tokio::join!(connecting, accepting);

        (client, server, (client_endpoint, server_endpoint))
    });

    Wire {
        runtime,
        writer,
        reader,
        gate: Mutex::new(()),
        _endpoints: endpoints,
    }
}

/// Transport parameters generous enough that nothing here is about them.
///
/// The stream limit is what a long run needs: one bidirectional stream per case,
/// and a case that ends with the reader refusing a frame leaves its stream to be
/// retired asynchronously.
fn transport() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4096u32.into());
    transport.max_idle_timeout(Some(
        Duration::from_secs(300).try_into().expect("idle timeout"),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    transport
}

/// What the reader made of a stream, in a form two runs can be compared in.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    /// DATA payload. Consecutive ones are merged by [`normalise`], because how
    /// a frame's payload is cut into chunks is quinn's choice, not the codec's.
    Data(Vec<u8>),
    /// A frame of an unknown type, skipped whole (RFC 9114 §9).
    Skipped(u64),
    /// A HEADERS frame, still QPACK-encoded.
    Headers(Vec<u8>),
    /// SETTINGS, reduced to the one setting this server acts on.
    Settings(bool),
    Goaway(u64),
    CancelPush(u64),
    MaxPushId(u64),
    PushPromise,
    /// The peer finished and the stream ended at a frame boundary.
    End,
    /// The bytes ran out inside a frame.
    ///
    /// Only an in-process run can end here: a [`FrameDecoder`] is told nothing
    /// about how the stream ends, so "no more input" and "the peer finished"
    /// are the same state to it and [`FrameDecoder::at_frame_boundary`] is the
    /// question a caller asks. On the wire that question has already been put,
    /// and its answer is [`Step::Violation`] with H3_FRAME_ERROR.
    Incomplete,
    /// The peer broke one of RFC 9114 §7's rules.
    Violation {
        code: u64,
        connection: bool,
    },
    /// The stream itself failed. Not a codec answer; recorded so a run that
    /// reached one is not silently compared against one that did not.
    Broken,
}

impl Step {
    fn of(item: Item) -> Self {
        match item {
            Item::Data(bytes) => Self::Data(bytes.to_vec()),
            Item::Skipped { kind } => Self::Skipped(kind),
            Item::Frame(Frame::Headers(bytes)) => Self::Headers(bytes.to_vec()),
            Item::Frame(Frame::Settings(settings)) => Self::Settings(settings.datagrams),
            Item::Frame(Frame::Goaway(id)) => Self::Goaway(id),
            Item::Frame(Frame::CancelPush(id)) => Self::CancelPush(id),
            Item::Frame(Frame::MaxPushId(id)) => Self::MaxPushId(id),
            Item::Frame(Frame::PushPromise) => Self::PushPromise,
        }
    }

    fn of_error(error: &frame::Error) -> Self {
        match error {
            frame::Error::Protocol(violation) => Self::Violation {
                code: violation.code().value(),
                connection: violation.is_connection_error(),
            },
            frame::Error::Stream(_) => Self::Broken,
        }
    }
}

/// Merges consecutive [`Step::Data`], which is the one thing a run may disagree
/// about without the codec being wrong.
///
/// A DATA frame's payload is handed out in the chunks quinn delivered it in, and
/// quinn chooses those from packetisation. The bytes and their order are the
/// codec's answer; where the cuts fall are not. Two adjacent DATA frames merge
/// into one entry here, which is the small amount of resolution this costs.
fn normalise(steps: Vec<Step>) -> Vec<Step> {
    let mut out: Vec<Step> = Vec::with_capacity(steps.len());
    for step in steps {
        match (out.last_mut(), step) {
            (Some(Step::Data(held)), Step::Data(more)) => held.extend_from_slice(&more),
            (_, step) => out.push(step),
        }
    }
    out
}

/// Writes `chunks` on a fresh stream and reads them back with a [`FrameReader`]
/// drawing on `budget`.
///
/// The stream is finished as soon as the last chunk is written, so a reader
/// waiting for bytes that never come sees the end rather than hanging. That
/// makes "the stream ended part-way through a frame" -- RFC 9114 §7.1's
/// H3_FRAME_ERROR -- the answer for a truncated input, which is exactly the
/// answer a real peer would get. (The one path that does not finish is a write
/// the reader stopped, which means the reader has already answered.)
fn drive_with(chunks: &[Vec<u8>], budget: &Arc<BufferBudget>) -> Vec<Step> {
    let wire = wire();
    let budget = Arc::clone(budget);

    // A failed case panics out of here, which poisons the gate; the wire itself
    // is none the worse for it, so the guard is taken back rather than becoming
    // a second failure on every case after the first.
    let _guard = wire.gate.lock().unwrap_or_else(PoisonError::into_inner);

    wire.runtime.block_on(async move {
        let attempt = async {
            let (mut send, _client_recv) = wire.writer.open_bi().await.expect("open a stream");

            let write = async move {
                for chunk in chunks {
                    // A failed write is not a failure of the test: a reader that
                    // has refused the stream stops it, and STOP_SENDING is what
                    // that looks like from here.
                    if send.write_all(chunk).await.is_err() {
                        return;
                    }
                }
                let _ = send.finish();
            };

            let read = async move {
                let (_server_send, recv) = wire.reader.accept_bi().await.expect("accept a stream");
                let mut reader = FrameReader::new(recv, budget);
                let mut steps = Vec::new();
                loop {
                    match reader.next().await {
                        Ok(Some(item)) => steps.push(Step::of(item)),
                        Ok(None) => {
                            steps.push(Step::End);
                            break;
                        }
                        Err(error) => {
                            steps.push(Step::of_error(&error));
                            break;
                        }
                    }
                }
                steps
            };

            let (_, steps) = tokio::join!(write, read);
            normalise(steps)
        };

        tokio::time::timeout(WIRE_TIMEOUT, attempt)
            .await
            .expect("a stream must not outlast the timeout")
    })
}

/// [`drive_with`] on a budget of this stream's own.
fn drive(chunks: &[Vec<u8>]) -> Vec<Step> {
    drive_with(chunks, &Arc::new(BufferBudget::default()))
}

/// Pushes `chunks` through `decoder`, appending what comes out to `steps`.
///
/// `false` once the decoder has refused something, which is the end of what it
/// has to say: the chunk it stopped in is not consumed, and pushing another
/// would trip [`FrameDecoder::push`]'s debug assertion. Every other return
/// leaves the decoder ready for more, which is what lets a caller feed it in
/// stages -- a request, then the CONNECT being answered, then the tunnel.
fn feed(decoder: &mut FrameDecoder, chunks: &[Vec<u8>], steps: &mut Vec<Step>) -> bool {
    for chunk in chunks {
        decoder.push(Bytes::from(chunk.clone()));
        loop {
            match decoder.next_item() {
                Ok(Some(item)) => steps.push(Step::of(item)),
                Ok(None) => break,
                Err(error) => {
                    steps.push(Step::of_error(&error));
                    return false;
                }
            }
        }
    }
    true
}

/// Where a decoder that has run out of input stands (RFC 9114 §7.1).
fn terminal(decoder: &FrameDecoder) -> Step {
    if decoder.at_frame_boundary() {
        Step::End
    } else {
        Step::Incomplete
    }
}

/// What a decoder for `kind` makes of `chunks`, in the vocabulary [`drive`]
/// answers in.
fn decode_chunks(kind: StreamKind, chunks: &[Vec<u8>]) -> Vec<Step> {
    let mut decoder = FrameDecoder::new(kind, Arc::new(BufferBudget::default()));
    let mut steps = Vec::new();
    if feed(&mut decoder, chunks, &mut steps) {
        steps.push(terminal(&decoder));
    }
    normalise(steps)
}

/// [`decode_chunks`] with every byte its own chunk.
///
/// The worst case a real stream can produce, and the one thing the wire cannot
/// be asked for: it is where a frame header straddling chunks is either
/// reassembled or mis-parsed.
fn decode_bytewise(kind: StreamKind, bytes: &[u8]) -> Vec<Step> {
    let chunks: Vec<Vec<u8>> = bytes.iter().map(|byte| vec![*byte]).collect();
    decode_chunks(kind, &chunks)
}

/// Reads `request`, answers the CONNECT if `narrow`, then reads `tail`.
///
/// The transition RFC 9114 §4.4 turns on, which no constructor reaches: a
/// stream that carried a field section a moment ago is a tunnel now.
fn through_connect(narrow: bool, request: &[Vec<u8>], tail: &[Vec<u8>]) -> Vec<Step> {
    let mut decoder = FrameDecoder::new(StreamKind::Request, Arc::new(BufferBudget::default()));
    let mut steps = Vec::new();

    if feed(&mut decoder, request, &mut steps) {
        if narrow {
            decoder.connect_completed();
        }
        if feed(&mut decoder, tail, &mut steps) {
            steps.push(terminal(&decoder));
        }
    }
    normalise(steps)
}

/// The frame types that may not appear on `kind` at all.
///
/// Written out here rather than asked of `frame`, where the rule is private
/// anyway: a test that read the table the code enforces would agree with the
/// code whatever the table held.
fn refused_on(kind: StreamKind) -> &'static [u64] {
    match kind {
        // RFC 9114 §6.2.1 makes this the stream every one of them belongs on.
        StreamKind::Control => &[],
        StreamKind::Request => &[
            frame::SETTINGS,
            frame::GOAWAY,
            frame::CANCEL_PUSH,
            frame::MAX_PUSH_ID,
            frame::PUSH_PROMISE,
        ],
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
        //# Once the CONNECT method has completed, only DATA frames are permitted
        //# to be sent on the stream.
        StreamKind::Tunnel => &[
            frame::HEADERS,
            frame::SETTINGS,
            frame::GOAWAY,
            frame::CANCEL_PUSH,
            frame::MAX_PUSH_ID,
            frame::PUSH_PROMISE,
        ],
    }
}

/// The refusal every rule in [`refused_on`] hands out.
fn frame_unexpected() -> Step {
    Step::Violation {
        code: Code::H3_FRAME_UNEXPECTED.value(),
        connection: true,
    }
}

/// A frame every stream kind may carry, for the bytes before the one under test.
///
/// DATA, or a type RFC 9114 §9 says to skip. Neither is refused anywhere, so a
/// property about where the *next* frame may appear is not decided by these.
fn any_allowed_frame_spec() -> impl Strategy<Value = FrameSpec> {
    prop_oneof![
        2 => payload(96).prop_map(|payload| FrameSpec { kind: frame::DATA, payload }),
        1 => any_unknown_type().prop_flat_map(|kind| {
            payload(96).prop_map(move |payload| FrameSpec { kind, payload })
        }),
    ]
}

/// What [`any_allowed_frame_spec`] frames must decode to, computed from the
/// specs rather than from a run.
fn expected_steps(specs: &[FrameSpec]) -> Vec<Step> {
    normalise(
        specs
            .iter()
            .map(|spec| match spec.kind {
                frame::DATA => Step::Data(spec.payload.clone()),
                kind => Step::Skipped(kind),
            })
            .collect(),
    )
}

/// Whether `prefix` is what `whole` had answered by some point in its input.
///
/// Element-wise equality, except that the last entry may be a byte-prefix of its
/// counterpart: DATA payload is handed out as it arrives, so a run whose bytes
/// stopped inside a DATA frame has rightly reported fewer of them.
fn is_answer_prefix(prefix: &[Step], whole: &[Step]) -> bool {
    if prefix.len() > whole.len() {
        return false;
    }
    let Some((last, rest)) = prefix.split_last() else {
        return true;
    };
    if rest != &whole[..rest.len()] {
        return false;
    }
    match (last, &whole[rest.len()]) {
        (Step::Data(held), Step::Data(all)) => all.starts_with(held),
        (left, right) => left == right,
    }
}

/// Every stream kind a decoder can be built for.
fn any_stream_kind() -> impl Strategy<Value = StreamKind> {
    prop::sample::select(vec![
        StreamKind::Control,
        StreamKind::Request,
        StreamKind::Tunnel,
    ])
}

/// One frame to put on the wire.
#[derive(Debug, Clone)]
struct FrameSpec {
    kind: u64,
    payload: Vec<u8>,
}

/// Encodes them with the crate's own `frame::put_header`, unlike the raw-stream
/// helpers, which hand-write their varints: this is a round trip through the
/// codec under test and the encoder is deliberately half of it.
fn frame_bytes(specs: &[FrameSpec]) -> Vec<u8> {
    let mut out = BytesMut::new();
    for spec in specs {
        frame::put_header(&mut out, spec.kind, spec.payload.len() as u64);
        out.put_slice(&spec.payload);
    }
    out.to_vec()
}

/// A frame type that is neither defined by RFC 9114 §7.2 nor reserved by
/// §11.2.1, so RFC 9114 §9 says it must be skipped.
fn any_unknown_type() -> impl Strategy<Value = u64> {
    prop_oneof![
        // The reserved "grease" types of RFC 9114 §7.2.8, which a real client
        // sends precisely to catch a peer that cannot skip what it does not
        // know: 0x1f * N + 0x21.
        2 => (0u64..=0x0002_0000).prop_map(|n| 0x1f * n + 0x21),
        3 => any_varint(),
    ]
    .prop_filter("a type this server knows", |kind| {
        !KNOWN_TYPES.contains(kind) && !RESERVED_TYPES.contains(kind)
    })
}

/// A well-formed payload for `kind`, so the structured generator reaches the
/// parsers behind the framing rather than stopping at them.
fn well_formed_payload(kind: u64) -> BoxedStrategy<Vec<u8>> {
    match kind {
        frame::DATA => payload(1024).boxed(),
        frame::HEADERS => prop::collection::vec((payload(24), payload(48)), 0..6)
            .prop_map(|fields| {
                let mut block = BytesMut::new();
                qpack::encode(
                    &mut block,
                    fields
                        .iter()
                        .map(|(name, value)| (name.as_slice(), value.as_slice())),
                );
                block.to_vec()
            })
            .boxed(),
        frame::SETTINGS => prop::collection::vec((any_varint(), any_varint()), 0..8)
            .prop_map(|pairs| {
                let mut out = BytesMut::new();
                let mut seen = Vec::new();
                for (identifier, value) in pairs {
                    // RFC 9114 §7.2.4 forbids a repeat and §11.2.2 the five
                    // HTTP/2 identifiers; a "well-formed" payload has neither,
                    // and the mutated generator is what reaches those branches.
                    if seen.contains(&identifier) || (identifier <= 0x05 && identifier != 0x01) {
                        continue;
                    }
                    seen.push(identifier);
                    // RFC 9297 §2.1.1 restricts this one to 0 or 1; every other
                    // value is either ignored or acted on whatever it says.
                    let value = if identifier == frame::SETTING_H3_DATAGRAM {
                        value & 1
                    } else {
                        value
                    };
                    datagram::put_varint(&mut out, identifier);
                    datagram::put_varint(&mut out, value);
                }
                out.to_vec()
            })
            .boxed(),
        frame::GOAWAY | frame::CANCEL_PUSH | frame::MAX_PUSH_ID => any_varint()
            .prop_map(|value| {
                let mut out = BytesMut::new();
                datagram::put_varint(&mut out, value);
                out.to_vec()
            })
            .boxed(),
        // PUSH_PROMISE's payload is never parsed -- receiving one at all is the
        // fault -- and an unknown type's is skipped without being looked at.
        _ => payload(256).boxed(),
    }
}

fn any_frame_spec() -> impl Strategy<Value = FrameSpec> {
    prop_oneof![
        5 => prop::sample::select(KNOWN_TYPES.to_vec())
            .prop_flat_map(|kind| well_formed_payload(kind).prop_map(move |payload| FrameSpec { kind, payload })),
        3 => any_unknown_type()
            .prop_flat_map(|kind| payload(128).prop_map(move |payload| FrameSpec { kind, payload })),
        1 => prop::sample::select(RESERVED_TYPES.to_vec())
            .prop_flat_map(|kind| payload(32).prop_map(move |payload| FrameSpec { kind, payload })),
    ]
}

/// Bytes aimed at every branch of the frame decoder: well-formed sequences,
/// well-formed sequences with a few bytes rewritten, an alphabet of varint
/// prefixes, and pure noise.
fn frame_ish_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        4 => prop::collection::vec(any_frame_spec(), 1..5).prop_map(|specs| frame_bytes(&specs)),
        3 => (
            prop::collection::vec(any_frame_spec(), 1..5),
            prop::collection::vec((any::<u16>(), any::<u8>()), 1..8),
        ).prop_map(|(specs, edits)| {
            let mut bytes = frame_bytes(&specs);
            for (index, byte) in edits {
                if !bytes.is_empty() {
                    let index = usize::from(index) % bytes.len();
                    bytes[index] = byte;
                }
            }
            bytes
        }),
        2 => prop::collection::vec(
            prop_oneof![
                Just(0x00u8), Just(0x01), Just(0x02), Just(0x03), Just(0x04),
                Just(0x3f), Just(0x40), Just(0x80), Just(0xc0), Just(0xff),
                any::<u8>(),
            ],
            0..256,
        ),
        1 => prop::collection::vec(any::<u8>(), 0..512),
    ]
}

proptest! {
    // Low by default and scaled by `PROPTEST_CASES`: every case here is a QUIC
    // stream with a round trip on it, some three orders of magnitude dearer than
    // a pure-function case.
    #![proptest_config(config(64))]

    /// Arbitrary bytes never panic the frame layer, no answer it gives is
    /// larger than what it says it buffers, and where the writes were split
    /// makes no difference to any of it.
    ///
    /// The three claims are one property because they are one run: splitting the
    /// writes is only interesting if the unsplit run is also checked, and the
    /// size bound has to hold in both.
    #[test]
    fn arbitrary_frame_bytes_decode_the_same_however_the_writes_are_split(
        bytes in frame_ish_bytes(),
        cuts in prop::collection::vec(any::<u16>(), 0..6),
    ) {
        let whole = drive(std::slice::from_ref(&bytes));
        prop_assert_eq!(drive(&split_at(&bytes, &cuts)), whole.clone(), "cuts {:?}", cuts);

        for step in &whole {
            // The per-frame cap is on the *declared* length, so nothing the
            // decoder hands back may be past it. A HEADERS frame larger than
            // this would mean the length check was skipped, which is the bound
            // an unauthenticated peer's memory footprint rests on.
            if let Step::Headers(block) = step {
                prop_assert!(
                    block.len() as u64 <= MAX_FIELD_SECTION_SIZE,
                    "a {}-byte HEADERS frame came back",
                    block.len()
                );
            }
        }

        // A run either ends or fails, exactly once, at the end.
        let terminal = whole
            .iter()
            .filter(|step| matches!(step, Step::End | Step::Violation { .. } | Step::Broken))
            .count();
        prop_assert_eq!(terminal, 1, "{:?}", whole);
        prop_assert!(
            matches!(
                whole.last(),
                Some(Step::End | Step::Violation { .. } | Step::Broken)
            ),
            "a run must end with its terminal step: {:?}",
            whole
        );
    }

    /// RFC 9114 §9: a frame type this server does not know is skipped whole,
    /// whatever its payload is and wherever it sits in the sequence.
    ///
    /// The frames either side are the point: a decoder that mislaid the skipped
    /// frame's length by a byte would report the DATA after it as something
    /// else, or not at all.
    #[test]
    fn an_unknown_frame_type_is_skipped_without_disturbing_its_neighbours(
        kind in any_unknown_type(),
        skipped in payload(600),
        before in payload(64),
        after in payload(64),
        cuts in prop::collection::vec(any::<u16>(), 0..6),
    ) {
        let specs = [
            FrameSpec { kind: frame::DATA, payload: before.clone() },
            FrameSpec { kind, payload: skipped },
            FrameSpec { kind: frame::DATA, payload: after.clone() },
        ];
        let bytes = frame_bytes(&specs);

        let expected = vec![
            Step::Data(before.clone()),
            Step::Skipped(kind),
            Step::Data(after.clone()),
            Step::End,
        ];

        prop_assert_eq!(drive(std::slice::from_ref(&bytes)), expected.clone());
        prop_assert_eq!(drive(&split_at(&bytes, &cuts)), expected, "cuts {:?}", cuts);
    }

    /// RFC 9114 §7.2.8: a frame type reserved because HTTP/2 used it is a
    /// connection error of type H3_FRAME_UNEXPECTED, decided from the type
    /// alone.
    ///
    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
    //# These frame types MUST NOT be sent, and their receipt MUST be treated
    //# as a connection error of type H3_FRAME_UNEXPECTED.
    ///
    /// "From the type alone" is the half worth a property: the payload is never
    /// written, so the refusal cannot have depended on it.
    #[test]
    fn a_reserved_http2_frame_type_is_a_connection_error(
        kind in prop::sample::select(RESERVED_TYPES.to_vec()),
        length in any_varint(),
        before in payload(48),
        cuts in prop::collection::vec(any::<u16>(), 0..4),
    ) {
        let mut bytes = BytesMut::new();
        frame::put_header(&mut bytes, frame::DATA, before.len() as u64);
        bytes.put_slice(&before);
        // Header only: whatever length it claims, not one byte of the payload
        // follows it.
        frame::put_header(&mut bytes, kind, length);
        let bytes = bytes.to_vec();

        let expected = vec![
            Step::Data(before.clone()),
            Step::Violation {
                code: Code::H3_FRAME_UNEXPECTED.value(),
                connection: true,
            },
        ];

        prop_assert_eq!(drive(std::slice::from_ref(&bytes)), expected.clone());
        prop_assert_eq!(drive(&split_at(&bytes, &cuts)), expected, "cuts {:?}", cuts);
    }

    /// A declared length past the per-frame cap is refused from the header
    /// alone.
    ///
    /// This is the allocation bound, stated the only way a test can state one
    /// without a heap profiler: nothing but the frame header is ever written --
    /// nine bytes for a 2^62-1 length -- so a decoder that waited for the
    /// payload before answering would hang here rather than fail, and one that
    /// sized a buffer from the declared length would be asking for four
    /// exabytes before it could. The refusal arrives instead, and it is a
    /// stream error: the request is lost, the connection and its tunnels are
    /// not.
    ///
    /// That the refusal also costs the *connection's* budget nothing is checked
    /// by [`refusing_frames_never_charges_the_connections_budget`], as one case
    /// rather than a property: it needs a 64 KiB frame per run.
    #[test]
    fn a_length_past_the_cap_is_refused_from_the_header_alone(
        kinds in prop::collection::vec(prop::sample::select(BUFFERED_TYPES.to_vec()), 1..4),
        lengths in prop::collection::vec(
            prop_oneof![
                2 => Just(MAX_FIELD_SECTION_SIZE + 1),
                2 => Just(VARINT_MAX),
                3 => (MAX_FIELD_SECTION_SIZE + 1)..=VARINT_MAX,
            ],
            1..4,
        ),
    ) {
        let budget = Arc::new(BufferBudget::default());
        let started = Instant::now();

        for (kind, length) in kinds.iter().zip(lengths.iter().cycle()) {
            let mut header = BytesMut::new();
            frame::put_header(&mut header, *kind, *length);
            prop_assert!(header.len() <= 16, "a frame header is two varints");

            prop_assert_eq!(
                drive_with(&[header.to_vec()], &budget),
                vec![Step::Violation {
                    code: Code::H3_EXCESSIVE_LOAD.value(),
                    connection: false,
                }],
                "type {:#x} declaring {} bytes",
                kind,
                length
            );
        }

        // Promptness, as a bound rather than a measurement: every refusal above
        // is decided from a handful of bytes, so a run anywhere near the timeout
        // was waiting for a payload nobody sent.
        prop_assert!(
            started.elapsed() < WIRE_TIMEOUT,
            "the refusals took {:?}",
            started.elapsed()
        );
    }

    /// A `FrameReader` on a QUIC stream answers what its `FrameDecoder` did,
    /// plus RFC 9114 §7.1's verdict on a stream that ended inside a frame.
    ///
    /// The bridge between the two halves of this section, and the reason the
    /// in-process properties are allowed to stand for on-wire behaviour: the
    /// same bytes go to a real stream and to a decoder built by hand, and the
    /// only difference permitted between the two answers is the one thing a
    /// decoder cannot know -- that the peer has finished sending.
    ///
    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.1
    //# When a stream terminates cleanly, if the last frame on the stream was
    //# truncated, this MUST be treated as a connection error of type
    //# H3_FRAME_ERROR.
    ///
    /// `FrameReader::new` is the control stream's constructor, so
    /// `StreamKind::Control` is the decoder this compares against; the other two
    /// kinds have no on-wire spelling a test binary can reach, which is what
    /// makes this property the whole of the tie between them.
    #[test]
    fn a_stream_reader_adds_only_the_end_of_stream_rule_to_the_decoder(
        bytes in frame_ish_bytes(),
    ) {
        let decoded = decode_chunks(StreamKind::Control, std::slice::from_ref(&bytes));

        let expected: Vec<Step> = decoded
            .iter()
            .map(|step| match step {
                Step::Incomplete => Step::Violation {
                    code: Code::H3_FRAME_ERROR.value(),
                    connection: true,
                },
                other => other.clone(),
            })
            .collect();

        prop_assert_eq!(drive(std::slice::from_ref(&bytes)), expected);
    }
}

proptest! {
    // No QUIC stream, no round trip: these run at the speed of the state
    // machine, which is why the default is three orders of magnitude above the
    // wire properties above.
    #![proptest_config(config(4096))]

    /// A frame type that may not appear on this stream is refused from its
    /// header alone, at every length, wherever the chunk boundaries fall.
    ///
    /// The ordering is what this pins, and it is load-bearing in both
    /// directions. A frame type refused for *where it is* is a connection error
    /// (RFC 9114 §7.2.3, §7.2.4, §7.2.5, §7.2.7 and §4.1 each say so for one of
    /// them, and §4.4 for a tunnel), while a declared length past what this
    /// server buffers is a *stream* error answered with 431. So a SETTINGS frame
    /// on a request stream declaring 2^62-1 bytes must earn the first verdict
    /// and not the second: answering a MUST-close with a 431 would leave the
    /// connection running, and the peer would have learnt that a frame it may
    /// never send is merely too big.
    ///
    /// Not one byte of payload is ever written, so a decoder that waited for it
    /// would answer `Incomplete` here rather than refusing.
    #[test]
    fn a_frame_the_stream_may_not_carry_is_refused_from_its_header(
        kind in prop::sample::select(vec![StreamKind::Request, StreamKind::Tunnel]),
        choice in any::<u8>(),
        length in prop_oneof![
            3 => any_varint(),
            2 => prop::sample::select(vec![
                0, 1, MAX_FIELD_SECTION_SIZE - 1, MAX_FIELD_SECTION_SIZE,
                MAX_FIELD_SECTION_SIZE + 1, VARINT_MAX,
            ]),
        ],
        before in prop::collection::vec(any_allowed_frame_spec(), 0..3),
        cuts in prop::collection::vec(any::<u16>(), 0..6),
    ) {
        let refused = refused_on(kind);
        let refused_kind = refused[usize::from(choice) % refused.len()];

        let mut bytes = frame_bytes(&before);
        let mut header = BytesMut::new();
        frame::put_header(&mut header, refused_kind, length);
        bytes.extend_from_slice(&header);

        let mut expected = expected_steps(&before);
        expected.push(frame_unexpected());
        let expected = normalise(expected);

        for (spelling, chunks) in [
            ("whole", vec![bytes.clone()]),
            ("byte at a time", bytes.iter().map(|byte| vec![*byte]).collect()),
            ("cut", split_at(&bytes, &cuts)),
        ] {
            prop_assert_eq!(
                decode_chunks(kind, &chunks),
                expected.clone(),
                "{:?}: type {:#x} of {} bytes, {}",
                kind, refused_kind, length, spelling
            );
        }

        // The complement, and the reason this is a rule about the stream rather
        // than about the frame: the very same bytes on the peer's control stream
        // are never refused for the type they name.
        let control = decode_chunks(StreamKind::Control, &[bytes]);
        prop_assert!(
            !control.contains(&frame_unexpected()),
            "type {:#x} of {} bytes belongs on the control stream: {:?}",
            refused_kind, length, control
        );
    }

    /// Answering the CONNECT narrows the stream to DATA, and does it from the
    /// frame header.
    ///
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
    //# Receipt of any other known frame type MUST be treated as a connection
    //# error of type H3_FRAME_UNEXPECTED.
    ///
    /// The transition is the subject, so the two runs share every byte and
    /// differ only in whether the CONNECT was answered between them. HEADERS is
    /// the type that tells them apart: a request stream is made of it, and a
    /// tunnel may not carry one -- which is what stops a peer holding this
    /// connection's buffering budget in field sections on a stream that is
    /// carrying a socket.
    #[test]
    fn answering_the_connect_narrows_the_stream_to_data_frames(
        kind in prop::sample::select(
            KNOWN_TYPES.iter().copied().filter(|kind| *kind != frame::DATA).collect::<Vec<u64>>(),
        ),
        block in payload(96),
        body in payload(96),
        length in prop_oneof![
            3 => any_varint(),
            2 => prop::sample::select(vec![0, 1, MAX_FIELD_SECTION_SIZE, VARINT_MAX]),
        ],
        cuts in prop::collection::vec(any::<u16>(), 0..6),
    ) {
        let request = frame_bytes(&[FrameSpec { kind: frame::HEADERS, payload: block.clone() }]);

        let mut tail = frame_bytes(&[FrameSpec { kind: frame::DATA, payload: body.clone() }]);
        let mut header = BytesMut::new();
        frame::put_header(&mut header, kind, length);
        tail.extend_from_slice(&header);

        let request = split_at(&request, &cuts);
        let tail = split_at(&tail, &cuts);

        prop_assert_eq!(
            through_connect(true, &request, &tail),
            vec![Step::Headers(block.clone()), Step::Data(body.clone()), frame_unexpected()],
            "type {:#x} of {} bytes after the CONNECT completed",
            kind, length
        );

        // Without the transition the same bytes get the request stream's rules,
        // which refuse five of the six types and accept a field section.
        let open = through_connect(false, &request, &tail);
        if refused_on(StreamKind::Request).contains(&kind) {
            prop_assert_eq!(
                open,
                vec![Step::Headers(block), Step::Data(body), frame_unexpected()],
                "type {:#x} is refused on a request stream too",
                kind
            );
        } else {
            prop_assert!(
                !open.contains(&frame_unexpected()),
                "type {:#x} of {} bytes belongs on a request stream: {:?}",
                kind, length, open
            );
        }
    }

    /// Where the chunks fall changes nothing, on any stream kind: the same bytes
    /// whole, a byte at a time, and cut at generated offsets all decode alike.
    ///
    /// The property the wire runs could only approximate, since quinn chooses
    /// how a write is packetised and a single `write_all` may still arrive in
    /// pieces. Here the pieces are the test's, and "a byte at a time" is a
    /// spelling the wire has no way to ask for -- which is the case where a
    /// frame header straddles every boundary it has.
    #[test]
    fn frame_decoding_never_depends_on_where_the_chunks_fall(
        bytes in frame_ish_bytes(),
        kind in any_stream_kind(),
        cuts in prop::collection::vec(any::<u16>(), 0..8),
    ) {
        let whole = decode_chunks(kind, std::slice::from_ref(&bytes));

        prop_assert_eq!(decode_bytewise(kind, &bytes), whole.clone(), "{:?}", kind);
        prop_assert_eq!(
            decode_chunks(kind, &split_at(&bytes, &cuts)),
            whole.clone(),
            "{:?}, cuts {:?}",
            kind, cuts
        );

        // A run says one terminal thing, at the end, whatever it was fed.
        let terminal = whole
            .iter()
            .filter(|step| matches!(
                step,
                Step::End | Step::Incomplete | Step::Violation { .. } | Step::Broken
            ))
            .count();
        prop_assert_eq!(terminal, 1, "{:?}", whole);

        for step in &whole {
            // Nothing handed back may be past the per-frame cap, which is on the
            // *declared* length: a larger field section would mean the check
            // that bounds an unauthenticated peer's memory had been skipped.
            if let Step::Headers(block) = step {
                prop_assert!(
                    block.len() as u64 <= MAX_FIELD_SECTION_SIZE,
                    "a {}-byte HEADERS frame came back",
                    block.len()
                );
            }
        }
    }

    /// What a decoder has already answered, more bytes never take back.
    ///
    /// An incremental decoder is only useful if its answers are final: this
    /// server hands DATA payload straight into a socket as it arrives, and a
    /// frame the decoder later decided it had misread is a frame whose bytes are
    /// already gone. So every prefix of an input must answer a prefix of what
    /// the whole input answers -- with the one allowance that a run cut inside a
    /// DATA frame has reported fewer of that frame's bytes, which is the same
    /// thing said about the payload rather than the item.
    ///
    /// It follows that a refusal is final too, which is the half that matters
    /// for the connection errors above: bytes after a violation cannot turn it
    /// into anything else, because the violation is the last thing either run
    /// says.
    #[test]
    fn more_bytes_never_revoke_what_a_decoder_has_already_answered(
        bytes in frame_ish_bytes(),
        kind in any_stream_kind(),
        cut in any::<u16>(),
    ) {
        let cut = usize::from(cut) % (bytes.len() + 1);
        let whole = decode_chunks(kind, std::slice::from_ref(&bytes));

        let mut answered = decode_chunks(kind, &[bytes[..cut].to_vec()]);
        // `End` and `Incomplete` are statements about the input stopping where
        // it did, not about the frames; they are what the extra bytes revise.
        if matches!(answered.last(), Some(Step::End | Step::Incomplete)) {
            answered.pop();
        }

        prop_assert!(
            is_answer_prefix(&answered, &whole),
            "{:?} cut at {}: {:?} is not what {:?} had said by then",
            kind, cut, answered, whole
        );
    }
}

/// Refusing a frame charges the connection's buffering budget nothing.
///
/// How the peak is checked without reading a counter: `BufferBudget::held` is
/// `#[cfg(test)]`-private, so instead a budget that has just refused sixty-four
/// frames declaring 2^62-1 bytes each is handed a HEADERS frame of exactly the
/// largest size it allows. That frame is 64 KiB of a 1 MiB budget and must be
/// accepted -- which it cannot be if the refusals had charged, or leaked,
/// anything like what they declared. Sixty-four of them is sixteen times the
/// budget at the largest *allowed* length, so even a refusal that charged only
/// the cap rather than the declared length would show up here.
///
/// One case rather than a property: it writes 64 KiB, which is not something to
/// repeat twenty thousand times.
#[test]
fn refusing_frames_never_charges_the_connections_budget() {
    let budget = Arc::new(BufferBudget::default());

    for kind in BUFFERED_TYPES.iter().cycle().take(64) {
        let mut header = BytesMut::new();
        frame::put_header(&mut header, *kind, VARINT_MAX);
        assert_eq!(
            drive_with(&[header.to_vec()], &budget),
            vec![Step::Violation {
                code: Code::H3_EXCESSIVE_LOAD.value(),
                connection: false,
            }],
            "type {kind:#x}"
        );
    }

    let block = pattern(MAX_FIELD_SECTION_SIZE as usize, 0x5a);
    let mut full = BytesMut::new();
    frame::put_header(&mut full, frame::HEADERS, MAX_FIELD_SECTION_SIZE);
    full.put_slice(&block);

    assert_eq!(
        drive_with(&[full.to_vec()], &budget),
        vec![Step::Headers(block), Step::End],
        "the refused frames must not have charged the connection's budget"
    );
}

/// A DATA frame declaring 2^62-1 bytes is *not* refused: it is streamed, so
/// there is nothing to allocate and nothing to bound.
///
/// The complement of the property above, and the reason that property names the
/// six buffered types rather than "every type": DATA is the one frame whose
/// declared length this server never has to hold, so the cap does not apply to
/// it. What ends the stream is the peer stopping mid-frame, which RFC 9114 §7.1
/// makes H3_FRAME_ERROR.
#[test]
fn a_data_frame_declaring_the_whole_varint_range_is_streamed_not_refused() {
    let mut bytes = BytesMut::new();
    frame::put_header(&mut bytes, frame::DATA, VARINT_MAX);
    bytes.put_slice(b"only these");

    assert_eq!(
        drive(&[bytes.to_vec()]),
        vec![
            Step::Data(b"only these".to_vec()),
            Step::Violation {
                code: Code::H3_FRAME_ERROR.value(),
                connection: true,
            },
        ]
    );
}

// ---------------------------------------------------------------------------
// QPACK
// ---------------------------------------------------------------------------
//
// `qpack::decode` takes a whole field section as a slice, so there is no
// chunking property to state: the frame layer above it is what buffers a
// HEADERS frame, and that is where the chunk boundaries were fuzzed.

/// A field section prefix that references nothing: Required Insert Count 0,
/// Sign 0, Delta Base 0 (RFC 9204 §4.5.1).
const EMPTY_PREFIX: [u8; 2] = [0, 0];

/// Names and values aimed at the encoder's three cases and the decoder's
/// length handling: static-table hits, empty strings, high bytes, and a long
/// literal.
fn any_field_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => payload(24),
        2 => prop::collection::vec(any::<u8>(), 0..24),
        2 => prop::sample::select(vec![
            Vec::new(),
            b":method".to_vec(),
            b"CONNECT".to_vec(),
            b":authority".to_vec(),
            b"proxy-authorization".to_vec(),
            b"/".to_vec(),
            vec![0xff; 8],
            vec![0x00; 8],
        ]),
        1 => (0usize..=600, any::<u8>()).prop_map(|(length, seed)| vec![seed; length]),
        1 => (0usize..=600).prop_map(|length| vec![0xff; length]),
    ]
}

fn any_fields() -> impl Strategy<Value = Vec<(Vec<u8>, Vec<u8>)>> {
    prop::collection::vec((any_field_bytes(), any_field_bytes()), 0..8)
}

fn encode_fields(fields: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut block = BytesMut::new();
    qpack::encode(
        &mut block,
        fields
            .iter()
            .map(|(name, value)| (name.as_slice(), value.as_slice())),
    );
    block.to_vec()
}

/// The RFC 9114 §4.2.2 size of a field list, computed independently of `qpack`.
fn section_size(fields: &[(Vec<u8>, Vec<u8>)]) -> u64 {
    fields
        .iter()
        .map(|(name, value)| name.len() as u64 + value.len() as u64 + FIELD_OVERHEAD)
        .sum()
}

/// A *complete* field line representation that names the dynamic table, in each
/// of the four spellings RFC 9204 §4.5 gives one.
///
/// With `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` the encoder may not insert, so
/// every one of these is a protocol violation rather than an unsupported
/// feature -- which is why they are generated rather than assumed absent.
///
/// "Complete" is load-bearing and was found the hard way: an index equal to the
/// prefix mask means "a continuation byte follows" (RFC 7541 §5.1), so
/// `0b1011_1111` on its own is a *truncated* representation rather than a
/// reference to entry 63, and the decoder answers it as such. What that is and
/// why it is right is pinned by
/// [`a_truncated_dynamic_reference_is_a_stream_error_not_a_connection_one`]
/// below; here each index either stays under the mask or is given the
/// continuation byte it asked for.
fn any_dynamic_reference() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        // 4.5.2. Indexed Field Line with T = 0, index inside the 6-bit prefix.
        (0u8..=0x3e).prop_map(|index| vec![0b1000_0000 | index]),
        // The same with the prefix full, so the index runs into a continuation
        // byte: still a complete representation, still a dynamic reference.
        (0u8..=0x7f).prop_map(|extra| vec![0b1011_1111, extra]),
        // 4.5.4. Literal Field Line With Name Reference with T = 0.
        (0u8..=0x0e, any::<bool>()).prop_map(|(index, never_indexed)| {
            vec![0b0100_0000 | (u8::from(never_indexed) << 5) | index, 0x00]
        }),
        // 4.5.3. Indexed Field Line With Post-Base Index.
        (0u8..=0x0f).prop_map(|index| vec![0b0001_0000 | index]),
        // 4.5.5. Literal Field Line With Post-Base Name Reference.
        (0u8..=0x07, any::<bool>()).prop_map(|(index, never_indexed)| {
            vec![(u8::from(never_indexed) << 3) | index, 0x00]
        }),
    ]
}

/// Field sections aimed at every branch: what the encoder produces, what it
/// produces with bytes rewritten, dynamic references, and noise behind a
/// well-formed prefix.
fn section_ish_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => any_fields().prop_map(|fields| encode_fields(&fields)),
        3 => (any_fields(), prop::collection::vec((any::<u16>(), any::<u8>()), 1..6))
            .prop_map(|(fields, edits)| {
                let mut block = encode_fields(&fields);
                for (index, byte) in edits {
                    let index = usize::from(index) % block.len();
                    block[index] = byte;
                }
                block
            }),
        2 => prop::collection::vec(any::<u8>(), 0..96).prop_map(|mut body| {
            let mut block = EMPTY_PREFIX.to_vec();
            block.append(&mut body);
            block
        }),
        2 => prop::collection::vec(any::<u8>(), 0..96),
    ]
}

proptest! {
    #![proptest_config(config(512))]

    /// Whatever the encoder wrote, the decoder reads back: the same names, the
    /// same values, in the same order.
    ///
    /// Order is not incidental. RFC 9110 §5.3 lets a name repeat and makes the
    /// order of the values under one name part of what they mean, and `auth`
    /// tries the credentials in the order they arrived -- so a decoder that
    /// reordered a section would change which password was tried first.
    #[test]
    fn an_encoded_field_section_decodes_to_what_went_in(fields in any_fields()) {
        // The generator could in principle build a section past the advertised
        // limit; that is the next property's subject, not this one's.
        prop_assume!(section_size(&fields) <= MAX_FIELD_SECTION_SIZE);

        let block = encode_fields(&fields);
        let decoded = qpack::decode(&block, MAX_FIELD_SECTION_SIZE)
            .expect("what this encoder wrote must decode");
        prop_assert_eq!(decoded.len(), fields.len());
        for (field, (name, value)) in decoded.iter().zip(fields.iter()) {
            prop_assert_eq!(field.name.as_ref(), &name[..]);
            prop_assert_eq!(field.value.as_ref(), &value[..]);
        }
    }

    /// The advertised limit is exact: a section of exactly that size is
    /// accepted, and one byte more is refused.
    ///
    /// The limit is derived from the fields rather than the other way round, and
    /// with the 32-byte overhead added here rather than read out of `qpack`, so
    /// this checks the formula as well as the comparison. A limit that was
    /// off by one either way would let a peer past the bound this server told it
    /// about, or refuse a request that obeyed it.
    #[test]
    fn a_field_section_is_refused_exactly_one_byte_past_the_limit(
        fields in prop::collection::vec((payload(20), payload(40)), 1..6),
    ) {
        let block = encode_fields(&fields);
        let size = section_size(&fields);

        let accepted = qpack::decode(&block, size).expect("exactly the limit is within it");
        prop_assert_eq!(accepted.len(), fields.len());

        let error = qpack::decode(&block, size - 1).expect_err("one byte past the limit");
        prop_assert_eq!(error.code(), Code::H3_EXCESSIVE_LOAD);
        // The peer ignored a bound it was told about; the request is refused
        // with 431 and the connection -- and its tunnels -- carry on.
        prop_assert!(!error.is_connection_error(), "{}", error);
    }

    /// A reference to the dynamic table is a connection error in all four of its
    /// spellings, and never a field.
    ///
    //= https://www.rfc-editor.org/rfc/rfc9204#section-2.2.3
    //# If the decoder encounters a reference in a field line representation to
    //# a dynamic table entry that has already been evicted or that has an
    //# absolute index greater than or equal to the declared Required Insert
    //# Count (Section 4.5.1), it MUST treat this as a connection error of type
    //# QPACK_DECOMPRESSION_FAILED.
    ///
    /// With a zero table capacity every absolute index is greater than or equal
    /// to a Required Insert Count of zero, so every dynamic reference is that
    /// case. The valid fields around it are what make the property say something
    /// stronger than "this byte fails": the section decodes up to the reference
    /// and must still be refused whole.
    #[test]
    fn any_dynamic_table_reference_is_a_connection_error(
        fields in prop::collection::vec((payload(12), payload(12)), 0..4),
        reference in any_dynamic_reference(),
        trailing in payload(16),
    ) {
        let mut block = encode_fields(&fields);
        block.extend_from_slice(&reference);
        block.extend_from_slice(&trailing);

        let error = qpack::decode(&block, MAX_FIELD_SECTION_SIZE)
            .expect_err("a dynamic reference is not a field");
        prop_assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
        prop_assert!(error.is_connection_error(), "{}", error);
    }

    /// Arbitrary and near-miss bytes: no panic, and nothing that decodes may be
    /// past the limit it was decoded against.
    ///
    /// `src/h3/qpack.rs`'s own `arbitrary_bytes_never_panic_the_decoder` states
    /// the first half over unstructured `Vec<u8>`; what this adds is a generator
    /// that actually reaches the field-line branches -- a random byte string
    /// almost always dies on the prefix -- and the size claim about a success.
    #[test]
    fn arbitrary_field_sections_never_panic_and_never_exceed_their_limit(
        block in section_ish_bytes(),
        limit in prop_oneof![
            3 => Just(MAX_FIELD_SECTION_SIZE),
            2 => 0u64..=4096,
            1 => Just(0u64),
        ],
    ) {
        if let Ok(fields) = qpack::decode(&block, limit) {
            let size: u64 = fields
                .iter()
                .map(|field| field.name.len() as u64 + field.value.len() as u64 + FIELD_OVERHEAD)
                .sum();
            prop_assert!(size <= limit, "{} bytes of fields against a {} limit", size, limit);
        }
    }
}

/// A dynamic reference whose *index* never arrived is a stream error, not the
/// connection error RFC 9204 §2.2.3 gives a complete one.
///
/// Found by `any_dynamic_table_reference_is_a_connection_error` at 20000 cases,
/// which shrank to the single byte `0xBF`. Recorded rather than filtered out,
/// because the byte looks like it should be the §2.2.3 case and is not:
/// `0b10_111111` is an Indexed Field Line (§4.5.2) with T = 0, and its 6-bit
/// prefix is full, which RFC 7541 §5.1 makes "a continuation byte follows"
/// rather than "index 63". `qpack::decode` reads the integer before it looks at
/// T, so with nothing following, what it has is a representation that ended
/// mid-integer -- and it says so.
///
/// Not a defect, and the narrower answer is the safer one: §2.2.3 speaks of "a
/// reference ... to a dynamic table entry", and a representation that never
/// named an entry is not one. With a zero table capacity nothing is carried
/// between field sections, so a section this decoder could not read
/// desynchronises nothing, and answering on the stream costs the one request
/// instead of every tunnel on the connection -- exactly the reasoning
/// `qpack::stream_error` gives for every other truncation. Both answers carry
/// QPACK_DECOMPRESSION_FAILED, so a peer sees the same code either way.
///
/// The complete forms either side of it are here too, so the boundary is the
/// subject rather than a single byte: one more byte and the same representation
/// *is* the connection error.
#[test]
fn a_truncated_dynamic_reference_is_a_stream_error_not_a_connection_one() {
    let truncated = [EMPTY_PREFIX.as_slice(), &[0xbf]].concat();
    let error = qpack::decode(&truncated, MAX_FIELD_SECTION_SIZE).expect_err("nothing decodes");
    assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
    assert!(
        !error.is_connection_error(),
        "a representation that ended mid-integer is a stream error: {error}"
    );

    // The same byte with its continuation: now it names entry 63 of a dynamic
    // table that cannot exist, which is §2.2.3 exactly.
    let complete = [EMPTY_PREFIX.as_slice(), &[0xbf, 0x00]].concat();
    let error = qpack::decode(&complete, MAX_FIELD_SECTION_SIZE).expect_err("nothing decodes");
    assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
    assert!(error.is_connection_error(), "{error}");

    // And so does the same representation with an index inside the prefix.
    let inside = [EMPTY_PREFIX.as_slice(), &[0b1000_0000]].concat();
    let error = qpack::decode(&inside, MAX_FIELD_SECTION_SIZE).expect_err("nothing decodes");
    assert!(error.is_connection_error(), "{error}");
}

/// A field section of exactly `MAX_FIELD_SECTION_SIZE`, and one byte more.
///
/// The boundary the properties reach only at small sizes, checked once at the
/// real one. 64 KiB is not something to build 20000 times.
#[test]
fn the_advertised_limit_itself_is_the_boundary() {
    // One field, sized so that name + value + 32 is exactly the limit.
    let name = b"x".to_vec();
    let value = vec![b'v'; MAX_FIELD_SECTION_SIZE as usize - name.len() - FIELD_OVERHEAD as usize];
    let fields = vec![(name.clone(), value.clone())];
    assert_eq!(section_size(&fields), MAX_FIELD_SECTION_SIZE);

    let block = encode_fields(&fields);
    let decoded = qpack::decode(&block, MAX_FIELD_SECTION_SIZE).expect("exactly the limit");
    assert_eq!(
        decoded,
        vec![Field {
            name: name.clone().into(),
            value: value.clone().into(),
        }]
    );

    let over = vec![(name, [value, vec![b'v']].concat())];
    assert_eq!(section_size(&over), MAX_FIELD_SECTION_SIZE + 1);
    let error = qpack::decode(&encode_fields(&over), MAX_FIELD_SECTION_SIZE)
        .expect_err("one byte past the limit");
    assert_eq!(error.code(), Code::H3_EXCESSIVE_LOAD);
    assert!(!error.is_connection_error(), "{error}");
}

// ---------------------------------------------------------------------------
// Huffman
// ---------------------------------------------------------------------------
//
// `it_huffman` round-trips every one of the 256 symbols through the server's
// decoder and sends real Huffman-coded requests over the wire; the two padding
// rules are pinned there by one hand-built literal each. What this adds is the
// same rules over *arbitrary* input: any byte string, coded by the independent
// encoder in `tests/common/huffman.rs`, and then the two ways RFC 7541 §5.2 says
// the padding can be wrong applied to whatever encoding that produced.

/// How many bits of padding the encoder puts after `input`.
///
/// Derived from the code lengths rather than from the encoder's output, so the
/// two disagree if either is wrong: `common::huffman::encode` pads to the next
/// octet boundary, so the padding is whatever is left of the last byte.
fn padding_bits(input: &[u8]) -> u32 {
    let bits: u32 = input
        .iter()
        .map(|symbol| u32::from(common::huffman::CODES[usize::from(*symbol)].1))
        .sum();
    (8 - bits % 8) % 8
}

proptest! {
    #![proptest_config(config(512))]

    /// The independent encoder's output decodes back to what went in, for any
    /// byte string.
    ///
    /// `it_huffman` states this one symbol at a time, which catches a mistyped
    /// table entry; this states it for sequences, which is where the bit
    /// accumulator lives -- a code is up to 30 bits wide and crosses as many as
    /// four octet boundaries, and nothing about that is exercised by a
    /// single-symbol literal.
    #[test]
    fn the_independent_encoder_round_trips_through_the_decoder(
        input in prop_oneof![
            3 => prop::collection::vec(any::<u8>(), 0..64),
            2 => payload(256),
            2 => prop::collection::vec(prop::sample::select(
                b"abcdefghijklmnopqrstuvwxyz0123456789-_.:/".to_vec()), 0..64),
            1 => (0usize..=512).prop_map(|length| vec![0xff; length]),
            1 => (0usize..=512).prop_map(|length| vec![0x00; length]),
        ],
    ) {
        let encoded = common::huffman::encode(&input);
        prop_assert_eq!(huffman::decode(&encoded).expect("what was encoded decodes"), input);
    }

    /// RFC 7541 §5.2, the first of the two padding rules.
    ///
    //= https://www.rfc-editor.org/rfc/rfc7541#section-5.2
    //# A padding not corresponding to the most significant bits of the code
    //# for the EOS symbol MUST be treated as a decoding error.
    ///
    /// Those bits are all ones, so clearing one of them breaks the rule. The
    /// *least significant* bit specifically, and that is not arbitrary: a padding
    /// bit cleared higher up can leave a prefix that is a valid code followed by
    /// a shorter all-ones padding, which is a literal a conformant encoder could
    /// have produced and which the decoder is right to accept. `1111110` is not
    /// a code of any length (the longest all-ones code in RFC 7541 Appendix B is
    /// EOS, at thirty bits), so clearing the last bit is always the error and
    /// never a different reading of the same octet.
    #[test]
    fn padding_that_is_not_all_ones_is_a_decoding_error(
        input in prop::collection::vec(any::<u8>(), 1..48).prop_map(|mut input| {
            // An input whose codes happen to fill a whole number of octets has
            // no padding to corrupt. Rejecting those would spend the run's
            // rejection budget on an eighth of every case -- which is how this
            // property first failed, at 20000 cases, with "Too many global
            // rejects" and not a single wrong answer. Nudging instead keeps the
            // case: "a" is five bits (RFC 7541 Appendix B), so appending one
            // leaves the encoding three bits short of an octet.
            if padding_bits(&input) == 0 {
                input.push(b'a');
            }
            input
        }),
    ) {
        prop_assert!(padding_bits(&input) > 0, "the nudge must have taken");

        let mut encoded = common::huffman::encode(&input);
        let last = encoded.last_mut().expect("a padded encoding has a last byte");
        *last &= 0b1111_1110;

        let error = huffman::decode(&encoded).expect_err("padding must be all ones");
        prop_assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
        prop_assert!(!error.is_connection_error(), "{}", error);
    }

    /// RFC 7541 §5.2, the second.
    ///
    //= https://www.rfc-editor.org/rfc/rfc7541#section-5.2
    //# A padding strictly longer than 7 bits MUST be treated as a decoding
    //# error.
    ///
    /// A whole octet of ones appended to a valid encoding leaves between 8 and
    /// 15 trailing ones, and no code in RFC 7541 Appendix B is all ones at any
    /// of those lengths -- EOS, the only all-ones code, is thirty bits -- so no
    /// symbol can complete and what is left is padding, of more than seven bits.
    #[test]
    fn padding_longer_than_seven_bits_is_a_decoding_error(
        input in prop::collection::vec(any::<u8>(), 0..48),
    ) {
        let mut encoded = common::huffman::encode(&input);
        encoded.push(0xff);

        let error = huffman::decode(&encoded).expect_err("padding must be under eight bits");
        prop_assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
        prop_assert!(!error.is_connection_error(), "{}", error);
    }

    /// Arbitrary bytes never panic the decoder, and a success is always
    /// reversible.
    ///
    /// The second half is what makes this more than a crash test: a decoder that
    /// accepted a literal and produced the wrong symbols would pass "no panic"
    /// and fail here, because re-encoding what it claimed to have read gives
    /// different bytes.
    #[test]
    fn arbitrary_bytes_never_panic_the_huffman_decoder(
        encoded in prop_oneof![
            3 => prop::collection::vec(any::<u8>(), 0..64),
            2 => prop::collection::vec(
                prop_oneof![Just(0xffu8), Just(0x00), Just(0x7f), Just(0xfe), any::<u8>()],
                0..64,
            ),
            2 => prop::collection::vec(any::<u8>(), 1..24)
                .prop_map(|input| common::huffman::encode(&input)),
            1 => (prop::collection::vec(any::<u8>(), 1..24), any::<u16>(), any::<u8>())
                .prop_map(|(input, index, byte)| {
                    let mut encoded = common::huffman::encode(&input);
                    if !encoded.is_empty() {
                        let index = usize::from(index) % encoded.len();
                        encoded[index] = byte;
                    }
                    encoded
                }),
        ],
    ) {
        if let Ok(decoded) = huffman::decode(&encoded) {
            prop_assert_eq!(
                common::huffman::encode(&decoded),
                encoded,
                "a literal that decoded must re-encode to itself"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP Datagrams and capsules
// ---------------------------------------------------------------------------
//
// `it_props` covers both in depth and neither is repeated here:
//
// * `a_datagram_round_trips`, `a_udp_payload_encodes_with_context_zero`,
//   `an_oversized_quarter_stream_id_is_a_connection_error`,
//   `a_non_minimally_encoded_datagram_decodes_to_the_same_values` and
//   `decoding_arbitrary_bytes_never_panics` for `datagram`;
// * `capsule_decoding_does_not_depend_on_chunking` (against a single push, a
//   byte at a time, and random cuts), `a_truncated_capsule_sequence_waits_for
//   _the_rest`, `arbitrary_capsule_bytes_decode_the_same_however_they_are
//   _chunked`, `an_oversized_datagram_capsule_is_refused_from_its_header` and
//   `a_datagram_capsule_within_the_maximum_is_accepted` for `capsule`.
//
// The two below are what those leave: which of the two truncation errors a
// given cut produces, and what an *unknown* capsule type does with a declared
// length -- the cap `it_props` exercises is the DATAGRAM one, and an unknown
// type has none.

proptest! {
    #![proptest_config(config(512))]

    /// Every proper prefix of an encoded datagram is the truncation error that
    /// belongs to where the cut fell, and the second of them is never a
    /// connection error.
    ///
    /// `it_props` checks that the classification rule holds for whatever error
    /// comes out; this checks *which* error comes out, which is the part that
    /// decides whether a two-byte datagram can end every tunnel on a connection.
    /// A cut inside the Quarter Stream ID is `MissingQuarterStreamId` -- RFC 9297
    /// §2.1 makes that a connection error, and it is the only one -- and a cut
    /// after it is `MissingContextId`, which must stay droppable.
    #[test]
    fn where_a_datagram_is_cut_decides_which_truncation_error_it_is(
        quarter_stream_id in 0u64..=(1 << 60) - 1,
        context_id in any_varint(),
        body in payload(64),
    ) {
        let encoded = datagram::encode(quarter_stream_id, context_id, &body);
        let quarter_len = datagram::varint_len(quarter_stream_id);
        let context_len = datagram::varint_len(context_id);

        for cut in 0..quarter_len + context_len {
            let prefix = Bytes::copy_from_slice(&encoded[..cut]);
            let error = datagram::decode(prefix).expect_err("a prefix is not a datagram");

            if cut < quarter_len {
                prop_assert_eq!(error, DecodeError::MissingQuarterStreamId, "cut at {}", cut);
                prop_assert!(error.is_connection_error());
            } else {
                prop_assert_eq!(error, DecodeError::MissingContextId, "cut at {}", cut);
                prop_assert!(
                    !error.is_connection_error(),
                    "a truncated Context ID must not end the connection"
                );
            }
        }
    }

    /// An unknown capsule type may declare any length at all: it is discarded as
    /// it arrives, so there is nothing to bound and nothing to refuse.
    ///
    /// The complement of `it_props`'s
    /// `an_oversized_datagram_capsule_is_refused_from_its_header`: that cap is
    /// specific to the DATAGRAM capsule, whose value has to be held whole
    /// because a Context ID has to be read off the front of it. This pins that
    /// the *absence* of a cap on the other types is not a hole -- a peer that
    /// declares 2^62-1 bytes of an unknown capsule gets no error and costs no
    /// memory, because the decoder never accumulates a byte of it.
    #[test]
    fn an_unknown_capsule_may_declare_any_length_and_is_never_buffered(
        capsule_type in any_varint().prop_filter(
            "not DATAGRAM",
            |kind| *kind != capsule::CAPSULE_TYPE_DATAGRAM,
        ),
        length in prop_oneof![
            2 => Just(VARINT_MAX),
            2 => Just(capsule::MAX_DATAGRAM_CAPSULE_VALUE + 1),
            3 => (1u64 << 32)..=VARINT_MAX,
        ],
        arriving in payload(256),
    ) {
        let mut header = BytesMut::new();
        datagram::put_varint(&mut header, capsule_type);
        datagram::put_varint(&mut header, length);

        let mut decoder = CapsuleDecoder::new();
        decoder.push(&header);
        prop_assert_eq!(decoder.next_capsule(), Ok(None), "an unknown type is not refused");
        prop_assert!(!decoder.at_capsule_boundary(), "it is mid-capsule");

        // However much of the value arrives, it is consumed and not held: the
        // decoder still wants more, and still is not at a boundary.
        decoder.push(&arriving);
        prop_assert_eq!(decoder.next_capsule(), Ok(None));
        prop_assert!(!decoder.at_capsule_boundary());
    }
}

// ---------------------------------------------------------------------------
// The message layer
// ---------------------------------------------------------------------------

/// Field names and values from every corner: valid, one octet outside the set,
/// empty, and noise.
fn any_name_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => "[a-z0-9!#$%&'*+.^_`|~-]{0,24}".prop_map(String::into_bytes),
        2 => prop::collection::vec(any::<u8>(), 0..16),
        2 => prop::sample::select(vec![
            Vec::new(),
            b":method".to_vec(),
            b"Proxy-Authorization".to_vec(),
            b"proxy-authorization".to_vec(),
            b"host".to_vec(),
            b"a b".to_vec(),
            b"a\rb".to_vec(),
        ]),
    ]
}

fn any_value_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => prop::collection::vec(
            prop_oneof![0x21u8..=0x7e, 0x80u8..=0xff, Just(b' '), Just(b'\t')],
            0..24,
        ),
        3 => prop::collection::vec(any::<u8>(), 0..24),
        1 => prop::sample::select(vec![
            Vec::new(),
            b"Basic dXNlcjE6czNjcmV0".to_vec(),
            vec![b'\r'],
            vec![b'\n'],
            vec![0x00],
            vec![0x7f],
        ]),
    ]
}

proptest! {
    #![proptest_config(config(1024))]

    /// The three parsers a peer's bytes reach never panic, and each accepts
    /// exactly the set its documentation names -- recomputed here rather than
    /// asked of the module under test.
    ///
    /// The acceptance sets are the point. `Method::parse` is RFC 9110 §5.6.2's
    /// `token`; `field_name` is that restricted by RFC 9114 §4.2's rule that an
    /// uppercase name is malformed; `FieldValue::parse` is VCHAR, `obs-text`, SP
    /// and HTAB, which is RFC 9114 §10.3's three dangerous octets refused and
    /// nothing else. A parser that drifted either way would change what this
    /// server calls malformed.
    #[test]
    fn the_message_parsers_accept_exactly_what_they_document(
        name in any_name_bytes(),
        value in any_value_bytes(),
        status in prop::collection::vec(any::<u8>(), 0..5),
    ) {
        const TCHAR: &[u8] = b"!#$%&'*+-.^_`|~";
        let is_tchar = |byte: &u8| byte.is_ascii_alphanumeric() || TCHAR.contains(byte);

        let token = !name.is_empty() && name.iter().all(is_tchar);
        prop_assert_eq!(Method::parse(&name).is_some(), token, "{:?}", name);
        if let Some(method) = Method::parse(&name) {
            prop_assert_eq!(method.as_str().as_bytes(), &name[..]);
            prop_assert_eq!(method == Method::Connect, name == b"CONNECT");
        }

        let lowercase_token = token && !name.iter().any(u8::is_ascii_uppercase);
        prop_assert_eq!(message::field_name(&name).is_some(), lowercase_token, "{:?}", name);

        let printable = value
            .iter()
            .all(|byte| matches!(byte, 0x21..=0x7e | 0x80..=0xff | b' ' | b'\t'));
        prop_assert_eq!(FieldValue::parse(&value).is_some(), printable, "{:?}", value);
        if let Some(parsed) = FieldValue::parse(&value) {
            prop_assert_eq!(parsed.as_bytes(), &value[..]);
            prop_assert_eq!(parsed.len(), value.len());
            prop_assert_eq!(parsed.is_empty(), value.is_empty());
        }

        let three_digits = status.len() == 3
            && status[0] != b'0'
            && status.iter().all(u8::is_ascii_digit);
        prop_assert_eq!(Status::parse(&status).is_some(), three_digits, "{:?}", status);
        if let Some(parsed) = Status::parse(&status) {
            prop_assert_eq!(parsed.as_str().as_bytes(), &status[..]);
        }
    }

    /// A field list built from arbitrary names answers lookups the same way
    /// whatever case the name is asked in, and never loses or reorders a value.
    ///
    /// `Fields` is a list because a field section is one, and `auth` walks
    /// `get_all` in arrival order to try each credential the client sent. The
    /// case folding is what keeps a lookup from depending on RFC 9114 §4.2's
    /// lowercase rule having been enforced somewhere else.
    ///
    /// The names that go *in* are lowercase, because that is all that can:
    /// `Fields::append` debug-asserts `field_name`, so a list is only ever built
    /// out of names the parser already accepted. It is the lookups that vary in
    /// case, which is the direction the folding exists for.
    #[test]
    fn a_field_list_keeps_every_value_in_order_and_folds_case_on_lookup(
        entries in prop::collection::vec(
            ("[a-z0-9-]{1,8}", prop::collection::vec(0x21u8..=0x7e, 0..8)),
            0..8,
        ),
    ) {
        let mut fields = Fields::new();
        for (name, value) in &entries {
            fields.append(
                name.as_str(),
                FieldValue::parse(value).expect("a printable value"),
            );
        }

        prop_assert_eq!(fields.len(), entries.len());
        prop_assert_eq!(fields.is_empty(), entries.is_empty());
        prop_assert_eq!(fields.iter().count(), entries.len());

        for (name, _) in &entries {
            let expected: Vec<&[u8]> = entries
                .iter()
                .filter(|(other, _)| other.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_slice())
                .collect();

            for spelling in [name.to_lowercase(), name.to_uppercase(), name.clone()] {
                let found: Vec<&[u8]> = fields
                    .get_all(&spelling)
                    .map(FieldValue::as_bytes)
                    .collect();
                prop_assert_eq!(&found, &expected, "as {:?}", spelling);
                prop_assert!(fields.contains(&spelling));
                prop_assert_eq!(
                    fields.get(&spelling).map(FieldValue::as_bytes),
                    expected.first().copied()
                );
            }
        }
    }

    /// Arbitrary pseudo-headers on a [`Request`] never panic anything that reads
    /// one.
    ///
    /// The complement of the `build_request` properties below, and the half they
    /// cannot state: this is a [`Request`] nobody validated. Every field of the
    /// type is `pub` and `Option<Box<str>>`, so a combination the validator
    /// would never have produced -- a classic CONNECT carrying a path, a
    /// `:protocol` on a GET -- can be built directly here, which pins that
    /// nothing downstream of the parse assumes the parse happened.
    #[test]
    fn arbitrary_pseudo_headers_never_panic_the_message_layer(
        method in any_name_bytes(),
        scheme in prop::option::of("\\PC{0,16}"),
        authority in prop::option::of("\\PC{0,16}"),
        path in prop::option::of("\\PC{0,32}"),
        query in prop::option::of("\\PC{0,16}"),
        protocol in prop::option::of("\\PC{0,16}"),
        fields in prop::collection::vec(("[a-z-]{1,8}", "[\\x21-\\x7e]{0,8}"), 0..4),
    ) {
        let method = Method::parse(&method).unwrap_or(Method::Connect);
        let mut request = Request::new(method.clone());
        request.scheme = scheme.map(Into::into);
        request.authority = authority.map(Into::into);
        request.path = path.map(Into::into);
        request.query = query.map(Into::into);
        request.protocol = protocol.map(Into::into);
        for (name, value) in &fields {
            request.fields.append(
                name.as_str(),
                FieldValue::parse(value.as_bytes()).expect("a printable value"),
            );
        }

        // Everything a request is read through, on a request nobody validated.
        prop_assert_eq!(&request.method, &method);
        prop_assert_eq!(request.fields.len(), fields.len());
        let _ = format!("{request:?}");
        let _ = request.fields.get("host");
        let _ = request.fields.get_all("proxy-authorization").count();
        let _ = request.clone();
    }
}

// ---------------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------------
//
// `stream::build_request` turns a decoded field section into a `Request` or says
// why it cannot, and it is where RFC 9114 §4.1.2's "malformed" verdict is
// reached. It takes a `Vec<qpack::Field>` and returns, so a property can put an
// arbitrary *combination* of pseudo-headers through it -- which is what the
// rules are about, and what a live request stream cannot supply at proptest's
// rates. `src/h3/stream.rs`'s own tests are the table of named cases; these are
// the combinations between them.
//
// The properties state what the function does, which is not always what the RFC
// alone would suggest. Two places where they differ are worth naming: a classic
// CONNECT never consults a Host field, because §4.4's branch is reached before
// §4.3.1's agreement rule and reads only `:authority`; and the agreement itself
// is judged after RFC 9110 §5.5's optional whitespace has been excluded from the
// Host value, so " example.com " and "example.com" agree.

/// The authority these requests name.
const AUTHORITY: &str = "example.com:443";

/// A different one, for the half of RFC 9114 §4.3.1's rule that disagrees.
const OTHER_AUTHORITY: &str = "other.example:443";

/// One field, in the vocabulary `qpack::decode` hands `build_request`.
fn field(name: &[u8], value: &[u8]) -> Field {
    Field {
        name: Cow::Owned(name.to_vec()),
        value: Cow::Owned(value.to_vec()),
    }
}

/// A well-formed extended CONNECT: all five pseudo-headers, no regular field.
///
/// Every pseudo-header RFC 9114 §4.3 defines is already here, which is what
/// makes [`any_extra_pseudo_header_field_is_malformed`] a statement about all of
/// them: an extra one is either undefined or a repeat, and there is no third
/// case.
fn connect_udp_section() -> Vec<Field> {
    vec![
        field(b":method", b"CONNECT"),
        field(b":protocol", b"connect-udp"),
        field(b":scheme", b"https"),
        field(b":authority", AUTHORITY.as_bytes()),
        field(b":path", b"/.well-known/masque/udp/192.0.2.1/443/"),
    ]
}

/// Methods worth telling apart: the one RFC 9114 §4.4 gives its own rules, ones
/// it does not, and a token that differs from CONNECT only in case.
fn any_method_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => prop::sample::select(vec![
            b"CONNECT".to_vec(),
            b"GET".to_vec(),
            b"POST".to_vec(),
            b"OPTIONS".to_vec(),
            b"connect".to_vec(),
        ]),
        1 => "[A-Za-z]{1,8}".prop_map(String::into_bytes),
    ]
}

/// Authorities that pass the RFC 3986 §3.2 syntax check `uri_authority` applies,
/// so that only the agreement rule can decide the outcome.
fn any_authority() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9.-]{0,10}(:[0-9]{1,5})?"
}

/// A well-formed classic CONNECT: RFC 9114 §4.4's two pseudo-headers and no
/// more.
fn classic_connect_section() -> Vec<Field> {
    vec![
        field(b":method", b"CONNECT"),
        field(b":authority", AUTHORITY.as_bytes()),
    ]
}

/// One of the two shapes this server serves, chosen by a generated flag.
fn well_formed_section(extended: bool) -> Vec<Field> {
    if extended {
        connect_udp_section()
    } else {
        classic_connect_section()
    }
}

/// A name that might be a pseudo-header: one of the five, one that only looks
/// like them, or whatever [`any_name_bytes`] produces.
fn any_field_name_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => prop::sample::select(vec![
            b":method".to_vec(),
            b":scheme".to_vec(),
            b":authority".to_vec(),
            b":path".to_vec(),
            b":protocol".to_vec(),
        ]),
        1 => any_name_bytes().prop_map(|name| [b":".to_vec(), name].concat()),
        3 => any_name_bytes(),
    ]
}

/// A value one of those names might carry: one a client would send, or one no
/// client would.
fn any_field_value_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => prop::sample::select(vec![
            b"CONNECT".to_vec(),
            b"GET".to_vec(),
            b"https".to_vec(),
            AUTHORITY.as_bytes().to_vec(),
            OTHER_AUTHORITY.as_bytes().to_vec(),
            b"/".to_vec(),
            b"*".to_vec(),
            b"connect-udp".to_vec(),
            b"trailers".to_vec(),
            Vec::new(),
        ]),
        2 => any_value_bytes(),
    ]
}

/// Field sections aimed at every branch: requests a client could have sent,
/// those requests with one field rewritten, and names and values related to
/// nothing.
///
/// The middle arm is what most of the rules are actually about. A section built
/// only out of arbitrary names and values almost never reaches the branch that
/// *accepts* a request -- five pseudo-headers have to arrive together, each
/// carrying a value of its own kind -- so the shape invariants this generator
/// exists for would go unexercised. Starting from a well-formed request and
/// changing one field lands next to every boundary instead.
fn any_section() -> impl Strategy<Value = Vec<Field>> {
    prop_oneof![
        3 => (
            any::<bool>(),
            prop::collection::vec((any_name_bytes(), any_value_bytes()), 0..3),
        ).prop_map(|(extended, extra)| {
            let mut section = well_formed_section(extended);
            section.extend(extra.iter().map(|(name, value)| field(name, value)));
            section
        }),
        4 => (
            any::<bool>(),
            any::<u8>(),
            any_field_name_bytes(),
            any_field_value_bytes(),
            any::<bool>(),
        ).prop_map(|(extended, at, name, value, replace)| {
            let mut section = well_formed_section(extended);
            let at = usize::from(at) % (section.len() + 1);
            if replace && at < section.len() {
                section[at] = field(&name, &value);
            } else {
                section.insert(at, field(&name, &value));
            }
            section
        }),
        3 => prop::collection::vec((any_field_name_bytes(), any_field_value_bytes()), 0..8)
            .prop_map(|pairs| {
                pairs
                    .iter()
                    .map(|(name, value)| field(name, value))
                    .collect()
            }),
    ]
}

proptest! {
    #![proptest_config(config(2048))]

    /// Which pseudo-headers a request must carry, and which it must not, is
    /// decided by its method -- and the answer is recomputed here rather than
    /// asked of the function under test.
    ///
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
    //# A CONNECT request that does not conform to these restrictions is
    //# malformed.
    ///
    /// The five pseudo-headers are switched on and off independently, so all
    /// thirty-two combinations are reachable for each method, with and without a
    /// Host field. That is the shape of the rule: a classic CONNECT is the one
    /// request that must *omit* `:scheme` and `:path`, an extended CONNECT is an
    /// ordinary request that additionally may not lean on Host for its
    /// authority, and `:protocol` anywhere but a CONNECT is a pseudo-header
    /// outside the context RFC 8441 §4 defined it in.
    #[test]
    fn which_pseudo_headers_a_request_needs_is_decided_by_its_method(
        method in prop::option::of(any_method_bytes()),
        scheme in any::<bool>(),
        authority in any::<bool>(),
        path in any::<bool>(),
        protocol in any::<bool>(),
        host in prop::option::of(prop::sample::select(vec![AUTHORITY, OTHER_AUTHORITY])),
    ) {
        let mut section = Vec::new();
        if let Some(method) = &method {
            section.push(field(b":method", method));
        }
        if scheme {
            section.push(field(b":scheme", b"https"));
        }
        if authority {
            section.push(field(b":authority", AUTHORITY.as_bytes()));
        }
        if path {
            section.push(field(b":path", b"/"));
        }
        if protocol {
            section.push(field(b":protocol", b"connect-udp"));
        }
        if let Some(host) = host {
            section.push(field(b"host", host.as_bytes()));
        }

        let connect = method.as_deref() == Some(b"CONNECT".as_slice());
        let classic = connect && !protocol;
        let expected = if method.is_none() || (protocol && !connect) {
            false
        } else if classic {
            // §4.4: the authority and nothing else. A Host field is not
            // consulted on this branch at all, which is why `host` is absent
            // from this arm.
            authority && !scheme && !path
        } else {
            scheme && path && match (authority, host) {
                (true, Some(host)) => host == AUTHORITY,
                (true, None) => true,
                // RFC 8441 §4 makes the authority mandatory on a request that
                // carries :protocol, so Host cannot stand in for it.
                (false, _) if protocol => false,
                (false, Some(_)) => true,
                (false, None) => false,
            }
        };

        let built = build_request(section);
        prop_assert_eq!(
            built.is_ok(),
            expected,
            "method {:?}, scheme {}, authority {}, path {}, protocol {}, host {:?}: {:?}",
            method, scheme, authority, path, protocol, host,
            built.as_ref().err().map(ToString::to_string)
        );

        match built {
            Ok(request) => {
                prop_assert_eq!(request.protocol.is_some(), protocol);
                // Whichever of the two named it: `:authority` when it is there,
                // and the Host field standing in for it when it is not.
                prop_assert_eq!(
                    request.authority.as_deref(),
                    if authority { Some(AUTHORITY) } else { host }
                );
                if classic {
                    prop_assert_eq!(request.scheme, None);
                    prop_assert_eq!(request.path, None);
                } else {
                    prop_assert_eq!(request.scheme.as_deref(), Some("https"));
                    prop_assert_eq!(request.path.as_deref(), Some("/"));
                }
            }
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
            //# Malformed requests or responses that are detected MUST be treated
            //# as a stream error of type H3_MESSAGE_ERROR.
            Err(error) => {
                prop_assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
                prop_assert!(!error.is_connection_error(), "{}", error);
            }
        }
    }

    /// A pseudo-header field is malformed exactly when a regular field came
    /// before it.
    ///
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
    //# All pseudo-header fields MUST appear in the header section before
    //# regular header fields.
    ///
    /// The interleavings are generated rather than listed: several regular
    /// fields are inserted at generated positions into a section that is
    /// otherwise well-formed, and the verdict is computed from where they landed.
    /// Their names all begin "x-", so none of them is the Host, TE or Connection
    /// field that a rule of its own would have decided instead -- what is being
    /// varied here is position, and nothing else.
    #[test]
    fn a_pseudo_header_after_a_regular_field_is_malformed(
        regulars in prop::collection::vec(("x-[a-z-]{1,6}", "[\\x21-\\x7e]{0,8}"), 1..4),
        positions in prop::collection::vec(any::<u8>(), 1..4),
    ) {
        let mut section = connect_udp_section();
        for ((name, value), position) in regulars.iter().zip(positions.iter().cycle()) {
            let at = usize::from(*position) % (section.len() + 1);
            section.insert(at, field(name.as_bytes(), value.as_bytes()));
        }

        let first_regular = section.iter().position(|field| !field.name.starts_with(b":"));
        let last_pseudo = section.iter().rposition(|field| field.name.starts_with(b":"));
        let ordered = match (first_regular, last_pseudo) {
            (Some(first), Some(last)) => first > last,
            _ => true,
        };

        let names: Vec<String> = section
            .iter()
            .map(|field| String::from_utf8_lossy(&field.name).into_owned())
            .collect();

        let built = build_request(section);
        prop_assert_eq!(built.is_ok(), ordered, "{:?}", names);

        if let Err(error) = built {
            prop_assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
            prop_assert!(!error.is_connection_error(), "{}", error);
        }
    }

    /// `:authority` and Host must say the same thing, and whichever of them is
    /// there is the authority the request ends up with.
    ///
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
    //# If the :scheme pseudo-header field identifies a scheme that has a
    //# mandatory authority component [...] the request MUST contain either an
    //# :authority pseudo-header field or a Host header field.  If these fields
    //# are present, they MUST NOT be empty.  If both fields are present, they
    //# MUST contain the same value.
    ///
    /// The Host value is padded with generated leading and trailing whitespace,
    /// which RFC 9110 §5.5 excludes from a field value before anything evaluates
    /// it -- so the padding must make no difference to the agreement, and the
    /// authority the request carries must be the unpadded one. That is the
    /// reading `add_field` implements, and it is what keeps a client whose
    /// encoder pads a value from being told its request is malformed.
    #[test]
    fn authority_and_host_must_say_the_same_thing(
        authority in prop::option::of(any_authority()),
        host in prop::option::of((any_authority(), "[ \t]{0,3}", "[ \t]{0,3}")),
        protocol in any::<bool>(),
    ) {
        let mut section = vec![field(
            b":method",
            if protocol { b"CONNECT".as_slice() } else { b"GET".as_slice() },
        )];
        if protocol {
            section.push(field(b":protocol", b"connect-udp"));
        }
        section.push(field(b":scheme", b"https"));
        if let Some(authority) = &authority {
            section.push(field(b":authority", authority.as_bytes()));
        }
        section.push(field(b":path", b"/"));
        if let Some((host, lead, trail)) = &host {
            section.push(field(b"host", format!("{lead}{host}{trail}").as_bytes()));
        }

        let host = host.map(|(host, _, _)| host);
        let expected = match (authority.as_deref(), host.as_deref()) {
            (Some(authority), Some(host)) => authority == host,
            (Some(_), None) => true,
            (None, _) if protocol => false,
            (None, Some(_)) => true,
            (None, None) => false,
        };

        let built = build_request(section);
        prop_assert_eq!(
            built.is_ok(),
            expected,
            "authority {:?}, host {:?}, protocol {}",
            authority, host, protocol
        );

        match built {
            Ok(request) => {
                prop_assert_eq!(
                    request.authority.as_deref(),
                    authority.as_deref().or(host.as_deref())
                );
                // The padding is gone from the field as well, which is what
                // `crate::auth` and the agreement check above both read.
                if let Some(host) = &host {
                    prop_assert_eq!(
                        request.fields.get("host").map(FieldValue::as_bytes),
                        Some(host.as_bytes())
                    );
                }
            }
            Err(error) => {
                prop_assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
                prop_assert!(!error.is_connection_error(), "{}", error);
            }
        }
    }

    /// Any extra pseudo-header field on a complete request is malformed,
    /// wherever it sits.
    ///
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
    //# Endpoints MUST treat a request or response that contains undefined or
    //# invalid pseudo-header fields as malformed.
    ///
    /// The base section already carries all five pseudo-headers RFC 9114 §4.3
    /// defines, so a sixth is either one of the five again -- which §4.3.1's
    /// "exactly one value" forbids -- or a name that is not defined for a
    /// request, `:status` included. There is no third case, which is what lets
    /// the name be generated rather than chosen: every byte string beginning ":"
    /// falls into one or the other.
    #[test]
    fn any_extra_pseudo_header_field_is_malformed(
        name in prop_oneof![
            3 => "[a-z]{1,10}".prop_map(|name| format!(":{name}")),
            2 => prop::sample::select(vec![
                ":status", ":method", ":scheme", ":authority", ":path", ":protocol",
                ":Path", ":", ":volto", ":method ",
            ]).prop_map(str::to_owned),
            1 => "[\\x21-\\x7e]{0,6}".prop_map(|rest| format!(":{rest}")),
        ],
        value in "[\\x21-\\x7e]{0,12}",
        position in any::<u8>(),
    ) {
        let mut section = connect_udp_section();
        let at = usize::from(position) % (section.len() + 1);
        section.insert(at, field(name.as_bytes(), value.as_bytes()));

        let error = build_request(section)
            .map(|request| request.method)
            .expect_err(&format!("{name:?} at {at} must be malformed"));
        prop_assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
        prop_assert!(!error.is_connection_error(), "{}", error);
    }

    /// Arbitrary field sections never panic the validator, every refusal costs
    /// the stream and never the connection, and every acceptance has the shape
    /// the rest of the server reads without checking.
    ///
    /// The invariants are the point, and each is something a caller downstream
    /// relies on: `tunnel::tcp` resolves `request.authority` and would have
    /// nothing to resolve without it; the router reads `request.protocol` and
    /// answers a CONNECT that has none as a TCP tunnel; `auth` walks the fields;
    /// and `tunnel::udp` parses the path against RFC 9298 §2's template. A
    /// request that reached any of them missing what they assume would be a
    /// panic or a wrong answer, in a task started by an unauthenticated peer.
    ///
    /// That every rejection is a *stream* error matters as much: a field section
    /// is the first thing a peer sends, and a malformed one that ended the
    /// connection would take every tunnel on it along.
    #[test]
    fn arbitrary_field_sections_are_refused_on_the_stream_or_accepted_whole(
        section in any_section(),
    ) {
        const AUTHORITY_CHARACTERS: &[u8] = b"-._~%!$&'()*+,;=:@[]";

        match build_request(section) {
            Ok(request) => {
                let classic = request.method == Method::Connect && request.protocol.is_none();

                // RFC 9114 §4.4 for the classic form, §4.3.1 and RFC 8441 §4 for
                // everything else.
                if classic {
                    prop_assert!(request.scheme.is_none(), "{:?}", request);
                    prop_assert!(request.path.is_none(), "{:?}", request);
                    prop_assert!(request.query.is_none(), "{:?}", request);
                } else {
                    prop_assert!(request.scheme.is_some(), "{:?}", request);
                    prop_assert!(request.path.is_some(), "{:?}", request);
                }
                if request.protocol.is_some() {
                    prop_assert_eq!(&request.method, &Method::Connect, "{:?}", request);
                }

                let authority = request.authority.as_deref().unwrap_or_else(|| {
                    panic!("every accepted request names an authority: {request:?}")
                });
                prop_assert!(!authority.is_empty(), "{:?}", request);
                prop_assert!(
                    authority.bytes().all(|byte| byte.is_ascii_alphanumeric()
                        || AUTHORITY_CHARACTERS.contains(&byte)),
                    "{:?}",
                    request
                );

                // The agreement of §4.3.1, from the other end: whatever Host
                // survived says what the authority says. Except on a classic
                // CONNECT, where §4.4's branch reads `:authority` alone and a
                // Host field is an ordinary field like any other.
                if !classic
                    && let Some(host) = request.fields.get("host")
                {
                    prop_assert_eq!(host.as_bytes(), authority.as_bytes(), "{:?}", request);
                }
                prop_assert!(request.fields.get_all("host").count() <= 1, "{:?}", request);

                // §4.3.1's asterisk form is the one target that is not a path.
                if let Some(path) = request.path.as_deref() {
                    prop_assert!(path == "*" || path.starts_with('/'), "{:?}", request);
                }

                // RFC 9114 §4.2 on the regular fields that came through.
                for (name, value) in request.fields.iter() {
                    prop_assert!(!name.is_empty(), "{:?}", request);
                    prop_assert!(!name.bytes().any(|byte| byte.is_ascii_uppercase()), "{}", name);
                    prop_assert_ne!(name, "connection", "{:?}", request);
                    if name == "te" {
                        prop_assert_eq!(value.as_bytes(), b"trailers", "{:?}", request);
                    }
                }
            }
            Err(error) => {
                prop_assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
                prop_assert!(!error.is_connection_error(), "{}", error);
            }
        }
    }
}
