//! Property tests over the three hand-rolled parsers that read untrusted bytes.
//!
//! `datagram`, `capsule` and `tunnel::udp::parse_target` all decode input a peer
//! controls, and all three are small enough that the interesting failures are
//! not "the happy path is wrong" but "some prefix, some chunking, some length
//! nobody wrote a case for". The unit tests next to each module pin the cases a
//! human thought of; these pin the shape of the answer for every input in a
//! range, which is where a truncation or an off-by-one hides.
//!
//! This is a stand-in for coverage-guided fuzzing. `cargo fuzz` needs a nightly
//! toolchain, the development host has stable Rust only, and the parsers are
//! small and pure, so a generator plus a shrinker reaches the same corners.
//! Run the file as a fuzzer with:
//!
//! ```sh
//! PROPTEST_CASES=100000 cargo test --release --test it_props
//! ```
//!
//! `PROPTEST_CASES` is honoured by every property here: the per-property case
//! counts below are defaults for CI, applied only when the variable is unset.

use std::collections::BTreeSet;

use bytes::{BufMut, Bytes, BytesMut};
use proptest::prelude::*;

use volto::capsule::{
    self, Capsule, CapsuleDecoder, CAPSULE_TYPE_DATAGRAM, MAX_DATAGRAM_CAPSULE_VALUE,
};
use volto::datagram::{
    self, DecodeError, CONTEXT_ID_UDP_PAYLOAD, MAX_QUARTER_STREAM_ID, MAX_UDP_PAYLOAD, VARINT_MAX,
};
use volto::tunnel::udp::parse_target;

/// The RFC 9298 §2 default template prefix.
const PREFIX: &str = "/.well-known/masque/udp/";

/// A configuration with `cases` defaulted per property but still overridable.
///
/// `ProptestConfig::default()` already reads `PROPTEST_CASES`; setting the field
/// unconditionally would override the environment, so the default is applied
/// only when the variable is absent. That keeps the committed suite cheap and
/// the 100k "fuzz" run one variable away.
fn config(default_cases: u32) -> ProptestConfig {
    let mut config = ProptestConfig::default();
    if std::env::var_os("PROPTEST_CASES").is_none() {
        config.cases = default_cases;
    }
    config
}

/// Varints across all four length classes, with the boundaries oversampled.
///
/// A uniform `0..=VARINT_MAX` would spend almost every case on 8-byte encodings
/// and never see a 1-byte one.
fn any_varint() -> impl Strategy<Value = u64> {
    prop_oneof![
        2 => 0u64..=0x3f,
        2 => 0x40u64..=0x3fff,
        2 => 0x4000u64..=0x3fff_ffff,
        2 => 0x4000_0000u64..=VARINT_MAX,
        1 => prop::sample::select(vec![
            0,
            1,
            0x3f,
            0x40,
            0x3fff,
            0x4000,
            0x3fff_ffff,
            0x4000_0000,
            MAX_QUARTER_STREAM_ID,
            MAX_QUARTER_STREAM_ID + 1,
            VARINT_MAX,
        ]),
    ]
}

/// A legal Quarter Stream ID, boundaries included.
fn any_quarter_stream_id() -> impl Strategy<Value = u64> {
    prop_oneof![
        3 => 0u64..=MAX_QUARTER_STREAM_ID,
        1 => prop::sample::select(vec![0, 1, 0x3f, 0x40, 0x3fff, 0x4000, MAX_QUARTER_STREAM_ID]),
    ]
}

/// A payload described by its length and a seed, rather than byte by byte.
///
/// Generating 65527 individual `u8` strategies per case would dominate the run
/// time and shrink for hours; a length plus a fill pattern still detects a
/// misaligned copy and costs one allocation.
fn payload(max: usize) -> impl Strategy<Value = Vec<u8>> {
    (0usize..=max, any::<u8>()).prop_map(|(length, seed)| pattern(length, seed))
}

fn pattern(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| seed ^ (index as u8).wrapping_mul(31))
        .collect()
}

/// Writes `value` as a varint of any length that can hold it, not necessarily
/// the shortest -- which RFC 9000 §16 explicitly permits and `put_varint`, which
/// only ever emits the shortest, cannot produce.
fn put_padded_varint(buf: &mut BytesMut, value: u64, length: prop::sample::Index) {
    let lengths: Vec<usize> = [1usize, 2, 4, 8]
        .into_iter()
        .filter(|candidate| *candidate >= datagram::varint_len(value))
        .collect();

    match length.get(&lengths) {
        1 => buf.put_u8(value as u8),
        2 => buf.put_u16(0x4000 | value as u16),
        4 => buf.put_u32(0x8000_0000 | value as u32),
        _ => buf.put_u64(0xc000_0000_0000_0000 | value),
    }
}

/// Bytes aimed at every branch of `datagram::decode`: long noise, short noise
/// (where the two truncation errors live), and well-formed datagrams cut at an
/// arbitrary point.
fn datagram_ish_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => prop::collection::vec(any::<u8>(), 0..1500),
        3 => prop::collection::vec(any::<u8>(), 0..12),
        2 => (any_quarter_stream_id(), any_varint(), payload(32), 0usize..24).prop_map(
            |(quarter_stream_id, context_id, payload, cut)| {
                let encoded = datagram::encode(quarter_stream_id, context_id, &payload);
                encoded[..cut.min(encoded.len())].to_vec()
            }
        ),
    ]
}

// ---------------------------------------------------------------------------
// QUIC varints and HTTP datagrams
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(config(1024))]

    /// Round trip: what `put_varint` writes, `take_varint` reads back, in
    /// exactly `varint_len` bytes, leaving whatever followed it untouched.
    #[test]
    fn a_varint_round_trips_and_leaves_the_remainder_alone(
        value in any_varint(),
        tail in payload(64),
    ) {
        let mut buf = BytesMut::new();
        datagram::put_varint(&mut buf, value);
        let encoded_len = datagram::varint_len(value);
        prop_assert_eq!(buf.len(), encoded_len);

        buf.put_slice(&tail);
        let mut bytes = buf.freeze();

        let (peeked, peeked_len) = datagram::peek_varint(&bytes).expect("a whole varint");
        prop_assert_eq!(peeked, value);
        prop_assert_eq!(peeked_len, encoded_len);

        prop_assert_eq!(datagram::take_varint(&mut bytes), Some(value));
        prop_assert_eq!(&bytes[..], &tail[..], "the remainder must be untouched");
    }

    /// Every proper prefix of a varint is "need more bytes", never a value and
    /// never a panic -- and `take_varint` must not consume on failure.
    #[test]
    fn every_proper_prefix_of_a_varint_needs_more_bytes(value in any_varint()) {
        let mut buf = BytesMut::new();
        datagram::put_varint(&mut buf, value);
        let encoded = buf.freeze();

        for cut in 0..encoded.len() {
            let prefix = encoded.slice(..cut);
            prop_assert_eq!(datagram::peek_varint(&prefix), None, "peek at {} bytes", cut);

            let mut taking = prefix.clone();
            prop_assert_eq!(datagram::take_varint(&mut taking), None, "take at {} bytes", cut);
            prop_assert_eq!(&taking[..], &prefix[..], "a failed take must not consume");
        }
    }

    /// Dividing a legal QUIC stream id by four can never leave the Quarter
    /// Stream ID range, so nothing legitimate is ever refused as too large.
    #[test]
    fn a_quarter_stream_id_from_a_legal_stream_id_is_always_legal(
        stream_id in 0u64..=VARINT_MAX,
    ) {
        let quarter = datagram::quarter_stream_id(stream_id);
        prop_assert_eq!(quarter, stream_id / 4);
        prop_assert!(quarter <= MAX_QUARTER_STREAM_ID);
    }
}

proptest! {
    #![proptest_config(config(512))]

    /// `encoded_len` predicts `encode`, and a datagram survives the round trip
    /// with its three parts intact.
    #[test]
    fn a_datagram_round_trips(
        quarter_stream_id in any_quarter_stream_id(),
        context_id in any_varint(),
        payload in prop_oneof![
            8 => payload(2048),
            1 => payload(MAX_UDP_PAYLOAD),
            1 => Just(pattern(MAX_UDP_PAYLOAD, 0xa5)),
        ],
    ) {
        let encoded = datagram::encode(quarter_stream_id, context_id, &payload);
        prop_assert_eq!(
            encoded.len(),
            datagram::encoded_len(quarter_stream_id, context_id, payload.len())
        );

        let decoded = datagram::decode(encoded).expect("what we encoded decodes");
        prop_assert_eq!(decoded.quarter_stream_id, quarter_stream_id);
        prop_assert_eq!(decoded.context_id, context_id);
        prop_assert_eq!(&decoded.payload[..], &payload[..]);
    }

    /// The UDP helper is `encode` with Context ID 0, and says so on the wire.
    #[test]
    fn a_udp_payload_encodes_with_context_zero(
        quarter_stream_id in any_quarter_stream_id(),
        payload in payload(1500),
    ) {
        let decoded = datagram::decode(datagram::encode_udp_payload(quarter_stream_id, &payload))
            .expect("decodes");
        prop_assert_eq!(decoded.context_id, CONTEXT_ID_UDP_PAYLOAD);
        prop_assert_eq!(decoded.quarter_stream_id, quarter_stream_id);
        prop_assert_eq!(&decoded.payload[..], &payload[..]);
    }

    /// A Quarter Stream ID above the legal maximum is a connection error, not a
    /// dropped datagram -- RFC 9297 §2.1 makes that a MUST, and only that class.
    #[test]
    fn an_oversized_quarter_stream_id_is_a_connection_error(
        quarter_stream_id in (MAX_QUARTER_STREAM_ID + 1)..=VARINT_MAX,
        context_id in any_varint(),
        payload in payload(256),
    ) {
        let encoded = datagram::encode(quarter_stream_id, context_id, &payload);
        let error = datagram::decode(encoded).expect_err("above the maximum");

        prop_assert_eq!(error, DecodeError::QuarterStreamIdTooLarge(quarter_stream_id));
        prop_assert!(error.is_connection_error());
    }

    /// A varint may be written longer than it needs to be (RFC 9000 §16), and a
    /// peer that does so must still be understood. `encode` is therefore a
    /// normaliser, not the inverse of `decode`: same meaning, shorter bytes.
    #[test]
    fn a_non_minimally_encoded_datagram_decodes_to_the_same_values(
        quarter_stream_id in any_quarter_stream_id(),
        context_id in any_varint(),
        payload in payload(64),
        padding in (any::<prop::sample::Index>(), any::<prop::sample::Index>()),
    ) {
        let mut buf = BytesMut::new();
        put_padded_varint(&mut buf, quarter_stream_id, padding.0);
        put_padded_varint(&mut buf, context_id, padding.1);
        buf.put_slice(&payload);

        let decoded = datagram::decode(buf.freeze()).expect("a padded varint is still a varint");
        prop_assert_eq!(decoded.quarter_stream_id, quarter_stream_id);
        prop_assert_eq!(decoded.context_id, context_id);
        prop_assert_eq!(&decoded.payload[..], &payload[..]);
    }

    /// Arbitrary bytes: never a panic, errors classified exactly as the unit
    /// test `only_quarter_stream_id_failures_are_connection_errors` says, and a
    /// success that re-encodes to itself whenever the input was minimal.
    #[test]
    fn decoding_arbitrary_bytes_never_panics(raw in datagram_ish_bytes()) {
        let bytes = Bytes::from(raw.clone());

        match datagram::decode(bytes) {
            Err(error) => {
                let connection_error = matches!(
                    error,
                    DecodeError::MissingQuarterStreamId | DecodeError::QuarterStreamIdTooLarge(_)
                );
                prop_assert_eq!(
                    error.is_connection_error(),
                    connection_error,
                    "{:?} was classified against the rule",
                    error
                );
                // A Context ID that does not parse must stay droppable, or a
                // peer could kill every session on the connection with one
                // two-byte datagram.
                if matches!(error, DecodeError::MissingContextId) {
                    prop_assert!(!error.is_connection_error());
                }
            }
            Ok(decoded) => {
                let re_encoded = datagram::encode(
                    decoded.quarter_stream_id,
                    decoded.context_id,
                    &decoded.payload,
                );

                // Canonical re-encoding always decodes back to the same values.
                prop_assert_eq!(
                    datagram::decode(re_encoded.clone()).expect("re-encoded decodes"),
                    decoded.clone()
                );

                // Byte equality only holds when the input used the shortest
                // encoding for both varints: RFC 9000 §16 permits longer forms
                // and `peek_varint` accepts them, so `encode` is a normaliser
                // rather than an inverse. That is deliberate, not a defect.
                let (_, quarter_len) = datagram::peek_varint(&raw).expect("it decoded");
                let (_, context_len) =
                    datagram::peek_varint(&raw[quarter_len..]).expect("it decoded");
                let minimal = quarter_len == datagram::varint_len(decoded.quarter_stream_id)
                    && context_len == datagram::varint_len(decoded.context_id);
                if minimal {
                    prop_assert_eq!(&re_encoded[..], &raw[..]);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The capsule decoder
// ---------------------------------------------------------------------------

/// One capsule to put on the wire.
#[derive(Debug, Clone)]
enum Spec {
    /// A DATAGRAM capsule, which the decoder must surface.
    Datagram { context_id: u64, payload: Vec<u8> },
    /// A capsule of a type the decoder does not know, which it must skip.
    Unknown { capsule_type: u64, value: Vec<u8> },
}

fn any_spec() -> impl Strategy<Value = Spec> {
    let sizes = prop_oneof![7 => 0usize..64, 2 => 0usize..512, 1 => 0usize..2000];
    prop_oneof![
        3 => (any_varint(), sizes.clone(), any::<u8>()).prop_map(|(context_id, length, seed)| {
            Spec::Datagram { context_id, payload: pattern(length, seed) }
        }),
        1 => (1u64..=VARINT_MAX, sizes, any::<u8>()).prop_map(|(capsule_type, length, seed)| {
            Spec::Unknown { capsule_type, value: pattern(length, seed) }
        }),
    ]
}

/// Encodes a capsule of a type the decoder does not know.
fn encode_unknown(capsule_type: u64, value: &[u8]) -> Bytes {
    let mut buf = BytesMut::new();
    datagram::put_varint(&mut buf, capsule_type);
    datagram::put_varint(&mut buf, value.len() as u64);
    buf.put_slice(value);
    buf.freeze()
}

/// Serialises `specs`, returning the wire bytes, the capsules a correct decoder
/// must surface, and the byte offsets at which the sequence is between capsules.
fn wire(specs: &[Spec]) -> (Bytes, Vec<Capsule>, BTreeSet<usize>) {
    let mut buf = BytesMut::new();
    let mut expected = Vec::new();
    let mut boundaries = BTreeSet::new();
    boundaries.insert(0);

    for spec in specs {
        match spec {
            Spec::Datagram {
                context_id,
                payload,
            } => {
                buf.extend_from_slice(&capsule::encode_datagram(*context_id, payload));
                expected.push(Capsule::Datagram {
                    context_id: *context_id,
                    payload: Bytes::copy_from_slice(payload),
                });
            }
            Spec::Unknown {
                capsule_type,
                value,
            } => buf.extend_from_slice(&encode_unknown(*capsule_type, value)),
        }
        boundaries.insert(buf.len());
    }

    (buf.freeze(), expected, boundaries)
}

/// What a decoder did with a stream: the capsules, the errors, and whether it
/// ended between capsules.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Outcome {
    capsules: Vec<Capsule>,
    errors: Vec<capsule::Error>,
    boundary: bool,
}

/// Feeds `chunks` to a fresh decoder, draining after every push.
///
/// Draining continues past an error: every error path consumes the bytes it
/// rejected before returning, so the loop always makes progress, and continuing
/// is what proves the decoder does not become unusable. A panic inside
/// `next_capsule` -- or a state that stops consuming -- is itself the failure
/// this driver catches.
fn drive(chunks: &[Bytes]) -> Outcome {
    let mut decoder = CapsuleDecoder::new();
    let mut capsules = Vec::new();
    let mut errors = Vec::new();

    for chunk in chunks {
        decoder.push(chunk);
        loop {
            match decoder.next_capsule() {
                Ok(Some(capsule)) => capsules.push(capsule),
                Ok(None) => {
                    // Nothing may appear out of thin air: without new bytes the
                    // answer must stay the same.
                    assert_eq!(decoder.next_capsule(), Ok(None), "None must be stable");
                    break;
                }
                Err(error) => errors.push(error),
            }
        }
    }

    Outcome {
        capsules,
        errors,
        boundary: decoder.at_capsule_boundary(),
    }
}

/// Splits `bytes` at the offsets in `cuts` (clamped into range, deduplicated).
fn chunks(bytes: &Bytes, cuts: &[u16]) -> Vec<Bytes> {
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
        .map(|pair| bytes.slice(pair[0]..pair[1]))
        .filter(|chunk| !chunk.is_empty())
        .collect()
}

/// One chunk per byte, the worst case a stream can produce.
fn one_byte_at_a_time(bytes: &Bytes) -> Vec<Bytes> {
    (0..bytes.len())
        .map(|index| bytes.slice(index..index + 1))
        .collect()
}

proptest! {
    #![proptest_config(config(256))]

    /// Chunking invariance, the property the whole decoder exists for: capsules
    /// do not align with stream reads, so the answer must not depend on where
    /// the reads fall. Checked against a single push, against a byte at a time,
    /// and against random split points -- and `at_capsule_boundary` must be
    /// true at exactly the offsets that end a capsule.
    #[test]
    fn capsule_decoding_does_not_depend_on_chunking(
        specs in prop::collection::vec(any_spec(), 1..8),
        cuts in prop::collection::vec(any::<u16>(), 0..8),
    ) {
        let (bytes, expected, boundaries) = wire(&specs);

        let whole = drive(std::slice::from_ref(&bytes));
        prop_assert_eq!(&whole.capsules, &expected);
        prop_assert!(whole.errors.is_empty(), "well-formed input: {:?}", whole.errors);
        prop_assert!(whole.boundary);

        prop_assert_eq!(&drive(&chunks(&bytes, &cuts)), &whole, "cuts {:?}", cuts);
        prop_assert_eq!(&drive(&one_byte_at_a_time(&bytes)), &whole);

        // The boundary flag has to be exact, not merely true at the end: a
        // decoder that claimed to be between capsules mid-value would let a
        // truncated stream pass as well-formed.
        let mut decoder = CapsuleDecoder::new();
        for prefix_len in 0..=bytes.len() {
            if prefix_len > 0 {
                decoder.push(&bytes[prefix_len - 1..prefix_len]);
            }
            while decoder.next_capsule().expect("well-formed input").is_some() {}
            prop_assert_eq!(
                decoder.at_capsule_boundary(),
                boundaries.contains(&prefix_len),
                "after {} of {} bytes",
                prefix_len,
                bytes.len()
            );
        }
    }

    /// A truncated sequence is "not yet", not "malformed": no error, no
    /// boundary, and pushing the missing tail completes it.
    #[test]
    fn a_truncated_capsule_sequence_waits_for_the_rest(
        specs in prop::collection::vec(any_spec(), 1..6),
        cut in any::<u16>(),
    ) {
        let (bytes, expected, boundaries) = wire(&specs);
        let cut = usize::from(cut) % (bytes.len() + 1);

        let mut decoder = CapsuleDecoder::new();
        decoder.push(&bytes[..cut]);
        let mut decoded = Vec::new();
        while let Some(capsule) = decoder.next_capsule().expect("a prefix is not an error") {
            decoded.push(capsule);
        }
        prop_assert_eq!(
            decoder.at_capsule_boundary(),
            boundaries.contains(&cut),
            "cut at {}",
            cut
        );

        decoder.push(&bytes[cut..]);
        while let Some(capsule) = decoder.next_capsule().expect("the whole thing decodes") {
            decoded.push(capsule);
        }

        prop_assert_eq!(decoded, expected);
        prop_assert!(decoder.at_capsule_boundary());
    }

    /// Arbitrary and near-miss bytes, pushed in arbitrary chunks: no panic, no
    /// stall, and the same outcome however the bytes are split.
    #[test]
    fn arbitrary_capsule_bytes_decode_the_same_however_they_are_chunked(
        bytes in capsule_ish_bytes(),
        cuts in prop::collection::vec(any::<u16>(), 0..8),
    ) {
        let whole = drive(std::slice::from_ref(&bytes));
        prop_assert_eq!(drive(&chunks(&bytes, &cuts)), whole.clone(), "cuts {:?}", cuts);
        prop_assert_eq!(drive(&one_byte_at_a_time(&bytes)), whole);
    }
}

/// Bytes that look enough like capsules to reach the interesting states: pure
/// noise, an alphabet of varint prefixes, and well-formed sequences with a few
/// bytes corrupted.
fn capsule_ish_bytes() -> impl Strategy<Value = Bytes> {
    prop_oneof![
        2 => prop::collection::vec(any::<u8>(), 0..512).prop_map(Bytes::from),
        2 => prop::collection::vec(
            prop_oneof![
                Just(0x00u8), Just(0x01), Just(0x02), Just(0x3f),
                Just(0x40), Just(0x80), Just(0xc0), Just(0xff),
                any::<u8>(),
            ],
            0..512,
        ).prop_map(Bytes::from),
        3 => (
            prop::collection::vec(any_spec(), 1..6),
            prop::collection::vec((any::<u16>(), any::<u8>()), 0..8),
        ).prop_map(|(specs, edits)| {
            let (bytes, _, _) = wire(&specs);
            let mut buf = BytesMut::from(&bytes[..]);
            for (index, byte) in edits {
                if !buf.is_empty() {
                    let index = usize::from(index) % buf.len();
                    buf[index] = byte;
                }
            }
            buf.freeze()
        }),
    ]
}

proptest! {
    #![proptest_config(config(512))]

    /// A DATAGRAM capsule that declares more than a UDP payload can hold is
    /// refused from its header alone -- before a single value byte is accepted,
    /// which is the whole point: the declared length must never become an
    /// allocation.
    #[test]
    fn an_oversized_datagram_capsule_is_refused_from_its_header(
        length in (MAX_DATAGRAM_CAPSULE_VALUE + 1)..=VARINT_MAX,
    ) {
        let mut header = BytesMut::new();
        datagram::put_varint(&mut header, CAPSULE_TYPE_DATAGRAM);
        datagram::put_varint(&mut header, length);

        let mut decoder = CapsuleDecoder::new();
        decoder.push(&header.freeze());

        prop_assert_eq!(
            decoder.next_capsule(),
            Err(capsule::Error::DatagramTooLarge { length })
        );

        // Not one byte of the value was waited for: the decoder is back at a
        // header, so the next bytes are read as the next capsule rather than as
        // the rejected capsule's value. (`tunnel::udp` resets the stream on this
        // error and never pushes again -- this only pins that the rejection
        // costs no buffering, whatever the declared length claimed.)
        decoder.push(&capsule::encode_datagram(0, b"next"));
        prop_assert_eq!(
            decoder.next_capsule(),
            Ok(Some(Capsule::Datagram {
                context_id: 0,
                payload: Bytes::from_static(b"next"),
            }))
        );
    }

    /// The complement: at or below the maximum the header is accepted and the
    /// decoder simply waits for the value.
    ///
    /// Length 0 is excluded, and not arbitrarily: a zero-length value is already
    /// complete when its header arrives, and a DATAGRAM capsule with no room for
    /// its Context ID is malformed rather than pending. That case is pinned by
    /// `capsule::tests::a_datagram_capsule_without_a_context_id_is_malformed`
    /// and used again in `the_decoder_resumes_at_the_next_capsule_after_an_error`
    /// below. (Found by this property at 100000 cases, which shrank straight to
    /// `length = 0`.)
    #[test]
    fn a_datagram_capsule_within_the_maximum_is_accepted(
        length in 1..=MAX_DATAGRAM_CAPSULE_VALUE,
    ) {
        let mut header = BytesMut::new();
        datagram::put_varint(&mut header, CAPSULE_TYPE_DATAGRAM);
        datagram::put_varint(&mut header, length);

        let mut decoder = CapsuleDecoder::new();
        decoder.push(&header.freeze());
        prop_assert_eq!(decoder.next_capsule(), Ok(None));
    }
}

/// A DATAGRAM capsule of exactly `MAX_DATAGRAM_CAPSULE_VALUE` bytes decodes.
///
/// Pushing 64 KiB is not something to repeat 100000 times, so the boundary is a
/// single case rather than a property.
#[test]
fn a_datagram_capsule_at_exactly_the_maximum_decodes() {
    // An 8-byte Context ID varint leaves room for the largest possible UDP
    // payload, which is how the cap was derived in the first place.
    let context_id = VARINT_MAX;
    let payload = pattern(MAX_UDP_PAYLOAD, 0x5c);
    let encoded = capsule::encode_datagram(context_id, &payload);

    let mut header = BytesMut::new();
    datagram::put_varint(&mut header, CAPSULE_TYPE_DATAGRAM);
    datagram::put_varint(&mut header, MAX_DATAGRAM_CAPSULE_VALUE);
    assert_eq!(
        &encoded[..header.len()],
        &header[..],
        "the largest capsule must be exactly the cap"
    );

    let mut decoder = CapsuleDecoder::new();
    decoder.push(&encoded);
    assert_eq!(
        decoder.next_capsule(),
        Ok(Some(Capsule::Datagram {
            context_id,
            payload: Bytes::from(payload),
        }))
    );
    assert!(decoder.at_capsule_boundary());
}

/// What the decoder does *after* an error, which the properties above exercise
/// but do not describe: both errors consume the bytes they rejected and leave
/// the decoder at a header, so the next call resumes at the following capsule
/// rather than repeating the error. Neither error is sticky; deciding to abort
/// the stream is the caller's job.
#[test]
fn the_decoder_resumes_at_the_next_capsule_after_an_error() {
    let mut wire = BytesMut::new();
    // A DATAGRAM capsule with no room for its Context ID: malformed.
    datagram::put_varint(&mut wire, CAPSULE_TYPE_DATAGRAM);
    datagram::put_varint(&mut wire, 0);
    // A DATAGRAM capsule that declares more than a UDP payload can hold. Its
    // value never arrives, because the header alone is the error.
    datagram::put_varint(&mut wire, CAPSULE_TYPE_DATAGRAM);
    datagram::put_varint(&mut wire, MAX_DATAGRAM_CAPSULE_VALUE + 1);
    wire.extend_from_slice(&capsule::encode_datagram(9, b"still readable"));

    let mut decoder = CapsuleDecoder::new();
    decoder.push(&wire.freeze());

    assert_eq!(
        decoder.next_capsule(),
        Err(capsule::Error::MalformedDatagram)
    );
    assert_eq!(
        decoder.next_capsule(),
        Err(capsule::Error::DatagramTooLarge {
            length: MAX_DATAGRAM_CAPSULE_VALUE + 1
        })
    );
    assert_eq!(
        decoder.next_capsule(),
        Ok(Some(Capsule::Datagram {
            context_id: 9,
            payload: Bytes::from_static(b"still readable"),
        }))
    );
    assert_eq!(decoder.next_capsule(), Ok(None));
    assert!(decoder.at_capsule_boundary());

    // Worth knowing rather than worth changing: because a rejected capsule is
    // consumed, a decoder that has nothing else buffered reports a boundary
    // immediately after an error -- the flag answers "is the buffer between
    // capsules", not "was the stream so far well formed". Nothing consults it
    // there (`tunnel::udp` resets the stream on `Err` and only asks about the
    // boundary at a clean EOF), but a caller that tried to recover from an error
    // would have to keep the error, not the flag.
    let mut header = BytesMut::new();
    datagram::put_varint(&mut header, CAPSULE_TYPE_DATAGRAM);
    datagram::put_varint(&mut header, MAX_DATAGRAM_CAPSULE_VALUE + 1);

    let mut decoder = CapsuleDecoder::new();
    decoder.push(&header.freeze());
    assert!(decoder.next_capsule().is_err());
    assert!(decoder.at_capsule_boundary());
}

// ---------------------------------------------------------------------------
// The CONNECT-UDP URI template
// ---------------------------------------------------------------------------

/// Percent-encodes every byte, which is always a legal spelling of a segment
/// and is how an IPv6 literal reaches the server in the RFC 9298 §3 form.
fn percent_encode_all(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("%{byte:02X}")).collect()
}

/// Host characters that survive a path segment without being encoded.
///
/// A literal `%` would start a percent escape and `/` would break the segment,
/// so the generator cannot produce either and nothing here is filtered out.
fn literal_host() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            prop::char::range('a', 'z'),
            prop::char::range('A', 'Z'),
            prop::char::range('0', '9'),
            prop::sample::select(vec!['.', '-', '_', '~']),
        ],
        1..64,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

proptest! {
    #![proptest_config(config(1024))]

    /// The template round trips: whatever host and port were put in the path
    /// come back out, with or without the optional trailing slash.
    #[test]
    fn the_template_round_trips_a_literal_host(
        host in literal_host(),
        port in 1u16..=u16::MAX,
        trailing_slash in any::<bool>(),
    ) {
        let slash = if trailing_slash { "/" } else { "" };
        let path = format!("{PREFIX}{host}/{port}{slash}");
        prop_assert_eq!(parse_target(&path, None), Ok((host, port)));
    }

    /// The same for a percent-encoded host, which is the only way to spell a
    /// bare IPv6 literal (RFC 9298 §3 escapes the colons) or anything else
    /// that would otherwise break the path apart.
    #[test]
    fn the_template_round_trips_a_percent_encoded_host(
        host in "\\PC{1,32}",
        port in 1u16..=u16::MAX,
    ) {
        // A bracket is the template's syntax rather than part of a host, so no
        // host containing one round trips: the enclosing pair comes off, which
        // `the_template_round_trips_ip_literals` pins, and any other bracket is
        // refused outright.
        prop_assume!(!host.contains(['[', ']']));

        let path = format!("{PREFIX}{}/{port}/", percent_encode_all(host.as_bytes()));
        prop_assert_eq!(parse_target(&path, None), Ok((host, port)));
    }

    /// IP literals in both accepted spellings: bare with escaped colons, and
    /// bracketed, which is not the RFC form but is what some clients send.
    #[test]
    fn the_template_round_trips_ip_literals(
        v4 in any::<[u8; 4]>(),
        v6 in any::<[u16; 8]>(),
        port in 1u16..=u16::MAX,
    ) {
        let v4 = std::net::Ipv4Addr::from(v4).to_string();
        prop_assert_eq!(
            parse_target(&format!("{PREFIX}{v4}/{port}/"), None),
            Ok((v4.clone(), port))
        );

        let v6 = std::net::Ipv6Addr::from(v6).to_string();
        let escaped = v6.replace(':', "%3A");
        prop_assert_eq!(
            parse_target(&format!("{PREFIX}{escaped}/{port}/"), None),
            Ok((v6.clone(), port))
        );

        // The bracketed spelling reaches the same host as the bare one: the
        // brackets are the template's syntax and come off with it.
        let bracketed = format!("[{v6}]").replace(':', "%3A");
        prop_assert_eq!(
            parse_target(&format!("{PREFIX}{bracketed}/{port}/"), None),
            Ok((v6, port))
        );
    }

    /// A query string means the request URI is not the template, whatever the
    /// path says. An empty query is indistinguishable from none and is allowed.
    #[test]
    fn any_query_string_is_refused(
        host in literal_host(),
        port in 1u16..=u16::MAX,
        query in "\\PC{1,32}",
    ) {
        let path = format!("{PREFIX}{host}/{port}/");
        prop_assert!(parse_target(&path, Some(&query)).is_err());
        prop_assert!(parse_target(&path, Some("")).is_ok(), "an empty query is no query");
    }

    /// Anything not under the well-known prefix is refused, however plausible.
    #[test]
    fn a_path_outside_the_template_is_refused(path in "\\PC{0,64}") {
        prop_assume!(!path.starts_with(PREFIX));
        prop_assert!(parse_target(&path, None).is_err());
    }

    /// Only 1..=65535 is a port. Zero is refused explicitly (it can never be a
    /// UDP destination), and anything that is not a `u16` fails to parse.
    #[test]
    fn a_port_outside_the_range_is_refused(
        host in literal_host(),
        port in prop_oneof![
            Just("0".to_owned()),
            Just("65536".to_owned()),
            Just("-1".to_owned()),
            Just(String::new()),
            (65536u64..=u64::MAX).prop_map(|port| port.to_string()),
            "[^0-9]{1,8}",
        ],
    ) {
        let path = format!("{PREFIX}{host}/{port}/");
        prop_assert!(parse_target(&path, None).is_err(), "port {:?}", port);
    }

    /// Arbitrary input never panics, and a success is always a usable target:
    /// a non-empty host and a non-zero port.
    #[test]
    fn arbitrary_input_never_panics(
        path in template_ish_path(),
        query in prop::option::of("\\PC{0,16}"),
    ) {
        if let Ok((host, port)) = parse_target(&path, query.as_deref()) {
            prop_assert!(!host.is_empty());
            prop_assert!(port > 0);
            prop_assert!(query.is_none_or(|query| query.is_empty()));
        }
    }
}

/// What the template accepts that a reader might not expect, pinned so that a
/// future tightening is a deliberate change rather than a surprise.
///
/// None of it is a defect: the port is parsed with `u16::from_str`, which takes
/// a leading `+` and leading zeros, and the host is percent-decoded and handed
/// on without a syntax check -- name resolution and the destination policy are
/// what refuse a host, and they see the decoded string either way.
#[test]
fn the_template_accepts_more_spellings_than_it_advertises() {
    // Ports, via `u16::from_str`.
    assert_eq!(
        parse_target("/.well-known/masque/udp/example.com/+53/", None),
        Ok(("example.com".to_owned(), 53))
    );
    assert_eq!(
        parse_target("/.well-known/masque/udp/example.com/00053/", None),
        Ok(("example.com".to_owned(), 53))
    );
    // Percent-encoding applies to the port segment too.
    assert_eq!(
        parse_target("/.well-known/masque/udp/example.com/%35%33/", None),
        Ok(("example.com".to_owned(), 53))
    );

    // Hosts are decoded, not validated: anything that is UTF-8 gets through.
    assert_eq!(
        parse_target("/.well-known/masque/udp/%20%01not%2Fa%2Fhost/53/", None),
        Ok((" \u{1}not/a/host".to_owned(), 53))
    );
    // Except when the escapes do not spell UTF-8 at all.
    assert!(parse_target("/.well-known/masque/udp/%FF/53/", None).is_err());
}

/// Paths aimed at the template's edges: percent escapes (including sequences
/// that decode to invalid UTF-8), control characters, empty and over-long
/// segments, too many segments, and pure noise.
fn template_ish_path() -> impl Strategy<Value = String> {
    let segment = prop_oneof![
        2 => "\\PC{0,12}",
        2 => "[a-z0-9.:%\\[\\]-]{0,12}",
        1 => Just(String::new()),
        1 => prop::collection::vec(any::<u8>(), 0..16).prop_map(|raw| percent_encode_all(&raw)),
        1 => (0usize..3000).prop_map(|length| "a".repeat(length)),
        1 => prop::sample::select(vec![
            "%".to_owned(),
            "%2".to_owned(),
            "%2F".to_owned(),
            "%FF".to_owned(),
            "%C3%28".to_owned(),
            "0".to_owned(),
            "65536".to_owned(),
            "+53".to_owned(),
            "\u{7f}".to_owned(),
        ]),
    ];

    prop_oneof![
        3 => (prop::collection::vec(segment.clone(), 0..4), any::<bool>()).prop_map(
            |(segments, trailing_slash)| {
                let slash = if trailing_slash { "/" } else { "" };
                format!("{PREFIX}{}{slash}", segments.join("/"))
            }
        ),
        1 => prop::collection::vec(segment, 0..4)
            .prop_map(|segments| format!("/{}", segments.join("/"))),
        1 => "\\PC{0,48}",
        // Without this branch the strategy above practically never lands on a
        // path that parses, and the success half of the property would be
        // vacuous: two segments have to line up, and the second has to be a
        // port. A near-miss port keeps the failing side represented too.
        2 => (literal_host(), 0u32..70_000, any::<bool>()).prop_map(
            |(host, port, trailing_slash)| {
                let slash = if trailing_slash { "/" } else { "" };
                format!("{PREFIX}{host}/{port}{slash}")
            }
        ),
    ]
}
