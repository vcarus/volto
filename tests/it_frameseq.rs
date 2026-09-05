//! Generated frame *sequences* against the live server's connection state
//! machine.
//!
//! `it_hostile` is the hand-written matrix: every row is a sequence a reviewer
//! thought of, pinned once. `it_fuzz` generates frame sequences too, but feeds
//! them to the pure `FrameDecoder` -- deliberately, so it can pick the chunk
//! boundaries -- which means everything *above* the decoder is out of its
//! reach: the control stream's stateful rules (`connection::Control`), the
//! request reader's ordering rules (`stream::read_request`), the uni-stream
//! accounting, and how any of it composes across streams on one connection.
//! This file generates sequences at that level and asserts what the peer
//! observes on the wire, so the space between the hand-written rows is walked
//! by a machine instead of left to reviewers.
//!
//! # The oracle
//!
//! Every case computes its expected outcome from a model written against
//! RFC 9114 directly (`control_verdict` and the fatal tables below), never by
//! asking the server -- and every case *ends the connection deliberately*, so
//! the assertion is an exact CONNECTION_CLOSE code rather than "nothing
//! happened within a window". A sequence with no offence gets a sentinel
//! offence appended; the close code then proves two things at once: every
//! frame before the sentinel was accepted (a misjudged one would have closed
//! with a different code first), and the connection was still serving when the
//! sentinel arrived.
//!
//! Where two of RFC 9114's MUST-close rules apply to the same frame -- a
//! reserved HTTP/2 type as the control stream's first frame is both §7.2.8's
//! H3_FRAME_UNEXPECTED and §6.2.1's H3_MISSING_SETTINGS -- the RFC ranks
//! neither, so either code satisfies it. The model pins the code this server
//! deterministically produces (the frame layer judges before `Control` does),
//! and says so at each such arm: those assertions are regression pins on a
//! defensible choice, not claims that the other code would be wrong.
//!
//! # Shared-codec caveat
//!
//! Frames are written with the same varint/QPACK encoders the server reads
//! with, like the rest of this suite; a bug shared by both sides of the codec
//! is invisible here and belongs to the masque-go interop job. What this file
//! judges is on the *other* side of that boundary: which close code the server
//! chose, read off quinn, against a model that never consults the server.
//!
//! # Run as a longer exploration
//!
//! ```sh
//! PROPTEST_CASES=2000 cargo test --release --test it_frameseq
//! ```
//!
//! Every property honours `PROPTEST_CASES`; the committed defaults keep the
//! file to a few seconds. Every case is bounded by [`CASE_TIMEOUT`], so a hang
//! is a failure rather than an orphaned run.

// The package-wide default is `deny` (`Cargo.toml`); this file argues for its
// allow: the frame lengths are ones this file writes out itself.
#![allow(clippy::as_conversions)]

mod common;

#[path = "common/proptest_support.rs"]
mod props;

use std::sync::OnceLock;
use std::time::Duration;

use bytes::BytesMut;
use proptest::prelude::*;

use props::config;

use common::rawstream::{
    DENIED_TARGET, FRAME_CANCEL_PUSH, FRAME_DATA, FRAME_GOAWAY, FRAME_HEADERS, FRAME_MAX_PUSH_ID,
    FRAME_PUSH_PROMISE, FRAME_SETTINGS, H3_CLOSED_CRITICAL_STREAM, H3_FRAME_ERROR,
    H3_FRAME_UNEXPECTED, H3_ID_ERROR, H3_MISSING_SETTINGS, H3_REQUEST_INCOMPLETE,
    H3_SETTINGS_ERROR, H3_STREAM_CREATION_ERROR, RESERVED_HTTP2_TYPES, SETTINGS_H3_DATAGRAM,
    SETTINGS_MAX_FIELD_SECTION_SIZE, STREAM_CONTROL, STREAM_PUSH, STREAM_QPACK_DECODER,
    STREAM_QPACK_ENCODER, application_close, connect_headers_frame, frame, grease_type, read_frame,
    status_of,
};
use common::{TIMEOUT, TestServer, connect_quic, spawn_echo_target};
use volto::datagram;

/// Upper bound on one generated case, so a hang fails instead of orphaning
/// the run.
const CASE_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// The lab: one server, one echo target, one runtime, shared by every case
// ---------------------------------------------------------------------------

/// The server every case connects to.
///
/// Shared because a case is a *connection*: each one opens its own QUIC
/// connection, drives it to a deliberate CONNECTION_CLOSE, and leaves the
/// server standing for the next -- which is itself a small property, since a
/// server that did not survive one case's close would fail every case after
/// it.
struct Lab {
    runtime: tokio::runtime::Runtime,
    server: TestServer,
    /// A TCP echo target the CONNECT tunnels point at; it accepts in a loop,
    /// so one serves every case.
    echo: std::net::SocketAddr,
}

fn lab() -> &'static Lab {
    static LAB: OnceLock<Lab> = OnceLock::new();
    LAB.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("a tokio runtime");
        let (server, echo) =
            runtime.block_on(async { (TestServer::start().await, spawn_echo_target().await) });
        Lab {
            runtime,
            server,
            echo,
        }
    })
}

/// Runs one case on the lab runtime, bounded by [`CASE_TIMEOUT`].
fn run_case<F>(case: F)
where
    F: std::future::Future<Output = ()> + Send,
{
    lab().runtime.block_on(async {
        tokio::time::timeout(CASE_TIMEOUT, case)
            .await
            .expect("a case must not outlast its timeout");
    });
}

/// A frame whose whole payload is one varint (GOAWAY, CANCEL_PUSH,
/// MAX_PUSH_ID).
fn varint_frame(kind: u64, value: u64) -> Vec<u8> {
    let mut payload = BytesMut::new();
    datagram::put_varint(&mut payload, value);
    frame(kind, &payload)
}

/// A SETTINGS frame carrying the given identifier/value pairs.
fn settings_frame(pairs: &[(u64, u64)]) -> Vec<u8> {
    let mut payload = BytesMut::new();
    for (identifier, value) in pairs {
        datagram::put_varint(&mut payload, *identifier);
        datagram::put_varint(&mut payload, *value);
    }
    frame(FRAME_SETTINGS, &payload)
}

/// A deterministic fill for frame payloads whose bytes carry no meaning.
fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index as u8) ^ 0x5a).collect()
}

/// Opens a unidirectional stream of `stream_type` and writes `bytes` after the
/// type varint, tolerating a connection that has already been closed.
///
/// Unlike `rawstream::open_uni_stream`, a failed write here is not a test
/// failure: a script whose early frames already ended the connection can lose
/// the race to deliver its later bytes, and the close code those early frames
/// drew is exactly what the case is waiting to read.
async fn open_uni_tolerant(
    connection: &quinn::Connection,
    stream_type: u64,
    bytes: &[u8],
) -> Option<quinn::SendStream> {
    let mut stream = connection.open_uni().await.ok()?;
    let mut wire = BytesMut::new();
    datagram::put_varint(&mut wire, stream_type);
    wire.extend_from_slice(bytes);
    let _ = stream.write_all(&wire).await;
    Some(stream)
}

// ---------------------------------------------------------------------------
// Property 1: the control stream's frame-sequence rules
// ---------------------------------------------------------------------------
//
// `connection::Control` is a state machine -- whether SETTINGS has been seen,
// the GOAWAY floor, the MAX_PUSH_ID ceiling -- and its unit tests plus the
// `it_hostile`/`it_settings`/`it_critical_streams` rows pin single transitions.
// What none of them state is the *sequence* property: for any interleaving of
// legal and offending control frames, the connection closes with the code of
// the first offence and not before it. The generator walks that space; the
// model below computes the verdict independently.

/// One frame to put on the control stream.
#[derive(Debug, Clone)]
enum ControlEvent {
    /// A well-formed SETTINGS frame: legal first, H3_FRAME_UNEXPECTED again.
    Settings,
    /// A SETTINGS frame whose one identifier is unknown: RFC 9114 §7.2.4 says
    /// an unknown identifier is ignored, so the frame is as legal as
    /// [`ControlEvent::Settings`] -- and as illegal second.
    SettingsUnknownId,
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL with a value outside 0/1, which
    /// RFC 8441 §3 makes meaningless at a server and this one ignores (the
    /// choice its `parse_settings` documents); legal in the same way.
    SettingsConnectProtocolOutOfRange,
    /// A SETTINGS payload repeating an identifier (RFC 9114 §7.2.4).
    SettingsDuplicatePair,
    /// A SETTINGS payload using an identifier RFC 9114 §7.2.4.1 reserves.
    SettingsReservedId,
    /// SETTINGS_H3_DATAGRAM with a value that is neither 0 nor 1
    /// (RFC 9297 §2.1.1).
    SettingsBadDatagramValue,
    /// A SETTINGS payload that ends in the middle of a pair (RFC 9114 §7.1).
    SettingsTruncatedPair,
    /// GOAWAY with this identifier (RFC 9114 §5.2: it must never grow).
    Goaway(u64),
    /// A GOAWAY whose payload is empty rather than one varint (RFC 9114 §7.1).
    GoawayMalformed,
    /// MAX_PUSH_ID with this value (RFC 9114 §7.2.7: it must never shrink).
    MaxPushId(u64),
    /// A MAX_PUSH_ID whose payload has a byte after its varint: the other half
    /// of RFC 9114 §7.1's payload-shape rule, whose ends-early half
    /// [`ControlEvent::GoawayMalformed`] carries.
    MaxPushIdTrailingBytes,
    /// CANCEL_PUSH for a push ID this server never promised (RFC 9114 §7.2.3).
    CancelPush(u64),
    /// A complete frame of a grease type, which RFC 9114 §9 says to ignore --
    /// but only §6.2.1's first-frame rule has been satisfied.
    Grease { n: u64, len: usize },
    /// A HEADERS frame, which RFC 9114 §7.2.2 forbids on the control stream.
    Headers,
    /// A DATA frame, which belongs on no control stream (RFC 9114 §7.2.1).
    Data(usize),
    /// PUSH_PROMISE, which a client may never send (RFC 9114 §7.2.5).
    PushPromise,
    /// A frame type reserved for HTTP/2 (RFC 9114 §11.2.1), by index into
    /// [`RESERVED_HTTP2_TYPES`].
    ReservedH2(usize),
}

/// How the control-stream script ends, once its events are on the wire.
#[derive(Debug, Clone, Copy)]
enum ControlEnd {
    /// Append a CANCEL_PUSH, whose verdict the model already knows: the
    /// sentinel that turns "every earlier frame was accepted" into an exact
    /// close code.
    Sentinel,
    /// Finish the stream cleanly: RFC 9114 §6.2.1 forbids closing the control
    /// stream, so this draws H3_CLOSED_CRITICAL_STREAM.
    FinishCleanly,
    /// Finish the stream in the middle of a declared frame: RFC 9114 §7.1
    /// makes a truncated final frame H3_FRAME_ERROR.
    FinishMidFrame,
}

impl ControlEvent {
    /// The event's bytes on the wire.
    fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Settings => settings_frame(&[(SETTINGS_MAX_FIELD_SECTION_SIZE, 65536)]),
            // 0x1f * N + 0x21 is reserved for greasing settings identifiers
            // too (RFC 9114 §7.2.4.1), so this is exactly what a greasing
            // client sends.
            Self::SettingsUnknownId => settings_frame(&[(grease_type(2), 1)]),
            // SETTINGS_ENABLE_CONNECT_PROTOCOL is 0x08 (RFC 8441 §3).
            Self::SettingsConnectProtocolOutOfRange => settings_frame(&[(0x08, 5)]),
            Self::SettingsDuplicatePair => settings_frame(&[
                (SETTINGS_MAX_FIELD_SECTION_SIZE, 65536),
                (SETTINGS_MAX_FIELD_SECTION_SIZE, 65536),
            ]),
            // 0x00 is SETTINGS_HEADER_TABLE_SIZE in HTTP/2 and reserved here.
            Self::SettingsReservedId => settings_frame(&[(0x00, 0)]),
            Self::SettingsBadDatagramValue => settings_frame(&[(SETTINGS_H3_DATAGRAM, 2)]),
            Self::SettingsTruncatedPair => {
                // An identifier with no value behind it, inside a length that
                // is honest about it: the payload itself ends mid-pair.
                let mut payload = BytesMut::new();
                datagram::put_varint(&mut payload, SETTINGS_MAX_FIELD_SECTION_SIZE);
                frame(FRAME_SETTINGS, &payload)
            }
            Self::Goaway(id) => varint_frame(FRAME_GOAWAY, *id),
            Self::GoawayMalformed => frame(FRAME_GOAWAY, &[]),
            Self::MaxPushId(id) => varint_frame(FRAME_MAX_PUSH_ID, *id),
            Self::MaxPushIdTrailingBytes => {
                let mut payload = BytesMut::new();
                datagram::put_varint(&mut payload, 4);
                payload.extend_from_slice(b"\x00");
                frame(FRAME_MAX_PUSH_ID, &payload)
            }
            Self::CancelPush(id) => varint_frame(FRAME_CANCEL_PUSH, *id),
            Self::Grease { n, len } => frame(grease_type(*n), &pattern(*len)),
            // The payload of a HEADERS or PUSH_PROMISE frame is never parsed
            // on this stream -- the type is the offence -- so its bytes are
            // arbitrary.
            Self::Headers => frame(FRAME_HEADERS, b"never decoded"),
            Self::Data(len) => frame(FRAME_DATA, &pattern(*len)),
            Self::PushPromise => frame(FRAME_PUSH_PROMISE, b"\x00"),
            Self::ReservedH2(index) => frame(RESERVED_HTTP2_TYPES[*index], b"as HTTP/2"),
        }
    }
}

/// The close code the first offence in `events` draws, or `None` if every
/// event is legal.
///
/// Written against the RFC rather than against the server's tables, with one
/// deliberate exception: where two MUST-close rules apply to one frame, the
/// model follows the layering the server evaluates them in -- the frame layer
/// (reserved types, §7.1 payload-shape errors, §7.2.4.1 identifier rules)
/// before the control-stream state (§6.2.1's first-frame rule, §5.2/§7.2.x's
/// stateful rules) -- because the RFC ranks neither and the code on the wire
/// is deterministic. Each arm below says which rule it is applying.
fn control_verdict(events: &[ControlEvent]) -> Option<u64> {
    let mut settings_seen = false;
    let mut goaway: Option<u64> = None;
    let mut max_push_id: Option<u64> = None;

    for event in events {
        match event {
            // RFC 9114 §11.2.1 / §7.2.8: reserved HTTP/2 types are
            // H3_FRAME_UNEXPECTED wherever and *whenever* they arrive -- the
            // frame layer judges the type before the first-frame rule can ask
            // whether it was SETTINGS.
            ControlEvent::ReservedH2(_) => return Some(H3_FRAME_UNEXPECTED),

            // RFC 9114 §7.1: a payload that does not hold what its type
            // promises -- ending early or carrying bytes beyond it -- is
            // H3_FRAME_ERROR, also judged at the frame layer, before SETTINGS
            // has or has not been seen can matter.
            ControlEvent::GoawayMalformed
            | ControlEvent::MaxPushIdTrailingBytes
            | ControlEvent::SettingsTruncatedPair => return Some(H3_FRAME_ERROR),

            // RFC 9114 §7.2.4 (duplicate identifier), §7.2.4.1 (reserved
            // identifier) and RFC 9297 §2.1.1 (H3_DATAGRAM outside 0/1) are
            // all H3_SETTINGS_ERROR, and a SETTINGS frame is parsed before the
            // second-SETTINGS rule is consulted, so the payload's verdict wins
            // even when the frame is also a second SETTINGS.
            ControlEvent::SettingsDuplicatePair
            | ControlEvent::SettingsReservedId
            | ControlEvent::SettingsBadDatagramValue => return Some(H3_SETTINGS_ERROR),

            // The two odd-but-legal payloads are SETTINGS frames like any
            // other: RFC 9114 §7.2.4 ignores an unknown identifier and
            // RFC 8441 §3 gives ENABLE_CONNECT_PROTOCOL no effect at a server,
            // so all three arms differ only in what a *wrong* server would do.
            ControlEvent::Settings
            | ControlEvent::SettingsUnknownId
            | ControlEvent::SettingsConnectProtocolOutOfRange => {
                if settings_seen {
                    // RFC 9114 §7.2.4: a second SETTINGS frame is
                    // H3_FRAME_UNEXPECTED.
                    return Some(H3_FRAME_UNEXPECTED);
                }
                settings_seen = true;
            }

            // RFC 9114 §9 says to ignore an unknown type, but §6.2.1's rule
            // that the first frame must be SETTINGS still applies to it: a
            // greasing peer that leads with grease is answered
            // H3_MISSING_SETTINGS, and after SETTINGS the frame is ignored.
            ControlEvent::Grease { .. } => {
                if !settings_seen {
                    return Some(H3_MISSING_SETTINGS);
                }
            }

            // RFC 9114 §7.2.1/§7.2.2/§7.2.5: none of these belong on the
            // control stream (H3_FRAME_UNEXPECTED) -- unless it is the first
            // frame, where §6.2.1 answers H3_MISSING_SETTINGS instead.
            ControlEvent::Headers | ControlEvent::Data(_) | ControlEvent::PushPromise => {
                return Some(if settings_seen {
                    H3_FRAME_UNEXPECTED
                } else {
                    H3_MISSING_SETTINGS
                });
            }

            ControlEvent::Goaway(id) => {
                if !settings_seen {
                    return Some(H3_MISSING_SETTINGS);
                }
                // RFC 9114 §5.2: an identifier larger than one previously
                // received is H3_ID_ERROR; equal or smaller is legal.
                if goaway.is_some_and(|previous| *id > previous) {
                    return Some(H3_ID_ERROR);
                }
                goaway = Some(*id);
            }

            ControlEvent::MaxPushId(id) => {
                if !settings_seen {
                    return Some(H3_MISSING_SETTINGS);
                }
                // RFC 9114 §7.2.7: a value smaller than one previously
                // received is H3_ID_ERROR; repeating or growing is legal.
                if max_push_id.is_some_and(|previous| *id < previous) {
                    return Some(H3_ID_ERROR);
                }
                max_push_id = Some(*id);
            }

            // RFC 9114 §7.2.3: a CANCEL_PUSH for a push ID never mentioned by
            // a PUSH_PROMISE is H3_ID_ERROR, and this server never promises.
            ControlEvent::CancelPush(_) => {
                return Some(if settings_seen {
                    H3_ID_ERROR
                } else {
                    H3_MISSING_SETTINGS
                });
            }
        }
    }

    None
}

/// The verdict for a whole script: the first offence among the events, or the
/// ending's own.
fn script_verdict(events: &[ControlEvent], end: ControlEnd) -> u64 {
    if let Some(code) = control_verdict(events) {
        return code;
    }
    match end {
        // The sentinel is a CANCEL_PUSH, judged by the same model *in the
        // state the events left behind*: after SETTINGS it is H3_ID_ERROR,
        // before it H3_MISSING_SETTINGS.
        ControlEnd::Sentinel => {
            let mut with_sentinel = events.to_vec();
            with_sentinel.push(ControlEvent::CancelPush(7));
            control_verdict(&with_sentinel).expect("a CANCEL_PUSH always offends")
        }
        // RFC 9114 §6.2.1: closing the control stream, however politely, is
        // H3_CLOSED_CRITICAL_STREAM.
        ControlEnd::FinishCleanly => H3_CLOSED_CRITICAL_STREAM,
        // RFC 9114 §7.1: a stream that ends with its last frame truncated is
        // H3_FRAME_ERROR.
        ControlEnd::FinishMidFrame => H3_FRAME_ERROR,
    }
}

/// Drives one control-stream script and returns the close code and reason the
/// server answered with.
async fn drive_control_script(events: &[ControlEvent], end: ControlEnd) -> (u64, String) {
    let (_endpoint, connection) = connect_quic(&lab().server).await;

    let mut script = Vec::new();
    for event in events {
        script.extend_from_slice(&event.bytes());
    }
    if matches!(end, ControlEnd::Sentinel) {
        script.extend_from_slice(&ControlEvent::CancelPush(7).bytes());
    }

    // Held for the whole case: dropping a `quinn::SendStream` finishes it,
    // which is `FinishCleanly` whether the case asked for it or not.
    let stream = open_uni_tolerant(&connection, STREAM_CONTROL, &script).await;
    if let Some(mut stream) = stream {
        match end {
            ControlEnd::Sentinel => {}
            ControlEnd::FinishCleanly => {
                let _ = stream.finish();
            }
            ControlEnd::FinishMidFrame => {
                // A grease frame announcing five bytes, of which two arrive
                // before the FIN.
                let mut partial = BytesMut::new();
                datagram::put_varint(&mut partial, grease_type(3));
                datagram::put_varint(&mut partial, 5);
                partial.extend_from_slice(b"\x00\x01");
                let _ = stream.write_all(&partial).await;
                let _ = stream.finish();
            }
        }
        let closed = application_close(&connection, TIMEOUT).await;
        drop(stream);
        closed
    } else {
        // The connection ended before the stream could open, which no script
        // here can cause: fail loudly rather than judge nothing.
        panic!("the control stream could not be opened at all");
    }
}

/// Identifier values that make monotonicity interesting: repeats, near
/// neighbours, and every varint length class.
fn any_push_value() -> impl Strategy<Value = u64> {
    prop::sample::select(vec![0u64, 1, 2, 4, 8, 0x3f, 0x40, 0x3fff, 0x4000])
}

fn any_control_event() -> impl Strategy<Value = ControlEvent> {
    prop_oneof![
        6 => any_push_value().prop_map(ControlEvent::Goaway),
        6 => any_push_value().prop_map(ControlEvent::MaxPushId),
        4 => (0u64..8, 0usize..24)
            .prop_map(|(n, len)| ControlEvent::Grease { n, len }),
        1 => Just(ControlEvent::Settings),
        1 => Just(ControlEvent::SettingsUnknownId),
        1 => Just(ControlEvent::SettingsConnectProtocolOutOfRange),
        1 => Just(ControlEvent::SettingsDuplicatePair),
        1 => Just(ControlEvent::SettingsReservedId),
        1 => Just(ControlEvent::SettingsBadDatagramValue),
        1 => Just(ControlEvent::SettingsTruncatedPair),
        1 => Just(ControlEvent::GoawayMalformed),
        1 => Just(ControlEvent::MaxPushIdTrailingBytes),
        1 => any_push_value().prop_map(ControlEvent::CancelPush),
        1 => Just(ControlEvent::Headers),
        1 => (0usize..16).prop_map(ControlEvent::Data),
        1 => Just(ControlEvent::PushPromise),
        1 => (0usize..RESERVED_HTTP2_TYPES.len()).prop_map(ControlEvent::ReservedH2),
    ]
}

/// A whole script: usually a legal SETTINGS first -- the space of *stateful*
/// sequences lives behind it -- and sometimes not, so the first-frame rule
/// keeps being exercised at every event type.
fn any_control_script() -> impl Strategy<Value = (Vec<ControlEvent>, ControlEnd)> {
    let end = prop_oneof![
        4 => Just(ControlEnd::Sentinel),
        1 => Just(ControlEnd::FinishCleanly),
        1 => Just(ControlEnd::FinishMidFrame),
    ];
    (
        prop::bool::weighted(0.85),
        prop::collection::vec(any_control_event(), 0..10),
        end,
    )
        .prop_map(|(settings_first, mut events, end)| {
            if settings_first {
                events.insert(0, ControlEvent::Settings);
            }
            (events, end)
        })
}

proptest! {
    // Every case is a QUIC connection driven to a CONNECTION_CLOSE, so the
    // default is low and `PROPTEST_CASES` scales it.
    #![proptest_config(config(48))]

    /// For any sequence of control frames, the connection closes with the code
    /// of the *first* offence -- and a sequence with no offence accepts every
    /// frame, proven by the sentinel's code arriving and no other.
    #[test]
    fn the_control_stream_closes_on_the_first_offence_and_not_before(
        (events, end) in any_control_script(),
    ) {
        let expected = script_verdict(&events, end);
        run_case(async {
            let (code, reason) = drive_control_script(&events, end).await;
            assert_eq!(
                code, expected,
                "events {events:?} ending {end:?}: the reason was {reason:?}"
            );
            assert!(!reason.is_empty(), "the peer must be told what it did");
        });
    }
}

/// Every model arm at least once per CI run, at a position after a legal
/// prefix -- proptest's coverage of the rarer arms is probabilistic, and a
/// wrong model arm should fail the suite deterministically, not one run in
/// five.
#[test]
fn every_control_offence_draws_its_modelled_code() {
    let legal_prefix = vec![
        ControlEvent::Settings,
        ControlEvent::Grease { n: 2, len: 9 },
        ControlEvent::Goaway(8),
        ControlEvent::MaxPushId(4),
        ControlEvent::Goaway(8),
        ControlEvent::MaxPushId(4),
        ControlEvent::Goaway(2),
        ControlEvent::MaxPushId(0x4000),
    ];

    let offences: Vec<(ControlEvent, u64)> = vec![
        (ControlEvent::Settings, H3_FRAME_UNEXPECTED),
        (ControlEvent::SettingsUnknownId, H3_FRAME_UNEXPECTED),
        (
            ControlEvent::SettingsConnectProtocolOutOfRange,
            H3_FRAME_UNEXPECTED,
        ),
        (ControlEvent::MaxPushIdTrailingBytes, H3_FRAME_ERROR),
        (ControlEvent::SettingsDuplicatePair, H3_SETTINGS_ERROR),
        (ControlEvent::SettingsReservedId, H3_SETTINGS_ERROR),
        (ControlEvent::SettingsBadDatagramValue, H3_SETTINGS_ERROR),
        (ControlEvent::SettingsTruncatedPair, H3_FRAME_ERROR),
        (ControlEvent::Goaway(9), H3_ID_ERROR),
        (ControlEvent::GoawayMalformed, H3_FRAME_ERROR),
        (ControlEvent::MaxPushId(3), H3_ID_ERROR),
        (ControlEvent::CancelPush(0), H3_ID_ERROR),
        (ControlEvent::Headers, H3_FRAME_UNEXPECTED),
        (ControlEvent::Data(4), H3_FRAME_UNEXPECTED),
        (ControlEvent::PushPromise, H3_FRAME_UNEXPECTED),
        (ControlEvent::ReservedH2(0), H3_FRAME_UNEXPECTED),
    ];

    for (offence, expected) in offences {
        let mut events = legal_prefix.clone();
        events.push(offence.clone());
        assert_eq!(
            control_verdict(&events),
            Some(expected),
            "the model must agree with this table for {offence:?}"
        );
        run_case(async {
            let (code, reason) = drive_control_script(&events, ControlEnd::Sentinel).await;
            assert_eq!(code, expected, "{offence:?}: the reason was {reason:?}");
        });
    }

    // And the two endings, behind the same legal prefix.
    for (end, expected) in [
        (ControlEnd::Sentinel, H3_ID_ERROR),
        (ControlEnd::FinishCleanly, H3_CLOSED_CRITICAL_STREAM),
        (ControlEnd::FinishMidFrame, H3_FRAME_ERROR),
    ] {
        assert_eq!(script_verdict(&legal_prefix, end), expected);
        run_case(async {
            let (code, reason) = drive_control_script(&legal_prefix, end).await;
            assert_eq!(code, expected, "{end:?}: the reason was {reason:?}");
        });
    }

    // The odd-but-legal SETTINGS spellings in their legal role: as the first
    // frame, satisfying §6.2.1, proven by the sentinel's H3_ID_ERROR -- a
    // server that wrongly refused either would close with its own code
    // instead.
    for first in [
        ControlEvent::SettingsUnknownId,
        ControlEvent::SettingsConnectProtocolOutOfRange,
    ] {
        let events = vec![first.clone(), ControlEvent::Goaway(4)];
        assert_eq!(script_verdict(&events, ControlEnd::Sentinel), H3_ID_ERROR);
        run_case(async {
            let (code, reason) = drive_control_script(&events, ControlEnd::Sentinel).await;
            assert_eq!(
                code, H3_ID_ERROR,
                "{first:?} must satisfy the first-frame rule; the reason was {reason:?}"
            );
        });
    }
}

// ---------------------------------------------------------------------------
// Property 2: unidirectional stream openings, in any order
// ---------------------------------------------------------------------------
//
// The counting rules -- one control stream, one QPACK stream of each kind, no
// client push -- are pinned one offence at a time in `it_hostile`. What those
// rows fix in place is a particular history (nothing else open); the property
// here is that the verdict depends on the *counts* alone, whatever legal
// openings preceded the offence and in whatever order.

/// A stream the peer is entitled to open.
#[derive(Debug, Clone, Copy, PartialEq)]
enum UniOpen {
    /// The control stream, carrying a legal SETTINGS.
    Control,
    /// The peer's one QPACK encoder stream (RFC 9204 §4.2).
    QpackEncoder,
    /// The peer's one QPACK decoder stream (RFC 9204 §4.2).
    QpackDecoder,
    /// A stream of a grease type, which costs itself and nothing else
    /// (RFC 9114 §6.2).
    Unknown(u64),
    /// A grease-typed stream the peer finishes at once: still nothing
    /// (RFC 9114 §6.2 aborts or discards it either way).
    UnknownFinished(u64),
    /// A stream reset before its type varint completes, which RFC 9114 §6.2
    /// obliges a receiver to tolerate.
    ResetBeforeType,
}

/// The offence that ends the case.
#[derive(Debug, Clone, Copy)]
enum UniOffence {
    /// A client-initiated push stream (RFC 9114 §6.2.2).
    Push,
    /// A second control stream (RFC 9114 §6.2.1).
    SecondControl,
    /// A second QPACK encoder stream (RFC 9204 §4.2).
    SecondEncoder,
    /// A second QPACK decoder stream (RFC 9204 §4.2).
    SecondDecoder,
    /// Finishing the control stream (RFC 9114 §6.2.1).
    FinishControl,
}

impl UniOffence {
    fn expected_code(self) -> u64 {
        match self {
            // RFC 9114 §6.2.1/§6.2.2 and RFC 9204 §4.2 all name
            // H3_STREAM_CREATION_ERROR for a stream that may not exist.
            Self::Push | Self::SecondControl | Self::SecondEncoder | Self::SecondDecoder => {
                H3_STREAM_CREATION_ERROR
            }
            // RFC 9114 §6.2.1: a critical stream that closes is
            // H3_CLOSED_CRITICAL_STREAM.
            Self::FinishControl => H3_CLOSED_CRITICAL_STREAM,
        }
    }
}

/// Openings in a generated order, plus an offence the order makes applicable.
fn any_uni_case() -> impl Strategy<Value = (Vec<UniOpen>, UniOffence)> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        prop::collection::vec(
            prop_oneof![
                3 => (0u64..8).prop_map(|n| UniOpen::Unknown(grease_type(n))),
                1 => (0u64..8).prop_map(|n| UniOpen::UnknownFinished(grease_type(n))),
                1 => Just(UniOpen::ResetBeforeType),
            ],
            0..3,
        ),
        any::<prop::sample::Index>(),
    )
        .prop_flat_map(|(control, encoder, decoder, unknowns, pick)| {
            let mut opens = Vec::new();
            if control {
                opens.push(UniOpen::Control);
            }
            if encoder {
                opens.push(UniOpen::QpackEncoder);
            }
            if decoder {
                opens.push(UniOpen::QpackDecoder);
            }
            opens.extend(unknowns);

            let mut offences = vec![UniOffence::Push];
            if control {
                offences.push(UniOffence::SecondControl);
                offences.push(UniOffence::FinishControl);
            }
            if encoder {
                offences.push(UniOffence::SecondEncoder);
            }
            if decoder {
                offences.push(UniOffence::SecondDecoder);
            }
            let offence = offences[pick.index(offences.len())];

            (Just(opens).prop_shuffle(), Just(offence))
        })
}

proptest! {
    #![proptest_config(config(24))]

    /// Whatever legal unidirectional streams are open, and in whatever order
    /// they were opened, breaking one of the counting rules closes the
    /// connection with that rule's code.
    #[test]
    fn uni_stream_offences_draw_their_code_whatever_is_already_open(
        (opens, offence) in any_uni_case(),
    ) {
        run_case(async {
            let (_endpoint, connection) = connect_quic(&lab().server).await;

            let mut held = Vec::new();
            let mut control = None;
            for open in &opens {
                let stream = match open {
                    UniOpen::Control => {
                        let stream = open_uni_tolerant(
                            &connection,
                            STREAM_CONTROL,
                            &settings_frame(&[(SETTINGS_MAX_FIELD_SECTION_SIZE, 65536)]),
                        )
                        .await;
                        control = stream;
                        continue;
                    }
                    UniOpen::QpackEncoder => {
                        open_uni_tolerant(&connection, STREAM_QPACK_ENCODER, &[]).await
                    }
                    UniOpen::QpackDecoder => {
                        open_uni_tolerant(&connection, STREAM_QPACK_DECODER, &[]).await
                    }
                    UniOpen::Unknown(kind) => {
                        open_uni_tolerant(&connection, *kind, b"nothing here means anything").await
                    }
                    UniOpen::UnknownFinished(kind) => {
                        let stream = open_uni_tolerant(&connection, *kind, b"and gone").await;
                        if let Some(mut stream) = stream {
                            let _ = stream.finish();
                        }
                        continue;
                    }
                    UniOpen::ResetBeforeType => {
                        // Half a two-byte type varint (RFC 9000 §16), then a
                        // reset: the type never completes.
                        if let Ok(mut stream) = connection.open_uni().await {
                            let _ = stream.write_all(&[0x40]).await;
                            let _ = stream.reset(quinn::VarInt::from_u32(0));
                        }
                        continue;
                    }
                };
                // Held rather than dropped: a dropped stream finishes, and a
                // finished control stream is a different offence.
                held.extend(stream);
            }

            match offence {
                UniOffence::Push => {
                    held.extend(open_uni_tolerant(&connection, STREAM_PUSH, &[]).await);
                }
                UniOffence::SecondControl => {
                    held.extend(open_uni_tolerant(&connection, STREAM_CONTROL, &[]).await);
                }
                UniOffence::SecondEncoder => {
                    held.extend(open_uni_tolerant(&connection, STREAM_QPACK_ENCODER, &[]).await);
                }
                UniOffence::SecondDecoder => {
                    held.extend(open_uni_tolerant(&connection, STREAM_QPACK_DECODER, &[]).await);
                }
                UniOffence::FinishControl => {
                    let mut stream = control.take().expect("the case opened a control stream");
                    let _ = stream.finish();
                    held.push(stream);
                }
            }

            let (code, reason) = application_close(&connection, TIMEOUT).await;
            assert_eq!(
                code,
                offence.expected_code(),
                "opens {opens:?}, offence {offence:?}: the reason was {reason:?}"
            );
            drop(held);
            drop(control);
        });
    }
}

// ---------------------------------------------------------------------------
// Property 3: request-stream lifecycles, interleaved across streams
// ---------------------------------------------------------------------------
//
// The request reader's ordering rules -- grease is skipped before the request
// (RFC 9114 §9), a stream that ends without one is H3_REQUEST_INCOMPLETE
// (§4.1), DATA first is H3_FRAME_UNEXPECTED (§4.1), a truncated frame is
// H3_FRAME_ERROR (§7.1), and a tunnel takes DATA alone (§4.4) -- are pinned
// one at a time by `it_hostile`/`it_tcp`, and generatively at the decoder by
// `it_fuzz`. What has no pin is the composition on the live server: several
// streams in several phases at once, each step's answer read off the wire
// before the next, ending in a fatal whose code must be untouched by
// everything legal that preceded it.

/// One request stream's planned life.
#[derive(Debug, Clone)]
enum StreamPlan {
    /// Grease frames, a CONNECT to the echo target, a 200, tunnel traffic.
    Echo {
        grease: Vec<(u64, usize)>,
        /// Whether a DATA frame rides in the same write as the CONNECT,
        /// before the 200 could possibly have arrived.
        early: bool,
        ops: Vec<TunnelOp>,
        end: TunnelEnd,
    },
    /// Grease frames, a CONNECT the policy refuses, a 403.
    Denied { grease: Vec<(u64, usize)> },
    /// Grease frames and then a FIN with no request behind them: the server
    /// aborts its response stream with H3_REQUEST_INCOMPLETE (RFC 9114 §4.1).
    FinWithoutRequest { grease: Vec<(u64, usize)> },
}

/// One thing to do on an established tunnel.
#[derive(Debug, Clone)]
enum TunnelOp {
    /// DATA that must come back from the echo target byte for byte.
    Data(usize),
    /// An empty DATA frame, legal and invisible (RFC 9114 §7.2.1).
    EmptyData,
    /// A complete frame of a grease type, skipped even on a tunnel
    /// (RFC 9114 §9 and §4.4's allowance for unknown types).
    Grease(u64, usize),
}

/// How a tunnel's script ends.
#[derive(Debug, Clone, Copy)]
enum TunnelEnd {
    /// A clean FIN: the tunnel half-closes, the echo target hangs up, and the
    /// stream ends with nothing left over.
    Fin,
    /// A client reset: the tunnel is abandoned; the connection must not be.
    Reset,
    /// Left open until the case ends.
    LeaveOpen,
}

/// The offence that ends the case, always the last thing on the wire.
#[derive(Debug, Clone, Copy)]
enum RequestFatal {
    /// DATA -- empty or not -- before any HEADERS (RFC 9114 §4.1).
    DataFirst { empty: bool },
    /// A control-stream frame on a fresh request stream (RFC 9114
    /// §7.2.3-§7.2.7), by index into [`CONTROL_ONLY_TYPES`].
    ControlFrame(usize),
    /// A reserved HTTP/2 type on a fresh request stream (RFC 9114 §11.2.1).
    Reserved(usize),
    /// A HEADERS frame announced and truncated by FIN (RFC 9114 §7.1).
    FinMidHeaders,
    /// A trailer-like HEADERS on a live tunnel (RFC 9114 §4.4).
    TrailerOnTunnel,
    /// A second HEADERS written in the same flight as the CONNECT, before its
    /// answer could have arrived: RFC 9114 §4.4 judges it once the CONNECT
    /// completes, wherever the 200 was at the time (`it_tcp` pins the
    /// stand-alone case; here it lands amid other live streams).
    TrailerBeforeAnswer,
    /// A DATA frame announced on a live tunnel and truncated by FIN
    /// (RFC 9114 §7.1).
    FinMidData,
    /// A CANCEL_PUSH on the control stream (RFC 9114 §7.2.3): the control
    /// stream's verdict must be untouched by every request stream in flight.
    ControlOffence,
}

/// The frame types that belong on the control stream alone.
const CONTROL_ONLY_TYPES: [u64; 5] = [
    FRAME_SETTINGS,
    FRAME_GOAWAY,
    FRAME_CANCEL_PUSH,
    FRAME_MAX_PUSH_ID,
    FRAME_PUSH_PROMISE,
];

impl RequestFatal {
    fn expected_code(self) -> u64 {
        match self {
            // RFC 9114 §4.1 (frame order), §7.2.3-§7.2.7 (control-only
            // types), §11.2.1 (reserved types) and §4.4 (a tunnel takes DATA
            // alone) all name H3_FRAME_UNEXPECTED.
            Self::DataFirst { .. }
            | Self::ControlFrame(_)
            | Self::Reserved(_)
            | Self::TrailerOnTunnel
            | Self::TrailerBeforeAnswer => H3_FRAME_UNEXPECTED,
            // RFC 9114 §7.1: a stream whose last frame is truncated is
            // H3_FRAME_ERROR.
            Self::FinMidHeaders | Self::FinMidData => H3_FRAME_ERROR,
            // RFC 9114 §7.2.3: CANCEL_PUSH for a push that was never promised
            // is H3_ID_ERROR.
            Self::ControlOffence => H3_ID_ERROR,
        }
    }
}

/// A held-open tunnel: both halves, plus the id its payloads are tagged with.
struct LiveTunnel {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

/// Establishes a request stream: grease frames, the CONNECT, and optionally a
/// DATA frame sent *optimistically in the same write* -- before any answer
/// could have arrived -- then the response, whose status is returned with the
/// two stream halves.
///
/// The optimistic DATA is the point where a request stream's bytes cross an
/// internal seam: the resolver may well have read them along with the HEADERS
/// before the CONNECT is answered, and they must survive the handoff to the
/// tunnel that is only then created. Nothing else in the suite sends it.
async fn establish(
    connection: &quinn::Connection,
    grease: &[(u64, usize)],
    authority: &str,
    early_data: Option<&[u8]>,
) -> (quinn::SendStream, quinn::RecvStream, String) {
    let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");

    let mut wire = Vec::new();
    for (n, len) in grease {
        wire.extend_from_slice(&frame(grease_type(*n), &pattern(*len)));
    }
    wire.extend_from_slice(&connect_headers_frame(authority));
    if let Some(early) = early_data {
        wire.extend_from_slice(&frame(FRAME_DATA, early));
    }
    send.write_all(&wire).await.expect("send the request");

    let (frame_type, payload) = read_frame(&mut recv).await;
    assert_eq!(frame_type, FRAME_HEADERS, "a response begins with HEADERS");
    let status = status_of(&payload);
    (send, recv, status)
}

/// Reads DATA frames off a tunnel until `expected` has come back whole,
/// however the server framed the returning bytes.
async fn read_echoed(recv: &mut quinn::RecvStream, expected: &[u8]) {
    let mut received = Vec::new();
    while received.len() < expected.len() {
        let (frame_type, chunk) = read_frame(recv).await;
        assert_eq!(frame_type, FRAME_DATA, "a tunnel carries DATA alone");
        received.extend_from_slice(&chunk);
    }
    assert_eq!(received, expected, "the echo must return what was sent");
}

/// Sends one DATA frame through a tunnel and reads it back off the echo.
async fn echo_round_trip(tunnel: &mut LiveTunnel, payload: &[u8]) {
    tunnel
        .send
        .write_all(&frame(FRAME_DATA, payload))
        .await
        .expect("send tunnel payload");
    read_echoed(&mut tunnel.recv, payload).await;
}

/// Runs one stream's whole plan, returning the tunnel if it is left open.
///
/// Every observable answer -- the response status, each echo round trip, the
/// H3_REQUEST_INCOMPLETE reset -- is read before this returns, which is what
/// lets the schedule interleave plans without racing the model: by the time
/// the next plan's step runs, this one's claims are already proven.
async fn run_plan(
    connection: &quinn::Connection,
    plan: &StreamPlan,
    tag: usize,
) -> Option<LiveTunnel> {
    match plan {
        StreamPlan::Echo {
            grease,
            early,
            ops,
            end,
        } => {
            let authority = lab().echo.to_string();
            let early_payload = format!("early-{tag}");
            let early_data = early.then_some(early_payload.as_bytes());
            let (send, mut recv, status) =
                establish(connection, grease, &authority, early_data).await;
            assert_eq!(status, "200", "the tunnel must open (grease {grease:?})");
            if let Some(early) = early_data {
                // The optimistic bytes crossed into the tunnel: the echo
                // returns them like any others.
                read_echoed(&mut recv, early).await;
            }
            let mut tunnel = LiveTunnel { send, recv };

            for (index, op) in ops.iter().enumerate() {
                match op {
                    TunnelOp::Data(len) => {
                        let mut payload = pattern(*len + 1);
                        payload[0] = tag as u8;
                        echo_round_trip(&mut tunnel, &payload).await;
                    }
                    TunnelOp::EmptyData => {
                        tunnel
                            .send
                            .write_all(&frame(FRAME_DATA, &[]))
                            .await
                            .expect("send an empty DATA frame");
                    }
                    TunnelOp::Grease(n, len) => {
                        tunnel
                            .send
                            .write_all(&frame(grease_type(*n), &pattern(*len)))
                            .await
                            .expect("send a grease frame on the tunnel");
                    }
                }
                // Unacknowledged ops leave no trace of their own; the probe
                // after each is what proves they were skipped or absorbed
                // rather than left half-read.
                if matches!(op, TunnelOp::EmptyData | TunnelOp::Grease(..)) {
                    let probe = format!("probe-{tag}-{index}");
                    echo_round_trip(&mut tunnel, probe.as_bytes()).await;
                }
            }

            match end {
                TunnelEnd::Fin => {
                    tunnel.send.finish().expect("finish the tunnel");
                    // The echo target answers the half-close by hanging up, so
                    // the response side ends with nothing beyond what the
                    // round trips already read.
                    let rest = tokio::time::timeout(TIMEOUT, tunnel.recv.read_to_end(4096))
                        .await
                        .expect("the tunnel must end after the client's FIN")
                        .expect("the tunnel must end cleanly");
                    assert!(
                        rest.is_empty(),
                        "everything the echo sent was already read: {rest:?}"
                    );
                    None
                }
                TunnelEnd::Reset => {
                    // The abandonment itself: what it does to the target and
                    // the response side is `it_tcp`'s to pin; here it only has
                    // to leave the rest of the connection standing, which the
                    // steps after this prove.
                    let _ = tunnel.send.reset(quinn::VarInt::from_u32(0x10c));
                    None
                }
                TunnelEnd::LeaveOpen => Some(tunnel),
            }
        }

        StreamPlan::Denied { grease } => {
            let (send, recv, status) = establish(connection, grease, DENIED_TARGET, None).await;
            assert_eq!(status, "403", "the policy must refuse this target");
            drop((send, recv));
            None
        }

        StreamPlan::FinWithoutRequest { grease } => {
            let (mut send, mut recv) = connection.open_bi().await.expect("open a request stream");
            let mut wire = Vec::new();
            for (n, len) in grease {
                wire.extend_from_slice(&frame(grease_type(*n), &pattern(*len)));
            }
            send.write_all(&wire).await.expect("send the grease");
            send.finish().expect("finish without a request");

            // RFC 9114 §4.1: the server aborts its response stream with
            // H3_REQUEST_INCOMPLETE -- the grease frames must not have been
            // mistaken for the beginnings of a request.
            let ended = tokio::time::timeout(TIMEOUT, recv.read_to_end(256))
                .await
                .expect("the server must answer a request that never was");
            match ended {
                Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code))) => {
                    assert_eq!(
                        code.into_inner(),
                        H3_REQUEST_INCOMPLETE,
                        "grease {grease:?}"
                    );
                }
                other => panic!(
                    "a stream finished before its request must be reset with \
                     H3_REQUEST_INCOMPLETE, got {other:?}"
                ),
            }
            None
        }
    }
}

/// Commits the fatal and returns the code the model expects for it.
///
/// `control` is the case's control stream, if a prelude opened one: the
/// control offence lands there, in whatever state the prelude left, and on a
/// control stream of its own otherwise.
async fn commit_fatal(
    connection: &quinn::Connection,
    fatal: RequestFatal,
    live: &mut Vec<LiveTunnel>,
    control: &mut Option<quinn::SendStream>,
) -> u64 {
    /// A fresh stream carrying `bytes`, with a write failure tolerated: the
    /// close it is racing is the one the case asserts.
    async fn fresh(connection: &quinn::Connection, bytes: &[u8]) -> Option<quinn::SendStream> {
        let (mut send, _recv) = connection.open_bi().await.ok()?;
        let _ = send.write_all(bytes).await;
        Some(send)
    }

    /// The last tunnel still open, or a fresh one against the echo target: the
    /// tunnel offences need a stream whose CONNECT has completed.
    async fn a_live_tunnel(
        connection: &quinn::Connection,
        live: &mut Vec<LiveTunnel>,
    ) -> LiveTunnel {
        if let Some(tunnel) = live.pop() {
            return tunnel;
        }
        let authority = lab().echo.to_string();
        let (send, recv, status) = establish(connection, &[], &authority, None).await;
        assert_eq!(status, "200", "the offence needs a live tunnel");
        LiveTunnel { send, recv }
    }

    match fatal {
        RequestFatal::DataFirst { empty } => {
            let payload = if empty { Vec::new() } else { pattern(9) };
            let held = fresh(connection, &frame(FRAME_DATA, &payload)).await;
            drop(held);
        }
        RequestFatal::ControlFrame(index) => {
            // A complete frame, payload and all: `it_hostile` pins the verdict
            // for an announced-but-unsent one, so this is the other spelling.
            let kind = CONTROL_ONLY_TYPES[index];
            let bytes = if kind == FRAME_PUSH_PROMISE {
                frame(kind, b"\x00")
            } else if kind == FRAME_SETTINGS {
                settings_frame(&[(SETTINGS_MAX_FIELD_SECTION_SIZE, 65536)])
            } else {
                varint_frame(kind, 4)
            };
            let held = fresh(connection, &bytes).await;
            drop(held);
        }
        RequestFatal::Reserved(index) => {
            let held = fresh(
                connection,
                &frame(RESERVED_HTTP2_TYPES[index], b"as HTTP/2"),
            )
            .await;
            drop(held);
        }
        RequestFatal::FinMidHeaders => {
            if let Ok((mut send, _recv)) = connection.open_bi().await {
                let mut wire = BytesMut::new();
                datagram::put_varint(&mut wire, FRAME_HEADERS);
                datagram::put_varint(&mut wire, 8);
                wire.extend_from_slice(b"\x00\x01\x02");
                let _ = send.write_all(&wire).await;
                let _ = send.finish();
            }
        }
        RequestFatal::TrailerOnTunnel => {
            let mut tunnel = a_live_tunnel(connection, live).await;
            // Complete, not merely announced: the announced spelling is
            // `it_hostile`'s row j6.
            let _ = tunnel
                .send
                .write_all(&frame(FRAME_HEADERS, b"trailer"))
                .await;
            live.push(tunnel);
        }
        RequestFatal::FinMidData => {
            let mut tunnel = a_live_tunnel(connection, live).await;
            let mut wire = BytesMut::new();
            datagram::put_varint(&mut wire, FRAME_DATA);
            datagram::put_varint(&mut wire, 32);
            wire.extend_from_slice(b"\x00\x01");
            let _ = tunnel.send.write_all(&wire).await;
            let _ = tunnel.send.finish();
            live.push(tunnel);
        }
        RequestFatal::TrailerBeforeAnswer => {
            // The CONNECT and its forbidden trailer in one write; the answer
            // is never read, so nothing here waits for the 200 the verdict
            // does not depend on.
            if let Ok((mut send, recv)) = connection.open_bi().await {
                let mut wire = connect_headers_frame(&lab().echo.to_string());
                wire.extend_from_slice(&frame(FRAME_HEADERS, b"trailer"));
                let _ = send.write_all(&wire).await;
                live.push(LiveTunnel { send, recv });
            }
        }
        RequestFatal::ControlOffence => {
            let offence = ControlEvent::CancelPush(9).bytes();
            match control {
                Some(stream) => {
                    let _ = stream.write_all(&offence).await;
                }
                None => {
                    let mut script = ControlEvent::Settings.bytes();
                    script.extend_from_slice(&offence);
                    *control = open_uni_tolerant(connection, STREAM_CONTROL, &script).await;
                }
            }
        }
    }

    fatal.expected_code()
}

fn any_grease_prefix() -> impl Strategy<Value = Vec<(u64, usize)>> {
    prop::collection::vec((0u64..8, 0usize..24), 0..3)
}

fn any_tunnel_op() -> impl Strategy<Value = TunnelOp> {
    prop_oneof![
        3 => (0usize..48).prop_map(TunnelOp::Data),
        1 => Just(TunnelOp::EmptyData),
        1 => (0u64..8, 0usize..24).prop_map(|(n, len)| TunnelOp::Grease(n, len)),
    ]
}

fn any_stream_plan() -> impl Strategy<Value = StreamPlan> {
    prop_oneof![
        4 => (
            any_grease_prefix(),
            any::<bool>(),
            prop::collection::vec(any_tunnel_op(), 0..4),
            prop_oneof![
                2 => Just(TunnelEnd::Fin),
                1 => Just(TunnelEnd::Reset),
                2 => Just(TunnelEnd::LeaveOpen),
            ],
        )
            .prop_map(|(grease, early, ops, end)| StreamPlan::Echo { grease, early, ops, end }),
        1 => any_grease_prefix().prop_map(|grease| StreamPlan::Denied { grease }),
        1 => any_grease_prefix().prop_map(|grease| StreamPlan::FinWithoutRequest { grease }),
    ]
}

fn any_request_fatal() -> impl Strategy<Value = RequestFatal> {
    prop_oneof![
        (any::<bool>()).prop_map(|empty| RequestFatal::DataFirst { empty }),
        (0usize..CONTROL_ONLY_TYPES.len()).prop_map(RequestFatal::ControlFrame),
        (0usize..RESERVED_HTTP2_TYPES.len()).prop_map(RequestFatal::Reserved),
        Just(RequestFatal::FinMidHeaders),
        Just(RequestFatal::TrailerOnTunnel),
        Just(RequestFatal::TrailerBeforeAnswer),
        Just(RequestFatal::FinMidData),
        Just(RequestFatal::ControlOffence),
    ]
}

/// A control-stream script that is legal by construction: SETTINGS first,
/// grease anywhere after it, GOAWAY identifiers that never grow, MAX_PUSH_ID
/// values that never shrink.
fn any_legal_control_prelude() -> impl Strategy<Value = Vec<ControlEvent>> {
    (
        prop::collection::vec((0u64..8, 0usize..16), 0..2),
        prop::collection::vec(any_push_value(), 0..3),
        prop::collection::vec(any_push_value(), 0..3),
    )
        .prop_map(|(grease, mut goaways, mut push_ids)| {
            goaways.sort_unstable_by(|a, b| b.cmp(a));
            push_ids.sort_unstable();

            let mut events = vec![ControlEvent::Settings];
            events.extend(
                grease
                    .into_iter()
                    .map(|(n, len)| ControlEvent::Grease { n, len }),
            );
            events.extend(goaways.into_iter().map(ControlEvent::Goaway));
            events.extend(push_ids.into_iter().map(ControlEvent::MaxPushId));
            events
        })
}

proptest! {
    #![proptest_config(config(24))]

    /// Any mixture of request-stream lifecycles -- tunnels with greased,
    /// optimistic and fragmented traffic, refusals, abandoned requests, with
    /// or without a legal control stream beside them -- runs to its
    /// per-stream answers, and the one fatal at the end closes the connection
    /// with that fatal's code: nothing legal before it changed the verdict,
    /// and nothing before it closed the connection early (a premature close
    /// would fail a round trip first).
    #[test]
    fn request_lifecycles_compose_and_the_one_fatal_decides_the_close(
        prelude in prop::option::of(any_legal_control_prelude()),
        plans in prop::collection::vec(any_stream_plan(), 1..4),
        fatal in any_request_fatal(),
    ) {
        if let Some(prelude) = &prelude {
            prop_assert_eq!(
                control_verdict(prelude), None,
                "the prelude generator must only build legal scripts"
            );
        }
        run_case(async {
            let (_endpoint, connection) = connect_quic(&lab().server).await;

            let mut control = match &prelude {
                Some(events) => {
                    let mut script = Vec::new();
                    for event in events {
                        script.extend_from_slice(&event.bytes());
                    }
                    open_uni_tolerant(&connection, STREAM_CONTROL, &script).await
                }
                None => None,
            };

            let mut live = Vec::new();
            for (tag, plan) in plans.iter().enumerate() {
                live.extend(run_plan(&connection, plan, tag).await);
            }

            let expected = commit_fatal(&connection, fatal, &mut live, &mut control).await;
            let (code, reason) = application_close(&connection, TIMEOUT).await;
            assert_eq!(
                code, expected,
                "prelude {prelude:?}, plans {plans:?}, fatal {fatal:?}: \
                 the reason was {reason:?}"
            );
            drop((live, control));
        });
    }
}

/// Every request-stream fatal at least once per CI run, each on its own
/// connection with one live tunnel standing, so a wrong expected code fails
/// deterministically rather than probabilistically.
#[test]
fn every_request_fatal_draws_its_modelled_code() {
    let fatals = [
        RequestFatal::DataFirst { empty: true },
        RequestFatal::DataFirst { empty: false },
        RequestFatal::ControlFrame(0),
        RequestFatal::ControlFrame(1),
        RequestFatal::ControlFrame(2),
        RequestFatal::ControlFrame(3),
        RequestFatal::ControlFrame(4),
        RequestFatal::Reserved(0),
        RequestFatal::FinMidHeaders,
        RequestFatal::TrailerOnTunnel,
        RequestFatal::TrailerBeforeAnswer,
        RequestFatal::FinMidData,
        RequestFatal::ControlOffence,
    ];

    for fatal in fatals {
        run_case(async {
            let (_endpoint, connection) = connect_quic(&lab().server).await;

            // One live tunnel first -- with optimistic early data, so the
            // seam it crosses is exercised deterministically too -- so the
            // fatal always lands on a connection that is demonstrably serving.
            let plan = StreamPlan::Echo {
                grease: vec![(1, 4)],
                early: true,
                ops: vec![TunnelOp::Data(16)],
                end: TunnelEnd::LeaveOpen,
            };
            let mut live = Vec::new();
            live.extend(run_plan(&connection, &plan, 0).await);

            let mut control = None;
            let expected = commit_fatal(&connection, fatal, &mut live, &mut control).await;
            let (code, reason) = application_close(&connection, TIMEOUT).await;
            assert_eq!(code, expected, "{fatal:?}: the reason was {reason:?}");
            drop((live, control));
        });
    }
}
