//! Two modes on the D106 SNI gate, chosen by the first byte.
//!
//! This is the parser that runs first and trusts least: it reads a UDP datagram
//! before quinn has seen it, before a handshake has begun and therefore before
//! anything has authenticated, on bytes whose sender chose every one of them. A
//! panic here is a packet that stops the server.
//!
//! Even inputs: a whole datagram through [`gate::judgement`] — the long header,
//! the Initial packet protection under the keys the datagram's own Destination
//! Connection ID derives, the frame walk that assembles the offset-0 CRYPTO
//! stream, and the ClientHello reader on the far side of it.
//!
//! Odd inputs: CRYPTO bytes straight into [`gate::first_flight`]. The only way
//! to reach the ClientHello reader through a datagram is to spell an Initial
//! packet that authenticates, which a fuzzer cannot do by luck; the seed corpus
//! carries a few real ones, and this mode is what actually explores the TLS
//! parsing behind them.
//!
//! The seeds are written by a test in `tests/it_gate_shapes.rs`, so `cargo
//! test` refreshes `fuzz/corpus/gate/` and the mode byte in front of each seed
//! is kept in step with the two constants below.

#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use volto::gate::{self, FirstFlight, Names, Refusal, Verdict};

/// Header Form bit: set on a long header (RFC 9000 §17).
const LONG_HEADER_FORM: u8 = 0x80;

/// Long Packet Type bits, zero for an Initial in QUIC v1 (RFC 9000 §17.2.2).
const LONG_PACKET_TYPE: u8 = 0x30;

/// The smallest UDP payload a server judges an Initial in (RFC 9000 §14.1).
const MIN_INITIAL_DATAGRAM: usize = 1200;

/// The shortest Destination Connection ID a client's first Initial may carry
/// (RFC 9000 §7.2).
const MIN_CLIENT_CONNECTION_ID: usize = 8;

/// The TLS `client_hello` handshake message type (RFC 8446 §4).
const CLIENT_HELLO: u8 = 1;

/// The lists a datagram may be judged against, chosen by the mode byte.
///
/// `localhost` is the name the seed corpus asks for, so the first two hold it
/// and the third does not: under the third, every seed that names a host is a
/// refusal for its name. An empty list is not here, because an empty list is
/// the gate switched off and `poll_recv` never calls the judgement path at all.
/// Spelling variants (case, a root dot) are not here either: `Names::new`
/// normalises them once at load, and that is unit-tested where it lives.
const NAMES: [&[&str]; 3] = [
    &["localhost"],
    &["localhost", "other.example"],
    &["other.example"],
];

/// [`NAMES`], built once rather than on every iteration.
static LISTS: LazyLock<[Names; 3]> = LazyLock::new(|| {
    NAMES.map(|list| {
        let configured: Vec<String> = list.iter().map(|name| (*name).to_owned()).collect();
        Names::new(&configured)
    })
});

/// Longest a refused name may print as, which `logfmt::bounded_bytes` caps.
///
/// The same bound `fuzz_targets/auth.rs` asserts: a peer-chosen token reaches
/// a log line through `escaped_bytes`, and a `server_name` may be 65535 bytes
/// long.
const MAX_BOUNDED: usize = 256;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };

    if mode & 1 == 1 {
        read_a_first_flight(rest);
        return;
    }

    judge_a_datagram(rest, &LISTS[usize::from(mode >> 1) % LISTS.len()]);
});

/// Every datagram whose verdict the gate's own documentation states.
fn judge_a_datagram(datagram: &[u8], names: &Names) {
    // A verdict is a function of the bytes and the list, and of nothing else:
    // the gate keeps no state between datagrams. Judged once here — the seed
    // corpus test judges each seed twice, which pins that without paying two
    // decryptions per fuzz iteration.
    let verdict = gate::judgement(datagram, names);

    let long_header = datagram
        .first()
        .is_some_and(|first| first & LONG_HEADER_FORM != 0);
    let initial = datagram
        .first()
        .is_some_and(|first| first & LONG_PACKET_TYPE == 0);
    let version = datagram
        .get(1..5)
        .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));

    // The shapes the module documentation promises to pass. Everything here is
    // a packet quinn drops without a word, so refusing one would be the gate
    // costing a legitimate peer something for nothing.
    let passes = !long_header
        || version.is_none()
        || (version == Some(1) && !initial)
        || (version == Some(1) && initial && datagram.len() < MIN_INITIAL_DATAGRAM);
    if passes {
        assert_eq!(
            verdict,
            Verdict::Pass,
            "a datagram quinn answers nothing to must pass"
        );
    }

    // The one shape the gate refuses on the header alone, and the departure from
    // RFC 9000 §5.2.2 that D106 is about: a Version Negotiation packet is a
    // reply, and a reply is what a scan came for.
    if let Some(named) = version
        && long_header
        && named != 1
    {
        assert_eq!(
            verdict,
            Verdict::Refuse(Refusal::Version(named)),
            "a long header naming another version must draw nothing"
        );
    }

    match &verdict {
        Verdict::Pass => {}
        // The one refusal that is decided on the header alone.
        Verdict::Refuse(Refusal::Version(refused)) => {
            assert_eq!(Some(*refused), version, "the version that was refused");
            assert_ne!(*refused, 1, "version 1 is the one we speak");
        }
        // The four that are decided behind the packet protection, which is only
        // reachable by opening the packet: the gate must have had a v1 Initial,
        // in a datagram large enough for a server to look at, to get here at
        // all.
        Verdict::Refuse(refusal) => {
            assert!(
                long_header
                    && initial
                    && version == Some(1)
                    && datagram.len() >= MIN_INITIAL_DATAGRAM,
                "{refusal:?} on a datagram that carries no Initial packet"
            );
            match refusal {
                Refusal::OtherName(name) => {
                    assert!(name.len() < MAX_BOUNDED, "an unbounded name reached a log");
                }
                // The one refusal decided on the header behind the protection:
                // the length it names is the length byte the datagram carries,
                // and it is under the floor RFC 9000 §7.2 sets.
                Refusal::ShortConnectionId(length) => {
                    assert_eq!(
                        Some(*length),
                        datagram.get(5).map(|byte| usize::from(*byte)),
                        "a refused length that is not the one in the header"
                    );
                    assert!(
                        *length < MIN_CLIENT_CONNECTION_ID,
                        "a connection ID a client may choose was refused for its length"
                    );
                }
                _ => {}
            }
        }
    }

    refusing_needs_the_keys_this_datagram_carries(datagram, names, &verdict);
}

/// The v0.9.1 rule: only a packet the gate could open may be refused for what
/// was behind its packet protection — the ClientHello, or the connection ID
/// length that opening the packet turns into a statement about a first flight.
///
/// The keys are derived from the Destination Connection ID in the datagram
/// itself, so changing that field must turn any such refusal into a pass — a
/// packet keyed by something the gate cannot see is exactly the shape of every
/// client Initial after the server has answered (RFC 9000 §7.2, RFC 9001 §5.2),
/// and refusing those cost every admitted handshake a probe timeout in v0.9.0.
fn refusing_needs_the_keys_this_datagram_carries(
    datagram: &[u8],
    names: &Names,
    verdict: &Verdict,
) {
    let refused_by_what_was_opened = matches!(
        verdict,
        Verdict::Refuse(
            Refusal::ShortConnectionId(_)
                | Refusal::NotClientHello
                | Refusal::Anonymous
                | Refusal::OtherName(_)
        )
    );
    if !refused_by_what_was_opened {
        return;
    }

    // Reachable only through a header the gate parsed, so the length byte and a
    // first byte of the connection ID are both there.
    let dcid_length = usize::from(datagram[5]);
    if dcid_length == 0 {
        return;
    }

    let mut rotated = datagram.to_vec();
    rotated[6] ^= 0x01;
    assert_eq!(
        gate::judgement(&rotated, names),
        Verdict::Pass,
        "a datagram whose keys the gate cannot derive was refused"
    );
}

/// The hand-written TLS reader, on bytes that never had to be a ClientHello.
fn read_a_first_flight(crypto: &[u8]) {
    let read = gate::first_flight(crypto);
    assert_eq!(
        gate::first_flight(crypto),
        read,
        "the same CRYPTO bytes read twice"
    );

    match crypto.first() {
        None => assert_eq!(
            read,
            FirstFlight::Truncated,
            "nothing at all is not a message"
        ),
        Some(&kind) if kind != CLIENT_HELLO => assert_eq!(
            read,
            FirstFlight::NotAClientHello,
            "a first handshake message of type {kind}"
        ),
        Some(_) => {}
    }

    if let FirstFlight::Named(name) = &read {
        // The name is read out of the message rather than composed: the type
        // byte and the three length bytes are in front of it at the very least.
        assert!(
            name.len() + 4 <= crypto.len(),
            "a name longer than the bytes it came from"
        );
    }

    fail_open_before_the_message_is_whole(crypto, &read);
}

/// The fail-open rule, judged against a length read here rather than there.
///
/// A ClientHello may be spread over several Initial packets, and the gate is
/// only allowed to name a flight it has all of: every cut before the declared
/// end of the message must read as [`FirstFlight::Truncated`], and no cut at or
/// after it may. This reads the 24-bit length itself so that the oracle is not
/// the code under test.
fn fail_open_before_the_message_is_whole(crypto: &[u8], read: &FirstFlight) {
    if crypto.first() != Some(&CLIENT_HELLO) {
        return;
    }
    let Some(header) = crypto.get(1..4) else {
        assert_eq!(*read, FirstFlight::Truncated, "no length, no message");
        return;
    };
    let declared =
        (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
    let end = declared + 4;

    if crypto.len() < end {
        assert_eq!(
            *read,
            FirstFlight::Truncated,
            "a ClientHello of {declared} bytes with {} present must fail open",
            crypto.len().saturating_sub(4)
        );
        return;
    }

    assert_ne!(
        *read,
        FirstFlight::Truncated,
        "a whole ClientHello was read as an unfinished one"
    );

    // Any strict prefix of the message is unfinished, whatever field the cut
    // lands in. A handful rather than all of them: this runs on every input.
    for cut in [4, end / 2, end - 1] {
        if cut >= end {
            continue;
        }
        assert_eq!(
            gate::first_flight(&crypto[..cut]),
            FirstFlight::Truncated,
            "a ClientHello cut at {cut} of {end} bytes must fail open"
        );
    }
}
