//! The hold of the D115 gate: first flights held until their ClientHello is
//! whole, then judged with an ECH key.
//!
//! This is the state the gate keeps for datagrams nobody has authenticated:
//! the reassembly of a CRYPTO stream across Initial packets, the expiry and
//! eviction of flights, the choice of key by config_id, the HPKE check, and
//! the replay record. The input is a
//! policy byte and then a run of records, each a datagram with the address it
//! came from and how much time passed before it, driven through
//! [`gate::Screening`], which runs the receive path's own code under a clock
//! this target moves.
//!
//! Byte 0 is a policy byte: bit 0 is `require_ech`, bit 1 puts `localhost` on
//! the name list, bit 2 puts the previous key beside the current one, as a
//! server holds it during a key rotation, bit 3 swaps the two keys' places,
//! as the rotation itself does, and bit 4 leaves the server with no ECH key.
//! Then records of one header byte, a big-endian `u16` length, and that many
//! bytes of body. The header's low two bits pick one of four source
//! addresses, bit 2 says how the body is read, and the top five bits are the
//! time that passed before it, in steps of 100 ms, so a run can outlast
//! `HOLD_LIFETIME`.
//!
//! With bit 2 clear the body is the datagram, as it arrived, with one
//! exception: a body of exactly one byte is a reload, and the byte is the
//! policy byte that is in force from then on. That is how the target reaches
//! what a reload does to the hold and the replay record: a flight held under
//! one set of keys and judged under another, a key removed and put back, and
//! the hold emptied when the last key goes. With bit 2 set
//! the body is frames: its first byte picks one of four Destination
//! Connection IDs (low two bits) and the packet number (the other six), and
//! the rest is sealed into a first Initial under the keys that connection ID
//! derives, by [`gate::sealed_initial`]. A mutation of a raw datagram's
//! ciphertext fails the AEAD and the hold never sees it, so the sealed records
//! are how the fuzzer chooses the frames the hold reads: overlapping and
//! disagreeing CRYPTO frames in one packet, empty ones at any offset, frame
//! types no Initial may carry, and ClientHellos it has edited.
//!
//! Oracles beyond "no panic": the table, the byte total and the replay record
//! never exceed their bounds; the byte total, summed again from what the hold
//! holds, equals the running count after every record; the replay record
//! never holds more entries than flights were admitted, across every reload;
//! nothing is held after a reload that leaves no key; a datagram passed or
//! refused gets the verdict the stateless gate gives it; every datagram
//! released is one that was held, from the address it came from, byte for
//! byte; and every flight released is one the rule table admits. That last
//! one reads the flight's ClientHello again from the CRYPTO frames of its
//! released datagrams ([`gate::held_fragments`]), with a reassembly and a rule
//! check of its own: no two values at one offset, a whole ClientHello within
//! `HOLD_HELLO_BYTES`, and then an ECH extension the key opens, or none with
//! `require_ech` off and the name on the list when there is one, all under the
//! policy in force when the flight was released. The oracle
//! tries each of that policy's keys in turn, not the set's lookup by config_id,
//! so ECH under the previous key is admitted only when the policy byte holds
//! that key, and `EchKey::opens` refuses an extension that names another
//! key's config_id before it decrypts.
//!
//! The ECH keys are fixed: the current one ([`gate::hold_input_key`],
//! config_id 7) and the previous one ([`gate::hold_input_previous_key`],
//! config_id 8). The seeds written by a test in `tests/it_gate_shapes.rs`
//! carry ECH that opens under either, in both record forms, which a fuzzer
//! could not produce by luck. The input is read
//! by [`gate::HoldInput`], the same reader that test runs each seed through,
//! so the two cannot read one input differently.

#![no_main]

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use libfuzzer_sys::fuzz_target;
use volto::gate::{
    self, HOLD_FLIGHTS, HOLD_HELLO_BYTES, HOLD_TOTAL_BYTES, HoldInput, HoldStep, Names,
    REPLAY_ENTRIES, Screened, Screening, Verdict,
};
use volto::hello::{self, Ech};
use volto::tls::EchKey;

/// The current key, built once.
static KEY: LazyLock<Arc<EchKey>> = LazyLock::new(|| Arc::new(gate::hold_input_key()));

/// The previous key, built once.
static PREVIOUS: LazyLock<Arc<EchKey>> =
    LazyLock::new(|| Arc::new(gate::hold_input_previous_key()));

/// Checks that the flight whose released datagrams are `flight` is one the
/// rule table admits, reading its ClientHello again from their CRYPTO frames.
///
/// The reassembly here is a plain vector of optional bytes, not the hold's
/// stream and bitmap, and the rules are written out from the table in the
/// gate's module documentation rather than called, so the hold's own
/// judgement is not the oracle. The replay rule is not checked: a replay is a
/// drop, and this looks only at what was admitted.
fn admitted_by_the_rules(
    flight: &[(SocketAddr, Vec<u8>)],
    keys: &[&EchKey],
    require_ech: bool,
    names: &[String],
) {
    let mut stream: Vec<Option<u8>> = Vec::new();
    for (_, datagram) in flight {
        let fragments =
            gate::held_fragments(datagram).expect("a released datagram is one the hold read");
        for (offset, bytes) in fragments {
            if bytes.is_empty() {
                continue;
            }
            let start = usize::try_from(offset).expect("an offset the hold accepted");
            let end = start + bytes.len();
            assert!(
                end <= HOLD_HELLO_BYTES,
                "a released flight reaches past the limit"
            );
            if stream.len() < end {
                stream.resize(end, None);
            }
            for (slot, byte) in stream[start..end].iter_mut().zip(bytes) {
                assert!(
                    slot.is_none_or(|held| held == byte),
                    "a released flight carries two values at one offset"
                );
                *slot = Some(byte);
            }
        }
    }
    let contiguous: Vec<u8> = stream.iter().map_while(|byte| *byte).collect();
    let body =
        hello::client_hello_body(&contiguous).expect("a released flight holds a whole ClientHello");
    assert!(
        body.len() + 4 <= HOLD_HELLO_BYTES,
        "a released ClientHello past the limit"
    );
    match hello::ech(body) {
        Some(Ech::Outer(outer)) => assert!(
            keys.iter().any(|key| key.opens(body, &outer)),
            "a released ECH that none of the input's keys opens"
        ),
        Some(Ech::Absent) => {
            assert!(
                !require_ech,
                "a flight without ECH released under require_ech"
            );
            if !names.is_empty() {
                let name =
                    hello::server_name(body).expect("a released flight without ECH names a host");
                let text = std::str::from_utf8(name).expect("a released name is text");
                let relative = text.strip_suffix('.').unwrap_or(text);
                assert!(
                    names.iter().any(|held| held.eq_ignore_ascii_case(relative)),
                    "a released flight names {text:?}, off the list {names:?}"
                );
            }
        }
        other => panic!("a released flight whose ECH is {other:?}"),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(input) = HoldInput::new(data) else {
        return;
    };
    let mut policy = input.policy.clone();
    let mut list = Names::new(&policy.names);
    let mut screening = Screening::new(policy.policy(&KEY, &PREVIOUS));

    let mut held: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
    let mut admitted = 0usize;
    for step in input {
        let record = match step {
            HoldStep::Datagram(record) => record,
            HoldStep::Reload(new) => {
                screening.set(new.policy(&KEY, &PREVIOUS));
                policy = new;
                list = Names::new(&policy.names);
                if policy.keys(&KEY, &PREVIOUS).is_empty() {
                    assert_eq!(screening.flights(), 0, "no key, nothing held");
                }
                assert_eq!(
                    screening.recounted_bytes(),
                    screening.held_bytes(),
                    "the byte count after a reload"
                );
                assert!(
                    screening.replay_entries() <= admitted,
                    "a reload adds nothing to the replay record"
                );
                continue;
            }
        };
        let (after, from, datagram) = (record.after, record.from, record.datagram);

        let (screened, _drops) = screening.receive(after, from, &datagram);
        match &screened {
            Screened::Passed => assert_eq!(gate::judgement(&datagram, &list), Verdict::Pass),
            Screened::Refused(refusal) => assert_eq!(
                gate::judgement(&datagram, &list),
                Verdict::Refuse(refusal.clone())
            ),
            Screened::Held | Screened::Released => held.push((from, datagram.clone())),
            Screened::Dropped => {}
        }
        if screened == Screened::Released {
            admitted += 1;
        }

        assert_eq!(
            screening.recounted_bytes(),
            screening.held_bytes(),
            "the byte count is what the hold holds"
        );
        let released = screening.released();
        if screened == Screened::Released {
            let keys: Vec<&EchKey> = policy
                .keys(&KEY, &PREVIOUS)
                .into_iter()
                .map(|key| &**key)
                .collect();
            admitted_by_the_rules(&released, &keys, policy.require_ech, &policy.names);
        } else {
            assert!(
                released.is_empty(),
                "datagrams released by a record that released nothing"
            );
        }
        for released in released {
            let Some(at) = held.iter().position(|entry| *entry == released) else {
                panic!("a released datagram was never held from that address");
            };
            held.swap_remove(at);
        }

        assert!(screening.flights() <= HOLD_FLIGHTS, "the table bound");
        assert!(screening.held_bytes() <= HOLD_TOTAL_BYTES, "the byte bound");
        assert_eq!(
            screening.recounted_bytes(),
            screening.held_bytes(),
            "the byte count after the release"
        );
        assert!(
            screening.replay_entries() <= REPLAY_ENTRIES,
            "the replay bound"
        );
        assert!(
            screening.replay_entries() <= admitted,
            "only an admitted flight adds to the replay record"
        );
    }
});
