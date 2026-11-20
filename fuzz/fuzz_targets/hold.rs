//! The hold of the D115 gate: first flights held until their ClientHello is
//! whole, then judged with an ECH key.
//!
//! This is the state the gate keeps for datagrams nobody has authenticated:
//! the reassembly of a CRYPTO stream across Initial packets, the expiry and
//! eviction of flights, the HPKE check, and the replay record. The input is a
//! policy byte and then a run of datagrams, each with the address it came from
//! and how much time passed before it, driven through [`gate::Screening`],
//! which runs the receive path's own code under a clock this target moves.
//!
//! Byte 0: bit 0 is `require_ech`, bit 1 puts `localhost` on the name list.
//! Then records of one header byte, a big-endian `u16` length, and that many
//! bytes of datagram. The header's low two bits pick one of four source
//! addresses; the other six are the time that passed before it, in steps of
//! 50 ms, so a run can outlast `HOLD_LIFETIME`.
//!
//! Oracles beyond "no panic": the table, the byte total and the replay record
//! never exceed their bounds; the replay record never holds more entries than
//! flights were admitted; a datagram passed or refused gets the verdict the
//! stateless gate gives it; and every datagram released is one that was held,
//! from the address it came from, byte for byte.
//!
//! The ECH key is fixed (`FUZZ_KEY`), and the seeds written by a test in
//! `tests/it_gate_shapes.rs` carry ECH that opens under it, which a fuzzer
//! could not produce by luck.

#![no_main]

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use volto::gate::{
    self, HOLD_FLIGHTS, HOLD_TOTAL_BYTES, Names, Policy, REPLAY_ENTRIES, Screened, Screening,
    Verdict,
};
use volto::tls::EchKey;

/// The X25519 private key of the target's ECH key. The seed test in
/// `tests/it_gate_shapes.rs` builds the same key from the same bytes.
const FUZZ_KEY: [u8; 32] = [0x42; 32];

/// The key, built once.
static KEY: LazyLock<Arc<EchKey>> = LazyLock::new(|| {
    Arc::new(EchKey::from_private_bytes(&FUZZ_KEY, "public.example", 7, 0).expect("the fuzz key"))
});

/// The four source addresses a record may come from.
fn source(index: u8) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 40_000 + u16::from(index & 0x03)))
}

fuzz_target!(|data: &[u8]| {
    let Some((&policy, mut rest)) = data.split_first() else {
        return;
    };
    let names: Vec<String> = if policy & 0x02 != 0 {
        vec!["localhost".to_owned()]
    } else {
        Vec::new()
    };
    let list = Names::new(&names);
    let mut screening = Screening::new(Policy::new(
        Names::new(&names),
        Some(KEY.clone()),
        policy & 0x01 != 0,
    ));

    let mut after = Duration::ZERO;
    let mut held: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
    let mut admitted = 0usize;
    while let [header, high, low, tail @ ..] = rest {
        let length = usize::from(u16::from_be_bytes([*high, *low])).min(tail.len());
        let (datagram, next) = tail.split_at(length);
        rest = next;
        after += Duration::from_millis(50 * u64::from(header >> 2));
        let from = source(*header);

        let (screened, _drops) = screening.receive(after, from, datagram);
        match &screened {
            Screened::Passed => assert_eq!(gate::judgement(datagram, &list), Verdict::Pass),
            Screened::Refused(refusal) => assert_eq!(
                gate::judgement(datagram, &list),
                Verdict::Refuse(refusal.clone())
            ),
            Screened::Held | Screened::Released => held.push((from, datagram.to_vec())),
            Screened::Dropped => {}
        }
        if screened == Screened::Released {
            admitted += 1;
        }

        for released in screening.released() {
            let Some(at) = held.iter().position(|entry| *entry == released) else {
                panic!("a released datagram was never held from that address");
            };
            held.swap_remove(at);
        }

        assert!(screening.flights() <= HOLD_FLIGHTS, "the table bound");
        assert!(screening.held_bytes() <= HOLD_TOTAL_BYTES, "the byte bound");
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
