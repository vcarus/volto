//! The gate's entry points for the fuzz targets and the tests (D83).
//!
//! Every item here exists for `fuzz/` and `tests/`. Each is public and hidden,
//! and the gate re-exports it, so its path stays `volto::gate::<name>`. Each
//! judging seam calls the functions the socket path calls, the server's
//! Initial key code included.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::udp::RecvMeta;

use super::initial::{INITIAL_PACKET_TYPE, LONG_HEADER_FORM, QUIC_V1};
use super::{
    Classified, Dropped, MIN_INITIAL_DATAGRAM, Memory, Names, Policy, Screened, Verdict, classify,
    flight_fragments, follow, judge, screen_one,
};
use crate::tls::{EchKey, EchKeySet};

/// What a first flight's CRYPTO bytes said, and the reader that says it.
///
/// Both live in [`crate::hello`], the one ClientHello parser the gate, the TLS
/// provider and the tests share. They are re-exported here, hidden and public,
/// for the fuzz target and `tests/it_gate_shapes.rs`, which hand CRYPTO bytes
/// to the reader directly, because the only other way to reach it is to spell
/// a whole Initial packet that authenticates, which a fuzzer cannot do by luck.
#[doc(hidden)]
pub use crate::hello::{FirstFlight, first_flight};

/// The hold's bounds, for the fuzz target and the tests that assert them.
#[doc(hidden)]
pub use super::hold::{
    HOLD_FLIGHT_BYTES, HOLD_FLIGHTS, HOLD_HELLO_BYTES, HOLD_LIFETIME, HOLD_TOTAL_BYTES,
    REPLAY_ENTRIES,
};

/// The gate's verdict on one datagram, for the fuzz target and the tests.
///
/// This is the `judge` that `screen_one` calls, Initial key code included.
/// The socket, the batch walk and the blinding are left out, and none of them
/// is a parser.
#[doc(hidden)]
pub fn judgement(datagram: &[u8], expected: &Names) -> Verdict {
    judge(datagram, expected)
}

/// The gate with the hold, driven one datagram at a time, for the fuzz target
/// and the tests.
///
/// It runs `screen_one`, the function the receive path calls for every
/// datagram, under a policy the caller gives and a clock the caller moves.
/// The socket, the batch walk, the blinding, the `any` flag and the delivery
/// into quinn's buffers are what is left out, so a policy that is off is
/// judged here as a names-only policy with an empty list.
#[doc(hidden)]
pub struct Screening {
    memory: Memory,
    epoch: Instant,
}

impl Screening {
    /// A gate under `policy` with an empty hold.
    pub fn new(policy: impl Into<Policy>) -> Self {
        Self {
            memory: Memory::new(Arc::new(policy.into())),
            epoch: Instant::now(),
        }
    }

    /// Screens `datagram` from `from`, received `after` the screening began.
    ///
    /// Returns what became of it and every flight the hold dropped on the
    /// way, with the address it came from. A policy without an ECH key is the
    /// stateless gate, as on the socket path.
    pub fn receive(
        &mut self,
        after: Duration,
        from: SocketAddr,
        datagram: &[u8],
    ) -> (Screened, Vec<(SocketAddr, Dropped)>) {
        let mut drops = Vec::new();
        let meta = RecvMeta {
            addr: from,
            len: datagram.len(),
            stride: datagram.len(),
            ..RecvMeta::default()
        };
        let screened = screen_one(
            &mut self.memory,
            &meta,
            datagram,
            &mut Some(self.epoch + after),
            &mut |from, why| drops.push((from, why)),
        );
        (screened, drops)
    }

    /// Takes the datagrams of admitted flights, in the order quinn would get
    /// them, with the address each came from.
    pub fn released(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        std::iter::from_fn(|| self.memory.hold.pop_released())
            .map(|held| (held.meta.addr, held.bytes))
            .collect()
    }

    /// How many flights are held.
    pub fn flights(&self) -> usize {
        self.memory.hold.flights()
    }

    /// Every byte the hold occupies, as its byte bound counts.
    pub fn held_bytes(&self) -> usize {
        self.memory.hold.bytes()
    }

    /// Every byte the hold occupies, summed from what it holds. Equal to
    /// [`Screening::held_bytes`] after every datagram, or the count has
    /// drifted.
    pub fn recounted_bytes(&self) -> usize {
        self.memory.hold.recount()
    }

    /// How many `enc` values the replay record holds.
    pub fn replay_entries(&self) -> usize {
        self.memory.replay.len()
    }

    /// Replaces the policy as a reload does, with the same effect on the
    /// replay record and the hold as [`Expected::set`](super::Expected::set).
    pub fn set(&mut self, policy: impl Into<Policy>) {
        follow(&mut self.memory, Arc::new(policy.into()));
    }
}

/// The CRYPTO frames the hold reads from `datagram`, as offsets and owned
/// bytes, or `None` when the gate would not hand it to the hold as an opened
/// first Initial whose frames all parse.
///
/// For the `hold` fuzz target: it reads a released flight's ClientHello again
/// from these, with a reassembly and a rule check of its own, to say whether
/// the hold should have admitted it.
#[doc(hidden)]
pub fn held_fragments(datagram: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let Classified::Opened { frames, more, .. } = classify(datagram, true) else {
        return None;
    };
    let fragments = flight_fragments(&frames, &more)?;
    Some(
        fragments
            .into_iter()
            .map(|(offset, bytes)| (offset, bytes.to_vec()))
            .collect(),
    )
}

/// The most frame bytes [`sealed_initial`] carries: what a two-byte Length
/// field leaves after the one-byte packet number and the AEAD tag.
#[doc(hidden)]
pub const SEALED_FRAMES_MAX: usize = 0x3fff - 1 - 16;

/// A first Initial carrying `frames`, sealed under the keys its own
/// Destination Connection ID `dcid` derives, for the fuzz target `hold` and
/// the test that writes its seeds.
///
/// The fuzz target cannot spell a packet that authenticates, so without this
/// it could change a held packet's bytes only by breaking its AEAD, and the
/// hold would never see frames the fuzzer chose. With it, the fuzzer chooses
/// the frames and this function seals them. The keys are the client's Initial
/// keys, from the server's own key code (`tls::client_initial_keys`). That
/// code is checked against RFC 9001 Appendix A in both directions, and
/// `tests/it_gate_shapes.rs` opens a packet sealed here with rustls's keys.
///
/// The header is the plainest a client sends: QUIC v1, no Source Connection
/// ID, no token, a two-byte Length field and a one-byte packet number
/// `number`. The frames are followed by PADDING up to a 1200-byte datagram,
/// and cut at [`SEALED_FRAMES_MAX`] bytes.
#[doc(hidden)]
pub fn sealed_initial(dcid: &[u8; 8], number: u8, frames: &[u8]) -> Vec<u8> {
    let keys = crate::tls::client_initial_keys(dcid);
    let tag = keys.packet.tag_len();
    let frames = &frames[..frames.len().min(SEALED_FRAMES_MAX)];

    let mut packet = vec![LONG_HEADER_FORM | 0x40 | INITIAL_PACKET_TYPE];
    packet.extend_from_slice(&QUIC_V1.to_be_bytes());
    packet.push(8);
    packet.extend_from_slice(dcid);
    packet.push(0); // no Source Connection ID
    packet.push(0); // no token
    let number_offset = packet.len() + 2;
    let payload = frames
        .len()
        .max(MIN_INITIAL_DATAGRAM - number_offset - 1 - tag);
    let length = u16::try_from(1 + payload + tag).expect("at most SEALED_FRAMES_MAX frame bytes");
    packet.extend_from_slice(&(0x4000 | length).to_be_bytes());
    packet.push(number);
    packet.extend_from_slice(frames);
    packet.resize(number_offset + 1 + payload, 0); // PADDING
    packet.resize(number_offset + 1 + payload + tag, 0); // room for the tag
    keys.packet
        .encrypt(u64::from(number), &mut packet, number_offset + 1);
    keys.header.encrypt(number_offset, &mut packet);
    packet
}

/// The ECH key of the `hold` fuzz target, built from fixed bytes so that the
/// seeds `tests/it_gate_shapes.rs` writes carry ECH that opens under it.
#[doc(hidden)]
pub fn hold_input_key() -> EchKey {
    EchKey::from_private_bytes(&[0x42; 32], "public.example", 7, 0).expect("the hold input key")
}

/// The previous ECH key of the `hold` fuzz target, which an input's policy
/// byte may put beside [`hold_input_key`]: other fixed bytes and config_id 8,
/// so the two keys differ in config_id as a server's two keys must.
#[doc(hidden)]
pub fn hold_input_previous_key() -> EchKey {
    EchKey::from_private_bytes(&[0x43; 32], "public.example", 8, 0)
        .expect("the hold input previous key")
}

/// The Destination Connection IDs a sealed record of a hold input may be
/// addressed to.
const HOLD_INPUT_DCIDS: [[u8; 8]; 4] = [[0xaa; 8], [0xa1; 8], [0xa2; 8], [0xa3; 8]];

/// The record header bit that makes a record's body frames to seal.
const HOLD_INPUT_SEALED: u8 = 0x04;

/// The policy one byte of a hold input selects, from the target's two fixed
/// keys.
///
/// Bit 0 is `require_ech`. Bit 1 puts `localhost` on the name list. Bit 2 puts
/// a previous key beside the current one. Bit 3 swaps the two keys' places, so
/// the key that was the previous one is the current one, which is what a
/// rotation does. Bit 4 leaves the server with no ECH key at all, which turns
/// the hold off.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldPolicy {
    /// Bit 0.
    pub require_ech: bool,
    /// `localhost` when bit 1 is set, else empty.
    pub names: Vec<String>,
    previous: bool,
    swapped: bool,
    keyless: bool,
}

impl HoldPolicy {
    fn from_byte(byte: u8) -> Self {
        let names = if byte & 0x02 != 0 {
            vec!["localhost".to_owned()]
        } else {
            Vec::new()
        };
        Self {
            require_ech: byte & 0x01 != 0,
            names,
            previous: byte & 0x04 != 0,
            swapped: byte & 0x08 != 0,
            keyless: byte & 0x10 != 0,
        }
    }

    /// The keys this policy holds, the current one first: none, one or both
    /// of `key` and `previous`, the target's two fixed keys.
    pub fn keys<'k>(
        &self,
        key: &'k Arc<EchKey>,
        previous: &'k Arc<EchKey>,
    ) -> Vec<&'k Arc<EchKey>> {
        if self.keyless {
            return Vec::new();
        }
        let (current, other) = if self.swapped {
            (previous, key)
        } else {
            (key, previous)
        };
        if self.previous {
            vec![current, other]
        } else {
            vec![current]
        }
    }

    /// The gate policy this is, with the keys [`HoldPolicy::keys`] gives.
    pub fn policy(&self, key: &Arc<EchKey>, previous: &Arc<EchKey>) -> Policy {
        let keys = match self.keys(key, previous)[..] {
            [] => None,
            [current] => Some(EchKeySet::new(current.clone())),
            [current, other, ..] => Some(
                EchKeySet::new(current.clone())
                    .with_previous(other.clone())
                    .expect("the two hold input keys have different config_ids"),
            ),
        };
        Policy::new(
            Names::new(&self.names),
            keys.map(Arc::new),
            self.require_ech,
        )
    }
}

/// One input of the `hold` fuzz target, read step by step.
///
/// This is the one reader of that format: the fuzz target and the test that
/// writes its seeds both call it, so a seed's outcome in the test is its
/// outcome in the target. The format is in the target's module
/// documentation, `fuzz/fuzz_targets/hold.rs`. Byte 0 is the policy the run
/// begins under; then each record is one header byte, a big-endian `u16`
/// length, and that many bytes of body, cut at the end of the input.
#[doc(hidden)]
pub struct HoldInput<'a> {
    /// The policy byte 0 selects.
    pub policy: HoldPolicy,
    rest: &'a [u8],
    after: Duration,
}

/// One step of a [`HoldInput`].
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldStep {
    /// A datagram for the gate to receive.
    Datagram(HoldRecord),
    /// A reload that puts this policy in force.
    Reload(HoldPolicy),
}

/// One datagram of a [`HoldInput`], as the gate is to receive it.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldRecord {
    /// The time since the input began, summed over every record so far.
    pub after: Duration,
    /// The source address the header's low two bits pick.
    pub from: SocketAddr,
    /// The datagram the body stands for.
    pub datagram: Vec<u8>,
}

impl<'a> HoldInput<'a> {
    /// Reads the policy byte of `data`, or `None` for an empty input.
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let (&policy, rest) = data.split_first()?;
        Some(Self {
            policy: HoldPolicy::from_byte(policy),
            rest,
            after: Duration::ZERO,
        })
    }
}

impl Iterator for HoldInput<'_> {
    type Item = HoldStep;

    fn next(&mut self) -> Option<HoldStep> {
        let [header, high, low, tail @ ..] = self.rest else {
            return None;
        };
        let header = *header;
        let length = usize::from(u16::from_be_bytes([*high, *low])).min(tail.len());
        let (body, next) = tail.split_at(length);
        self.rest = next;
        self.after += Duration::from_millis(100 * u64::from(header >> 3));
        let from = SocketAddr::from(([127, 0, 0, 1], 40_000 + u16::from(header & 0x03)));
        let datagram = if header & HOLD_INPUT_SEALED == 0 {
            // No datagram of one byte reaches the hold, so that length is the
            // reload record, and its byte is the new policy.
            if let [policy] = body {
                return Some(HoldStep::Reload(HoldPolicy::from_byte(*policy)));
            }
            body.to_vec()
        } else {
            let (selector, frames) = match body.split_first() {
                Some((selector, frames)) => (*selector, frames),
                None => (0, &[][..]),
            };
            sealed_initial(
                &HOLD_INPUT_DCIDS[usize::from(selector & 0x03)],
                selector >> 2,
                frames,
            )
        };
        Some(HoldStep::Datagram(HoldRecord {
            after: self.after,
            from,
            datagram,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seam the `hold` fuzz target rereads a released flight with gives
    /// the CRYPTO frames the hold is given, and nothing for a datagram the
    /// hold is not given or drops for its frames.
    #[test]
    fn held_fragments_are_the_crypto_frames_the_hold_reads() {
        let frames = [0x06, 0x05, 0x03, b'a', b'b', b'c', 0x01];
        let sealed = sealed_initial(&[0x52; 8], 0, &frames);
        assert_eq!(held_fragments(&sealed), Some(vec![(5, b"abc".to_vec())]));

        // A STREAM frame, which no Initial packet may carry.
        let stream = sealed_initial(&[0x52; 8], 0, &[0x08, 0x00, 0x00]);
        assert_eq!(held_fragments(&stream), None);
        // A datagram that does not open, and one too short to be judged.
        let mut forged = sealed.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0x01;
        assert_eq!(held_fragments(&forged), None);
        assert_eq!(held_fragments(&sealed[..1199]), None);
    }
}
