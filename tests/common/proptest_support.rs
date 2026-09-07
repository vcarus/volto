//! Generators and knobs shared by the property-test binaries.
//!
//! `it_props`, `it_fuzz` and `it_frameseq` each drive `proptest` at a different
//! subject, and each wrote out the same case-count policy and the same
//! length-plus-seed payload generator to do it. Those are here.
//!
//! Reached with `#[path = "common/proptest_support.rs"] mod props;` rather than
//! declared inside `common`: `tests/common/mod.rs` does not name this file, so
//! `mod common;` does not compile it and no other test binary links `proptest`
//! on its account. That was the objection recorded at `it_fuzz`'s copy of
//! [`config`] — "`tests/common` is compiled into every integration binary" —
//! and it is an objection to `mod common;`, not to sharing, which is the same
//! distinction D66's QR5 turned on.
//!
//! What is deliberately *not* here: `it_props`'s and `it_fuzz`'s `any_varint`,
//! which differ by two entries in their boundary lists, and `it_frameseq`'s
//! `pattern`, which is a different fill from the other two. Sharing any of
//! those would change what a binary generates rather than only where the code
//! lives.

#![allow(dead_code)]
// Each property-test binary uses a subset of this.

// The package-wide default is `deny` (`Cargo.toml`); this file argues for its
// allow: the generated inputs have the lengths this module chose for them.
#![allow(clippy::as_conversions)]

use bytes::{BufMut, BytesMut};
use proptest::prelude::*;

/// A configuration with `cases` defaulted per property but still overridable.
///
/// `ProptestConfig::default()` already reads `PROPTEST_CASES`; setting the
/// field unconditionally would override the environment, so the default is
/// applied only when the variable is absent. That keeps the committed suite
/// cheap and the 100k "fuzz" run one variable away.
pub fn config(default_cases: u32) -> ProptestConfig {
    let mut config = ProptestConfig::default();
    if std::env::var_os("PROPTEST_CASES").is_none() {
        config.cases = default_cases;
    }
    config
}

/// A deterministic byte string of `length` bytes, filled from `seed`.
///
/// Generating N individual `u8` strategies costs more to shrink than it buys: a
/// length plus a seed still catches a misaligned copy, and shrinks in one
/// dimension instead of N.
pub fn pattern(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| seed ^ (index as u8).wrapping_mul(31))
        .collect()
}

/// A payload described by its length and a seed, rather than byte by byte.
pub fn payload(max: usize) -> impl Strategy<Value = Vec<u8>> {
    (0usize..=max, any::<u8>()).prop_map(|(length, seed)| pattern(length, seed))
}

/// The boundaries a run of `cuts` divides `len` bytes into, in order.
///
/// Each cut is folded into `0..=len`, both ends are added, and the result is
/// sorted and deduplicated, so consecutive offsets are a chunking of the whole
/// input with no empty piece between two equal cuts. Always at least `[0, len]`,
/// or `[0]` for an empty input.
///
/// The slicing is left with the caller on purpose: `it_fuzz` copies out of a
/// `&[u8]` into `Vec<u8>` and `it_props` takes `Bytes::slice` of a `Bytes`,
/// which is a zero-copy view, and neither wants the other's.
pub fn cut_offsets(len: usize, cuts: &[u16]) -> Vec<usize> {
    let mut offsets: Vec<usize> = cuts
        .iter()
        .map(|cut| usize::from(*cut) % (len + 1))
        .collect();
    offsets.push(0);
    offsets.push(len);
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

/// Writes `value` as a varint of exactly `length` bytes (RFC 9000 §16).
///
/// `length` must be able to hold `value`; the caller chooses it, which is the
/// point — RFC 9000 §16 explicitly permits an encoding longer than the
/// shortest, and `datagram::put_varint`, which only ever emits the shortest,
/// cannot produce one.
pub fn put_varint_in(buf: &mut BytesMut, value: u64, length: usize) {
    match length {
        1 => buf.put_u8(value as u8),
        2 => buf.put_u16(0x4000 | value as u16),
        4 => buf.put_u32(0x8000_0000 | value as u32),
        _ => buf.put_u64(0xc000_0000_0000_0000 | value),
    }
}
