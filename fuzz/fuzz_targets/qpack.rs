//! Two modes on the field-section decoder, chosen by the first byte.
//!
//! Even inputs: arbitrary bytes through [`qpack::decode`] at fuzzer-chosen
//! section-size budgets, small ones included so the size-limit refusals get
//! exercised, not just the parse errors.
//!
//! Odd inputs: a round trip. The remaining bytes are cut into name/value
//! pairs, encoded with [`qpack::encode`] and decoded back; the result must be
//! the same fields in the same order. The encoder never sets the Huffman bit
//! and matches the static table byte-exactly, so equality is exact.

#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use volto::h3::qpack;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };

    if mode & 1 == 0 {
        let budget = if mode & 2 == 0 {
            // Tiny budgets: every field risks overshooting.
            u64::from(mode >> 2) * 8
        } else {
            volto::h3::MAX_FIELD_SECTION_SIZE
        };
        let _ = qpack::decode(rest, budget);
        return;
    }

    let mut fields: Vec<(&[u8], &[u8])> = Vec::new();
    let mut cursor = rest;
    while fields.len() < 64 {
        let Some((&name_len, tail)) = cursor.split_first() else {
            break;
        };
        let Some((&value_len, tail)) = tail.split_first() else {
            break;
        };
        let name_len = usize::from(name_len % 24) + 1;
        let value_len = usize::from(value_len % 48);
        let Some(name) = tail.get(..name_len) else {
            break;
        };
        let Some(value) = tail.get(name_len..name_len + value_len) else {
            break;
        };
        fields.push((name, value));
        cursor = &tail[name_len + value_len..];
    }

    let mut block = BytesMut::new();
    qpack::encode(&mut block, fields.iter().copied());
    let decoded = qpack::decode(&block, u64::MAX).expect("round trip must decode");
    assert_eq!(decoded.len(), fields.len(), "field count survives the trip");
    for (field, (name, value)) in decoded.iter().zip(&fields) {
        assert_eq!(field.name.as_ref(), *name, "name survives the trip");
        assert_eq!(field.value.as_ref(), *value, "value survives the trip");
    }
});
