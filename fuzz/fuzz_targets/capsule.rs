//! Two modes on the RFC 9297 capsule decoder, chosen by the first byte.
//!
//! Even inputs: arbitrary bytes pushed in varying chunks; an error ends the
//! stream, exactly as `tunnel/udp.rs` treats it.
//!
//! Odd inputs: a round trip. A context id and payload are cut from the input,
//! encoded with [`capsule::encode_datagram`], pushed in two arbitrary halves,
//! and the decoder must yield that one capsule and sit at a boundary after.

#![no_main]

use libfuzzer_sys::fuzz_target;
use volto::capsule::{self, Capsule, CapsuleDecoder};
use volto::datagram::VARINT_MAX;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };

    if mode & 1 == 0 {
        let mut decoder = CapsuleDecoder::new();
        let mut chunk_len = 1 + usize::from(mode) % 16;
        let mut input = rest;
        while !input.is_empty() {
            let take = chunk_len.min(input.len());
            let (chunk, tail) = input.split_at(take);
            input = tail;
            chunk_len = (chunk_len % 16) + 1;

            decoder.push(chunk);
            loop {
                match decoder.next_capsule() {
                    Ok(Some(Capsule::Datagram { .. })) => continue,
                    Ok(None) => break,
                    Err(_) => return,
                }
            }
            let _ = decoder.at_capsule_boundary();
        }
        return;
    }

    let Some(id_bytes) = rest.get(..8) else {
        return;
    };
    let context_id = u64::from_le_bytes(id_bytes.try_into().unwrap()) % (VARINT_MAX + 1);
    let payload = &rest[8..];

    let encoded = capsule::encode_datagram(context_id, payload);
    let split = usize::from(mode >> 1) % (encoded.len() + 1);

    let mut decoder = CapsuleDecoder::new();
    decoder.push(&encoded[..split]);
    // Feeding half a capsule must never error, only ask for more.
    if let Ok(Some(_)) = decoder.next_capsule() {
        // A capsule already? Only possible when the split covered the whole
        // encoding; fall through and let the boundary check below judge it.
        assert_eq!(split, encoded.len(), "a capsule appeared before its bytes");
        assert!(decoder.at_capsule_boundary());
        return;
    }
    decoder.push(&encoded[split..]);
    match decoder.next_capsule() {
        Ok(Some(Capsule::Datagram {
            context_id: decoded_id,
            payload: decoded_payload,
        })) => {
            assert_eq!(decoded_id, context_id, "context id survives the trip");
            assert_eq!(&decoded_payload[..], payload, "payload survives the trip");
        }
        other => panic!("round trip must yield the capsule, got {other:?}"),
    }
    assert!(matches!(decoder.next_capsule(), Ok(None)));
    assert!(decoder.at_capsule_boundary(), "nothing may be left over");
});
