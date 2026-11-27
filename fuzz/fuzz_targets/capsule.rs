//! Two modes on the RFC 9297 capsule decoder, chosen by the first byte.
//!
//! Even inputs: arbitrary bytes pushed in varying chunks; an error ends the
//! stream, exactly as `tunnel/udp.rs` treats it.
//!
//! Odd inputs: a round trip. A context id and payload are cut from the input,
//! encoded with [`capsule::encode_datagram`], pushed in two arbitrary halves,
//! and the decoder must yield that one capsule and sit at a boundary after.

#![no_main]

use std::assert_matches;
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use volto::capsule::{self, Capsule, CapsuleDecoder, MAX_DATAGRAM_CAPSULE_VALUE};
use volto::datagram::{VARINT_MAX, varint_len};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };

    if mode & 1 == 0 {
        let mut decoder = CapsuleDecoder::new();
        let mut chunk_len = 1 + usize::from(mode) % 16;
        // One copy of the input, sliced per chunk, as the frame target does.
        let all = Bytes::copy_from_slice(rest);
        let mut offset = 0;
        while offset < all.len() {
            let take = chunk_len.min(all.len() - offset);
            let chunk = all.slice(offset..offset + take);
            offset += take;
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
    // A value past the decoder's bound is refused by design, so it is no round
    // trip to check.
    if u64::try_from(varint_len(context_id) + payload.len()).unwrap() > MAX_DATAGRAM_CAPSULE_VALUE {
        return;
    }

    let encoded = capsule::encode_datagram(context_id, payload);
    let split = usize::from(mode >> 1) % (encoded.len() + 1);

    let mut decoder = CapsuleDecoder::new();
    decoder.push(encoded.slice(..split));
    // Feeding half a capsule must never error, only ask for more.
    match decoder.next_capsule() {
        Ok(None) => {}
        // A capsule already? Only possible when the split covered the whole
        // encoding, and then nothing may be left over.
        Ok(Some(_)) => {
            assert_eq!(split, encoded.len(), "a capsule appeared before its bytes");
            assert!(decoder.at_capsule_boundary());
            return;
        }
        Err(error) => panic!("{split} of {} bytes failed: {error:?}", encoded.len()),
    }
    decoder.push(encoded.slice(split..));
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
    assert_matches!(decoder.next_capsule(), Ok(None));
    assert!(decoder.at_capsule_boundary(), "nothing may be left over");
});
