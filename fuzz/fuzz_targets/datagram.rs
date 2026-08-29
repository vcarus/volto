//! Two modes on the HTTP/3 datagram codec, chosen by the first byte.
//!
//! Even inputs: arbitrary bytes through [`datagram::decode`]. A successful
//! decode is re-encoded and decoded again, and the two decodes must agree —
//! the wire form may shorten (varints have non-canonical spellings) but the
//! meaning must not move. [`datagram::peek_varint`] and
//! [`datagram::take_varint`] must also agree with each other on the raw bytes.
//!
//! Odd inputs: a structured round trip through [`datagram::encode`], with
//! [`datagram::encoded_len`] checked against the bytes actually produced.

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use volto::datagram::{self, MAX_QUARTER_STREAM_ID, VARINT_MAX};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };

    if mode & 1 == 0 {
        match (datagram::peek_varint(rest), {
            let mut buf = Bytes::copy_from_slice(rest);
            datagram::take_varint(&mut buf).map(|value| (value, rest.len() - buf.len()))
        }) {
            (Some(peeked), Some(taken)) => assert_eq!(peeked, taken, "peek and take agree"),
            (None, None) => {}
            (peeked, taken) => panic!("peek said {peeked:?} but take said {taken:?}"),
        }

        let Ok(first) = datagram::decode(Bytes::copy_from_slice(rest)) else {
            return;
        };
        let reencoded = datagram::encode(first.quarter_stream_id, first.context_id, &first.payload);
        let second = datagram::decode(reencoded).expect("re-encoding must decode");
        assert_eq!(second, first, "meaning must not move across a re-encode");
        return;
    }

    let Some(id_bytes) = rest.get(..16) else {
        return;
    };
    let quarter_stream_id =
        u64::from_le_bytes(id_bytes[..8].try_into().unwrap()) % (MAX_QUARTER_STREAM_ID + 1);
    let context_id = u64::from_le_bytes(id_bytes[8..].try_into().unwrap()) % (VARINT_MAX + 1);
    let payload = &rest[16..];

    let encoded = datagram::encode(quarter_stream_id, context_id, payload);
    assert_eq!(
        encoded.len(),
        datagram::encoded_len(quarter_stream_id, context_id, payload.len()),
        "encoded_len must account for every byte"
    );
    let decoded = datagram::decode(encoded).expect("round trip must decode");
    assert_eq!(decoded.quarter_stream_id, quarter_stream_id);
    assert_eq!(decoded.context_id, context_id);
    assert_eq!(&decoded.payload[..], payload);
});
