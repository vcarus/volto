//! Arbitrary bytes through the RFC 7541 Huffman decoder. The decoder is pure,
//! so the only oracles are "no panic" and "no runaway allocation" — both of
//! which libFuzzer's sanitizer and RSS limit check for free.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = volto::h3::huffman::decode(data);
});
