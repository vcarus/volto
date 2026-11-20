//! Coverage-guided companion to the proptest suite in `tests/it_fuzz.rs`: the
//! same [`FrameDecoder`] state machine, fed arbitrary bytes at arbitrary chunk
//! boundaries on a fuzzer-chosen [`StreamKind`].
//!
//! The harness respects the decoder's contract (`push` only once `next_item`
//! has returned `Ok(None)`, nothing after an error), so the `debug_assert!` in
//! `push`, enabled in cargo-fuzz builds, checks the decoder, not the harness.

#![no_main]

use std::sync::Arc;

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use volto::h3::frame::{BufferBudget, Frame, FrameDecoder, Item, StreamKind};

fuzz_target!(|data: &[u8]| {
    let Some((&control, rest)) = data.split_first() else {
        return;
    };
    // `ServerControl` is the kind an unauthenticated peer's control stream gets;
    // the decoder records its own SETTINGS, so no harness state is needed.
    let kind = match control % 4 {
        0 => StreamKind::Control,
        1 => StreamKind::Request,
        2 => StreamKind::Tunnel,
        _ => StreamKind::ServerControl,
    };
    // On a request stream, optionally narrow to tunnel rules after the first
    // HEADERS, the way `h3::stream::Stream::split` does once a CONNECT is
    // answered.
    let promote = kind == StreamKind::Request && control & 0x80 != 0;

    let budget = Arc::new(BufferBudget::default());
    let mut decoder = FrameDecoder::new(kind, budget);

    // One copy of the input, sliced per chunk: a `slice` is a refcount bump,
    // where a copy per chunk would allocate per 1..16 input bytes.
    let all = Bytes::copy_from_slice(rest);
    let mut chunk_len = 1 + (control as usize) % 16;
    let mut offset = 0;
    'stream: while offset < all.len() {
        let take = chunk_len.min(all.len() - offset);
        let chunk = all.slice(offset..offset + take);
        offset += take;
        // Vary the split points so frame headers and payloads straddle chunks.
        chunk_len = (chunk_len % 16) + 1;

        decoder.push(chunk);
        loop {
            match decoder.next_item() {
                Ok(Some(item)) => {
                    if promote {
                        if let Item::Frame(Frame::Headers(_)) = item {
                            decoder.connect_completed();
                        }
                    }
                }
                Ok(None) => break,
                // A violation ends the stream; the real reader stops here too.
                Err(_) => break 'stream,
            }
        }
        let _ = decoder.at_frame_boundary();
    }
});
