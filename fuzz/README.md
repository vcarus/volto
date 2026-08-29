# Fuzzing

Coverage-guided fuzz targets (libFuzzer via `cargo fuzz`) for the decoders that read untrusted bytes: the HTTP/3 frame state machine, the QPACK field-section decoder, the Huffman decoder, the RFC 9297 capsule decoder, and the HTTP/3 datagram codec. They complement the property tests in `tests/it_props.rs` / `tests/it_fuzz.rs`, which run on stable and stay the CI-side check; these targets need a nightly toolchain and are run on demand.

Each target does more than "does not crash": where an encoder exists, odd-numbered inputs drive an encode→decode round trip whose result must match, and even-numbered inputs feed arbitrary bytes through the incremental decoders at fuzzer-chosen chunk boundaries. cargo-fuzz builds with debug assertions on, so the decoders' internal `debug_assert!` contracts act as oracles too.

This crate is its own cargo workspace, so the root `[patch.crates-io]` pin is repeated in `Cargo.toml` here; keep the two in lockstep.

## Running

The dev host carries stable Rust only, so runs go through Docker (any Linux container with rustup works; the named volumes cache the nightly toolchain, the cargo-fuzz binary and the crate registry between runs):

```sh
docker run --rm -v "$(git rev-parse --show-toplevel)":/src -w /src \
  -v volto-fuzz-rustup:/usr/local/rustup -v volto-fuzz-cargo:/usr/local/cargo \
  rust:1 sh -c '
    rustup toolchain install nightly --profile minimal &&
    cargo +nightly install cargo-fuzz --locked &&
    cargo +nightly fuzz run frame -- -max_total_time=600 -rss_limit_mb=4096'
```

Swap `frame` for any of `qpack`, `huffman`, `capsule`, `datagram`; `cargo +nightly fuzz list` enumerates them. The corpus accumulates under `fuzz/corpus/<target>/` on the host and is deliberately not committed; crash inputs land in `fuzz/artifacts/<target>/`.
