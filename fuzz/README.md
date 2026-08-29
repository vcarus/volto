# Fuzzing

Coverage-guided fuzz targets (libFuzzer via `cargo fuzz`) for every hand-written parser that reads bytes a peer chose. They complement the property tests in `tests/it_props.rs` / `tests/it_fuzz.rs`, which run on stable and stay the CI-side check; these targets need a nightly toolchain and are run on demand.

Each target does more than "does not crash": where an encoder exists, odd-numbered inputs drive an encode→decode round trip whose result must match, and even-numbered inputs feed arbitrary bytes through the incremental decoders at fuzzer-chosen chunk boundaries. cargo-fuzz builds with debug assertions on, so the decoders' internal `debug_assert!` contracts act as oracles too.

## The targets, and what each one is the only cover for

| Target | Parser | Where the bytes come from |
| --- | --- | --- |
| `frame` | `h3::frame` — the RFC 9114 §7 frame state machine, including the SETTINGS payload on a control stream | any QUIC stream |
| `qpack` | `h3::qpack` — field sections against the static table, and the RFC 7541 prefixed integers and string literals under them | a HEADERS frame |
| `huffman` | `h3::huffman` — RFC 7541 Appendix B decoding | a Huffman-coded QPACK string literal |
| `capsule` | `capsule` — the RFC 9297 §3 incremental capsule stream | the body of a CONNECT-UDP stream |
| `datagram` | `datagram` — Quarter Stream ID and Context ID varints (RFC 9297 §2.1) | a QUIC datagram |
| `request` | `h3::stream::build_request` and the `h3::message` syntax rules under it — RFC 9114 §4.1.2's malformed verdict | a decoded field section |
| `authority` | `tunnel::tcp::split_authority` and `tunnel::udp::parse_target` — the two routes a client names a target by | `:authority`, or the RFC 9298 §2 URI template in `:path` |
| `auth` | `auth` — the RFC 7617 scheme split, the base64 decoder it owns, the user-id/password split, and the `logfmt` bound on what reaches the journal | `Proxy-Authorization` / `Authorization`, from a peer that has not authenticated |

Two parsers on attacker bytes are deliberately not here, because neither can be reached without a live QUIC connection and neither has a panic surface to reach: `h3::connection::serve_qpack`, whose whole state is a bounded counter over the peer's QPACK streams (`it_critical_streams.rs` drives it), and `h3::connection::read_stream_type`, whose read length is `1 << (byte >> 6)` into an 8-byte buffer.

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

Swap `frame` for any of the names in the table above; `cargo +nightly fuzz list` enumerates them. The corpus accumulates under `fuzz/corpus/<target>/` on the host and is deliberately not committed; crash inputs land in `fuzz/artifacts/<target>/`.
