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

## What this workspace does not inherit

Being its own cargo workspace is what cargo-fuzz wants, and it also means nothing from the root manifest reaches here on its own. Four things are therefore restated in `Cargo.toml` beside this file, and each has to move when the root moves: the `[patch.crates-io]` pin on quinn-proto, so the targets fuzz the QUIC stack the server actually runs; `edition = "2024"`, so a target cannot keep an idiom `src/` has left behind; `rust-version`, which is a resolver floor rather than a support claim (edition 2024 implies the MSRV-aware resolver, and with the field absent that resolver floors on whatever toolchain is installed, which is how the two lockfiles drift apart); and `[lints.rust] unsafe_code = "deny"`, the root's policy for every target in the package. Only the first is asserted — `tests/it_release_assets.rs` fails if the two quinn-proto revisions differ — so the other three are on the reader, and the reason for each is written next to it.

`fuzz/Cargo.lock` is committed, and the `fuzz` job in `.github/workflows/ci.yml` type-checks the targets on stable with `--locked`. The graph the fuzzers run against is the one that was reviewed, then, rather than whatever resolves on the morning of the run — which is what makes a green CI check and a green container run weeks later statements about the same thing. Refresh it with `cargo generate-lockfile --manifest-path fuzz/Cargo.toml`, which rewrites this workspace's lockfile and not the root's; a bare `cargo update` at the root is never the move, for the reason the `[patch.crates-io]` comment in `../Cargo.toml` gives.

One entry in that lockfile is worth not re-litigating: `ring` is in it, and in the root's too, as a dependency quinn-proto declares for targets we do not build. `cargo tree -i ring --manifest-path fuzz/Cargo.toml` is empty on every platform this project ships, and the crate only appears under `--target all`. It is a lockfile row, not a second crypto backend, and D102's move to aws-lc-rs stands.

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

Swap `frame` for any of the names in the table above; `cargo +nightly fuzz list` enumerates the eight. The corpus accumulates under `fuzz/corpus/<target>/` on the host and is deliberately not committed; crash inputs land in `fuzz/artifacts/<target>/`.
