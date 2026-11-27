# Fuzzing

Coverage-guided fuzz targets (libFuzzer via `cargo fuzz`) for every hand-written parser that reads bytes a peer chose. They complement the property tests in `tests/it_props.rs` / `tests/it_fuzz.rs`, which run on stable in every CI run. These targets need a nightly toolchain. `.github/workflows/fuzz.yml` runs each of them for ten minutes a day on a corpus it keeps in the Actions cache, and for one minute on a pull request that changes `fuzz/`; a longer run is started by hand, there with `workflow_dispatch` or locally as below. The log of a run is public, so for `gate`, `hold` and `tls`, which cover code that runs before authentication, the workflow neither prints nor uploads a failing input: `withhold-input.awk` keeps the panic location and the stack trace and drops the panic message and everything libFuzzer and cargo-fuzz print after the failure. Such a finding is reproduced locally from the stack trace in the log.

Each target does more than "does not crash": where an encoder exists, odd-numbered inputs drive an encode→decode round trip whose result must match, and even-numbered inputs feed arbitrary bytes through the incremental decoders at fuzzer-chosen chunk boundaries. cargo-fuzz builds with debug assertions on, so the decoders' internal `debug_assert!` contracts act as oracles too.

## The targets, and what each one is the only cover for

| Target | Parser | Where the bytes come from |
| --- | --- | --- |
| `frame` | `h3::frame` — the RFC 9114 §7 frame state machine, including the SETTINGS payload on a control stream | any QUIC stream |
| `qpack` | `h3::qpack` — field sections against the static table, and the RFC 7541 prefixed integers and string literals under them | a HEADERS frame |
| `huffman` | `h3::huffman` — RFC 7541 Appendix B decoding | a Huffman-coded QPACK string literal |
| `capsule` | `capsule` — the RFC 9297 §3 incremental capsule stream | the body of a CONNECT-UDP stream |
| `datagram` | `datagram` — Quarter Stream ID and Context ID varints (RFC 9297 §2.1) | a QUIC datagram |
| `request` | `h3::request::build_request` and the `h3::message` syntax rules under it — RFC 9114 §4.1.2's malformed verdict | a decoded field section |
| `authority` | `tunnel::tcp::split_authority` and `tunnel::udp::parse_target` — the two routes a client names a target by | `:authority`, or the RFC 9298 §2 URI template in `:path` |
| `auth` | `auth` — the RFC 7617 scheme split, the base64 decoder it owns, the user-id/password split, and the `logfmt` bound on what reaches the journal | `Proxy-Authorization` / `Authorization`, from a peer that has not authenticated |
| `gate` | `gate` — the D106 SNI gate: the QUIC v1 long header, the Initial packet protection under the keys the datagram's own Destination Connection ID derives, the frame walk that assembles the offset-0 CRYPTO stream, and the ClientHello reader that pulls `server_name` out of it | any UDP datagram that arrives at the port, judged before quinn sees it and before a handshake has begun |
| `tls` | `tls::awslc`, the server's TLS on AWS-LC's libssl (D115): the ClientHello parser, ECH decryption, the Handshake-level and post-handshake message readers, and this provider's own buffering around them | the CRYPTO stream of every Initial, from a peer that has not authenticated |
| `hold` | `gate`'s hold, the stateful half of the gate an ECH key turns on (D115): the reassembly of a CRYPTO stream across Initial packets, expiry and eviction of held flights, the outer ECH check under a fixed key, the replay record, and the release of held datagrams | every first Initial that arrives at the port while an ECH key is configured, held before quinn sees it |

`gate` is the odd one out twice over. Its input is a whole datagram rather than a fragment of a stream, and its interesting inputs cannot be guessed: reaching the ClientHello reader through a datagram means spelling an Initial packet that authenticates under keys derived from its own Destination Connection ID, which a fuzzer will not do by luck. So it has both a seed corpus and a second mode that hands CRYPTO bytes to the TLS reader directly. The seeds — a name we answer to, a name we do not, a ClientHello with no `server_name`, one cut short, and a second-flight Initial keyed by a packet the gate never saw — are built and written by a test in `tests/it_gate_shapes.rs` that also asserts the verdict each one was built for, so `cargo test` at the root is what regenerates `fuzz/corpus/gate/` and a verdict that moves is a red test rather than a corpus that quietly stops covering anything. Its oracles beyond "no panic": a verdict is a function of the datagram's bytes and the configured list alone, every shape the module documentation promises to pass does pass, a refusal that names a host implies a datagram that carried an Initial packet at all, and changing the Destination Connection ID of a datagram refused for what was behind its packet protection turns the refusal into a pass — which is the rule that only a packet the gate could open may be refused for what it carried.

`hold` drives a run of datagrams through `gate::Screening`, which is the receive path's own classification and hold under a clock the target moves. A record is either a datagram as it arrived or frames that the target seals into a first Initial with `gate::sealed_initial`, under the keys its connection ID derives. The second form exists because a mutation inside a sealed packet's ciphertext fails the AEAD, so without it the fuzzer could never choose the CRYPTO frames the hold reads. A third kind of record is a reload to another policy: with or without the previous key, with the two keys' places swapped as a rotation swaps them, or with no key. So a run covers what a reload does to held flights and to the replay record. Its seeds carry ECH that opens under the target's fixed key (`gate::hold_input_key`), in both forms, which a fuzzer cannot produce by luck; a test in `tests/it_gate_shapes.rs` builds them with rustls under that key and asserts what each one reaches, as the `gate` seeds are. The input is read by `gate::HoldInput`, which the target and that test both call, so the two read every input the same way. Its oracles beyond "no panic": the flight table, the byte total and the replay record stay within their bounds, the byte total summed again from what the hold holds equals the running count after every record, the replay record never holds more entries than flights were admitted, a datagram the hold passes or refuses gets the stateless gate's verdict, and every released datagram is one that was held, from its own address, byte for byte.

Two parsers on attacker bytes are deliberately not here, because neither can be reached without a live QUIC connection and neither has a panic surface to reach: `serve_qpack` in the private module `h3::control`, whose whole state is a bounded counter over the peer's QPACK streams (`it_critical_streams.rs` drives it), and `read_stream_type` in the same module, whose read length is `1 << (byte >> 6)` into an 8-byte buffer.

## What this workspace does not inherit

Being its own cargo workspace is what cargo-fuzz wants, and it also means nothing from the root manifest reaches here on its own. `edition`, `rust-version` and `[lints.rust] unsafe_code = "deny"` are restated in `Cargo.toml` beside this file, with the reason for each written next to it, and have to move when the root's move. Only `rust-version` is asserted: `tests/it_release_assets.rs` holds it equal to the root's.

`fuzz/Cargo.lock` is committed, and the `fuzz` job in `.github/workflows/ci.yml` type-checks the targets on stable with `--locked`. Refresh it with `cargo generate-lockfile --manifest-path fuzz/Cargo.toml`, which rewrites this workspace's lockfile and not the root's; a `cargo update` at the root leaves this file exactly where it was, so a refresh before a release runs in both directories.

`ring` appears in both lockfiles as a dependency quinn-proto declares for targets this project does not build. `cargo tree -i ring --manifest-path fuzz/Cargo.toml` is empty on every platform this project ships, and the crate only appears under `--target all`.

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

Swap `frame` for any of the names in the table above; `cargo +nightly fuzz list` enumerates the eleven. The corpus accumulates under `fuzz/corpus/<target>/` on the host and is deliberately not committed; crash inputs land in `fuzz/artifacts/<target>/`.
