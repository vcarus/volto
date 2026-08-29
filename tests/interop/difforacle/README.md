# Differential decoding oracle: QPACK and Huffman

Two decoders, one byte sequence, one comparison. `src/h3/qpack.rs` and
`src/h3/huffman.rs` read untrusted bytes off the wire; this suite runs generated
and mutated field sections through them and through **ls-qpack** (via
`pylsqpack`), and reports every input the two answer differently -- either
because one accepted what the other refused, or because both accepted and the
decoded fields are not identical.

It exists because the checks already in the tree cannot ask that question:

- The `fuzz/` targets are round-trip and no-crash oracles. A round trip cannot
  see a decoder that accepts an input the RFC says MUST be refused, and
  `src/h3/huffman.rs` has no encoder at all, so nothing round-trips through it.
- The integration suite's client (`tests/common/h3client.rs`) is built on the
  same codec as the server, so a misreading shared by both ends is invisible to
  it. That is the gap the `interop` CI job covers for the protocol as a whole,
  and this suite covers for the field-section encoding in particular.
- Both hand-transcribed tables -- RFC 9204 Appendix A in `qpack.rs`, RFC 7541
  Appendix B in `huffman.rs` -- can only be checked against themselves in-tree.
  ls-qpack carries its own copy of each.

Like `fuzz/`, this is run on demand and is **not** part of CI.

## Running

`pylsqpack` is pinned in `../aioquic/requirements.txt` alongside the rest of the
aioquic interop client, so there is one pinned Python environment for both
suites rather than two that can drift:

```sh
python3 -m venv .venv
.venv/bin/pip install -r ../aioquic/requirements.txt
.venv/bin/python difforacle.py --seed 1 --count 20000
```

`--count` is inputs per generated direction; the run above is 100k decode
inputs plus 20k encode inputs and takes a few seconds. The first run builds
`cargo build --release --example diff_oracle`; `--oracle PATH` skips that and
uses an existing binary. `--dump FILE` writes every divergence as
`kind<TAB>why<TAB>input hex<TAB>volto verdict<TAB>ls-qpack verdict`, which is
what to hand to a classifier when a run turns up something new.

Exit status is 0 when nothing diverged and 1 otherwise.

## Seeds

Every input is derived from `--seed` through one `random.Random`, so a run is
reproducible from its seed and count alone, and both are printed in the summary.
Quote them in any report of a finding. Seeds 1, 2 and 3 at `--count 20000` were
the campaign that produced `tests/it_diff_oracle.rs`; they agree on the same
five divergence signatures and find no sixth, which is the bar a new seed is
expected to clear.

The corpus is not committed. It is a function of the seed, and an input worth
keeping becomes a Rust regression instead.

## The two halves

`oracle.rs` is the volto half, built as the `diff_oracle` example (the target is
declared in the root `Cargo.toml`, which is why the file lives here rather than
in an `examples/` directory). It is a filter: one request per line in, one
verdict per line out, so nothing about volto's decoders is linked into the
judge's process. Its module documentation states the line protocol.

`difforacle.py` is the driver and the judge. It generates the corpus, runs the
oracle once per direction in a batch, decodes the same bytes with `pylsqpack`,
and groups the disagreements by signature. Its own transcription of RFC 7541
Appendix B -- needed to *produce* Huffman literals, which neither volto nor
pylsqpack will do -- is checked at import against the encoded literals RFC 7541
Appendix C.4 prints, so a typo there fails loudly instead of appearing as a
phantom divergence.

## Directions

1. **decode**, the core: generated conformant field sections, one-to-three-edit
   mutations of them, pure noise (half of it behind a valid section prefix,
   without which the field line parser is nearly unreachable), Huffman literals
   carried as a field value, and a targeted family aimed at the edges -- static
   indices around the end of the table, integers spelled at length, values near
   the 64-bit boundary, lengths that overrun the section.
2. **encode**: volto's own field sections through ls-qpack, which is the only
   check on the encoder that does not use volto's decoder to grade it.
3. **strictness**: a fixed table of inputs the RFCs name as errors, each with
   the section that names it. Both sides must refuse every one, and a side that
   accepts is reported by name -- this is where the two MUSTs ls-qpack does not
   enforce were found.

Plus a transcription pass that walks all ninety-nine static table entries and
all 256 Huffman symbols one at a time, where both sides must accept and agree.

## What it found

Five divergence signatures, stable across seeds, none of them a fault in volto.
All five are pinned in `tests/it_diff_oracle.rs` with the bytes that produced
them and the RFC sentence that settles them, so they hold on every `cargo test`
without Python:

| Input | volto | ls-qpack | Settled by |
|---|---|---|---|
| An empty field section | accepts | refuses | RFC 9204 §4.5: "a prefix and a possibly empty sequence of representations" |
| A field line with a zero-length name | accepts, refused as a request one layer up | refuses in the decoder | RFC 9110 §5.1: `field-name = token`, and `token` is `1*tchar` |
| An integer with continuation octets that add nothing | accepts | refuses | RFC 7541 §5.1 states the decoding algorithm and no minimality rule |
| A Sign bit of 1 with a zero Required Insert Count | refuses | accepts | RFC 9204 §4.5.1.2, a MUST |
| Huffman padding longer than seven bits | refuses | accepts, for some inputs | RFC 7541 §5.2, a MUST |

The last is content-dependent in ls-qpack rather than systematic: sampling four
thousand random literals with one extra `0xff` octet appended, it refused all
but two. `tests/it_diff_oracle.rs` carries three literals it accepted and one it
refused, so the pin does not depend on that ratio.
