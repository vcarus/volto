# Traffic-shape replay

Turning a production log into a *shape*, and replaying that shape against a lab
server.

## The gap this closes

Every other test in this tree drives the server the way a script drives it: open
a tunnel, use it, close it, assert. Production drives it the way an application
does — dozens of connections at once, hundreds of tunnels on each, targets that
repeat, a client that disappears mid-transfer and comes back a second later with
a new connection, all over a link with 80–95 ms of round trip.

So a whole class of question has only ever been askable of production. The
standing example is a protocol-violation investigation that was closed as "not
reproducible in the lab" — where the lab was never shaped like the thing it was
trying to reproduce, and no amount of re-running it would have been.

These three pieces make the shape itself the artefact: extract it from the log,
replay it, and compare the two profiles field by field.

## The pieces

| | |
|---|---|
| `shape_extract.py` | reads volto's own INFO log, writes a JSON shape profile |
| `shape_compare.py` | puts two profiles side by side with the ratio between them |
| `profiles/*.json` | committed profiles, one per captured host |
| `../it_replay.rs` | the replayer: consumes a profile, drives a lab server |
| `shape.rs` | the profile reader, the seeded sampler and the planner behind it |
| `netem.rs` | the lossy path: a qdisc on the QUIC four-tuple |
| `lossy-lab.sh` | the container that can run one, a tier at a time |

Python is the host's `python3` and nothing else; the Rust side adds no
dependency, which is why `shape.rs` carries its own small JSON reader.

## Privacy

The input is the operator's own browsing metadata: every `authority=` in the log
is a host they visited. The extractor replaces each name with an opaque index
the moment it parses it, keeps only that index, the port class and the name
length, and never writes the index table anywhere. A profile therefore carries
counts, rates and histograms and no strings but its own name, the schema version
and the server versions it saw — which is what makes one safe to commit.

The `--events` dump is not: it carries per-tunnel indices and is working
material. Keep it out of the repository.

Anything given to `--name`, and any profile filename, is chosen by whoever runs
the tool. Name them for what they are (`host-a`, `host-busy`) and not for the
machine.

## Using it

Extract, from a journal export or the rotated syslog files or both at once —
lines are deduplicated on timestamp and content, so overlapping inputs are
correct rather than double-counted:

```sh
python3 tests/replay/shape_extract.py \
    --name host-a --out tests/replay/profiles/host-a.json \
    /path/to/syslog.gz /path/to/journal.txt
```

Replay, with any knob overridden through the environment (the full list is in
`it_replay.rs`'s module documentation):

```sh
cargo test --release --test it_replay -- --ignored --nocapture
VOLTO_REPLAY_SECONDS=60 VOLTO_REPLAY_COMPRESSION=2000 \
    cargo test --release --test it_replay -- --ignored --nocapture
```

The run prints where it wrote the lab server's own log. Putting that file back
through the extractor gives a profile in the same schema, which is what makes
the last step a comparison rather than two lists of numbers:

```sh
python3 tests/replay/shape_extract.py --name lab --out /tmp/lab.json /tmp/volto-replay-*.log
python3 tests/replay/shape_compare.py tests/replay/profiles/host-b.json /tmp/lab.json
```

## The profile schema

`volto.traffic-shape/1`. Every distribution is a *summary*: `n`, `min`, `max`,
`mean`, `p50`, `p90`, `p99`, and `buckets` as a list of `[lower bound, count]`
pairs on a 1-2-5 ladder. A sampler picks a bucket in proportion to its count and
then a value uniformly inside it.

```
schema, name
source/            what was read: line counts, window, server versions seen,
                   distinct target and client-address counts
connections/       count, per_hour, interarrival, lifetime, concurrency,
                   outcome + outcome_share, lifetime_by_outcome, rtt, mtu,
                   bytes, packets, loss_permille, dropped_datagrams
connections/joint  the (outcome, lifetime, tunnel count) contingency table
tunnels/           counts and shares by kind, port class, name length,
                   per_connection, transport_bytes_per_tunnel,
                   spacing_within_connection, fanout, popularity
restarts/          client arrival bursts, server restarts
violations/        count and rates, offset from connection start, tunnels and
                   bytes at the violation
datagrams/         oversize drops and send-buffer evictions
by_server_version/ the same headline numbers, one row per release
```

Two of those need a word about how they are measured, because the log does not
give them up directly.

**`connections/joint`** exists because a connection's ending, its lifetime and
its tunnel count are strongly dependent, and sampling them independently
produces connections production could not contain: an idle close after 40 ms, or
ten thousand tunnels inside a one-second window. The table is a contingency over
the three, so a planner draws all three from one row.

**`tunnels/fanout` and `tunnels/spacing_within_connection`** are measured over
*solo epochs* only — the stretches when exactly one connection is open on a
process, so a tunnel line with no connection identifier on it can still be
attributed to one. A fifth to a third of all tunnels fall in such a stretch in
the captures this was built against. The alternative, following stream ids,
was tried and does not work: ids from every open connection interleave and
advance past requests that never reach INFO level, and it got the tunnel count
right for 18% of connections against the closing line's own 100%.

Everything else per connection — lifetime, tunnel count, bytes, packets, loss,
dropped datagrams, close reason — is read off the closing line, exactly, for
every connection that has one.

## Measured fidelity

One baseline, seed `24061`, against `profiles/host-b.json`. Two runs, because
no single compression serves both purposes: a strong one buys sample size, a
weak one buys timing.

```sh
# A. volume: 150 s at 1400x = 58 production-hours, 657 connections, 44 393 tunnels
VOLTO_REPLAY_SECONDS=150 VOLTO_REPLAY_COMPRESSION=1400 \
VOLTO_REPLAY_TARGETS=256 VOLTO_REPLAY_MAX_TUNNELS=4096 \
    cargo test --release --test it_replay -- --ignored --nocapture

# B. timing: 200 s at 120x with a 1 s idle timeout, 67 connections
VOLTO_REPLAY_SECONDS=200 VOLTO_REPLAY_COMPRESSION=120 VOLTO_REPLAY_IDLE_SECS=1 \
VOLTO_REPLAY_TARGETS=256 VOLTO_REPLAY_MAX_TUNNELS=4096 \
    cargo test --release --test it_replay -- --ignored --nocapture
```

Run A against the production profile, the rows that matter:

| metric | production | replay | ratio |
|---|---|---|---|
| violations per 1000 connections | 53.83 | 53.27 | 0.99x |
| violations per 1000 tunnel attempts | 0.508 | 0.791 | 1.56x |
| close: idle | 0.8085 | 0.8189 | 1.01x |
| close: peer_close | 0.1268 | 0.1263 | 1.00x |
| close: protocol_violation | 0.0538 | 0.0533 | 0.99x |
| blackhole share of attempts | 0.0641 | 0.0657 | 1.02x |
| address-literal share of attempts | 0.4226 | 0.4586 | 1.09x |
| UDP share of established tunnels | 0.00866 | 0.00808 | 0.93x |
| most popular target's share | 0.1464 | 0.1465 | 1.00x |
| tunnels per connection, mean | 89.5 | 67.6 | 0.75x |
| dropped datagrams per connection | 0.038 | 0 | — |
| concurrency, mean | 3.10 | 10.98 | 3.54x |

Reading it:

* The **close-reason mix** and the **violation rate per connection** land within
  a percent. That is the headline: the thing an operator watches is reproducible
  in the lab now, and a rate that moved would be visible against it.
* **Per tunnel** the violation rate reads 1.56x high, and the row below says
  why: the replay delivers three quarters of production's tunnels per
  connection. Violations are planned per connection, so the shortfall lands
  entirely in the denominator. Prefer the per-connection rate; use the per-tunnel
  one only against another replay at the same settings.
* The tunnel shortfall itself is the long tail being cut in three places, all
  printed by the run: `tunnels past window`, `capped tunnel counts`, and the
  tunnels a restart burst takes with the connection it aborts.
* **Concurrency** and **lifetime** are the rows to disbelieve, for the reason in
  the section below.
* **Dropped datagrams** are zero in the lab against 0.038 per connection in
  production. Not a fidelity gap: those are drops on a lossy 80-95 ms path, and
  the replay has no such path. Zero is what an assertion holds it to.

## The lossy path

Loopback was the replay's largest single limitation, and it is the one that
mattered most: the production symptom this harness was built to chase is
erasure-loss spikes, and a path that cannot lose a packet cannot produce one.

`netem.rs` injects a real one. It is a `tc` qdisc, so the loss and the delay are
applied by the same kernel code that would apply them on a wire, and it is aimed
at the QUIC four-tuple alone — two `u32` filters on the lab server's UDP port,
one netem per direction — so the server-to-target hop stays on unshaped
loopback, as it broadly is in production. Segmentation offload is turned off so
a loss draw deletes one datagram rather than a whole GSO batch, and `lo` is
given a 1500-byte MTU so DPLPMTUD has something real to discover. The reasoning
for each of those is in the module's own documentation.

It needs Linux, `iproute2` and `CAP_NET_ADMIN`, none of which the macOS dev host
has, so `lossy-lab.sh` runs it in a container:

```sh
tests/replay/lossy-lab.sh                              # off, steady, spike
TIERS="off severe" SECONDS_PER_TIER=600 tests/replay/lossy-lab.sh
```

Three presets, all at a 90 ms round trip with 6 ms of jitter, differing only in
the per-packet loss:

| preset | loss | where the number comes from |
|---|---|---|
| `steady` | 0.2% | the standing measured rate for this link (D33) |
| `spike` | 13% | the p90 connection in `profiles/host-b.json` |
| `severe` | 42% | the other intensity point D71 recorded |

Two things about how it is used are load-bearing.

**Run the `off` tier.** Every tier executes the identical plan and differs only
in the path, so a metric that moves between tiers moved because of the path.
Comparing a shaped run against the loopback numbers published in this file
instead would compare two different plans at two different compressions and
prove nothing.

**Compression has a ceiling here that it does not have on loopback.** At
compression *C* a production connection's 262-second median lifetime becomes
262/*C* seconds, and 90 ms of round trip only stays in proportion while that
stays well above it. `lossy-lab.sh` defaults to 100x for that reason where the
loopback baseline below uses 1400x, and buys its sample size with wall time.

A shaped run checks its own premise before reporting anything: it asserts that
the server independently measured a round trip near the one the qdisc was given,
and that the qdisc carried packets at all. A replay that believed it was lossy
and was not would file a loopback result under a lossy heading, which is the one
outcome worse than not running.

## What the replay cannot do

Stated here as well as in `it_replay.rs` because it is the first thing to read
before believing a number out of a run:

* **The path is loopback unless it is shaped.** Sub-millisecond RTT against
  80–95 ms, and no loss at all against a link whose p90 connection loses 13% of
  its packets. Congestion control, MTU discovery and everything loss-driven are
  not under test in an unshaped run — see *The lossy path* above for the one
  that puts them there.
* **Payload sizes are inferred.** The log records transport bytes per
  *connection*, so a tunnel's transfer size is that divided by the tunnel count:
  an over-count, and flat across a connection's tunnels.
* **Tunnel lifetime is not in the data at all.** Nothing at INFO level says when
  a tunnel ends, so a replayed one lives as long as its transfer takes.
* **A connection's quiet time cannot be replayed.** Production carries a
  connection through a long silence on the server's keep-alive PINGs — its
  measured gaps between tunnels reach a minute and a half at the 99th
  percentile, well past its 30-second idle timeout. The lab cannot: a keep-alive
  must be under half the idle timeout, the idle timeout is already at its
  one-second floor, and PINGs would stop an idle-ended connection ever timing
  out, which is the ending four in five production connections have. The planner
  therefore shortens gaps and quiet tails it cannot hold, and prints how many.
  A replayed connection lives for its working time plus one idle timeout, so
  **lifetime and concurrency read high at strong compression and low at weak
  compression** and neither figure should be compared. Nothing else is affected.
* **The target pool is small.** Distinct authorities in the lab are bounded by
  the pool size, well below production's distinct-target count, so the fan-out
  curve is followed only up to that bound. The most popular target's share comes
  out right; the next nine are spread thinner than production's.
* **Host limits are the lab's, not production's.** A hard run on macOS reaches
  ephemeral-port and descriptor limits that a server does not, and the run
  reports them as refusals with their `Proxy-Status` reason — `503
  connection_limit_reached` when a connection's compressed tunnels overlap past
  `max_targets_per_conn`, `500 proxy_internal_error` when the host runs out of
  something to `connect()` with. Both are the server naming a local failure
  correctly. Read them as a note on the settings, not on the server.
