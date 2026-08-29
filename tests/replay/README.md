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

## What the replay cannot do

Stated here as well as in `it_replay.rs` because it is the first thing to read
before believing a number out of a run:

* **The path is loopback.** Sub-millisecond RTT against 80–95 ms, and no loss at
  all against a link whose p90 connection loses 13% of its packets. Congestion
  control, MTU discovery and everything loss-driven are not under test.
* **Payload sizes are inferred.** The log records transport bytes per
  *connection*, so a tunnel's transfer size is that divided by the tunnel count:
  an over-count, and flat across a connection's tunnels.
* **Tunnel lifetime is not in the data at all.** Nothing at INFO level says when
  a tunnel ends, so a replayed one lives as long as its transfer takes.
* **Time compression has a floor.** The lab idle timeout cannot go below a
  second, and four in five production connections end on that timer, so at high
  compression measured lifetime and concurrency read high. The run prints the
  factor.
* **The target pool is small.** Distinct authorities in the lab are bounded by
  the pool size, well below production's distinct-target count, so the fan-out
  curve is followed only up to that bound.
