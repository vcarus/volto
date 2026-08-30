#!/usr/bin/env bash
#
# Runs the shape replay over a lossy path, one container per tier.
#
# The replay's own limit has always been the path: loopback has no round trip
# and loses nothing, so the loss-driven half of the server -- recovery,
# congestion control, path MTU discovery -- never runs, and the production
# symptom the replay was built to chase is loss-driven. `replay/netem.rs` puts a
# real qdisc on the QUIC four-tuple to close that, and this script supplies what
# it needs: Linux, iproute2, ethtool, and CAP_NET_ADMIN. None of that exists on
# the macOS dev host, which is why this is a container and not a test you can
# just run.
#
# What it is *for* is the comparison, not any single number. Every tier below
# runs the identical plan -- same profile, same seed, same compression, same
# everything -- and differs only in the path underneath. So a metric that moves
# between tiers moved because of the path, and nothing else. The `off` tier is
# the control and is worth the minutes it costs: comparing a shaped run against
# a previously published loopback number taken at other settings proves nothing.
#
# Usage:
#
#     tests/replay/lossy-lab.sh                     # off, steady and spike
#     TIERS="spike severe" tests/replay/lossy-lab.sh
#     SECONDS_PER_TIER=1200 COMPRESSION=100 tests/replay/lossy-lab.sh
#
# Every knob is an environment variable, listed with its default below. The
# defaults are chosen so that the round trip is small against a connection's
# lifetime: at compression C a production connection's 262 s median lifetime
# becomes 262/C seconds, and a 90 ms round trip only stays in proportion while
# that stays well above it. Compression therefore has a ceiling here that it does
# not have on loopback, and the run buys its sample size with wall time instead.
#
# Each tier writes two files into OUT: the server's own log, which
# `shape_extract.py` turns into a profile directly comparable with the captured
# host's, and the run's console output, which carries the plan, the client-side
# tallies and the qdisc counters.
#
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/../.." && pwd)

# The tiers to run, in order. `off` is the control.
TIERS=${TIERS:-"off steady spike"}
# Wall-clock seconds of load per tier.
SECONDS_PER_TIER=${SECONDS_PER_TIER:-900}
# Production seconds per wall second. See the note above on its ceiling here.
COMPRESSION=${COMPRESSION:-100}
SEED=${SEED:-24061}
IDLE_SECS=${IDLE_SECS:-3}
TARGETS=${TARGETS:-256}
MAX_TUNNELS=${MAX_TUNNELS:-4096}
PROFILE=${PROFILE:-tests/replay/profiles/host-b.json}
OUT=${OUT:-$REPO/target/lossy-replay}

# A volume of this session's own, never one shared with another worktree: a
# target directory carrying another tree's build state produces green runs of
# code that was never compiled.
TARGET_VOLUME=${TARGET_VOLUME:-volto-lossy-replay-target}
IMAGE=${IMAGE:-volto-lossy-lab:1}
BASE_IMAGE=${BASE_IMAGE:-rust:1}

mkdir -p "$OUT"

# One image with the shaping tools in it, built once and reused, so a tier does
# not spend its first half-minute in apt.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "==> building $IMAGE"
    docker build -t "$IMAGE" - <<EOF
FROM $BASE_IMAGE
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 ethtool \
 && rm -rf /var/lib/apt/lists/*
EOF
fi

docker volume create "$TARGET_VOLUME" >/dev/null

for tier in $TIERS; do
    echo
    echo "==> tier $tier: ${SECONDS_PER_TIER}s at ${COMPRESSION}x, seed $SEED"

    # NET_ADMIN is what lets the test install the qdisc; without it the test
    # panics rather than running unshaped, which is the intended behaviour.
    docker run --rm \
        --cap-add=NET_ADMIN \
        -v "$REPO":/w -w /w \
        -v "$TARGET_VOLUME":/target -e CARGO_TARGET_DIR=/target \
        -v volto-cargo-cache:/usr/local/cargo/registry \
        -v volto-cargo-git:/usr/local/cargo/git \
        -v "$OUT":/out \
        -e VOLTO_REPLAY_NETEM="$tier" \
        -e VOLTO_REPLAY_PROFILE="/w/$PROFILE" \
        -e VOLTO_REPLAY_SECONDS="$SECONDS_PER_TIER" \
        -e VOLTO_REPLAY_COMPRESSION="$COMPRESSION" \
        -e VOLTO_REPLAY_SEED="$SEED" \
        -e VOLTO_REPLAY_IDLE_SECS="$IDLE_SECS" \
        -e VOLTO_REPLAY_TARGETS="$TARGETS" \
        -e VOLTO_REPLAY_MAX_TUNNELS="$MAX_TUNNELS" \
        -e VOLTO_REPLAY_LOG="/out/$tier.log" \
        "$IMAGE" \
        cargo test --release --test it_replay -- --ignored --nocapture \
        2>&1 | tee "$OUT/$tier.txt"
done

echo
echo "==> logs and console output in $OUT"
echo "    turn one into a profile:"
echo "      python3 tests/replay/shape_extract.py --name lab-<tier> \\"
echo "          --out /tmp/lab-<tier>.json $OUT/<tier>.log"
echo "      python3 tests/replay/shape_compare.py $PROFILE /tmp/lab-<tier>.json"
