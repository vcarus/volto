#!/usr/bin/env python3
"""Puts two shape profiles side by side.

The replay is only worth anything if its fidelity can be stated, and fidelity
is not a single number: a replay can get the arrival rate exactly right and the
close-reason mix badly wrong. So this prints the metrics an operator watches,
one row each, with the ratio between the two profiles -- which is what turns
"the replay ran" into "the replay reproduced the tunnel mix to within 4% and the
close-reason mix to within a factor of two".

Both sides are produced by `shape_extract.py`, so both sides mean the same
thing by every row: the lab server writes the same log lines production does,
and the same parser reads them.

    python3 tests/replay/shape_compare.py PRODUCTION.json LAB.json
"""

from __future__ import annotations

import argparse
import json
import sys

# Each row is (label, path into the profile, how to format it). A path that a
# profile does not carry prints as `-` rather than failing: profiles from
# different releases carry different fields, which is the whole reason the
# extractor tolerates them.
ROWS = [
    ("violations per 1000 tunnel attempts", "violations/per_1000_tunnel_attempts", "{:.4f}"),
    ("violations per 1000 connections", "violations/per_1000_connections", "{:.4f}"),
    ("violations", "violations/count", "{:.0f}"),
    ("violation offset p50 (ms)", "violations/offset_from_connection_start/p50", "{:.0f}"),
    ("", None, None),
    ("connections", "connections/count", "{:.0f}"),
    ("close: idle", "connections/outcome_share/idle", "{:.4f}"),
    ("close: peer_close", "connections/outcome_share/peer_close", "{:.4f}"),
    ("close: protocol_violation", "connections/outcome_share/protocol_violation", "{:.4f}"),
    ("close: drained", "connections/outcome_share/drained", "{:.4f}"),
    ("close: other_error", "connections/outcome_share/other_error", "{:.4f}"),
    ("concurrency mean", "connections/concurrency/mean", "{:.2f}"),
    ("concurrency p90", "connections/concurrency/p90", "{:.0f}"),
    ("lifetime p50 (ms)", "connections/lifetime/p50", "{:.0f}"),
    ("interarrival p50 (ms)", "connections/interarrival/p50", "{:.0f}"),
    ("dropped datagrams per connection", "connections/dropped_datagrams/mean", "{:.4f}"),
    ("dropped datagrams worst connection", "connections/dropped_datagrams/max", "{:.0f}"),
    ("", None, None),
    ("tunnel attempts", "tunnels/attempts_logged", "{:.0f}"),
    ("tunnels per connection p50", "tunnels/per_connection/p50", "{:.0f}"),
    ("tunnels per connection p90", "tunnels/per_connection/p90", "{:.0f}"),
    ("tunnels per connection mean", "tunnels/per_connection/mean", "{:.2f}"),
    ("udp share of established", "tunnels/udp_share_of_established", "{:.5f}"),
    ("blackhole share of attempts", "tunnels/blackhole_share_of_attempts", "{:.5f}"),
    ("literal share of attempts", "tunnels/literal_share_of_attempts", "{:.5f}"),
    ("tunnel spacing p50 (ms)", "tunnels/spacing_within_connection/gap/p50", "{:.0f}"),
    ("tunnel spacing p90 (ms)", "tunnels/spacing_within_connection/gap/p90", "{:.0f}"),
    ("distinct targets", "tunnels/popularity/distinct", "{:.0f}"),
    ("top target share", "tunnels/popularity/share_of_tunnels/top_1", "{:.4f}"),
    ("top 10 target share", "tunnels/popularity/share_of_tunnels/top_10", "{:.4f}"),
]

# Rows where a ratio says nothing, because the replay deliberately runs at a
# different size or on a different clock.
SCALE_FREE = {
    "connections",
    "tunnel attempts",
    "violations",
    "lifetime p50 (ms)",
    "interarrival p50 (ms)",
    "tunnel spacing p50 (ms)",
    "tunnel spacing p90 (ms)",
    "distinct targets",
    "violation offset p50 (ms)",
}


def dig(profile, path):
    here = profile
    for step in path.split("/"):
        if not isinstance(here, dict) or step not in here:
            return None
        here = here[step]
    return here if isinstance(here, (int, float)) else None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("left", help="the reference profile, normally production")
    parser.add_argument("right", help="the profile to judge, normally the replay")
    args = parser.parse_args(argv)

    with open(args.left) as handle:
        left = json.load(handle)
    with open(args.right) as handle:
        right = json.load(handle)

    label_width = max(len(row[0]) for row in ROWS)
    header = f"{'metric':<{label_width}}  {left.get('name', 'left'):>14}  {right.get('name', 'right'):>14}  {'ratio':>8}"
    print(header)
    print("-" * len(header))

    for label, path, form in ROWS:
        if path is None:
            print()
            continue

        a = dig(left, path)
        b = dig(right, path)
        rendered_a = form.format(a) if a is not None else "-"
        rendered_b = form.format(b) if b is not None else "-"

        if label in SCALE_FREE or a in (None, 0) or b is None:
            ratio = "-"
        else:
            ratio = f"{b / a:.2f}x"

        print(f"{label:<{label_width}}  {rendered_a:>14}  {rendered_b:>14}  {ratio:>8}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
