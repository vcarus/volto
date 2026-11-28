#!/usr/bin/env python3
"""Checks shape_extract.py against log lines in the shape the server writes now.

`cargo test --test it_replay` runs it, and so does
`python3 tests/replay/shape_extract_test.py`. The fixture lines are
made up: the addresses are from the documentation ranges and the names are
under `.example`. Each line copies the message text and the field names of the
statement it stands for, so a change to either in `src/` that the extractor
does not follow shows up here.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import shape_extract  # noqa: E402

# One process, two connections. The first has a target refused by policy and
# is closed by this server for a protocol violation; the second is closed by
# its peer with H3_GENERAL_PROTOCOL_ERROR.
FIXTURE = """\
2026-11-28T10:00:00.000000Z  INFO volto::quic: accepting QUIC connections log_id="h3ld0001" version="1.8.6"
2026-11-28T10:00:01.000000Z  INFO volto::quic: connection established log_id="7l4svyo3" remote=192.0.2.10:40000 alpn=h3 server_name=proxy.example ech=false rtt_ms=80
2026-11-28T10:00:02.000000Z  INFO volto::tunnel: every address of the target is prohibited by policy; further refusals on this connection are logged at debug level until the count doubles log_id="ucmaf4w6" stream_id=0 host="mail.example" port=25 addresses=[198.51.100.7:25] refusals=1
2026-11-28T10:00:03.000000Z  WARN volto::quic: connection closed with error log_id="9pds6tk6" remote=192.0.2.10:40000 remote_now=192.0.2.10:40000 error=closed by this server: H3_GENERAL_PROTOCOL_ERROR: a frame a request stream may not carry rtt_ms=80 mtu=1350 mtu_black_holes=0 tunnels=1 dropped_datagrams=0
2026-11-28T10:00:04.000000Z  INFO volto::quic: connection established log_id="7l4svyo3" remote=192.0.2.11:50001 alpn=h3 server_name=proxy.example ech=false rtt_ms=90
2026-11-28T10:00:05.000000Z  WARN volto::quic: connection closed with error log_id="9pds6tk6" remote=192.0.2.11:50001 remote_now=192.0.2.11:50001 error=ApplicationClose: H3_GENERAL_PROTOCOL_ERROR rtt_ms=90 mtu=1350 mtu_black_holes=0 tunnels=0 dropped_datagrams=0
"""


def reconstructed():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "fixture.log")
        with open(path, "w") as handle:
            handle.write(FIXTURE)
        events, counts = shape_extract.read_events([path], None)
    assert counts.get("lines_unparsed", 0) == 0, counts
    return shape_extract.reconstruct(events)


class CurrentLogShape(unittest.TestCase):
    def test_a_policy_refusal_counts_as_a_tunnel_attempt(self):
        # The INFO line carries a suffix about its sampling after the
        # stable text; the DEBUG line between two INFO ones does not.
        kinds = [tunnel["kind"] for tunnel in reconstructed()["tunnels"]]
        self.assertEqual(kinds, ["policy_denied"])

    def test_a_close_this_server_decided_is_not_one_the_peer_reported(self):
        outcomes = [c.outcome for c in reconstructed()["connections"]]
        self.assertEqual(outcomes, ["server_violation", "protocol_violation"])


if __name__ == "__main__":
    unittest.main()
