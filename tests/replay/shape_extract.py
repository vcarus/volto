#!/usr/bin/env python3
"""Turns volto's own INFO log into a traffic *shape profile*.

The lab has never been able to reproduce what only production produces. Its
client is an in-process script that opens a tunnel, uses it and closes it;
production is a real application behind a real proxy client, on a link with
80-95 ms of RTT, restarted mid-transfer, opening hundreds of tunnels per
connection at whatever rate a person browsing produces. A whole class of
question -- "is this rate of protocol violations normal?", "what does a loss
spike look like from the server's side?" -- has therefore only ever been asked
of production.

This script closes the input half of that gap. It reads the lines the server
already writes at INFO level and distils them into a JSON profile of *shapes*:
how often connections arrive, how long they live, how many tunnels they carry
and how fast, how those tunnels split between TCP and UDP, how many distinct
targets a connection touches, how connections end, and how often a peer reports
a protocol violation. `tests/it_replay.rs` consumes that profile and drives a
lab server with it.

Privacy
-------

The input contains the operator's own browsing metadata: every `authority=` is
a host they visited. This script is built so that nothing derived from a name
can leave it:

* Names are replaced by an opaque index the moment they are parsed. The
  index table lives in memory for one run and is never written anywhere.
* What survives a name is its opaque index, its port class (80 / 443 / 853 /
  other) and its length in characters. The optional `--events` dump carries
  those; the profile itself carries neither indices nor lengths of individual
  names, only aggregates over thousands of them.
* Client addresses are treated the same way: an index, used to pair a
  connection's open and close lines and to spot a client restarting, and
  discarded after that.

The profile is therefore safe to commit; an `--events` dump is not, and the
script says so in the dump's own header line.

Usage
-----

    python3 tests/replay/shape_extract.py \\
        --name host-a --out tests/replay/profiles/host-a.json \\
        /var/log/syslog.gz /var/log/syslog

Inputs may be plain text or gzip (by `.gz` suffix), in any order and with any
overlap: lines are deduplicated on their timestamp and content, then sorted, so
handing it both `journalctl` output and the rotated syslog files that already
contain those same lines is correct rather than double-counting.

Nothing about a particular capture is hardcoded. The parser keys on the
message texts the server logs, which are the stable part of its grammar, and
tolerates fields that a given release did not yet log -- the shipped `INFO`
lines have gained fields over time and a four-week capture spans several
releases.
"""

from __future__ import annotations

import argparse
import gzip
import json
import math
import re
import sys
from collections import Counter, defaultdict

# --------------------------------------------------------------------------
# Line grammar
# --------------------------------------------------------------------------

# `tracing`'s default format, with whatever the transport in front of it
# prepended: journalctl's `<stamp> <host> <unit>[<pid>]:` or syslog's variant of
# the same. The unit and pid are optional because a log read straight off the
# process has neither; when they are there the pid separates one run of the
# server from the next, which matters because stream ids and connection
# identities both restart with the process.
LINE = re.compile(
    r"^(?:.*?\s)??(?:(?P<unit>[\w.-]+)\[(?P<pid>\d+)\]:\s+)?"
    r"(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)\s+"
    r"(?P<level>[A-Z]+)\s+(?P<target>[\w:]+):\s+(?P<rest>.*)$"
)

# A field name at the start of the line or after whitespace. Used to find where
# one field's value ends and the next begins, which is the only way to read a
# value that has spaces in it -- `error=` is a `Display` of an error type and
# routinely a whole sentence.
FIELD_KEY = re.compile(r"(?:^|\s)([a-z_][a-z0-9_]*)=")

# Colour. A process whose stdout is not a terminal usually turns it off, but not
# always -- a run started by hand, or a unit whose environment says otherwise,
# writes SGR sequences into the journal, and rsyslog escapes each ESC into the
# four literal characters `#033` on the way to disk. Either form splits a field
# name from its `=` and hides the whole line from the parser: in the captures
# this was written against it was a quarter of one host's lines, silently
# dropped, until the count of unparsed lines was looked at rather than trusted.
COLOUR = re.compile(r"(?:\x1b|#033)\[[0-9;]*[A-Za-z]")


def parse_timestamp(text: str) -> int:
    """`2026-08-27T07:35:54.176862Z` to microseconds since the epoch.

    Hand-parsed rather than handed to `datetime.strptime`, which costs about a
    second per hundred thousand lines and is the whole cost of a run otherwise.
    The format is fixed by `tracing`, so there is nothing to be flexible about.
    """
    year = int(text[0:4])
    month = int(text[5:7])
    day = int(text[8:10])
    hour = int(text[11:13])
    minute = int(text[14:16])
    second = int(text[17:19])
    micros = int(text[20:26])

    # Days from the civil calendar, after Howard Hinnant's `days_from_civil`.
    shifted_year = year - (month <= 2)
    era = shifted_year // 400
    year_of_era = shifted_year - era * 400
    day_of_year = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    day_of_era = year_of_era * 365 + year_of_era // 4 - year_of_era // 100 + day_of_year
    days = era * 146097 + day_of_era - 719468

    return ((days * 24 + hour) * 3600_000_000) + (minute * 60 + second) * 1_000_000 + micros


def split_fields(rest: str) -> tuple[str, dict[str, str]]:
    """Splits `message key=value key=value` into the message and the fields.

    A value runs to the start of the next field name rather than to the next
    space, so `error=aborted by peer: ...` survives whole. Quoted and bracketed
    values are scanned to their closing delimiter first, so a field name that
    happened to appear inside one could not end it early.
    """
    keys = list(FIELD_KEY.finditer(rest))
    if not keys:
        return rest.strip(), {}

    message = rest[: keys[0].start()].strip()
    fields: dict[str, str] = {}

    index = 0
    while index < len(keys):
        match = keys[index]
        name = match.group(1)
        start = match.end()

        if start < len(rest) and rest[start] in "\"[":
            closing = '"' if rest[start] == '"' else "]"
            cursor = start + 1
            while cursor < len(rest):
                if rest[cursor] == "\\":
                    cursor += 2
                    continue
                if rest[cursor] == closing:
                    cursor += 1
                    break
                cursor += 1
            end = cursor
            # Skip the field names that fell inside the quoted or bracketed run.
            while index + 1 < len(keys) and keys[index + 1].start() < end:
                index += 1
        else:
            end = keys[index + 1].start() if index + 1 < len(keys) else len(rest)

        fields[name] = rest[start:end].strip()
        index += 1

    return message, fields


def unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return value


# --------------------------------------------------------------------------
# Message texts
# --------------------------------------------------------------------------

MSG_LISTENING = "accepting QUIC connections"
MSG_ESTABLISHED = "connection established"
MSG_CLOSED = "connection closed"
MSG_CLOSED_ERROR = "connection closed with error"
MSG_TCP_TUNNEL = "tcp tunnel established"
MSG_UDP_SESSION = "udp session established"
MSG_BLACKHOLE = "every address of the target is a DNS blackhole"
MSG_POLICY_DENIED = "every address of the target is prohibited by policy"
MSG_GOAWAY = "sent GOAWAY, draining tunnels"
MSG_SIGNAL = "received a termination signal"
MSG_OVERSIZE = "target packet too large for a QUIC datagram, dropping"
MSG_EVICTION = "QUIC datagram send buffer full, older datagrams evicted"

# Every message that stands for one request stream that reached the routing
# layer. A blackholed or policy-denied target consumed a stream and a resolver
# slot exactly as a successful tunnel did, so all four count as tunnel
# *attempts*; the `outcome` field is what tells them apart afterwards.
TUNNEL_MESSAGES = {
    MSG_TCP_TUNNEL: "tcp",
    MSG_UDP_SESSION: "udp",
    MSG_BLACKHOLE: "blackhole",
    MSG_POLICY_DENIED: "policy_denied",
}


def close_outcome(fields: dict[str, str]) -> str:
    """Names how a connection ended, across every release in the capture.

    The `reason=` field is what current releases log; older ones logged only the
    `ConnectionError`, whose `Display` says the same things in other words, and
    in three different vocabularies as the HTTP/3 layer was rewritten under it.
    All of them are folded into one set of names here, so a capture spanning
    several releases aggregates instead of splitting into eras:

    * The current layer prints the code by name: `ApplicationClose:
      H3_GENERAL_PROTOCOL_ERROR`, or `ApplicationClose: 0x0` for a code it has
      no name for.
    * The release before it printed quinn's own text, which is `aborted by
      peer:` followed by the reason string the peer sent -- and the client in
      this capture sends RFC 9114's own description of the code, so a protocol
      violation reads as a sentence about protocol compliance.
    * Older still, the `h3` crate wrapped both in `Remote error: ...`.

    `protocol_violation` is the one that matters: the peer closing with
    H3_GENERAL_PROTOCOL_ERROR, which is the server-visible half of a
    client-reported protocol violation.
    """
    if "reason" in fields:
        return unquote(fields["reason"])

    # Older still than any of the error vocabularies below: before there was a
    # reason at all, the closing line carried one boolean saying whether the
    # idle timer was what ended it.
    if "idle" in fields:
        return "idle" if fields["idle"] == "true" else "peer_close"

    if "error" not in fields:
        # Older than the boolean too: the line said a connection had closed and
        # nothing about why. Named for what it is rather than folded in with the
        # faults, so that `other_error` stays a row worth looking twice at.
        return "unrecorded"

    error = fields["error"]
    if "H3_GENERAL_PROTOCOL_ERROR" in error or "protocol compliance" in error:
        return "protocol_violation"
    if error.endswith("Timeout"):
        return "idle"
    if "ApplicationClose: 0x0" in error or "ApplicationClose: H3_NO_ERROR" in error:
        return "peer_close"
    if "ApplicationClose:" in error:
        # Some other code the peer chose: a problem it is reporting, but not the
        # one this profile counts.
        return "peer_error"
    if error.endswith("closed"):
        # `ConnectionError::LocallyClosed`: this endpoint closed the connection,
        # which at INFO level only happens when the grace period expired during
        # a shutdown. A deploy, not a fault of the connection.
        return "server_shutdown"
    return "other_error"


def port_class(port: int | None) -> str:
    """The bucket a target port falls in.

    Three named ports and a catch-all: HTTP, HTTPS, and DNS-over-TLS, which is
    the shape the proxy's UDP path mostly carries. A port is not private, but a
    port *with* a name would be, so only the class survives into the profile.
    """
    if port in (80, 443, 853):
        return str(port)
    return "other"


class Anonymizer:
    """Maps each distinct string to an opaque index, and forgets nothing else.

    The table exists for the duration of one run so that repeats of the same
    name can be recognised as repeats. It is never serialised: the profile
    carries counts over indices, and the optional event dump carries the indices
    alone.
    """

    def __init__(self, prefix: str) -> None:
        self._prefix = prefix
        self._index: dict[str, str] = {}

    def key(self, name: str) -> str:
        existing = self._index.get(name)
        if existing is None:
            existing = f"{self._prefix}{len(self._index):04d}"
            self._index[name] = existing
        return existing

    def __len__(self) -> int:
        return len(self._index)


def split_authority(authority: str) -> tuple[str, int | None]:
    """`host:port`, `[v6]:port` or a bare host into its parts."""
    if authority.startswith("["):
        closing = authority.find("]")
        if closing >= 0:
            host = authority[1:closing]
            rest = authority[closing + 1 :]
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except ValueError:
                    return host, None
            return host, None

    if ":" in authority:
        host, _, port = authority.rpartition(":")
        try:
            return host, int(port)
        except ValueError:
            return authority, None

    return authority, None


IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def is_literal(host: str) -> bool:
    """Whether the target was an address rather than a name.

    Worth keeping because it decides whether the request costs a name lookup at
    all: an address literal takes no slot in the resolver budget (D90), so a
    replay whose targets are all literals never exercises it.
    """
    return bool(IPV4.match(host)) or ":" in host


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------


def read_events(paths: list[str], unit: str | None) -> tuple[list[tuple], dict[str, int]]:
    """Parses every input into a timestamp-sorted, deduplicated event list.

    Deduplication is on `(timestamp, message-and-fields)`. Two different lines
    cannot collide on a microsecond timestamp *and* identical content, while the
    same line read from two sources always does -- which is what makes it safe
    to hand this both a journal export and the syslog files that already contain
    the same lines.
    """
    seen: set[tuple[str, str]] = set()
    events: list[tuple] = []
    counts = Counter()

    for path in paths:
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", errors="replace") as handle:  # type: ignore[operator]
            for line in handle:
                counts["lines_read"] += 1
                if COLOUR.search(line):
                    line = COLOUR.sub("", line)
                    counts["lines_decoloured"] += 1
                match = LINE.match(line)
                if match is None:
                    counts["lines_unparsed"] += 1
                    continue
                if unit is not None and match.group("unit") not in (None, unit):
                    counts["lines_other_unit"] += 1
                    continue

                stamp = match.group("ts")
                rest = match.group("rest")
                identity = (stamp, rest)
                if identity in seen:
                    counts["lines_duplicate"] += 1
                    continue
                seen.add(identity)

                pid = match.group("pid")
                message, fields = split_fields(rest)
                events.append(
                    (parse_timestamp(stamp), int(pid) if pid else 0, message, fields)
                )
                counts["lines_kept"] += 1

    events.sort(key=lambda event: event[0])
    return events, dict(counts)


# --------------------------------------------------------------------------
# Reconstruction
# --------------------------------------------------------------------------


class Connection:
    """One QUIC connection, from its `established` line to its closing line."""

    __slots__ = (
        "peer",
        "version",
        "opened_us",
        "closed_us",
        "outcome",
        "rtt_open_ms",
        "rtt_close_ms",
        "tunnels",
        "tx_bytes",
        "rx_bytes",
        "sent_packets",
        "lost_packets",
        "dropped_datagrams",
        "mtu",
        "mtu_black_holes",
        "migrated",
        "solo_targets",
        "solo_tunnels",
        "solo_gaps_us",
        "last_solo_us",
    )

    def __init__(self, peer: str, version: str, opened_us: int, rtt_ms: int | None) -> None:
        self.peer = peer
        self.version = version
        self.opened_us = opened_us
        self.closed_us: int | None = None
        self.outcome: str | None = None
        self.rtt_open_ms = rtt_ms
        self.rtt_close_ms: int | None = None
        self.tunnels: int | None = None
        self.tx_bytes: int | None = None
        self.rx_bytes: int | None = None
        self.sent_packets: int | None = None
        self.lost_packets: int | None = None
        self.dropped_datagrams: int | None = None
        self.mtu: int | None = None
        self.mtu_black_holes: int | None = None
        self.migrated = False
        # Filled only while this connection is the sole open one on its process;
        # see `SOLO ATTRIBUTION` below.
        self.solo_targets: list[str] = []
        self.solo_tunnels = 0
        self.solo_gaps_us: list[int] = []
        self.last_solo_us: int | None = None


# SOLO ATTRIBUTION
# ----------------
# A tunnel line carries a stream id but not the connection it belongs to, and a
# stream id is only unique within a connection. On a host serving several
# connections at once there is therefore no way to say which connection opened
# a given tunnel -- stream ids from every open connection interleave, and they
# advance past requests that never reached INFO level, so following the
# sequence does not identify one either (measured: 18% of connections got their
# tunnel count right that way, against 100% from the closing line's own
# `tunnels=`).
#
# What *is* unambiguous is a tunnel that arrives while exactly one connection is
# open on that process. Those stretches are called solo epochs here, and they
# carry a fifth to a third of all tunnels in the captures this was built
# against, which is enough to measure two things nothing else gives:
#
#   * how a connection's tunnels are spaced in time, and
#   * how many *distinct* targets a connection has touched after n tunnels,
#
# both of which the replayer needs and neither of which appears on the closing
# line. Everything else per connection -- lifetime, tunnel count, bytes,
# packets, loss, dropped datagrams -- is read off the closing line, exactly,
# for every connection.


def reconstruct(events: list[tuple]) -> dict:
    """Walks the event stream into connections, tunnels and lifecycle marks."""
    targets = Anonymizer("h")
    peers = Anonymizer("p")

    connections: list[Connection] = []
    tunnels: list[dict] = []
    restarts: list[int] = []
    goaways = 0
    oversize_drops = 0
    datagram_evictions = 0
    versions: Counter = Counter()

    # Open connections, keyed by (pid, peer address). The peer address is the
    # only identity a connection has in the log, and it is reused across
    # processes, so the pid has to be part of the key.
    live: dict[tuple[int, str], Connection] = {}
    unattributed = 0

    # Which release each process is running, so a capture spanning several of
    # them can be read release by release. A process whose startup line fell
    # outside the window is `unknown` rather than guessed at.
    running: dict[int, str] = {}

    for stamp, pid, message, fields in events:
        if message == MSG_LISTENING:
            # A new process: whatever was open under the old pid ended with it,
            # and its closing lines are either already seen or lost with it.
            for key in [key for key in live if key[0] == pid]:
                live.pop(key)
            restarts.append(stamp)
            version = unquote(fields.get("version", "unknown"))
            running[pid] = version
            versions[version] += 1
            continue

        if message == MSG_ESTABLISHED:
            remote = fields.get("remote", "")
            rtt = fields.get("rtt_ms")
            connection = Connection(
                peers.key(remote.rsplit(":", 1)[0]),
                running.get(pid, "unknown"),
                stamp,
                int(rtt) if rtt and rtt.isdigit() else None,
            )
            live[(pid, remote)] = connection
            continue

        if message in (MSG_CLOSED, MSG_CLOSED_ERROR):
            remote = fields.get("remote", "")
            connection = live.pop((pid, remote), None)
            if connection is None:
                # The `established` line fell outside the capture window.
                continue

            connection.closed_us = stamp
            connection.outcome = close_outcome(fields)
            connection.migrated = fields.get("remote_now", remote) != remote
            for name, attribute in (
                ("tunnels", "tunnels"),
                ("tx_bytes", "tx_bytes"),
                ("rx_bytes", "rx_bytes"),
                ("sent_packets", "sent_packets"),
                ("lost_packets", "lost_packets"),
                ("dropped_datagrams", "dropped_datagrams"),
                ("mtu", "mtu"),
                ("mtu_black_holes", "mtu_black_holes"),
                ("rtt_ms", "rtt_close_ms"),
            ):
                raw = fields.get(name)
                if raw is not None and raw.isdigit():
                    setattr(connection, attribute, int(raw))
            connections.append(connection)
            continue

        if message == MSG_GOAWAY:
            goaways += 1
            continue
        if message.startswith(MSG_OVERSIZE):
            oversize_drops += 1
            continue
        if message.startswith(MSG_EVICTION):
            datagram_evictions += 1
            continue

        kind = TUNNEL_MESSAGES.get(message)
        if kind is None:
            continue

        # Two shapes of target in the log: a TCP CONNECT logs `authority`, and
        # everything reached through the RFC 9298 template logs `host` and
        # `port` separately.
        if "authority" in fields:
            host, port = split_authority(unquote(fields["authority"]))
        else:
            host = unquote(fields.get("host", ""))
            raw_port = fields.get("port", "")
            port = int(raw_port) if raw_port.isdigit() else None

        record = {
            "at_us": stamp,
            "kind": kind,
            "version": running.get(pid, "unknown"),
            "target": targets.key(f"{host}:{port}"),
            "port_class": port_class(port),
            "name_len": len(host),
            "literal": is_literal(host),
        }
        tunnels.append(record)

        open_here = [key for key in live if key[0] == pid]
        if len(open_here) == 1:
            connection = live[open_here[0]]
            connection.solo_tunnels += 1
            connection.solo_targets.append(record["target"])
            if connection.last_solo_us is not None:
                connection.solo_gaps_us.append(stamp - connection.last_solo_us)
            connection.last_solo_us = stamp
        else:
            unattributed += 1

    return {
        "connections": connections,
        "tunnels": tunnels,
        "restarts": restarts,
        "goaways": goaways,
        "oversize_drops": oversize_drops,
        "datagram_evictions": datagram_evictions,
        "versions": versions,
        "distinct_targets": len(targets),
        "distinct_peers": len(peers),
        "tunnels_unattributed": unattributed,
    }


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------

# A 1-2-5 ladder. Readable in a diff, dense enough near zero that a
# sub-millisecond gap and a ten-second one land in different buckets, and it
# spans the whole range every quantity here needs without a per-quantity
# choice.
def ladder(limit: float) -> list[int]:
    edges = [0]
    step = 1
    while step <= limit:
        for factor in (1, 2, 5):
            value = step * factor
            if value <= limit:
                edges.append(value)
        step *= 10
    return edges


def summarize(values: list[int | float], unit: str) -> dict:
    """A distribution as both order statistics and a bucket histogram.

    The order statistics are what a human reads; the buckets are what the
    replayer samples from, which is why both are here. A bucket is `[lower
    bound, count]` and runs to the next bucket's lower bound.
    """
    if not values:
        return {"unit": unit, "n": 0}

    ordered = sorted(values)
    count = len(ordered)

    def at(fraction: float):
        index = min(count - 1, max(0, int(round(fraction * (count - 1)))))
        return ordered[index]

    edges = ladder(max(ordered[-1], 1))
    counts = [0] * len(edges)
    for value in ordered:
        # The ladder is short (about 30 entries), so a scan beats a bisect
        # import and reads better.
        slot = 0
        for index, edge in enumerate(edges):
            if value >= edge:
                slot = index
            else:
                break
        counts[slot] += 1

    return {
        "unit": unit,
        "n": count,
        "min": ordered[0],
        "max": ordered[-1],
        "mean": round(sum(ordered) / count, 3),
        "p50": at(0.50),
        "p90": at(0.90),
        "p99": at(0.99),
        "buckets": [[edge, hits] for edge, hits in zip(edges, counts) if hits],
    }


def rarefaction(connections: list[Connection]) -> dict:
    """How many distinct targets a connection has seen after n tunnels.

    Measured over solo epochs only, and reported as the mean over every
    connection whose solo-attributed sequence reached n, together with how many
    connections that was. A replayer reads it as a probability that the next
    tunnel goes somewhere new: `p_new(n) = distinct(n + 1) - distinct(n)`.

    The ladder stops where the sample does: a mean over three connections is
    not worth publishing, so a step needs at least `MIN_SAMPLES` of them.
    """
    MIN_SAMPLES = 8

    steps = [1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597]
    sequences = [
        connection.solo_targets for connection in connections if connection.solo_targets
    ]

    curve = []
    for step in steps:
        reaching = [sequence for sequence in sequences if len(sequence) >= step]
        if len(reaching) < MIN_SAMPLES:
            break
        distinct = [len(set(sequence[:step])) for sequence in reaching]
        curve.append([step, round(sum(distinct) / len(distinct), 3), len(reaching)])

    return {
        "note": (
            "distinct targets after n tunnels on one connection, measured over "
            "solo epochs; entries are [n, mean distinct, connections sampled]"
        ),
        "curve": curve,
    }


def joint(connections: list[Connection]) -> dict:
    """How a connection's ending, lifetime and tunnel count go together.

    Three separate distributions are not enough to plan a replay from, because
    the three are strongly dependent and the dependence is the interesting part:
    a connection the idle timer ended lived at least one idle timeout by
    definition, and a connection that carried ten thousand tunnels did not do it
    in two seconds. Sampling them independently produces connections production
    could not contain -- an idle close after 40 ms, ten thousand tunnels in a
    one-second window -- and a replay full of those is a replay of nothing.

    So the three are published as one contingency table: each row is an outcome,
    a lifetime bucket, a tunnel-count bucket and how many connections landed in
    that cell. A planner draws a row in proportion to its count and gets all
    three at once, correlated exactly as the capture had them.

    Only connections whose closing line carried a tunnel count can be in it; a
    profile whose releases predate that field gets an empty table and a planner
    has to fall back on the marginals.
    """
    lifetime_edges = ladder(1_000_000_000)
    tunnel_edges = ladder(1_000_000)

    def bucket(edges: list[int], value: float) -> tuple[int, int]:
        slot = 0
        for index, edge in enumerate(edges):
            if value >= edge:
                slot = index
            else:
                break
        low = edges[slot]
        high = edges[slot + 1] if slot + 1 < len(edges) else max(low * 2, low + 1)
        return low, high

    cells: Counter = Counter()
    for connection in connections:
        if connection.closed_us is None or connection.tunnels is None:
            continue
        lifetime_ms = (connection.closed_us - connection.opened_us) // 1000
        low_life, high_life = bucket(lifetime_edges, lifetime_ms)
        low_tun, high_tun = bucket(tunnel_edges, connection.tunnels)
        cells[(connection.outcome, low_life, high_life, low_tun, high_tun)] += 1

    rows = [
        [outcome, low_life, high_life, low_tun, high_tun, count]
        for (outcome, low_life, high_life, low_tun, high_tun), count in sorted(
            cells.items(), key=lambda item: (item[0][0], item[0][1], item[0][3])
        )
    ]

    return {
        "note": (
            "rows are [outcome, lifetime ms low, lifetime ms high, tunnels low, "
            "tunnels high, connections]; draw a row in proportion to its count "
            "to get an outcome, a lifetime and a tunnel count that belong "
            "together"
        ),
        "connections": sum(cells.values()),
        "rows": rows,
    }


def popularity(tunnels: list[dict]) -> dict:
    """How concentrated the target set is, without naming anything.

    The replayer needs to know that a handful of targets take most of the
    traffic -- reusing one connection's targets is what makes a replay's DNS and
    socket behaviour look like production rather than like a scan.
    """
    counts = Counter(record["target"] for record in tunnels)
    total = sum(counts.values())
    if total == 0:
        return {"distinct": 0}

    ranked = [count for _, count in counts.most_common()]
    shares = {}
    for top in (1, 5, 10, 50, 100, 500):
        if top <= len(ranked):
            shares[f"top_{top}"] = round(sum(ranked[:top]) / total, 4)

    return {
        "distinct": len(counts),
        "tunnels": total,
        "share_of_tunnels": shares,
        "requests_per_target": summarize(ranked, "tunnels"),
    }


def bursts(stamps: list[int], within_us: int, least: int) -> dict:
    """Clusters of connection arrivals: what a client restarting looks like.

    A proxy client that restarts drops every connection it held and opens
    replacements within a second or two, so a burst of establishments is the
    server-side signature of one. Reported as the burst-size distribution and
    the gaps between bursts, which is what a replayer needs to schedule them.
    """
    if not stamps:
        return {"bursts": 0}

    sizes: list[int] = []
    starts: list[int] = []
    current = [stamps[0]]
    for stamp in stamps[1:]:
        if stamp - current[-1] <= within_us:
            current.append(stamp)
        else:
            if len(current) >= least:
                sizes.append(len(current))
                starts.append(current[0])
            current = [stamp]
    if len(current) >= least:
        sizes.append(len(current))
        starts.append(current[0])

    gaps = [(b - a) // 1000 for a, b in zip(starts, starts[1:])]
    return {
        "window_ms": within_us // 1000,
        "least": least,
        "bursts": len(sizes),
        "size": summarize(sizes, "connections"),
        "gap_between_bursts": summarize(gaps, "ms"),
    }


def by_release(connections: list[Connection], tunnels: list[dict]) -> dict:
    """The same headline numbers, one row per server release in the capture.

    A capture long enough to be worth taking spans several releases, and the
    numbers an operator watches are quoted per release -- a protocol-violation
    rate is only meaningful against the build that produced it. Rolling the
    whole window into one figure would average a fixed release together with the
    one that had the bug.
    """
    attempts = Counter(record["version"] for record in tunnels)
    rows: dict[str, dict] = {}

    for version in sorted(set(attempts) | {c.version for c in connections}):
        here = [c for c in connections if c.version == version]
        if not here:
            continue
        violations = sum(1 for c in here if c.outcome == "protocol_violation")
        seen = attempts.get(version, 0)
        rows[version] = {
            "connections": len(here),
            "tunnel_attempts": seen,
            "violations": violations,
            "violations_per_1000_tunnel_attempts": (
                round(1000 * violations / seen, 4) if seen else None
            ),
            "violations_per_1000_connections": round(1000 * violations / len(here), 4),
        }

    return rows


def build_profile(name: str, world: dict, counts: dict, sources: list[str]) -> dict:
    connections: list[Connection] = world["connections"]
    tunnels: list[dict] = world["tunnels"]

    if not connections or not tunnels:
        raise SystemExit("no connections or tunnels were found in the input")

    first = min(min(c.opened_us for c in connections), tunnels[0]["at_us"])
    last = max(max(c.closed_us or c.opened_us for c in connections), tunnels[-1]["at_us"])
    span_s = max(1.0, (last - first) / 1_000_000)

    opened = sorted(c.opened_us for c in connections)
    interarrival = [(b - a) // 1000 for a, b in zip(opened, opened[1:])]
    lifetimes = [
        (c.closed_us - c.opened_us) // 1000 for c in connections if c.closed_us is not None
    ]

    outcomes = Counter(c.outcome for c in connections if c.outcome)
    violations = [c for c in connections if c.outcome == "protocol_violation"]

    tunnel_counts = [c.tunnels for c in connections if c.tunnels is not None]
    tunnels_reported = sum(tunnel_counts)

    kinds = Counter(record["kind"] for record in tunnels)
    established = kinds["tcp"] + kinds["udp"]

    # Concurrency, sampled at every connection event rather than on a clock: an
    # arrival or a departure is the only moment the number can change.
    marks: list[tuple[int, int]] = []
    for connection in connections:
        marks.append((connection.opened_us, 1))
        if connection.closed_us is not None:
            marks.append((connection.closed_us, -1))
    marks.sort()
    live = 0
    concurrency: list[int] = []
    for _, delta in marks:
        live += delta
        concurrency.append(live)

    solo_gaps = [gap // 1000 for c in connections for gap in c.solo_gaps_us]
    solo_tunnels = sum(c.solo_tunnels for c in connections)

    bytes_per_tunnel = [
        (c.tx_bytes + c.rx_bytes) // c.tunnels
        for c in connections
        if c.tx_bytes is not None and c.rx_bytes is not None and c.tunnels
    ]

    loss_permille = [
        round(1000 * c.lost_packets / c.sent_packets, 3)
        for c in connections
        if c.sent_packets and c.lost_packets is not None
    ]

    return {
        "schema": "volto.traffic-shape/1",
        "name": name,
        "source": {
            "files": len(sources),
            "lines_read": counts.get("lines_read", 0),
            "lines_kept": counts.get("lines_kept", 0),
            "lines_duplicate": counts.get("lines_duplicate", 0),
            "lines_other_unit": counts.get("lines_other_unit", 0),
            "lines_decoloured": counts.get("lines_decoloured", 0),
            "lines_not_tracing": counts.get("lines_unparsed", 0),
            "window_seconds": round(span_s, 1),
            "window_days": round(span_s / 86400, 2),
            "server_restarts": len(world["restarts"]),
            "server_versions": sorted(world["versions"]),
            "distinct_targets": world["distinct_targets"],
            "distinct_client_addresses": world["distinct_peers"],
            "note": (
                "aggregates only; no name, address or log line from the input "
                "survives into this file"
            ),
        },
        "connections": {
            "count": len(connections),
            "per_hour": round(3600 * len(connections) / span_s, 3),
            "interarrival": summarize(interarrival, "ms"),
            "lifetime": summarize(lifetimes, "ms"),
            "concurrency": summarize(concurrency, "connections"),
            "outcome": dict(outcomes.most_common()),
            "outcome_share": {
                key: round(value / len(connections), 5)
                for key, value in outcomes.most_common()
            },
            "lifetime_by_outcome": {
                outcome: summarize(
                    [
                        (c.closed_us - c.opened_us) // 1000
                        for c in connections
                        if c.outcome == outcome and c.closed_us is not None
                    ],
                    "ms",
                )
                for outcome in outcomes
            },
            "joint": joint(connections),
            "migrated": sum(1 for c in connections if c.migrated),
            "goaways_sent": world["goaways"],
            "rtt_at_open": summarize(
                [c.rtt_open_ms for c in connections if c.rtt_open_ms is not None], "ms"
            ),
            "rtt_at_close": summarize(
                [c.rtt_close_ms for c in connections if c.rtt_close_ms is not None], "ms"
            ),
            "mtu_at_close": summarize(
                [c.mtu for c in connections if c.mtu is not None], "bytes"
            ),
            "mtu_black_holes": summarize(
                [c.mtu_black_holes for c in connections if c.mtu_black_holes is not None],
                "events",
            ),
            "tx_bytes": summarize(
                [c.tx_bytes for c in connections if c.tx_bytes is not None], "bytes"
            ),
            "rx_bytes": summarize(
                [c.rx_bytes for c in connections if c.rx_bytes is not None], "bytes"
            ),
            "sent_packets": summarize(
                [c.sent_packets for c in connections if c.sent_packets is not None],
                "packets",
            ),
            "loss_permille": summarize(loss_permille, "per thousand packets"),
            "dropped_datagrams": summarize(
                [
                    c.dropped_datagrams
                    for c in connections
                    if c.dropped_datagrams is not None
                ],
                "datagrams",
            ),
        },
        "tunnels": {
            "attempts_logged": len(tunnels),
            "attempts_per_hour": round(3600 * len(tunnels) / span_s, 2),
            "reported_by_closing_lines": tunnels_reported,
            "kind": dict(kinds.most_common()),
            "udp_share_of_established": (
                round(kinds["udp"] / established, 5) if established else 0.0
            ),
            "blackhole_share_of_attempts": round(kinds["blackhole"] / len(tunnels), 5),
            "policy_denied_share_of_attempts": round(
                kinds["policy_denied"] / len(tunnels), 5
            ),
            "literal_share_of_attempts": round(
                sum(1 for r in tunnels if r["literal"]) / len(tunnels), 5
            ),
            "port_class": dict(Counter(r["port_class"] for r in tunnels).most_common()),
            "name_length": summarize(
                [r["name_len"] for r in tunnels if not r["literal"]], "characters"
            ),
            "per_connection": summarize(tunnel_counts, "tunnels"),
            "per_connection_coverage": round(len(tunnel_counts) / len(connections), 4),
            "transport_bytes_per_tunnel": summarize(bytes_per_tunnel, "bytes"),
            "spacing_within_connection": {
                "note": (
                    "gaps between consecutive tunnels on one connection, "
                    "measured over solo epochs only"
                ),
                "attributed": solo_tunnels,
                "attributed_share": round(solo_tunnels / len(tunnels), 4),
                "gap": summarize(solo_gaps, "ms"),
            },
            "fanout": rarefaction(connections),
            "popularity": popularity(tunnels),
        },
        "restarts": {
            "note": (
                "a client restarting drops every connection it held and opens "
                "replacements at once, so a burst of establishments is its "
                "server-side signature"
            ),
            "client_bursts": bursts(opened, 5_000_000, 4),
            "server_restarts": len(world["restarts"]),
        },
        "violations": {
            "note": (
                "connections the peer closed with H3_GENERAL_PROTOCOL_ERROR; "
                "the server-visible half of a client-reported protocol violation. "
                "Rate it against tunnel attempts, which are counted from the "
                "tunnel lines themselves and are complete; the closing line's "
                "own tunnel count is a newer field and covers only part of a "
                "multi-release capture"
            ),
            "count": len(violations),
            "per_1000_connections": round(1000 * len(violations) / len(connections), 4),
            "per_1000_tunnel_attempts": round(1000 * len(violations) / len(tunnels), 4),
            "per_1000_reported_tunnels": (
                round(1000 * len(violations) / tunnels_reported, 4)
                if tunnels_reported
                else None
            ),
            "offset_from_connection_start": summarize(
                [
                    (c.closed_us - c.opened_us) // 1000
                    for c in violations
                    if c.closed_us is not None
                ],
                "ms",
            ),
            "tunnels_at_violation": summarize(
                [c.tunnels for c in violations if c.tunnels is not None], "tunnels"
            ),
            "transport_bytes_at_violation": summarize(
                [
                    c.tx_bytes + c.rx_bytes
                    for c in violations
                    if c.tx_bytes is not None and c.rx_bytes is not None
                ],
                "bytes",
            ),
        },
        "datagrams": {
            "oversize_drops_logged": world["oversize_drops"],
            "send_buffer_evictions_logged": world["datagram_evictions"],
        },
        "by_server_version": by_release(connections, tunnels),
    }


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("logs", nargs="+", help="log files, plain or .gz")
    parser.add_argument(
        "--name", required=True, help="profile name; pick one that names no host"
    )
    parser.add_argument("--out", required=True, help="where to write the JSON profile")
    parser.add_argument(
        "--unit",
        default="volto",
        help="systemd unit whose lines to keep, or 'any' (default: volto)",
    )
    parser.add_argument(
        "--events",
        help=(
            "also write the anonymized per-tunnel dump here; it carries target "
            "indices, so it is working material and must not be committed"
        ),
    )
    args = parser.parse_args(argv)

    events, counts = read_events(args.logs, None if args.unit == "any" else args.unit)
    if not events:
        raise SystemExit("no volto log lines were found in the input")

    world = reconstruct(events)
    profile = build_profile(args.name, world, counts, args.logs)

    with open(args.out, "w") as handle:
        json.dump(profile, handle, indent=2, sort_keys=False)
        handle.write("\n")

    if args.events:
        with open(args.events, "w") as handle:
            handle.write(
                "# volto tunnel shapes, anonymized. Working material: not for "
                "the repository.\n"
            )
            for record in world["tunnels"]:
                handle.write(json.dumps(record, sort_keys=True) + "\n")

    source = profile["source"]
    print(
        f"{args.name}: {source['lines_kept']} lines over "
        f"{source['window_days']} days -> {profile['connections']['count']} "
        f"connections, {profile['tunnels']['attempts_logged']} tunnel attempts, "
        f"{profile['violations']['count']} protocol violations "
        f"({profile['violations']['per_1000_tunnel_attempts']} per 1000 tunnel "
        f"attempts)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
