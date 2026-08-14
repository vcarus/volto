# Configuration

volto reads one TOML file, named with `--config`:

```sh
volto --config /etc/volto/config.toml
```

Only `[server]` is required; every other section and key has a default. Unknown
keys are an error at startup rather than being silently ignored, so a typo fails
loudly. A commented reference file ships as
[`script/config.example.toml`](../script/config.example.toml).

`SIGHUP` re-reads the file. A file that fails to parse or validate is rejected
whole and the running configuration keeps serving; see
[deployment.md](deployment.md#reloading).

## `[server]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `listen` | string | required | UDP address to listen on, e.g. `"0.0.0.0:443"`. QUIC is UDP; there is no TCP listener |
| `cert` | path | required | PEM certificate chain, leaf first |
| `key` | path | required | PEM private key (PKCS#8, PKCS#1 or SEC1) |
| `alpn` | array of strings | `["h3"]` | ALPN identifiers to advertise, in preference order. Change only for interop debugging |
| `shutdown_grace` | seconds | `30` | How long established tunnels may finish after SIGTERM. systemd's `TimeoutStopSec` must be larger |

## `[auth]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `users` | array of tables | `[]` | List of `{ username, password }`. **An empty list disables authentication and makes this an open proxy**; volto warns at startup when that is the case |

A username may not contain a colon (RFC 7617). Credentials are compared in
constant time. Both `Proxy-Authorization` (preferred) and `Authorization` are
accepted, because Surge's manual does not say which it sends; a failed check is
answered with 407 and `Proxy-Authenticate: Basic`.

## `[limits]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `udp_session_timeout` | seconds | `180` | Idle timeout for a UDP session. RFC 9298 §3.1 says a proxy SHOULD NOT go below 120; volto warns if you do |
| `max_targets_per_conn` | integer | `256` | Concurrent tunnels on one QUIC connection, TCP and UDP sharing the budget. Beyond it, requests get 503 with `Proxy-Status: volto; error=connection_limit_reached` |
| `max_connections` | integer | `256` | Simultaneously open QUIC connections; `0` removes the limit. Excess connections are refused during the handshake, before any per-connection state exists here |
| `max_streams_bidi` | integer | `1024` | Concurrent bidirectional streams per connection — one per tunnel. quinn's own default of 100 runs out during ordinary browsing |
| `max_idle_timeout` | seconds | `60` | How long a connection may go without traffic before it is closed. Range 1..3600 |
| `keep_alive_interval` | seconds | `20` | Keep-alive period; `0` switches it off. **Must be strictly less than `max_idle_timeout / 2`**, or startup and reload fail |
| `initial_mtu` | bytes | `1200` | Size of the first QUIC packets. **Below 1200 is an error** (RFC 9000 §14) rather than a silent round-up |
| `mtu_discovery` | bool | `true` | Probe for a larger path MTU (RFC 8899 DPLPMTUD). `false` pins the packet size at `initial_mtu`: slower, but deterministic |
| `congestion_control` | string | `"bbr"` | QUIC congestion controller: `bbr`, `cubic` or `newreno` |
| `initial_rtt_ms` | milliseconds | `333` | Round-trip time assumed before the first measurement. Range 10..10000 |

### Notes that matter in practice

**The fd budget is one number split in two.** Every tunnel costs one file
descriptor, so `max_targets_per_conn` and systemd's `LimitNOFILE` are two halves
of the same budget. The defaults line up deliberately: 256 connections × 256
tunnels = 65536, the `LimitNOFILE` in the shipped unit. volto warns at startup
when `RLIMIT_NOFILE` leaves no margin.

**The last six keys are QUIC transport parameters and apply to new connections
only.** A reload carries them to connections accepted from then on; connections
already open keep what they negotiated at handshake time, because QUIC cannot
renegotiate transport parameters.

**`keep_alive_interval` is validated as strictly below half the idle timeout,
not at most half.** At exactly half, losing a single keep-alive packet is enough
for the connection to time out. This pairing is what keeps a NAT mapping alive
across an idle period; see
[running behind a UDP relay](deployment.md#running-behind-a-udp-relay).

**`congestion_control` should usually stay on BBR.** Over a long, lossy path a
loss-based controller (cubic, newreno) reads every dropped packet as congestion
and collapses the window — downloads stall to near zero while a co-located TCP
proxy, which the kernel runs on BBR, is unaffected. BBR models bandwidth and RTT
instead. Switch to cubic only on a clean path, or as a fallback.

**`initial_rtt_ms` seeds the handshake retransmission timers.** Until the first
ACK arrives there is no RTT sample, and a lost handshake packet waits roughly
three times this value before it is resent. The default of 333 comes from
RFC 9002 and is deliberately conservative. On a known path, set 1.5–2× the RTT
that volto's connection logs report as `rtt_ms` — a measured ~90 ms path wants
about 150 — which cuts the worst-case handshake stall from about a second to a
few hundred milliseconds. Keep the margin: a value below the real RTT makes the
timer fire early and retransmit packets that were never lost.

## `[security]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `allow_private_networks` | bool | `false` | Allow tunnels to loopback, RFC 1918, link-local and ULA addresses. Keep it off on a public deployment |
| `denied_ports` | array of integers | `[25]` | Target ports refused regardless of address, answered with 403. **Do not add 53** (see below) |
| `unanswered_packet_budget` | integer | `64` | Packets a UDP session may send before its target has answered; `0` disables the mitigation |
| `max_auth_failures` | integer | `5` | Authentication failures tolerated on one connection before it is dropped; `0` disables it |

- Addresses are normalized before matching, so neither `::ffff:127.0.0.1` nor
  `::127.0.0.1` gets past `allow_private_networks = false`.
- Multicast, broadcast and the unspecified address are refused **regardless** of
  that setting. They are amplification primitives, not destinations.
- **UDP/53 must stay reachable.** Surge's UDP availability test is a DNS query
  through the tunnel, so denying port 53 makes Surge report the policy as broken.
  volto warns if 53 appears in `denied_ports`.
- `unanswered_packet_budget` stops a client using the proxy as a reflector or a
  port scanner (RFC 9298 §7). The first reply from the target lifts the limit for
  the rest of the session, so it only bites on one-way floods. The default is
  generous on purpose: handshakes that legitimately need several packets before
  the first reply must not break.
- `max_auth_failures` is not a rate limit and not a ban. It raises the cost of
  guessing from "one handshake, then unlimited attempts" to "one handshake per N
  attempts", without any cross-connection state to keep or evict. Pair it with
  fail2ban for actual banning — see [deployment.md](deployment.md#fail2ban).

## `[log]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `level` | string | `"info"` | A bare level (`trace`/`debug`/`info`/`warn`/`error`) or a directive list such as `"volto=debug,quinn=info"`. `RUST_LOG` overrides it |
| `keylog` | bool | `false` | Write TLS secrets to the file named by `SSLKEYLOGFILE`. Debugging only; volto warns while it is on |

At `debug`, every inbound request is logged with its method, path, `:protocol`
and header lines. Credential *values* are replaced with
`<scheme> <redacted N bytes>`, but the header names are kept — that is what makes
the log usable for confirming which authorization header a client actually sends.

A keylog file decrypts **every** session through the proxy, including sessions
already recorded. Turn it off and delete the file when you are done.

Under systemd, volto prefixes each line with a syslog priority (`<3>` for ERROR,
`<4>` for WARN, `<6>` for INFO, `<7>` for DEBUG and TRACE). journald parses that
prefix, strips it, and files the record with the matching `PRIORITY`, so
`journalctl -u volto -p warning` selects what it says it does instead of matching
everything. The prefix appears only when systemd sets `JOURNAL_STREAM`, so
running volto in a terminal prints the same lines it always did, and the shipped
unit needs no extra setting (`SyslogLevelPrefix=` already defaults to true).

One refusal is deliberately quieter than its neighbours. A target whose every
resolved address is `0.0.0.0` or `::` is a name a filtering resolver has
blackholed, so it is logged at INFO; the response is the same 403 either way. A
target that resolves to loopback, private or mixed addresses stays a WARN,
because that is what a probe for internal services looks like from here.

## A minimal file

```toml
[server]
listen = "0.0.0.0:443"
cert   = "/etc/volto/fullchain.pem"
key    = "/etc/volto/privkey.pem"

[auth]
users = [{ username = "user1", password = "…" }]
```
