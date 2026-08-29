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
| `shutdown_grace` | seconds | `5` | How long established tunnels may finish after SIGTERM. Range 0..3600, where `0` closes every tunnel at once. Kept short because a client that keeps using a connection after GOAWAY (Surge does) has its new requests fail for the whole drain. systemd's `TimeoutStopSec` must be larger — and the ceiling is there because the value is a bound: a drain longer than an hour has outlived any service manager's patience, so it would only replace the graceful ending with a `SIGKILL` |

## `[auth]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `users` | array of tables | `[]` | List of `{ username, password }`. **An empty list disables authentication and makes this an open proxy**; volto warns at startup when that is the case |

A username may not contain a colon (RFC 7617), and may not be longer than 32
bytes — the length a user-id is carried at in a log line, and therefore the
length authentication failures are bucketed under, so a longer name could never
have its failures cleared by its own success. Credentials are compared in
constant time. Both `Proxy-Authorization` (preferred) and `Authorization` are
accepted, because Surge's manual does not say which it sends; a failed check is
answered with 407 and `Proxy-Authenticate: Basic`.

## `[limits]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `udp_session_timeout` | seconds | `180` | Idle timeout for a UDP session, where idle means no packet crossed the proxy in either direction: a payload reaching the target or the target answering re-arms it, while bytes that complete nothing — a capsule still being assembled or skipped, packets a budget or a full queue dropped — do not, so a peer cannot hold a session's socket and buffers open by dripping. RFC 9298 §3.1 says a proxy SHOULD NOT go below 120 (volto warns if you do), and the ceiling is 3600. Also bounds each write in a half-closed TCP tunnel's surviving direction: one that does not complete within it cuts the tunnel, while a half-closed tunnel parked in a read is left alone (see the architecture doc) |
| `max_targets_per_conn` | integer | `256` | Concurrent tunnels on one QUIC connection, TCP and UDP sharing the budget. Beyond it, requests get 503 with `Proxy-Status: volto; error=connection_limit_reached` |
| `max_connections` | integer | `256` | Simultaneously open QUIC connections; `0` removes the limit and never evicts. At the cap a new connection takes the slot of the oldest connection that has never had a request pass the credentials check — closed with `H3_NO_ERROR` and logged with `reason=evicted` — so a peer that keeps handshaking without ever authenticating cannot hold the server shut. Only a newcomer whose address QUIC has validated may evict: at the cap an unvalidated one is answered with a Retry (RFC 9000 §8.1) and takes no slot, which costs a spoofed Initial the flood it was for. A client that has connected before pays nothing — it returns a NEW_TOKEN token (RFC 9000 §8.1.3) and is already validated — so the extra round trip falls on first contact, on a token older than two weeks, and on the first reconnection after a restart or `SIGHUP`, and only while the server is full. Only when every live connection has authenticated is the newcomer refused during the handshake, before any per-connection state exists here |
| `connect_timeout` | seconds | `10` | Budget for reaching a target; `0` disables it, and the ceiling is 3600. Spent twice per request and separately — once on name resolution, once on the whole list of addresses it resolved to — so a request holds its tunnel slot for at most twice this before any byte flows. A lookup that runs out answers 504 with `Proxy-Status: volto; error=dns_timeout`, a connect that runs out answers 504 with `error=connection_timeout` |
| `ip_family_preference` | string | `"ipv4"` | Which address family a resolved target name is tried on first: `ipv4`, `ipv6` or `system` (the resolver's own RFC 6724 order). Applies to both tunnel kinds |
| `max_streams_bidi` | integer | `1024` | Concurrent bidirectional streams per connection — one per tunnel. Range 1..65536, and the ceiling is there because of where the cost falls: a stream slot is reserved for every unit of the credit when a connection is *created*, not when a stream is opened, so the value is work every handshake pays for — roughly 11 ms at the default, 135 ms at the ceiling and 7 s at a million on the dev host. quinn's own default of 100 runs out during ordinary browsing. The peer's *unidirectional* streams are not a key: they are fixed at 16 (`MAX_PEER_UNI_STREAMS` in `quic.rs`), where HTTP/3 needs exactly three — the control stream and the QPACK encoder/decoder pair, RFC 9114 §6.2 and RFC 9204 §4.2. Exceeding a transport parameter is a QUIC-level failure with no HTTP-level explanation attached, which is why there is margin rather than three |
| `max_idle_timeout` | seconds | `60` | How long a connection may go without traffic before it is closed. Range 1..3600. It also bounds every application-level wait that precedes a tunnel, whatever the connection's authentication state: the QUIC/TLS handshake, the HTTP/3 handshake, the read of each peer unidirectional stream's type, the read of a request stream's HEADERS, and every refusal this proxy writes. A separate bound of twice this applies only while a connection has never had a request pass the credentials check — counted from the handshake and never re-armed by a new stream, so it bounds the connection rather than a pause in it — and is lifted for good once a request authenticates, so a client that keeps an idle connection between requests is unaffected |
| `keep_alive_interval` | seconds | `20` | Keep-alive period; `0` switches it off. **Must be strictly less than `max_idle_timeout / 2`**, or startup and reload fail |
| `initial_mtu` | bytes | `1200` | Size of the first QUIC packets — a *UDP payload* size, not an IP packet size. Range 1200..1452. **Below 1200 is an error** (RFC 9000 §14) rather than a silent round-up; above 1452 is an error too, because an Ethernet frame leaves 1452 bytes of payload over IPv6 (1472 over IPv4) and quinn applies `initial_mtu` with no ceiling of its own — so a handshake sent in packets no path carries leaves the server unreachable with nothing to fall back to. That failure mode is what separates this key from `mtu_upper_bound`: this value is sent blind, before any feedback channel exists to correct it |
| `mtu_discovery` | bool | `true` | Probe for a larger path MTU (RFC 8899 DPLPMTUD). `false` stops the upward search, so packets stay at `initial_mtu` — except that quinn's black-hole detector still runs and can drop them to the 1200-byte floor for the rest of the connection, with nothing to bring them back up. Slower, but predictable |
| `mtu_upper_bound` | bytes | `1452` | Ceiling for the MTU discovery search — a *UDP payload* size like `initial_mtu`. Range `initial_mtu`..1472. The default is the value safe over both IPv4 and IPv6 on Ethernet; an operator who has measured their path (`ping -M do`, `tracepath`) can claim what IPv4 leaves above that, at most 1472. Safe to overshoot, unlike `initial_mtu`: a size is only adopted after a probe of that size is acknowledged, and a lost probe is retried then abandoned without counting as congestion, so a bound above what the path carries costs a few PINGs and nothing else. No effect (and a startup warning) when `mtu_discovery` is off |
| `congestion_control` | string | `"bbr"` | QUIC congestion controller: `bbr`, `cubic` or `newreno` |
| `initial_rtt_ms` | milliseconds | `333` | Round-trip time assumed before the first measurement. Range 10..10000 |
| `socket_recv_buffer` | bytes | `2097152` | UDP socket receive buffer to request when the socket is created; `0` leaves the operating system's own value alone. Capped by `net.core.rmem_max`, and volto warns at startup when it was capped |
| `socket_send_buffer` | bytes | `2097152` | The same on the way out, capped by `net.core.wmem_max` |

### Notes that matter in practice

**The fd budget is one number split in two.** Every tunnel costs one file
descriptor, so `max_targets_per_conn` and systemd's `LimitNOFILE` are two halves
of the same budget. What volto compares against `RLIMIT_NOFILE` at startup is
`max_connections` × `max_targets_per_conn` **plus 64 descriptors of headroom**
for the listening socket, the request streams and a certificate reload — 65600
for the defaults, which the shipped unit's `LimitNOFILE=131072` has room for.
Raise either limit past that point and `LimitNOFILE` has to go up with it, or
the startup warning fires.

**A CONNECT-UDP session costs memory as well as a descriptor**, and only the
descriptors are checked at startup. Each session holds two buffers for its whole
life: a 64 KiB receive buffer for the packets it reads off its target socket —
it cannot be smaller, because a `recv` into a short buffer truncates the packet
silently — and an inbound datagram queue of 64 entries, each at most the
1472-byte `max_udp_payload_size` this server advertises, so about 92 KiB. That
is roughly 156 KiB per session, 39 MiB per connection at
`max_targets_per_conn = 256`, and about 9.8 GiB across a server saturated at
both defaults. Lowering either limit lowers it proportionally. It is a ceiling
rather than a resting size because the queue is only full while a client sends
faster than the proxy forwards.

**A TCP tunnel costs less, not nothing.** Its relay buffer starts at 16 KiB, and
settles on a single 64 KiB block once the tunnel has relayed anything: reads are
cut from one block until too little of it is left to offer a full-sized window,
and that is also why the first 16 KiB is let go after the first read. So the
saturation product for TCP is `max_connections` × `max_targets_per_conn` ×
64 KiB = 4 GiB at the defaults, beside the 9.8 GiB of the UDP one. What a tunnel
holds beyond that one block is bounded by quinn's per-connection send window:
the pieces cut from a block share it, and each is held until the segment
carrying it has been acknowledged, so the block outlives them all.

**`connect_timeout` is spent per request, not per connection.** Without it a
target that silently drops SYNs holds a tunnel slot and its file descriptor for
as long as the operating system keeps retrying — around two minutes on Linux —
so a handful of black-holed addresses during ordinary browsing can spend a
connection's whole `max_targets_per_conn` on tunnels that will never open. No
attacker is needed for that. A reload carries a new value to connections
accepted from then on, and each request those connections make gets the budget
afresh; connections already open keep the value they were accepted with, like
the rest of the per-connection policy. Set it to `0` only to hand the wait back
to the operating system — and know what that hands back: a client that resets a
request stream while its target is still being dialled does not cancel the dial,
so with the budget off the slot stays spent until the kernel gives up. volto
warns at startup when the budget is off.

**`connect_timeout` bounds the answer, not the resolver.** A lookup that runs
out of budget is answered 504 immediately, but the `getaddrinfo` call behind it
cannot be cancelled and keeps its thread until the system resolver gives up. The
server bounds that separately: every connection has a name-lookup slot reserved
for it that nothing else can take, plus a capped share of a server-wide
allowance, so a client aiming at names that never resolve cannot stop anyone
else's names from resolving. Nothing is configurable there, and nothing changes
on the wire — the refusals are the same 504 `dns_timeout` they always were.

**`max_connections` also sizes the blocking thread pool, at startup only.** The
pool is given a thread for every reserved lookup slot the budget can hand out,
plus the shared allowance and headroom; threads are created on demand and reaped
when idle. A reload that raises `max_connections` takes effect for new
connections but does not resize the pool, which needs a restart.

**`max_streams_bidi`, `max_idle_timeout`, `keep_alive_interval`, `initial_mtu`,
`mtu_discovery`, `congestion_control` and `initial_rtt_ms` are QUIC transport
settings and apply to new connections only.** A reload carries them to
connections accepted from then on; connections already open keep what they
negotiated at handshake time, because QUIC cannot renegotiate transport
parameters. `ip_family_preference` is not a transport parameter, but it is
snapshotted the same way: a connection resolves every target with the preference
that was in force when it was accepted.

**The two socket buffer keys are startup-only, not reloadable at all.** They are
applied to the UDP socket when it is created, and a reload does not rebind that
socket — changing them needs a restart, the same as `[server].listen`. Each
request is capped by the host: `net.core.rmem_max` / `net.core.wmem_max` on
Linux, `kern.ipc.maxsockbuf` on macOS, and a host may fail the request outright
rather than clamping it. volto warns at startup, naming the sysctl, whenever it
got less than it asked for, and comes up on the operating system's default
either way. `0` asks for nothing and leaves that default in place. The reason
these keys exist at all is that quinn never calls `setsockopt` itself, so a
server that does not ask gets `net.core.rmem_default` — around 208 KiB —
however high `rmem_max` has been raised; see
[UDP socket buffers](deployment.md#udp-socket-buffers).

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

**Path MTU discovery reports what it found in the connection close line.** The
`INFO ... connection closed` and `WARN ... connection closed with error` lines
carry `mtu=`, the largest UDP payload the sender settled on for that path, and
`mtu_black_holes=`, how many times quinn's black-hole detector pushed it back to
the floor during the connection, next to `rtt_ms=` and `remote_now=`. Both are
reports, not knobs. A `mtu=` still at `initial_mtu` when a long-lived connection
ends means the DPLPMTUD probes were never acknowledged, which is what a path
that black-holes large packets looks like from here, and the case
`mtu_discovery = false` exists for; anything above `initial_mtu` is discovery
having done its job. The counter tells a fall-back apart from a path that never
got there: the detector is a heuristic over loss bursts, and full-size packets
lost to ordinary congestion during a bulk transfer look the same to it as a
path that stopped carrying them, after which the connection sends packets at
the 1200-byte floor for a one-minute cooldown before probing again. A
non-zero count on a path where other connections settle above the floor is
therefore that heuristic firing, not the path changing.

**Those lines also report what the connection carried.** Alongside `rtt_ms=`
and `mtu=` they carry `tunnels=`, how many requests on that connection were
granted a tunnel slot — TCP CONNECT and CONNECT-UDP draw on the same budget, and
a request turned away before the slot (407, a malformed message, the tunnel
limit itself) is not counted, while a destination the policy rejects and a
target that could not be reached both are, since the slot is taken before the
target is judged — and four transport counters. `tx_bytes=` and
`rx_bytes=` are UDP-level byte counts: everything this server put on or took off
the wire for that connection, QUIC and HTTP/3 framing, retransmissions,
acknowledgements and padding included. They are neither tunnel payload, which is
always smaller, nor bytes the peer acknowledged, since a packet is counted when
it is sent whether or not it arrived; read them as how much this connection
moved through the host, not as an accounting figure. `sent_packets=` and
`lost_packets=` are reported together because a loss rate needs both, and a
single count on its own says nothing about the path. `dropped_datagrams=` is
this server's own doing rather than the path's: inbound HTTP Datagrams the
connection's router dropped on purpose — an unknown Context ID, a Quarter
Stream ID no session claims, a session whose inbound queue was full, or a
datagram cut short of its Context ID — each of which the RFCs require or permit
to be silent where it happens, leaving this total as their only
production-visible trace. All of them come from one
snapshot taken as the connection ends, so they cost nothing while it is running.

**`initial_rtt_ms` seeds the handshake retransmission timers.** Until the first
ACK arrives there is no RTT sample, and a lost handshake packet waits roughly
three times this value before it is resent. The default of 333 comes from
RFC 9002 and is deliberately conservative. On a known path, set 1.5–2× the RTT
that volto's connection logs report as `rtt_ms` — a measured ~90 ms path wants
about 150 — which cuts the worst-case handshake stall from about a second to a
few hundred milliseconds. The example configuration in `script/` — and therefore
every install derived from it — ships 150 for that reason; the compiled-in
fallback used when the key is absent stays at 333. Keep the margin: a value
below the real RTT makes the timer fire early and retransmit packets that were
never lost.

**`ip_family_preference` decides which half of a dual-stack target is tried
first, and it is an operator's call rather than the resolver's.** `getaddrinfo`
sorts its answers by RFC 6724, which puts a global IPv6 address ahead of every
IPv4 one whenever the host has a usable IPv6 route — the right answer for a host
that is only a client of the internet, and the wrong one for a proxy whose IPv6
egress is tunnelled or worse peered than its native IPv4, which is a common
shape on a VPS. volto therefore defaults to `ipv4`. A TCP tunnel would otherwise
spend the whole IPv6 connect attempt before IPv4 is tried, and a CONNECT-UDP
session would not recover at all: its socket is connected to the first address
that has a route, and nothing later revisits that choice. Set `ipv6` when the
host's IPv6 path is the better one — native IPv6 with tunnelled or NATed IPv4 —
and `system` to hand the ordering back to the resolver, which on glibc can then
be shaped through `gai.conf`. The ordering is a stable partition, so whatever
RFC 6724 decided *within* a family still stands; a target that resolves to one
family, an IP literal above all, is unaffected by any of the three.

## `[security]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `allow_private_networks` | bool | `false` | Allow tunnels to address space RFC 6890 marks special-purpose: "this host on this network" (`0.0.0.0/8`), loopback, RFC 1918, link-local, shared address space (`100.64.0.0/10`), IETF protocol assignments (`192.0.0.0/24`), benchmarking (`198.18.0.0/15` and `2001:2::/48`), 6to4 relay anycast (`192.88.99.0/24`), reserved (`240.0.0.0/4`), the documentation ranges, ULA, ORCHID (`2001:10::/28`), the deprecated site-local `fec0::/10`, `2001:db8::/32` and `100::/64`. Keep it off on a public deployment |
| `denied_ports` | array of integers | `[25]` | Target ports refused regardless of address, answered with 403. **Do not add 53** (see below) |
| `unanswered_packet_budget` | integer | `64` | Packets a UDP session may send before its target has answered; `0` disables the mitigation |
| `max_auth_failures` | integer | `5` | Authentication failures tolerated on one connection before it is dropped; `0` disables it. Failures are counted in buckets — one per configured user-id that is guessed at, one shared by every user-id that is not configured, one for the requests that named nobody — and the connection goes when the **total** across them reaches this value. A request that authenticates clears **its own user's bucket and the credential-less one**, so failures cannot add up over the life of a working connection; it clears nothing else, so a peer holding one valid credential cannot buy back its guesses at a second user's password by interleaving a good request, and a scan for user-ids that do not exist is never cleared by anything |

- Addresses are normalized before matching, so neither `::ffff:127.0.0.1` nor
  `::127.0.0.1` gets past `allow_private_networks = false`.
- IPv6 transition addresses are judged by the IPv4 address they carry, because
  that is what a host routing them actually reaches: NAT64 (`64:ff9b::/96` and
  `64:ff9b:1::/48`), 6to4 (`2002::/16`) and Teredo (`2001::/32`). So
  `64:ff9b::7f00:1` is refused as the 127.0.0.1 it is, while `64:ff9b::808:808`
  is reachable as 8.8.8.8.
- Multicast, broadcast and the unspecified address are never dialled,
  **regardless** of that setting. They are amplification primitives, not
  destinations. What the client is *told* about the unspecified address is a
  separate question — see the note on blackholed names under [`[log]`](#log).
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

One refusal is deliberately quieter than its neighbours, in the log and on the
wire. A target whose every resolved address is `0.0.0.0` or `::` is a name a
filtering resolver has blackholed: that decision belongs to the resolver, not to
volto, so it is logged at INFO and answered with a 200 whose stream is closed
immediately — the client sees a tunnel that opened and died, which is what a
blocked name looks like through a transport that has no way to explain itself.
Answering 403 instead would invite the client to blame the proxy for an ad
blocker's decision. A target that resolves to loopback, private or mixed
addresses is a refusal volto really did make: it stays a WARN and a 403 with
`Proxy-Status: …; error=destination_ip_prohibited`, because that is what a probe
for internal services looks like from here.

## A minimal file

```toml
[server]
listen = "0.0.0.0:443"
cert   = "/etc/volto/fullchain.pem"
key    = "/etc/volto/privkey.pem"

[auth]
users = [{ username = "user1", password = "…" }]
```
