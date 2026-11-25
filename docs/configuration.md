# Configuration

volto reads one TOML file, named with `--config`, or `-c` for short:

```sh
volto --config /etc/volto/config.toml
volto -c /etc/volto/config.toml
```

Only `[server]` is required; every other section and key has a default. Unknown
keys are an error at startup rather than being silently ignored, so a typo fails
loudly — in every table, not only in `[server]`. That also makes a config file
forward-only, which matters when rolling a release back; see
[version compatibility](#version-compatibility). A commented reference file
ships as [`script/config.example.toml`](https://github.com/vcarus/volto/blob/main/script/config.example.toml).

`--check-config` answers whether a given binary can read a given file without
starting anything; see
[checking a file](#checking-a-file-without-starting-the-server).

`SIGHUP` re-reads the file. A file that fails to parse or validate is rejected
whole and the running configuration keeps serving; see
[deployment.md](deployment.md#reloading).

## `[server]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `listen` | string | required | UDP address to listen on, e.g. `"0.0.0.0:443"`. QUIC is UDP; there is no TCP listener |
| `cert` | path | required | PEM certificate chain, leaf first |
| `key` | path | required | PEM private key (PKCS#8, PKCS#1 or SEC1) |
| `alpn` | array of strings | `["h3"]` | ALPN identifiers to advertise, in preference order. Change only for interop debugging. A list that does not offer `h3` starts a server no client can reach — HTTP/3 is the only protocol volto serves, so TLS ends every handshake with `no_application_protocol`, an alert that says nothing about why — and volto warns about it at startup |
| `shutdown_grace` | seconds | `5` | How long established tunnels may finish after SIGTERM. Range 0..3600, where `0` closes every tunnel at once. [Graceful shutdown](deployment.md#graceful-shutdown) gives why the default is short, how long the whole exit can take and the `TimeoutStopSec` that needs |
| `ech_key` | path | none | ECH key file written by `volto ech-keygen`. Without it the server is plain TLS 1.3; with it the server also accepts Encrypted Client Hello, and drops a handshake whose ECH extension no configured key opens without any reply. See [Encrypted Client Hello](#encrypted-client-hello) |
| `ech_previous_key` | path | none | The previous ECH key file during a key rotation, in the format `ech_key` takes. A handshake under this key is still accepted, and its ECHConfigList is not sent to anyone. Needs `ech_key` and a config_id other than that key's, and is refused otherwise, at startup, by `--check-config` and on reload. Reloadable. See [Rotating the key](#rotating-the-key) |

### Encrypted Client Hello

With `ech_key` set, a client that holds the server's ECHConfigList can encrypt
its ClientHello, so the name it asks for travels inside the encryption and only
the ECHConfig's public name is in the clear. A client without the list still
connects as before, unless [`[security].require_ech`](#security) is on. A client
that cannot be given the list, such as
[Apple's relay client](deployment.md#apples-relay-client), connects only while
it is off.

The server never publishes the ECHConfigList: an operator hands it to each
client. That makes the key a credential the server can check before it answers
anything, and the SNI gate does exactly that. It holds a new handshake's first
packets until the ClientHello is complete, opens the ECH extension with the
key, and only then lets the handshake reach QUIC and TLS.

**Generating the key.**

```sh
sudo volto ech-keygen --public-name public.example --out /etc/volto/ech.pem
sudo chgrp volto /etc/volto/ech.pem
sudo chmod 0640 /etc/volto/ech.pem
```

writes the key file and prints the ECHConfigList on stdout, in standard base64.
That value is what a client takes, for example Surge's `ech-config`.
`--config-id` picks the ECHConfig's config_id (random when left out), and
`--max-name-length` its `maximum_name_length`, which only steers how much a
client pads (default 0). `--replaces <file>` is for a rotation: it reads the
key file being replaced, gives the new key a config_id other than that key's,
and that key's public name and `maximum_name_length` when `--public-name` and
`--max-name-length` are left out. An existing file
is never overwritten. `/etc/volto` is
`root:volto` 0750, so only root can create the file, and the service reads it
through the `volto` group. Run as root in a directory closed to other users,
`ech-keygen` creates the file 0640 with the directory's group itself; anywhere
else, or run as another user, it creates the file 0600 for its owner only. The
`chgrp` and `chmod` lines then change nothing, and they give the service the
file when an earlier release wrote it. To print the list again from the file:

```sh
volto ech-config /etc/volto/ech.pem
```

**The key file** holds two PEM blocks: `PRIVATE KEY`, the X25519 private key as
PKCS#8, and `ECHCONFIG`, the ECHConfigList with its one ECHConfig. Because the
ECHConfig itself is stored, the file fixes the private key, the config_id, the
public name, the HPKE suites (HKDF-SHA256 with AES-128-GCM or
ChaCha20-Poly1305) and the maximum name length together, and the list a client
holds stays the same across restarts and reloads. Nothing in `config.toml`
changes it. The file is read at startup, by `--check-config` and on every
`SIGHUP`, and refused whole if a block is missing or doubled, if the private key
is not X25519, if the two blocks do not belong together, or if the public name
is one a client would ignore: it must be a host name of at most 255 bytes, of
letters, digits and hyphens, with no empty label, no label over 63 bytes, no
label that begins or ends with a hyphen, and a last label that is neither all
digits nor `0x` followed by hex digits (RFC 9849 §6.1.7). `ech-keygen` applies
the same rule to `--public-name`. A refused file at `SIGHUP` leaves the running
key in force.

**What each ClientHello gets**, with a key configured:

| ClientHello | `require_ech = false` | `require_ech = true` |
|---|---|---|
| no ECH extension | judged by `expected_sni` as usual | dropped without a reply |
| an ECH extension the key its config_id names opens, `ech_key` or `ech_previous_key` | admitted; the name in the clear is not looked at | admitted; the name in the clear is not looked at |
| an ECH extension no configured key opens (a key no longer configured, GREASE, a damaged payload) | dropped without a reply | dropped without a reply |
| the ECH of a handshake already admitted, sent again from another address | dropped without a reply | dropped without a reply |

A dropped ClientHello gets nothing back, not even a QUIC acknowledgement, and
nothing of it reaches the TLS layer. That differs from RFC 9849 §7.1 on
purpose: the RFC has a server go on with the outer ClientHello and send its
ECHConfigList back as `retry_configs`, which would hand the list to anyone who
sends an ECH extension at all. The same ECH sent again from the address it
first came from is admitted, which is a client retransmitting its first
packets. The record of admitted ECH handshakes lives in memory. A reload keeps
it, whatever it does to the keys, so a first flight recorded under the old key
stays a replay from another address through a rotation. A restart loses it.

The TLS layer refuses the same ClientHellos a second time, in case the gate
ever lets one through: a ClientHello whose ECH extension libssl did not accept,
and under `require_ech` one with no ECH at all, is refused with a
`handshake_failure` alert before the server writes anything, so even then no
ECHConfigList is sent.

**`expected_sni` and the public name.** A ClientHello whose ECH the key opens
is admitted without its public name being looked at, so the public name does
not belong in `expected_sni`; listing it would make it a second name a probe
could copy. The TLS layer still judges the name inside the encrypted
ClientHello against `expected_sni`, so the real name stays on the list.

#### Rotating the key

`ech_previous_key` names the key a rotation replaces, so the server can change
first and the clients after it. The server then accepts ECH under either key.
It picks the key by the config_id the ClientHello names, so the two keys must
have different config_ids (`ech-keygen --replaces` picks one that differs),
and a first flight is still opened with one key at most. libssl holds the
previous key as a key it decrypts with and never sends:
its `retry_configs` would carry the current key's ECHConfigList alone, and the
gate and the TLS layer keep every ClientHello that would draw them from getting
that far, as the paragraphs above say. The steps are under
[Rotating the ECH key](deployment.md#rotating-the-ech-key) in deployment.md.

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
| `max_targets_per_conn` | integer | `256` | Concurrent tunnels on one QUIC connection, TCP and UDP sharing the budget. Beyond it, requests get 503 with `Proxy-Status: volto; error=connection_limit_reached`. Range 1..65536, the same ceiling `max_streams_bidi` has and for the same reason: one tunnel is one bidirectional stream, and every tunnel also costs a file descriptor |
| `max_connections` | integer | `256` | Simultaneously open QUIC connections; `0` removes the limit and never evicts. At the cap a new connection takes the slot of the oldest connection that has never had a request pass the credentials check — closed with `H3_NO_ERROR` and logged with `reason=evicted` — so a peer that keeps handshaking without ever authenticating cannot hold the server shut. Only a newcomer whose address QUIC has validated may evict: at the cap an unvalidated one is answered with a Retry (RFC 9000 §8.1) and takes no slot, which costs a spoofed Initial the flood it was for. A client that has connected before pays nothing — it returns a NEW_TOKEN token (RFC 9000 §8.1.3) and is already validated — so the extra round trip falls on first contact, on a token older than two weeks, and on the first reconnection after a restart or `SIGHUP`, and only while the server is full. Only when every live connection has authenticated is the newcomer refused during the handshake, before any per-connection state exists here |
| `connect_timeout` | seconds | `10` | Budget for reaching a target; `0` disables it, and the ceiling is 3600. Spent twice per request and separately: once on name resolution, once on the whole list of addresses it resolved to. The connect budget is shared out over the addresses, tried one at a time in resolution order: each attempt gets an equal share of what is left, but never less than 3 seconds unless less than that is left, so with a small budget or a long list only the first few addresses are tried (at the default, at most four). So a request holds its tunnel slot for at most twice this plus one `max_idle_timeout`, the bound on writing the 200, before any byte flows. A lookup that runs out answers 504 with `Proxy-Status: volto; error=dns_timeout`, a connect that runs out answers 504 with `error=connection_timeout` |
| `ip_family_preference` | string | `"ipv4"` | Which address family a resolved target name is tried on first: `ipv4`, `ipv6` or `system` (the resolver's own RFC 6724 order). Applies to both tunnel kinds |
| `max_streams_bidi` | integer | `1024` | Concurrent bidirectional streams per connection — one per tunnel — **once a request on that connection has passed the credentials check.** It is not what the handshake advertises: a connection is accepted on a fixed allowance of `INITIAL_BIDI_STREAMS` = 16 (in `quic/transport.rs`) and granted this value in a single step by its first authenticated request, so a peer that has proved nothing can neither hold a thousand request streams open nor draw a refusal on each. A client that opens more than 16 tunnels before its first one is answered finds the seventeenth held — QUIC backpressure, not an error — until that answer comes back, which is a wait it was already having. An operator who configures *fewer* than 16 gets what they configured, before authentication as well as after it. Range 1..65536, and the ceiling is there because of where the cost falls: a stream slot is reserved for every unit of the credit when the allowance is *granted*, not when a stream is opened, so the value is work paid in one go by the connection's first authenticated request rather than by every handshake — milliseconds at the ceiling on the dev host and whole seconds at a million, which is why the range stops where it does. quinn's own default of 100 runs out during ordinary browsing. The peer's *unidirectional* streams are not a key: they are fixed by `MAX_PEER_UNI_STREAMS` = 16 (in `quic/transport.rs`), where HTTP/3 needs exactly three — the control stream and the QPACK encoder/decoder pair, RFC 9114 §6.2 and RFC 9204 §4.2. Exceeding a transport parameter is a QUIC-level failure with no HTTP-level explanation attached, which is why there is margin rather than three |
| `max_idle_timeout` | seconds | `60` | How long a connection may go without traffic before it is closed. Range 1..3600. It also bounds every application-level wait that precedes a tunnel, whatever the connection's authentication state: the QUIC/TLS handshake, the HTTP/3 handshake, the read of each peer unidirectional stream's type, the read of a request stream's HEADERS, and every refusal this proxy writes. A separate bound of twice this applies only while a connection has never had a request pass the credentials check — counted from the handshake and never re-armed by a new stream, so it bounds the connection rather than a pause in it — and is lifted for good once a request authenticates, so a client that keeps an idle connection between requests is unaffected |
| `keep_alive_interval` | seconds | `20` | Keep-alive period; `0` switches it off. **Must be strictly less than `max_idle_timeout / 2`**, or startup and reload fail |
| `initial_mtu` | bytes | `1200` | Size of the first QUIC packets — a *UDP payload* size, not an IP packet size. Range 1200..1452. **Below 1200 is an error** (RFC 9000 §14) rather than a silent round-up; above 1452 is an error too, because an Ethernet frame leaves 1452 bytes of payload over IPv6 (1472 over IPv4) and quinn applies `initial_mtu` with no ceiling of its own — so a handshake sent in packets no path carries leaves the server unreachable with nothing to fall back to. That failure mode is what separates this key from `mtu_upper_bound`: this value is sent blind, before any feedback channel exists to correct it |
| `mtu_discovery` | bool | `true` | Probe for a larger path MTU (RFC 8899 DPLPMTUD). `false` stops the upward search, so packets stay at `initial_mtu` — except that quinn's black-hole detector still runs and can drop them to the 1200-byte floor for the rest of the connection, with nothing to bring them back up. Slower, but predictable |
| `mtu_upper_bound` | bytes | `1436` | Ceiling for the MTU discovery search, a *UDP payload* size like `initial_mtu`. Range `initial_mtu`..1472. When the key is absent and `initial_mtu` is above 1436, the ceiling is `initial_mtu`, so a file from a release whose default was 1452 still loads. No effect (and a startup warning) when `mtu_discovery` is off. Why the default is 1436 rather than quinn's 1452, and when to raise it, is in the MTU paragraphs under [Notes that matter in practice](#notes-that-matter-in-practice) |
| `congestion_control` | string | `"bbr"` | QUIC congestion controller: `bbr`, `cubic` or `newreno`. `bbr` is volto's own controller, which holds its window to at most 1.25 times the bandwidth-delay product it measures, plus what the path's own loss takes out of it; see [Notes that matter in practice](#notes-that-matter-in-practice) |
| `initial_rtt_ms` | milliseconds | `333` | Round-trip time assumed before the first measurement. Range 10..10000 |
| `socket_recv_buffer` | bytes | `2097152` | UDP socket receive buffer to request when the socket is created; `0` leaves the operating system's own value alone. Range `0`..`2147483647`, the largest value the socket API's signed 32-bit argument can carry; a larger one is refused at load time rather than truncated. Capped by `net.core.rmem_max`, and volto warns at startup when it was capped |
| `socket_send_buffer` | bytes | `2097152` | The same on the way out, capped by `net.core.wmem_max`; the same `0`..`2147483647` range and the same truncation reason |

### Notes that matter in practice

**Every tunnel costs one file descriptor**, so `max_connections` and
`max_targets_per_conn` set the descriptors the process needs; the sum, the
check volto runs against it and the unit's `LimitNOFILE` are under
[File-descriptor budget](deployment.md#file-descriptor-budget).

**A CONNECT-UDP session costs memory as well as a descriptor**, and only the
descriptors are checked at startup. Each session holds three buffers: a
`RECV_BLOCK_SIZE` = 16 KiB block its target's packets are received into,
allocated when the target first sends and kept from then on; an inbound datagram
queue of 64 entries, each at most the 1472-byte `max_udp_payload_size` this
server advertises, so about 92 KiB; and the capsule decoder on the request
stream, which buffers one DATAGRAM capsule's value until all of it has arrived
and so tops out at 64 KiB. On Linux, where quinn receives packets in GRO
batches of up to 64, the first datagram in an empty queue is not copied out of
its batch and can keep that batch's buffer of up to 92 KiB alive, so the queue
tops out around 183 KiB. That is roughly 263 KiB per session, 66 MiB per
connection at `max_targets_per_conn = 256`, and about 16.4 GiB across a server
saturated at both defaults; without GRO it is 172 KiB, 43 MiB and 10.75 GiB.
Lowering either limit lowers it proportionally. It
is a ceiling rather than a resting size: the queue is only full while a client
sends faster than the proxy forwards, and the capsule buffer only fills for a
client that leaves a capsule unfinished. A packet longer than 2 KiB is received
partly into a buffer of about 62 KiB that each runtime thread has once, not
each session. While quinn still holds datagrams cut from a session's blocks, a
session can keep a second block alive, and the queued datagrams of a whole
connection can keep at most 1.15 times quinn's 1 MiB datagram send buffer of
blocks alive on top.

**Each connection also holds a few datagrams before their session exists.** A client may send the first UDP payload in the same flight as its CONNECT-UDP request, and the payload can arrive while the request is still being decoded and authenticated. volto holds such a datagram for the session that is about to claim it, as RFC 9297 §2.1 permits, instead of dropping it: at most `EARLY_DATAGRAMS` = 8 of them on a connection at once, each a copy of at most 1472 bytes. A held datagram is handed to its session only within 333 ms of its arrival. One that is not claimed in that time is discarded the next time the hold is used, by another early datagram or by a session starting, and at the latest when the connection ends, so an idle connection can keep its copies for as long as it lives. That is about 11.5 KiB per connection and about 2.9 MiB across the default `max_connections`. The hold is per connection rather than per session and is reachable before authentication, so it belongs with what an unauthenticated peer can make the server hold. A datagram that finds the hold full, or that is discarded unclaimed, is counted in `dropped_datagrams=`.

**A TCP tunnel costs less, not nothing.** Its relay buffer starts at
`RELAY_BUF_SIZE` = 16 KiB, and settles on a single `RELAY_BLOCK_SIZE` = 64 KiB
block once the tunnel has relayed anything: reads are cut from one block until
too little of it is left to offer a full-sized window, and that is also why the
first 16 KiB is let go after the first read. So the saturation product for TCP
is `max_connections` × `max_targets_per_conn` × 64 KiB = 4 GiB at the defaults,
beside the 16.4 GiB of the UDP one. What a tunnel holds beyond that one block is
bounded by quinn's per-connection send window (`SEND_WINDOW` = 10 MB). That
window counts bytes retained from what this server writes rather than bytes
still unacknowledged: the pieces cut from a block share it, and each goes on
counting until the storage holding it is released, which is after its
acknowledgement rather than at it, so the block outlives them all.

**Both kinds of tunnel read the client's side in batches.** Once a request has
been accepted, its stream's reader takes up to `READ_AHEAD_CHUNKS` = 32 chunks
from quinn per read, and the TCP relay writes what one read took with one
`writev`. The slots cost 1 KiB per tunnel, and a TCP tunnel adds a 2 KiB list
for its vectored write once it has carried an upload. The chunks are quinn's own
buffers, about 1.4 KB each in a bulk upload, so a tunnel in the middle of one
holds some 45 KB that quinn's flow-control windows no longer count, on top of
the figures above. The worst case per tunnel is unchanged: one read takes at
most what quinn had buffered for the stream, which the 2 MiB stream receive
window bounds, and a single chunk could already be that large. Nothing of this
applies before a request has been accepted, so it adds nothing to what an
unauthenticated peer can make the server hold.

**Every tunnel also holds its request's header fields.** volto advertises
`MAX_FIELD_SECTION_SIZE` = 65536 in its SETTINGS, and a client is entitled to
send a request that large; decoded, it costs roughly that much again — about 77
KiB measured — and it is kept for the whole life of the tunnel the request
opened, not just until the target has been named. At the defaults that is
another 19 MiB per connection and about 4.8 GiB across the server, on top of the
tunnel figures above. Real clients send a few hundred bytes of headers, so this
is a ceiling reached only by a client that chooses to fill the advertised limit;
it is listed because nothing else in this section accounts for it.

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
when idle. The reserved slots are `max_connections` up to 1024, and 1024 when
`max_connections = 0`. A reload that raises `max_connections` takes effect for new
connections but resizes neither the pool nor the reserved slots, which needs a
restart.

**`max_streams_bidi`, `max_idle_timeout`, `keep_alive_interval`, `initial_mtu`,
`mtu_discovery`, `mtu_upper_bound`, `congestion_control` and `initial_rtt_ms`
are QUIC transport settings and apply to new connections only.** A reload carries them to
connections accepted from then on; connections already open keep what they
negotiated at handshake time, because QUIC cannot renegotiate transport
parameters. `ip_family_preference` is not a transport parameter, but it is
snapshotted the same way: a connection resolves every target with the preference
that was in force when it was accepted.

`max_streams_bidi` is the one of them that also moves *within* a connection's
life, when its first authenticated request raises the allowance from 16 to the
configured value. That is not renegotiation — the raise travels as a
`MAX_STREAMS` frame, which QUIC allows at any time and only ever upwards — and it
makes the key no more reloadable than the rest: what a connection is raised to is
the value that was in force when it was **accepted**, not whatever a later reload
set. A reload during a connection's unauthenticated window changes nothing about
that connection either.

**`[server].listen` is startup-only.** A reload carrying a new value for it is
accepted — the rest of the file still applies, because the usual sender of
`SIGHUP` is a renewal hook that rewrites the whole file and refusing the reload
over one key would be worse than ignoring it — but the socket does not move.
The reload says so, naming both addresses, so an operator who did mean to move
it is not left reading a successful reload that quietly did not apply:

```
WARN volto::quic: server.listen changed, but a reload cannot move the listening
socket; the server is still bound where it started. Restart to apply it.
bound=0.0.0.0:443 configured=0.0.0.0:8443
```

**The two socket buffer keys are startup-only, not reloadable at all.** They are
applied to the UDP socket when it is created, and a reload does not rebind that
socket, so changing them needs a restart, the same as `[server].listen`. The
range stops at `2147483647` because the value is converted to a `c_int` before
`setsockopt`: anything larger would reach the kernel as a different number, and
`4294967296` would become `0`, the operating system's minimum rather than a
request. A larger value is refused at load time, naming the key, the value and
the limit. What the host does with the request, and why the keys exist at all,
is under [UDP socket buffers](deployment.md#udp-socket-buffers).

**`[log].level` is startup-only.** The tracing subscriber that applies it is
built once, before the server binds, and nothing rebuilds it. A reload carrying
a new value is accepted and stored in the live configuration, but every line is
still filtered by the level the process started with. The reload says so,
naming both levels, so a `SIGHUP` meant to raise verbosity is not mistaken for
one that did. Restart to apply it. `RUST_LOG`, when set, overrides `log.level`
at startup, so a service environment that sets it is unaffected by either.

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

**`bbr` is volto's own controller, with its window held to at most 1.25 times
the bandwidth-delay product it measures, plus what the path's own loss takes
out of it.** quinn's BBR estimates the bottleneck
bandwidth several times too high, so during a bulk download it sends faster than
the path carries and the path drops the difference. `bbr` uses no part of it. It
measures the delivery rate once per round trip and sets the window, and with it
the pacing rate, to a gain times that rate times the minimum RTT, widened for
the path's base loss as described below. Outside a
recovery and the re-measurement of the minimum RTT the window is never below the
240 kB a new connection starts with, so on a path whose bandwidth-delay product
is under 192 kB the window can be 240 kB. The gain is
1.25 and follows the path down to 1.05. At 1.25 a quarter of a bandwidth-delay
product stands in the bottleneck queue, and a queue shorter than that loses the
rest. So when one percent or more of the bytes are lost beyond the path's base
loss, the controller tries
the gain at which in-flight data is what the path carried, and keeps it only if
the loss then falls as a short queue predicts: the loss is counted over windows
of at least four round trips, and each of four windows at the lower gain has to
lose less than every one of the four before it. Random loss does not fall, and
there the gain stays at 1.25, which a lossy path needs. Through 1.8.0 one window
of eight was enough, and loss that comes in bursts passed that test by chance:
on a 28 Mbit/s path with a 75 ms RTT and bursts of loss in the lab, 1.8.0
carried 25.7 Mbit/s and 1.8.1 carries 26.9, which is what a fixed 1.25 carries.
A lowered gain is tried
higher again from time to time, and is given up when the measured rate does not
hold. In a lab with a 150 Mbit/s bottleneck and a 60 ms RTT, behind a 50 kB
queue this took the loss from 18.9 to 1.0 percent of the packets sent and the
throughput from 121 to 144 Mbit/s; behind a 150 kB queue from 8.6 to 0.2 percent
and from 127 to 144 Mbit/s; under 0.2 and 2 percent random loss and behind a
queue of one bandwidth-delay product nothing changed. Behind a 20 kB queue the
loss went from 20.4 to 4.4 percent and the throughput from 117 to 114 Mbit/s. A new connection uses
2.89 times instead, BBR's startup
gain, until its measured rate stops growing, or until a round trip in which it
did not grow loses more than 1.5 times the path's base loss, which before the
first reading is any loss at all, or carries an ECN mark, once the connection
has counted 100 packets. Through 1.8.2 that exit applied from the first
packet, so a handshake that lost a packet in each of two round trips ended the
startup on a dozen packets and the connection never ran one; within 100
packets the window is the initial window's whatever the gain. Behind a
150 Mbit/s bottleneck in the lab it
reached 90 percent of that rate 1.4 s after the handshake at a 60 ms RTT and 2.9
s at 150 ms, against 2.0 and 4.5 s with 1.25 from the start. The higher gain
returns when the measured rate, after falling below half of its highest value,
rises in three round trips in a row. After a 3 s burst of 90 percent loss in the
lab, the climb back to 90 percent of the bottleneck rate, once sending resumed,
took 0.2 s at a 60 ms RTT and 2.0 to 2.2 s at 150 ms, against 0.8 to 0.9 s and
3.2 to 3.5 s before this rule. A new connection's window is also at most the
initial window plus the bytes acknowledged until that first startup has ended,
as in slow start.

Some paths drop a share of all packets whatever the sending rate. A lost packet
stays counted in the window until it is declared lost, a quarter of a round trip
longer than a delivered one, so on such a path a window of 1.25 bandwidth-delay
products delivers less than the measured rate once more than about one sixth of
the packets are lost. Each measurement then comes out lower than the last, and
the window falls to its 240 kB floor although the path could carry far more.
Through 1.8.2 that is what happened. The controller now reads the path's base
loss where its own sending cannot be the cause: among the packets sent while
the window is held at half for the re-measurement of the minimum RTT, and
only when what arrived fell with what was sent: the arrival rate during the
re-measurement has to be at most three quarters of the arrival rate in the
round trip before it. Behind a rate limit with a large burst allowance, where
the startup has measured several times the limit, sending less leaves the
arrivals as they were, and the loss is the sender's own. When a startup has lost
5 percent of its bytes or more and no reading is kept yet, that re-measurement
starts as soon as the startup ends rather than 10 s or more later; on a path
with a clean rate limit this costs one re-measurement about a second into the
connection. When one re-measurement counts too few packets and shows the loss,
the next follows at once, up to four. The base loss is the lowest of the last
four readings, at most 40 percent, and the steady window is multiplied by
(1 + p/4) / (1 - p) for a base loss p. So what is in flight and will arrive
stays at most 1.25 bandwidth-delay products. When a re-measurement lowered
what was sent and what arrived did not fall, the sender was above the path's
rate, and the base loss in force is cleared. A reading that brings the base
loss up from zero is checked by one more re-measurement about ten round trips
later, so a reading taken in an outage acts for about that long. Loss that
comes in episodes is covered when an episode falls into a reading and not
otherwise; on a simulated limiter line with loss in episodes calibrated to
production captures, sent over delivered stayed within 0.012 of 1.8.2 in the
mean and 0.055 in the worst run over 120 s. Loss the sender causes itself by
exceeding a rate limit or a queue does not enter a reading, with one known
exception: behind a buffer of under ten packets quinn's bursts of ten packets
overflow it at any rate, and in the simulator behind a 20 Mbit/s queue of
10 kB the sent rate rose from 20.4 to 23.5 Mbit/s for 19.4 delivered. A rise of
the base loss takes effect once every kept reading has risen, which can take a
minute or two. In a lab with Surge as the client, on a path of 85 ms that
carries 150 Mbit/s before its loss, 1.8.2 delivered 16 Mbit/s with 23 percent
of the packets dropped and this controller 109 to 112, where the path carries
115. Earlier builds of the change delivered 131 to 132 where 1.8.2 gave 106 to
111 with 15 percent dropped, and 123 to 124 where it gave 21 to 24 with 18
percent. On a path of 151 ms with 24 percent dropped 1.8.2 ended at the floor,
9 Mbit/s, at once in one run and after 40 s in the other; this controller ran
at 63 to 67 from 1.5 s on, where the client's own windows were the limit.
Behind rate limits without a queue the sent rate over the delivered rate was
1.09 against 1.14 to 1.15 for 1.8.2 at 30 Mbit/s with a burst allowance of
1 MB, 1.10 against 1.12 to 1.16 at 60 Mbit/s with 4 MB, and 1.00 for both at
190 Mbit/s with 1 MB, and no base loss was read. An earlier build of the
change, which differs from this one only where a base loss is read or a packet
of the handshake is lost, stayed within what 1.8.2 gives from run to run behind
a 50 kB queue, a deep queue, 2 percent random loss, a poor Wi-Fi hop, and a
competing CUBIC flow through a short, a middle and a deep queue.

After a loss, in-flight data is held for one round trip and
then grows by the bytes acknowledged. Apart from the gain rule above, it does
not take a lost packet for a reason to send less for longer than that, which is
what makes BBR the choice for a lossy path. It keeps its own
minimum RTT, which lasts 10 s unless an equal sample renews it. A lower sample
replaces it once ACKs of three different arrival times within a second have
shown one, and the new minimum is the highest of the three. quinn stamps every
ACK of one socket poll with one clock reading, so a poll that the scheduler or
the host of a virtual machine held up gives samples that are too short; through
1.8.0 one such sample was taken as the minimum and held the window too small
for 10 s. In the lab a 60 ms path read as 37 ms once every 7 s carried 50 to 81
Mbit/s of 144 with that rule and 141 to 144 with this one. When the minimum
runs out, and once the sender is not app-limited, the window is held at half the
bandwidth-delay product for at least 200 ms so that the bottleneck queue
empties, and the new minimum is taken from the samples seen then by the same
rule. In a lab with a
150 Mbit/s bottleneck and a 60 ms RTT, behind a queue of one bandwidth-delay
product, quinn's BBR as it ships lost 28 percent of the packets it sent and
`bbr` none, at 8 percent higher throughput, and under 0.2 and 2 percent random
loss the throughput of `bbr` was 15 and 26 percent higher. The re-measurement
costs about 1.4
percent of the throughput. A lasting rise in the path's RTT lowers throughput
until the next re-measurement, 10 s after the last one or later while the sender
is app-limited; after a rise from 60 to 150 ms the throughput was back at the
bottleneck rate 1.6 to 2.9 s after that, against 3.2 to 3.6 s before the startup
gain could return, at a cost of 0.05 to 0.21 percent of the packets sent in the
45 s after the rise. It is the default since 1.2.0, after download A/B runs on a
production relay path in which it lost fewer packets and carried more data than
quinn's BBR in every run. Through 1.7.0 it was built around quinn's BBR and its
gain was fixed at 1.25; the startup, loss-burst, RTT-rise and quinn's-BBR
figures in this paragraph were measured on those releases, and the short-queue
figures on 1.8.0; with the stricter test of 1.8.1 the 50 kB and 150 kB figures
are the same, and behind the 20 kB queue the loss is 5.0 to 5.5 percent at 121
to 123 Mbit/s. The stricter test has a cost where even 1.05 overflows the
queue and a lower gain only loses less: behind a 50 kB queue at a 150 ms RTT
1.8.1 carried 74 to 79 Mbit/s at 9 to 12 percent loss, 1.8.0 76 to 91 at 4 to
7 percent, and 1.7.0 71 at 16 percent. The names it has had, and the value `bbr-uncapped` that
selected quinn's BBR from 1.2.0 to 1.7.0, are under
[What is stable from v1.0.0](#what-is-stable-from-v100).

**A packet is declared lost by its age, not by how many packets were
acknowledged after it.** quinn's defaults, the initial values of RFC 9002, call
a packet lost once a packet three numbers later has been acknowledged, or once
it is 9/8 of a round-trip time old. A path that delivers some packets a few
milliseconds late meets the first rule on every one of them at a bulk
download's rate, so each is sent a second time although it arrived, and the
congestion controller counts a loss that did not happen. From 1.8.2 on volto switches
the count off and sets the age to 5/4 of the round-trip time, the allowance RACK-TLP
(RFC 8985) starts with for TCP. This holds for all three values of
`congestion_control` and there is no key for it. On a production path where 2
to 3.5 percent of the packets arrived out of order, the server called 94 to 98
percent of those lost with quinn's defaults and 13 to 28 percent with these
values, and of two downloads sharing the path the one with these values carried
16 percent more. The price is paid on a path that does not reorder: a packet
that really was lost is sent again about a quarter of a round trip later, and
the data sent after it stays charged to the client's flow-control window for
that much longer. In the lab at 150 Mbit/s and a 60 ms RTT with 2 or 5 percent
random loss, a client with a 16 MiB connection window, which is what Surge
advertises, received the same as before, and a client with a 4 MiB window
received 6 to 8 percent less.

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
therefore either that heuristic firing on congestion or a ceiling above the
size the path carries under load. The paragraphs on the two MTU keys below
describe the second case.

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

**The two MTU keys are shipped as live keys too.** The example configuration
in `script/` ships `initial_mtu = 1242` and `mtu_upper_bound = 1436`, and the
installer substitutes only the listen address, the certificate paths and the
user. The compiled-in defaults that apply when the keys are absent are 1200 and
1436, so an install derived from the example differs from them only in
`initial_mtu`. 1242 keeps the handshake inside a 1270-byte IPv4 packet: under
the 1280 bytes any practical path carries, and below what Chromium (1250) and
quic-go (1280) send everywhere. Over IPv6 the same packets are 1290 bytes, past
that guarantee, so put it back to 1200 if clients reach the server over IPv6.
This is the key that is sent blind, and a size the path cannot carry kills the
connection with nothing to fall back to.

**A probe that gets through is not the same as a path that carries the size.**
Discovery adopts a size once one probe of it is acknowledged, and a path can
deliver that probe while losing most traffic at that size under load. On a
measured relay path, IPv4 packets above 1464 bytes (UDP payload above 1436) arrived with
the DF bit cleared. Single probes of those sizes got through, so discovery
adopted 1452 or 1464, and at bulk rate 62 to 89 percent of the packets at that
size were lost. The black-hole detector then dropped the size to 1200, and
after its one-minute cooldown the same probe succeeded again. Packets of up to
1464 IP bytes kept DF set and lost about what 1200-byte packets lost. 1436 is
the largest UDP payload whose IPv4 packet crosses that path with DF set, which
is why it is both the default and the shipped value. quinn's 1452, the value
that fits both IPv4 and IPv6 on Ethernet, is a 1480-byte IPv4 packet, above that
boundary, and in one of two runs with that ceiling 85
percent of the 1452-byte packets were lost. The example shipped 1464 before:
what an IPv4 uplink behind a 1492-byte first-hop IP MTU leaves. That uplink was
measured correctly, but it is not the segment that limits the relay path. Over
IPv6, 1452 is what an Ethernet frame leaves and 1436 is below it, so the default
holds on either family.

**The counter to watch is `mtu_black_holes=` in the connection close line.** A
ceiling above what the path carries costs failed probes on a path that drops
oversize packets. On a path that delivers single probes but not bulk traffic at
that size, it costs lost traffic until the black-hole detector fires, and shows
up as connections that carried bulk traffic and close with the counter non-zero.
On the measured path, a ceiling of 1400 ran with no black-hole event. 1472,
clean Ethernet over IPv4, is the most volto accepts, and `ping -M do` alone does
not justify raising the ceiling toward it, because a path that clears DF
delivers that probe too. An operator who has measured their own path can raise
it, but only after a bulk transfer at the new size has run with
`mtu_black_holes=0`. Neither
value is a measurement of *your* path: lower `initial_mtu` on the first sign
that a handshake is not getting through.

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
| `allow_private_networks` | bool | `false` | Allow tunnels to the special-purpose address space listed in the IANA registries that RFC 6890 set up: loopback, RFC 1918, link-local, shared address space, the IETF protocol assignment blocks and the rest of the table under [Ranges refused unless `allow_private_networks` is on](#ranges-refused-unless-allow_private_networks-is-on). Keep it off on a public deployment |
| `denied_ports` | array of integers | `[25]` | Target ports refused regardless of address, answered with 403. **Do not add 53 or 123** (see below) |
| `unanswered_packet_budget` | integer | `64` | Packets a UDP session may send before its target has answered; `0` disables the mitigation |
| `max_auth_failures` | integer | `5` | Authentication failures tolerated on one connection before it is dropped; `0` disables it. What one failure is, and what clears it, is under the table |
| `require_ech` | bool | `false` | Drop every handshake that carries no ECH extension, without any reply, so only a client holding the ECHConfigList reaches TLS. Needs `[server].ech_key` and is refused without it, at startup, by `--check-config` and on reload. Reloadable. Configure every client with the list before turning it on: a client without it then sees the port as closed. See [Encrypted Client Hello](#encrypted-client-hello) |
| `expected_sni` | array of strings | `[]` | Host names this server answers to. **An empty list answers to any name**, which is the default. A non-empty list turns on the SNI gate, and a handshake whose ClientHello names none of these hosts is refused, as a rule with no reply at all. Every client must then send the name as SNI (in Surge, the `sni=` parameter), so change this key and the clients together. How names are matched, which are refused at startup and what the gate does are under [The SNI gate](#the-sni-gate) |

- **This whole section is snapshotted per connection, at accept.** A reload
  applies it to connections accepted after it, and a connection already open
  keeps the rules it was accepted with for its whole life, tunnels opened on it
  later included, so a tightened `allow_private_networks` or a new entry in
  `denied_ports` reaches a client that is holding a connection open only when
  that connection ends. Use `systemctl restart volto` when the tightening has to
  apply to everything at once; the same reasoning and the same remedy as for
  credentials, worked through under
  [Reloading](deployment.md#reloading) in deployment.md.
- Addresses are normalized before matching, so neither `::ffff:127.0.0.1` nor
  `::127.0.0.1` gets past `allow_private_networks = false`.
- IPv6 transition addresses are judged by the IPv4 address they carry, because
  that is what a host routing them actually reaches: the well-known NAT64 prefix
  (`64:ff9b::/96`), 6to4 (`2002::/16`) and Teredo (`2001::/32`). So
  `64:ff9b::7f00:1` is refused as the 127.0.0.1 it is, while `64:ff9b::808:808`
  is reachable as 8.8.8.8. The local-use NAT64 prefix `64:ff9b:1::/48` is judged
  differently: its operator picks where the IPv4 address sits inside it and
  RFC 8215 §5 forbids a reader assuming a layout, so the whole prefix counts as
  private and follows `allow_private_networks`.
- Multicast, broadcast and the unspecified address are never dialled,
  **regardless** of that setting. They are amplification primitives, not
  destinations. What the client is *told* about the unspecified address is a
  separate question — see the note on blackholed names under [`[log]`](#log).
- **This host's own addresses are never dialled either**, at any port and
  **regardless** of that setting, because the reason is a different one: a tunnel
  to an address this machine carries reaches the machine's own services with the
  proxy's own source address, which is the privilege escalation RFC 9298 §7
  names. Loopback is the exception, and it is the exception the RFC makes too:
  it lists "localhost" as a class of its own, and here that class is the private
  one above, off by default and opened by `allow_private_networks`. So a target
  is refused with `403` and `destination_ip_prohibited` when it resolves to an
  address of this host other than loopback, whether that address is public, on
  the LAN, or the one the server listens on. An IPv6 address that carries an
  IPv4 address (NAT64, 6to4, Teredo or the deprecated `::a.b.c.d`) counts as
  this host's when the host holds either the IPv6 address itself or the IPv4
  address it carries. The check asks the kernel whether it would bind the
  address, so on a Linux host with `net.ipv4.ip_nonlocal_bind` or
  `net.ipv6.ip_nonlocal_bind` set every address of that family looks like this
  host's own, and every tunnel to that family is refused.
- **What that rule does not cover, said rather than left to be discovered.**
  With `allow_private_networks = true` a client can still reach this server's own
  listener through `127.0.0.1`, exactly as it can reach every other loopback
  service the operator opened: loopback is the private class above, and that
  switch is what decides it. And behind a relay the address a client dials the
  proxy on is the relay's, not one any interface here carries, so a target naming
  that address is judged like any other public address and it is the relay rather
  than this rule that stands in the way.
- **UDP/123 and UDP/53 must stay reachable.** Surge's UDP availability test is
  an NTP query to port 123 through the tunnel, so denying port 123 makes Surge
  report the policy as broken. Denying port 53 refuses every DNS query a client
  sends through the tunnel, which breaks name resolution for a client that
  resolves names that way. volto warns if 53 or 123 appears in `denied_ports`.
- `unanswered_packet_budget` stops a client using the proxy as a reflector or a
  port scanner (RFC 9298 §7). The first reply from the target lifts the limit for
  the rest of the session, so it only bites on one-way floods. The default is
  generous on purpose: handshakes that legitimately need several packets before
  the first reply must not break. The **connection** carries a total of its own,
  `CONNECTION_UNANSWERED_MULTIPLIER` = 8 times this value (512 packets at the
  default), spent by every session on it that sends into silence. A session
  whose target answers gives back what that session spent, and nothing else
  does, so opening a new session no longer restores the allowance, a
  long-lived connection of short answered sessions (DNS through the tunnel)
  spends none of it, and a session that finds the total spent is closed rather
  than left running and muted. `0` switches both halves off.
- `max_auth_failures` is not a rate limit and not a ban. It raises the cost of
  guessing from "one handshake, then unlimited attempts" to "one handshake per N
  attempts", without any cross-connection state to keep or evict. What it counts
  is credential values rather than requests: every value that is tried and
  refused costs one failure, so a request carrying a guess under each of the two
  accepted field names spends two. A request carrying more than two credential
  values is answered `400` before any of them is tried, and costs nothing,
  because two is all that accepting both field names asks for. N is therefore a
  number of guesses whatever shape they arrive in. Failures are counted in
  buckets: one per configured user-id that is guessed at, one shared by every
  user-id that is not configured, and one for the requests that named nobody.
  The connection goes when the **total** across them reaches N. A request that
  authenticates clears **its own user's bucket and the credential-less one**, so
  failures cannot add up over the life of a working connection. It clears
  nothing else, so a peer holding one valid credential cannot buy back its
  guesses at a second user's password by interleaving a good request, and a scan
  for user-ids that do not exist is never cleared by anything. Pair it with
  fail2ban for actual banning; see [deployment.md](deployment.md#fail2ban).

### Ranges refused unless `allow_private_networks` is on

Each range is refused with a 403 while `allow_private_networks` is `false`. An IPv6 transition address (IPv4-mapped, the well-known NAT64 prefix, 6to4, Teredo) is first replaced by the IPv4 address it carries and then judged by these rows, so the `::/8` row below never meets the IPv4-mapped `::ffff:0:0/96` or the well-known `64:ff9b::/96` inside it.

| Range | What it is | Source | Note |
|---|---|---|---|
| `0.0.0.0/8` | "This host on this network" | RFC 1122 |  |
| `127.0.0.0/8`, `::1` | Loopback | RFC 1122, RFC 4291 |  |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | Private use | RFC 1918 |  |
| `fc00::/7` | Unique local (ULA) | RFC 4193 |  |
| `169.254.0.0/16`, `fe80::/10` | Link-local | RFC 3927, RFC 4291 | `169.254.169.254` is the cloud metadata address |
| `fec0::/10` | Site-local, deprecated | RFC 3879 |  |
| `100.64.0.0/10` | Shared address space | RFC 6598 | The inside of a carrier-grade NAT |
| `192.0.0.0/24` | IETF protocol assignments | RFC 6890 | The PCP and TURN anycast addresses `192.0.0.9` and `192.0.0.10` included |
| `2001::/23` | IETF protocol assignments | RFC 2928 | Refused whole. It holds the anycast service addresses `2001:1::1` to `2001:1::3`, benchmarking `2001:2::/48`, AMT `2001:3::/32`, AS112 `2001:4:112::/48`, ORCHID `2001:10::/28`, ORCHIDv2 `2001:20::/28` and the DETs prefix `2001:30::/28`. Teredo `2001::/32` inside it is judged by the IPv4 address it carries, as described above |
| `192.52.193.0/24` | AMT relay discovery | RFC 7450 |  |
| `192.31.196.0/24`, `192.175.48.0/24`, `2620:4f:8000::/48` | AS112 DNS anycast | RFC 7535, RFC 7534 |  |
| `198.18.0.0/15` | Benchmarking | RFC 2544 |  |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `3fff::/20` | Documentation | RFC 5737, RFC 3849, RFC 9637 |  |
| `192.88.99.0/24` | 6to4 relay anycast, deprecated | RFC 7526 |  |
| `240.0.0.0/4` | Reserved | RFC 1112 |  |
| `100::/64` | Discard-only | RFC 6666 |  |
| `100:0:0:1::/64` | Dummy IPv6 prefix | RFC 9780 |  |
| `5f00::/16` | SRv6 SIDs | RFC 9602 |  |
| `64:ff9b:1::/48` | Local-use NAT64 | RFC 8215 | Refused whole, because the position of the embedded IPv4 address is the operator's choice |
| `::/96` | IPv4-compatible, deprecated | RFC 4291 | Stacks that still honour it route `::127.0.0.1` to loopback, which would otherwise be a second way around the IPv4 rules |
| `::ffff:0:0:0/96` | IPv4-translated | RFC 2765 | `::ffff:0:a.b.c.d`, one segment along from the IPv4-mapped form. Refused whole, whatever it carries; with `allow_private_networks` on, one that carries an unspecified, broadcast or multicast address is still refused |
| `::/8` | Reserved by IETF | RFC 4291 | The rest of the block, after the rows above and the transition forms that are judged as IPv4 |

### The SNI gate

`expected_sni` is the one key here that changes what an outsider sees rather than
what a client may reach. With it set, the UDP port stops answering anybody who
cannot name the host: the check runs on the datagram itself, under the QUIC
layer, and a handshake that fails it is discarded rather than refused. There is
no reply of any kind, no Version Negotiation packet, no `CONNECTION_CLOSE` and
no TLS alert, so a scan of the address finds a closed port. The one exception is
the TLS alert described under "A name is checked twice" below.

What it is for is a deployment whose address is not the name — volto behind a
relay, where the port is on an IP that nothing else advertises. What it is *not*
is traffic obfuscation: it says nothing about what a connection looks like once
one is open, and it does not stop a probe that already knows the name.

**Turning it on is a two-sided change.** Set it to the name on the certificate,
and make sure every client sends that name as SNI. Surge does when the policy
line names the host; when the policy points at a relay's IP instead, that is the
`sni=` parameter (with `server-cert-verify-name=`), which such a deployment
already needs. A client that sends the wrong name, or none, gets silence, and
silence is indistinguishable from the server being down: no error appears
anywhere but this server's debug log. So the two halves belong in the same
change window.

Some details worth knowing before relying on it:

- **Matching** is name for name, ASCII case-insensitive, with one trailing root
  dot ignored. There are no wildcards and no suffix matching.
- **A name is checked twice.** Without an ECH key, the socket-level check reads
  the ClientHello out of the client's first Initial packet, which is where a
  small ClientHello fits whole. One that is split across several packets is
  deliberately let through, because refusing a first flight before its
  extensions have arrived would make a large ClientHello unreachable. It is
  stopped a layer up instead, by the TLS layer, which refuses a name it does
  not know before it sends a certificate. That second refusal is a TLS alert rather than silence,
  which is the one case where a probe learns something.
- **With an ECH key, the whole ClientHello is judged.** The gate holds the first
  packets of a new handshake until its ClientHello is complete, then lets them
  through or drops them all; see [Encrypted Client Hello](#encrypted-client-hello).
  The ClientHello split across packets is then judged at the socket like any
  other, and an Initial packet that carries no ClientHello at all is held and,
  when none follows, dropped, so the acknowledgements described below are not
  sent. What is held is bounded in time (two seconds), in number (64 handshakes
  at once, the oldest giving way to a new one) and in bytes (4 MiB in all).
- **Reloadable.** `SIGHUP` applies a new list to handshakes from then on;
  connections already open are unaffected, exactly like the rest of the file.
- **Not a certificate selector.** There is still one certificate and one key.
  Naming several hosts means volto answers to all of them with the same
  certificate, so they all have to be on it. A name the certificate does not
  cover draws a warning at startup and on reload, because a typo here is
  otherwise indistinguishable from a dead server.
- **A packet that names nobody can still draw an acknowledgement.** The check
  refuses an Initial whose Destination Connection ID is under the eight bytes
  RFC 9000 §7.2 requires of a client's first packet, since no later one is that
  shape either and quinn applies the same floor before decrypting;
  what it passes, it passes to quinn, which acknowledges an Initial carrying an
  ack-eliciting frame whether or not a name is in it. Sending one means building
  a QUIC Initial packet on purpose, which is a probe aimed at this server rather
  than a scan of the address.
- **No Stateless Reset.** A short-header packet for a connection this server
  does not hold draws nothing, with the gate on or off. RFC 9000 §10.3 lets an
  endpoint send a Stateless Reset for one and does not require it, and volto
  does not send one, even for a recorded packet of a connection it once held.
  The cost is that a client whose connection the server has forgotten, and that
  missed the server's `CONNECTION_CLOSE`, finds out from its own idle timeout.
  The gate itself passes every short-header packet, because telling a live
  connection's packets from a stranger's needs state the gate does not have,
  and filtering on the address instead would break the connection migration a
  phone behind a relay's NAT depends on. During the shutdown grace, after the
  server stops accepting new connections, it drops every Initial packet without
  a reply, so a client that arrives then gives up at its own handshake timeout.
- **Rejected names.** A name that no ClientHello could carry is refused at
  startup, by `--check-config` and on reload, rather than accepted and never
  matched: an empty string, a wildcard, a name over 253 bytes, and anything
  outside the ASCII letters, digits, `-`, `.` and `_` an A-label is made of. So
  is a name with an empty label (a leading dot, two dots in a row, or a second
  trailing dot) and an IP address literal, because RFC 6066 §3 permits neither
  in a `server_name`. So is a name the server's TLS does not read as a DNS host
  name (a label longer than 63 bytes, a label that starts or ends with `-`, or a
  last label that is a number), because the server treats such a name in a
  ClientHello as no name and refuses the handshake. The failure mode this avoids
  is a gate that starts cleanly and silently refuses every client.

## `[log]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `level` | string | `"info"` | A bare level (`trace`/`debug`/`info`/`warn`/`error`, in any letter case) or a directive list such as `"volto=debug,quinn=info"`. Spaces around the value and around each directive are removed, and the value without them is both the one judged and the one applied. A value that turns this server's own lines off is refused, because the configuration warnings are among them: `off` or `0`, `volto=off` or `off` for a module of it, and a list that names only other targets, such as a lone `quinn=off`, which matches none of this server's lines. `info,quinn=off` is accepted. Startup-only: the subscriber is built once at startup, a reload accepts a new value but cannot apply it, and a restart applies it. `RUST_LOG`, if set, overrides it and is held to the same rule: a `RUST_LOG` that turns this server's lines off stops the start with an error, and one that does not parse, is empty, or is a single word that is not a level name (such as `warning` or `3`) is reported at startup and `log.level` is used instead |
| `keylog` | bool | `false` | Write TLS secrets to the file named by `SSLKEYLOGFILE`. Debugging only; volto warns while it is on |

At `debug`, every inbound request is logged with its method, path, `:protocol`
and header lines. Credential *values* are replaced with
`<scheme> <redacted N bytes>`, but the header names are kept — that is what makes
the log usable for confirming which authorization header a client actually sends.

A keylog file decrypts **every** session through the proxy, including sessions
already recorded. Turn it off and delete the file when you are done.

Under the shipped unit it writes nowhere. `ProtectSystem=strict` with no
`ReadWritePaths=` leaves the service no writable path but its own
`PrivateTmp=yes` directory, and the server notes the
failure to open at `debug` and carries on, so the operator gets a server that started,
a startup warning saying the keylog is on, and no file. Give it a directory and
a path with a drop-in:

```ini
# /etc/systemd/system/volto.service.d/keylog.conf
[Service]
Environment=SSLKEYLOGFILE=/var/lib/volto/keylog
ReadWritePaths=/var/lib/volto
```

after `sudo install -d -o volto -g volto -m 0700 /var/lib/volto`, then
`systemctl daemon-reload` and restart. Remove the drop-in and the directory
together with `keylog = false` when the session is over: the file is every
secret the proxy has negotiated since it was created.

Under systemd, volto prefixes each line with a syslog priority (`<3>` for ERROR,
`<4>` for WARN, `<6>` for INFO, `<7>` for DEBUG and TRACE). journald parses that
prefix, strips it, and files the record with the matching `PRIORITY`, so
`journalctl -u volto -p warning` selects what it says it does instead of matching
everything. The prefix appears only when systemd sets `JOURNAL_STREAM`, so
running volto in a terminal prints the same lines it always did, and the shipped
unit needs no extra setting (`SyslogLevelPrefix=` already defaults to true). The
reason a start failed is printed to stderr rather than logged, and under the same
condition each of its lines carries `<3>`, so it is filed at `err` as well.

Every line at `info` or above carries a `log_id` field, eight lowercase letters
and digits. It names one statement in the source, is assigned once and is never
reused, and it stays the same when that line is reworded, so it is what a
runbook or a journal filter should match on. The message text is not covered by
the compatibility promise below; the id is the stable half of the pair.

One refusal is deliberately quieter than its neighbours, in the log and on the
wire. A target whose every resolved address is `0.0.0.0` or `::` is a name a
filtering resolver has blackholed: that decision belongs to the resolver, not to
volto, so it is logged at INFO and answered with a 200 whose stream is closed
immediately — the client sees a tunnel that opened and died, which is what a
blocked name looks like through a transport that has no way to explain itself.
Answering 403 instead would invite the client to blame the proxy for an ad
blocker's decision. A target that resolves to loopback, private or mixed
addresses is a refusal volto really did make: it is answered with a 403 and
`Proxy-Status: …; error=destination_ip_prohibited`, and logged at INFO with the
target and its addresses, because that is what a probe for internal services
looks like from here. The line is INFO rather than WARN because the refusal is
the configured behaviour working as intended, not a fault of this host.

That policy-refusal line, and the warning a request refused for reaching
`max_targets_per_conn` writes, are reported on a doubling schedule per
connection: the 1st, 2nd, 4th, 8th and so on, each carrying `refusals=` with the
running total, and the ones in between at DEBUG. Both are refusals a client can
repeat as fast as it can open request streams, and journald's rate limiting
counts lines, so one line per request would let a peer decide how much of the
journal is left to record anything else in, including the lines about it. A
scan of every port on a host is 16 lines rather than 65535, the first arrives
as promptly as it ever did, and the last one says how large the scan was to
within a factor of two.

## Checking a file without starting the server

```sh
volto --check-config --config /etc/volto/config.toml
```

reads the file, validates it and exits. A file that is good exits 0 with one
line on stdout; a file that is not exits non-zero with the reason on stderr —
the same error, word for word, that the service would print at startup, because
it is the same code path. Settings that are legal but worth a word (`[auth].users`
empty, `log.keylog` on, a file every local user can read) are printed to stderr as
warnings and do not change the exit status: they describe a server that runs, not one that refuses to.

Nothing is bound, started or written, so this needs no privilege beyond reading
the file it is given — which on a host set up by `install-selfsigned.sh` still
means root or `sudo -u volto`, since `/etc/volto` is `0750 root:volto`.

**What it covers** is what startup does with the file before it becomes a
server: TOML syntax, every table's refusal of a key it does not know, and every
range and cross-field rule (`keep_alive_interval` against `max_idle_timeout`,
`mtu_upper_bound` against `initial_mtu`, and the rest) — including that
`server.cert` and `server.key` exist and are files. When `server.cert` reads as
a PEM certificate chain, its leaf is parsed and refused in the words startup
uses if the server's TLS would refuse it. `server.ech_key`, when set, is read
whole: the same checks startup makes on that file. So is
`server.ech_previous_key`, together with the check that its config_id differs
from the current key's. One thing outside the file
is judged too: `RUST_LOG`, when it is set in the check's environment, by the
rule startup holds it to, so a value that would stop the start fails the check
with the same message, and one startup would ignore is a warning.

**What it does not cover** is what only the running service can answer: whether
the listen address is free, whether a certificate file that does not read as
PEM parses at all, whether the key parses and whether the two form a usable
pair, and whether `RLIMIT_NOFILE` leaves room for `max_connections` ×
`max_targets_per_conn`. That last one is a property of the systemd unit rather
than of the file, so answering it from a shell would answer a different
question than the one that matters. A file that passes can still fail to serve
for one of those reasons; a file that fails will not start at all.

The reason the flag exists is the section below: it is how
[`script/deploy.sh`](deployment.md#deploying-from-releases) asks a release it is
about to install whether it can read the file this host already has, before it
swaps the binary.

## Collecting a support bundle

```sh
volto --diagnostics --config /etc/volto/config.toml
```

prints, to stdout, everything an issue about a host would otherwise be a series
of questions about, and exits 0. In order: the version of the binary that
printed it; the configuration file's path and every table of it as this binary
parsed it, after defaults, so `[limits]` and `[security]` are the values the
server would actually run on rather than the subset the file happens to name;
the warnings `--check-config` prints; the descriptor limits of **the process
that ran the command**, soft and hard, since the hard limit is what says whether
a soft one that is too low can be raised here at all or needs the unit changed,
and on Linux the same pair for the running service, read from `/proc`; the four
`net.core` UDP buffer sysctls named under [UDP socket
buffers](deployment.md#udp-socket-buffers), read from `/proc/sys` on Linux and
reported as unavailable on any other platform; and the kernel's name, release
and machine, the line `uname -srm` prints, read with the system call so that no
`uname` program is needed.

**Passwords are redacted.** Every `[auth].users` entry prints its password as
`<redacted>`, by the same guard that keeps one out of the error a malformed file
produces, so the output is safe to paste into an issue. Read it before pasting
anyway: the rest of the configuration is there in full, host names and listen
address included.

**The descriptor limits are this command's, not the service's.** Run from an SSH
shell the two `RLIMIT_NOFILE` lines are that shell's, which is how 1024 and
1048576 came to be recorded for two hosts running the service at 131072. The
line under them says so, and on Linux the section then prints the running
service's own figures, read from `/proc/<pid>/limits`:

```text
[file descriptors]
RLIMIT_NOFILE soft = 1024
RLIMIT_NOFILE hard = 1048576
these two are this process's own limits, not the service's (the service's are in /proc/<MainPID>/limits)
service pid 5312 Max open files soft = 131072
service pid 5312 Max open files hard = 131072
```

The service is found by walking `/proc`, so no unit name is assumed and nothing
is asked of `systemctl`: a process matches when its `comm` is `volto`, or when
its `exe` link resolves to the binary this command is running. The name alone
is enough because the link is readable only with privilege, reads `(deleted)`
once the deploy script has replaced the file under the running service, and is
a different path when this command is run from a freshly unpacked tarball.
Every match is printed with its own pid,
so a second volto started by hand is visible rather than folded into one answer.
A host with no such process prints one line saying so, and a file that cannot be
read prints one line saying that; neither changes the exit status. On any other
platform the section says these figures are Linux only. To read them by hand,
`systemctl show -p MainPID volto` gives the pid for `/proc/<MainPID>/limits`.

Nothing is bound, connected or resolved, nothing is written, and no journal is
read, so this asks for no more privilege than reading the configuration file
does. The two flags refuse to be combined: `--check-config` and `--diagnostics`
answer different questions and neither is the obvious winner, so a command line
naming both is rejected rather than one of them ignored.

## Version compatibility

An unknown key is refused, and the file is refused *whole* rather than the one
key: nothing else in it takes effect, so this is a startup failure and not a
warning. Two consequences, and they are not symmetric.

**Upgrading is safe, with one kind of exception.** A key a later release adds takes its
documented default when the file does not mention it, and nothing ever rewrites
`/etc/volto/config.toml`: not `script/deploy.sh` on an update, not
`install-selfsigned.sh` on a re-run. No key has been renamed or removed. Two
accepted values of `congestion_control` have been removed: `"bbr-capped"` in
v1.3.0 and `"bbr-uncapped"` in v1.8.0 (documented under
[What is stable from v1.0.0](#what-is-stable-from-v100)). A file that sets
either is refused at startup, and apart from those two values a file written
for any earlier release still loads.

**Rolling back is not.** A file that names a key the older binary does not know
stops it from starting at all, which is the one moment that costs the most: a
rollback is only ever run when something is already wrong. The failure looks
like this in the journal, and it names the file, the line and the column but not
the key — a parse error redacts every quoted segment of the parser's message,
because the same message can quote a password, and a key is quoted the same way:

```
Error: failed to parse config file /etc/volto/config.toml at line 181, column 1: unknown field `<redacted>`
```

The line number is what to act on: comment that key out and start the
service. To find out before the restart instead of after it, ask the binary you
are about to install:

```sh
/path/to/old/volto --check-config --config /etc/volto/config.toml
```

which is what `script/deploy.sh` does on your behalf — but only for a release
that knows the flag. Rolling back past the release that introduced it leaves you
with the table below and the line number in the journal.

| Key | Introduced in |
|---|---|
| `[limits].connect_timeout` | v0.2.6 |
| `[limits].socket_recv_buffer`, `[limits].socket_send_buffer` | v0.2.8 |
| `[limits].ip_family_preference` | v0.2.9 |
| `[limits].mtu_upper_bound` | v0.4.5 |
| `[security].expected_sni` | v0.9.0 |
| `[server].ech_key` | v1.6.0 |
| `[security].require_ech` | v1.6.0 |
| `[server].ech_previous_key` | v1.7.0 |

Everything else has been there since v0.1.0. `mtu_upper_bound` is the one that
matters in practice, because the shipped example sets it and every install made by
`install-selfsigned.sh` is derived from that example — so a host first installed
at v0.4.5 or later carries it whether or not anyone chose it.

**Why the rejection stays.** Ignoring unknown keys would make rollback a
non-event, and it would also make one typo dangerous rather than merely wrong.
Every misspelled key falls back to a default; for `[auth].users` that default is
the empty list, and an empty user list is an open proxy. A configuration that
silently drops its credentials is a worse failure than a service that refuses to
start, so the refusal stands and the rollback cost is paid in this section
instead.

### What is stable from v1.0.0

Configuration keys and the command-line arguments are stable within 1.x, under
four rules. A key keeps its name and its meaning. A file written for any earlier
1.x release still loads. A documented default can move in a minor release when
the release note says so, and the old value stays settable. A key is removed
only after at least one minor release has warned about it at startup. The
cases so far are these. v1.2.0 lowers the documented default of `mtu_upper_bound` from
1452 to 1436 on measured evidence (the MTU paragraphs under [Notes that matter
in practice](#notes-that-matter-in-practice) give it); a host that relied on
1452 can set it explicitly. v1.2.0 also changes what `bbr`, the default value of
`congestion_control`, selects: from 1.2.0 to 1.7.0 it was quinn's BBR with its
window capped, the controller v1.1.0 and v1.1.1 called `bbr-capped`. A file that writes
`bbr` or leaves the key out gets it without an edit. In v1.1.0 and v1.1.1 that
controller was opt-in under the name `bbr-capped`, and 1.2.0 also accepted
`bbr-capped` as an alias. v1.3.0 removes the alias without a warning release
first, the first of two exceptions to the rules above so far. The value existed
for two patch releases only, so a file that still writes `bbr-capped` is refused
at startup with an unknown-variant error that gives its line and column, and the
fix is to write `bbr`. From 1.2.0 to 1.7.0 `bbr-uncapped` selected quinn's BBR as `bbr`
had selected it before. v1.8.0 removes that value, also
without a warning release, which is the second exception: `bbr` no longer uses
quinn's BBR, the comparison the value existed for is made, and quinn's BBR
loses packets on a bulk download that `bbr` does not. A file that still writes
`bbr-uncapped` is refused at startup with an unknown-variant error that gives
its line and column, and the fix is to write `bbr` or to remove the line. A new key keeps
taking its documented default when the file does not mention it, which is what
makes the upgrade half of this section a no-op.

Two things are deliberately outside that promise. Log line shapes are not an
interface: fields are added, reworded and moved between levels as the
operational picture changes, and a parser built on them is built on something
that moves. Neither is the `volto` library API: the crate is a library so that
the tests and the fuzz targets can reach the parsers and the bounds directly,
and every item it exposes exists for them.

## A minimal file

```toml
[server]
listen = "0.0.0.0:443"
cert   = "/etc/volto/fullchain.pem"
key    = "/etc/volto/privkey.pem"

[auth]
users = [{ username = "user1", password = "…" }]
```
