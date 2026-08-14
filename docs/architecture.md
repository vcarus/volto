# Architecture

MASQUE is not one protocol but a set of IETF specifications that put proxy
tunnels on top of HTTP/3. A classic HTTP proxy gives you one TCP tunnel per
connection; here one QUIC connection multiplexes arbitrarily many TCP and UDP
tunnels, and looks like ordinary HTTP/3 traffic from the outside.

```
CONNECT-UDP (RFC 9298)          UDP proxying semantics
classic CONNECT (RFC 9114 §4.4) TCP proxying semantics
HTTP Datagrams + Capsules (RFC 9297)
Extended CONNECT (RFC 9220)
HTTP/3 (RFC 9114) + QPACK (RFC 9204)
QUIC (RFC 9000) + DATAGRAM frames (RFC 9221)
TLS 1.3 (RFC 8446 / RFC 9001) over UDP
```

RFC 9298 stands on 9297 and 9220; 9297 stands on 9221. The TCP path needs none of
them — only RFC 9114 itself.

## The path of a request

`quic.rs` owns the quinn endpoint. Transport parameters come from `[limits]`, so
the stream cap, idle timeout, keep-alive, MTU settings, congestion controller and
initial RTT are configuration rather than constants; they apply to connections
accepted from then on, including across a SIGHUP reload.

Each accepted connection is handed to `h3api::Connection::handshake`, which must
advertise **both** `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08) and
`SETTINGS_H3_DATAGRAM` (0x33). Surge checks for both and disconnects if either is
missing; this is the first thing to suspect when a client drops immediately after
a successful TLS handshake.

`conn.rs` runs the accept loop and dispatches each request stream on the
`:protocol` pseudo-header, after authenticating it:

- **absent, method CONNECT** → `tunnel/tcp.rs`
- **`connect-udp`** → `tunnel/udp.rs`
- **anything else** → 501

Authentication deliberately runs *before* routing, so an unauthenticated client
gets 407 rather than learning from a 501 which `:protocol` values this server
implements.

One caveat about that 501: at the pinned h3 revision, `:protocol` values unknown
to h3 itself are rejected as `H3_MESSAGE_ERROR` inside h3 before the request
reaches application code. Protocols h3 knows (`connect-ip`, `webtransport`,
`websocket`) still get a proper 501. RFC 9220 makes the 501 a SHOULD, and the
gap costs nothing in practice, so it is an accepted deviation rather than an
upstream patch.

### TCP tunnels

`tunnel/tcp.rs` resolves `:authority` explicitly — not implicitly through
`TcpStream::connect((host, port))`, because the destination policy has to see the
resolved address — answers 200, and then runs two independent pumps with full
RFC 9114 §4.4 half-close semantics:

| Event | Behaviour |
|---|---|
| client finishes the stream | `shutdown(Write)` on the target socket, **not** a full close |
| target EOF | finish the send side of the response stream |
| target RST or error | reset the stream with `H3_CONNECT_ERROR` |
| client resets the stream | close the TCP connection |

Collapsing this into "one side closes, everything closes" breaks every protocol
that depends on half-close. The abnormal paths coordinate through a sticky
`watch` teardown channel so that neither pump can strand the other.

### UDP tunnels

`tunnel/udp.rs` parses the RFC 9298 well-known path template. Surge has no URI
template parameter, so it uses the default template the RFC defines for exactly
that case:

```
https://$PROXY_HOST:$PROXY_PORT/.well-known/masque/udp/{target_host}/{target_port}/
```

Parsing is deliberately lenient: percent-decoding, an optional trailing slash, a
port in 1..=65535 and an empty query. IPv6 literals arrive **without** brackets,
with the colons escaped (`2001:db8::42` → `2001%3Adb8%3A%3A42`) per RFC 9298
§3.1; the bracketed form is also accepted.

Two ordering rules that are easy to get wrong:

- **Answer 2xx immediately** — do not wait for the target to send anything. UDP
  is connectionless and the proxy cannot know whether the target is reachable.
- **But resolve DNS first.** When `target_host` is a name, resolution MUST
  complete before the response; a failure is refused with 502 and
  `Proxy-Status: volto; error=dns_error` (RFC 9209). "Immediate" means "without
  waiting for the target", not "without resolving".

The target socket is connected, so packets from anywhere else are dropped by the
kernel. Sessions have their own idle timeout (default 180 s; RFC 9298 §3.5 asks
for at least 120), and closing the socket must also close the request stream.

## Datagram routing

Each connection runs one `read_datagram` task, in `conn.rs`, that routes inbound
datagrams to per-session channels. Two fields decide where a packet goes, and
both are silent when wrong:

- **Quarter Stream ID = stream ID ÷ 4** (RFC 9297 §2.1), not the stream ID.
  Client-initiated bidirectional stream IDs are always multiples of four, so the
  low two bits carry no information and dividing saves encoding space. The old
  draft term "Flow Identifier" is gone, and there is no separate mapping table.
- **Context ID**, a varint at the head of the payload (RFC 9298 §4). `0` means a
  raw UDP payload; anything else is an extension. An unknown Context ID is
  dropped silently — never a connection error.

Get either wrong and the symptom is "the handshake succeeds, the tunnel is
established, and not one packet gets through", with no error anywhere. The
encoder and decoder are hand-rolled in `src/datagram.rs` — about thirty lines,
which is why no dependency is carried for them.

Routing uses a bounded channel and `try_send`: a session that is not draining
its queue loses packets, which is correct UDP behaviour, instead of blocking the
routing task and starving every other session on the connection.

## The capsule stream

The request stream of a CONNECT-UDP tunnel is not an empty stream. Its body is a
sequence of capsules (RFC 9297 §3), each `Type varint + Length varint + Value`,
handled by `src/capsule.rs` as an incremental TLV decoder:

- Requests and responses carry `Capsule-Protocol: ?1`; a response using capsules
  must not carry `Content-Length`, `Content-Type` or `Transfer-Encoding`.
- **Unknown capsule types are skipped** by reading the length and discarding the
  value edge-to-edge, with no accumulation — a peer declaring a 2⁶²-byte capsule
  costs no memory. A truncated capsule is a malformed message.
- The DATAGRAM capsule (type 0x00) is the reliable fallback channel for when QUIC
  datagrams are unavailable. It is a *fallback*, not a downgrade: a target packet
  too large for a QUIC datagram is dropped rather than re-routed through the
  capsule stream, which would break end-to-end unreliability and defeat the
  inner path-MTU discovery.

Treating the stream bytes as opaque is a worse trap than the Quarter Stream ID:
the decoder desynchronizes on the first capsule that arrives.

RFC 9297 §2.1.1 also forbids sending QUIC datagrams before the peer has
advertised `SETTINGS_H3_DATAGRAM`. volto tracks this per connection and refreshes
it on every request rather than snapshotting it at handshake time, because the
peer's SETTINGS frame usually arrives after the handshake completes — a snapshot
would silently drop the first session's packets.

## Why h3 is pinned

`Cargo.toml` pins `h3` and `h3-quinn` to a git revision, and `Cargo.lock` is
committed. The published 0.0.x releases predate three fixes that a proxy cannot
live without ([hyperium/h3](https://github.com/hyperium/h3)):

- **#340** — `h3-datagram` 0.0.2 computes the Quarter Stream ID varint and then
  writes a zeroed array instead. Every outbound datagram is tagged Quarter Stream
  ID 0, so the first UDP session on a connection happens to work and every
  session after it is misrouted. This is the textbook version of "handshake fine,
  no packets".
- **#344** — unbounded memory growth in `BufRecvStream` against a slow consumer,
  which is a denial-of-service surface for a long-running proxy.
- **#331** — a panic in h3-quinn when `stop_sending` lands on a receive stream
  that is still in progress. A proxy resets tunnel streams routinely.
- **#357** — included in the same pinned revision.

`h3-datagram` is deliberately **not** a dependency, both because of #340 and
because everything volto needs from it is two varint operations; quinn's native
`send_datagram`/`read_datagram` plus `src/datagram.rs` cover it.

Do not bump the revision, run a blanket `cargo update`, or add `h3-datagram`
without reviewing the upstream changes and running the full suite.

## The h3api boundary

`src/h3api.rs` is the only module allowed to name `h3` or `h3-quinn` types.
Everything else sees `http`, `bytes` and `quinn` types. The boundary keeps a
0.0.x dependency's API churn contained in one file, and leaves the door open to
swapping the HTTP/3 implementation without touching the tunnel logic.

One gotcha it cannot hide: `h3api::Connection::handshake` consumes the
`quinn::Connection`, so clone it first if you also need datagram I/O.

## Testing

Integration tests assert **on-wire behaviour, not internal state**: status codes,
response headers, and in `it_settings` the actual bytes the server writes on its
control stream. That is what makes a dependency bump reviewable — the tests
describe the protocol, so they still mean something after the implementation
underneath changes.

Two tests are load-bearing beyond their names:

- The multi-session concurrent CONNECT-UDP test is the regression baseline for
  Quarter-Stream-ID-class bugs. Three sessions on one connection, each verified
  to receive its own traffic. Never weaken it.
- `it_migration` rebinds the client endpoint mid-tunnel and asserts that existing
  tunnels survive the address change and that new ones can still be opened, which
  pins QUIC connection migration against an accidental `migration(false)` or an
  upstream regression.

`it_stress` keeps a heavy tier behind `#[ignore]` (500 concurrent tunnels, 10000
setup/teardown rounds) and a light tier in the default run that catches slot
leaks by shrinking the quota until a leak turns into an observable 503.

Test infrastructure lives in `tests/common/mod.rs`: an in-process server plus
self-signed certificates from `rcgen`, so no test needs a fixture on disk.

One thing that suite cannot do is disagree with itself: its client is built from
the same pinned `h3` revision as the server, so both ends share any
misunderstanding of the specification. The `interop` CI job closes that gap by
starting a real `volto` process and driving it with Go's
[masque-go](https://github.com/quic-go/masque-go) on quic-go — an independent
implementation — over the RFC 9298 default URI template, with authentication on
and the server's certificate trusted rather than skipped. It asserts multi-round
CONNECT-UDP echo on one session, three concurrent sessions on a single QUIC
connection receiving only their own traffic, `Proxy-Status` on a refusal, and a
407 when credentials are omitted. The client lives in `tests/interop/`, which is
a Go module rather than a Rust test, so `cargo test` neither sees nor needs it.
