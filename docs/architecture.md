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

The UDP socket underneath is bound here rather than by `quinn::Endpoint::server`,
which is a bare `std::net::UdpSocket::bind` and never sets `SO_RCVBUF`/`SO_SNDBUF`
— a server that does not ask keeps `net.core.rmem_default` whatever `rmem_max`
says. `limits.socket_recv_buffer` / `socket_send_buffer` are requested at that
moment and the granted sizes read back, so a capped request becomes a startup
warning rather than silent packet loss. Being a property of the socket rather
than of a connection, these two are the only `[limits]` keys a reload cannot
change.

Each accepted connection is handed to `h3api::Connection::handshake`, which must
advertise **both** `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08) and
`SETTINGS_H3_DATAGRAM` (0x33). Surge checks for both and disconnects if either is
missing; this is the first thing to suspect when a client drops immediately after
a successful TLS handshake. The frame also carries `SETTINGS_MAX_FIELD_SECTION_SIZE`
(64 KiB), both QPACK settings as zero, and one reserved "grease" identifier of
RFC 9114 §7.2.4.1's `0x1f * N + 0x21` form, which that section says endpoints
SHOULD send so peers keep exercising the rule that unknown identifiers are
ignored.

`conn.rs` runs the accept loop and dispatches each request stream on the
`:protocol` pseudo-header, after authenticating it:

- **absent, method CONNECT** → `tunnel/tcp.rs`
- **`connect-udp`** → `tunnel/udp.rs`
- **anything else** → 501

Authentication deliberately runs *before* routing, so an unauthenticated client
gets 407 rather than learning from a 501 which `:protocol` values this server
implements — but *after* the connection-specific-field check described below, so
a peer that sends one of those fields gets 400 whether or not it has
credentials.

That 501 is a real one for every `:protocol` value, not only the ones this
server has heard of. The token is carried through as the bytes that arrived, so
`connect-ip`, `webtransport` and anything else are answered with the status
RFC 9220 asks for and logged under the name the client actually sent, rather
than being refused as malformed before anything can look at them.

Every wait that stands between a packet arriving and a tunnel opening is bounded
by `limits.max_idle_timeout`, whatever the connection's authentication state:
the QUIC/TLS handshake in `quic.rs`, the HTTP/3 handshake and the read of each
peer unidirectional stream's type in `h3/connection.rs`, the read of a request
stream's HEADERS in `Resolver::resolve`, and every response this server writes
before a tunnel starts relaying — 400, 403, 407, 431, 501 and the 5xx family,
the 200 that closes on the spot, and the 200 that opens a tunnel — in
`Stream::respond_within`. The bound is needed because the keep-alive PINGs
this server sends are answered by the peer's QUIC stack with no application ever
involved, so the transport's own idle timer never fires on a peer that is
present but says nothing; the response writes need it because a peer that grants
no flow-control window never takes even the fifty-odd bytes of a 407. A tunnel's
own 200 is bounded like the rest: the pumps that would otherwise end the wait do
not exist until that write returns, and a lapsed one resets the stream and drops
the target socket the request had already opened.

One further bound applies until a request on a connection has passed the
credentials check: twice `limits.max_idle_timeout` for one request to
authenticate. It is armed once at the handshake and never re-armed by a new
stream, so what it bounds is the connection rather than a pause in it; twice, so
that the transport's own idle timeout stays the first thing to fire on a peer
that has simply gone away. Without it a peer that finishes the QUIC handshake
and then says nothing holds a `max_connections` slot for as long as it keeps its
socket open. It is lifted for the life of the connection the moment one request
authenticates, so a client reusing an idle connection between requests is
untouched. A lapsed connection bound closes the connection with `H3_NO_ERROR`,
which is not an error and is logged as the idle ending it is; a lapsed HEADERS
bound resets that one stream with `H3_REQUEST_INCOMPLETE` and a lapsed response
write resets it with `H3_REQUEST_CANCELLED`, leaving everything else on the
connection running.

### Target address selection

Both tunnel kinds resolve their target through one function in `tunnel/mod.rs`,
which is also where the resolved list is ordered by
`limits.ip_family_preference` — before the destination policy filters it and
before either tunnel dials anything, so the two cannot disagree about which
family goes first. The default is IPv4-first, deliberately unlike `getaddrinfo`, which
orders by RFC 6724 and so puts global IPv6 ahead of IPv4 on any host with an
IPv6 route. That ordering is an operator policy on a proxy rather than a
resolver detail: the TCP path walks the list in order, so the non-preferred
family costs a full connect attempt, and the CONNECT-UDP path has no failover at
all — connecting a UDP socket only asks the kernel for a route, so the first
address with one wins outright. The reorder is a stable partition, leaving
RFC 6724's ordering within each family intact; `system` opts out of it entirely.

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
§3; the bracketed form is also accepted.

Two ordering rules that are easy to get wrong:

- **Answer 2xx immediately** — do not wait for the target to send anything. UDP
  is connectionless and the proxy cannot know whether the target is reachable.
- **But resolve DNS first.** When `target_host` is a name, resolution MUST
  complete before the response; a failure is refused with 502 and
  `Proxy-Status: volto; error=dns_error` (RFC 9209). "Immediate" means "without
  waiting for the target", not "without resolving".

The target socket is connected, so packets from anywhere else are dropped by the
kernel. Sessions have their own idle timeout (default 180 s; RFC 9298 §3.1 asks
for at least 120), and closing the socket must also close the request stream.

## Datagram routing

Each connection routes inbound datagrams to per-session channels from its own
background task, in `src/h3/connection.rs` — the same task that reads the peer's
unidirectional streams, since both belong to the connection and both end with
it. A peer may hold sixteen of those open at once (`MAX_PEER_UNI_STREAMS`, a
transport parameter rather than a configuration key) where HTTP/3 needs three,
and each one's type has to arrive within an idle timeout. Routing is per
*request stream*, which is why it lives in the HTTP/3 layer: a session claims
its Quarter Stream ID by asking its stream for a `DatagramReceiver` and holds
the claim exactly as long as it holds that receiver, so a session that ends —
however it ends — takes its routing entry with it. Sending is the other half
and stays outside: a UDP session writes its datagrams straight onto the
`quinn::Connection`.

Two fields decide where a packet goes, and getting either subtly wrong is
silent:

- **Quarter Stream ID = stream ID ÷ 4** (RFC 9297 §2.1), not the stream ID.
  Client-initiated bidirectional stream IDs are always multiples of four, so the
  low two bits carry no information and dividing saves encoding space. The old
  draft term "Flow Identifier" is gone, and there is no separate mapping table.
  A value no session owns is dropped, since a session can close with packets
  still in flight — but a value that cannot be a stream ID at all (above 2⁶⁰-1,
  or a datagram too short to parse one) closes the whole QUIC connection with
  H3_DATAGRAM_ERROR (0x33), which RFC 9297 §2.1 states as a MUST.
- **Context ID**, a varint at the head of the payload (RFC 9298 §5). `0` means a
  raw UDP payload; anything else is an extension. An unknown Context ID is
  dropped silently — never a connection error — and so is a truncated one, which
  no requirement covers.

Get either wrong and the symptom is "the handshake succeeds, the tunnel is
established, and not one packet gets through", with no error anywhere. The
encoder and decoder are hand-rolled in `src/datagram.rs` — about thirty lines,
which is why no dependency is carried for them.

Routing uses a bounded channel and `try_send`: a session that is not draining
its queue loses packets, which is correct UDP behaviour, instead of blocking the
routing task and starving every other session on the connection. A CONNECT (TCP)
tunnel never claims a receiver, so it never appears in the table at all.

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
advertised `SETTINGS_H3_DATAGRAM`. The flag is one shared atomic rather than a
value each session snapshots: the task that reads the peer's control stream
writes it and every session reads it once per packet, so a session opened before
the SETTINGS arrived moves onto QUIC datagrams the moment they do. The module
comment on `src/h3/connection.rs` records what the sampled version cost.

## The HTTP/3 layer

HTTP/3 is implemented in `src/h3` rather than taken from a crate. What it covers
is what a CONNECT proxy needs, and it is stated in full:

- **Framing** (RFC 9114 §7) — an incremental decoder that hands DATA payload on
  in the chunks quinn delivered it in, buffers every other frame because none of
  them can be acted on piecewise, and skips an unknown frame type by its declared
  length without allocating for it.
- **QPACK** (RFC 9204) against the static table, including Huffman decoding
  (RFC 7541 Appendix B).
- **The control stream** — SETTINGS, GOAWAY, and the rules about what may appear
  there, read by a task of its own for as long as the connection lasts.
- **Request validation** — RFC 9114 §4.1.2, §4.3 and §4.4 plus RFC 8441 §4: the
  point at which a field section becomes a request or is refused as malformed.
- **The message vocabulary** — a status, a method, a request and a list of field
  lines, in `src/h3/message.rs`. These were the `http` crate's until decision
  D78; carrying it meant every decoded field was validated and copied a second
  time into a `HeaderName`/`HeaderValue`, and the pseudo-headers were folded into
  a URI that the tunnels then took apart again. A field section is now decoded
  once, validated once, and carried in one type, and the crate is gone from the
  dependency tree.

What it leaves out, deliberately:

- **The QPACK dynamic table.** `SETTINGS_QPACK_MAX_TABLE_CAPACITY` and
  `SETTINGS_QPACK_BLOCKED_STREAMS` are both advertised as 0, which RFC 9204
  §3.2.3 and §2.1.2 make binding on the peer's encoder. A field line referencing
  a dynamic entry is therefore a protocol violation answered with
  `QPACK_DECOMPRESSION_FAILED`, not a gap in the implementation — and the
  eviction and head-of-line blocking that go with a dynamic table are gone with
  it. The peer's encoder and decoder streams are still read, instruction by
  instruction: with no table, an insertion, a capacity above zero, a Section
  Acknowledgment or an Insert Count Increment is the connection error RFC 9204
  §3.2.2, §4.3.1, §4.4.1 and §4.4.3 make it, and only a zero capacity and a
  Stream Cancellation pass.
- **Huffman encoding.** A response here is a status line and at most two short
  fields; compressing it would save a handful of bytes per tunnel. Decoding is
  implemented because a client's request arrives Huffman-coded.
- **Server push and WebTransport.** A push stream from a client is a connection
  error either way (RFC 9114 §6.2.2), and `webtransport` is a `:protocol` this
  server answers 501 to. The push bookkeeping frames are still judged: every
  CANCEL_PUSH names a push this server never promised (RFC 9114 §7.2.3), and a
  MAX_PUSH_ID may not shrink (§7.2.7) — both `H3_ID_ERROR`.

A connection error is a `quinn::Connection::close` carrying the HTTP/3 code,
which is exactly what RFC 9114 §8 defines one to be. Nothing has to be
propagated between tasks: closing the connection makes every operation on it
fail on its own, so only the *reason* is recorded on the way past — quinn
overwrites its own stored reason with "closed locally" — and read back by the
accept loop.

Field sections are bounded at 64 KiB, advertised as
`SETTINGS_MAX_FIELD_SECTION_SIZE` so a peer that respects SETTINGS never sends
more, and enforced on receipt so one that does not gets no further. The frame
layer refuses an oversized non-DATA frame from its declared length, before a byte
is allocated for it.

That bound is per frame, and a peer may open as many streams as its transport
parameters allow. What one connection may hold in frames it has announced but not
finished is therefore bounded separately, at 1 MiB summed over its request
streams: a frame is charged for the length it announced the moment the decoder
commits to buffering it, and the charge is returned when the frame completes or
when the stream carrying it ends. The request that would take a connection past
that is refused with **431 and stopped** with `H3_EXCESSIVE_LOAD`, which is the
same answer a single oversized field section gets; the connection and its tunnels
are untouched. A CONNECT request with credentials is a few hundred bytes, so
every request stream the transport allows could be mid-HEADERS at once and still
be using a tenth of the budget — what reaches it is sixteen field sections of the
largest advertised size in flight together, and the seventeenth of those is what
is refused. The peer's control stream is not counted in it: there is one of it
per connection, it buffers one frame at a time, and nothing on it can be refused
stream by stream.

One choice here is worth stating, though it is within the RFC: a malformed
request is answered with a bare **400 and a clean stream close** rather than a
reset wherever the fault is visible at the tunnel layer -- a CONNECT-UDP request
carrying `Content-Length` or `Content-Type` (RFC 9297 §3.2), or any request
carrying one of the connection-specific fields RFC 9114 §4.2 forbids
(`Proxy-Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`). RFC 9114
§4.1.2 lets a server "send an HTTP response indicating the error prior to
closing or resetting the stream", and `it_tcp` and `it_udp` pin the 400. The
`Connection` field itself is refused at decode time with `H3_MESSAGE_ERROR`,
earlier still. The four-field check runs before the credentials check rather
than after it, unlike the routing it precedes: a message carrying one is
malformed whoever sent it, and judging it afterwards answered that MUST with a
407 to an unauthenticated peer and a 400 to an authenticated one.

One deviation is taken knowingly:

- A peer that closes its QPACK encoder or decoder stream is **not** treated as
  `H3_CLOSED_CRITICAL_STREAM`, which RFC 9204 §4.2 requires. With a zero table
  capacity those streams carry nothing, so nothing is lost when they end — and a
  client that tidily finishes its streams a moment before CONNECTION_CLOSE would
  otherwise be logged as a fault it did not commit.

HTTP Datagrams are hand-rolled in `src/datagram.rs`. That started as a way around
`h3-datagram` 0.0.2, which tagged every datagram with Quarter Stream ID 0 and so
misrouted every session after the first on a connection; it is simply ours now —
about thirty lines of varint work with no dependency behind them.

## Why quinn-proto is patched (temporary)

`Cargo.toml` carries a `[patch.crates-io]` stanza pointing `quinn-proto` at a
commit on upstream's `0.11.x` branch. quinn-proto's MTU black-hole detector treats
an ordinary congestion loss burst during a bulk transfer as proof that the path
has stopped carrying the current MTU, so a download makes the connection fall
back to the 1200-byte floor — and on the 0.11.x branch every further loss burst
at the floor re-triggers the detector and pushes the next probe out again, so the
MTU stays there for as long as the transfer lasts. That branch was also missing
two comparison fixes that upstream had landed on `main` only.

The pinned commit, `dcb9eabe`, is the squash merge of
[quinn-rs/quinn#2799](https://github.com/quinn-rs/quinn/pull/2799): the
`quinn-proto-0.11.17` tag plus three fixes, all of them in
`quinn-proto/src/connection/mtud.rs`:

- "Fix some comparisons in the black hole detector" and "Relax MTU discovery
  state assertion", backported from
  [quinn-rs/quinn#2400](https://github.com/quinn-rs/quinn/pull/2400).
- "proto: treat an equal-size delivery as evidence against a preceding loss
  burst". The actual bug is
  [#2791](https://github.com/quinn-rs/quinn/issues/2791) and the fix
  [#2792](https://github.com/quinn-rs/quinn/pull/2792), merged to `main`.

No 0.11.x *release* carries these yet, which is why the stanza pins a commit
rather than a version. Because that commit's version *is* the upstream tag,
anything true of quinn-proto 0.11.17 is true here except those three fixes.

**Exit condition:** drop the stanza as soon as a quinn-proto 0.11.x release
includes the fix, then `cargo update -p quinn-proto` and remove the CI audit
workaround described below. Two things do not work while it is in place:

- Dependabot does not touch git dependencies, so it cannot bump this one. The
  pinned commit is moved by hand whenever quinn-proto ships a security or
  hardening release, and moving it is forced if a `quinn` release raises its
  quinn-proto requirement above 0.11.17.
- cargo-audit skips lockfile entries whose source is not the default registry, so
  the patched entry would fall out of RustSec coverage. The `audit` job in
  `.github/workflows/ci.yml` works around this by scanning a copy of `Cargo.lock`
  with that one `source` line rewritten back to the registry — which is sound
  precisely because the version is the upstream tag.

## The h3api facade

`src/h3api.rs` is the facade over `src/h3`: the only module allowed to name a
type from it, so that everything else — `conn`, `quic`, the tunnels — sees
`bytes` and `quinn` types plus the handful of names it exports. The facade began
as insulation from a 0.0.x dependency's API churn and was kept on its own terms:
it is the list of what a proxy actually asks of HTTP/3, and it is short enough to
read in one sitting.

The message types — `Request`, `Status`, `Fields` — are re-exported through it
rather than wrapped in something else. The rule the facade enforces is about
*where a type is named*, not about hiding it: nothing outside `src/h3` reaches
into that module, so this one file still says everything the rest of the crate
may assume about HTTP/3.

One gotcha it cannot hide: `h3api::Connection::handshake` consumes the
`quinn::Connection`, so clone it first if you also need to *send* datagrams on
it. Receiving them needs no clone — the HTTP/3 connection routes them itself.

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
  upstream regression. What makes migration work behind NAT at all is quinn's
  non-zero-length server connection IDs (8 bytes by default) — the property
  RFC 9308 §9 strongly recommends for exactly this reason — so any future
  endpoint tuning must not shorten them to zero.

`it_stress` keeps a heavy tier behind `#[ignore]` (500 concurrent tunnels, 10000
setup/teardown rounds) and a light tier in the default run that catches slot
leaks by shrinking the quota until a leak turns into an observable 503.

Test infrastructure lives in `tests/common/`: an in-process server plus
self-signed certificates from `rcgen`, so no test needs a fixture on disk, and
the HTTP/3 client in `tests/common/h3client.rs` that drives it.

One thing that suite cannot do is disagree with itself: that client is built on
the same codec as the server, so a misreading of the framing or of QPACK is one
both ends share. The `interop` CI job closes that gap by
starting a real `volto` process and driving it with Go's
[masque-go](https://github.com/quic-go/masque-go) on quic-go — an independent
implementation — over the RFC 9298 default URI template, with authentication on
and the server's certificate trusted rather than skipped. It asserts multi-round
CONNECT-UDP echo on one session, three concurrent sessions on a single QUIC
connection receiving only their own traffic, `Proxy-Status` on a refusal, and a
407 when credentials are omitted. The client lives in `tests/interop/`, which is
a Go module rather than a Rust test, so `cargo test` neither sees nor needs it.
