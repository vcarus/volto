# volto

A MASQUE proxy server in Rust: HTTP/3 CONNECT tunnels (RFC 9114 §4.4) and
CONNECT-UDP tunnels (RFC 9298) carried over HTTP Datagrams (RFC 9297). It is
built to be reached directly by [Surge](https://nssurge.com)'s `masque` policy,
and to run unattended.

One QUIC connection multiplexes every tunnel. TCP traffic goes through classic
CONNECT, UDP through CONNECT-UDP, and both paths are implemented — a server that
only speaks CONNECT-UDP carries almost none of an ordinary client's traffic.

## Features

- **Both tunnel types.** Classic CONNECT for TCP, CONNECT-UDP for UDP, dispatched
  by the `:protocol` pseudo-header on one connection.
- **Full RFC 9114 §4.4 half-close.** A client FIN shuts down only the write side
  of the target socket; a target EOF finishes only the response side. Protocols
  that depend on half-close survive the proxy.
- **RFC 9297 Capsule Protocol.** The request stream body is a capsule sequence,
  not an empty stream. Unknown capsule types are skipped; the DATAGRAM capsule is
  the fallback channel when QUIC datagrams are unavailable.
- **Authentication.** HTTP Basic on every CONNECT, compared in constant time.
  Both `Proxy-Authorization` and `Authorization` are accepted.
- **Open-proxy defences.** Private and loopback ranges are refused by default
  (including IPv4-mapped bypasses such as `::ffff:127.0.0.1`), port 25 is denied,
  tunnels are capped per connection, and an unanswered UDP session may only send
  a bounded number of packets before its target replies.
- **Configurable QUIC transport.** Stream limits, idle timeout, keep-alive
  interval, initial MTU, PMTU probing, congestion controller and initial RTT are
  all configuration, not constants.
- **SIGHUP reload.** Certificates and credentials are re-read in place. A
  configuration that fails to validate is rejected whole and the running one
  keeps serving — a renewal hook cannot cause an outage.
- **Graceful shutdown.** SIGTERM stops accepting, sends GOAWAY on established
  connections and waits out a configurable grace period.
- **Self-sufficient diagnostics.** Per-request debug logging with redacted
  credentials, plus an `SSLKEYLOGFILE` switch for frame-level analysis.

Explicit non-goals: CONNECT-IP (RFC 9484), traffic obfuscation, and a web admin
panel.

## Quickstart

Grab a static binary from the [releases page](https://github.com/vcarus/volto/releases)
(`x86_64` and `aarch64` musl builds), or build from source with Rust 1.85+.
Every cargo command below passes `--locked`: `Cargo.lock` is committed and
redirects `quinn-proto` at a patched commit, so a build without it is not the
same build (see [docs/deployment.md](docs/deployment.md#building)).

```sh
cargo build --release --locked      # target/release/volto
```

The fastest way to a working server is the self-signed installer, which creates
the system user, generates a certificate, writes `/etc/volto/config.toml` with a
generated 144-bit password, installs the systemd unit and starts it:

```sh
sudo script/install-selfsigned.sh
```

Or let `script/deploy.sh` do the downloading too: it fetches the newest release,
verifies it against `SHA256SUMS` and installs it — running the installer above on
a fresh host, or swapping the binary in place (with automatic rollback if the new
version fails to start) on a host that already has one. With `--enable-timer` it
keeps doing that on a daily systemd timer, so deploy and update become the same
command. Run it from a checkout or a release tarball (`sudo script/deploy.sh
--enable-timer`), or bootstrap a bare host in one line — everything it installs
comes out of the checksum-verified release tarball, the piped copy only steers;
see [docs/deployment.md](docs/deployment.md#deploying-from-releases).

```sh
curl -fsSL https://raw.githubusercontent.com/vcarus/volto/main/script/deploy.sh |
  sudo bash -s -- --enable-timer --username yourname
```

It finishes by printing the certificate fingerprint and a ready-to-paste Surge
policy line:

```
volto = masque, 203.0.113.10, 443, sni=volto.internal, server-cert-fingerprint-sha256=AA:BB:…:FF, username=yourname, password=…
```

The fingerprint *is* the trust anchor in that mode: carry it to the client over a
channel you trust, and never substitute `skip-cert-verify` for it — Basic
credentials are sent on every request, so a man in the middle collects them
immediately. For a domain certificate from a public CA instead, see
[docs/deployment.md](docs/deployment.md).

Run it by hand during development:

```sh
cargo run --locked -- --config config.toml
```

## Documentation

- [docs/configuration.md](docs/configuration.md) — every configuration key, its
  default and what it costs to change.
- [docs/deployment.md](docs/deployment.md) — building, certificates, systemd,
  firewall, file-descriptor budget, reloads, running behind a UDP relay and
  fail2ban.
- [docs/architecture.md](docs/architecture.md) — how a request becomes a tunnel,
  what the in-tree HTTP/3 layer does and does not implement, why quinn-proto is
  patched, and what the tests assert.
- [API documentation](https://vcarus.github.io/volto/) — the crate's rustdoc,
  module by module, rebuilt from `main` on every push.

A commented example configuration ships in
[script/config.example.toml](script/config.example.toml).

## Testing

```sh
cargo test --locked                                # unit + integration
cargo test --locked --test it_policy               # authentication / ACL / quotas
cargo test --locked --test it_stress -- --ignored  # heavy load tier
```

Integration tests assert on-wire behaviour — status codes, response headers, the
actual bytes on the control stream — rather than internal state.

Because that suite has volto on both ends, CI also runs a cross-implementation
job that drives a real server with Go's
[masque-go](https://github.com/quic-go/masque-go) client. The client lives in
[tests/interop](tests/interop) and needs a Go toolchain plus a running server;
see [docs/architecture.md](docs/architecture.md#testing).

## License

MIT. See [LICENSE](LICENSE).
