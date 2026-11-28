<div align="center">

<img src="docs/assets/logo.png" width="120" alt="">

# volto

**A MASQUE proxy server in Rust: HTTP/3 CONNECT and CONNECT-UDP over one QUIC connection, for [Surge](https://nssurge.com)'s `masque` policy and [sing-box](https://sing-box.sagernet.org)'s HTTP/3 `http` outbound.**

[![CI](https://github.com/vcarus/volto/actions/workflows/ci.yml/badge.svg)](https://github.com/vcarus/volto/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/vcarus/volto?display_name=tag)](https://github.com/vcarus/volto/releases/latest)
[![MSRV](https://img.shields.io/badge/rust-1.100%2B-blue)](docs/deployment.md#building)
[![Docs](https://img.shields.io/badge/docs-manual-8da0cb)](https://vcarus.github.io/volto/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

[Quickstart](#quickstart) · [Features](#features) · [Compatibility](#compatibility) · [Documentation](#documentation) · [Testing](#testing)

</div>

---

The server terminates TLS, speaks HTTP/3 to the client and carries **TCP through classic CONNECT** (RFC 9114 §4.4) and **UDP through CONNECT-UDP** (RFC 9298, HTTP Datagrams per RFC 9297). Both paths matter: a server that only speaks CONNECT-UDP carries almost none of an ordinary client's traffic. It runs unattended on a small Linux host, reloads certificates and credentials on `SIGHUP`, and ships as a static binary.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/topology-dark.svg">
    <img src="docs/assets/topology-light.svg" alt="Surge opens one QUIC connection carrying CONNECT and CONNECT-UDP tunnels to volto, optionally through an L4 UDP relay; volto reaches TCP targets over plain TCP and UDP targets over plain UDP" width="880">
  </picture>
</p>

## Quickstart

### 1. One line on a fresh Ubuntu host

Downloads the newest release for the host's architecture, verifies the release key's signature and the checksum, creates the system user, generates a self-signed certificate and a 144-bit password, writes `/etc/volto/config.toml`, installs the systemd unit and starts it. With `--enable-timer` the same script re-runs daily and upgrades in place, with automatic rollback if the new version fails to start.

```sh
curl -fsSL https://raw.githubusercontent.com/vcarus/volto/main/script/deploy.sh |
  sudo bash -s -- --enable-timer --username yourname
```

Add `--ech-public-name public.example` to set up [Encrypted Client Hello](docs/deployment.md#encrypted-client-hello) in the same run (from v1.8.8); the policy line then carries `ech-config` too, and the sing-box outbound an `ech` object.

It finishes by printing a ready-to-paste Surge policy line:

```
volto = masque, 203.0.113.10, 443, sni=volto.internal, server-cert-fingerprint-sha256=AA:BB:…:FF, username=yourname, password=…
```

Below it the same run prints the server as a [sing-box](docs/deployment.md#sing-box) `http` outbound, a JSON object to paste into `outbounds`, for sing-box 1.15.0 or newer.

> **The fingerprint is the trust anchor:** carry it to the client over a channel you trust and never replace it with `skip-cert-verify`, for the reasons under [Self-signed with fingerprint pinning](docs/deployment.md#self-signed-with-fingerprint-pinning). For a public-CA certificate instead, see [Certificates](docs/deployment.md#certificates).

What the signature covers, and why the piped copy is trusted only as far as the repository is, is under [The release signature](docs/deployment.md#the-release-signature); every flag is under [Deploying from releases](docs/deployment.md#deploying-from-releases).

### 2. From a release tarball

Static musl builds for `x86_64` and `aarch64` are on the [releases page](https://github.com/vcarus/volto/releases). Each archive unpacks to the binary, `script/` and `docs/`, so the installer runs straight out of it:

```sh
tar xzf volto-*-x86_64-unknown-linux-musl.tar.gz && cd volto-*/
sudo script/install-selfsigned.sh --binary ./volto  # first install
sudo script/deploy.sh --enable-timer                # or: install + keep it updated
```

### 3. From source

Rust 1.100 or newer, a C and C++ compiler, cmake and libclang (the server's TLS builds AWS-LC's libssl; see [Building](docs/deployment.md#building)). `Cargo.lock` is committed, so build `--locked` to get the dependency graph the releases are built from.

```sh
cargo build --release --locked             # target/release/volto
cargo run --locked -- --config config.toml # run by hand during development
```

A commented example configuration is [script/config.example.toml](script/config.example.toml); only `[server]` is required.

## Features

| Area | What you get |
|---|---|
| **Tunnels** | Classic CONNECT for TCP and CONNECT-UDP for UDP, dispatched by the `:protocol` pseudo-header on one QUIC connection. Full RFC 9114 §4.4 half-close, so protocols that depend on it survive the proxy. |
| **Capsules & datagrams** | RFC 9297 Capsule Protocol on the request stream; unknown capsules are skipped. QUIC DATAGRAM is the fast path, the DATAGRAM capsule the fallback when datagrams are unavailable. |
| **Authentication** | HTTP Basic on every CONNECT, compared in constant time; `Proxy-Authorization` and `Authorization` both accepted; 407 on failure, with a per-connection failure budget. |
| **Open-proxy defences** | Private, loopback and multicast ranges refused by default (IPv4-mapped bypasses included), port 25 denied, tunnels capped per connection, unanswered UDP sessions bounded, name-lookup budget per connection. |
| **TLS** | TLS 1.3 on AWS-LC's libssl with the key exchange groups X25519MLKEM768, X25519, P-256 and P-384, of which the client's order of preference picks one, 1-RTT only with no session tickets, and optional Encrypted Client Hello: `volto ech-keygen` writes the key and prints the ECHConfigList a client's `ech-config` takes. See [Encrypted Client Hello](docs/configuration.md#encrypted-client-hello). |
| **QUIC transport** | Stream limits, idle timeout, keep-alive, initial MTU, PMTU probing, congestion controller (BBR by default) and initial RTT are configuration, not constants. |
| **Operations** | `SIGHUP` reload that rejects a bad configuration whole and keeps serving; graceful shutdown with GOAWAY and a grace period; systemd unit, installer and self-updating deploy script included. |
| **Diagnostics** | Per-request debug logging with redacted credentials, `SSLKEYLOGFILE` for frame-level analysis, `--check-config` (see [what it covers](docs/configuration.md#checking-a-file-without-starting-the-server)), and `--diagnostics`, which prints a support bundle with the passwords redacted. |

**Explicit non-goals:** CONNECT-IP (RFC 9484), traffic obfuscation, and a web admin panel. CONNECT-IP is what sing-box's `masque-client` endpoint and Xray's `masque` outbound speak, so neither connects; sing-box connects through its `http` outbound.

## Compatibility

| | |
|---|---|
| **Client** | Surge (iOS / macOS) `masque` policy. Auth is HTTP Basic; add `sni=` and `server-cert-verify-name=` when the server sits behind a relay IP. |
| **sing-box** | sing-box 1.15.0 or newer, `http` outbound with `"version": 3`: CONNECT for TCP, CONNECT-UDP for UDP, HTTP Basic, certificate pinning and ECH. Tested in CI against the release pinned in `tests/interop/singbox/go.mod`. See [sing-box](docs/deployment.md#sing-box). |
| **Other clients** | Apple's relay client (`NERelay`, `ProxyConfiguration(relayHops:)`) works for CONNECT and CONNECT-UDP; tested through `Network.framework` on macOS 15, not with a device profile. It sends no ECH, so it needs `require_ech` off. See [Apple's relay client](docs/deployment.md#apples-relay-client). |
| **Server** | Linux (`x86_64`, `aarch64`); static musl binaries, no runtime dependencies. Listens on **UDP only**: open the QUIC port in your firewall, there is no TCP listener. |
| **Behind a relay** | Works behind a plain L4 UDP DNAT relay; TLS terminates only on volto. See [Running behind a UDP relay](docs/deployment.md#running-behind-a-udp-relay). |
| **Development** | macOS or Linux, Rust 1.100+. The test suite is green on both. |

From v1.0.0 on, configuration keys and the command-line arguments are stable within 1.x; [What is stable from v1.0.0](docs/configuration.md#what-is-stable-from-v100) gives the rules, the exceptions so far and what the promise leaves out.

## Documentation

| Page | What is in it |
|---|---|
| [The manual](https://vcarus.github.io/volto/) | The three pages below as one searchable book, rebuilt from `main` on every push. |
| [docs/configuration.md](docs/configuration.md) | Every key, its default, and what it costs to change. |
| [docs/deployment.md](docs/deployment.md) | Building, certificates (ACME DNS-01 or self-signed + pinning), releases and rollback, systemd, firewall, fd budget, reloads, relays, fail2ban. |
| [docs/architecture.md](docs/architecture.md) | How a request becomes a tunnel, the in-tree HTTP/3 layer, what the tests assert. |
| [API docs](https://vcarus.github.io/volto/api/) | The crate's rustdoc, rebuilt from `main` on every push. |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability privately. |

## Testing

```sh
cargo test --locked                                # unit + integration
cargo test --locked --test it_policy               # authentication / ACL / quotas
cargo test --locked --test it_stress -- --ignored  # heavy load tier
```

Integration tests assert on-wire behaviour — status codes, response headers, the actual bytes on the control stream — rather than internal state. Because that suite has volto on both ends, CI also runs a cross-implementation job against three independent clients, Go's [masque-go](https://github.com/quic-go/masque-go) (CONNECT-UDP, with and without ECH), Python's [aioquic](https://github.com/aiortc/aioquic) (CONNECT and CONNECT-UDP) and [sing-box](https://github.com/SagerNet/sing-box) (both, through its SOCKS5 inbound, with and without ECH); see [tests/interop](tests/interop) and [Testing](docs/architecture.md#testing).

## License

MIT. See [LICENSE](LICENSE).
