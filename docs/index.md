<p align="center"><img src="assets/logo.png" width="96" alt=""></p>

# volto

This manual covers volto, a MASQUE proxy server written in Rust. One QUIC connection from the client carries TCP through classic CONNECT (RFC 9114 §4.4) and UDP through CONNECT-UDP (RFC 9298, HTTP Datagrams per RFC 9297), both dispatched by the `:protocol` pseudo-header. It terminates TLS itself, runs unattended on a small Linux host, reloads certificates and credentials on `SIGHUP`, and ships as a static binary. It is built to interoperate with Surge's `masque` policy.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/topology-dark.svg">
    <img src="assets/topology-light.svg" alt="Surge opens one QUIC connection carrying CONNECT and CONNECT-UDP tunnels to volto, optionally through an L4 UDP relay; volto reaches TCP targets over plain TCP and UDP targets over plain UDP" width="880">
  </picture>
</p>

## Install

One line on a fresh Ubuntu host downloads the newest release for the architecture, verifies it against `SHA256SUMS`, creates the system user, generates a self-signed certificate and a password, writes `/etc/volto/config.toml`, installs the systemd unit and starts it:

```sh
curl -fsSL https://raw.githubusercontent.com/vcarus/volto/main/script/deploy.sh |
  sudo bash -s -- --enable-timer --username yourname
```

It finishes by printing a ready-to-paste client policy line. Every flag, the certificate options and the tarball route are in the deployment chapter.

## This manual

- [Configuration](configuration.md) — every key, its default, and what it costs to change.
- [Deployment](deployment.md) — building, certificates (ACME DNS-01 or self-signed plus pinning), releases and rollback, systemd, firewall, fd budget, reloads, relays, fail2ban.
- [Architecture](architecture.md) — how a request becomes a tunnel, the in-tree HTTP/3 layer, why quinn-proto is patched, and what the tests assert.

## Reference

- [API documentation](https://vcarus.github.io/volto/api/) — the crate's rustdoc, rebuilt from `main` on every push.
- [Source repository](https://github.com/vcarus/volto) — the code, the issue tracker, and the tracked copy of these pages.
- [Releases](https://github.com/vcarus/volto/releases) — static musl binaries for `x86_64` and `aarch64`, with `SHA256SUMS`.
- [Security policy](https://github.com/vcarus/volto/blob/main/SECURITY.md) — how to report a vulnerability privately.
