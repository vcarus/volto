# Deployment

Target platform is a Linux host with systemd; the development host is macOS and
the test suite is expected to pass on both.

## Building

Rust 1.85 or newer. `Cargo.lock` is committed, and `quinn-proto` is redirected
by a `[patch.crates-io]` stanza to a commit carrying an MTU fix no release has
yet (see
[architecture.md](architecture.md#why-quinn-proto-is-patched-temporary)), so
build with the lockfile and do **not** run `cargo update`:

```sh
cargo build --release --locked      # target/release/volto
```

On Debian or Ubuntu that needs `build-essential` and `pkg-config`. Compiling on
the server itself is the simplest route; the dependency stack is pure Rust apart
from ring's build, so cross-compiling works as well:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked --target x86_64-unknown-linux-musl
```

Cross-compiling to musl needs a C toolchain for ring (`musl-tools` for the
x86_64 target, a cross toolchain for aarch64). The release workflow builds both
targets with [`cross`](https://github.com/cross-rs/cross); the resulting static
binaries are attached to each tagged release together with a `SHA256SUMS` file
and the contents of `script/`.

## Certificates

Two paths. Pick one.

### ACME with DNS-01

The right choice when you own a domain and want clients to need no extra
configuration. When the domain's A record points at a UDP relay rather than at
the server, HTTP-01 and TLS-ALPN-01 cannot validate — they are answered at the
address the record names — so DNS-01 is the only usable challenge:

```sh
sudo apt install -y certbot python3-certbot-dns-cloudflare   # or your provider's plugin
sudo certbot certonly \
  --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.ini \
  --key-type ecdsa \
  -d example.com
```

`--key-type ecdsa` is not only a performance preference. Until a client's address
is validated, QUIC lets a server send at most three times the bytes it received
(RFC 9000 §8.1, roughly a 3600-byte budget). An RSA chain can exceed that and
cost the handshake an extra round trip; an ECDSA chain fits comfortably.

The symlinks under `/etc/letsencrypt/live/` are readable by root only, so rather
than pointing volto at them, have the renewal hook copy the files into
`/etc/volto` and reload:

```sh
sudo tee /etc/letsencrypt/renewal-hooks/deploy/volto.sh >/dev/null <<'EOF'
#!/bin/sh
set -e
install -o volto -g volto -m 0644 /etc/letsencrypt/live/example.com/fullchain.pem /etc/volto/fullchain.pem
install -o volto -g volto -m 0640 /etc/letsencrypt/live/example.com/privkey.pem   /etc/volto/privkey.pem
systemctl reload volto
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/volto.sh
sudo /etc/letsencrypt/renewal-hooks/deploy/volto.sh   # run it once by hand
```

### Self-signed with fingerprint pinning

The right choice for a handful of your own devices when maintaining a domain and
DNS-01 credentials is not worth it. The client verifies one specific certificate
by its SHA-256 fingerprint instead of a chain.

```sh
cargo build --release --locked
sudo script/install-selfsigned.sh
```

The installer creates the `volto` system user, installs the binary, generates an
EC P-256 certificate valid for ten years, derives `/etc/volto/config.toml` from
the shipped example with a random password, installs and starts the systemd unit,
opens the port in ufw if it is active, and prints the fingerprint, the expiry
date and a pasteable Surge policy line. It asks for the certificate name when
neither `--sni` nor `$SNI` is set and a terminal is attached; everything else has
a default:

```sh
sudo script/install-selfsigned.sh \
  --sni volto.internal \
  --port 443 \
  --username yourname \
  --password 'or let it generate one'
```

A username may not contain a colon (RFC 7617) and may not be longer than 32
bytes (see [configuration.md](configuration.md#auth)), and neither a username
nor a password may contain `"`, `\`, `|` or `&`: the first two cannot be
written into the generated TOML string, and the other two are metacharacters of
the substitution that writes it. The installer refuses them up front rather than
installing something other than what was asked for. Everything else printable is
accepted, `*` and `.` included, and a generated password never runs into this.

Re-running is safe: an existing config file, certificate or user is kept.
`--force` regenerates the certificate only — it never rewrites `config.toml`, so
hand edits survive. Regenerating changes the fingerprint, and every client then
has to be updated.

Generating the certificate by hand instead:

```sh
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /etc/volto/key.pem -out /etc/volto/cert.pem \
  -days 3650 -nodes \
  -subj "/CN=volto.internal" \
  -addext "subjectAltName=DNS:volto.internal" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

sudo chown volto:volto /etc/volto/cert.pem /etc/volto/key.pem
sudo chmod 0644 /etc/volto/cert.pem
sudo chmod 0640 /etc/volto/key.pem

openssl x509 -in /etc/volto/cert.pem -noout -fingerprint -sha256   # for the client
openssl x509 -in /etc/volto/cert.pem -noout -enddate               # note the expiry
```

The SAN is what gets matched — a bare CN has not been accepted for years — so it
must be present even though the name is fictional. The name need not resolve:
the client connects to an address and uses this only as the SNI and the name to
match.

What pinning changes, and why each point matters:

- **The fingerprint is the trust anchor.** Generate it on the server, and carry
  it to each client yourself. If it arrives over a channel someone else can
  rewrite, pinning buys nothing — an attacker supplies their own fingerprint.
- **The private key never leaves the machine.** Not into backups, not into chat.
- **There is no revocation.** If the key may have leaked, the only remedy is
  regenerating (`--force`) and updating the fingerprint on every client by hand.
- **Track the expiry date yourself.** A pinning client usually skips validity and
  hostname checks, so an expired certificate may fail silently and only surface
  after a client update. The installer prints the date; put it in a calendar.
- **Never use `skip-cert-verify` instead of pinning.** It disables server
  identity entirely, and Basic credentials are sent on *every* request — a man in
  the middle collects the username and password on first use.

## Deploying from releases

[`script/deploy.sh`](../script/deploy.sh) turns the release page into the
deployment mechanism: it resolves the newest release (or the one given with
`--tag`), downloads the tarball for the host's architecture, verifies it
against the release's `SHA256SUMS`, and then does whichever of three things the
host needs:

- **No install yet** (`/etc/volto/config.toml` absent): it runs the bundled
  `install-selfsigned.sh` for the full first-time setup, so the same flags and
  environment variables apply (`--sni`, `--port`, `--username`, `--password`).
- **Older version installed**: it asks the release it is about to install
  whether it can load this host's `/etc/volto/config.toml` and stops if it
  cannot (see [before the swap](#before-the-swap)); otherwise it keeps the
  current binary at `/usr/local/bin/volto.prev`, swaps in the new one, refreshes
  the systemd unit and restarts. If the service is not running a few seconds
  later, the previous binary is restored and restarted, and the script fails
  loudly.
- **Already on that version**, with the config and the unit in place: it exits
  without touching anything. The presence checks are part of the deal —
  deleting `/etc/volto/config.toml` and re-running is the supported way to
  regenerate it (the certificate and the system user survive, so the
  fingerprint does not change).

`--dry-run` prints which of the three a run would pick and stops before doing
anything about it. It needs an explicit `--tag`, since resolving "latest" is a
network call, and it is how `tests/it_deploy.rs` exercises the decision without
root, systemd or a download.

The script is also its own bootstrap. On a bare host, pipe it straight from the
repository and let it do the downloading — everything it installs comes out of
the checksum-verified release tarball, the piped copy only steers. With stdin
being a pipe it never prompts, so give `--sni` (and friends) explicitly or
accept their defaults:

```sh
curl -fsSL https://raw.githubusercontent.com/vcarus/volto/main/script/deploy.sh |
  sudo bash -s -- --enable-timer --sni volto.internal --port 443 \
       --username yourname --password 'or let it generate one'
```

Omitting `--password` is also fine, and usually better: the installer generates
18 random bytes — 144 bits, 24 characters — and prints the result in the final
Surge policy line. `--username` is independent, so naming the user still leaves
the password generated.

The no-op path is what makes it safe to run on a schedule:

```sh
sudo script/deploy.sh --enable-timer
```

installs the script as `/usr/local/sbin/volto-deploy` plus a systemd timer that
re-runs it daily (`OnCalendar=daily`, randomized by up to an hour, `Persistent=`
so a powered-off day is caught up). Every later deploy refreshes the installed
copy of the script from the release it just verified, so the timer keeps pace
with the repository. `journalctl -u volto-deploy.service` shows what each run
did; a failed update leaves the timer unit in a failed state, which is the
signal to go look.

### Before the swap

On every update, and on a rollback above all, the script asks the binary it is
about to install whether it can load the configuration this host already has:

```sh
volto --check-config --config /etc/volto/config.toml
```

If the answer is no, nothing is installed, the running service is not touched,
and the run fails with the candidate's own message — file, line and column —
on stderr. Asking before the swap is the only time the answer is worth having:
afterwards the service is already down, and the guard below has restored the
release you were trying to leave.

Whether the candidate can be asked at all is decided by looking for the flag in
its own `--help`, not by running it and reading how it fails, so a release from
before the flag existed is never mistaken for a bad configuration. Such a
release simply goes unchecked — which means a rollback *past* the release that
introduced `--check-config` is exactly as unguarded as it always was, and gets
the advisory below instead.

### Rolling back

Rolling back is the same flow pinned to an older release:

```sh
sudo volto-deploy --tag v0.1.0
```

It is also the one flow nobody rehearses, so the script says the two things
that bite on the way back before it does anything about them.

**The config file goes back with nothing.** The script never rewrites
`/etc/volto/config.toml` or the certificate — both belong to
`install-selfsigned.sh`'s first run and to you afterwards — and an older volto
refuses a key it does not know, refusing the *whole* file rather than the key,
so the service does not start at all. `mtu_upper_bound` is the one that bites in
practice: it reached the shipped example in v0.4.5, and every install is derived
from that example. The startup error names the file, the line and the column;
comment that key out and start the service, or comment out everything
introduced after the target release beforehand. See
[version compatibility](configuration.md#version-compatibility) for which key
arrived when. On a rollback the check above catches this first, when the target
release is new enough to be asked.

The script's own guardrail does not help here, and reads backwards if you are
not expecting it: when the newly installed binary is not running a few seconds
later, the previous one is restored — which on a rollback is the release you
were trying to leave.

**`--tag` is not a pin.** The script carries no version pin of its own; it
converges on whatever the newest *published* release is, in either direction. So
a rollback left alone is undone by the next timer tick, within a day. Hold it
with

```sh
sudo systemctl disable --now volto-deploy.timer
```

or, if the release itself is the problem for every host, delete it from the
releases page — that rolls every host back on its own next tick and needs no
per-host action at all.

## systemd

The shipped unit is [`script/masque.service`](../script/masque.service). Manual
installation:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin volto
sudo install -m 0755 target/release/volto /usr/local/bin/volto
sudo install -d -o volto -g volto -m 0750 /etc/volto
sudo install -o volto -g volto -m 0640 script/config.example.toml /etc/volto/config.toml
sudo install -m 0644 script/masque.service /etc/systemd/system/volto.service
sudo systemctl daemon-reload
sudo systemctl enable --now volto
```

Then edit `/etc/volto/config.toml`: set the `cert`/`key` paths and **set
`[auth].users`**. An empty user list means no authentication at all.

The unit runs as a fixed system user rather than with `DynamicUser=yes` on
purpose: the private key must be readable by this service and nothing else,
which needs a stable owner to grant it to (`chown volto:volto`, mode 0640).
`AmbientCapabilities=CAP_NET_BIND_SERVICE` is what allows binding a low port
without root, and the rest of the unit is standard systemd hardening —
`ProtectSystem=strict` with `ReadOnlyPaths=/etc/volto`, a `@system-service`
syscall filter, no new privileges.

`RUST_LOG` overrides the configured log level without editing the config:

```ini
# /etc/systemd/system/volto.service.d/debug.conf
[Service]
Environment=RUST_LOG=volto=debug,quinn=info
```

Log lines carry a syslog priority when systemd is reading them, so journald's own
severity filter works rather than needing a text search:

```sh
journalctl -u volto -p warning --since -24h
```

## Firewall

QUIC is UDP. This is the single most common reason for "it works locally but the
client cannot connect":

```sh
sudo ufw allow 443/udp
sudo ss -lunp | grep 443     # confirm volto is actually listening on UDP
```

A cloud provider's security group needs the same rule, on UDP.

## File-descriptor budget

Each tunnel — TCP or UDP — costs one descriptor, and one client multiplexes many
onto a single QUIC connection. The quota is per connection, so the number the
process has to have descriptors for is the **product**, plus a fixed 64 for the
listening socket, the request streams, stdio and the certificate a `SIGHUP`
re-reads:

```
limits.max_connections × limits.max_targets_per_conn + 64
```

The shipped defaults make that 256 × 256 + 64 = 65600, and the shipped unit sets
`LimitNOFILE=131072`, so a stock install has room over. The drop-in below is for
operators who raise either limit past that point: at `max_connections = 512` the
number needed is 512 × 256 + 64 = 131136, past what the unit grants, and clients
at their quotas can then consume every descriptor the process has, leaving none
for the listening socket, for the certificate a `SIGHUP` re-reads, or for
anything else. Fd exhaustion is not a crash here — a tunnel whose `socket()`
fails is refused with a 500 and `Proxy-Status: volto; error=proxy_internal_error`,
one request at a time, and the tunnels already running are untouched — but it is
a degradation that hits every connection at once. That error type is what
distinguishes it from an unreachable destination: it is RFC 9209's "internal
error unrelated to the origin", so a burst of them in a client's logs points at
this host's descriptor budget rather than at the targets, and it carries no
`next-hop` because nothing was contacted. The same answer covers the other ways
a host can run out — no kernel buffer, no ephemeral port left to bind.

volto compares that number against `RLIMIT_NOFILE` at startup and warns when it
does not fit, which is worth heeding rather than silencing. Take the headroom in
whichever direction suits the host: raise `LimitNOFILE`, or lower
`limits.max_connections`, which is also the knob that bounds memory.

```ini
# /etc/systemd/system/volto.service.d/nofile.conf
[Service]
LimitNOFILE=262144
```

## UDP socket buffers

On a high-bandwidth path the kernel's UDP socket buffers are where packets are
dropped first, and two different sysctls decide how big they are. Only one of
them is a ceiling:

* `net.core.rmem_default` / `wmem_default` is what a socket gets when the
  application never asks — about 208 KiB on a stock Linux.
* `net.core.rmem_max` / `wmem_max` is the most an application may *request*.
  Raising it does nothing at all for a program that does not ask.

volto asks. `limits.socket_recv_buffer` and `limits.socket_send_buffer` are
requested when the socket is created — 2 MiB each by default — so on this server
the ceiling is the sysctl that matters:

```sh
sudo sysctl -w net.core.rmem_max=4194304
sudo sysctl -w net.core.wmem_max=4194304
```

Sized so the default request fits with room to spare; put the same lines in
`/etc/sysctl.d/` to survive a reboot. When the kernel caps the request instead,
volto warns at startup and names the sysctl to raise, so a host that never had
these touched says so in its own log rather than dropping packets quietly.

Two readings that look wrong and are not. Linux reports a granted buffer as
double the size — the accounting includes per-packet overhead — so a satisfied
2 MiB request shows as `rb 4194304` in `ss -uanpm`, and that same number is what
the startup line prints as `so_rcvbuf`. And both keys take effect only when the
socket is created: a reload does not rebind it, so changing them needs a
restart. `0` hands the size back to the operating system.

## Reloading

`systemctl reload volto` sends SIGHUP. volto re-reads the configuration file and
applies it to connections accepted from then on: a renewed certificate, a changed
user list, a raised or lowered `limits.max_connections`, changed transport
parameters. Established connections keep the
configuration they were accepted with — a tunnel's rules must not change
mid-transfer, and QUIC cannot renegotiate transport parameters anyway.

That matters when the change is meant to revoke access: a client that still holds
an established connection keeps working on the old credentials, and keep-alives
routinely hold one open across long idle periods. Use `systemctl restart volto`
rather than `reload` when the old credentials must stop working — a restart
closes those connections after the shutdown grace period (see
[Graceful shutdown](#graceful-shutdown)) instead of leaving them running.

A reload is all-or-nothing. Parsing, validation and certificate loading all
happen before anything is swapped in, so there is no state where a new
certificate is paired with an old user list. If the file is broken, volto logs
the error and **keeps running on the previous configuration**; it never exits.
That property is the point: the process sending this signal is usually a renewal
hook running unattended, and a typo must not become an outage.

## Graceful shutdown

SIGTERM stops the endpoint from accepting new connections, sends GOAWAY on the
established ones and waits for their tunnels to finish, up to
`server.shutdown_grace` (default 5 s). The default is short on purpose: a
client that keeps using a connection after GOAWAY instead of opening a new one
— Surge does — has every new request fail until the drain ends, so a long
grace period trades a longer outage for every new request against finishing the
transfers already in flight. Raise it if long transfers matter more to you than
a few seconds of failed requests at each restart. Keep systemd's
`TimeoutStopSec` comfortably above whatever you choose — the shipped unit uses
45 — so systemd does not send SIGKILL mid-drain. An hour is the most that can
be configured: the grace period is the bound the drain is built around, and a
value past that would only hand the ending back to `SIGKILL`.

The GOAWAY carries an identifier, and it is a promise in both directions.
Requests below it were already accepted and are still served during the drain,
tunnel and all, even if the client only finishes sending them after the signal.
Requests at or past it are rejected with `H3_REQUEST_REJECTED`, which tells the
client they were not processed and may be retried on another connection.

Sending the GOAWAY is itself bounded by `limits.max_idle_timeout`, because a
peer decides when a write to it completes: one that grants no flow-control
window on the control stream would otherwise hold that connection's drain open
for the whole grace period, and with it the process. A connection whose peer will
not take the frame within that bound drains without one and is closed when its
tunnels end, exactly as it would have been otherwise.

A SIGHUP that arrives once the drain has begun is refused and logged: the
listener has been closed by then, and reopening it to accept handshakes that are
seconds from being closed again would be worse than doing nothing. Reload before
you stop, not during.

## Running behind a UDP relay

volto needs no special configuration to sit behind a plain layer-4 UDP
forwarder, because TLS terminates only at volto itself. The relay moves opaque
UDP packets and holds no key material. Three things are worth knowing:

- **Keep the relay's UDP conntrack timeout above the keep-alive interval.** On
  Linux `nf_conntrack_udp_timeout` defaults to 30 seconds. volto sends
  keep-alives every 20 seconds by default, which refreshes the mapping in time;
  if your relay expires entries faster, lower `keep_alive_interval` well under
  that value and lower `max_idle_timeout` with it (the keep-alive must stay
  below half the idle timeout, and volto refuses to start otherwise).
- **Issue certificates with DNS-01** when the domain's A record points at the
  relay — the other challenge types validate against that address and cannot
  reach volto; see [ACME with DNS-01](#acme-with-dns-01) above.
- **Point the client at the relay's address, and the certificate name at the
  domain.** In Surge that is `sni=` plus `server-cert-verify-name=`:

  ```
  volto = masque, 203.0.113.10, 443, sni=example.com, server-cert-verify-name=example.com, username=user1, password=…
  ```

One consequence to plan for: every client then reaches volto from the relay's
address, so per-IP banning at the server cannot distinguish them — see
[fail2ban](#fail2ban) below.

## fail2ban

A failed authentication logs one stable `WARN` line carrying the source address:

```
WARN ... authentication failed ... remote=203.0.113.7:5678 username="user1" reason="credentials rejected"
```

`/etc/fail2ban/filter.d/volto.conf`:

```ini
[Definition]
failregex = ^.*authentication failed.*remote=<HOST>:\d+.*$
ignoreregex =
```

`/etc/fail2ban/jail.d/volto.conf`:

```ini
[volto]
enabled  = true
backend  = systemd
journalmatch = _SYSTEMD_UNIT=volto.service
filter   = volto
maxretry = 10
findtime = 10m
bantime  = 1h
# QUIC is UDP: the action has to ban the UDP port.
action   = iptables[name=volto, port=443, protocol=udp]
```

**Check first that the logged address actually distinguishes clients.** Any NAT
in the path rewrites it: behind a UDP relay every client appears with the relay's
address, and a server behind carrier-grade NAT can see all inbound traffic
rewritten to one gateway address. Verify by connecting yourself and comparing
`remote=` against your own public address. If they do not match, or if every
connection shares one address, banning by IP bans everyone — drop fail2ban and
rely on the connection-level limit instead, or run the ban on the machine
closest to the internet that still sees real client addresses.

That connection-level limit needs no configuration and is unaffected by topology:
after `security.max_auth_failures` failures (default 5) the whole QUIC connection
is closed, so an attacker pays for a full QUIC and TLS handshake every N guesses.
