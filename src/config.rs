//! Configuration file loading and validation.
//!
//! The configuration is TOML. Unknown keys are rejected so typos surface at
//! startup instead of being silently ignored:
//!
//! ```toml
//! [server]
//! listen = "0.0.0.0:443"
//! cert   = "/etc/volto/fullchain.pem"
//! key    = "/etc/volto/privkey.pem"
//! alpn   = ["h3"]      # optional, this is the default
//! shutdown_grace = 5   # seconds to let tunnels finish after SIGTERM, 0..3600
//!
//! [auth]
//! users = [{ username = "user1", password = "..." }]
//!
//! [limits]
//! udp_session_timeout  = 180   # seconds
//! max_targets_per_conn = 256
//! max_connections      = 256
//! connect_timeout      = 10    # seconds, 0 disables the budget
//! ip_family_preference = "ipv4" # ipv4 | ipv6 | system
//! max_streams_bidi     = 1024  # 1..65536
//! max_idle_timeout     = 60    # seconds
//! keep_alive_interval  = 20    # seconds, must be < max_idle_timeout / 2
//! initial_mtu          = 1200  # bytes, 1200..1452
//! mtu_discovery        = true
//! mtu_upper_bound      = 1452  # bytes, initial_mtu..1472
//! congestion_control   = "bbr" # bbr | cubic | newreno
//! initial_rtt_ms       = 333   # milliseconds, 10..10000
//! socket_recv_buffer   = 2097152 # bytes, 0 keeps the OS default
//! socket_send_buffer   = 2097152 # bytes, 0 keeps the OS default
//!
//! [security]
//! allow_private_networks   = false
//! denied_ports             = [25]
//! unanswered_packet_budget = 64
//! max_auth_failures        = 5
//!
//! [log]
//! level  = "info"      # optional, this is the default
//! keylog = false       # write TLS secrets to $SSLKEYLOGFILE (debug only)
//! ```
//!
//! Every section except `[server]` is optional, and every key within them has a
//! default, so a minimal file is four lines. Two consequences of that are worth
//! stating explicitly, because they are the difference between a safe and an
//! unsafe deployment:
//!
//! * an absent or empty `[auth].users` **disables authentication**, and
//! * `[security]` defaults deny private address space but nothing else.
//!
//! [`Config::warnings`] reports the first of those at startup.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

/// ALPN protocol identifiers advertised when the config does not say otherwise.
///
/// Surge speaks HTTP/3, so `h3` is the only default. It stays configurable
/// because interop debugging occasionally needs a draft identifier.
pub const DEFAULT_ALPN: &[&str] = &["h3"];

/// Log level used when `[log].level` is absent.
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// Default grace period for a graceful shutdown, in seconds.
///
/// Long enough for an in-flight page load or API call to finish, and short on
/// purpose: a client that keeps using a connection after GOAWAY instead of
/// opening a fresh one — the Surge client does — has every new request fail
/// for as long as the drain lasts, so the grace period is also a window of
/// failed requests on the client, and it only buys time for transfers that are
/// already running. Five seconds keeps that window short while still letting
/// short exchanges complete. Well below a service manager's own kill timeout
/// (systemd's default `TimeoutStopSec` is 90s).
pub const DEFAULT_SHUTDOWN_GRACE: u64 = 5;

/// Default UDP session idle timeout, in seconds.
///
/// RFC 9298 §3.1 says a proxy SHOULD NOT use a timeout below two minutes, since
/// UDP has no close signal and a short timeout breaks long-lived flows.
pub const DEFAULT_UDP_SESSION_TIMEOUT: u64 = 180;

/// Default cap on simultaneously open QUIC connections.
///
/// Sized against the rest of the budget rather than picked at random: what the
/// startup check compares against `RLIMIT_NOFILE` is
/// `max_connections * max_targets_per_conn` plus 64 descriptors of headroom,
/// which is 256 * 256 + 64 = 65600 here, against the `LimitNOFILE=131072` the
/// shipped systemd unit sets. Raising either limit past that point means raising
/// `LimitNOFILE` with it.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 256;

/// Default budget for reaching a target, in seconds.
///
/// Applied twice per request and separately: once to name resolution, once to
/// the whole list of addresses the name resolved to. A tunnel slot and the file
/// descriptor behind it are held for the length of both, so without a budget an
/// unreachable target pins them for however long the operating system waits on a
/// SYN that draws no answer — on Linux roughly two minutes, which is long enough
/// for ordinary browsing to a black-holed address to exhaust
/// `max_targets_per_conn` on its own.
///
/// Ten seconds is well past a healthy connect on any path this proxy serves (the
/// production RTT is under 100 ms) while being short enough that a client's
/// budget is not consumed by one dead target. Zero restores the unbounded
/// behaviour and leaves the wait to the operating system.
pub const DEFAULT_CONNECT_TIMEOUT: u64 = 10;

/// Default number of authentication failures tolerated on one connection.
pub const DEFAULT_MAX_AUTH_FAILURES: u32 = 5;

/// Default concurrent client-initiated bidirectional streams per connection.
///
/// One stream per tunnel: Surge multiplexes every proxied TCP connection onto one
/// QUIC connection, so quinn's default of 100 runs out during ordinary browsing.
pub const DEFAULT_MAX_STREAMS_BIDI: u32 = 1024;

/// Default QUIC idle timeout, in seconds.
///
/// Deliberately longer than a typical relay's 30s UDP conntrack entry, so that the
/// keep-alive below — not the timeout — decides connection liveness.
///
/// Not the value in force on its own: RFC 9000 §10.1 makes the effective idle
/// timeout the minimum of what the two endpoints advertise, and Surge advertises
/// `max_idle_timeout` = 30,000 ms. So the production link times out at 30s
/// however high this is set, which is still comfortably above the keep-alive.
pub const DEFAULT_MAX_IDLE_TIMEOUT: u64 = 60;

/// Default keep-alive interval, in seconds.
///
/// Well under the 30s UDP conntrack default on a relay, so the NAT mapping is
/// refreshed even when the tunnel is idle. Must stay below half the idle timeout,
/// which [`Config::validate`] enforces: at exactly half, a single lost keep-alive
/// packet is enough to let the connection time out.
///
/// That rule is checked against the configured `max_idle_timeout` rather than the
/// effective one. Against the 30s Surge advertises (see
/// [`DEFAULT_MAX_IDLE_TIMEOUT`]) 20s is past half, leaving one interval of margin
/// instead of two. Left as it is deliberately: the keep-alive is an ack-eliciting
/// server-to-client PING, so a lost one is retransmitted by the PTO timer well
/// inside 30s, whereas halving the interval would double the radio wakeups it
/// costs a mobile client.
pub const DEFAULT_KEEP_ALIVE_INTERVAL: u64 = 20;

/// Default initial QUIC packet size, in bytes.
///
/// 1200 is the floor QUIC guarantees (RFC 9000 §14) and the conservative choice on
/// a tunnelled path, where anything larger risks a PMTU black hole. Path MTU
/// discovery raises it from here unless `mtu_discovery` is off.
pub const DEFAULT_INITIAL_MTU: u16 = 1200;

/// The smallest `initial_mtu` QUIC permits (RFC 9000 §14).
pub const MIN_INITIAL_MTU: u16 = 1200;

/// The largest `initial_mtu` this server accepts, in bytes.
///
/// A *UDP payload* size rather than an IP packet size, which is what makes the
/// ceiling 1452 and not 1500: quinn documents `initial_mtu` as "the initial
/// value to be used as the maximum UDP payload size before running MTU
/// discovery", and Ethernet's 1500-byte MTU leaves 1472 bytes of payload over
/// IPv4 (20-byte header + 8-byte UDP) and 1452 over IPv6 (40 + 8). The ceiling
/// stays at the both-families value even though `mtu_upper_bound` may claim
/// IPv4's extra 20 bytes: discovery earns a size by probing it and loses only
/// the probe when wrong, while this value is sent blind in the handshake —
/// see the next paragraph for what wrong costs here.
///
/// There is no floor to fall back to if this is wrong: quinn applies the value
/// with a `max()` against the 1200-byte minimum and no `min()` above it, so the
/// handshake flight goes out in packets the path drops and the server is simply
/// unreachable. Its black-hole detector is no help either -- that runs inside an
/// established connection, and with this wrong there is never one. A reload
/// applies the value to connections accepted from then on, which is what makes
/// the mistake worth rejecting rather than tolerating: a `SIGHUP` with a typo
/// here turns a running server into one that still answers `systemctl status`
/// and nothing else (audit 2026-08-23).
pub const MAX_INITIAL_MTU: u16 = 1452;

/// Default ceiling for path MTU discovery, in bytes.
///
/// quinn's own default, which "stays within Ethernet's MTU when using IPv4 and
/// IPv6" (quinn-proto `config/transport.rs`): 1500 minus IPv6's 40-byte header
/// and UDP's 8. Safe whichever family the path runs.
pub const DEFAULT_MTU_UPPER_BOUND: u16 = 1452;

/// The largest `mtu_upper_bound` this server accepts, in bytes.
///
/// Ethernet's 1500 minus IPv4's 20-byte header and UDP's 8. Nothing on a
/// standard internet path carries more than that, so a higher bound could only
/// spend probes on sizes that cannot exist. The ceiling being *above*
/// [`MAX_INITIAL_MTU`] is deliberate, not an inconsistency: discovery only ever
/// reaches a size by probing it — a lost probe is retried, then abandoned, and
/// is never treated as congestion — whereas `initial_mtu` is sent blind in the
/// handshake with no recovery path (see [`MAX_INITIAL_MTU`]). An upper bound
/// the path cannot carry costs a few PINGs; an initial the path cannot carry
/// costs the server.
pub const MAX_MTU_UPPER_BOUND: u16 = 1472;

/// Default round-trip time assumed before the first measurement, in milliseconds.
///
/// quinn's own default, straight from RFC 9002's `kInitialRtt`. It seeds the
/// loss-recovery timers during the handshake, when no RTT sample exists yet: a
/// lost handshake packet waits roughly three times this value before it is
/// resent. On a path whose RTT is known (the `rtt_ms` field in the connection
/// logs), 1.5–2x that measurement recovers a lost handshake in a fraction of
/// the default wait. The margin is not optional: a value below the real RTT
/// makes the timer fire early and retransmit packets that were never lost.
pub const DEFAULT_INITIAL_RTT_MS: u64 = 333;

/// Accepted range for `initial_rtt_ms`.
///
/// Below 10 ms the timer is tighter than ordinary scheduling jitter even on a
/// LAN; past 10 s the seed is slower than any real path and only delays
/// handshake recovery beyond what the default already risks.
const INITIAL_RTT_RANGE_MS: std::ops::RangeInclusive<u64> = 10..=10_000;

/// Largest accepted `max_idle_timeout`, `udp_session_timeout` and
/// `connect_timeout`, in seconds.
///
/// Not a protocol limit. Past an hour the value stops meaning anything: any relay's
/// conntrack entry will have expired long before, so a larger timeout only delays
/// noticing a peer that is already unreachable.
///
/// For the two application timers it is also a hard-safety line: they are added
/// to `Instant::now()` to make deadlines, and an absurd number of seconds —
/// they are plain `u64`s — would panic that addition rather than mean anything.
/// The ceiling keeps every such sum far from the edge.
const MAX_IDLE_TIMEOUT_CEILING: u64 = 3600;

/// Largest accepted `shutdown_grace`, in seconds.
///
/// The same number as [`MAX_IDLE_TIMEOUT_CEILING`] and half of the same
/// reasoning — past an hour a wait stops describing anything anybody observes,
/// and a drain that long has outlived any service manager's own patience
/// (systemd's default `TimeoutStopSec` is 90 seconds).
///
/// The other half is this key's own, and it is the opposite of the timers'.
/// A grace period that cannot be added to `Instant::now()` does not panic:
/// `tokio::time::timeout` folds a duration it cannot add into a deadline in the
/// far future instead, so an absurd `u64` of seconds fails quietly rather than
/// loudly — it removes the bound `crate::quic`'s drain is built around, leaving
/// the process waiting on connections that may never end until a `SIGKILL`
/// arrives, which is precisely the ungraceful ending the grace period exists to
/// avoid. Bounding the key is what keeps that state unreachable.
const MAX_SHUTDOWN_GRACE: u64 = MAX_IDLE_TIMEOUT_CEILING;

/// Default UDP socket receive buffer to request, in bytes.
///
/// Not a size that arrives on its own. quinn never calls
/// `setsockopt(SO_RCVBUF)`, so a QUIC server that does not ask keeps whatever
/// the kernel hands out — `net.core.rmem_default`, around 208 KiB on a stock
/// Linux — however high `net.core.rmem_max` has been raised, because that
/// sysctl is only a ceiling on what an application may *request*, not an
/// allocation.
///
/// 2 MiB is cheap insurance in the same spirit as the per-stream flow-control
/// window in [`crate::quic`]: it costs nothing until a burst needs it, and the
/// bursts it covers are ordinary ones — a batch of packets arriving while the
/// read loop is elsewhere, a GSO segment train, a scheduling hiccup. What it
/// buys is the absence of a silent drop, which the kernel counts as `receive
/// buffer errors` in `netstat -su` and the sender pays for in retransmissions.
///
/// Requested when the socket is created, so this is a startup-only setting.
/// Zero leaves the operating system's own value alone.
pub const DEFAULT_SOCKET_RECV_BUFFER: usize = 2 * 1024 * 1024;

/// Default UDP socket send buffer to request, in bytes.
///
/// The mirror of [`DEFAULT_SOCKET_RECV_BUFFER`] on the way out: capped by
/// `net.core.wmem_max` rather than `rmem_max`, and drained by the network
/// interface rather than by this process. It binds on the same bursts, with a
/// milder ending: when the endpoint hands the kernel more at once than the
/// buffer holds, the send returns `EAGAIN` and quinn holds the packet until the
/// socket drains — a stall rather than a drop, though the kernel still counts
/// each one as a `send buffer error` in `netstat -su`.
///
/// Requested when the socket is created, so this is a startup-only setting.
/// Zero leaves the operating system's own value alone.
pub const DEFAULT_SOCKET_SEND_BUFFER: usize = 2 * 1024 * 1024;

/// Default number of concurrent tunnels allowed on one QUIC connection.
///
/// Every tunnel costs one file descriptor, so this is also the per-connection
/// share of the process fd budget (see [`crate::net::fd_soft_limit`]).
pub const DEFAULT_MAX_TARGETS_PER_CONN: u32 = 256;

/// Ports no target may be reached on unless the operator says otherwise.
///
/// 25 is the classic open-relay abuse vector. Note that 53 is deliberately *not*
/// here: Surge's UDP availability test is a DNS query through the tunnel.
pub const DEFAULT_DENIED_PORTS: &[u16] = &[25];

/// Default number of packets a UDP session may send before the target answers.
///
/// RFC 9298 §7 asks a proxy to limit what an unanswered session can emit, so it
/// cannot be used as a reflector or a port scanner. The default is deliberately
/// generous: handshakes that legitimately need several packets before the first
/// reply (QUIC retransmits, some game protocols) must not break.
pub const DEFAULT_UNANSWERED_PACKET_BUDGET: u32 = 64;

/// The complete server configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Listener, certificate and ALPN settings.
    pub server: Server,
    /// Credentials accepted on CONNECT requests.
    #[serde(default)]
    pub auth: Auth,
    /// Resource limits.
    #[serde(default)]
    pub limits: Limits,
    /// Destination policy and abuse mitigations.
    #[serde(default)]
    pub security: Security,
    /// Logging settings.
    #[serde(default)]
    pub log: Log,
}

/// `[auth]` — the accepted credentials.
///
/// An empty user list disables authentication entirely, which makes this an open
/// proxy; [`Config::warnings`] says so at startup.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    /// Users allowed to open tunnels, as HTTP Basic credentials.
    #[serde(default)]
    pub users: Vec<User>,
}

/// One set of HTTP Basic credentials.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// The user-id, which RFC 7617 §2 forbids from containing a colon.
    pub username: String,
    /// The password, compared in constant time and never logged.
    pub password: String,
}

/// Redacts the password.
///
/// `Config` is `Debug`, and a `Debug`-formatted config is exactly the kind of
/// thing that ends up in a log line or a panic message.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// QUIC congestion controller, selected by `[limits].congestion_control`.
///
/// The default is BBR, deliberately. This proxy exists to carry traffic over
/// long, often lossy international paths, and a loss-based controller reads the
/// non-congestive packet loss of those paths as congestion and keeps the window
/// from ever opening — the download direction collapses to near-zero. BBR models
/// bottleneck bandwidth and RTT instead of reacting to loss, so it holds
/// throughput where CUBIC and NewReno stall, matching what the Linux kernel does
/// for TCP with `net.ipv4.tcp_congestion_control = bbr`.
///
/// The loss-based controllers are kept as an escape hatch: quinn's BBR is a
/// port marked "experimental", so an operator who hits trouble after a
/// dependency bump can fall back without recompiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CongestionControl {
    /// BBR (quinn's experimental port of BBRv1). The default; best on lossy
    /// long-haul paths.
    Bbr,
    /// CUBIC, quinn's own default. Loss-based; the standard choice on clean paths.
    Cubic,
    /// NewReno. Loss-based and the most conservative; mainly of interest for
    /// interop testing.
    NewReno,
}

/// Which address family a target name is tried on first, selected by
/// `[limits].ip_family_preference`.
///
/// The default is IPv4, which is deliberately *not* what the C library hands
/// back. `getaddrinfo` — glibc and musl alike — orders its answers by RFC 6724,
/// and that ordering puts a global IPv6 address ahead of every IPv4 one whenever
/// the host has a usable IPv6 route. On a host that is only a client of the
/// internet that is the right answer. On a proxy it is an operator policy
/// wearing a resolver's clothes: a host whose IPv6 egress is tunnelled, or
/// otherwise weaker than its native IPv4 — a common shape on a VPS — would send
/// every dual-stack target down the weaker path first. A TCP tunnel pays for
/// that with the whole IPv6 attempt before IPv4 is even tried, because
/// [`crate::tunnel::tcp`] walks the address list in order; a CONNECT-UDP session
/// pays for it outright, because its socket is connected to the first address
/// that has a route and there is no failover behind that choice.
///
/// [`System`](Self::System) is the escape hatch back to RFC 6724 ordering, which
/// on glibc an operator can shape further through `gai.conf`. The knob and its
/// default have precedent: shadowsocks-rust carries the same choice as
/// `ipv6_first`, likewise off by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpFamilyPreference {
    /// Try IPv4 addresses before IPv6 ones. The default.
    Ipv4,
    /// Try IPv6 addresses before IPv4 ones.
    Ipv6,
    /// Keep the resolver's own order, which on libc means RFC 6724.
    System,
}

/// `[limits]` — resource and lifetime limits.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Seconds a UDP session may sit idle before it is closed.
    pub udp_session_timeout: u64,
    /// Concurrent tunnels allowed on one QUIC connection.
    pub max_targets_per_conn: u32,
    /// Simultaneously open QUIC connections. Zero means no limit.
    ///
    /// Beyond this, new connections are refused at the QUIC layer, before a
    /// handshake completes and before any per-connection state is built.
    pub max_connections: u32,
    /// Seconds allowed for reaching a target. Zero disables the budget.
    ///
    /// Spent twice per request: once on name resolution, once on the whole list
    /// of addresses it resolved to. See [`DEFAULT_CONNECT_TIMEOUT`].
    pub connect_timeout: u64,
    /// Which address family a resolved target is tried on first.
    ///
    /// Applied once, at the single point where a name becomes a list of
    /// addresses, so both tunnel kinds see the same order; see
    /// [`IpFamilyPreference`] for why the default departs from the resolver's.
    pub ip_family_preference: IpFamilyPreference,
    /// Concurrent client-initiated bidirectional streams per QUIC connection.
    ///
    /// Between 1 and 65536. The ceiling is not a formality: the credit is
    /// reserved slot by slot when a connection is created rather than when a
    /// stream is opened, so it is work every handshake pays for.
    pub max_streams_bidi: u32,
    /// Seconds a QUIC connection may go without traffic before it is closed.
    ///
    /// Only half of what decides that: RFC 9000 §10.1 takes the minimum of both
    /// endpoints' advertisements, so a client advertising less wins. See
    /// [`DEFAULT_MAX_IDLE_TIMEOUT`].
    pub max_idle_timeout: u64,
    /// Seconds between keep-alive packets. Zero disables them.
    ///
    /// Must be below half of [`Limits::max_idle_timeout`]; see
    /// [`DEFAULT_KEEP_ALIVE_INTERVAL`] for why.
    pub keep_alive_interval: u64,
    /// Size of the first QUIC packets, in bytes. Between 1200 and 1452.
    ///
    /// A UDP payload size rather than an IP packet size; see
    /// [`MAX_INITIAL_MTU`] for where the upper end of that range comes from.
    pub initial_mtu: u16,
    /// Probe for a larger path MTU than `initial_mtu` (RFC 8899 DPLPMTUD).
    ///
    /// On by default. Turning it off stops the upward search: packets start at
    /// `initial_mtu` and are never probed larger. It is not a hard pin, though —
    /// quinn's black-hole detector still runs, and if it fires it drops the packet
    /// size to the 1200-byte floor for the rest of the connection, with nothing
    /// left to probe it back up. Trades throughput for predictability on a path
    /// that black-holes large packets.
    pub mtu_discovery: bool,
    /// Ceiling for path MTU discovery, in bytes. Between `initial_mtu` and 1472.
    ///
    /// A UDP payload size like `initial_mtu`. quinn's default of 1452 is the
    /// value safe over both IPv4 and IPv6 on Ethernet; an operator who has
    /// measured their path (`ping -M do`, `tracepath`) can claim what IPv4
    /// leaves above that — at most 1472 — and overshooting is harmless, because
    /// a size is only ever reached by probing it. Moot when `mtu_discovery` is
    /// off, which is warned about rather than rejected. See
    /// [`MAX_MTU_UPPER_BOUND`].
    pub mtu_upper_bound: u16,
    /// QUIC congestion controller. Defaults to BBR; see [`CongestionControl`].
    pub congestion_control: CongestionControl,
    /// Milliseconds of round-trip time assumed before the first measurement.
    ///
    /// Seeds the handshake retransmission timers; see [`DEFAULT_INITIAL_RTT_MS`]
    /// for the trade-off and how to pick a value from the connection logs.
    pub initial_rtt_ms: u64,
    /// UDP socket receive buffer to request, in bytes. Zero keeps the OS default.
    ///
    /// Applied to the socket when it is created, which makes this a startup-only
    /// setting: a `SIGHUP` reload does not rebind the socket, so a change here
    /// needs a restart — the same class as [`Server::listen`], and unlike every
    /// key above it.
    ///
    /// Two things the kernel does with the request are worth knowing before
    /// reading a log line about it. It is capped at a host ceiling —
    /// `net.core.rmem_max` on Linux, `kern.ipc.maxsockbuf` on macOS — and a host
    /// may fail the call outright instead of clamping. And on Linux the value
    /// read back is *double* what was granted, because the accounting includes
    /// per-packet overhead, so a satisfied 2 MiB request reads as 4194304 both
    /// here and in `ss -uanpm`. Either way the endpoint still comes up, and volto
    /// warns at startup when it got less than it asked for. See
    /// [`DEFAULT_SOCKET_RECV_BUFFER`].
    pub socket_recv_buffer: usize,
    /// UDP socket send buffer to request, in bytes. Zero keeps the OS default.
    ///
    /// Startup-only, read back and warned about exactly like
    /// [`Limits::socket_recv_buffer`]; the ceiling on this side is
    /// `net.core.wmem_max`. See [`DEFAULT_SOCKET_SEND_BUFFER`].
    pub socket_send_buffer: usize,
}

/// `[security]` — destination policy and abuse mitigations.
///
/// The defaults are the ones RFC 9298 §7 asks for: private address space is out
/// of reach, the classic relay port is closed, and a session that has not heard
/// from its target cannot be used as an amplifier.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Security {
    /// Allow tunnels to loopback, RFC 1918, link-local and ULA addresses.
    ///
    /// Off by default: the proxy's own source address often carries privileges a
    /// remote client must not borrow.
    pub allow_private_networks: bool,
    /// Target ports that are refused regardless of address.
    pub denied_ports: Vec<u16>,
    /// Packets a UDP session may send before its target has answered.
    ///
    /// Zero disables the mitigation.
    pub unanswered_packet_budget: u32,
    /// Authentication failures tolerated on one connection before it is closed.
    ///
    /// Not a rate limit: it raises the cost of guessing from "one handshake, then
    /// unlimited attempts" to "one handshake per N attempts". Zero disables it.
    pub max_auth_failures: u32,
}

/// `[server]` — the QUIC listener and its TLS identity.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    /// UDP socket address to listen on, e.g. `"0.0.0.0:443"`.
    pub listen: SocketAddr,
    /// PEM file holding the certificate chain (leaf first).
    pub cert: PathBuf,
    /// PEM file holding the private key (PKCS#8, PKCS#1 or SEC1).
    pub key: PathBuf,
    /// ALPN identifiers to advertise, in preference order.
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
    /// Seconds to let existing tunnels finish after SIGTERM, at most an hour.
    ///
    /// Zero closes everything at once. The wait ends early if all tunnels finish
    /// sooner, so a generous value costs nothing in the common case — but it is
    /// a bound rather than a wish, which is why it has a ceiling of its own.
    #[serde(default = "default_shutdown_grace")]
    pub shutdown_grace: u64,
}

/// `[log]` — logging settings.
///
/// `RUST_LOG` takes precedence over [`Log::level`] when set, so an operator can
/// raise verbosity without editing the config file.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Log {
    /// A `tracing_subscriber` filter directive, e.g. `"info"` or
    /// `"volto=debug,quinn=info"`.
    pub level: String,
    /// Write TLS secrets to the file named by `SSLKEYLOGFILE`.
    ///
    /// This is the debugging tool that makes the wire readable: with the secrets,
    /// Wireshark decrypts the QUIC and HTTP/3 frames of a real Surge session, so
    /// "handshake fine, nothing flows" can be diagnosed at frame level. It also
    /// hands anyone who can read that file the plaintext of every session, so it
    /// is off by default and warned about when on.
    pub keylog: bool,
}

fn default_alpn() -> Vec<String> {
    DEFAULT_ALPN.iter().map(|s| (*s).to_owned()).collect()
}

fn default_shutdown_grace() -> u64 {
    DEFAULT_SHUTDOWN_GRACE
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            udp_session_timeout: DEFAULT_UDP_SESSION_TIMEOUT,
            max_targets_per_conn: DEFAULT_MAX_TARGETS_PER_CONN,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            ip_family_preference: IpFamilyPreference::Ipv4,
            max_streams_bidi: DEFAULT_MAX_STREAMS_BIDI,
            max_idle_timeout: DEFAULT_MAX_IDLE_TIMEOUT,
            keep_alive_interval: DEFAULT_KEEP_ALIVE_INTERVAL,
            initial_mtu: DEFAULT_INITIAL_MTU,
            mtu_discovery: true,
            mtu_upper_bound: DEFAULT_MTU_UPPER_BOUND,
            congestion_control: CongestionControl::Bbr,
            initial_rtt_ms: DEFAULT_INITIAL_RTT_MS,
            socket_recv_buffer: DEFAULT_SOCKET_RECV_BUFFER,
            socket_send_buffer: DEFAULT_SOCKET_SEND_BUFFER,
        }
    }
}

impl Default for Security {
    fn default() -> Self {
        Self {
            allow_private_networks: false,
            denied_ports: DEFAULT_DENIED_PORTS.to_vec(),
            unanswered_packet_budget: DEFAULT_UNANSWERED_PACKET_BUDGET,
            max_auth_failures: DEFAULT_MAX_AUTH_FAILURES,
        }
    }
}

impl Limits {
    /// The UDP session idle timeout as a duration.
    pub fn udp_session_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.udp_session_timeout)
    }

    /// The QUIC idle timeout as a duration.
    pub fn max_idle_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.max_idle_timeout)
    }

    /// `initial_rtt_ms` as a [`Duration`](std::time::Duration).
    pub fn initial_rtt(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.initial_rtt_ms)
    }

    /// The budget for reaching a target, or `None` when it is disabled.
    ///
    /// Read once per request rather than baked into the transport, so it is not
    /// one of the parameters a connection is stuck with for its whole life.
    pub fn connect_timeout(&self) -> Option<std::time::Duration> {
        match self.connect_timeout {
            0 => None,
            seconds => Some(std::time::Duration::from_secs(seconds)),
        }
    }

    /// The keep-alive interval, or `None` when keep-alives are disabled.
    pub fn keep_alive_interval(&self) -> Option<std::time::Duration> {
        match self.keep_alive_interval {
            0 => None,
            seconds => Some(std::time::Duration::from_secs(seconds)),
        }
    }
}

impl Default for Log {
    fn default() -> Self {
        Self {
            level: DEFAULT_LOG_LEVEL.to_owned(),
            keylog: false,
        }
    }
}

impl Config {
    /// Reads and validates the configuration at `path`.
    ///
    /// A parse failure is rendered by `parse_error` rather than carried in the
    /// error chain, because this file holds passwords and the `toml` crate's own
    /// `Display` prints the offending source line.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let config: Config =
            toml::from_str(&text).map_err(|error| parse_error(path, &text, &error))?;
        config
            .validate()
            .with_context(|| format!("invalid config file {}", path.display()))?;
        Ok(config)
    }

    /// Checks everything that TOML deserialization cannot express.
    ///
    /// Every error names the offending field so the operator does not have to
    /// guess which key is wrong.
    /// Checks are ordered cheapest first, so a syntactic mistake is reported
    /// without touching the filesystem.
    pub fn validate(&self) -> Result<()> {
        validate_log_level(&self.log.level)?;

        if self.server.alpn.is_empty() {
            bail!("server.alpn must list at least one protocol identifier");
        }
        for (i, id) in self.server.alpn.iter().enumerate() {
            if id.is_empty() {
                bail!("server.alpn[{i}] is empty");
            }
            // An ALPN identifier is length-prefixed with a single byte on the
            // wire, so it cannot exceed 255 bytes.
            if id.len() > 255 {
                bail!(
                    "server.alpn[{i}] is {} bytes, the wire format allows at most 255",
                    id.len()
                );
            }
        }

        if self.server.shutdown_grace > MAX_SHUTDOWN_GRACE {
            bail!(
                "server.shutdown_grace = {} exceeds {MAX_SHUTDOWN_GRACE} seconds; \
                 a drain that long outlives the service manager's own kill timeout, \
                 and use 0 to close every tunnel at once instead",
                self.server.shutdown_grace
            );
        }

        if self.limits.udp_session_timeout == 0
            || self.limits.udp_session_timeout > MAX_IDLE_TIMEOUT_CEILING
        {
            bail!(
                "limits.udp_session_timeout = {} must be between 1 and \
                 {MAX_IDLE_TIMEOUT_CEILING} seconds",
                self.limits.udp_session_timeout
            );
        }
        if self.limits.connect_timeout > MAX_IDLE_TIMEOUT_CEILING {
            bail!(
                "limits.connect_timeout = {} exceeds {MAX_IDLE_TIMEOUT_CEILING} seconds; \
                 use 0 to disable the budget instead",
                self.limits.connect_timeout
            );
        }
        if self.limits.max_targets_per_conn == 0 {
            bail!("limits.max_targets_per_conn must be greater than zero");
        }
        if self.limits.max_targets_per_conn > MAX_TARGETS_PER_CONN_CEILING {
            bail!(
                "limits.max_targets_per_conn = {} exceeds the {MAX_TARGETS_PER_CONN_CEILING} \
                 this server allows; every tunnel costs a file descriptor",
                self.limits.max_targets_per_conn
            );
        }

        if self.limits.max_streams_bidi == 0 {
            bail!(
                "limits.max_streams_bidi must be greater than zero, or no tunnel could \
                 ever be opened"
            );
        }
        if self.limits.max_streams_bidi > MAX_STREAMS_BIDI_CEILING {
            bail!(
                "limits.max_streams_bidi = {} exceeds the {MAX_STREAMS_BIDI_CEILING} this \
                 server allows; a stream slot is reserved for every unit of the credit when \
                 a connection is created, so the value is paid at every handshake rather \
                 than when a stream is opened",
                self.limits.max_streams_bidi
            );
        }

        if self.limits.max_idle_timeout == 0
            || self.limits.max_idle_timeout > MAX_IDLE_TIMEOUT_CEILING
        {
            bail!(
                "limits.max_idle_timeout = {} must be between 1 and \
                 {MAX_IDLE_TIMEOUT_CEILING} seconds",
                self.limits.max_idle_timeout
            );
        }

        // Strictly below half, not at it: at exactly half, losing a single
        // keep-alive packet is enough for the connection to time out. The relay in
        // front of this server is the reason keep-alives exist at all — its UDP
        // conntrack entry expires on its own schedule (30s by default), and only a
        // keep-alive that comfortably beats both timeouts keeps the NAT mapping
        // alive.
        //
        // Written as `interval >= ceil(idle / 2)` rather than the more obvious
        // `interval * 2 >= idle`: the two reject exactly the same pairs of
        // integers, and this one cannot overflow. The doubling could, and a
        // `u64` large enough to make it — anything above `u64::MAX / 2` — is
        // reachable straight from the file, since TOML integers deserialize
        // across the whole target type's range. A debug build panicked inside
        // this function; a release build wrapped the product to something small,
        // accepted the interval, and handed it to quinn, where it becomes
        // `Instant::now() + interval` the moment a connection is established and
        // panics the connection driver instead (D86).
        if self.limits.keep_alive_interval > 0
            && self.limits.keep_alive_interval >= self.limits.max_idle_timeout.div_ceil(2)
        {
            bail!(
                "limits.keep_alive_interval = {} must be less than half of \
                 limits.max_idle_timeout = {} (i.e. below {}), so that a lost keep-alive \
                 packet cannot let the connection time out",
                self.limits.keep_alive_interval,
                self.limits.max_idle_timeout,
                self.limits.max_idle_timeout as f64 / 2.0
            );
        }

        if self.limits.initial_mtu < MIN_INITIAL_MTU {
            bail!(
                "limits.initial_mtu = {} is below the {MIN_INITIAL_MTU} bytes QUIC \
                 requires (RFC 9000 §14); a smaller value cannot carry a QUIC \
                 handshake packet",
                self.limits.initial_mtu
            );
        }

        if self.limits.initial_mtu > MAX_INITIAL_MTU {
            bail!(
                "limits.initial_mtu = {} is above the {MAX_INITIAL_MTU} bytes this \
                 server allows; the value is a UDP payload size, and an Ethernet \
                 frame leaves that much of one over IPv6, so a handshake sent in \
                 larger packets is dropped by the path with nothing to fall back to",
                self.limits.initial_mtu
            );
        }

        if self.limits.mtu_upper_bound < self.limits.initial_mtu {
            bail!(
                "limits.mtu_upper_bound = {} is below limits.initial_mtu = {}; \
                 discovery searches upward from the initial size, so a ceiling \
                 under the start describes a search that cannot happen",
                self.limits.mtu_upper_bound,
                self.limits.initial_mtu
            );
        }

        if self.limits.mtu_upper_bound > MAX_MTU_UPPER_BOUND {
            bail!(
                "limits.mtu_upper_bound = {} is above the {MAX_MTU_UPPER_BOUND} bytes this \
                 server allows; the value is a UDP payload size, and an Ethernet \
                 frame leaves at most that much of one over IPv4, so a larger \
                 bound could only probe sizes no standard path carries",
                self.limits.mtu_upper_bound
            );
        }

        if !INITIAL_RTT_RANGE_MS.contains(&self.limits.initial_rtt_ms) {
            bail!(
                "limits.initial_rtt_ms = {} must be between {} and {}; it seeds the \
                 handshake retransmission timers, and a value below the real path \
                 RTT retransmits packets that were never lost",
                self.limits.initial_rtt_ms,
                INITIAL_RTT_RANGE_MS.start(),
                INITIAL_RTT_RANGE_MS.end()
            );
        }

        for (i, user) in self.auth.users.iter().enumerate() {
            if user.username.is_empty() {
                bail!("auth.users[{i}].username is empty");
            }
            if user.username.contains(':') {
                // RFC 7617 §2: the colon separates user-id from password inside
                // the credentials, so a user-id containing one is unusable.
                bail!(
                    "auth.users[{i}].username contains a colon, which RFC 7617 §2 does not allow \
                     in HTTP Basic credentials"
                );
            }
            if user.username.len() > crate::logfmt::MAX_TOKEN {
                // A user-id this long is unusable in a subtler way. Failures are
                // bucketed by the user-id the request claimed, in the form a log
                // line carries it -- truncated at `logfmt::MAX_TOKEN` -- so a
                // name past that bound never matches the configured one, and its
                // failures land in the bucket no success can clear. The client
                // that really does hold those credentials would then lose its
                // connection at the `security.max_auth_failures`-th lifetime
                // failure however often it authenticates in between. Refusing
                // the name here is what makes that state unreachable.
                //
                // The name is not echoed: it is not a secret, but it lives in
                // the same table as one, and nothing out of `[auth]` goes to
                // stderr -- see `parse_error`. The index and the limit are what
                // it takes to find and fix it.
                bail!(
                    "auth.users[{i}].username is {} bytes, over the {}-byte limit a user-id has \
                     to stay within to be told apart in the logs and in the authentication \
                     failure counters",
                    user.username.len(),
                    crate::logfmt::MAX_TOKEN
                );
            }
            if user.password.is_empty() {
                bail!("auth.users[{i}].password is empty");
            }
            if let Some(first) = self.auth.users[..i]
                .iter()
                .position(|other| other.username == user.username)
            {
                bail!(
                    "auth.users[{i}].username duplicates auth.users[{first}].username = {:?}",
                    user.username
                );
            }
        }

        if let Some(i) = self
            .security
            .denied_ports
            .iter()
            .position(|port| *port == 0)
        {
            bail!("security.denied_ports[{i}] is 0, which is not a usable port");
        }

        if !self.server.cert.is_file() {
            bail!(
                "server.cert = {} is not a readable file",
                self.server.cert.display()
            );
        }
        if !self.server.key.is_file() {
            bail!(
                "server.key = {} is not a readable file",
                self.server.key.display()
            );
        }

        Ok(())
    }
}

impl Config {
    /// Settings that are legal but that an operator should be told about.
    ///
    /// Returned rather than logged so the caller can emit them *after* the
    /// tracing subscriber exists — a warning logged during `load()` would be
    /// written to a subscriber that has not been installed yet, i.e. nowhere —
    /// and so they can be asserted on in tests.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        if self.auth.users.is_empty() {
            warnings.push(
                "[auth].users is empty, so authentication is DISABLED: this is an open proxy and \
                 anyone who can reach the port can use it. Add users before exposing it."
                    .to_owned(),
            );
        }

        if self.limits.udp_session_timeout < 120 {
            warnings.push(format!(
                "limits.udp_session_timeout = {} is below the two minutes RFC 9298 §3.1 \
                 recommends; long-lived UDP flows may be cut off, and it is also how long \
                 a write in a half-closed TCP tunnel has to complete in before that tunnel \
                 is cut",
                self.limits.udp_session_timeout
            ));
        }

        if self.security.allow_private_networks {
            warnings.push(
                "security.allow_private_networks is on: clients can reach loopback, RFC 1918 and \
                 link-local addresses through this proxy, including services that trust \
                 127.0.0.1"
                    .to_owned(),
            );
        }

        if self.security.denied_ports.contains(&53) {
            warnings.push(
                "security.denied_ports contains 53: Surge's UDP availability test is a DNS query \
                 through the proxy, so it will report the policy as broken"
                    .to_owned(),
            );
        }

        if self.limits.max_connections == 0 {
            warnings.push(
                "limits.max_connections = 0 removes the cap on simultaneous connections: \
                 an unauthenticated peer can open as many as it likes, each with its own \
                 receive buffers"
                    .to_owned(),
            );
        }

        if self.security.max_auth_failures == 0 && !self.auth.users.is_empty() {
            warnings.push(
                "security.max_auth_failures = 0 lets one connection retry credentials \
                 without limit; guessing then costs a single QUIC handshake"
                    .to_owned(),
            );
        }

        if self.limits.keep_alive_interval == 0 {
            warnings.push(format!(
                "limits.keep_alive_interval = 0 disables QUIC keep-alives: behind a relay \
                 doing UDP DNAT, an idle connection will be dropped when the relay's \
                 conntrack entry expires (30s by default) even though both ends still \
                 believe it is alive, since limits.max_idle_timeout is {}s",
                self.limits.max_idle_timeout
            ));
        }

        if !self.limits.mtu_discovery {
            warnings.push(format!(
                "limits.mtu_discovery is off: the packet size starts at \
                 limits.initial_mtu = {} bytes and is never probed larger; it can still \
                 fall to 1200 if quinn's black-hole detector fires, and nothing brings it \
                 back up. Deliberate on a path that black-holes large packets, a throughput \
                 loss anywhere else",
                self.limits.initial_mtu
            ));
        }

        if !self.limits.mtu_discovery && self.limits.mtu_upper_bound != DEFAULT_MTU_UPPER_BOUND {
            warnings.push(format!(
                "limits.mtu_upper_bound = {} has no effect while limits.mtu_discovery \
                 is off: the value is a ceiling for the upward search, and there is no \
                 search to bound",
                self.limits.mtu_upper_bound
            ));
        }

        if self.log.keylog {
            warnings.push(
                "log.keylog is on: TLS secrets are being written to the file named by \
                 SSLKEYLOGFILE, which lets anyone holding that file decrypt every session \
                 through this proxy. Never leave this on in production."
                    .to_owned(),
            );
        }

        if self.security.unanswered_packet_budget == 0 {
            warnings.push(
                "security.unanswered_packet_budget = 0 disables the RFC 9298 §7 amplification \
                 mitigation: a client can make this proxy flood a target that never answers"
                    .to_owned(),
            );
        }

        if self.limits.connect_timeout == 0 {
            warnings.push(
                "limits.connect_timeout = 0 hands the connect wait back to the operating \
                 system: a request for a target that drops SYNs holds its tunnel slot until \
                 the kernel gives up (about two minutes on Linux), and a client that resets \
                 the request stream in the meantime does not shorten that, so a burst of \
                 black-holed targets can spend a connection's whole max_targets_per_conn"
                    .to_owned(),
            );
        }

        warnings
    }
}

/// Upper bound on `limits.max_targets_per_conn`.
///
/// Not a protocol limit — a sanity limit. A value beyond this cannot be backed by
/// file descriptors on any realistic host, so it is more likely a typo.
const MAX_TARGETS_PER_CONN_CEILING: u32 = 65_536;

/// Upper bound on `limits.max_streams_bidi`.
///
/// The same number as [`MAX_TARGETS_PER_CONN_CEILING`], because one tunnel is
/// one stream: credit past the ceiling on tunnels could not carry one anyway.
///
/// What makes it worth rejecting rather than tolerating is where the cost is
/// paid. quinn does not allocate a stream when one is opened — `StreamsState`
/// reserves a slot for every unit of the credit when the *connection* is
/// created, so this value is spent at every handshake, by any peer, before a
/// request has been seen. Measured on the dev host: a handshake takes about
/// 11 ms at the default of 1024, 135 ms at this ceiling, 7.3 s at a million,
/// and does not finish inside ten seconds at four million — where `u32::MAX`,
/// which a config file can hold, is a further thousandfold. A typo here leaves
/// a server that still answers `systemctl status` and no client at all, which
/// is the same failure `MAX_INITIAL_MTU` is written against.
const MAX_STREAMS_BIDI_CEILING: u32 = MAX_TARGETS_PER_CONN_CEILING;

/// Renders a TOML parse failure without the source line it points at.
///
/// The `toml` crate's `Display` for a deserialization error prints the offending
/// line under a caret, the way a compiler does. That is the wrong shape for this
/// file, and only for this file: a syntax error on a `password = ...` line puts
/// the password on stderr at startup and into the journal on every `SIGHUP`
/// reload, where `Restart=on-failure` reprints it every few seconds until
/// somebody notices. So the error never reaches the chain at all — what is
/// reported is the parser's own message plus the position it points at, and the
/// configuration text is not in scope for either.
///
/// The operator loses nothing they need: the file, the line and the column are
/// all still named, which is what it takes to find a typo. What the message
/// carries is the parser's account of what it found and what it expected there,
/// rather than a copy of what was written — see [`redact_quoted`] for the half
/// of that account which is a copy after all.
fn parse_error(path: &Path, text: &str, error: &toml::de::Error) -> anyhow::Error {
    let message = redact_quoted(error.message());

    // No span, or a span this text cannot place: the message is worth having
    // without a position, and a position that is not the mistake's is worse
    // than none.
    let Some((line, column)) = error
        .span()
        .and_then(|span| line_and_column(text, span.start))
    else {
        return anyhow!("failed to parse config file {}: {message}", path.display());
    };

    anyhow!(
        "failed to parse config file {} at line {line}, column {column}: {message}",
        path.display()
    )
}

/// What a redacted quoted segment is replaced by.
///
/// Backticks are kept around it so the sentence still reads the way the parser
/// wrote it, and they are kept whichever quotes the segment had: one marker to
/// look for is worth more than a faithful copy of the punctuation around
/// something that is no longer there.
const REDACTED: &str = "`<redacted>`";

/// Replaces every quoted segment of a parser message with [`REDACTED`].
///
/// Keeping the source line out of the error is not enough on its own, because
/// `toml::de::Error::message` quotes the offending value itself whenever serde
/// is the one that objected. Which quotes it uses is decided by the type serde
/// found, and both kinds carry a value: `password = 8675309` renders as
/// ``invalid type: integer `8675309`, expected a string``, while anything serde
/// reads as a string keeps its double quotes, so `users = ["user1:hunter2"]`
/// renders as `invalid type: string "user1:hunter2", expected struct User` —
/// credentials and all. Either way that is the password on stderr again by a
/// different route, and the double-quoted route survived the first fix, which
/// knew only about backticks.
///
/// So both characters open a segment, and a segment ends at the same character
/// that opened it: a backtick inside a double-quoted string belongs to the
/// redaction rather than starting another one, which is what keeps a password
/// containing a backtick from splitting its own rendering into "safe" halves.
/// Keys are quoted the same way and are redacted with them; that costs the
/// operator nothing the line and column do not still give them.
///
/// A double quote inside the value is the same trap one level down. serde
/// renders a string with `{:?}`, so `hun"ter2` arrives as `hun\"ter2`, and a
/// scan that stops at the first `"` it sees closes the segment in the middle of
/// the secret and puts the rest of it back in the sentence. Hence
/// [`closing_quote`], which skips the character after every backslash.
fn redact_quoted(message: &str) -> String {
    let mut redacted = String::with_capacity(message.len());
    let mut rest = message;

    while let Some(open) = rest.find(is_quote) {
        redacted.push_str(&rest[..open]);
        redacted.push_str(REDACTED);

        // Both quote characters are ASCII, so this byte is the whole character.
        let quote = char::from(rest.as_bytes()[open]);

        // An unpaired opening quote opens a segment with no end, so everything
        // after it is part of the redaction rather than part of the message.
        let Some(close) = closing_quote(&rest[open + 1..], quote) else {
            return redacted;
        };
        rest = &rest[open + 1 + close + 1..];
    }

    redacted.push_str(rest);
    redacted
}

/// The offset of the character that closes a segment `quote` opened, if there
/// is one, counted from the character after that opening quote.
///
/// Only a double-quoted segment has an escape convention to respect, because
/// only it is a `{:?}` rendering: serde spells the value it rejected with
/// `Debug`, so a double quote inside it arrives as `\"` and a backslash as
/// `\\`. Skipping the character after every backslash is what keeps both from
/// being read as the end of the segment -- and the last backslash before the
/// real closing quote is `\\`'s second half, so the skip lands on that quote
/// rather than over it.
///
/// A backtick segment is `{}`-rendered and has no escapes at all, so it is
/// scanned as it always was: anything else would make a backslash in a value
/// swallow the character behind it.
///
/// Bytes rather than characters throughout. Neither the backslash nor either
/// quote can appear inside a multi-byte UTF-8 character, so a skip that lands
/// mid-character cannot be mistaken for one of them, and the offset returned
/// always points at an ASCII quote.
fn closing_quote(rest: &str, quote: char) -> Option<usize> {
    if quote != '"' {
        return rest.find(quote);
    }

    // An iterator rather than a hand-stepped index: every pass consumes at
    // least one byte, so the scan cannot fail to terminate, and a defect in
    // the skip is a wrong answer instead of a hung error path.
    let mut bytes = rest.bytes().enumerate();
    while let Some((index, byte)) = bytes.next() {
        match byte {
            // The skip lands on the escaped byte. A message that ends in a
            // lone backslash has nothing to skip and the iterator runs out: an
            // opening quote with no close, redacted to the end.
            b'\\' => {
                bytes.next();
            }
            b'"' => return Some(index),
            _ => {}
        }
    }

    None
}

/// Whether `character` is one of the two a parser message quotes with.
fn is_quote(character: char) -> bool {
    character == '`' || character == '"'
}

/// The 1-based line and column of a byte offset into `text`, if it has one.
///
/// The `toml` crate reports a span and renders the position itself, but only as
/// part of the caret block [`parse_error`] exists to avoid, so the arithmetic is
/// repeated here. Columns are counted in characters rather than bytes, which is
/// what an editor shows.
///
/// `None` for an offset past the end of `text` or one landing inside a
/// multi-byte character: the position is a convenience on the way to an error
/// message, so it must not become a panic of its own — and it must not become a
/// fabricated line 1, column 1 either, which would send the operator to a line
/// that is not the one at fault.
fn line_and_column(text: &str, offset: usize) -> Option<(usize, usize)> {
    let before = text.get(..offset)?;

    let line = before.matches('\n').count() + 1;
    let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;

    Some((line, column))
}

/// Levels accepted as a bare `log.level`.
const LOG_LEVELS: [&str; 5] = ["trace", "debug", "info", "warn", "error"];

/// Validates `log.level`.
///
/// A plain word must name a level. This extra strictness matters because
/// `EnvFilter` would otherwise read a typo like `"warning"` as a *target* name,
/// accept it, and then log nothing at all. Anything containing filter syntax is
/// handed to `EnvFilter` as-is.
fn validate_log_level(level: &str) -> Result<()> {
    if level.contains([',', '=', '[']) {
        tracing_subscriber::EnvFilter::try_new(level)
            .with_context(|| format!("log.level = {level:?} is not a valid filter"))?;
        return Ok(());
    }

    if !LOG_LEVELS.iter().any(|l| level.eq_ignore_ascii_case(l)) {
        bail!(
            "log.level = {level:?} is not one of {LOG_LEVELS:?}; for anything more \
             specific use a filter directive such as \"volto=debug,quinn=info\""
        );
    }

    Ok(())
}

impl Server {
    /// The ALPN identifiers in the byte-vector form rustls expects.
    pub fn alpn_wire(&self) -> Vec<Vec<u8>> {
        self.alpn.iter().map(|p| p.as_bytes().to_vec()).collect()
    }

    /// The shutdown grace period as a duration.
    pub fn shutdown_grace(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.shutdown_grace)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn defaults_are_applied() {
        let cfg: Config = toml::from_str(
            r#"
            [server]
            listen = "127.0.0.1:4433"
            cert = "/tmp/c.pem"
            key = "/tmp/k.pem"
            "#,
        )
        .expect("parses");
        assert_eq!(cfg.server.alpn, vec!["h3".to_string()]);
        assert_eq!(cfg.log.level, "info");
        assert!(!cfg.log.keylog, "keylog must be opt-in");
        assert_eq!(cfg.limits.udp_session_timeout, 180);
        assert_eq!(cfg.limits.max_targets_per_conn, 256);
        assert_eq!(cfg.limits.max_connections, 256);
        assert_eq!(cfg.limits.connect_timeout, 10);
        assert_eq!(
            cfg.limits.connect_timeout(),
            Some(std::time::Duration::from_secs(10))
        );
        assert_eq!(cfg.limits.max_streams_bidi, 1024);
        assert_eq!(cfg.security.max_auth_failures, 5);
        // The connection cap and the tunnel quota multiply out to the product
        // the startup fd check adds its headroom to.
        assert_eq!(
            cfg.limits.max_connections as u64 * cfg.limits.max_targets_per_conn as u64,
            65536
        );
        assert_eq!(cfg.limits.max_idle_timeout, 60);
        assert_eq!(cfg.limits.keep_alive_interval, 20);
        assert_eq!(cfg.limits.initial_mtu, 1200);
        assert!(cfg.limits.mtu_discovery);
        // quinn's own ceiling: raising it is a per-path measurement, not a default.
        assert_eq!(cfg.limits.mtu_upper_bound, 1452);
        // The socket buffers are asked for, not inherited: quinn never calls
        // setsockopt, so an absent key would leave `net.core.rmem_default`.
        assert_eq!(cfg.limits.socket_recv_buffer, DEFAULT_SOCKET_RECV_BUFFER);
        assert_eq!(cfg.limits.socket_send_buffer, DEFAULT_SOCKET_SEND_BUFFER);
        assert_eq!(cfg.limits.socket_recv_buffer, 2 * 1024 * 1024);
        assert_eq!(cfg.limits.socket_send_buffer, 2 * 1024 * 1024);
        // BBR by default: the point of the proxy is lossy long-haul paths.
        assert_eq!(cfg.limits.congestion_control, CongestionControl::Bbr);
        // IPv4 first by default, which is not what the resolver would have
        // ordered on a dual-stack host (decision D58).
        assert_eq!(
            cfg.limits.ip_family_preference,
            IpFamilyPreference::Ipv4,
            "the default must put IPv4 first"
        );
        // The defaults must themselves satisfy the keep-alive rule.
        assert!(cfg.limits.keep_alive_interval * 2 < cfg.limits.max_idle_timeout);
        assert_eq!(cfg.server.shutdown_grace, 5);
        assert_eq!(cfg.server.alpn_wire(), vec![b"h3".to_vec()]);

        // Security defaults: private space closed, port 25 closed, port 53 open
        // because Surge tests UDP with a DNS query.
        assert!(!cfg.security.allow_private_networks);
        assert_eq!(cfg.security.denied_ports, vec![25]);
        assert!(!cfg.security.denied_ports.contains(&53));
        assert_eq!(cfg.security.unanswered_packet_budget, 64);

        // No users at all is legal and means "no authentication".
        assert!(cfg.auth.users.is_empty());
    }

    /// A minimal helper: the parsed config for `body`, with cert paths that exist
    /// left out (so only `body` is under test).
    fn parse(body: &str) -> Config {
        toml::from_str(&format!(
            r#"
            [server]
            listen = "127.0.0.1:4433"
            cert = "/tmp/c.pem"
            key = "/tmp/k.pem"
            {body}
            "#
        ))
        .expect("parses")
    }

    /// Asserts that everything about `cfg` is valid *except* its certificate paths,
    /// which `parse` deliberately points at files that do not exist.
    ///
    /// The certificate check is the last thing `validate` does, so any other
    /// complaint surfaces first and fails this.
    fn assert_valid_apart_from_certs(cfg: &Config, context: &str) {
        if let Err(error) = cfg.validate() {
            let msg = error.to_string();
            assert!(
                msg.contains("server.cert") || msg.contains("server.key"),
                "{context} should be valid, but: {msg}"
            );
        }
    }

    /// A file that removes itself however the test ends.
    ///
    /// The test below writes a password into the system temp directory, and a
    /// plain `remove_file` after the assertions only cleans up when they all
    /// pass — the failing run, the one somebody is about to go and look at, is
    /// exactly the run that would leave the file behind.
    struct TempConfig(std::path::PathBuf);

    impl TempConfig {
        fn write(tag: &str, body: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("volto-config-{tag}-{}.toml", std::process::id()));
            std::fs::write(&path, body).expect("write the broken config");
            Self(path)
        }
    }

    impl Drop for TempConfig {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Wraps `entry` in the smallest config that reaches the `[auth]` users
    /// array, with the entry on line 7.
    fn config_with_raw_user(entry: &str) -> String {
        format!(
            "[server]\n\
             listen = \"127.0.0.1:4433\"\n\
             cert = \"/tmp/c.pem\"\n\
             key = \"/tmp/k.pem\"\n\
             [auth]\n\
             users = [\n\
             {entry},\n\
             ]\n"
        )
    }

    /// [`config_with_raw_user`] with `password` written into a user table, so
    /// the password is the value serde rejects — on line 7.
    fn config_with_raw_password(password: &str) -> String {
        config_with_raw_user(&format!(
            "{{ username = \"user1\", password = {password} }}"
        ))
    }

    /// A secret written where an integer belongs, also on line 7.
    ///
    /// Nothing in `[limits]` is a credential, but what serde does with a string
    /// does not depend on the key it was written under: this is the same leak in
    /// a section an operator would never think to be careful in.
    fn config_with_raw_max_connections(value: &str) -> String {
        format!(
            "[server]\n\
             listen = \"127.0.0.1:4433\"\n\
             cert = \"/tmp/c.pem\"\n\
             key = \"/tmp/k.pem\"\n\
             [limits]\n\
             \n\
             max_connections = {value}\n"
        )
    }

    /// A parse error must name where it is, and must not quote what is there.
    ///
    /// The `toml` crate renders a parse error as the offending source line under
    /// a caret, so a typo on a `password = ...` line used to print the password
    /// on stderr at startup and into the journal on every `SIGHUP` reload — and
    /// `Restart=on-failure` makes the startup path repeat every few seconds.
    ///
    /// Six ways of getting the quotes wrong, because they fail at different
    /// depths and only one of them was covered before. A bare word is rejected
    /// by the lexer, which never sees a value and so cannot quote one. An
    /// integer and a boolean are *valid* TOML values of the wrong type, and
    /// there serde is the one that objects — with the value in its message
    /// (``invalid type: integer `8675309`, expected a string``), which is the
    /// password on stderr by a route the caret block never touched.
    ///
    /// The last three are the same objection about a value serde reads as a
    /// *string*, which it renders in double quotes rather than backticks:
    /// `invalid type: string "user1:hunter2", expected struct User`. A
    /// redaction that knew only about backticks left every one of them
    /// untouched, whatever section the mistake was in — and the third of them is
    /// the case that decides where a segment ends, a secret with a backtick of
    /// its own inside a double-quoted rendering.
    ///
    /// Both renderings of an `anyhow` error are checked because the two print
    /// different things: `{:#}` walks the chain of messages, `{:?}` adds the
    /// sources and any backtrace.
    #[test]
    fn a_parse_error_does_not_echo_the_value_it_rejects() {
        // Tag, the broken config, what must not survive in the message, and
        // whether the parser quoted a value at all: the lexer's complaint names
        // none, so there is nothing there for the marker to replace.
        let cases: [(&str, String, &[&str], bool); 9] = [
            (
                "bare",
                config_with_raw_password("correct-horse-battery-staple"),
                &["correct-horse-battery-staple"],
                false,
            ),
            (
                "integer",
                config_with_raw_password("8675309"),
                &["8675309"],
                true,
            ),
            ("boolean", config_with_raw_password("true"), &["true"], true),
            (
                "string-for-struct",
                config_with_raw_user("\"user1:hunter2\""),
                &["hunter2"],
                true,
            ),
            (
                "string-for-integer",
                config_with_raw_max_connections("\"correct-horse-battery-staple\""),
                &["correct-horse-battery-staple"],
                true,
            ),
            // A backtick inside the secret. With only backticks redacted, the
            // one in the middle opened a segment that never closed and the
            // message kept everything in front of it -- `hunter2` included.
            (
                "backticked-string",
                config_with_raw_user("\"user1:hunter2`x\""),
                &["hunter2"],
                true,
            ),
            // A double quote inside the secret, which serde renders escaped
            // (`{:?}`) and a scan for the closing quote used to stop on: the
            // segment closed inside the secret and its tail went to stderr as
            // if it were part of the parser's sentence. Written as a TOML
            // literal string, which needs no escaping of its own to carry one.
            (
                "quote-in-secret",
                config_with_raw_user("'user1:hun\"ter2-TAILSECRET'"),
                &["hunter2", "TAILSECRET"],
                true,
            ),
            // The same character reached through a TOML basic string, so the
            // file itself escapes it as well: the value serde sees is identical
            // and so is the rendering.
            (
                "escaped-quote-in-secret",
                config_with_raw_user("\"user1:hun\\\"ter2-TAILSECRET\""),
                &["hunter2", "TAILSECRET"],
                true,
            ),
            // A secret ending in a backslash. Its rendering ends `\\"`, so a
            // scan that skips the character after every backslash must not
            // skip the closing quote itself -- and must not run off the end
            // looking for another one.
            (
                "backslash-before-the-close",
                config_with_raw_user("'user1:hunter2-TAILSECRET\\'"),
                &["hunter2", "TAILSECRET"],
                true,
            ),
        ];

        for (tag, body, secrets, marked) in cases {
            let file = TempConfig::write(tag, &body);
            let error = Config::load(&file.0).expect_err("a mistyped value must not load");

            for rendered in [format!("{error:#}"), format!("{error:?}")] {
                for secret in secrets {
                    assert!(
                        !rendered.contains(secret),
                        "the {tag} value leaked {secret}: {rendered}"
                    );
                }
                assert!(
                    rendered.contains(REDACTED) == marked,
                    "the {tag} value must {}leave a marker behind: {rendered}",
                    if marked { "" } else { "not " }
                );
                assert!(
                    rendered.contains("line 7"),
                    "the operator still has to be told where the mistake is: {rendered}"
                );
            }
        }
    }

    /// The redaction has to leave the parser's account of the mistake behind.
    ///
    /// A message with the value cut out of it is only useful if what is left
    /// still says what went wrong, so this pins the shape rather than only the
    /// absence: the type serde found, the type it wanted, and a marker where the
    /// value was.
    #[test]
    fn a_rejected_value_is_replaced_rather_than_dropped() {
        let file = TempConfig::write("typed", &config_with_raw_password("8675309"));
        let error = Config::load(&file.0).expect_err("an integer password must not load");
        let rendered = format!("{error:#}");

        assert!(
            rendered.contains(REDACTED),
            "the value must leave a marker behind: {rendered}"
        );
        assert!(
            rendered.contains("invalid type") && rendered.contains("expected a string"),
            "the parser's account of the mistake must survive: {rendered}"
        );
    }

    /// Each quote kind is scanned by its own escape rules, and closing a
    /// segment in the right place is what keeps the rest of the sentence alive.
    ///
    /// A backtick segment is a `{}` rendering with no escapes: a backslash
    /// inside one is just a byte, and skipping the character behind it would
    /// swallow the closing backtick and take the rest of the message with it.
    /// A double-quoted segment is a `{:?}` rendering where `\\` must be
    /// stepped over whole — a scan that read its second half as an escape
    /// would run past the real closing quote and redact the `expected` clause,
    /// which is the half of the message the operator fixes the typo by.
    /// (Both halves were unpinned when the batch-10 verification mutated them.)
    #[test]
    fn each_quote_kind_is_scanned_by_its_own_rules() {
        assert_eq!(
            redact_quoted("expected `\\` at the start, kept `this` whole"),
            format!("expected {REDACTED} at the start, kept {REDACTED} whole"),
            "a backslash inside a backtick segment is a byte, not an escape"
        );

        let file = TempConfig::write(
            "trailing-backslash-keeps-expected",
            &config_with_raw_user("'user1:hunter2-TAILSECRET\\'"),
        );
        let error =
            Config::load(&file.0).expect_err("a string where a table belongs must not load");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(", expected struct User"),
            "the escape skip must close at the real quote, not run past it: {rendered}"
        );
    }

    /// A double-quoted segment with nothing closing it must run out *at* the end
    /// of the message rather than one byte past it.
    ///
    /// The scan indexes bytes directly, so a bound that admitted the length
    /// itself would panic on the empty slot behind the last character — inside
    /// the error path whose whole job is to keep a password off stderr, and on
    /// the input that reaches it, since serde renders an unterminated string in
    /// the file as a value with no closing quote of its own.
    #[test]
    fn an_unclosed_double_quoted_segment_runs_out_at_the_end() {
        assert_eq!(closing_quote("hunter2", '"'), None, "no quote at all");
        // The other way of reaching the end: the escape skip steps over the
        // last byte instead of landing on it.
        assert_eq!(closing_quote("hunter2\\", '"'), None, "a lone backslash");
        assert_eq!(closing_quote("hunter2\"", '"'), Some(7), "a closed segment");

        assert_eq!(
            redact_quoted("invalid type: string \"user1:hunter2"),
            format!("invalid type: string {REDACTED}"),
            "an unpaired quote redacts everything after it"
        );
    }

    /// A span the text cannot place must cost the position, not the message.
    ///
    /// `line_and_column` used to answer line 1, column 1 for an offset past the
    /// end of the file or one landing inside a multi-byte character, which sends
    /// the operator to a line that is not the one at fault.
    #[test]
    fn an_unplaceable_offset_has_no_position() {
        let text = "a = \"é\"\n";

        assert_eq!(line_and_column(text, 0), Some((1, 1)));
        // Column 7 rather than the byte offset's 8: the accented character is
        // two bytes and one column, which is what an editor shows.
        assert_eq!(line_and_column(text, 7), Some((1, 7)));
        assert_eq!(line_and_column(text, 6), None, "inside a character");
        assert_eq!(line_and_column(text, 99), None, "past the end");
    }

    #[test]
    fn users_are_parsed() {
        let cfg = parse(
            r#"
            [auth]
            users = [
              { username = "user1", password = "s3cret" },
              { username = "user2", password = "other" },
            ]
            "#,
        );
        assert_eq!(cfg.auth.users.len(), 2);
        assert_eq!(cfg.auth.users[0].username, "user1");
        assert_eq!(cfg.auth.users[0].password, "s3cret");
    }

    /// A `Debug`-formatted config must not leak passwords: it is one panic
    /// message or one stray log line away from being written down.
    #[test]
    fn debug_output_redacts_passwords() {
        let cfg = parse(
            r#"
            [auth]
            users = [{ username = "user1", password = "s3cret" }]
            "#,
        );

        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("s3cret"),
            "the password must be redacted; got:\n{rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // The username is not a secret and stays visible for diagnosis.
        assert!(rendered.contains("user1"), "{rendered}");
    }

    #[test]
    fn malformed_users_are_rejected_with_their_index() {
        let cases = [
            (
                r#"[auth]
                   users = [{ username = "", password = "p" }]"#,
                "auth.users[0].username",
            ),
            (
                r#"[auth]
                   users = [{ username = "a:b", password = "p" }]"#,
                "auth.users[0].username",
            ),
            (
                r#"[auth]
                   users = [{ username = "u", password = "" }]"#,
                "auth.users[0].password",
            ),
            (
                r#"[auth]
                   users = [
                     { username = "u", password = "p" },
                     { username = "u", password = "q" },
                   ]"#,
                "auth.users[1].username",
            ),
        ];

        for (body, expected) in cases {
            let err = parse(body).validate().expect_err("must be rejected");
            assert!(err.to_string().contains(expected), "{err}");
        }
    }

    /// A user-id longer than a log line carries whole is refused at load.
    ///
    /// Not a style rule: such a name can never be cleared by its own success.
    /// A failure that names it is charged by the truncated copy the log format
    /// hands out, which matches no configured user, so it lands in the bucket
    /// no success ever clears — and the client that really does hold those
    /// credentials loses the connection on the fifth lifetime failure however
    /// often it authenticates in between. Refusing the configuration is what
    /// makes that state unreachable.
    ///
    /// The limit is exactly the log format's, and the message must name it
    /// without echoing the user-id: a name is not a password, but it sits next
    /// to one in the same table, and this file's whole discipline is that
    /// nothing out of `[auth]` reaches stderr.
    #[test]
    fn an_over_long_username_is_rejected_without_echoing_it() {
        let username = "u".repeat(crate::logfmt::MAX_TOKEN + 1);
        let err = parse(&format!(
            "[auth]\nusers = [{{ username = \"{username}\", password = \"p\" }}]"
        ))
        .validate()
        .expect_err("a user-id past the log bound must be rejected");
        let rendered = err.to_string();

        assert!(
            rendered.contains("auth.users[0].username"),
            "the operator has to be told which entry it is: {rendered}"
        );
        assert!(
            rendered.contains(&crate::logfmt::MAX_TOKEN.to_string()),
            "the message has to name the limit: {rendered}"
        );
        assert!(
            !rendered.contains(&username),
            "the name itself must not be echoed: {rendered}"
        );

        // The limit itself is legal, so the rejection is of what is past it
        // rather than of a length that merely approaches it.
        let cfg = parse(&format!(
            "[auth]\nusers = [{{ username = \"{}\", password = \"p\" }}]",
            "u".repeat(crate::logfmt::MAX_TOKEN)
        ));
        assert_valid_apart_from_certs(&cfg, "a user-id exactly at the log bound");
    }

    #[test]
    fn a_zero_or_oversized_target_quota_is_rejected() {
        for value in ["0", "70000"] {
            let err = parse(&format!("[limits]\nmax_targets_per_conn = {value}"))
                .validate()
                .expect_err("must be rejected");
            assert!(err.to_string().contains("max_targets_per_conn"), "{err}");
        }

        // The ceiling is a sanity limit rather than a protocol one, so the value
        // at it is still a quota the operator meant: only what is past it is
        // read as a typo.
        let cfg = parse(&format!(
            "[limits]\nmax_targets_per_conn = {MAX_TARGETS_PER_CONN_CEILING}"
        ));
        assert_valid_apart_from_certs(&cfg, "a quota of exactly the ceiling");

        let err = parse(&format!(
            "[limits]\nmax_targets_per_conn = {}",
            MAX_TARGETS_PER_CONN_CEILING + 1
        ))
        .validate()
        .expect_err("one target past the ceiling must be rejected");
        assert!(err.to_string().contains("max_targets_per_conn"), "{err}");
    }

    /// Zero disables the connect budget rather than meaning "give up at once",
    /// which is the same shape `keep_alive_interval = 0` has.
    #[test]
    fn a_zero_connect_timeout_disables_the_budget() {
        let cfg = parse("[limits]\nconnect_timeout = 0");
        assert_valid_apart_from_certs(&cfg, "connect_timeout = 0");
        assert_eq!(cfg.limits.connect_timeout, 0);
        assert_eq!(cfg.limits.connect_timeout(), None);

        // And an ordinary value is carried through as a duration.
        let cfg = parse("[limits]\nconnect_timeout = 3");
        assert_valid_apart_from_certs(&cfg, "connect_timeout = 3");
        assert_eq!(
            cfg.limits.connect_timeout(),
            Some(std::time::Duration::from_secs(3))
        );
    }

    /// A budget that is not a whole number of seconds is a typo, and must fail at
    /// startup rather than silently becoming a default.
    #[test]
    fn a_malformed_connect_timeout_is_rejected() {
        for value in ["-1", "\"10\"", "1.5", "true"] {
            let err = toml::from_str::<Config>(&format!(
                r#"
                [server]
                listen = "127.0.0.1:4433"
                cert = "/tmp/c.pem"
                key = "/tmp/k.pem"
                [limits]
                connect_timeout = {value}
                "#
            ))
            .expect_err("{value} must be rejected");
            assert!(err.to_string().contains("connect_timeout"), "{err}");
        }
    }

    /// The rule that exists because of the relay: a keep-alive at or above half the
    /// idle timeout cannot survive losing a single packet.
    #[test]
    fn a_keep_alive_at_or_above_half_the_idle_timeout_is_rejected() {
        // Exactly half, and above it.
        for (idle, keepalive) in [(40, 20), (60, 30), (60, 45), (10, 5)] {
            let err = parse(&format!(
                "[limits]\nmax_idle_timeout = {idle}\nkeep_alive_interval = {keepalive}"
            ))
            .validate()
            .expect_err("must be rejected");
            let msg = err.to_string();
            assert!(msg.contains("keep_alive_interval"), "{msg}");
            // The message has to say what to compare against, not just complain.
            assert!(msg.contains("max_idle_timeout"), "{msg}");
        }

        // Just below half is fine.
        for (idle, keepalive) in [(41, 20), (60, 20), (60, 29), (1, 0)] {
            let cfg = parse(&format!(
                "[limits]\nmax_idle_timeout = {idle}\nkeep_alive_interval = {keepalive}"
            ));
            assert_valid_apart_from_certs(&cfg, &format!("idle={idle} keepalive={keepalive}"));
        }
    }

    /// The ratio check must survive the interval it is checking (D86).
    ///
    /// TOML integers deserialize across the whole of the target type, so every
    /// `u64` here is something an operator can write in the file, `u64::MAX`
    /// included. The check used to double the interval before comparing it,
    /// which above `u64::MAX / 2` has no answer to give: a debug build panicked
    /// inside `validate` — a validator that aborts the process instead of
    /// returning `Err` — and a release build wrapped the product to a small
    /// number, accepted the interval and passed it to quinn, where the first
    /// established connection turns it into `Instant::now() + interval` and
    /// panics the connection driver instead.
    #[test]
    fn an_overflowing_keep_alive_interval_is_rejected_rather_than_panicking() {
        for keepalive in [u64::MAX, u64::MAX - 1, u64::MAX / 2 + 1, 1u64 << 63] {
            let err = parse(&format!("[limits]\nkeep_alive_interval = {keepalive}"))
                .validate()
                .expect_err("an interval past half the idle timeout must be rejected");
            assert!(err.to_string().contains("keep_alive_interval"), "{err}");
        }
    }

    /// Zero disables keep-alives rather than failing the ratio check — but it is
    /// warned about, because behind a relay it is how idle connections die.
    #[test]
    fn disabling_keep_alives_is_allowed_but_warned_about() {
        let cfg = parse("[limits]\nkeep_alive_interval = 0");
        assert_valid_apart_from_certs(&cfg, "keep_alive_interval = 0");
        assert_eq!(cfg.limits.keep_alive_interval(), None);
        assert!(
            cfg.warnings()
                .iter()
                .any(|w| w.contains("keep_alive_interval") && w.contains("conntrack")),
            "{:?}",
            cfg.warnings()
        );
    }

    #[test]
    fn an_initial_mtu_below_the_quic_floor_is_rejected() {
        for value in [0, 1, 576, 1199] {
            let err = parse(&format!("[limits]\ninitial_mtu = {value}"))
                .validate()
                .expect_err("must be rejected");
            let msg = err.to_string();
            assert!(msg.contains("initial_mtu"), "{msg}");
            assert!(msg.contains("1200"), "the floor must be named: {msg}");
        }

        // The floor itself, and the range above it up to the ceiling.
        for value in [1200, 1350, MAX_INITIAL_MTU] {
            let cfg = parse(&format!("[limits]\ninitial_mtu = {value}"));
            assert_valid_apart_from_certs(&cfg, &format!("initial_mtu = {value}"));
        }
    }

    /// The other end of the same range, and the dangerous one.
    ///
    /// Below the floor quinn silently clamps up, so the worst a missing check
    /// costs is a value that is not the one configured. Above the ceiling there
    /// is no clamp at all: the handshake goes out in packets no path delivers,
    /// the black-hole detector never runs because no connection is ever
    /// established, and a reload makes that the state of a server that was
    /// working a moment ago.
    ///
    /// 1453 is the first rejected value and 1500 is in the list because it is
    /// the number the mistake reaches for: `initial_mtu` is a UDP payload size,
    /// so an Ethernet frame's 1500 bytes is an IP packet, not a payload.
    #[test]
    fn an_initial_mtu_above_the_ethernet_ceiling_is_rejected() {
        for value in [MAX_INITIAL_MTU + 1, 1500, 9000, u16::MAX] {
            let err = parse(&format!("[limits]\ninitial_mtu = {value}"))
                .validate()
                .expect_err("must be rejected");
            let msg = err.to_string();
            assert!(msg.contains("initial_mtu"), "{msg}");
            assert!(
                msg.contains(&MAX_INITIAL_MTU.to_string()),
                "the ceiling must be named: {msg}"
            );
        }
    }

    /// A ceiling below the start describes a search that cannot happen, and the
    /// operator meant *something*, so the mistake is reported rather than
    /// silently reduced to "no discovery". Equal is fine: it pins the search's
    /// destination to its start, which is a coherent (if pointless) request.
    #[test]
    fn an_mtu_upper_bound_below_the_initial_mtu_is_rejected() {
        let err = parse("[limits]\ninitial_mtu = 1350\nmtu_upper_bound = 1300")
            .validate()
            .expect_err("must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("mtu_upper_bound"), "{msg}");
        assert!(msg.contains("initial_mtu"), "{msg}");

        for body in [
            "[limits]\ninitial_mtu = 1350\nmtu_upper_bound = 1350",
            "[limits]\nmtu_upper_bound = 1452",
            // A measured path: 1464 is what an IPv4 uplink capped at 1492 bytes
            // of IP packet leaves, and the ceiling is the IPv4 Ethernet limit.
            "[limits]\nmtu_upper_bound = 1464",
            "[limits]\nmtu_upper_bound = 1472",
        ] {
            assert_valid_apart_from_certs(&parse(body), body);
        }
    }

    /// 1500 is in the list for the same reason as in the `initial_mtu` test:
    /// the value is a UDP payload size, and an Ethernet frame's 1500 bytes is
    /// an IP packet, not a payload.
    #[test]
    fn an_mtu_upper_bound_above_the_ipv4_ethernet_ceiling_is_rejected() {
        for value in [MAX_MTU_UPPER_BOUND + 1, 1500, 9000, u16::MAX] {
            let err = parse(&format!("[limits]\nmtu_upper_bound = {value}"))
                .validate()
                .expect_err("must be rejected");
            let msg = err.to_string();
            assert!(msg.contains("mtu_upper_bound"), "{msg}");
            assert!(
                msg.contains(&MAX_MTU_UPPER_BOUND.to_string()),
                "the ceiling must be named: {msg}"
            );
        }
    }

    /// With discovery off there is no search to bound, and a key the operator
    /// set to a non-default value deserves a word about why nothing changed.
    #[test]
    fn an_mtu_upper_bound_without_discovery_is_allowed_but_warned_about() {
        let cfg = parse("[limits]\nmtu_discovery = false\nmtu_upper_bound = 1464");
        assert_valid_apart_from_certs(&cfg, "mtu_discovery = false");
        assert!(
            cfg.warnings()
                .iter()
                .any(|w| w.contains("mtu_upper_bound") && w.contains("1464")),
            "{:?}",
            cfg.warnings()
        );

        // The default value draws no warning: nothing was configured away.
        let cfg = parse("[limits]\nmtu_discovery = false");
        assert!(
            !cfg.warnings().iter().any(|w| w.contains("mtu_upper_bound")),
            "{:?}",
            cfg.warnings()
        );
    }

    #[test]
    fn an_initial_rtt_outside_the_sane_range_is_rejected() {
        for value in [0, 9, 10_001] {
            let err = parse(&format!("[limits]\ninitial_rtt_ms = {value}"))
                .validate()
                .expect_err("must be rejected");
            let msg = err.to_string();
            assert!(msg.contains("initial_rtt_ms"), "{msg}");
        }

        // Both ends of the range, the default, and a tuned long-haul value.
        for value in [10, 150, 333, 10_000] {
            let cfg = parse(&format!("[limits]\ninitial_rtt_ms = {value}"));
            assert_valid_apart_from_certs(&cfg, &format!("initial_rtt_ms = {value}"));
        }
    }

    #[test]
    fn a_zero_stream_limit_or_idle_timeout_is_rejected() {
        for (body, field) in [
            ("[limits]\nmax_streams_bidi = 0", "max_streams_bidi"),
            ("[limits]\nmax_idle_timeout = 0", "max_idle_timeout"),
            ("[limits]\nmax_idle_timeout = 4000", "max_idle_timeout"),
        ] {
            let err = parse(body).validate().expect_err("must be rejected");
            assert!(err.to_string().contains(field), "{err}");
        }

        // The ceiling is a legal idle timeout, and the default keep-alive stays
        // well under half of it, so nothing else in the config objects to it.
        let cfg = parse(&format!(
            "[limits]\nmax_idle_timeout = {MAX_IDLE_TIMEOUT_CEILING}"
        ));
        assert_valid_apart_from_certs(&cfg, "an idle timeout of exactly the ceiling");

        let err = parse(&format!(
            "[limits]\nmax_idle_timeout = {}",
            MAX_IDLE_TIMEOUT_CEILING + 1
        ))
        .validate()
        .expect_err("one second past the ceiling must be rejected");
        assert!(err.to_string().contains("max_idle_timeout"), "{err}");
    }

    /// The stream credit is work per handshake, so it has a ceiling (D86).
    ///
    /// quinn reserves a slot for every unit of it when a connection is created,
    /// not when a stream is opened, so an operator writing a large number here
    /// is not raising a limit but adding work to every handshake: measured on
    /// the dev host, about 11 ms at the default 1024, 135 ms at the ceiling,
    /// 7.3 s at a million, and no completed handshake within ten seconds at
    /// four million. `u32::MAX` is a config file away from any of those.
    #[test]
    fn a_stream_limit_past_the_ceiling_is_rejected() {
        for streams in [u32::MAX, MAX_STREAMS_BIDI_CEILING + 1] {
            let err = parse(&format!("[limits]\nmax_streams_bidi = {streams}"))
                .validate()
                .expect_err("a stream limit past the ceiling must be rejected");
            assert!(err.to_string().contains("max_streams_bidi"), "{err}");
        }

        let cfg = parse(&format!(
            "[limits]\nmax_streams_bidi = {MAX_STREAMS_BIDI_CEILING}"
        ));
        assert_valid_apart_from_certs(&cfg, "a stream limit of exactly the ceiling");
    }

    /// The two application timers share the transport timeout's ceiling: both
    /// are added to `Instant::now()` to make deadlines, so an unbounded `u64`
    /// of seconds would panic that arithmetic instead of meaning anything.
    #[test]
    fn the_session_and_connect_timers_share_the_ceiling() {
        for (body, field) in [
            (
                format!(
                    "[limits]\nudp_session_timeout = {}",
                    MAX_IDLE_TIMEOUT_CEILING + 1
                ),
                "udp_session_timeout",
            ),
            (
                format!(
                    "[limits]\nconnect_timeout = {}",
                    MAX_IDLE_TIMEOUT_CEILING + 1
                ),
                "connect_timeout",
            ),
            // The panic the ceiling exists to keep unreachable.
            (
                "[limits]\nudp_session_timeout = 9300000000000000000".to_string(),
                "udp_session_timeout",
            ),
        ] {
            let err = parse(&body).validate().expect_err("must be rejected");
            assert!(err.to_string().contains(field), "{err}");
        }

        // The ceiling itself is legal for both.
        let cfg = parse(&format!(
            "[limits]\nudp_session_timeout = {MAX_IDLE_TIMEOUT_CEILING}\n\
             connect_timeout = {MAX_IDLE_TIMEOUT_CEILING}"
        ));
        assert_valid_apart_from_certs(&cfg, "both timers at exactly the ceiling");
    }

    /// The drain period is a bound, so it has to stay one (D86).
    ///
    /// Unlike the timers above, an absurd grace period does not panic anything:
    /// `tokio::time::timeout` folds a duration it cannot add to `Instant::now()`
    /// into a deadline in the far future, so `u64::MAX` seconds was accepted and
    /// silently removed the bound `crate::quic`'s drain is built around — a
    /// `SIGTERM` would then wait on connections that may never end until the
    /// service manager's `SIGKILL` arrived, which is the ungraceful ending the
    /// grace period exists to avoid.
    #[test]
    fn an_unbounded_shutdown_grace_is_rejected() {
        for grace in [u64::MAX, MAX_SHUTDOWN_GRACE + 1] {
            let err = toml::from_str::<Config>(&format!(
                "[server]\nlisten = \"127.0.0.1:4433\"\ncert = \"/tmp/c.pem\"\n\
                 key = \"/tmp/k.pem\"\nshutdown_grace = {grace}\n"
            ))
            .expect("parses")
            .validate()
            .expect_err("a grace period past the ceiling must be rejected");
            assert!(err.to_string().contains("shutdown_grace"), "{err}");
        }

        // Both ends of the accepted range stay accepted: zero closes everything
        // at once, and the ceiling itself is a legal drain.
        for grace in [0, MAX_SHUTDOWN_GRACE] {
            let cfg: Config = toml::from_str(&format!(
                "[server]\nlisten = \"127.0.0.1:4433\"\ncert = \"/tmp/c.pem\"\n\
                 key = \"/tmp/k.pem\"\nshutdown_grace = {grace}\n"
            ))
            .expect("parses");
            assert_valid_apart_from_certs(&cfg, &format!("shutdown_grace = {grace}"));
            assert_eq!(
                cfg.server.shutdown_grace(),
                std::time::Duration::from_secs(grace)
            );
        }
    }

    #[test]
    fn pinning_the_mtu_is_allowed_but_warned_about() {
        let cfg = parse("[limits]\nmtu_discovery = false\ninitial_mtu = 1350");
        assert_valid_apart_from_certs(&cfg, "mtu_discovery = false");
        assert!(
            cfg.warnings()
                .iter()
                .any(|w| w.contains("mtu_discovery") && w.contains("1350")),
            "{:?}",
            cfg.warnings()
        );
    }

    #[test]
    fn congestion_control_is_selectable_and_defaults_to_bbr() {
        assert_eq!(
            parse("").limits.congestion_control,
            CongestionControl::Bbr,
            "the default must be BBR"
        );
        for (value, expected) in [
            ("bbr", CongestionControl::Bbr),
            ("cubic", CongestionControl::Cubic),
            ("newreno", CongestionControl::NewReno),
        ] {
            let cfg = parse(&format!("[limits]\ncongestion_control = \"{value}\""));
            assert_eq!(cfg.limits.congestion_control, expected, "{value}");
            assert_valid_apart_from_certs(&cfg, value);
        }
    }

    #[test]
    fn an_unknown_congestion_controller_is_rejected() {
        let err = toml::from_str::<Config>(
            r#"
            [server]
            listen = "127.0.0.1:4433"
            cert = "/tmp/c.pem"
            key = "/tmp/k.pem"
            [limits]
            congestion_control = "reno"
            "#,
        )
        .expect_err("an unknown controller must be rejected");
        assert!(err.to_string().contains("congestion_control"), "{err}");
    }

    #[test]
    fn the_ip_family_preference_is_selectable_and_defaults_to_ipv4() {
        assert_eq!(
            parse("").limits.ip_family_preference,
            IpFamilyPreference::Ipv4,
            "the default must be IPv4-first"
        );
        for (value, expected) in [
            ("ipv4", IpFamilyPreference::Ipv4),
            ("ipv6", IpFamilyPreference::Ipv6),
            ("system", IpFamilyPreference::System),
        ] {
            let cfg = parse(&format!("[limits]\nip_family_preference = \"{value}\""));
            assert_eq!(cfg.limits.ip_family_preference, expected, "{value}");
            assert_valid_apart_from_certs(&cfg, value);
        }
    }

    /// A typo must name the key it was made in, since that is all an operator
    /// reading a failed startup has to go on.
    #[test]
    fn an_unknown_ip_family_preference_is_rejected() {
        let err = toml::from_str::<Config>(
            r#"
            [server]
            listen = "127.0.0.1:4433"
            cert = "/tmp/c.pem"
            key = "/tmp/k.pem"
            [limits]
            ip_family_preference = "v4"
            "#,
        )
        .expect_err("an unknown preference must be rejected");
        assert!(err.to_string().contains("ip_family_preference"), "{err}");
    }

    #[test]
    fn port_zero_cannot_be_denied() {
        let err = parse("[security]\ndenied_ports = [25, 0]")
            .validate()
            .expect_err("must be rejected");
        assert!(
            err.to_string().contains("security.denied_ports[1]"),
            "{err}"
        );
    }

    /// The open-proxy warning is the single most important thing an operator can
    /// be told at startup, so it is asserted rather than assumed.
    #[test]
    fn an_empty_user_list_warns_about_being_an_open_proxy() {
        let warnings = parse("").warnings();
        assert!(
            warnings.iter().any(|w| w.contains("open proxy")),
            "{warnings:?}"
        );
    }

    #[test]
    fn configured_users_produce_no_open_proxy_warning() {
        let warnings = parse(
            r#"
            [auth]
            users = [{ username = "u", password = "p" }]
            "#,
        )
        .warnings();
        assert!(
            !warnings.iter().any(|w| w.contains("open proxy")),
            "{warnings:?}"
        );
    }

    #[test]
    fn risky_but_legal_settings_are_warned_about() {
        let cfg = parse(
            r#"
            [auth]
            users = [{ username = "u", password = "p" }]

            [limits]
            udp_session_timeout = 30
            connect_timeout = 0

            [security]
            allow_private_networks = true
            denied_ports = [25, 53]
            unanswered_packet_budget = 0

            [log]
            keylog = true
            "#,
        );

        let warnings = cfg.warnings();
        // One per risky setting, and nothing else.
        assert_eq!(warnings.len(), 6, "{warnings:?}");
        for expected in [
            "udp_session_timeout",
            "connect_timeout = 0",
            "allow_private_networks",
            "denied_ports contains 53",
            "unanswered_packet_budget",
            "log.keylog",
        ] {
            assert!(
                warnings.iter().any(|w| w.contains(expected)),
                "missing a warning about {expected}: {warnings:?}"
            );
        }
    }

    /// RFC 9298 §3.1 recommends two minutes, and a configuration that meets the
    /// recommendation exactly has nothing to be told about: 120 is the first
    /// value that draws no warning, 119 the last that does.
    #[test]
    fn the_udp_session_timeout_warning_stops_at_the_recommended_two_minutes() {
        let warned = parse("[limits]\nudp_session_timeout = 119").warnings();
        assert!(
            warned.iter().any(|w| w.contains("udp_session_timeout")),
            "{warned:?}"
        );

        let quiet = parse("[limits]\nudp_session_timeout = 120").warnings();
        assert!(
            !quiet.iter().any(|w| w.contains("udp_session_timeout")),
            "{quiet:?}"
        );
    }

    /// An unlimited retry budget is a warning about guessing configured
    /// credentials, so it belongs to a configuration that has some. With no
    /// users there is nothing to guess and no counter to exhaust, and repeating
    /// it under the open-proxy warning would only dilute that one.
    #[test]
    fn an_unlimited_auth_failure_budget_warns_only_where_there_are_credentials() {
        let with_users = parse(
            r#"
            [auth]
            users = [{ username = "u", password = "p" }]

            [security]
            max_auth_failures = 0
            "#,
        )
        .warnings();
        assert!(
            with_users.iter().any(|w| w.contains("max_auth_failures")),
            "{with_users:?}"
        );

        let without_users = parse("[security]\nmax_auth_failures = 0").warnings();
        assert!(
            !without_users
                .iter()
                .any(|w| w.contains("max_auth_failures")),
            "{without_users:?}"
        );
    }

    /// The shipped example configuration must stay in step with the code.
    ///
    /// `deny_unknown_fields` makes this a real test: a key renamed here without
    /// updating `script/config.example.toml`, or a typo introduced in the example,
    /// fails the build rather than the operator's first startup.
    #[test]
    fn the_shipped_example_configuration_is_valid() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/script/config.example.toml");
        let text = std::fs::read_to_string(path).expect("the example config must exist");

        let cfg: Config = toml::from_str(&text).expect("the example config must parse");
        assert_eq!(cfg.server.listen.port(), 443);
        assert_eq!(cfg.auth.users.len(), 1, "the example must show a user");
        assert_eq!(cfg.log.level, "info");

        // Everything except the certificate paths, which do not exist in a checkout,
        // must pass validation.
        let error = cfg
            .validate()
            .expect_err("the example points at paths that do not exist here")
            .to_string();
        assert!(
            error.contains("server.cert"),
            "the example must be valid apart from its certificate paths, got: {error}"
        );
    }

    /// Both socket buffer keys parse, and `0` is a legal value rather than a
    /// number to be validated away.
    ///
    /// `0` is the escape hatch that hands the size back to the operating system,
    /// so it has to survive parsing untouched; every other value is judged by the
    /// kernel at bind time and reported as a startup warning if it was capped,
    /// which is why there is no range check here to test.
    #[test]
    fn socket_buffer_sizes_parse_and_zero_is_accepted() {
        let cfg = parse("[limits]\nsocket_recv_buffer = 4194304\nsocket_send_buffer = 1048576");
        assert_eq!(cfg.limits.socket_recv_buffer, 4 * 1024 * 1024);
        assert_eq!(cfg.limits.socket_send_buffer, 1024 * 1024);
        assert_valid_apart_from_certs(&cfg, "explicit socket buffer sizes");

        let cfg = parse("[limits]\nsocket_recv_buffer = 0\nsocket_send_buffer = 0");
        assert_eq!(cfg.limits.socket_recv_buffer, 0);
        assert_eq!(cfg.limits.socket_send_buffer, 0);
        assert_valid_apart_from_certs(&cfg, "socket buffers left to the OS");
    }

    #[test]
    fn unknown_key_is_rejected() {
        let err = toml::from_str::<Config>(
            r#"
            [server]
            listen = "127.0.0.1:4433"
            cert = "/tmp/c.pem"
            key = "/tmp/k.pem"
            lisen = "typo"
            "#,
        )
        .expect_err("must reject unknown keys");
        assert!(err.to_string().contains("lisen"), "{err}");
    }

    #[test]
    fn bad_listen_address_names_the_field() {
        let err = toml::from_str::<Config>(
            r#"
            [server]
            listen = "not-an-address"
            cert = "/tmp/c.pem"
            key = "/tmp/k.pem"
            "#,
        )
        .expect_err("must reject a malformed listen address");
        assert!(err.to_string().contains("listen"), "{err}");
    }

    #[test]
    fn empty_alpn_is_rejected() {
        let cfg: Config = toml::from_str(
            r#"
            [server]
            listen = "127.0.0.1:4433"
            cert = "/tmp/c.pem"
            key = "/tmp/k.pem"
            alpn = []
            "#,
        )
        .expect("parses");
        let err = cfg.validate().expect_err("empty alpn must be rejected");
        assert!(err.to_string().contains("server.alpn"), "{err}");
    }

    /// An ALPN identifier is length-prefixed with a single byte, so 255 bytes is
    /// the longest one the wire format can count -- and the longest is legal.
    /// The first identifier that cannot be sent at all is the one after it.
    #[test]
    fn an_alpn_identifier_is_capped_at_what_its_length_prefix_can_count() {
        let cfg = parse(&format!("alpn = [\"{}\"]", "h".repeat(255)));
        assert_valid_apart_from_certs(&cfg, "an ALPN identifier of exactly 255 bytes");

        let err = parse(&format!("alpn = [\"{}\"]", "h".repeat(256)))
            .validate()
            .expect_err("an identifier past the length prefix must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("server.alpn[0]"), "{msg}");
        assert!(msg.contains("255"), "the limit must be named: {msg}");
    }

    #[test]
    fn missing_cert_file_is_reported_with_the_path() {
        let cfg: Config = toml::from_str(
            r#"
            [server]
            listen = "127.0.0.1:4433"
            cert = "/nonexistent/volto/cert.pem"
            key = "/nonexistent/volto/key.pem"
            "#,
        )
        .expect("parses");
        let err = cfg.validate().expect_err("missing cert must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("server.cert"), "{msg}");
        assert!(msg.contains("/nonexistent/volto/cert.pem"), "{msg}");
    }

    #[test]
    fn plain_log_levels_are_accepted() {
        for level in ["trace", "debug", "info", "warn", "error", "INFO"] {
            validate_log_level(level).unwrap_or_else(|e| panic!("{level} should be valid: {e}"));
        }
    }

    #[test]
    fn filter_directives_are_accepted() {
        validate_log_level("volto=debug,quinn=info").expect("directive list is valid");
    }

    #[test]
    fn a_level_typo_is_rejected_rather_than_silently_disabling_logs() {
        // EnvFilter would accept these as target names and then log nothing.
        for level in ["warning", "verbose", "definitely not a level"] {
            let err = validate_log_level(level).expect_err("{level} must be rejected");
            assert!(err.to_string().contains("log.level"), "{err}");
        }
    }

    #[test]
    fn a_malformed_filter_directive_is_rejected() {
        let err = validate_log_level("volto=notalevel").expect_err("must be rejected");
        assert!(err.to_string().contains("log.level"), "{err}");
    }

    /// `u64`s worth generating for a key whose accepted range ends at `edge`.
    ///
    /// A uniform `u64` would spend essentially every case in the astronomically
    /// invalid region, where each key's first range check answers and nothing
    /// downstream is ever reached; a uniform value inside the range would never
    /// reach the arithmetic that only the far end can break. So the mix is
    /// deliberate: values around the range, the exact boundaries, the halves of
    /// `u64` that a doubling straddles, and the whole domain.
    fn around(edge: u64) -> BoxedStrategy<u64> {
        prop_oneof![
            4 => 0..=edge.saturating_mul(2).max(4),
            3 => prop::sample::select(vec![
                0,
                1,
                edge.saturating_sub(1),
                edge,
                edge.saturating_add(1),
            ]),
            2 => prop::sample::select(vec![
                u64::MAX,
                u64::MAX - 1,
                u64::MAX / 2,
                u64::MAX / 2 + 1,
                1 << 62,
                1 << 63,
            ]),
            1 => any::<u64>(),
        ]
        .boxed()
    }

    /// [`Limits`] over the whole of every field's integer domain.
    ///
    /// Shared with the transport-config property in [`crate::quic`], which is
    /// the other half of the same invariant: this module decides what is
    /// accepted, that one has to build a `quinn::TransportConfig` out of
    /// everything that was.
    pub(crate) fn any_limits() -> impl Strategy<Value = Limits> {
        // Saturating rather than truncating, so that "absurdly large" stays
        // absurdly large in the narrower types instead of wrapping to something
        // ordinary.
        fn narrow_u32(value: u64) -> u32 {
            u32::try_from(value).unwrap_or(u32::MAX)
        }
        fn narrow_u16(value: u64) -> u16 {
            u16::try_from(value).unwrap_or(u16::MAX)
        }

        (
            (
                around(MAX_IDLE_TIMEOUT_CEILING),
                around(u64::from(MAX_TARGETS_PER_CONN_CEILING)),
                around(u64::from(DEFAULT_MAX_CONNECTIONS)),
                around(MAX_IDLE_TIMEOUT_CEILING),
                around(u64::from(MAX_STREAMS_BIDI_CEILING)),
                around(MAX_IDLE_TIMEOUT_CEILING),
                around(MAX_IDLE_TIMEOUT_CEILING / 2),
            ),
            (
                around(u64::from(MAX_INITIAL_MTU)),
                around(u64::from(MAX_MTU_UPPER_BOUND)),
                around(*INITIAL_RTT_RANGE_MS.end()),
                around(DEFAULT_SOCKET_RECV_BUFFER as u64),
                around(DEFAULT_SOCKET_SEND_BUFFER as u64),
                any::<bool>(),
                prop::sample::select(vec![
                    CongestionControl::Bbr,
                    CongestionControl::Cubic,
                    CongestionControl::NewReno,
                ]),
                prop::sample::select(vec![
                    IpFamilyPreference::Ipv4,
                    IpFamilyPreference::Ipv6,
                    IpFamilyPreference::System,
                ]),
            ),
        )
            .prop_map(
                |(
                    (
                        udp_session_timeout,
                        max_targets_per_conn,
                        max_connections,
                        connect_timeout,
                        max_streams_bidi,
                        max_idle_timeout,
                        keep_alive_interval,
                    ),
                    (
                        initial_mtu,
                        mtu_upper_bound,
                        initial_rtt_ms,
                        socket_recv_buffer,
                        socket_send_buffer,
                        mtu_discovery,
                        congestion_control,
                        ip_family_preference,
                    ),
                )| Limits {
                    udp_session_timeout,
                    max_targets_per_conn: narrow_u32(max_targets_per_conn),
                    max_connections: narrow_u32(max_connections),
                    connect_timeout,
                    ip_family_preference,
                    max_streams_bidi: narrow_u32(max_streams_bidi),
                    max_idle_timeout,
                    keep_alive_interval,
                    initial_mtu: narrow_u16(initial_mtu),
                    mtu_discovery,
                    mtu_upper_bound: narrow_u16(mtu_upper_bound),
                    congestion_control,
                    initial_rtt_ms,
                    socket_recv_buffer: usize::try_from(socket_recv_buffer).unwrap_or(usize::MAX),
                    socket_send_buffer: usize::try_from(socket_send_buffer).unwrap_or(usize::MAX),
                },
            )
    }

    /// [`Limits`] that [`Config::validate`] accepts.
    ///
    /// [`any_limits`] folded into the accepted space rather than filtered down
    /// to it: a filter would reject essentially every case, since a value is
    /// only legal when all ten of its independently generated fields are, while
    /// clamping maps the whole invalid region onto the boundaries — which is
    /// where a transport parameter is most likely to be the one that cannot be
    /// built. The folding is a second statement of the ranges `validate`
    /// enforces, so the property that uses it checks that claim rather than
    /// trusting it.
    pub(crate) fn valid_limits() -> impl Strategy<Value = Limits> {
        any_limits().prop_map(|limits| {
            let max_idle_timeout = limits.max_idle_timeout.clamp(1, MAX_IDLE_TIMEOUT_CEILING);
            // Strictly below half, and 0 is always legal: an idle timeout of 1
            // or 2 seconds leaves no interval that is.
            let half = max_idle_timeout.div_ceil(2);
            let keep_alive_interval = match (limits.keep_alive_interval, half) {
                (0, _) | (_, 0..=1) => 0,
                (interval, half) => 1 + interval % (half - 1),
            };
            let initial_mtu = limits.initial_mtu.clamp(MIN_INITIAL_MTU, MAX_INITIAL_MTU);

            Limits {
                udp_session_timeout: limits
                    .udp_session_timeout
                    .clamp(1, MAX_IDLE_TIMEOUT_CEILING),
                max_targets_per_conn: limits
                    .max_targets_per_conn
                    .clamp(1, MAX_TARGETS_PER_CONN_CEILING),
                connect_timeout: limits.connect_timeout.min(MAX_IDLE_TIMEOUT_CEILING),
                max_streams_bidi: limits.max_streams_bidi.clamp(1, MAX_STREAMS_BIDI_CEILING),
                max_idle_timeout,
                keep_alive_interval,
                initial_mtu,
                mtu_upper_bound: limits
                    .mtu_upper_bound
                    .clamp(initial_mtu, MAX_MTU_UPPER_BOUND),
                initial_rtt_ms: limits
                    .initial_rtt_ms
                    .clamp(*INITIAL_RTT_RANGE_MS.start(), *INITIAL_RTT_RANGE_MS.end()),
                // Unbounded by `validate` and left that way here: the socket
                // buffers are a request the kernel answers, and `max_connections`
                // = 0 means no cap at all.
                ..limits
            }
        })
    }

    /// A config carrying `limits`, with everything else at its default.
    ///
    /// Its certificate paths do not exist, so a config whose limits are all
    /// legal still fails validation on the certificate check — the last thing
    /// `validate` does, and hence the marker that everything before it passed.
    pub(crate) fn config_with(limits: Limits) -> Config {
        let mut config = parse("");
        config.limits = limits;
        config
    }

    /// Whether `validate` found nothing wrong except the missing certificates.
    pub(crate) fn valid_apart_from_certs(config: &Config) -> bool {
        match config.validate() {
            Ok(()) => true,
            Err(error) => {
                let message = error.to_string();
                message.contains("server.cert") || message.contains("server.key")
            }
        }
    }

    proptest! {
        /// Property 1: validation answers. It never panics (D86).
        ///
        /// Every integer here is reachable from the file — TOML deserializes
        /// across the whole of each target type — so a `u64` that breaks the
        /// arithmetic *inside* `validate` is an operator's typo turning startup
        /// into an abort, and a `SIGHUP` into one on a running server. The
        /// property is deliberately weak on purpose: `Ok` or `Err`, but a third
        /// outcome is not allowed to exist.
        #[test]
        fn validation_of_any_limits_answers_rather_than_panicking(limits in any_limits()) {
            let config = config_with(limits);
            let _ = config.validate();
            // The warnings run over the same values, and are rendered on the
            // startup path right after validation.
            let _ = config.warnings();
        }

        /// The rewritten keep-alive comparison is the doubling it replaced.
        ///
        /// Same accept/reject boundary for every pair of integers, computed in
        /// arithmetic wide enough to hold the product the check no longer takes
        /// (D86). The idle timeout is generated inside its own range so that
        /// this is the only check that can object.
        #[test]
        fn the_keep_alive_ratio_keeps_the_boundary_its_doubling_had(
            max_idle_timeout in 1..=MAX_IDLE_TIMEOUT_CEILING,
            keep_alive_interval in around(MAX_IDLE_TIMEOUT_CEILING / 2),
        ) {
            let limits = Limits {
                max_idle_timeout,
                keep_alive_interval,
                ..Limits::default()
            };

            let rejected = config_with(limits)
                .validate()
                .is_err_and(|error| error.to_string().contains("keep_alive_interval"));

            let doubling = keep_alive_interval > 0
                && u128::from(keep_alive_interval) * 2 >= u128::from(max_idle_timeout);

            prop_assert_eq!(rejected, doubling);
        }
    }
}
