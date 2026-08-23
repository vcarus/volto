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
//! shutdown_grace = 5   # seconds to let tunnels finish after SIGTERM
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
//! max_streams_bidi     = 1024
//! max_idle_timeout     = 60    # seconds
//! keep_alive_interval  = 20    # seconds, must be < max_idle_timeout / 2
//! initial_mtu          = 1200  # bytes, at least 1200
//! mtu_discovery        = true
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

/// Largest accepted `max_idle_timeout`, in seconds.
///
/// Not a protocol limit. Past an hour the value stops meaning anything: any relay's
/// conntrack entry will have expired long before, so a larger timeout only delays
/// noticing a peer that is already unreachable.
const MAX_IDLE_TIMEOUT_CEILING: u64 = 3600;

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
    /// Size of the first QUIC packets, in bytes. At least 1200.
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
    /// Seconds to let existing tunnels finish after SIGTERM.
    ///
    /// Zero closes everything at once. The wait ends early if all tunnels finish
    /// sooner, so a generous value costs nothing in the common case.
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
    /// A parse failure is rendered by [`parse_error`] rather than carried in the
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

        if self.limits.udp_session_timeout == 0 {
            bail!("limits.udp_session_timeout must be greater than zero");
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
        if self.limits.keep_alive_interval > 0
            && self.limits.keep_alive_interval * 2 >= self.limits.max_idle_timeout
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
                 recommends; long-lived UDP flows may be cut off",
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
/// rather than a copy of what was written.
fn parse_error(path: &Path, text: &str, error: &toml::de::Error) -> anyhow::Error {
    let Some(span) = error.span() else {
        return anyhow!(
            "failed to parse config file {}: {}",
            path.display(),
            error.message()
        );
    };

    let (line, column) = line_and_column(text, span.start);
    anyhow!(
        "failed to parse config file {} at line {line}, column {column}: {}",
        path.display(),
        error.message()
    )
}

/// The 1-based line and column of a byte offset into `text`.
///
/// The `toml` crate reports a span and renders the position itself, but only as
/// part of the caret block [`parse_error`] exists to avoid, so the arithmetic is
/// repeated here. Columns are counted in characters rather than bytes, which is
/// what an editor shows.
fn line_and_column(text: &str, offset: usize) -> (usize, usize) {
    // An offset past the end, or one landing inside a multi-byte character,
    // cannot be placed: the position is a convenience on the way to an error
    // message and must not become a panic of its own.
    let Some(before) = text.get(..offset) else {
        return (1, 1);
    };

    let line = before.matches('\n').count() + 1;
    let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;

    (line, column)
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
mod tests {
    use super::*;

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

    /// A syntax error must name where it is, and must not quote what is there.
    ///
    /// The `toml` crate renders a parse error as the offending source line under
    /// a caret, so a typo on a `password = ...` line used to print the password
    /// on stderr at startup and into the journal on every `SIGHUP` reload — and
    /// `Restart=on-failure` makes the startup path repeat every few seconds. The
    /// missing quotes below are that typo, and both renderings of an `anyhow`
    /// error are checked because the two print different things: `{:#}` walks
    /// the chain of messages, `{:?}` adds the sources and any backtrace.
    #[test]
    fn a_syntax_error_does_not_echo_the_line_it_is_on() {
        const SECRET: &str = "correct-horse-battery-staple";

        let path = std::env::temp_dir().join(format!(
            "volto-config-syntax-error-{}.toml",
            std::process::id()
        ));
        std::fs::write(
            &path,
            format!(
                "[server]\n\
                 listen = \"127.0.0.1:4433\"\n\
                 cert = \"/tmp/c.pem\"\n\
                 key = \"/tmp/k.pem\"\n\
                 [auth]\n\
                 users = [\n\
                 {{ username = \"user1\", password = {SECRET} }},\n\
                 ]\n"
            ),
        )
        .expect("write the broken config");

        let error = Config::load(&path).expect_err("an unquoted value must not load");
        let _ = std::fs::remove_file(&path);

        for rendered in [format!("{error:#}"), format!("{error:?}")] {
            assert!(
                !rendered.contains(SECRET),
                "the password on the offending line leaked: {rendered}"
            );
            assert!(
                rendered.contains("line 7"),
                "the operator still has to be told where the mistake is: {rendered}"
            );
        }
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

    #[test]
    fn a_zero_or_oversized_target_quota_is_rejected() {
        for value in ["0", "70000"] {
            let err = parse(&format!("[limits]\nmax_targets_per_conn = {value}"))
                .validate()
                .expect_err("must be rejected");
            assert!(err.to_string().contains("max_targets_per_conn"), "{err}");
        }
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

        // The floor itself and above it are accepted.
        for value in [1200, 1500, 9000] {
            let cfg = parse(&format!("[limits]\ninitial_mtu = {value}"));
            assert_valid_apart_from_certs(&cfg, &format!("initial_mtu = {value}"));
        }
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
}
