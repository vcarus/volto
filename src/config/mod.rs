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
//! mtu_upper_bound      = 1436  # bytes, initial_mtu..1472
//! congestion_control   = "bbr" # bbr | bbr-uncapped | cubic | newreno
//! initial_rtt_ms       = 333   # milliseconds, 10..10000
//! socket_recv_buffer   = 2097152 # bytes, 0 keeps the OS default
//! socket_send_buffer   = 2097152 # bytes, 0 keeps the OS default
//!
//! [security]
//! allow_private_networks   = false
//! denied_ports             = [25]
//! unanswered_packet_budget = 64
//! max_auth_failures        = 5
//! expected_sni             = []   # non-empty turns the SNI gate on
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
//!
//! Rejecting unknown keys also makes a configuration file forward-only: one
//! written for this version does not load on a release that predates any key in
//! it, so the file has to be edited before a rollback rather than after the
//! service fails to start. `docs/configuration.md` carries the operator's half
//! of that (which key arrived in which release, and why the policy stays).

mod parse_error;
mod validate;
mod warnings;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use parse_error::parse_error;

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
/// purpose. A client that keeps using a connection after GOAWAY instead of
/// opening a fresh one (the Surge client does) has every new request fail for
/// as long as the drain lasts. So the grace period is also a window of failed
/// requests on the client, and it only helps transfers that are already
/// running. Five seconds keeps that window short and still lets short
/// exchanges complete. It is well below a service manager's own kill timeout
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
/// unreachable target holds them for as long as the operating system waits on a
/// SYN that draws no answer. On Linux that is roughly two minutes, long enough
/// for ordinary browsing to a black-holed address to exhaust
/// `max_targets_per_conn` on its own.
///
/// Ten seconds is well past a healthy connect on any path this proxy serves (the
/// production RTT is under 100 ms) and short enough that one dead target does
/// not consume a client's budget. Zero removes the bound and leaves the wait to
/// the operating system.
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
/// Deliberately longer than a typical relay's 30s UDP conntrack entry, so that
/// the keep-alive below, not the timeout, keeps the connection live.
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
/// IPv4's extra 20 bytes. Discovery reaches a size only after a probe of it is
/// acknowledged, and the black-hole detector takes the size back down when
/// traffic at it is lost. This value is sent blind in the handshake, and the
/// next paragraph says what a wrong value costs here.
///
/// There is no floor to fall back to if this is wrong. quinn applies the value
/// with a `max()` against the 1200-byte minimum and no `min()` above it, so the
/// handshake flight goes out in packets the path drops and the server is
/// unreachable. Its black-hole detector does not help either: it runs inside an
/// established connection, and with this wrong there is never one. A reload
/// applies the value to connections accepted from then on, which is why the
/// mistake is rejected rather than tolerated: a `SIGHUP` with a typo here
/// leaves a server that still answers `systemctl status` and nothing else.
pub const MAX_INITIAL_MTU: u16 = 1452;

/// Default ceiling for path MTU discovery, in bytes.
///
/// Below quinn's own default of 1452, which quinn-proto 0.11.x
/// `src/config/transport.rs`, `MtuDiscoveryConfig::upper_bound`, chooses "to
/// stay within Ethernet's MTU when using IPv4 and IPv6": 1500 minus IPv6's
/// 40-byte header and UDP's 8. The same doc comment says "It is safe to use an
/// arbitrarily high upper bound, regardless of the network path's MTU". That
/// holds only on a path that drops a packet it cannot carry.
///
/// A probe that is acknowledged does not show that the path carries that size
/// under load. On a measured relay path, IPv4 packets above 1464 bytes (UDP
/// payload above 1436) arrived with DF cleared. Single probes of those sizes got
/// through, so discovery adopted them, and at bulk rate those packets were lost
/// at 62 to 89 percent until the black-hole detector dropped the size to 1200.
/// After the detector's cooldown the same probe succeeded again. 1436 is the
/// largest UDP payload whose IPv4 packet (1464 bytes) crossed that path with DF
/// set (D81).
///
/// Over IPv6 the 1452 reasoning still holds, and 1436 is below 1452, so the
/// default is safe on either family.
pub const DEFAULT_MTU_UPPER_BOUND: u16 = 1436;

/// The largest `mtu_upper_bound` this server accepts, in bytes.
///
/// Ethernet's 1500 minus IPv4's 20-byte header and UDP's 8. Nothing on a
/// standard internet path carries more than that, so a higher bound could only
/// spend probes on sizes that cannot exist. The ceiling being *above*
/// [`MAX_INITIAL_MTU`] is deliberate, not an inconsistency. Discovery only ever
/// reaches a size by probing it. A lost probe is retried, then abandoned, and is
/// never treated as congestion, and the black-hole detector takes an adopted
/// size back down when traffic at it is lost. `initial_mtu` is sent blind in the
/// handshake with no recovery path (see [`MAX_INITIAL_MTU`]). An upper bound the
/// path cannot carry costs failed probes, or, on a path that delivers single
/// probes at a size it cannot carry under load, lost traffic until the detector
/// fires (see [`DEFAULT_MTU_UPPER_BOUND`]). An initial the path cannot carry
/// makes the server unreachable.
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
/// For the two application timers it is also a safety bound. They are plain
/// `u64`s added to `Instant::now()` to make deadlines, and an absurd number of
/// seconds would panic that addition. The ceiling keeps every such sum far from
/// the edge.
const MAX_IDLE_TIMEOUT_CEILING: u64 = 3600;

/// Largest accepted `shutdown_grace`, in seconds.
///
/// The same number as [`MAX_IDLE_TIMEOUT_CEILING`], for half of the same
/// reason: past an hour a wait stops describing anything anybody observes, and
/// a drain that long exceeds any service manager's stop timeout (systemd's
/// default `TimeoutStopSec` is 90 seconds).
///
/// The other half is this key's own, and it is the opposite of the timers'.
/// A grace period that cannot be added to `Instant::now()` does not panic:
/// `tokio::time::timeout` turns a duration it cannot add into a deadline in the
/// far future, so an absurd `u64` of seconds fails quietly. That removes the
/// bound `crate::quic`'s drain is built around, and the process waits on
/// connections that may never end until a `SIGKILL` arrives, which is the
/// ungraceful ending the grace period exists to avoid. Bounding the key keeps
/// that state unreachable.
const MAX_SHUTDOWN_GRACE: u64 = MAX_IDLE_TIMEOUT_CEILING;

/// Default UDP socket receive buffer to request, in bytes.
///
/// Not a size that arrives on its own. quinn never calls
/// `setsockopt(SO_RCVBUF)`, so a QUIC server that does not ask keeps what the
/// kernel hands out: `net.core.rmem_default`, around 208 KiB on a stock Linux.
/// That holds however high `net.core.rmem_max` has been raised, because that
/// sysctl is only a ceiling on what an application may *request*, not an
/// allocation.
///
/// Like the per-stream flow-control window in [`crate::quic`], 2 MiB costs
/// nothing until a burst needs it. The bursts it covers are ordinary ones: a
/// batch of packets arriving while the read loop is elsewhere, a GSO segment
/// train, a scheduling delay. Without it such a burst is dropped silently. The
/// kernel counts the drop as `receive buffer errors` in `netstat -su`, and the
/// sender has to retransmit.
///
/// Requested when the socket is created, so this is a startup-only setting.
/// Zero leaves the operating system's own value alone.
pub const DEFAULT_SOCKET_RECV_BUFFER: usize = 2 * 1024 * 1024;

/// Default UDP socket send buffer to request, in bytes.
///
/// The send side of [`DEFAULT_SOCKET_RECV_BUFFER`]: capped by
/// `net.core.wmem_max` rather than `rmem_max`, and drained by the network
/// interface rather than by this process. It matters on the same bursts, with a
/// milder result. When the endpoint hands the kernel more at once than the
/// buffer holds, the send returns `EAGAIN` and quinn holds the packet until the
/// socket drains. That is a stall rather than a drop, though the kernel still
/// counts each one as a `send buffer error` in `netstat -su`.
///
/// Requested when the socket is created, so this is a startup-only setting.
/// Zero leaves the operating system's own value alone.
pub const DEFAULT_SOCKET_SEND_BUFFER: usize = 2 * 1024 * 1024;

/// The largest socket buffer size this server accepts, in bytes.
///
/// `socket2` passes the value to `setsockopt` as a `c_int`, so a number above
/// `i32::MAX` is truncated before the kernel sees it: 4294967296 becomes 0 and
/// leaves the buffer at the operating system's minimum, and 3000000000 becomes
/// a negative integer the kernel clamps. [`Config::validate`] rejects both
/// socket buffer keys above this instead, naming the API limit, so a typo cannot
/// silently become a different number. `0` still leaves the socket alone.
#[allow(clippy::as_conversions)]
pub const MAX_SOCKET_BUFFER: usize = i32::MAX as usize;

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

/// The password `script/config.example.toml` ships, which no running server may
/// keep.
///
/// The example is what `script/install-selfsigned.sh` copies into place and what
/// the manual install in `docs/deployment.md` starts from, and the ACME section
/// of that page leaves the certificate at the paths the example already names.
/// So an unedited copy is a configuration a server starts on, and this password
/// is published in the repository. [`Config::warnings`] reports it, the
/// installer refuses to install a file that still carries it, and
/// `config::tests::the_shipped_example_configuration_is_valid` pins that this is
/// the string the example holds, so the two cannot drift apart. The installer's
/// own copy of the string is pinned to this constant by
/// `it_installer::the_placeholder_password_never_survives`.
pub const EXAMPLE_PLACEHOLDER_PASSWORD: &str = "replace-me-with-something-long";

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

/// `[auth]`: the accepted credentials.
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
/// long, often lossy international paths. A loss-based controller reads the
/// non-congestive packet loss of those paths as congestion and keeps the window
/// from opening, and the download direction falls to near zero. BBR models
/// bottleneck bandwidth and RTT instead of reacting to loss, so it holds
/// throughput where CUBIC and NewReno stall, matching what the Linux kernel does
/// for TCP with `net.ipv4.tcp_congestion_control = bbr`.
///
/// The value `bbr` selects quinn's BBR with its window capped
/// ([`crate::congestion`], D108), because quinn's BBR overestimates the
/// bottleneck and loses the difference on a bulk download. The capped
/// controller has the plain name so that a file that writes `bbr`, or leaves
/// the key out, gets it without an edit. quinn's controller as it ships is
/// selectable as `bbr-uncapped`.
///
/// The other controllers are kept as a fallback: quinn's BBR is a port marked
/// "experimental", so an operator who hits trouble after a dependency bump can
/// switch without recompiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CongestionControl {
    /// quinn's BBR with its window capped at 1.25 times the measured
    /// bandwidth-delay product; see [`crate::congestion`]. The default.
    Bbr,
    /// quinn's BBR as it ships (its experimental port of BBRv1), without the
    /// cap.
    #[serde(rename = "bbr-uncapped")]
    BbrUncapped,
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
/// back. `getaddrinfo` (glibc and musl alike) orders its answers by RFC 6724,
/// and that ordering puts a global IPv6 address ahead of every IPv4 one whenever
/// the host has a usable IPv6 route. On a host that is only a client of the
/// internet that is the right answer. On a proxy it is an operator policy made
/// by the resolver. A host whose IPv6 egress is tunnelled, or otherwise weaker
/// than its native IPv4 (a common shape on a VPS), would send every dual-stack
/// target down the weaker path first. For a TCP tunnel that costs the whole
/// IPv6 attempt before IPv4 is tried, because [`crate::tunnel::tcp`] walks the
/// address list in order. For a CONNECT-UDP session the choice is final,
/// because its socket is connected to the first address that has a route and
/// there is no failover behind that choice.
///
/// [`System`](Self::System) keeps RFC 6724 ordering, which on glibc an operator
/// can shape further through `gai.conf`. shadowsocks-rust carries the same
/// choice as `ipv6_first`, likewise off by default.
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

/// `[limits]`: resource and lifetime limits.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Seconds a UDP session may sit idle before it is closed.
    ///
    /// It bounds the TCP path too, despite the name: once one direction of a
    /// TCP tunnel has ended cleanly, each write in the surviving direction has
    /// this long to complete, which is the only thing keeping a half-closed
    /// tunnel from holding its socket and its slot for as long as the QUIC
    /// connection lasts (`tunnel::tcp` module docs). Both uses reach the tunnel
    /// as [`crate::tunnel::Context::stall_budget`]. The name is the CONNECT-UDP
    /// half alone because it is the older one and a configuration key cannot be
    /// renamed without breaking every deployed config file.
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
    /// Concurrent client-initiated bidirectional streams per QUIC connection,
    /// once a request on it has passed the credentials check.
    ///
    /// Not what the handshake advertises: a connection is accepted on the
    /// smaller `quic::INITIAL_BIDI_STREAMS` and raised to this by its first
    /// authenticated request, so an unauthenticated peer is never worth the
    /// configured value.
    ///
    /// Between 1 and 65536. The ceiling is not a formality: the credit is
    /// reserved slot by slot when the allowance is granted rather than when a
    /// stream is opened, so the whole allowance is paid for at once, at the
    /// connection's first authenticated request.
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
    /// `initial_mtu` and are never probed larger. It is not a hard pin, though.
    /// quinn's black-hole detector still runs, and if it fires it drops the packet
    /// size to the 1200-byte floor for the rest of the connection, with nothing
    /// left to probe it back up. Trades throughput for predictability on a path
    /// that black-holes large packets.
    pub mtu_discovery: bool,
    /// Ceiling for path MTU discovery, in bytes. Between `initial_mtu` and 1472.
    ///
    /// A UDP payload size like `initial_mtu`. The default of 1436 is below
    /// quinn's 1452 because an acknowledged probe does not show that the path
    /// carries that size under load; [`DEFAULT_MTU_UPPER_BOUND`] gives the
    /// measurement. An operator who has measured their own path at bulk rate
    /// can raise it, at most to 1472. Moot when `mtu_discovery` is off, which is
    /// warned about rather than rejected. See [`MAX_MTU_UPPER_BOUND`].
    ///
    /// `None` when the key is absent, which is what lets an absent ceiling
    /// follow `initial_mtu` up while a written one is checked exactly. Read the
    /// ceiling in effect through [`Limits::mtu_upper_bound`].
    pub mtu_upper_bound: Option<u16>,
    /// QUIC congestion controller. Defaults to `bbr`, quinn's BBR with its
    /// window capped; see [`CongestionControl`].
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
    /// needs a restart. That is the same class as [`Server::listen`], unlike
    /// every key above it. A reload carrying a different value is accepted,
    /// applies nothing, and says so, exactly as one carrying a different
    /// `listen` does.
    ///
    /// Two things the kernel does with the request are worth knowing before
    /// reading a log line about it. It is capped at a host ceiling
    /// (`net.core.rmem_max` on Linux, `kern.ipc.maxsockbuf` on macOS), and a
    /// host may fail the call outright instead of clamping. And on Linux the value
    /// read back is *double* what was granted, because the accounting includes
    /// per-packet overhead, so a satisfied 2 MiB request reads as 4194304 both
    /// here and in `ss -uanpm`. Either way the endpoint still comes up, and volto
    /// warns at startup when it got less than it asked for. See
    /// [`DEFAULT_SOCKET_RECV_BUFFER`].
    ///
    /// The socket API takes a signed 32-bit integer, so this key is limited to
    /// [`MAX_SOCKET_BUFFER`] = `i32::MAX`; a larger value is refused at load
    /// time rather than truncated to a different number on its way to the
    /// kernel. `0` still leaves the socket on the operating system's own value.
    pub socket_recv_buffer: usize,
    /// UDP socket send buffer to request, in bytes. Zero keeps the OS default.
    ///
    /// Startup-only, read back and warned about exactly like
    /// [`Limits::socket_recv_buffer`]; the ceiling on this side is
    /// `net.core.wmem_max`. Range-checked to `0..=`[`MAX_SOCKET_BUFFER`] for the
    /// same reason as the receive side: the socket API's argument is a signed
    /// 32-bit integer. See [`DEFAULT_SOCKET_SEND_BUFFER`].
    pub socket_send_buffer: usize,
}

/// `[security]`: destination policy and abuse mitigations.
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
    /// Host names this server answers to, or an empty list to answer to any.
    ///
    /// Empty is the default: the name a client asks for is logged and otherwise
    /// ignored. A non-empty
    /// list turns on the SNI gate (D106): a handshake whose ClientHello does not
    /// name one of these hosts is dropped at the socket, before quinn sees it,
    /// so a port scan of this address gets no answer at all. See
    /// [`crate::gate`] for what that covers and what it does not.
    pub expected_sni: Vec<String>,
}

/// `[server]`: the QUIC listener and its TLS identity.
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
    /// sooner, so a generous value costs nothing in the common case. It is still
    /// a bound, which is why it has a ceiling of its own.
    #[serde(default = "default_shutdown_grace")]
    pub shutdown_grace: u64,
}

/// `[log]`: logging settings.
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
            mtu_upper_bound: None,
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
            expected_sni: Vec::new(),
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

    /// The path MTU discovery ceiling in effect, in bytes.
    ///
    /// A ceiling the file sets is used as written; `validate` has already held
    /// it to `initial_mtu..=`[`MAX_MTU_UPPER_BOUND`]. An absent one is
    /// [`DEFAULT_MTU_UPPER_BOUND`], raised to `initial_mtu` when that is larger.
    /// The raise exists because the default (1436) is below
    /// [`MAX_INITIAL_MTU`] (1452): a file may set `initial_mtu` anywhere up to
    /// 1452 and no ceiling, and it has to load. quinn would raise a ceiling
    /// below the starting size to that size on its own; this makes the same
    /// value explicit, so the transport and the logs see the ceiling that is
    /// actually used.
    pub fn mtu_upper_bound(&self) -> u16 {
        self.mtu_upper_bound
            .unwrap_or_else(|| DEFAULT_MTU_UPPER_BOUND.max(self.initial_mtu))
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
}

/// Upper bound on `limits.max_targets_per_conn`.
///
/// Not a protocol limit but a sanity limit. A value beyond this cannot be backed by
/// file descriptors on any realistic host, so it is more likely a typo.
const MAX_TARGETS_PER_CONN_CEILING: u32 = 65_536;

/// Upper bound on `limits.max_streams_bidi`.
///
/// The same number as [`MAX_TARGETS_PER_CONN_CEILING`], because one tunnel is
/// one stream: credit past the ceiling on tunnels could not carry one anyway.
///
/// It is rejected rather than tolerated because of where the cost is paid.
/// quinn does not allocate a stream when one is opened: `StreamsState` reserves
/// a slot for every unit of the credit when the allowance is granted, once per
/// connection at its first authenticated request. The cost grows with the
/// credit. D86 measured it on the dev host, when it was paid per handshake:
/// about 11 ms at the default of 1024, 135 ms at this ceiling, 7.3 s at a
/// million, and no completed handshake within ten seconds at four million.
/// `u32::MAX`, which a config file can hold, is a thousand times more again. A
/// typo here gives every connection's first request a stall, the same kind of
/// self-inflicted outage `MAX_INITIAL_MTU` is written against.
const MAX_STREAMS_BIDI_CEILING: u32 = MAX_TARGETS_PER_CONN_CEILING;

/// The longest host name a `server_name` extension can carry, in bytes.
///
/// A fully qualified DNS name is at most 255 bytes on the wire, of which two are
/// the root label's length byte and the trailing zero, leaving 253 for the
/// presentation form. A configured name longer than that could never be matched,
/// because no client could have asked for it.
pub const MAX_EXPECTED_SNI: usize = 253;

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

    use std::collections::{BTreeMap, BTreeSet};

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
            u64::from(cfg.limits.max_connections) * u64::from(cfg.limits.max_targets_per_conn),
            65536
        );
        assert_eq!(cfg.limits.max_idle_timeout, 60);
        assert_eq!(cfg.limits.keep_alive_interval, 20);
        assert_eq!(cfg.limits.initial_mtu, 1200);
        assert!(cfg.limits.mtu_discovery);
        // Below quinn's 1452: the largest size a measured relay path carried
        // with DF set (D81). Raising it is a per-path measurement, not a default.
        // Absent from the file, so the field is `None` and the accessor answers.
        assert_eq!(cfg.limits.mtu_upper_bound, None);
        assert_eq!(cfg.limits.mtu_upper_bound(), 1436);
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
        // The SNI gate is off, which is what makes an absent key change nothing.
        assert!(cfg.security.expected_sni.is_empty());

        // No users at all is legal and means "no authentication".
        assert!(cfg.auth.users.is_empty());
    }

    /// A minimal helper: the parsed config for `body`, with cert paths that exist
    /// left out (so only `body` is under test).
    pub(super) fn parse(body: &str) -> Config {
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
    pub(super) fn assert_valid_apart_from_certs(cfg: &Config, context: &str) {
        assert!(
            valid_apart_from_certs(cfg),
            "{context} should be valid, but: {}",
            cfg.validate()
                .expect_err("only a complaint can make the predicate false")
        );
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

    #[test]
    fn congestion_control_is_selectable_and_defaults_to_bbr() {
        assert_eq!(
            parse("").limits.congestion_control,
            CongestionControl::Bbr,
            "the default must be BBR"
        );
        for (value, expected) in [
            ("bbr", CongestionControl::Bbr),
            ("bbr-uncapped", CongestionControl::BbrUncapped),
            ("cubic", CongestionControl::Cubic),
            ("newreno", CongestionControl::NewReno),
        ] {
            let cfg = parse(&format!("[limits]\ncongestion_control = \"{value}\""));
            assert_eq!(cfg.limits.congestion_control, expected, "{value}");
            assert_valid_apart_from_certs(&cfg, value);
        }
    }

    /// `bbr-capped`, the name the capped controller had in v1.1.0 and v1.1.1
    /// and an alias of `bbr` in 1.2.0, is not accepted since 1.3.0 (D108, user
    /// ruling 2026-10-03). The refusal names the accepted values, so the fix
    /// for a 1.1.x file is in the message.
    #[test]
    fn bbr_capped_is_no_longer_accepted() {
        let err = toml::from_str::<Config>(
            r#"
            [server]
            listen = "127.0.0.1:4433"
            cert = "/tmp/c.pem"
            key = "/tmp/k.pem"
            [limits]
            congestion_control = "bbr-capped"
            "#,
        )
        .expect_err("the 1.1.x alias must be refused")
        .to_string();
        assert!(err.contains("bbr-capped"), "{err}");
        assert!(err.contains("`bbr`"), "{err}");
        assert!(err.contains("bbr-uncapped"), "{err}");
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

    /// The shipped example configuration must stay in step with the code.
    ///
    /// `deny_unknown_fields` makes this a real test: a key renamed here without
    /// updating `script/config.example.toml`, or a typo introduced in the example,
    /// fails the build rather than the operator's first startup.
    #[test]
    fn the_shipped_example_configuration_is_valid() {
        let text = example_text();

        let cfg: Config = toml::from_str(&text).expect("the example config must parse");
        assert_eq!(cfg.server.listen.port(), 443);
        assert_eq!(cfg.auth.users.len(), 1, "the example must show a user");
        assert_eq!(
            cfg.auth.users[0].password, EXAMPLE_PLACEHOLDER_PASSWORD,
            "the example's password is the string `Config::warnings` looks for and the \
             installer refuses; changing one without the other leaves both silent"
        );
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

    /// The shipped example configuration, as text.
    fn example_text() -> String {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/script/config.example.toml");
        std::fs::read_to_string(path).expect("the example config must exist")
    }

    /// The key a line assigns, if it is a top-level assignment.
    ///
    /// Column zero and a bare `lower_snake` identifier, which is what keeps the
    /// `# { username = "user2", ... }` inside the example's `users` array --
    /// indented, and inside a value besides -- from being read as a key of the
    /// table it sits in.
    fn assigned_key(line: &str) -> Option<&str> {
        let (name, _) = line.split_once(" = ")?;
        let plausible =
            !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c == '_');
        plausible.then_some(name)
    }

    /// Every key the example must document, section by section.
    ///
    /// The exhaustive destructuring in [`the_example_documents_every_key_and_pins_every_default`]
    /// is what keeps this list honest in one direction: a field added to
    /// `Limits`, `Security`, `Log` or `Server` stops that test compiling until it
    /// is named and answered there, and this is the half a value assertion cannot
    /// do -- a key left out of the example parses to exactly the default the
    /// assertion is comparing against, so only the key set can catch it.
    /// `deny_unknown_fields` covers the other direction.
    ///
    /// `[auth]` is not here: `users` is the operator's own and has no default.
    const DOCUMENTED_KEYS: [(&str, &[&str]); 4] = [
        (
            "server",
            &["listen", "cert", "key", "alpn", "shutdown_grace"],
        ),
        (
            "limits",
            &[
                "udp_session_timeout",
                "max_targets_per_conn",
                "max_connections",
                "connect_timeout",
                "ip_family_preference",
                "max_streams_bidi",
                "max_idle_timeout",
                "keep_alive_interval",
                "initial_mtu",
                "mtu_discovery",
                "mtu_upper_bound",
                "congestion_control",
                "initial_rtt_ms",
                "socket_recv_buffer",
                "socket_send_buffer",
            ],
        ),
        (
            "security",
            &[
                "allow_private_networks",
                "denied_ports",
                "unanswered_packet_budget",
                "max_auth_failures",
                "expected_sni",
            ],
        ),
        ("log", &["level", "keylog"]),
    ];

    /// The example with every commented-out key uncommented, and the keys it
    /// documents in each section.
    ///
    /// The file writes an optional key as `#key = value` -- the `#` hard against
    /// the key -- and prose as `# sentence`, with a space. That whole convention
    /// is one character wide, so it is checked rather than trusted: a `#`
    /// followed by anything that is not a space and not an assignment panics
    /// here, instead of quietly leaving a key commented out and letting the
    /// default it was supposed to pin answer for itself.
    fn example_with_every_key_uncommented() -> (String, BTreeMap<String, BTreeSet<String>>) {
        let mut uncommented = String::new();
        let mut documented: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut section = String::new();

        for line in example_text().lines() {
            let code = match line.strip_prefix('#') {
                Some(rest) if rest.starts_with(' ') || rest.is_empty() => line,
                Some(rest) => {
                    assert!(
                        assigned_key(rest).is_some(),
                        "script/config.example.toml writes an optional key as \
                         `#key = value` and prose as `# sentence`; this line is \
                         neither: {line}"
                    );
                    rest
                }
                None => line,
            };

            if let Some(name) = code.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
                section = name.to_owned();
            } else if let Some(key) = assigned_key(code) {
                documented
                    .entry(section.clone())
                    .or_default()
                    .insert(key.to_owned());
            }

            uncommented.push_str(code);
            uncommented.push('\n');
        }

        (uncommented, documented)
    }

    /// Uncommented, the example is the defaults key for key -- apart from two
    /// values it deliberately raises.
    ///
    /// [`the_shipped_example_configuration_is_valid`] proves the file parses,
    /// which is a weaker claim than it looks: `Limits`, `Security` and `Log` all
    /// carry a container-level `#[serde(default)]`, so a key dropped from the
    /// example and a `DEFAULT_*` moved under it both leave that test green. What
    /// this one pins is the documentation itself. Every `# Default: N` in the
    /// file is a promise to the operator reading it, and the value beside the key
    /// is what that operator uncomments and gets.
    ///
    /// The file ships three keys uncommented. Two are its own deviations, for the
    /// reasons it gives beside them:
    ///
    /// * `initial_mtu = 1242`, which "keeps the handshake inside a 1270-byte IPv4
    ///   packet -- under the 1280 bytes any practical path carries", against a
    ///   program default of 1200 the file calls "the conservative" one.
    /// * `initial_rtt_ms = 150`, "sized with margin for the ~60-100 ms long-haul
    ///   paths a fronted deployment typically serves", cutting "the worst-case
    ///   handshake stall from ~1 s to a few hundred ms", against RFC 9002's
    ///   conservative 333.
    ///
    /// The third, `mtu_upper_bound = 1436`, is live and equal to the default. From
    /// v0.4.5 to v1.1.1 the file shipped 1464 against a program default of 1452.
    /// On a measured relay path, packets above 1436 bytes of UDP payload were
    /// delivered with DF cleared and lost at bulk rate, so the example and the
    /// default moved to 1436 together (D81). It stays a live key so that the
    /// installed file states the ceiling.
    ///
    /// Listing them is what stops a fourth arriving quietly. Every other field is
    /// asserted equal to its default, each deviation is asserted to still *be* a
    /// deviation, and the live key at its default is asserted to stay equal to
    /// it. A default moved onto a deviation, or away from the live key, fails
    /// here rather than silently making the paragraphs above untrue.
    #[test]
    fn the_example_documents_every_key_and_pins_every_default() {
        let (text, documented) = example_with_every_key_uncommented();

        for (section, keys) in DOCUMENTED_KEYS {
            let found = documented
                .get(section)
                .unwrap_or_else(|| panic!("the example must have a [{section}] section"));
            let expected: BTreeSet<String> = keys.iter().map(|key| (*key).to_owned()).collect();
            assert_eq!(
                found, &expected,
                "[{section}] in script/config.example.toml documents the wrong set of keys"
            );
        }

        let cfg: Config =
            toml::from_str(&text).expect("the example with every key uncommented must still parse");
        assert_valid_apart_from_certs(&cfg, "the example with every key uncommented");

        // Destructured rather than read field by field: this is what stops
        // compiling when a field is added, which is the only thing that can force
        // a new key to be documented above and answered here.
        let Limits {
            udp_session_timeout,
            max_targets_per_conn,
            max_connections,
            connect_timeout,
            ip_family_preference,
            max_streams_bidi,
            max_idle_timeout,
            keep_alive_interval,
            initial_mtu,
            mtu_discovery,
            mtu_upper_bound,
            congestion_control,
            initial_rtt_ms,
            socket_recv_buffer,
            socket_send_buffer,
        } = cfg.limits.clone();
        let limits = Limits::default();

        assert_eq!(udp_session_timeout, limits.udp_session_timeout);
        assert_eq!(max_targets_per_conn, limits.max_targets_per_conn);
        assert_eq!(max_connections, limits.max_connections);
        assert_eq!(connect_timeout, limits.connect_timeout);
        assert_eq!(ip_family_preference, limits.ip_family_preference);
        assert_eq!(max_streams_bidi, limits.max_streams_bidi);
        assert_eq!(max_idle_timeout, limits.max_idle_timeout);
        assert_eq!(keep_alive_interval, limits.keep_alive_interval);
        assert_eq!(mtu_discovery, limits.mtu_discovery);
        assert_eq!(congestion_control, limits.congestion_control);
        assert_eq!(socket_recv_buffer, limits.socket_recv_buffer);
        assert_eq!(socket_send_buffer, limits.socket_send_buffer);

        // The two deviations, each still a deviation.
        assert_eq!(initial_mtu, 1242);
        assert_ne!(initial_mtu, DEFAULT_INITIAL_MTU);
        assert_eq!(initial_rtt_ms, 150);
        assert_ne!(initial_rtt_ms, DEFAULT_INITIAL_RTT_MS);

        // The live key at its default, still at its default.
        assert_eq!(mtu_upper_bound, Some(1436));
        assert_eq!(mtu_upper_bound, Some(DEFAULT_MTU_UPPER_BOUND));

        let Security {
            allow_private_networks,
            denied_ports,
            unanswered_packet_budget,
            max_auth_failures,
            expected_sni,
        } = cfg.security.clone();
        let security = Security::default();

        assert_eq!(allow_private_networks, security.allow_private_networks);
        assert_eq!(denied_ports, security.denied_ports);
        assert_eq!(unanswered_packet_budget, security.unanswered_packet_budget);
        assert_eq!(max_auth_failures, security.max_auth_failures);
        assert_eq!(expected_sni, security.expected_sni);

        let Log { level, keylog } = cfg.log.clone();
        let log = Log::default();

        assert_eq!(level, log.level);
        assert_eq!(keylog, log.keylog);

        // `listen`, `cert` and `key` are the operator's own and have no default
        // to be compared against; the other two `[server]` keys do.
        let Server {
            listen: _,
            cert: _,
            key: _,
            alpn,
            shutdown_grace,
        } = cfg.server.clone();

        assert_eq!(alpn, default_alpn());
        assert_eq!(shutdown_grace, DEFAULT_SHUTDOWN_GRACE);
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

    /// The rejection is the policy of *every* table, not a property of
    /// `[server]`.
    ///
    /// It is enforced by a `deny_unknown_fields` attribute repeated on each
    /// struct, so it holds only for as long as nobody adds a table without one,
    /// and the file that would silently change meaning is `[auth]`: with the
    /// attribute missing there, `uesrs = [...]` deserializes to an empty user
    /// list, and an empty user list is an open proxy. Every other table's typo
    /// falls back to a default that is merely wrong. That asymmetry is why this
    /// is worth a test rather than a review note, and it is also the argument
    /// against relaxing the policy to make rollback easier — see
    /// [`a_config_that_names_a_key_from_the_future_is_refused_whole`].
    #[test]
    fn every_table_rejects_unknown_keys() {
        // Whole documents rather than fragments appended to a `[server]` table:
        // a bare key written after one lands *inside* it, so a fragment could
        // only ever exercise `Server`'s attribute however it was spelled.
        const SERVER: &str = "[server]\n\
                              listen = \"127.0.0.1:4433\"\n\
                              cert = \"/tmp/c.pem\"\n\
                              key = \"/tmp/k.pem\"\n";

        // One unknown key per table, each spelled as a plausible typo or as
        // something a later release might add.
        for (table, text) in [
            ("top level (key)", format!("stray_key = 1\n{SERVER}")),
            (
                "top level (table)",
                format!("{SERVER}\n[metrics]\nlisten = \"\""),
            ),
            ("[server]", format!("{SERVER}lisen = \"typo\"")),
            ("[auth]", format!("{SERVER}\n[auth]\nuesrs = []")),
            (
                "[auth.users]",
                format!(
                    "{SERVER}\n[auth]\nusers = [{{ username = \"u\", password = \"p\", role = \"admin\" }}]"
                ),
            ),
            (
                "[limits]",
                format!("{SERVER}\n[limits]\nmax_connection = 8"),
            ),
            (
                "[security]",
                format!("{SERVER}\n[security]\ndenied_port = [25]"),
            ),
            ("[log]", format!("{SERVER}\n[log]\nlevl = \"info\"")),
        ] {
            match toml::from_str::<Config>(&text) {
                Ok(accepted) => panic!(
                    "{table} must reject unknown keys, but the file parsed: {accepted:?}\n{text}"
                ),
                Err(error) => assert!(
                    error.to_string().contains("unknown field"),
                    "{table}: the refusal must be an unknown-field one, got: {error}"
                ),
            }
        }
    }

    /// A configuration file is forward-only: one written for this version does
    /// not load on a version that predates any key in it.
    ///
    /// That is the same `deny_unknown_fields` seen from the rollback side, and
    /// the consequence is not hypothetical. `script/config.example.toml` began
    /// setting `mtu_upper_bound` in v0.4.5, and `install-selfsigned.sh` derives
    /// every install from that file, so a host first installed at v0.4.5 or
    /// later carries a key v0.4.4 refuses to start on — during the one operation
    /// that only ever runs when something is already wrong.
    ///
    /// The policy stands anyway, for the reason in
    /// [`every_table_rejects_unknown_keys`]: ignoring unknown keys would let a
    /// misspelled `users` install an open proxy. What this test pins is that
    /// adding a key is a decision about rollback rather than a surprise during
    /// one, and `docs/configuration.md` states the resulting rule for operators.
    #[test]
    fn a_config_that_names_a_key_from_the_future_is_refused_whole() {
        // The whole file is refused, not the one key: nothing else in it takes
        // effect, which is why this is a startup failure rather than a warning.
        let err = toml::from_str::<Config>(
            r#"
            [server]
            listen = "127.0.0.1:4433"
            cert = "/tmp/c.pem"
            key = "/tmp/k.pem"

            [limits]
            initial_mtu = 1242
            a_key_a_later_release_added = 2
            "#,
        )
        .expect_err("a key this version does not know must refuse the file");
        assert!(
            err.to_string().contains("unknown field"),
            "the refusal must name the shape of the problem: {err}"
        );

        // And the position is the operator's only thread back to the offending
        // key, because `parse_error` redacts every quoted segment of the
        // message — the key name included. Rolling back turns on that span
        // still being there.
        assert!(
            err.span().is_some(),
            "the error must carry a span: it is what names the line to comment out"
        );
    }

    /// The other direction has no exceptions: a file written for an older
    /// release must load on this one, with every key added since taking its
    /// documented default.
    ///
    /// The body is the complete key set as of v0.4.3, every key set explicitly
    /// so a rename cannot pass unnoticed, and it deliberately does *not*
    /// mention `mtu_upper_bound` (v0.4.5) — the one key added inside the window
    /// of releases that have been deployed. An upgrade never rewrites
    /// `/etc/volto/config.toml`, so this is the file the new binary actually
    /// gets handed.
    #[test]
    fn a_config_from_an_older_release_still_loads_with_defaults_for_what_it_lacks() {
        let cfg: Config = toml::from_str(
            r#"
            [server]
            listen = "127.0.0.1:4433"
            cert = "/tmp/c.pem"
            key = "/tmp/k.pem"
            alpn = ["h3"]
            shutdown_grace = 5

            [auth]
            users = [{ username = "u", password = "p" }]

            [limits]
            udp_session_timeout = 180
            max_targets_per_conn = 256
            max_connections = 256
            connect_timeout = 10
            ip_family_preference = "ipv4"
            max_streams_bidi = 1024
            max_idle_timeout = 60
            keep_alive_interval = 20
            initial_mtu = 1200
            mtu_discovery = true
            congestion_control = "bbr"
            initial_rtt_ms = 150
            socket_recv_buffer = 2097152
            socket_send_buffer = 2097152

            [security]
            allow_private_networks = false
            denied_ports = [25]
            unanswered_packet_budget = 64
            max_auth_failures = 5

            [log]
            level = "info"
            keylog = false
            "#,
        )
        .expect("a configuration file from v0.4.3 must still parse");

        // The key added since is absent, so it takes its compiled-in default
        // rather than leaving the file half-applied.
        assert_eq!(cfg.limits.mtu_upper_bound, None);
        assert_eq!(cfg.limits.mtu_upper_bound(), DEFAULT_MTU_UPPER_BOUND);
        assert_eq!(cfg.limits.mtu_upper_bound(), 1436);

        // `bbr` written in an old file selects what `bbr` selects today, the
        // capped controller since 1.2.0 (D108), with no edit to the file.
        assert_eq!(cfg.limits.congestion_control, CongestionControl::Bbr);
        assert_eq!(
            cfg.limits.congestion_control,
            Limits::default().congestion_control
        );

        // And the default has to be consistent with what the old file *does*
        // say, or an upgrade would fail validation on a file that was fine.
        assert!(cfg.limits.mtu_upper_bound() >= cfg.limits.initial_mtu);
        assert_valid_apart_from_certs(&cfg, "a v0.4.3-era configuration file");
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

    /// `u64`s worth generating for a key whose accepted range ends at `edge`.
    ///
    /// A uniform `u64` would spend essentially every case in the astronomically
    /// invalid region, where each key's first range check answers and nothing
    /// downstream is ever reached; a uniform value inside the range would never
    /// reach the arithmetic that only the far end can break. So the mix is
    /// deliberate: values around the range, the exact boundaries, the halves of
    /// `u64` that a doubling straddles, and the whole domain.
    pub(super) fn around(edge: u64) -> BoxedStrategy<u64> {
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

        // Byte counts widening exactly into the `u64` this strategy takes,
        // which `From` has no `usize` impl to express.
        #[allow(clippy::as_conversions)]
        let recv_buffer = DEFAULT_SOCKET_RECV_BUFFER as u64;
        #[allow(clippy::as_conversions)]
        let send_buffer = DEFAULT_SOCKET_SEND_BUFFER as u64;

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
                // `None` too: an absent ceiling is the case every file that
                // leaves the key out takes.
                proptest::option::of(around(u64::from(MAX_MTU_UPPER_BOUND))),
                around(*INITIAL_RTT_RANGE_MS.end()),
                around(recv_buffer),
                around(send_buffer),
                any::<bool>(),
                prop::sample::select(vec![
                    CongestionControl::Bbr,
                    CongestionControl::BbrUncapped,
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
                    mtu_upper_bound: mtu_upper_bound.map(narrow_u16),
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
                    .map(|upper_bound| upper_bound.clamp(initial_mtu, MAX_MTU_UPPER_BOUND)),
                initial_rtt_ms: limits
                    .initial_rtt_ms
                    .clamp(*INITIAL_RTT_RANGE_MS.start(), *INITIAL_RTT_RANGE_MS.end()),
                // Both are a request the kernel answers, so validation only
                // bounds them by the socket API's signed 32-bit argument.
                socket_recv_buffer: limits.socket_recv_buffer.min(MAX_SOCKET_BUFFER),
                socket_send_buffer: limits.socket_send_buffer.min(MAX_SOCKET_BUFFER),
                // Unbounded by `validate` and left that way here:
                // `max_connections` = 0 means no cap at all.
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
}
