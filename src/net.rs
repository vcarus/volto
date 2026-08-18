//! Socket helpers: name resolution and UDP socket setup.
//!
//! Resolution is deliberately explicit rather than left to
//! `TcpStream::connect`'s implicit lookup. Two later requirements depend on
//! seeing the resolved addresses:
//!
//! * RFC 9298 §3.1 requires a CONNECT-UDP request to be resolved *before* the
//!   2xx response is sent.
//! * The destination ACL (M4) can only filter what it can see.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::config::IpFamilyPreference;

/// Reorders `addresses` so the preferred address family comes first.
///
/// A *stable* partition rather than a sort: within one family the resolver's own
/// order survives untouched, so whatever RFC 6724 decided between two IPv6
/// addresses (or two IPv4 ones) still decides which of them is tried first. Only
/// the choice *between* the families is taken away from the resolver, because
/// only that choice is an operator's to make — see [`IpFamilyPreference`].
///
/// [`System`](IpFamilyPreference::System) leaves the list exactly as it arrived.
/// A list that is empty or single-family — an IP literal is always the latter —
/// is unchanged by any preference.
pub fn prefer_family(addresses: &mut [SocketAddr], preference: IpFamilyPreference) {
    let prefer_ipv6 = match preference {
        IpFamilyPreference::System => return,
        IpFamilyPreference::Ipv4 => false,
        IpFamilyPreference::Ipv6 => true,
    };

    // `sort_by_key` is a stable sort, which is the whole requirement here: the
    // key has two values, so every pair inside one family compares equal and
    // keeps the order it came in with.
    addresses.sort_by_key(|address| address.is_ipv6() != prefer_ipv6);
}

/// Resolves `host`/`port` to a non-empty list of socket addresses.
///
/// An IP literal resolves to itself without consulting the resolver. Both
/// bracketed and bare IPv6 literals are accepted; RFC 9298 uses the bare form.
pub async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    // `lookup_host` wants the bracketed form for IPv6 literals, while RFC 9298
    // templates carry them bare.
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);

    let addresses: Vec<SocketAddr> = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        tokio::net::lookup_host((host, port)).await?.collect()
    };

    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{host} resolved to no addresses"),
        ));
    }

    Ok(addresses)
}

/// The process's soft limit on open file descriptors.
///
/// Every tunnel holds one, so this is the ceiling the tunnel quota has to fit
/// under: exhausting it does not degrade the proxy gracefully, it makes every
/// `accept`, `connect` and `socket` call fail at once, including the ones the
/// QUIC endpoint needs. Checked at startup against `limits.max_targets_per_conn`
/// rather than discovered at 3am.
///
/// `getrlimit` needs no `cfg` split: it is POSIX and present on both the Linux
/// production host and the macOS dev host. `None` means the call failed, which
/// should not happen for `RLIMIT_NOFILE` but is not worth a panic.
pub fn fd_soft_limit() -> Option<u64> {
    // SAFETY: `getrlimit` writes a `rlimit` and reads nothing else; the struct is
    // fully initialized by the call before we read it.
    let mut limit = unsafe { std::mem::zeroed::<libc::rlimit>() };
    let result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };

    if result != 0 {
        return None;
    }

    Some(limit.rlim_cur as u64)
}

/// Binds a UDP socket and connects it to `target`.
///
/// Connecting the socket makes the kernel drop any packet that does not come
/// from `target`, which is the source validation RFC 9298 §3.1 calls for.
pub async fn connected_udp_socket(target: SocketAddr) -> io::Result<UdpSocket> {
    // Bind a wildcard address of the same family as the target.
    let bind: SocketAddr = if target.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };

    let socket = UdpSocket::bind(bind).await?;
    set_dont_fragment(&socket);
    socket.connect(target).await?;

    // ECN is left alone: an unset codepoint is Not-ECT (RFC 3168), which is what
    // RFC 9298 §6.2 asks a proxy to send.

    Ok(socket)
}

/// Sets the IP "don't fragment" bit and enables path MTU discovery.
///
/// A proxy must not let the kernel fragment tunnelled UDP: fragments defeat PMTU
/// discovery end to end and are widely dropped. Failure is logged rather than
/// fatal — the tunnel still works, it just may lose oversized packets silently.
#[cfg(target_os = "linux")]
fn set_dont_fragment(socket: &UdpSocket) {
    use std::os::fd::AsRawFd;
    use tracing::debug;

    let fd = socket.as_raw_fd();
    let is_ipv4 = socket
        .local_addr()
        .map(|address| address.is_ipv4())
        .unwrap_or(true);

    let (level, option, value) = if is_ipv4 {
        (
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_DO,
        )
    } else {
        (
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            libc::IPV6_PMTUDISC_DO,
        )
    };

    // SAFETY: `fd` is owned by `socket` and outlives this call; `value` is a
    // 4-byte int matching the length passed to setsockopt.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };

    if result != 0 {
        debug!(
            error = %io::Error::last_os_error(),
            "failed to enable path MTU discovery on the target socket"
        );
    }
}

/// No portable equivalent outside Linux.
///
/// Development happens on macOS, where the tunnel still works; only the DF bit
/// is missing, which matters on the Linux production host.
#[cfg(not(target_os = "linux"))]
fn set_dont_fragment(_socket: &UdpSocket) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_ipv4_literals_without_a_resolver() {
        let addresses = resolve("192.0.2.1", 443).await.expect("literal resolves");
        assert_eq!(addresses, vec!["192.0.2.1:443".parse().unwrap()]);
    }

    #[tokio::test]
    async fn resolves_bare_and_bracketed_ipv6_literals() {
        // RFC 9298 templates carry IPv6 literals without brackets.
        let bare = resolve("2001:db8::1", 53).await.expect("bare literal");
        let bracketed = resolve("[2001:db8::1]", 53)
            .await
            .expect("bracketed literal");
        assert_eq!(bare, vec!["[2001:db8::1]:53".parse().unwrap()]);
        assert_eq!(bare, bracketed);
    }

    #[tokio::test]
    async fn resolves_localhost() {
        let addresses = resolve("localhost", 80).await.expect("localhost resolves");
        assert!(
            addresses.iter().all(|address| address.ip().is_loopback()),
            "{addresses:?}"
        );
    }

    /// A name that cannot resolve *anywhere*, so the assertion is about this code
    /// rather than about the local resolver.
    ///
    /// A plain nonexistent name is unusable as a test: resolvers that hijack
    /// NXDOMAIN — including Surge itself, which answers from a fake-IP range —
    /// make it succeed. A name longer than the 255 octets DNS allows is rejected
    /// by the stub resolver before any query goes out, on every platform.
    #[tokio::test]
    async fn a_name_too_long_for_dns_fails_to_resolve() {
        let label = "a".repeat(60);
        let host = vec![label; 5].join(".") + ".invalid";
        assert!(host.len() > 255, "{} octets", host.len());

        let error = resolve(&host, 443).await.expect_err("must not resolve");
        // Whatever the platform calls it, it must be an error rather than an
        // empty success.
        assert!(!error.to_string().is_empty());
    }

    /// The startup fd check is only useful if the probe works on both hosts.
    #[test]
    fn the_fd_soft_limit_is_readable() {
        let limit = fd_soft_limit().expect("RLIMIT_NOFILE is always readable");
        assert!(
            limit > 0,
            "a process with no descriptors could not run this"
        );
    }

    /// Two of each family, interleaved, so both the partition and its stability
    /// are visible in one list.
    fn mixed() -> Vec<SocketAddr> {
        vec![
            "[2001:db8::1]:443".parse().unwrap(),
            "192.0.2.1:443".parse().unwrap(),
            "[2001:db8::2]:443".parse().unwrap(),
            "192.0.2.2:443".parse().unwrap(),
        ]
    }

    #[test]
    fn the_default_preference_puts_ipv4_first() {
        let mut addresses = mixed();
        prefer_family(&mut addresses, IpFamilyPreference::Ipv4);
        assert_eq!(
            addresses,
            vec![
                "192.0.2.1:443".parse().unwrap(),
                "192.0.2.2:443".parse().unwrap(),
                "[2001:db8::1]:443".parse().unwrap(),
                "[2001:db8::2]:443".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn the_ipv6_preference_puts_ipv6_first() {
        let mut addresses = mixed();
        prefer_family(&mut addresses, IpFamilyPreference::Ipv6);
        assert_eq!(
            addresses,
            vec![
                "[2001:db8::1]:443".parse().unwrap(),
                "[2001:db8::2]:443".parse().unwrap(),
                "192.0.2.1:443".parse().unwrap(),
                "192.0.2.2:443".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn the_system_preference_leaves_the_resolver_order_alone() {
        let mut addresses = mixed();
        prefer_family(&mut addresses, IpFamilyPreference::System);
        assert_eq!(addresses, mixed(), "the resolver's order is the answer");
    }

    /// The property that makes this a partition and not a sort: RFC 6724 still
    /// decides the order *within* a family, so an unstable sort would silently
    /// throw away the resolver's tie-breaking.
    #[test]
    fn ordering_within_a_family_is_preserved() {
        for preference in [IpFamilyPreference::Ipv4, IpFamilyPreference::Ipv6] {
            let mut addresses = vec![
                "192.0.2.9:443".parse::<SocketAddr>().unwrap(),
                "[2001:db8::9]:443".parse().unwrap(),
                "192.0.2.1:443".parse().unwrap(),
                "[2001:db8::1]:443".parse().unwrap(),
                "192.0.2.5:443".parse().unwrap(),
            ];
            prefer_family(&mut addresses, preference);

            let v4: Vec<SocketAddr> = addresses.iter().copied().filter(|a| a.is_ipv4()).collect();
            let v6: Vec<SocketAddr> = addresses.iter().copied().filter(|a| a.is_ipv6()).collect();
            assert_eq!(
                v4,
                vec![
                    "192.0.2.9:443".parse::<SocketAddr>().unwrap(),
                    "192.0.2.1:443".parse().unwrap(),
                    "192.0.2.5:443".parse().unwrap(),
                ],
                "{preference:?}"
            );
            assert_eq!(
                v6,
                vec![
                    "[2001:db8::9]:443".parse::<SocketAddr>().unwrap(),
                    "[2001:db8::1]:443".parse().unwrap(),
                ],
                "{preference:?}"
            );
        }
    }

    /// The two shapes that arrive most often: an IP literal, which resolves to
    /// one address, and a name with only one family behind it.
    #[test]
    fn single_family_and_empty_lists_are_untouched() {
        for preference in [
            IpFamilyPreference::Ipv4,
            IpFamilyPreference::Ipv6,
            IpFamilyPreference::System,
        ] {
            let mut empty: Vec<SocketAddr> = Vec::new();
            prefer_family(&mut empty, preference);
            assert!(empty.is_empty(), "{preference:?}");

            let only_v4: Vec<SocketAddr> = vec![
                "192.0.2.1:443".parse().unwrap(),
                "192.0.2.2:443".parse().unwrap(),
            ];
            let mut addresses = only_v4.clone();
            prefer_family(&mut addresses, preference);
            assert_eq!(addresses, only_v4, "{preference:?}");

            let only_v6: Vec<SocketAddr> = vec![
                "[2001:db8::1]:443".parse().unwrap(),
                "[2001:db8::2]:443".parse().unwrap(),
            ];
            let mut addresses = only_v6.clone();
            prefer_family(&mut addresses, preference);
            assert_eq!(addresses, only_v6, "{preference:?}");
        }
    }

    #[tokio::test]
    async fn connected_socket_is_bound_to_the_target_family() {
        let socket = connected_udp_socket("127.0.0.1:9".parse().unwrap())
            .await
            .expect("connect udp");
        assert!(socket.local_addr().expect("local addr").is_ipv4());
    }
}
