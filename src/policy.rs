//! Destination policy: which targets this proxy is willing to reach.
//!
//! RFC 9298 §7 and RFC 9114 §4.4 both warn about the same thing from different
//! angles: a proxy that will dial anything is a reflector, a port scanner, and a
//! way to borrow the proxy's own source address. That last one is the sharpest —
//! plenty of services trust `127.0.0.1` or a private range without further
//! authentication, and the proxy is *inside* that perimeter.
//!
//! So the defaults deny private address space, and the operator can open it with
//! `security.allow_private_networks` for the deployments where the point of the
//! proxy is to reach a private network.
//!
//! # Normalization comes first
//!
//! `::ffff:127.0.0.1` is loopback wearing an IPv6 hat: the kernel routes it to
//! 127.0.0.1, while a naive matcher sees an IPv6 address that matches none of the
//! IPv4 rules. Every check therefore starts by canonicalizing
//! ([`canonical`]), and the deprecated `::/96` compatible range is folded in for
//! the same reason.
//!
//! # Two buckets
//!
//! * **Never allowed** — the unspecified address, the IPv4 broadcast address and
//!   all multicast. These are not unicast targets at all; sending to them is an
//!   amplification primitive, so `allow_private_networks` does not unlock them.
//! * **Private** — loopback, RFC 1918, link-local, ULA and the deprecated
//!   IPv4-compatible space. Denied by default, unlocked by
//!   `allow_private_networks`.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::config;

/// The destination rules in force for a connection.
pub struct Policy {
    /// Whether loopback and other private ranges may be dialled.
    allow_private_networks: bool,
    /// Target ports that are refused regardless of address.
    ///
    /// A `Vec` scanned linearly: realistic deny lists hold a handful of ports, so
    /// a set would cost more in hashing than it saves in comparisons.
    denied_ports: Vec<u16>,
}

impl Policy {
    /// Builds the policy described by the `[security]` section.
    pub fn new(security: &config::Security) -> Self {
        Self {
            allow_private_networks: security.allow_private_networks,
            denied_ports: security.denied_ports.clone(),
        }
    }

    /// Whether a target port may be reached at all.
    ///
    /// Checked before name resolution: it needs no address, and refusing early
    /// means a denied port cannot be used to make the proxy run DNS lookups.
    pub fn allows_port(&self, port: u16) -> bool {
        !self.denied_ports.contains(&port)
    }

    /// Whether one resolved address may be dialled.
    pub fn allows_address(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);

        if is_never_allowed(ip) {
            return false;
        }
        if is_private(ip) {
            return self.allow_private_networks;
        }

        true
    }

    /// The subset of `addresses` this proxy may dial.
    ///
    /// A name that resolves to both a public and a private address keeps only the
    /// public ones, which is what makes DNS rebinding onto loopback pointless.
    pub fn allowed_addresses(&self, addresses: &[SocketAddr]) -> Vec<SocketAddr> {
        addresses
            .iter()
            .copied()
            .filter(|address| self.allows_address(address.ip()))
            .collect()
    }
}

/// Normalizes an address into the form the kernel will actually route.
///
/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) becomes the IPv4 address it stands for.
/// The deprecated IPv4-compatible range (`::a.b.c.d`, RFC 4291 §2.5.5.1) is left
/// as IPv6 on purpose and handled by [`is_private`], because mapping it to IPv4
/// would turn `::1` into `0.0.0.1` and quietly lose the loopback meaning.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_canonical(),
        v4 => v4,
    }
}

/// Addresses that are never a legitimate tunnel target.
///
/// Not affected by `allow_private_networks`: these are not unicast destinations,
/// and a proxy that forwards to them is an amplifier (RFC 9298 §7).
fn is_never_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast(),
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_multicast(),
    }
}

/// Addresses only reachable when `allow_private_networks` is on.
fn is_private(ip: IpAddr) -> bool {
    match ip {
        // `is_private` is 10/8, 172.16/12 and 192.168/16; `is_link_local` is
        // 169.254/16.
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || is_unique_local(v6)
                || is_unicast_link_local(v6)
                || is_ipv4_compatible(v6)
        }
    }
}

/// `fc00::/7` — unique local addresses (RFC 4193).
///
/// Hand-rolled because `Ipv6Addr::is_unique_local` is still unstable.
fn is_unique_local(v6: Ipv6Addr) -> bool {
    v6.segments()[0] & 0xfe00 == 0xfc00
}

/// `fe80::/10` — link-local unicast (RFC 4291 §2.5.6).
///
/// Hand-rolled because `Ipv6Addr::is_unicast_link_local` is still unstable.
fn is_unicast_link_local(v6: Ipv6Addr) -> bool {
    v6.segments()[0] & 0xffc0 == 0xfe80
}

/// `::/96` — the deprecated IPv4-compatible range, and `::1` with it.
///
/// Treated as private rather than as ordinary IPv6: stacks that still honour the
/// range route `::127.0.0.1` to loopback, which would otherwise be a second way
/// around the IPv4 rules. The unspecified address is in here too, but
/// [`is_never_allowed`] has already claimed it.
fn is_ipv4_compatible(v6: Ipv6Addr) -> bool {
    v6.octets()[..12].iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(allow_private: bool, denied_ports: &[u16]) -> Policy {
        Policy::new(&config::Security {
            allow_private_networks: allow_private,
            denied_ports: denied_ports.to_vec(),
            ..Default::default()
        })
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("address literal")
    }

    /// Every range the spec names, in both address families.
    const PRIVATE: &[&str] = &[
        // IPv4
        "127.0.0.1",
        "127.255.255.254",
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
        "169.254.169.254", // the cloud metadata address, the classic prize
        // IPv6
        "::1",
        "fc00::1",
        "fdff::1",
        "fe80::1",
        "febf::1",
    ];

    const PUBLIC: &[&str] = &[
        "1.1.1.1",
        "8.8.8.8",
        "93.184.216.34",
        "172.32.0.1",  // just outside 172.16/12
        "172.15.0.1",  // just below it
        "169.253.0.1", // just outside 169.254/16
        "11.0.0.1",
        "192.169.0.1",
        "2001:4860:4860::8888",
        "2606:4700::1111",
        "fbff::1", // just below fc00::/7
        "fec0::1", // just above fe80::/10
    ];

    const NEVER: &[&str] = &[
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "239.255.255.255",
        "::",
        "ff02::1",
        "ff05::1:3",
    ];

    #[test]
    fn private_ranges_are_denied_by_default() {
        let policy = policy(false, &[]);
        for address in PRIVATE {
            assert!(
                !policy.allows_address(ip(address)),
                "{address} must be denied by default"
            );
        }
    }

    #[test]
    fn public_addresses_are_allowed() {
        for allow_private in [false, true] {
            let policy = policy(allow_private, &[]);
            for address in PUBLIC {
                assert!(
                    policy.allows_address(ip(address)),
                    "{address} must be allowed (allow_private={allow_private})"
                );
            }
        }
    }

    #[test]
    fn private_ranges_can_be_opened_up() {
        let policy = policy(true, &[]);
        for address in PRIVATE {
            assert!(
                policy.allows_address(ip(address)),
                "{address} must be allowed once private networks are"
            );
        }
    }

    /// Multicast, broadcast and the unspecified address are amplification
    /// primitives, not destinations: no switch opens them.
    #[test]
    fn unroutable_and_multicast_addresses_are_never_allowed() {
        for allow_private in [false, true] {
            let policy = policy(allow_private, &[]);
            for address in NEVER {
                assert!(
                    !policy.allows_address(ip(address)),
                    "{address} must never be allowed (allow_private={allow_private})"
                );
            }
        }
    }

    /// The classic bypass: an IPv4 address in IPv6 clothing.
    #[test]
    fn ipv4_mapped_addresses_are_matched_as_ipv4() {
        let strict = policy(false, &[]);

        for address in [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:192.168.1.1",
            "::ffff:169.254.169.254",
            // The same addresses written the way a resolver hands them over.
            "::ffff:7f00:1",
            "::ffff:a00:1",
        ] {
            assert!(
                !strict.allows_address(ip(address)),
                "{address} is loopback/private in disguise and must be denied"
            );
        }

        // A mapped *public* address is still allowed: normalization must not turn
        // into a blanket ban on the mapped form.
        assert!(strict.allows_address(ip("::ffff:8.8.8.8")));

        // And the mapped form follows the switch exactly like the bare form.
        let permissive = policy(true, &[]);
        assert!(permissive.allows_address(ip("::ffff:127.0.0.1")));
    }

    /// The deprecated sibling of the mapped form, `::a.b.c.d`.
    #[test]
    fn ipv4_compatible_addresses_are_denied_by_default() {
        let policy = policy(false, &[]);
        for address in ["::127.0.0.1", "::10.0.0.1", "::8.8.8.8", "::0.0.0.1"] {
            assert!(
                !policy.allows_address(ip(address)),
                "{address} is deprecated IPv4-compatible space and must be denied"
            );
        }
    }

    #[test]
    fn canonicalization_unwraps_only_the_mapped_form() {
        assert_eq!(canonical(ip("::ffff:127.0.0.1")), ip("127.0.0.1"));
        assert_eq!(canonical(ip("127.0.0.1")), ip("127.0.0.1"));
        assert_eq!(canonical(ip("2001:db8::1")), ip("2001:db8::1"));
        // `::1` must keep its loopback meaning rather than becoming 0.0.0.1.
        assert_eq!(canonical(ip("::1")), ip("::1"));
    }

    #[test]
    fn denied_ports_are_refused() {
        let policy = policy(false, &[25]);
        assert!(!policy.allows_port(25));
        assert!(policy.allows_port(443));
        assert!(policy.allows_port(80));
    }

    /// Surge's UDP availability test is a DNS query through the tunnel, so 53 has
    /// to work with a stock configuration.
    #[test]
    fn port_53_is_allowed_with_the_default_deny_list() {
        let policy = Policy::new(&config::Security::default());
        assert!(
            policy.allows_port(53),
            "Surge tests UDP by resolving a name"
        );
        assert!(!policy.allows_port(25));
    }

    /// A name that resolves to a mix keeps only what may be dialled — the reason
    /// resolution is explicit rather than left to `TcpStream::connect`.
    #[test]
    fn filtering_keeps_the_dialable_addresses() {
        let policy = policy(false, &[]);
        let addresses: Vec<SocketAddr> = [
            "127.0.0.1:443",
            "8.8.8.8:443",
            "[::1]:443",
            "[2001:db8::1]:443",
            "[::ffff:10.0.0.1]:443",
        ]
        .iter()
        .map(|a| a.parse().expect("socket address"))
        .collect();

        let allowed = policy.allowed_addresses(&addresses);
        assert_eq!(
            allowed,
            vec![
                "8.8.8.8:443".parse().unwrap(),
                "[2001:db8::1]:443".parse().unwrap()
            ]
        );
    }

    #[test]
    fn filtering_everything_out_yields_an_empty_list() {
        let policy = policy(false, &[]);
        let addresses: Vec<SocketAddr> = ["127.0.0.1:443", "[::ffff:127.0.0.1]:443"]
            .iter()
            .map(|a| a.parse().expect("socket address"))
            .collect();

        assert!(policy.allowed_addresses(&addresses).is_empty());
    }
}
