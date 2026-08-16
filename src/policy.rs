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
//! * **Private** — everything RFC 6890 calls special-purpose and this proxy
//!   might actually reach: loopback, RFC 1918, link-local, shared address space,
//!   the benchmarking and documentation ranges, reserved space, ULA and the
//!   deprecated IPv4-compatible space. Denied by default, unlocked by
//!   `allow_private_networks`.
//!
//! # Transition addresses are judged as IPv4
//!
//! NAT64, 6to4 and Teredo addresses embed an IPv4 address, and a host that
//! routes them reaches exactly that address. `64:ff9b::7f00:1` is therefore
//! 127.0.0.1 with three extra steps, and letting it past because it is
//! syntactically a global IPv6 address would undo the whole IPv4 half of this
//! module. [`embedded_ipv4`] unwraps them before any rule is applied.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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
        // A transition address is judged as the IPv4 address it carries, since
        // that is what a host routing it actually reaches. Done here rather than
        // inside the two rules below because the verdict may be either of them:
        // an embedded multicast or unspecified address is never allowed, an
        // embedded private one is private.
        let ip = embedded_ipv4(ip).map_or(ip, IpAddr::V4);

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

/// Whether every resolved address is the unspecified address (`0.0.0.0` / `::`).
///
/// This is the shape a filtering resolver uses to say "no": ad and telemetry
/// blockers answer a blocked name with the unspecified address rather than with
/// NXDOMAIN. Those answers are refused by [`Policy::allows_address`] like any
/// other unroutable target, but the refusal is routine housekeeping rather than
/// evidence of anything — on a host whose resolver filters, it is the bulk of all
/// refusals.
///
/// Callers use this to decide two things (decision D49). It picks the log level:
/// a blackhole is an INFO, every other refusal a WARN. And it picks the answer:
/// a blackholed name gets a 200 whose stream closes immediately, so the client
/// sees a tunnel that opened and died — the same thing a transport without an
/// in-band refusal channel shows it — while every other refusal keeps its 403
/// and its RFC 9209 `destination_ip_prohibited` reason. The split exists because
/// the blackhole decision was made by the resolver upstream, not by this proxy,
/// and a refusal from this proxy would misattribute it.
///
/// The test is deliberately all-or-nothing, and deliberately narrow to the
/// unspecified address:
///
/// * **All**, because a name resolving to `0.0.0.0` *and* `10.0.0.1` is not a
///   blackhole. The private address is a real target that the policy just
///   refused, which is exactly the SSRF-shaped evidence worth keeping loud.
/// * **Unspecified only**, because loopback, RFC 1918 and the rest of the private
///   space are what an attacker aims at, and a probe of them must stay visible.
///   The unspecified address is the one entry in the deny list that reaches
///   nothing at all.
///
/// An empty list is not a blackhole. It cannot arise on the paths that call this
/// (resolution either fails or yields addresses), and "no addresses at all" is no
/// reason to quieten a warning.
pub fn is_dns_blackhole(addresses: &[SocketAddr]) -> bool {
    !addresses.is_empty()
        && addresses
            .iter()
            .all(|address| canonical(address.ip()).is_unspecified())
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
///
/// The list is RFC 6890's special-purpose registry minus the entries
/// [`is_never_allowed`] has already claimed. Everything on it is either not
/// globally reachable or not a destination an internet-facing proxy has any
/// business dialling, and every one of them is a way past
/// `allow_private_networks = false` if it is missing: `100.64.0.0/10` is where a
/// carrier-grade NAT keeps its subscribers, `198.18.0.0/15` is what some
/// networks number their own infrastructure with, `192.0.0.0/24` holds protocol
/// assignments including the DS-Lite `192.0.0.0/29` link, and `240.0.0.0/4` is
/// routed inside more than one large private network in practice.
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();

            // `is_private` is 10/8, 172.16/12 and 192.168/16; `is_link_local` is
            // 169.254/16.
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                // 100.64.0.0/10 — shared address space (RFC 6598), i.e. the
                // inside of a carrier-grade NAT.
                || (octets[0] == 100 && octets[1] & 0xc0 == 64)
                // 192.0.0.0/24 — IETF protocol assignments (RFC 6890).
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                // 198.18.0.0/15 — benchmarking (RFC 2544).
                || (octets[0] == 198 && octets[1] & 0xfe == 18)
                // 240.0.0.0/4 — reserved (RFC 1112 §4). The broadcast address at
                // the top of it is already `is_never_allowed`, which runs first.
                || octets[0] & 0xf0 == 240
                || is_ipv4_documentation(octets)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || is_unique_local(v6)
                || is_unicast_link_local(v6)
                || is_ipv4_compatible(v6)
                || is_ipv6_documentation(v6)
                || is_discard_only(v6)
        }
    }
}

/// The three IPv4 documentation ranges (RFC 5737).
///
/// Reachable nowhere by definition, and the ranges examples and test fixtures
/// are written with — so a request for one is a misconfiguration rather than a
/// destination, and it should not turn into a connection attempt against
/// whoever happens to announce them.
fn is_ipv4_documentation(octets: [u8; 4]) -> bool {
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
    (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
}

/// `2001:db8::/32` — the IPv6 documentation range (RFC 3849).
fn is_ipv6_documentation(v6: Ipv6Addr) -> bool {
    let segments = v6.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

/// `100::/64` — the discard-only prefix (RFC 6666).
///
/// Traffic to it is meant to be black-holed, which makes it a way to ask this
/// proxy to open a tunnel that can only ever hold a slot.
fn is_discard_only(v6: Ipv6Addr) -> bool {
    let segments = v6.segments();
    segments[0] == 0x0100 && segments[1..4].iter().all(|segment| *segment == 0)
}

/// The IPv4 address an IPv6 transition address carries, if it carries one.
///
/// A host that routes any of these reaches the embedded IPv4 address, so this is
/// what the IPv4 rules must be applied to — otherwise `2002:0a00:0001::` is a
/// route to 10.0.0.1 that `allow_private_networks = false` never sees.
///
/// The four forms that matter here:
///
/// * `64:ff9b::/96` — the well-known NAT64 prefix (RFC 6052 §2.1), with the
///   address in the last 32 bits;
/// * `64:ff9b:1::/48` — the local-use NAT64 prefix (RFC 8215). At a /48 prefix
///   RFC 6052 §2.2 splits the address around the reserved octet at bits 64-71,
///   which is why this is not simply the last four octets. The reserved octet is
///   not checked: a host translating the address ignores it too, and refusing to
///   look would let a single non-zero byte hide a private target.
/// * `2002::/16` — 6to4 (RFC 3056), with the address at bits 16-47;
/// * `2001::/32` — Teredo (RFC 4380 §4). The client's own IPv4 address is the
///   last 32 bits with every bit inverted, which is the one this proxy would
///   reach.
///
/// The deprecated `::/96` IPv4-compatible range is deliberately **not** here:
/// unwrapping it would turn `::1` into 0.0.0.1 and lose the loopback meaning, so
/// [`is_ipv4_compatible`] keeps claiming it wholesale instead.
fn embedded_ipv4(ip: IpAddr) -> Option<Ipv4Addr> {
    let IpAddr::V6(v6) = ip else {
        return None;
    };
    let octets = v6.octets();

    // 64:ff9b::/96
    if octets[..4] == [0x00, 0x64, 0xff, 0x9b] && octets[4..12].iter().all(|byte| *byte == 0) {
        return Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }

    // 64:ff9b:1::/48
    if octets[..6] == [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01] {
        return Some(Ipv4Addr::new(octets[6], octets[7], octets[9], octets[10]));
    }

    // 2002::/16
    if octets[..2] == [0x20, 0x02] {
        return Some(Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]));
    }

    // 2001::/32
    if octets[..4] == [0x20, 0x01, 0x00, 0x00] {
        return Some(Ipv4Addr::new(
            octets[12] ^ 0xff,
            octets[13] ^ 0xff,
            octets[14] ^ 0xff,
            octets[15] ^ 0xff,
        ));
    }

    None
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
        // RFC 6598 shared address space: the inside of a carrier-grade NAT.
        "100.64.0.0",
        "100.127.255.255",
        // RFC 6890 IETF protocol assignments, including the DS-Lite link.
        "192.0.0.0",
        "192.0.0.255",
        // RFC 2544 benchmarking, which some networks number infrastructure with.
        "198.18.0.0",
        "198.19.255.255",
        // RFC 5737 documentation.
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        // RFC 1112 §4 reserved space, routed inside some large networks.
        "240.0.0.0",
        "255.255.255.254",
        // IPv6
        "::1",
        "fc00::1",
        "fdff::1",
        "fe80::1",
        "febf::1",
        // RFC 3849 documentation and the RFC 6666 discard prefix.
        "2001:db8::1",
        "100::1",
        "100:0:0:0:ffff::",
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
        // The neighbours of every range added for RFC 6890, on both sides.
        "100.63.255.255", // just below 100.64/10
        "100.128.0.0",    // just above it
        "192.0.1.1",      // just above 192.0.0/24, and not 192.0.2/24
        "198.17.255.255", // just below 198.18/15
        "198.20.0.0",     // just above it
        "192.0.3.1",      // just above 192.0.2/24
        "198.51.101.1",   // just above 198.51.100/24
        "203.0.114.1",    // just above 203.0.113/24
        // 224/4 through 239/8 is multicast and sits in NEVER, so the last public
        // address below the reserved block is the one at the top of 223/8.
        "223.255.255.255",
        "2001:4860:4860::8888",
        "2606:4700::1111",
        "fbff::1",      // just below fc00::/7
        "fec0::1",      // just above fe80::/10
        "2001:db9::1",  // just above 2001:db8::/32
        "100:0:0:1::1", // just outside 100::/64
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

    /// Every added range at both of its edges, so a mask typo cannot pass.
    ///
    /// The `PRIVATE`/`PUBLIC` lists above already carry these; this states the
    /// adjacency directly, because "first address in, neighbour out" is the
    /// property a wrong mask breaks and a list of literals does not say out loud.
    #[test]
    fn the_special_purpose_ranges_stop_where_they_should() {
        let strict = policy(false, &[]);

        for (last_public, first_private, last_private, first_public) in [
            (
                "100.63.255.255",
                "100.64.0.0",
                "100.127.255.255",
                "100.128.0.0",
            ),
            ("191.255.255.255", "192.0.0.0", "192.0.0.255", "192.0.1.0"),
            (
                "198.17.255.255",
                "198.18.0.0",
                "198.19.255.255",
                "198.20.0.0",
            ),
            ("192.0.1.255", "192.0.2.0", "192.0.2.255", "192.0.3.0"),
            (
                "198.51.99.255",
                "198.51.100.0",
                "198.51.100.255",
                "198.51.101.0",
            ),
            (
                "203.0.112.255",
                "203.0.113.0",
                "203.0.113.255",
                "203.0.114.0",
            ),
            // 240/4 runs to the broadcast address, which `is_never_allowed`
            // claims first — so there is no "first public" above it. The address
            // just below the range is multicast for the same reason, hence
            // 223.255.255.255 as the public neighbour.
            (
                "223.255.255.255",
                "240.0.0.0",
                "255.255.255.254",
                "223.255.255.255",
            ),
        ] {
            for public in [last_public, first_public] {
                assert!(
                    strict.allows_address(ip(public)),
                    "{public} is outside the range and must stay reachable"
                );
            }
            for private in [first_private, last_private] {
                assert!(
                    !strict.allows_address(ip(private)),
                    "{private} is inside the range and must be denied"
                );
            }
        }

        // The broadcast address is inside 240/4 but `is_never_allowed` wins, so
        // opening private space does not open it.
        assert!(!policy(true, &[]).allows_address(ip("255.255.255.255")));
        assert!(policy(true, &[]).allows_address(ip("240.0.0.1")));
    }

    /// NAT64, 6to4 and Teredo addresses are routes to an IPv4 address, so they
    /// are judged as that address and not as the global-looking IPv6 they are
    /// written as.
    #[test]
    fn transition_addresses_are_judged_by_the_ipv4_they_carry() {
        let strict = policy(false, &[]);
        let permissive = policy(true, &[]);

        // Embedding something private: denied by default, reachable once private
        // space is opened, exactly like the bare IPv4 address would be.
        for address in [
            "64:ff9b::7f00:1",          // NAT64 well-known prefix, 127.0.0.1
            "64:ff9b::a00:1",           // 10.0.0.1
            "64:ff9b::a9fe:a9fe",       // 169.254.169.254, the metadata address
            "64:ff9b:1:a9fe:a9:fe00::", // the /48 prefix, same address
            "2002:a00:1::",             // 6to4, 10.0.0.1
            "2002:7f00:1::",            // 6to4, 127.0.0.1
            "2001:0:0:0:0:0:f5ff:fffe", // Teredo, 10.0.0.1 inverted
        ] {
            assert!(
                !strict.allows_address(ip(address)),
                "{address} carries a private IPv4 address and must be denied"
            );
            assert!(
                permissive.allows_address(ip(address)),
                "{address} must follow the switch like the address it carries"
            );
        }

        // Embedding something public stays public: unwrapping must not become a
        // blanket ban on the transition forms.
        for address in [
            "64:ff9b::808:808",         // NAT64, 8.8.8.8
            "64:ff9b:1:808:8:800::",    // the /48 prefix, 8.8.8.8
            "2002:808:808::",           // 6to4, 8.8.8.8
            "2001:0:0:0:0:0:f7f7:f7f7", // Teredo, 8.8.8.8 inverted
        ] {
            assert!(
                strict.allows_address(ip(address)),
                "{address} carries a public IPv4 address and must be reachable"
            );
        }

        // And an embedded address that is never allowed stays never allowed, so
        // the switch cannot open it.
        for address in ["64:ff9b::", "2002::", "64:ff9b::e000:1"] {
            for policy in [&strict, &permissive] {
                assert!(
                    !policy.allows_address(ip(address)),
                    "{address} carries an address that is never a destination"
                );
            }
        }
    }

    /// The extraction itself, address by address.
    ///
    /// The bucket assertions above would pass on a near-miss — 169.254.0.169 is
    /// as link-local as 169.254.169.254 — so the exact value is asserted here.
    /// The RFC 6052 §2.2 /48 layout is the one worth stating: the IPv4 address is
    /// split around the reserved octet at bits 64-71 rather than sitting in one
    /// piece.
    #[test]
    fn the_embedded_ipv4_is_extracted_exactly() {
        for (address, expected) in [
            // RFC 6052 §2.1: the well-known prefix, address in the last 32 bits.
            ("64:ff9b::7f00:1", "127.0.0.1"),
            ("64:ff9b::808:808", "8.8.8.8"),
            ("64:ff9b::", "0.0.0.0"),
            // RFC 8215's /48 prefix, RFC 6052 §2.2's split layout.
            ("64:ff9b:1:a9fe:a9:fe00::", "169.254.169.254"),
            ("64:ff9b:1:808:8:800::", "8.8.8.8"),
            // 6to4: bits 16-47.
            ("2002:a00:1::", "10.0.0.1"),
            ("2002:808:808::1", "8.8.8.8"),
            // Teredo: the last 32 bits, every bit inverted.
            ("2001:0:0:0:0:0:f5ff:fffe", "10.0.0.1"),
            ("2001:0:808:808:0:0:f7f7:f7f7", "8.8.8.8"),
        ] {
            assert_eq!(
                embedded_ipv4(ip(address)).map(IpAddr::V4),
                Some(ip(expected)),
                "{address} carries {expected}"
            );
        }

        // Everything else carries nothing, including the ranges that merely look
        // adjacent and the deprecated `::/96` form that must stay whole.
        for address in [
            "2001:db8::1",  // documentation, not Teredo
            "2003::1",      // not 6to4
            "64:ff9c::1",   // not the NAT64 prefix
            "64:ff9b:2::1", // not the /48 NAT64 prefix either
            "::1",
            "::127.0.0.1",
            "2606:4700::1111",
            "8.8.8.8",
        ] {
            assert_eq!(embedded_ipv4(ip(address)), None, "{address}");
        }
    }

    /// A Teredo address's *client* IPv4 is the inverted last 32 bits, and the
    /// bits in between are a server address this proxy never dials — so the
    /// verdict must come from the right half of the address.
    #[test]
    fn a_teredo_address_is_read_from_its_client_field() {
        // 2001:0:<server>:<flags+port>:<client>. The server field here is a
        // public address and the client field a private one; the verdict follows
        // the client field.
        let strict = policy(false, &[]);
        assert!(!strict.allows_address(ip("2001:0:808:808:0:0:f5ff:fffe")));

        // The mirror image: private-looking server field, public client field.
        assert!(strict.allows_address(ip("2001:0:a00:1:0:0:f7f7:f7f7")));
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
            "[2606:4700::1111]:443",
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
                "[2606:4700::1111]:443".parse().unwrap()
            ]
        );
    }

    fn addresses(literals: &[&str]) -> Vec<SocketAddr> {
        literals
            .iter()
            .map(|a| a.parse().expect("socket address"))
            .collect()
    }

    /// The answer a filtering resolver gives, in every spelling it gives it in.
    #[test]
    fn an_all_unspecified_answer_is_a_blackhole() {
        for literals in [
            &["0.0.0.0:443"][..],
            &["0.0.0.0:53", "0.0.0.0:53"][..],
            &["[::]:443"][..],
            // IPv4-mapped: unspecified once canonicalized, like everywhere else.
            &["[::ffff:0.0.0.0]:443"][..],
            &["0.0.0.0:443", "[::]:443", "[::ffff:0.0.0.0]:443"][..],
        ] {
            assert!(
                is_dns_blackhole(&addresses(literals)),
                "{literals:?} is a filtered answer and must be recognised as one"
            );
        }
    }

    /// The half of the rule that keeps SSRF probes loud: anything that is not
    /// *only* the unspecified address stays an ordinary policy refusal.
    #[test]
    fn private_and_mixed_answers_are_not_blackholes() {
        for literals in [
            // A private address alongside the blackhole is still a private
            // address, and reaching for it is the thing worth warning about.
            &["0.0.0.0:443", "10.0.0.1:443"][..],
            &["[::]:443", "[::1]:443"][..],
            // Pure loopback / RFC 1918 / link-local: refused, never quietly.
            &["127.0.0.1:443"][..],
            &["10.0.0.1:443", "192.168.1.1:443"][..],
            &["169.254.169.254:80"][..],
            &["[::1]:443"][..],
            // Broadcast and multicast are refused for their own reasons.
            &["255.255.255.255:443"][..],
            &["224.0.0.1:443"][..],
            // A public address is not a blackhole either, mixed in or alone.
            &["0.0.0.0:443", "8.8.8.8:443"][..],
        ] {
            assert!(
                !is_dns_blackhole(&addresses(literals)),
                "{literals:?} must stay an ordinary policy refusal"
            );
        }
    }

    /// Unreachable on the calling paths, but "nothing resolved" is not evidence
    /// of filtering, so it takes the loud branch.
    #[test]
    fn no_addresses_is_not_a_blackhole() {
        assert!(!is_dns_blackhole(&[]));
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
