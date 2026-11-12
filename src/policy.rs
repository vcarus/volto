//! Destination policy: which targets this proxy is willing to reach.
//!
//! RFC 9298 §7 and RFC 9114 §4.4 both warn about the same thing from different
//! angles: a proxy that will dial anything is a reflector, a port scanner, and a
//! way to borrow the proxy's own source address. That last one is the most
//! serious: plenty of services trust `127.0.0.1` or a private range without
//! further authentication, and the proxy is *inside* that perimeter.
//!
//! So the defaults deny private address space, and the operator can open it with
//! `security.allow_private_networks` for the deployments where the point of the
//! proxy is to reach a private network.
//!
//! # Normalization comes first
//!
//! `::ffff:127.0.0.1` is loopback written as IPv6: the kernel routes it to
//! 127.0.0.1, while a naive matcher sees an IPv6 address that matches none of the
//! IPv4 rules. Every check therefore starts by canonicalizing
//! ([`canonical`]), and the deprecated `::/96` compatible range is folded in for
//! the same reason.
//!
//! # Two buckets
//!
//! * **Never allowed**: the unspecified address, the IPv4 broadcast address and
//!   all multicast. These are not unicast targets at all; sending to them is an
//!   amplification primitive, so `allow_private_networks` does not unlock them.
//! * **Private**: the special-purpose space this proxy might actually reach,
//!   drawn from the IANA registries that RFC 6890 set up. The list is one table,
//!   `PRIVATE_PREFIXES`: each row is a prefix with its name, its source and, in
//!   the comment above it, the reason it is refused. Denied by default, unlocked
//!   by `allow_private_networks`.
//!
//! # Transition addresses are judged as IPv4
//!
//! The well-known NAT64 prefix, 6to4 and Teredo addresses embed an IPv4 address
//! at a fixed place, and a host that routes them reaches exactly that address.
//! `64:ff9b::7f00:1` therefore reaches 127.0.0.1, and letting it past
//! because it is syntactically a global IPv6 address would undo the
//! whole IPv4 half of this module. `embedded_ipv4` unwraps them before any rule
//! is applied. Teredo (`2001::/32`) lies inside `2001::/23`, which is refused
//! whole, and is still judged by the IPv4 address it carries, because the
//! unwrapping comes first.
//!
//! The local-use NAT64 prefix `64:ff9b:1::/48` (RFC 8215) is the one transition
//! form that is not unwrapped. Its operator chooses the layout, RFC 8215 §5
//! forbids a reader assuming one, and a guess can read a private target as
//! public. The whole prefix sits in the private bucket instead.

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
        // A transition address is judged as the IPv4 address it carries, since
        // that is what a host routing it actually reaches. Done here rather than
        // inside the two rules below because the verdict may be either of them:
        // an embedded multicast or unspecified address is never allowed, an
        // embedded private one is private.
        let ip = routed_form(ip);

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
/// evidence of anything. On a host whose resolver filters, it is the bulk of
/// all refusals.
///
/// Callers use this to decide two things (decision D49). It picks the log line:
/// a blackhole gets an unsampled INFO line of its own, and every other refusal
/// gets the policy-refusal line, which is INFO on a doubling schedule. And it
/// picks the answer:
/// a blackholed name gets a 200 whose stream closes immediately, so the client
/// sees a tunnel that opened and closed at once. That is what a transport
/// without an in-band refusal channel shows it. Every other refusal keeps its
/// 403 and its RFC 9209 `destination_ip_prohibited` reason. The split exists because
/// the blackhole decision was made by the resolver upstream, not by this proxy,
/// and a refusal from this proxy would misattribute it.
///
/// The test is deliberately all-or-nothing, and deliberately narrow to the
/// unspecified address:
///
/// * **All**, because a name resolving to `0.0.0.0` *and* `10.0.0.1` is not a
///   blackhole. The private address is a real target that the policy just
///   refused, which is exactly the SSRF-shaped evidence worth keeping.
/// * **Unspecified only**, because loopback, RFC 1918 and the rest of the private
///   space are what an attacker aims at, and a probe of them must stay visible.
///   The unspecified address is the one entry in the deny list that reaches
///   nothing at all.
///
/// The unspecified address is judged in its routed form (`routed_form`), so a
/// NAT64, 6to4 or Teredo address whose embedded IPv4 address is `0.0.0.0` is the
/// same blackhole as `0.0.0.0` itself. On a DNS64 network that is the ordinary
/// shape of a blocked name: the resolver answers the A query with `0.0.0.0` and
/// DNS64 synthesizes `64:ff9b::`.
///
/// An empty list is not a blackhole. It cannot arise on the paths that call this
/// (resolution either fails or yields addresses), and "no addresses at all" is no
/// reason to take the blackhole branch.
pub fn is_dns_blackhole(addresses: &[SocketAddr]) -> bool {
    !addresses.is_empty()
        && addresses
            .iter()
            .all(|address| routed_form(address.ip()).is_unspecified())
}

/// The form the kernel routes for `ip`.
///
/// [`canonical`] first, then [`embedded_ipv4`]: a transition address is a route
/// to the IPv4 address it carries, so that is the address every rule and the
/// own-address check must judge. One helper rather than the same two steps
/// spelled out at each site, because [`Policy::allows_address`],
/// [`is_dns_blackhole`] and the tunnel's own-address check have to agree on
/// what "the routed form" means.
pub(crate) fn routed_form(ip: IpAddr) -> IpAddr {
    let ip = canonical(ip);
    embedded_ipv4(ip).map_or(ip, IpAddr::V4)
}

/// Normalizes an address into the form the kernel will actually route.
///
/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) becomes the IPv4 address it stands for.
/// The deprecated IPv4-compatible range (`::a.b.c.d`, RFC 4291 §2.5.5.1) is left
/// as IPv6 on purpose and handled by `is_private`, because mapping it to IPv4
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

/// Addresses only reachable when `allow_private_networks` is on: those inside a
/// row of [`PRIVATE_PREFIXES`].
///
/// [`Policy::allows_address`] calls this on the routed form ([`routed_form`]),
/// after [`is_never_allowed`], so a transition address meets these rows as the
/// IPv4 address it carries.
fn is_private(ip: IpAddr) -> bool {
    PRIVATE_PREFIXES
        .iter()
        .any(|prefix| prefix.net.contains(ip))
}

/// One row of [`PRIVATE_PREFIXES`].
struct Prefix {
    /// The addresses the row covers.
    net: Net,
    /// The allocation's name, as the IANA registry or its RFC gives it.
    #[cfg_attr(not(test), expect(dead_code, reason = "read by the tests"))]
    name: &'static str,
    /// The RFC or registry the allocation is defined in.
    #[cfg_attr(not(test), expect(dead_code, reason = "read by the tests"))]
    source: &'static str,
}

/// An address prefix: the network address and its length in bits.
#[derive(Clone, Copy, Debug)]
enum Net {
    V4(Ipv4Addr, u32),
    V6(Ipv6Addr, u32),
}

impl Net {
    /// Whether `ip` is inside the prefix. An address of the other family never is.
    fn contains(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4(base, len), IpAddr::V4(v4)) => {
                (v4.to_bits() ^ base.to_bits()) & v4_mask(len) == 0
            }
            (Self::V6(base, len), IpAddr::V6(v6)) => {
                (v6.to_bits() ^ base.to_bits()) & v6_mask(len) == 0
            }
            _ => false,
        }
    }
}

/// The network bits of an IPv4 prefix of length `len`, which is at most 32.
const fn v4_mask(len: u32) -> u32 {
    match u32::MAX.checked_shl(32 - len) {
        Some(mask) => mask,
        None => 0,
    }
}

/// The network bits of an IPv6 prefix of length `len`, which is at most 128.
const fn v6_mask(len: u32) -> u128 {
    match u128::MAX.checked_shl(128 - len) {
        Some(mask) => mask,
        None => 0,
    }
}

/// An IPv4 row. A length over 32 or a host bit set in `octets` fails the build.
const fn v4(octets: [u8; 4], len: u32, name: &'static str, source: &'static str) -> Prefix {
    assert!(len <= 32, "an IPv4 prefix is at most 32 bits long");
    let base = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    assert!(
        base.to_bits() & !v4_mask(len) == 0,
        "a prefix row sets no host bits"
    );
    Prefix {
        net: Net::V4(base, len),
        name,
        source,
    }
}

/// An IPv6 row, written as its leading segments with the rest zero. A length
/// over 128 or a host bit set fails the build.
const fn v6(leading: &[u16], len: u32, name: &'static str, source: &'static str) -> Prefix {
    assert!(len <= 128, "an IPv6 prefix is at most 128 bits long");
    let mut segments = [0u16; 8];
    let mut index = 0;
    while index < leading.len() {
        segments[index] = leading[index];
        index += 1;
    }
    let [a, b, c, d, e, f, g, h] = segments;
    let base = Ipv6Addr::new(a, b, c, d, e, f, g, h);
    assert!(
        base.to_bits() & !v6_mask(len) == 0,
        "a prefix row sets no host bits"
    );
    Prefix {
        net: Net::V6(base, len),
        name,
        source,
    }
}

/// The special-purpose prefixes in the private bucket, in both families.
///
/// The list is drawn from the IANA special-purpose address registries that
/// RFC 6890 set up, minus the entries [`is_never_allowed`] has already claimed.
/// Everything on it is either not globally reachable or not a destination an
/// internet-facing proxy has any business dialling, and every one of them is a
/// way past `allow_private_networks = false` if it is missing: `100.64.0.0/10` is where a
/// carrier-grade NAT keeps its subscribers, `198.18.0.0/15` is what some
/// networks number their own infrastructure with, `192.0.0.0/24` holds protocol
/// assignments including the DS-Lite `192.0.0.0/29` link, and `240.0.0.0/4` is
/// routed inside more than one large private network in practice.
///
/// Where an allocation has an IPv4 and an IPv6 half, the two rows sit together
/// under one comment. `docs/configuration.md` and `script/config.example.toml`
/// name every row; a unit test below holds them to it.
///
/// What is not a row: [`is_never_allowed`] (unspecified, broadcast and
/// multicast, which no switch opens), and the transition forms [`routed_form`]
/// unwraps before this table is consulted (IPv4-mapped, the well-known NAT64
/// prefix, 6to4 and Teredo), since those are judged by the IPv4 address they
/// carry rather than matched as a prefix. Teredo lies inside the `2001::/23`
/// row and is still judged that way, because the unwrapping runs first.
const PRIVATE_PREFIXES: &[Prefix] = &[
    // 0.0.0.0/8, "this host on this network" (RFC 6890 Table 1, from RFC 1122).
    // Only the all-zero address at the bottom of the block is
    // `is_never_allowed`, and that check runs first; the rest of it is a source
    // address a host uses before it has one, never a destination.
    v4([0, 0, 0, 0], 8, "This host on this network", "RFC 1122"),
    // Loopback. `::1` also lies inside the `::/96` row below.
    v4([127, 0, 0, 0], 8, "Loopback", "RFC 1122"),
    v6(
        &[0, 0, 0, 0, 0, 0, 0, 1],
        128,
        "Loopback Address",
        "RFC 4291",
    ),
    // Private-use space (RFC 1918) and its IPv6 counterpart, the unique local
    // address range `fc00::/7` (RFC 4193).
    v4([10, 0, 0, 0], 8, "Private-Use", "RFC 1918"),
    v4([172, 16, 0, 0], 12, "Private-Use", "RFC 1918"),
    v4([192, 168, 0, 0], 16, "Private-Use", "RFC 1918"),
    v6(&[0xfc00], 7, "Unique-Local", "RFC 4193"),
    // Link-local, `169.254.0.0/16` (RFC 3927) and `fe80::/10` (RFC 4291
    // §2.5.6). `169.254.169.254` is the cloud metadata address.
    v4([169, 254, 0, 0], 16, "Link Local", "RFC 3927"),
    v6(&[0xfe80], 10, "Link-Local Unicast", "RFC 4291"),
    // `fec0::/10`, the IPv6 site-local prefix RFC 3879 deprecated. It is here
    // despite having left the registry. New stacks treat it as global unicast,
    // which is exactly why it is worth denying: a network that numbered its
    // interior with it before 2004 still routes it, and nothing on the public
    // internet answers there, so a request for it is either a mistake or a way
    // in. Adjacent to link-local and, on a network old enough to still use it,
    // just as internal.
    v6(&[0xfec0], 10, "Site-Local (deprecated)", "RFC 3879"),
    // 100.64.0.0/10, shared address space (RFC 6598), the inside of a
    // carrier-grade NAT.
    v4([100, 64, 0, 0], 10, "Shared Address Space", "RFC 6598"),
    // `192.0.0.0/24` and `2001::/23`, IETF Protocol Assignments (RFC 6890 for
    // the IPv4 block, RFC 2928 for the IPv6 one). Both are refused whole.
    //
    // RFC 6890 Table 22 gives every one of the /23's Source, Destination,
    // Forwardable and Global attributes as "False[1]", and footnote [1] is
    // "Unless allowed by a more specific allocation". The allocations inside it
    // are the anycast service addresses `2001:1::1` (Port Control Protocol,
    // RFC 7723), `2001:1::2` (TURN, RFC 8155) and `2001:1::3` (DNS-SD Service
    // Registration Protocol, RFC 9665), Benchmarking `2001:2::/48` (RFC 5180),
    // AMT `2001:3::/32` (RFC 7450), AS112-v6 `2001:4:112::/48` (RFC 7535),
    // ORCHID `2001:10::/28` (RFC 4843), ORCHIDv2 `2001:20::/28` (RFC 7343), the
    // Drone Remote ID Protocol Entity Tags (DETs) prefix `2001:30::/28`
    // (RFC 9374), and Teredo `2001::/32` (RFC 4380). Apart from Teredo, this
    // proxy refuses each of them for a reason of its own. The anycast service
    // addresses, AMT and AS112 reach a service of the proxy's own network, for
    // the reason given below and beside the IPv4 rows that follow. Benchmarking
    // is what a lab numbers a device under test with. An ORCHID is a hash of a
    // host identity and a DET an identifier for a drone's remote identity:
    // neither is a locator, nothing forwards one, and a tunnel to it can only
    // hold a slot. The space between the allocations has no allocation to
    // allow it.
    //
    // Teredo is the one allocation inside the /23 that this row does not
    // decide. `routed_form` unwraps a Teredo address before the table is
    // consulted, so it is judged by the IPv4 address it carries and never
    // meets this row.
    //
    // Inside `192.0.0.0/24`, the PCP and TURN anycast addresses 192.0.0.9 and
    // 192.0.0.10 are not carved out. The IANA registry marks those two and the
    // three IPv6 ones globally reachable. An anycast address reaches the
    // instance nearest the sender, and through this proxy the sender is the
    // proxy. The service a client reaches is therefore the one of the proxy's
    // own network, which acts on the proxy's address: a PCP server opens a
    // mapping for the host that asked.
    v4([192, 0, 0, 0], 24, "IETF Protocol Assignments", "RFC 6890"),
    v6(&[0x2001], 23, "IETF Protocol Assignments", "RFC 2928"),
    // `192.52.193.0/24`, AMT relay discovery (RFC 7450). Its IPv6 half,
    // `2001:3::/32`, lies inside the `2001::/23` row.
    //
    // The IANA registry marks both globally reachable. RFC 7450 Section 4.1.4
    // says how they are used: "a gateway sends a message to an anycast IP
    // address within that prefix. This message is routed to the topologically
    // nearest relay that has advertised the prefix." Through this proxy the
    // sender is the proxy, so a client reaches the multicast relay of the
    // proxy's own network. That is the same reason the PCP and TURN anycast
    // addresses are refused.
    v4([192, 52, 193, 0], 24, "AMT", "RFC 7450"),
    // The AS112 prefixes. `192.31.196.0/24` and `2001:4:112::/48` serve DNAME
    // redirection (RFC 7535), and `192.175.48.0/24` and `2620:4f:8000::/48`
    // serve Direct Delegation (RFC 7534 Section 2.3). `2001:4:112::/48` lies
    // inside the `2001::/23` row.
    //
    // The IANA registries mark all four globally reachable. RFC 7534 Section 1
    // says how they are reached: "Each nameserver functions as a single node in
    // an AS112 anycast cloud [RFC4786] and is configured to answer
    // authoritatively for a particular set of nominated zones." Through this
    // proxy the sender is the proxy, so a client reaches the AS112 node nearest
    // the proxy. The same rule refuses the AMT relay discovery prefixes and the
    // anycast service addresses (D111).
    v4([192, 31, 196, 0], 24, "AS112-v4", "RFC 7535"),
    v4(
        [192, 175, 48, 0],
        24,
        "Direct Delegation AS112 Service",
        "RFC 7534",
    ),
    v6(
        &[0x2620, 0x4f, 0x8000],
        48,
        "Direct Delegation AS112 Service",
        "RFC 7534",
    ),
    // Benchmarking, `198.18.0.0/15` (RFC 2544). It is what a lab numbers a
    // device under test with, and some networks number their own
    // infrastructure with it, so a request for it is either a misconfiguration
    // or an attempt to reach that lab. Its IPv6 half, `2001:2::/48`, lies
    // inside the `2001::/23` row.
    v4([198, 18, 0, 0], 15, "Benchmarking", "RFC 2544"),
    // The documentation ranges: three IPv4 blocks (RFC 5737), and
    // `2001:db8::/32` (RFC 3849) and `3fff::/20` for IPv6. RFC 3849's block is
    // the one in long use; the IANA registry added `3fff::/20` as a second
    // documentation block in July 2024.
    //
    // Reachable nowhere by definition, and the ranges examples and test
    // fixtures are written with, so a request for one is a misconfiguration
    // rather than a destination, and it should not turn into a connection
    // attempt against whoever happens to announce them.
    v4([192, 0, 2, 0], 24, "Documentation (TEST-NET-1)", "RFC 5737"),
    v4(
        [198, 51, 100, 0],
        24,
        "Documentation (TEST-NET-2)",
        "RFC 5737",
    ),
    v4(
        [203, 0, 113, 0],
        24,
        "Documentation (TEST-NET-3)",
        "RFC 5737",
    ),
    v6(&[0x2001, 0xdb8], 32, "Documentation", "RFC 3849"),
    v6(&[0x3fff], 20, "Documentation", "RFC 9637"),
    // 192.88.99.0/24, 6to4 relay anycast (RFC 6890 Table 10, from RFC 3068).
    // RFC 7526 deprecated the relays and the registry kept the entry, so the
    // prefix now reaches whoever still announces it rather than any relay this
    // proxy meant to use.
    v4(
        [192, 88, 99, 0],
        24,
        "6to4 Relay Anycast (deprecated)",
        "RFC 7526",
    ),
    // 240.0.0.0/4, reserved (RFC 1112 §4). The broadcast address at the top of
    // it is already `is_never_allowed`, which runs first.
    v4([240, 0, 0, 0], 4, "Reserved", "RFC 1112"),
    // `100::/64` is the discard-only prefix (RFC 6666). Traffic to it is meant
    // to be black-holed, which makes it a way to ask this proxy to open a
    // tunnel that can only ever hold a slot.
    v6(&[0x0100], 64, "Discard-Only Address Block", "RFC 6666"),
    // `100:0:0:1::/64` is the Dummy IPv6 Prefix (RFC 9780). The IANA registry
    // marks it not globally reachable and not a destination. RFC 9780 Section 1
    // allocates it for the address written into the IP/UDP encapsulation of
    // management, control and OAM packets, where it is meant to raise an
    // exception and not to be delivered. Nothing answers there, so a tunnel to
    // it can only hold a slot.
    v6(&[0x0100, 0, 0, 1], 64, "Dummy IPv6 Prefix", "RFC 9780"),
    // `5f00::/16` is the Segment Routing (SRv6) SID block. The IANA registry
    // marks the block not globally reachable. A host with SRv6 routes can still
    // deliver it to an internal SID, which is the class
    // `allow_private_networks` is meant to gate.
    v6(&[0x5f00], 16, "Segment Routing (SRv6) SIDs", "RFC 9602"),
    // `64:ff9b:1::/48`, the local-use NAT64 prefix (RFC 8215), is here because
    // its contents cannot be read. An address here is a translation of some
    // IPv4 address, and the operator chooses where in the address that IPv4
    // address sits. RFC 8215 §5 says a reader must not guess: "they must not
    // make any assumptions regarding the syntax or properties of those
    // addresses (e.g., the existence and location of embedded IPv4 addresses)".
    // So the whole prefix is private, and it is `allow_private_networks` that
    // decides whether it may be dialled. See `embedded_ipv4` for what reading a
    // layout would cost.
    v6(
        &[0x64, 0xff9b, 1],
        48,
        "Local-Use IPv4/IPv6 Translation Prefix",
        "RFC 8215",
    ),
    // `::/96` is the deprecated IPv4-compatible range (RFC 4291 §2.5.5.1), and
    // `::1` with it. Refused rather than treated as ordinary IPv6: stacks that
    // still honour the range route `::127.0.0.1` to loopback, which would
    // otherwise be a second way around the IPv4 rules. It is not unwrapped like
    // the transition forms, because that would turn `::1` into 0.0.0.1. The
    // unspecified address is in here too, but `is_never_allowed` has already
    // claimed it.
    v6(&[], 96, "IPv4-compatible (deprecated)", "RFC 4291"),
];

/// The IPv4 address an IPv6 transition address carries, if it carries one.
///
/// A host that routes any of these reaches the embedded IPv4 address, so this is
/// what the IPv4 rules must be applied to. Otherwise `2002:0a00:0001::` is a
/// route to 10.0.0.1 that `allow_private_networks = false` never sees.
///
/// The three forms that matter here:
///
/// * `64:ff9b::/96`: the well-known NAT64 prefix (RFC 6052 §2.1), with the
///   address in the last 32 bits;
/// * `2002::/16`: 6to4 (RFC 3056), with the address at bits 16-47;
/// * `2001::/32`: Teredo (RFC 4380 §4). The client's own IPv4 address is the
///   last 32 bits with every bit inverted, which is the one this proxy would
///   reach.
///
/// The deprecated `::/96` IPv4-compatible range is deliberately **not** here:
/// unwrapping it would turn `::1` into 0.0.0.1 and lose the loopback meaning, so
/// its row in [`PRIVATE_PREFIXES`] claims it whole instead.
///
/// # The local-use prefix is refused whole rather than read
///
/// The well-known prefix is fixed at /96 by RFC 6052 §3.1, so there is one
/// answer for it. `64:ff9b:1::/48` is not like that. RFC 8215 §5: "64:ff9b:1::/48
/// is intended as a technology-agnostic and generic reservation. A network
/// operator may freely use it in combination with any kind of IPv4/IPv6
/// translation mechanism deployed within their network." The same section
/// forbids reading one of these addresses: "By default, IPv6 nodes and
/// applications must not treat IPv6 addresses within 64:ff9b:1::/48 differently
/// from other globally scoped IPv6 addresses. In particular, they must not make
/// any assumptions regarding the syntax or properties of those addresses (e.g.,
/// the existence and location of embedded IPv4 addresses)". RFC 6052 §2.2
/// allows prefix lengths of 32, 40, 48, 56, 64 and 96, and the four that are /48
/// or longer fit inside this reservation, each with the address in a different
/// place. Nothing in an address says which of them produced it.
///
/// Picking one layout judges an address deployed at another by octets no
/// translator will send to, and the direction of that error is not always the
/// refusing one: at the /64 layout the operator's subnet octets are read as the
/// first half of the address, so a subnet that spells a public IPv4 prefix hides
/// a private target from `allow_private_networks = false`. So this function
/// reads no layout at all, and the whole /48 is a row of [`PRIVATE_PREFIXES`]
/// instead.
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

    /// The first and last address of a prefix.
    fn edges(net: Net) -> (IpAddr, IpAddr) {
        match net {
            Net::V4(base, len) => {
                let first = base.to_bits();
                let last = first | !v4_mask(len);
                (
                    IpAddr::V4(Ipv4Addr::from_bits(first)),
                    IpAddr::V4(Ipv4Addr::from_bits(last)),
                )
            }
            Net::V6(base, len) => {
                let first = base.to_bits();
                let last = first | !v6_mask(len);
                (
                    IpAddr::V6(Ipv6Addr::from_bits(first)),
                    IpAddr::V6(Ipv6Addr::from_bits(last)),
                )
            }
        }
    }

    /// The address one below `ip`, if there is one.
    fn below(ip: IpAddr) -> Option<IpAddr> {
        match ip {
            IpAddr::V4(v4) => v4
                .to_bits()
                .checked_sub(1)
                .map(|bits| Ipv4Addr::from_bits(bits).into()),
            IpAddr::V6(v6) => v6
                .to_bits()
                .checked_sub(1)
                .map(|bits| Ipv6Addr::from_bits(bits).into()),
        }
    }

    /// The address one above `ip`, if there is one.
    fn above(ip: IpAddr) -> Option<IpAddr> {
        match ip {
            IpAddr::V4(v4) => v4
                .to_bits()
                .checked_add(1)
                .map(|bits| Ipv4Addr::from_bits(bits).into()),
            IpAddr::V6(v6) => v6
                .to_bits()
                .checked_add(1)
                .map(|bits| Ipv6Addr::from_bits(bits).into()),
        }
    }

    /// The verdicts of the default and the permissive policy, in that order.
    fn verdicts(address: IpAddr) -> (bool, bool) {
        (
            policy(false, &[]).allows_address(address),
            policy(true, &[]).allows_address(address),
        )
    }

    /// Every row of the table, at both of its edges and at the address just
    /// outside each edge.
    ///
    /// Inside a row: refused by default and allowed once private networks are,
    /// unless the address is one [`is_never_allowed`] claims first (`0.0.0.0` at
    /// the bottom of `0.0.0.0/8`, `::` at the bottom of `::/96`, the broadcast
    /// address at the top of `240.0.0.0/4`), in which case it is refused by both
    /// and the next address inward is held to the row instead. An address that
    /// carries an IPv4 address (Teredo, 6to4, NAT64) is judged as that address,
    /// so for it the row is not the rule and the test asserts that instead.
    ///
    /// Just outside a row: outside the row itself, and then judged by what does
    /// cover it, if anything: another row, `is_never_allowed`, an embedded IPv4
    /// address, or nothing, in which case both policies allow it. That last case
    /// is what catches a check outside the table that claims more than the
    /// table says.
    #[test]
    fn every_row_is_refused_to_its_edges_and_no_further() {
        let covered =
            |address: IpAddr| PRIVATE_PREFIXES.iter().any(|row| row.net.contains(address));

        for row in PRIVATE_PREFIXES {
            let (first, last) = edges(row.net);
            let label = format!("{} ({}, {:?})", row.name, row.source, row.net);

            for (edge, inward) in [(first, above(first)), (last, below(last))] {
                assert!(row.net.contains(edge), "{edge} is an edge of {label}");
                let routed = routed_form(edge);
                if routed != edge {
                    assert_eq!(
                        verdicts(edge),
                        verdicts(routed),
                        "{edge} in {label} carries {routed} and is judged as it"
                    );
                    continue;
                }
                let held = if is_never_allowed(edge) {
                    assert_eq!(verdicts(edge), (false, false), "{edge} is never allowed");
                    inward.expect("a row of more than one address")
                } else {
                    edge
                };
                assert!(row.net.contains(held), "{held} is inside {label}");
                assert_eq!(
                    verdicts(held),
                    (false, true),
                    "{held} is inside {label}: refused by default, allowed once private networks are"
                );
            }

            for neighbour in [below(first), above(last)].into_iter().flatten() {
                assert!(
                    !row.net.contains(neighbour),
                    "{neighbour} is outside {label}"
                );
                let routed = routed_form(neighbour);
                let expected = if is_never_allowed(routed) {
                    (false, false)
                } else if routed != neighbour {
                    verdicts(routed)
                } else if covered(neighbour) {
                    (false, true)
                } else {
                    (true, true)
                };
                assert_eq!(
                    verdicts(neighbour),
                    expected,
                    "{neighbour} is just outside {label}"
                );
            }
        }
    }

    /// How `docs/configuration.md` and `script/config.example.toml` write a row:
    /// a bare address for a single-address row, `address/length` otherwise.
    fn written(net: Net) -> String {
        match net {
            Net::V4(base, 32) => base.to_string(),
            Net::V6(base, 128) => base.to_string(),
            Net::V4(base, len) => format!("{base}/{len}"),
            Net::V6(base, len) => format!("{base}/{len}"),
        }
    }

    /// Whether `text` names `token` as a whole address or prefix.
    ///
    /// A match inside a longer literal does not count: `::1` inside
    /// `::127.0.0.1`, or `::/96` inside `64:ff9b::/96`. A full stop after the
    /// token ends a sentence unless a digit follows it.
    fn names(text: &str, token: &str) -> bool {
        let literal = |c: char| c.is_ascii_hexdigit() || c == ':' || c == '/';
        text.match_indices(token).any(|(at, _)| {
            let before = text[..at].chars().next_back();
            let mut after = text[at + token.len()..].chars();
            let next = after.next();
            let continues = match next {
                Some('.') => after.next().is_some_and(|c| c.is_ascii_digit()),
                Some(c) => literal(c),
                None => false,
            };
            !before.is_some_and(|c| literal(c) || c == '.') && !continues
        })
    }

    /// The heading in `docs/configuration.md` above the table of refused ranges.
    const RANGES_HEADING: &str = "### Ranges refused unless `allow_private_networks` is on";

    /// The text that lists the refused ranges, in both places.
    ///
    /// In `docs/configuration.md` that is the section under [`RANGES_HEADING`],
    /// up to the next heading. In `script/config.example.toml` it is the comment
    /// block between `[security]` and the commented key.
    fn private_networks_documentation() -> [(&'static str, String); 2] {
        let page = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/configuration.md"
        ))
        .expect("docs/configuration.md must exist");
        let section: Vec<&str> = page
            .lines()
            .skip_while(|line| !line.starts_with(RANGES_HEADING))
            .skip(1)
            .take_while(|line| !line.starts_with('#'))
            .collect();
        assert!(
            section.iter().any(|line| line.starts_with("| `")),
            "docs/configuration.md lists the refused ranges in a table under {RANGES_HEADING:?}"
        );
        let section = section.join("\n");

        let example = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/script/config.example.toml"
        ))
        .expect("script/config.example.toml must exist");
        let block: Vec<&str> = example
            .lines()
            .skip_while(|line| *line != "[security]")
            .take_while(|line| !line.starts_with("#allow_private_networks"))
            .collect();
        assert!(
            block.len() > 1,
            "script/config.example.toml has a [security] comment block above allow_private_networks"
        );

        [
            ("docs/configuration.md", section),
            ("script/config.example.toml", block.join("\n")),
        ]
    }

    /// Both places that list the refused ranges for the operator name every row
    /// of the table.
    #[test]
    fn the_docs_name_every_refused_prefix() {
        for (file, text) in private_networks_documentation() {
            let missing: Vec<String> = PRIVATE_PREFIXES
                .iter()
                .map(|row| (written(row.net), row.name))
                .filter(|(token, _)| !names(&text, token))
                .map(|(token, name)| format!("{token} ({name})"))
                .collect();
            assert!(
                missing.is_empty(),
                "{file} does not name these refused prefixes where it documents \
                 allow_private_networks: {missing:?}"
            );
        }
    }

    /// The matcher [`the_docs_name_every_refused_prefix`] relies on.
    #[test]
    fn a_prefix_is_named_only_as_a_whole_literal() {
        assert!(names("loopback (`::1`)", "::1"));
        assert!(names("ends with 10.0.0.0/8.", "10.0.0.0/8"));
        assert!(names("# 2001:db8::/32, 100::/64", "100::/64"));
        assert!(!names("`::127.0.0.1`", "::1"));
        assert!(!names("`64:ff9b::/96`", "::/96"));
        assert!(!names("`2100::/64`", "100::/64"));
        assert!(!names("`10.0.0.0/80`", "10.0.0.0/8"));
        assert!(!names("`110.0.0.0/8`", "10.0.0.0/8"));
    }

    /// Ordinary public addresses, and the stated neighbours the table test does
    /// not reach.
    const PUBLIC: &[&str] = &[
        "1.1.1.1",
        "8.8.8.8",
        "93.184.216.34",
        // 224/4 through 239/8 is multicast and sits in NEVER, so the last public
        // address below the reserved block 240.0.0.0/4 is the one at the top of
        // 223/8. The table test sees only the multicast address just below it.
        "223.255.255.255",
        "2001:4860:4860::8888",
        "2606:4700::1111",
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

    /// `192.0.0.0/24` is refused whole, its two anycast service addresses
    /// and the NAT64 discovery addresses included.
    ///
    /// The registry marks `192.0.0.9` (PCP anycast) and `192.0.0.10` (TURN
    /// anycast) globally reachable. Through this proxy an anycast address
    /// reaches the instance nearest the proxy, which is a service of the
    /// proxy's own network, so both stay private with the rest of the block,
    /// and both still follow the switch.
    #[test]
    fn the_protocol_anycast_addresses_stay_inside_the_ietf_block() {
        let strict = policy(false, &[]);
        let permissive = policy(true, &[]);
        for address in [
            "192.0.0.8",
            "192.0.0.9",
            "192.0.0.10",
            "192.0.0.11",
            "192.0.0.170",
            "192.0.0.171",
        ] {
            assert!(
                !strict.allows_address(ip(address)),
                "{address} is in 192.0.0.0/24 and must be denied by default"
            );
            assert!(
                permissive.allows_address(ip(address)),
                "{address} must follow allow_private_networks"
            );
        }
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

    /// The local-use NAT64 prefix is private as a whole, at every layout.
    ///
    /// RFC 8215 §5 forbids assuming where the IPv4 address sits inside
    /// `64:ff9b:1::/48`, so this proxy does not look for one. Each address below
    /// is a translation of 10.0.0.1 at one of the RFC 6052 §2.2 layouts that fit
    /// inside that /48, and in each of them the four octets a /48 reader takes
    /// spell a public address instead. Reading the layout would therefore let a
    /// private target past `allow_private_networks = false`.
    #[test]
    fn the_local_use_nat64_prefix_is_private_at_every_layout() {
        let strict = policy(false, &[]);
        let permissive = policy(true, &[]);

        for (address, layout, misread) in [
            ("64:ff9b:1:80a:0:1::", "/56", "8.10.0.0"),
            ("64:ff9b:1:808:a:0:100:0", "/64", "8.8.10.0"),
            ("64:ff9b:1:808:8:800:a00:1", "/96", "8.8.8.8"),
        ] {
            assert!(
                !strict.allows_address(ip(address)),
                "{address} translates 10.0.0.1 at the {layout} layout \
                 and must be denied rather than read as {misread}"
            );
            assert!(
                permissive.allows_address(ip(address)),
                "{address} is private and must follow the switch"
            );
        }
    }

    /// The extraction itself, address by address.
    ///
    /// The bucket assertions above would pass on a near-miss — 169.254.0.169 is
    /// as link-local as 169.254.169.254 — so the exact value is asserted here.
    #[test]
    fn the_embedded_ipv4_is_extracted_exactly() {
        for (address, expected) in [
            // RFC 6052 §2.1: the well-known prefix, address in the last 32 bits.
            ("64:ff9b::7f00:1", "127.0.0.1"),
            ("64:ff9b::808:808", "8.8.8.8"),
            ("64:ff9b::", "0.0.0.0"),
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

        // Everything else carries nothing: the local-use prefix whose layout must
        // not be guessed, the ranges that merely look adjacent, and the
        // deprecated `::/96` form that must stay whole.
        for address in [
            "64:ff9b:1::1",              // the local-use prefix, read at no layout
            "64:ff9b:1:a9fe:a9:fe00::",  // the /48 layout, once read as 169.254.169.254
            "64:ff9b:1:808:8:800:a00:1", // the /96 layout, once read as 8.8.8.8
            "2001:db8::1",               // documentation, not Teredo
            "2003::1",                   // not 6to4
            "64:ff9c::1",                // not the NAT64 prefix
            "64:ff9b:2::1",              // outside the local-use prefix
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

    /// `2001::/23` is refused whole, the space between its allocations
    /// included, and the address on each side of it is not.
    ///
    /// Every address below lies in the /23 outside Teredo and outside every
    /// allocation the registry lists there, so the /23 row is the only rule that
    /// refuses it. `2001:db8::/32` sits above the /23 and is refused by its own
    /// row.
    #[test]
    fn the_whole_ietf_protocol_assignments_block_is_refused() {
        let strict = policy(false, &[]);
        let permissive = policy(true, &[]);

        for address in [
            "2001:1::",                               // below the PCP anycast address
            "2001:1::4",                              // above the DNS-SD SRP anycast address
            "2001:1:0:0:1::1",                        // elsewhere in 2001:1::/32
            "2001:1:ffff:ffff:ffff:ffff:ffff:ffff",   // just below 2001:2::/48
            "2001:2:1::",                             // just above it
            "2001:4::1",                              // above the AMT prefix 2001:3::/32
            "2001:4:113::",                           // just above AS112-v6
            "2001:f:ffff:ffff:ffff:ffff:ffff:ffff",   // just below ORCHID
            "2001:40::",                              // just above DETs
            "2001:100::1",                            // unallocated
            "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", // the last address of the /23
        ] {
            assert!(
                !strict.allows_address(ip(address)),
                "{address} is inside 2001::/23 and must be refused by default"
            );
            assert!(
                permissive.allows_address(ip(address)),
                "{address} must follow allow_private_networks"
            );
        }

        for address in ["2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:200::"] {
            assert!(
                strict.allows_address(ip(address)),
                "{address} is just outside 2001::/23 and stays public"
            );
        }

        assert!(
            !strict.allows_address(ip("2001:db8::")),
            "2001:db8::/32 is refused by its own row"
        );
    }

    /// Teredo, `2001::/32`, is judged by the IPv4 address it carries under both
    /// policies, whatever else the table refuses around it.
    ///
    /// The prefix lies inside `2001::/23`. [`Policy::allows_address`] unwraps a
    /// Teredo address with [`routed_form`] before any row is consulted, so a row
    /// covering the /23 never sees one.
    #[test]
    fn teredo_follows_its_embedded_address_inside_the_ietf_block() {
        let strict = policy(false, &[]);
        let permissive = policy(true, &[]);

        for (address, carried) in [
            ("2001:0:0:0:0:0:f7f7:f7f7", "8.8.8.8"),
            ("2001:0:808:808:8000:f227:fefe:fefe", "1.1.1.1"),
            // Near the top of the /32.
            ("2001:0:ffff:ffff:ffff:ffff:f7f7:f7f7", "8.8.8.8"),
            ("2001:0:a00:1:0:0:a247:27dd", "93.184.216.34"),
        ] {
            assert_eq!(
                embedded_ipv4(ip(address)).map(IpAddr::V4),
                Some(ip(carried))
            );
            assert!(
                strict.allows_address(ip(address)),
                "{address} carries the public {carried} and must be reachable"
            );
            assert!(permissive.allows_address(ip(address)), "{address}");
        }

        for (address, carried) in [
            ("2001:0:0:0:0:0:f5ff:fffe", "10.0.0.1"),
            ("2001:0:808:808:0:0:80ff:fffe", "127.0.0.1"),
            ("2001:0:ffff:ffff:ffff:ffff:5601:5601", "169.254.169.254"),
        ] {
            assert_eq!(
                embedded_ipv4(ip(address)).map(IpAddr::V4),
                Some(ip(carried))
            );
            assert!(
                !strict.allows_address(ip(address)),
                "{address} carries the private {carried} and must be refused"
            );
            assert!(
                permissive.allows_address(ip(address)),
                "{address} must follow the switch like {carried}"
            );
        }
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
            // Transition forms of the unspecified address: the routed form is
            // 0.0.0.0, so a DNS64 network's blocked answer arrives as an IPv6
            // address that looks global and still routes to 0.0.0.0.
            &["[64:ff9b::]:443"][..],
            &["[2002::]:443"][..],
            // Teredo: the last 32 bits are the client address with every bit
            // inverted, so all-ones there decodes to 0.0.0.0.
            &["[2001::ffff:ffff]:443"][..],
        ] {
            assert!(
                is_dns_blackhole(&addresses(literals)),
                "{literals:?} is a filtered answer and must be recognised as one"
            );
        }
    }

    /// The half of the rule that keeps SSRF probes on the policy-refusal line:
    /// anything that is not *only* the unspecified address stays an ordinary
    /// policy refusal.
    #[test]
    fn private_and_mixed_answers_are_not_blackholes() {
        for literals in [
            // A private address alongside the blackhole is still a private
            // address, and reaching for it is the thing worth reporting.
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
