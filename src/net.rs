//! Socket helpers: name resolution and UDP socket setup.
//!
//! Resolution is deliberately explicit rather than left to
//! `TcpStream::connect`'s implicit lookup. Two later requirements depend on
//! seeing the resolved addresses:
//!
//! * RFC 9298 §3.1 requires a CONNECT-UDP request to be resolved *before* the
//!   2xx response is sent.
//! * The destination ACL ([`crate::policy`]) can only filter what it can see.
//!
//! A lookup can ask for one address family. With `ip_family_preference` at
//! `ipv4` or `ipv6`, a tunnel's name is looked up in the preferred family
//! first ([`ConnectionResolver::lookup_family`]), so the C library sends one
//! query of that family and the tunnel waits for that answer alone. The other
//! family's lookup ([`OtherFamily`]) starts at the same moment when the
//! connection has a lookup slot to spare, and otherwise only when a tunnel
//! needs it: when the preferred family gave no usable address, or when every
//! preferred address failed to connect. With `system`, a name is one lookup of
//! both families through `std`, as `TcpStream::connect` would make it. Every
//! lookup takes a slot of the D90 budget and holds it until the resolver
//! returns.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

use crate::config::IpFamilyPreference;

/// One address family, as a lookup can be limited to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// A records, IPv4 addresses.
    Ipv4,
    /// AAAA records, IPv6 addresses.
    Ipv6,
}

impl Family {
    /// The family `preference` asks for first, or `None` for
    /// [`System`](IpFamilyPreference::System), which asks for both in one call.
    pub fn preferred(preference: IpFamilyPreference) -> Option<Self> {
        match preference {
            IpFamilyPreference::Ipv4 => Some(Self::Ipv4),
            IpFamilyPreference::Ipv6 => Some(Self::Ipv6),
            IpFamilyPreference::System => None,
        }
    }

    /// The family that is not this one.
    pub fn other(self) -> Self {
        match self {
            Self::Ipv4 => Self::Ipv6,
            Self::Ipv6 => Self::Ipv4,
        }
    }

    /// Whether `address` is of this family.
    fn holds(self, address: &SocketAddr) -> bool {
        address.is_ipv6() == (self == Self::Ipv6)
    }
}

/// Whether a lookup error says the name has no address of the family asked
/// for, rather than that the lookup itself failed.
///
/// That is `EAI_NODATA` from a lookup of one family, and an answer that held
/// no address at all. Both carry a private marker type, which is what this
/// checks for. The [`io::ErrorKind`] alone cannot say it: an `EAI_SYSTEM`
/// failure carries the `errno` of the call, and that can be `ENOENT`.
pub fn is_no_data(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<NoAddress>())
}

/// The error of a lookup that found the name but no address of the family it
/// asked for. Its text is the resolver's own.
#[derive(Debug)]
struct NoAddress(String);

impl std::fmt::Display for NoAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NoAddress {}

/// A [`NoAddress`] error with `message` as its text.
fn no_address(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, NoAddress(message))
}

/// `host` read as an IP address, which resolves to itself.
///
/// An IPv6 literal is written bare: the brackets belong to the syntax a target
/// arrived in, and each of the two places a target arrives has already taken
/// them off: `tunnel::tcp` splitting an RFC 3986 authority, `tunnel::udp`
/// decoding an RFC 9298 template, which carries them bare to begin with.
/// Stripping them here as well would mean accepting a host neither of those
/// produced, and answering `example.com]:443` by dialling `example.com`.
pub(crate) fn literal(host: &str, port: u16) -> Option<SocketAddr> {
    host.parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, port))
}

/// The answer of a lookup [`System::spawn`] started.
///
/// Takes the handle by reference so that a caller that stops waiting keeps it
/// and can wait again later ([`OtherFamily::addresses`]). A handle must not be
/// polled again once this has returned.
async fn answered(
    host: &str,
    lookup: &mut JoinHandle<io::Result<Vec<SocketAddr>>>,
) -> io::Result<Vec<SocketAddr>> {
    let addresses = match lookup.await {
        Ok(addresses) => addresses?,
        // The runtime is shutting down, or the resolver call panicked. Neither
        // is an answer about the name.
        Err(error) => return Err(io::Error::other(error)),
    };

    if addresses.is_empty() {
        return Err(no_address(format!("{host} resolved to no addresses")));
    }

    Ok(addresses)
}

/// The resolver a lookup is asked of.
///
/// In a build that is not a test there is one: the system's `getaddrinfo`.
/// The tests put a stand-in in its place (`ResolverBudget::per_connection_with`),
/// so that they say what each family answers and when, on tokio's clock.
#[derive(Clone)]
enum System {
    /// `getaddrinfo`, on a thread of the blocking pool.
    Getaddrinfo,
    /// A test's stand-in, run as a task of the runtime.
    #[cfg(test)]
    StandIn(StandIn),
}

/// A test's stand-in for `getaddrinfo`: the addresses `host` has in the
/// family asked for, or in both for `None`, with the port still to be set.
#[cfg(test)]
pub(crate) type StandIn = Arc<
    dyn Fn(
            &str,
            Option<Family>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = io::Result<Vec<std::net::IpAddr>>> + Send>,
        > + Send
        + Sync,
>;

impl std::fmt::Debug for System {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Getaddrinfo => f.write_str("Getaddrinfo"),
            #[cfg(test)]
            Self::StandIn(_) => f.write_str("StandIn"),
        }
    }
}

impl System {
    /// Starts a lookup of `host` in `family`, or in both families for `None`,
    /// holding `slot` until it returns.
    ///
    /// `None` is the call `std::net::ToSocketAddrs` makes, unchanged. A family
    /// is asked through [`one_family`].
    ///
    /// The blocking task is spawned here rather than left to
    /// `tokio::net::lookup_host`, which spawns the same task, because the slot
    /// has to be dropped by the *thread*, not by the future. A `connect_timeout`
    /// that expires drops the caller, and `getaddrinfo` is not cancellable: the
    /// thread stays in the resolver until the stub gives up, five seconds per
    /// attempt on a stock `resolv.conf` and tens of seconds where the nameserver
    /// answers nothing at all. A slot released at that moment would say a
    /// thread is free while the thread it stands for is still gone, which is
    /// the accounting that lets a client park the pool one `connect_timeout` at
    /// a time (D90).
    fn spawn(
        &self,
        host: &str,
        port: u16,
        family: Option<Family>,
        slot: LookupSlot,
    ) -> JoinHandle<io::Result<Vec<SocketAddr>>> {
        let owned = host.to_owned();
        match self {
            Self::Getaddrinfo => tokio::task::spawn_blocking(move || {
                let addresses = match family {
                    None => std::net::ToSocketAddrs::to_socket_addrs(&(owned.as_str(), port))
                        .map(Iterator::collect),
                    Some(family) => one_family(&owned, port, family),
                };
                // Explicit, and last: the slot is what the thread is holding,
                // so it is given back where the thread finishes rather than
                // where the caller does.
                drop(slot);
                addresses
            }),
            #[cfg(test)]
            Self::StandIn(stand_in) => {
                let answer = stand_in(&owned, family);
                tokio::spawn(async move {
                    let answer = answer.await;
                    drop(slot);
                    answer.map(|ips| {
                        ips.into_iter()
                            .map(|ip| SocketAddr::new(ip, port))
                            .collect()
                    })
                })
            }
        }
    }
}

/// Asks the system resolver for the addresses of `host` in `family` alone.
///
/// The hint is what makes the C library send one query: with `AF_INET` musl
/// and glibc send an A query and no AAAA query, and with `AF_INET6` the
/// reverse. `std` passes no family, so it always waits for both answers.
///
/// The socket type is `SOCK_STREAM`, as `std` asks, because without one every
/// address comes back once per socket type. `EAI_NODATA`, a name with no
/// address of this family, becomes a [`NoAddress`] error with the resolver's
/// text; every other error keeps the text `std` would give it.
fn one_family(host: &str, port: u16, family: Family) -> io::Result<Vec<SocketAddr>> {
    let hints = dns_lookup::AddrInfoHints {
        socktype: dns_lookup::SockType::Stream.into(),
        address: match family {
            Family::Ipv4 => dns_lookup::AddrFamily::Inet,
            Family::Ipv6 => dns_lookup::AddrFamily::Inet6,
        }
        .into(),
        ..dns_lookup::AddrInfoHints::default()
    };

    let answers = dns_lookup::getaddrinfo(Some(host), None, Some(hints)).map_err(lookup_error)?;
    Ok(one_family_list(
        answers.map(|answer| answer.map(|answer| answer.sockaddr)),
        port,
        family,
    ))
}

/// A `dns-lookup` error as the [`io::Error`] the rest of the crate reads.
fn lookup_error(error: dns_lookup::LookupError) -> io::Error {
    match error.kind() {
        dns_lookup::LookupErrorKind::NoData => no_address(error.to_string()),
        _ => error.into(),
    }
}

/// The addresses of one family's answer, in the resolver's order, each once
/// and with `port` set.
///
/// The C library hands back every address with port 0, because no service
/// was named. An entry it cannot read is skipped, as `std` skips one. An
/// address of the other family is dropped, so the list is of `family` whatever
/// the C library does with the hint. An address it lists twice is kept once:
/// glibc lists `127.0.0.1` twice for `localhost` under an IPv4 hint, because
/// it reads the `::1 localhost` line of `/etc/hosts` as `127.0.0.1` too.
fn one_family_list(
    answers: impl Iterator<Item = io::Result<SocketAddr>>,
    port: u16,
    family: Family,
) -> Vec<SocketAddr> {
    let mut addresses: Vec<SocketAddr> = Vec::new();
    for mut address in answers.filter_map(Result::ok) {
        address.set_port(port);
        if family.holds(&address) && !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses
}

/// Name lookups the whole process may have in flight beyond the one every
/// connection keeps in reserve.
///
/// The number this bounds is threads, not queries: a lookup holds a thread of
/// the runtime's *blocking* pool until `getaddrinfo` returns, whatever the
/// client does meanwhile ([`System::spawn`]). So an unbounded proxy
/// converts one client's black-holed names directly into parked threads, and the
/// pool is process-wide: with the default `max_connections` x
/// `max_targets_per_conn` at 65 536 in-flight requests against tokio's 512
/// threads, two connections' worth of hung lookups leave every *other*
/// connection's resolution waiting for a thread, including names that never
/// needed the resolver at all (D90).
pub const SHARED_LOOKUPS: usize = 128;

/// Lookups one connection may take from [`SHARED_LOOKUPS`] at once.
///
/// The reserved slot below is what guarantees progress; this is what keeps the
/// guarantee worth having. A connection opening a page's worth of tunnels wants
/// its lookups to run at once, so the figure is well clear of a browser's
/// per-page domain count, and four connections at it exhaust the shared
/// allowance. That is the point at which everyone else falls back on their
/// reserved slot rather than on nothing.
pub const BURST_LOOKUPS: usize = 32;

/// Blocking threads the pool keeps clear of name resolution.
///
/// One other user of the blocking pool exists: the `SIGHUP` reload, which
/// `main` runs through `spawn_blocking` because it reads and parses files.
/// The headroom is what keeps a reload from queueing behind lookups when every
/// lookup slot is taken, and one reload at a time needs one thread of it. The
/// rest is for the day another user appears, and so that the arithmetic below
/// never has to be exact. D90 says to recompute this when one does.
pub const LOOKUP_FREE_THREADS: usize = 64;

/// Connections the blocking pool is sized to reserve a lookup slot for.
///
/// `max_connections` is an operator's number and may be raised without limit (or
/// switched off entirely, which is what `0` means), while a thread is a real
/// resource. Past this ceiling the reservation is best-effort: connections still
/// have their slot, but the server-wide reserved allowance
/// ([`reserved_lookups`]) has fewer permits than there are connections, so a
/// reserved lookup may wait for another connection's to finish.
pub const RESERVED_LOOKUP_CEILING: usize = 1024;

/// Reserved-slot lookups the whole server may have in flight at once:
/// `min(max_connections, 1024)`, and the ceiling when `max_connections` is `0`.
///
/// One per connection the pool is sized for. A reserved-slot lookup holds one
/// of these as well as its connection's own slot and gives both back in the
/// blocking thread, so connection turnover cannot hand out more reserved slots
/// than the pool has threads for (D90).
///
/// Read from `max_connections` once, at startup, like [`blocking_pool_size`],
/// because it is the pool's number. A `SIGHUP` that changes `max_connections`
/// changes neither.
// A `u32` is always a `usize` on both supported targets, and a `const fn` may
// not call `TryFrom` to say so.
#[allow(clippy::as_conversions)]
pub const fn reserved_lookups(max_connections: u32) -> usize {
    // `0` is "uncapped", so there is nothing to size against and the ceiling is
    // the answer. Written out rather than as `min` because a `const fn` may not
    // call `Ord::min`, and this is a constant in the tests that check it.
    if max_connections == 0 || max_connections as usize > RESERVED_LOOKUP_CEILING {
        RESERVED_LOOKUP_CEILING
    } else {
        max_connections as usize
    }
}

/// The blocking pool the runtime is built with, in threads.
///
/// Sized from the configuration rather than left at tokio's 512 so that the two
/// numbers that matter are related on purpose: every connection's reserved
/// lookup slot has a thread to run on, the shared allowance has its own, and
/// [`LOOKUP_FREE_THREADS`] are left over. Threads are created on demand and
/// reaped when idle, so this is a ceiling and not an allocation: a server with
/// three clients holds three of them.
///
/// Startup-only: a `SIGHUP` that raises `max_connections` does not resize the
/// pool, and does not grow [`reserved_lookups`] either, so the reservation for
/// the connections it adds is best-effort in the same way
/// [`RESERVED_LOOKUP_CEILING`] describes.
pub const fn blocking_pool_size(max_connections: u32) -> usize {
    reserved_lookups(max_connections) + SHARED_LOOKUPS + LOOKUP_FREE_THREADS
}

/// The server's share of the blocking pool, handed out one connection at a time.
///
/// Every connection gets its own view of it ([`ResolverBudget::per_connection`]),
/// which is the whole design: what one connection can take away from the
/// others is bounded, and what it keeps for itself cannot be taken by another
/// connection. See [`ConnectionResolver`].
#[derive(Clone, Debug)]
pub struct ResolverBudget {
    /// The reserved allowance, [`reserved_lookups`] permits.
    reserved: Arc<Semaphore>,
    /// The shared allowance, [`SHARED_LOOKUPS`] permits.
    shared: Arc<Semaphore>,
}

impl ResolverBudget {
    /// The budget for one server whose blocking pool was sized from
    /// `max_connections` by [`blocking_pool_size`].
    pub fn new(max_connections: u32) -> Self {
        Self {
            reserved: Arc::new(Semaphore::new(reserved_lookups(max_connections))),
            shared: Arc::new(Semaphore::new(SHARED_LOOKUPS)),
        }
    }

    /// One connection's view of it.
    pub fn per_connection(&self) -> ConnectionResolver {
        self.view(System::Getaddrinfo)
    }

    /// One connection's view of it, asking `stand_in` instead of the system
    /// resolver. The budget is the real one.
    #[cfg(test)]
    pub(crate) fn per_connection_with(&self, stand_in: StandIn) -> ConnectionResolver {
        self.view(System::StandIn(stand_in))
    }

    /// The whole shared allowance, held until the permit is dropped, which is
    /// how hostile connections that never let go leave it.
    #[cfg(test)]
    pub(crate) fn hold_shared(&self) -> OwnedSemaphorePermit {
        self.shared
            .clone()
            .try_acquire_many_owned(u32::try_from(SHARED_LOOKUPS).expect("128 fits a u32"))
            .expect("the shared allowance starts whole")
    }

    fn view(&self, system: System) -> ConnectionResolver {
        ConnectionResolver {
            reserved: Arc::new(Semaphore::new(1)),
            reserved_allowance: self.reserved.clone(),
            burst: Arc::new(Semaphore::new(BURST_LOOKUPS)),
            shared: self.shared.clone(),
            system,
        }
    }
}

/// Burst permits a connection may have in use and still start the other
/// family's lookup at once: fewer than this many.
///
/// Half of [`BURST_LOOKUPS`]. Our own rule, not a protocol number. A
/// connection that opens a page's worth of tunnels at once therefore starts
/// each preferred lookup as it would without this rule, and starts few of the
/// second lookups beside them. A second lookup that is not started at once is
/// asked for later, if it is needed at all ([`OtherFamily`]).
pub const SPARE_BURST_IN_USE: usize = BURST_LOOKUPS / 2;

/// What one connection may ask the resolver to do at once.
///
/// Two tiers, because a single shared pool answers only one of the two questions
/// worth asking:
///
/// * **One reserved slot**, held by this connection alone and by nothing else.
///   No other connection can use it, so among live connections none is starved
///   outright: at worst its lookups run one at a time. This is the guarantee,
///   with the one limit the next sentence states; the shared allowance is only
///   ever an optimisation on top of it. After heavy connection turnover a
///   reserved lookup may wait for a permit of [`reserved_lookups`] that a
///   closed connection's lookup still holds, which is bounded by the host
///   resolver's timeout.
/// * **[`BURST_LOOKUPS`] from the shared allowance**, so ordinary use (a
///   client opening thirty tunnels at once) still resolves them in parallel,
///   while one connection can never hold more than its share of the pool.
///
/// The waiting itself is inside the caller's `connect_timeout`, so a lookup that
/// cannot get a slot in time is refused exactly as a resolver that did not
/// answer in time is, with the same 504 and the same `Proxy-Status` (D90).
/// One of these per connection, made by [`ResolverBudget::per_connection`] and
/// held for the connection's whole life by its [`crate::tunnel::Context`].
/// Deliberately not [`Clone`]: the bound is the connection's, so a second handle
/// counting separately would be no bound at all. With one owner, the
/// semaphores need no outer `Arc`; each has its own because `acquire_owned`
/// needs one.
#[derive(Debug)]
pub struct ConnectionResolver {
    /// This connection's own slot. One permit, never shared.
    reserved: Arc<Semaphore>,
    /// The server-wide reserved allowance, from [`ResolverBudget`].
    reserved_allowance: Arc<Semaphore>,
    /// How much of the shared allowance this connection may hold at once.
    burst: Arc<Semaphore>,
    /// The server-wide allowance, from [`ResolverBudget`].
    shared: Arc<Semaphore>,
    /// The resolver the lookups are asked of.
    system: System,
}

impl ConnectionResolver {
    /// The addresses of `host` in both families, in the resolver's order, with
    /// a slot in the blocking pool taken for the length of the lookup.
    ///
    /// An IP literal never reaches the resolver and so never occupies a thread:
    /// it is answered without taking a slot at all, which keeps the budget
    /// spent on the only thing that can block.
    pub async fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if let Some(address) = literal(host, port) {
            return Ok(vec![address]);
        }

        let slot = self.acquire().await;
        answered(host, &mut self.system.spawn(host, port, None, slot)).await
    }

    /// [`lookup`](Self::lookup) of `family` alone, with the lookup of the
    /// other family started beside it when this connection has a slot to spare.
    ///
    /// This lookup takes its slot exactly as [`lookup`](Self::lookup) does.
    /// Once it holds one, `other` is started at once if a slot of the shared
    /// allowance is spare ([`SPARE_BURST_IN_USE`]), and is left unstarted
    /// otherwise. Either way the answer
    /// returned is this family's alone, and it does not wait for `other`.
    ///
    /// `other` is borrowed rather than returned so that it keeps its lookup
    /// when the caller stops waiting for this one, which is what a
    /// `connect_timeout` that expires does.
    pub async fn lookup_family(
        &self,
        host: &str,
        port: u16,
        family: Family,
        other: &mut OtherFamily,
    ) -> io::Result<Vec<SocketAddr>> {
        if let Some(address) = literal(host, port) {
            return Ok(vec![address]);
        }

        let slot = self.acquire().await;
        let mut lookup = self.system.spawn(host, port, Some(family), slot);
        other.start_if_spare(self);
        answered(host, &mut lookup).await
    }

    /// A slot for a lookup nobody waits for yet, if one is free right now.
    ///
    /// Taken from the shared allowance only, and only while fewer than
    /// [`SPARE_BURST_IN_USE`] of this connection's burst permits are in use.
    /// Never the reserved slot, and never by waiting: a lookup that may not be
    /// needed must not take the slot that the next name's lookup waits for.
    fn spare(&self) -> Option<LookupSlot> {
        if BURST_LOOKUPS - self.burst.available_permits() >= SPARE_BURST_IN_USE {
            return None;
        }
        let burst = self.burst.clone().try_acquire_owned().ok()?;
        let shared = self.shared.clone().try_acquire_owned().ok()?;

        Some(LookupSlot::Shared {
            _burst: burst,
            _shared: shared,
        })
    }

    /// Takes this connection's reserved slot or a share of the allowance,
    /// whichever is free first.
    ///
    /// A race rather than a check-then-queue, because the reserved slot can
    /// free *while* a lookup waits: the shared allowance may not come back for
    /// tens of seconds under attack, while the reserved slot turns over as
    /// fast as this connection's own lookups finish. A lookup parked on the
    /// shared queue therefore keeps a claim on the reserved slot too. That is
    /// what makes "serial at worst" literally true instead of "one lookup per
    /// burst of arrivals". `biased` puts the reserved slot first so a free one
    /// is taken before the shared allowance is touched.
    ///
    /// Within each branch the order is not interchangeable: the per-connection
    /// permit is taken *first*, so a connection already at its own limit
    /// queues on that limit rather than on the server's, and never holds a
    /// server-wide permit while it waits on its own limit. Losing the race
    /// drops that branch and gives back whatever it held.
    ///
    /// No semaphore is ever closed, and a closed one is the only error
    /// `acquire_owned` has.
    async fn acquire(&self) -> LookupSlot {
        let from_reserved = async {
            let own = self
                .reserved
                .clone()
                .acquire_owned()
                .await
                .expect("the budget is never closed");
            let allowance = self
                .reserved_allowance
                .clone()
                .acquire_owned()
                .await
                .expect("the budget is never closed");

            LookupSlot::Reserved {
                _slot: own,
                _allowance: allowance,
            }
        };

        let from_shared = async {
            let burst = self
                .burst
                .clone()
                .acquire_owned()
                .await
                .expect("the budget is never closed");
            let shared = self
                .shared
                .clone()
                .acquire_owned()
                .await
                .expect("the budget is never closed");

            LookupSlot::Shared {
                _burst: burst,
                _shared: shared,
            }
        };

        tokio::select! {
            biased;
            slot = from_reserved => slot,
            slot = from_shared => slot,
        }
    }
}

/// A lookup's claim on the blocking pool, released when it is dropped.
///
/// Owned rather than borrowed because of where it is dropped: it travels into
/// the blocking task and is released there, outliving the future that asked for
/// it whenever a `connect_timeout` expires first. See [`System::spawn`].
#[derive(Debug)]
enum LookupSlot {
    /// The connection's own slot, and the server-wide reserved permit it
    /// stands for.
    ///
    /// Named with a leading underscore because it is never read: a permit is
    /// held, not consulted, and releasing it is what dropping this does.
    Reserved {
        _slot: OwnedSemaphorePermit,
        _allowance: OwnedSemaphorePermit,
    },
    /// One of the connection's burst permits, and the shared one it stands for.
    Shared {
        _burst: OwnedSemaphorePermit,
        _shared: OwnedSemaphorePermit,
    },
}

/// The lookup of the family a preference puts second.
///
/// Started beside the preferred family's lookup when the connection has a
/// slot to spare ([`ConnectionResolver::lookup_family`]), and otherwise only
/// when [`addresses`](Self::addresses) is first awaited, which a tunnel does
/// only once it needs this family. A lookup that has started holds its slot
/// until the resolver returns, as every lookup does, even when this value is
/// dropped first.
#[derive(Debug)]
pub struct OtherFamily {
    host: String,
    port: u16,
    family: Family,
    state: OtherState,
}

#[derive(Debug)]
enum OtherState {
    /// No slot was spare when the preferred lookup started.
    NotStarted,
    /// The lookup is running, or has returned and not been read yet.
    Running(JoinHandle<io::Result<Vec<SocketAddr>>>),
    /// [`OtherFamily::addresses`] has returned the answer.
    Read,
}

impl OtherFamily {
    /// The lookup of `host` in `family`, not yet started.
    pub fn new(host: &str, port: u16, family: Family) -> Self {
        Self {
            host: host.to_owned(),
            port,
            family,
            state: OtherState::NotStarted,
        }
    }

    /// The family this lookup asks for.
    pub fn family(&self) -> Family {
        self.family
    }

    /// Whether the lookup has been started.
    pub fn is_started(&self) -> bool {
        !matches!(self.state, OtherState::NotStarted)
    }

    /// Starts the lookup on a spare slot of `resolver`, if it has one.
    fn start_if_spare(&mut self, resolver: &ConnectionResolver) {
        if self.is_started() {
            return;
        }
        if let Some(slot) = resolver.spare() {
            self.start(resolver, slot);
        }
    }

    fn start(&mut self, resolver: &ConnectionResolver, slot: LookupSlot) {
        self.state = OtherState::Running(resolver.system.spawn(
            &self.host,
            self.port,
            Some(self.family),
            slot,
        ));
    }

    /// The answer of this lookup, starting it now if it has not started.
    ///
    /// A lookup started here takes its slot the normal way, as
    /// [`ConnectionResolver::lookup`] does, because it is now the lookup a
    /// tunnel waits for. Safe to stop awaiting and await again: a slot not yet taken
    /// is given back, and a lookup already started stays started. Gives the
    /// answer once; after that it is an error.
    pub async fn addresses(
        &mut self,
        resolver: &ConnectionResolver,
    ) -> io::Result<Vec<SocketAddr>> {
        loop {
            match &mut self.state {
                OtherState::NotStarted => {
                    let slot = resolver.acquire().await;
                    self.start(resolver, slot);
                }
                OtherState::Running(lookup) => {
                    let answer = answered(&self.host, lookup).await;
                    self.state = OtherState::Read;
                    return answer;
                }
                OtherState::Read => {
                    return Err(io::Error::other("this lookup's answer was already read"));
                }
            }
        }
    }
}

/// Whether this host holds `address`, meaning a socket of this process may be
/// bound to it.
///
/// One `bind(2)` on a UDP socket at an ephemeral port, and the socket is dropped
/// on the way out. The kernel answers `EADDRNOTAVAIL` for an address no local
/// interface carries and succeeds for one it does, on both Linux and macOS, so
/// this asks the kernel the question directly. There is no interface
/// enumeration in `std` to ask instead.
///
/// The `SocketAddr` rather than the `IpAddr` is what keeps an IPv6 scope ID:
/// binding a link-local address without the scope that selects its interface
/// fails even when the host holds the address, so the scope has to survive the
/// call.
///
/// Nothing is cached. The call is on the tunnel-open path, which is per request
/// and never per packet, an interface can come and go while the server runs, and
/// a cache would need invalidating by an event this process has no portable way
/// to see.
///
/// An error that is not "this address is not ours", an empty descriptor table
/// or an exhausted ephemeral port range, answers `false` as well. That is D89's
/// rule: local exhaustion is this proxy's own fault and must not turn into a
/// verdict about the target. The tunnel that follows fails on its own socket a
/// moment later and reports `proxy_internal_error`, which is the truthful
/// answer.
///
/// Known limit: on a Linux host with `net.ipv4.ip_nonlocal_bind` or
/// `net.ipv6.ip_nonlocal_bind` set, the kernel accepts a bind to an address it
/// does not hold. This probe then answers `true` for every address of that
/// family, and every tunnel to that family is refused as the proxy's own. The
/// failure is closed: no target is reached that should have been refused.
pub fn holds_address(address: SocketAddr) -> bool {
    std::net::UdpSocket::bind(address).is_ok()
}

/// The process's soft limit on open file descriptors, or `None` if it has none.
///
/// Every tunnel holds one, so this is the ceiling the tunnel quota has to fit
/// under: exhausting it does not degrade the proxy gracefully, it makes every
/// `accept`, `connect` and `socket` call fail at once, including the ones the
/// QUIC endpoint needs. Checked at startup against `limits.max_targets_per_conn`
/// rather than discovered in production.
///
/// `getrlimit` needs no `cfg` split: it is POSIX and present on both the Linux
/// production host and the macOS dev host. It also cannot fail for a resource
/// the kernel always knows about, which is why rustix's wrapper returns no
/// `Result`. So `None` here is `RLIM_INFINITY` rather than a failed read: the
/// process has no ceiling at all, and there is nothing for the startup check to
/// compare a budget against. See [`crate::quic`]'s `warn_if_fd_budget_is_tight`,
/// which treats that as room to spare.
pub fn fd_soft_limit() -> Option<u64> {
    fd_limits().0
}

/// The process's `RLIMIT_NOFILE`, soft limit first and hard limit second.
///
/// `None` in either place is `RLIM_INFINITY`, exactly as [`fd_soft_limit`]
/// describes for the soft one. The pair is what `volto --diagnostics` prints,
/// because the hard limit is what says whether a soft limit that is too low can
/// be raised on this host at all or needs the service manager changed.
pub fn fd_limits() -> (Option<u64>, Option<u64>) {
    let nofile = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    (nofile.current, nofile.maximum)
}

/// The `Max open files` row of a `/proc/<pid>/limits` file, soft limit first.
///
/// `None` in either position is the file's literal `unlimited`, the same thing
/// [`fd_limits`] reports as `None` for `RLIM_INFINITY`. `None` for the pair
/// means the text carries no `Max open files` row, or carries one that does not
/// have two readable value columns. Those two are not told apart, because the
/// caller has the same thing to say about either: there is no number to print.
///
/// This takes the file's text rather than a pid, which is what makes it
/// testable on the macOS development host where no such file exists. Reading
/// the file, and finding the pid to read it for, belong to the one caller:
/// `volto --diagnostics`, whose `[file descriptors]` section prints the running
/// service's limits beside the ones `getrlimit` reports for itself. The two
/// differ whenever the command is typed into an SSH shell, because the service
/// runs under the unit's `LimitNOFILE` and the shell does not.
///
/// The kernel writes the row in fixed-width columns, and each value column is
/// either a decimal number or the word `unlimited`:
///
/// ```text
/// Limit                     Soft Limit           Hard Limit           Units
/// Max open files            131072               131072               files
/// ```
pub fn max_open_files(limits: &str) -> Option<(Option<u64>, Option<u64>)> {
    // The row name is followed by its padding, so a line that only begins with
    // those words and then continues into a longer name is not this row.
    let row = limits
        .lines()
        .find_map(|line| line.strip_prefix("Max open files"))
        .filter(|row| row.starts_with(char::is_whitespace))?;

    let mut columns = row.split_whitespace();
    let soft = limit_column(columns.next()?)?;
    let hard = limit_column(columns.next()?)?;
    Some((soft, hard))
}

/// One value column of a `/proc/<pid>/limits` row.
///
/// `Some(None)` is `unlimited` and the outer `None` is a column that is neither
/// that word nor a number, which is the case [`max_open_files`] reports as
/// having no readable row.
fn limit_column(column: &str) -> Option<Option<u64>> {
    if column == "unlimited" {
        return Some(None);
    }
    column.parse::<u64>().ok().map(Some)
}

/// Binds a UDP socket and connects it to `target`.
///
/// Connecting the socket makes the kernel drop any packet that does not come
/// from `target`, which is the source validation RFC 9298 §3.1 calls for.
///
/// An IPv4-mapped IPv6 target (`::ffff:a.b.c.d`) is connected as the IPv4
/// address it stands for, which is also how [`crate::policy`] judged it. On an
/// IPv6 socket its packets would leave as IPv4 without the IPv4 "don't
/// fragment" setting, and a host with `net.ipv6.bindv6only = 1` would refuse
/// the connect.
pub async fn connected_udp_socket(target: SocketAddr) -> io::Result<UdpSocket> {
    let target = SocketAddr::new(crate::policy::canonical(target.ip()), target.port());

    // Bind a wildcard address of the same family as the target.
    let bind: SocketAddr = if target.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };

    let socket = UdpSocket::bind(bind).await?;
    set_dont_fragment(&socket, target.is_ipv4());
    socket.connect(target).await?;

    // ECN is left alone: an unset codepoint is Not-ECT (RFC 3168), which is what
    // RFC 9298 §6.2 asks a proxy to send.

    Ok(socket)
}

/// Sets the IP "don't fragment" bit and enables path MTU discovery on a
/// socket of the family `is_ipv4` names.
///
/// A proxy must not let the kernel fragment tunnelled UDP: fragments defeat PMTU
/// discovery end to end and are widely dropped. Failure is logged rather than
/// fatal: the tunnel still works, but it may lose oversized packets silently.
#[cfg(target_os = "linux")]
fn set_dont_fragment(socket: &UdpSocket, is_ipv4: bool) {
    use rustix::net::sockopt::{Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery};
    use tracing::debug;

    // The socket is borrowed as an `AsFd` rather than a raw descriptor, so the
    // setsockopt cannot outlive it. rustix's own `cfg` on these two is
    // `linux_kernel`, which the `cfg` on this function is already inside.
    let result = if is_ipv4 {
        rustix::net::sockopt::set_ip_mtu_discover(socket, Ipv4PathMtuDiscovery::DO)
    } else {
        rustix::net::sockopt::set_ipv6_mtu_discover(socket, Ipv6PathMtuDiscovery::DO)
    };

    if let Err(errno) = result {
        debug!(
            error = %io::Error::from(errno),
            "failed to enable path MTU discovery on the target socket"
        );
    }
}

/// No portable equivalent outside Linux.
///
/// Development happens on macOS, where the tunnel still works; only the DF bit
/// is missing, which matters on the Linux production host.
#[cfg(not(target_os = "linux"))]
fn set_dont_fragment(_socket: &UdpSocket, _is_ipv4: bool) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The resolver budget, tested as the thing it is: an accounting rule.
    ///
    /// Nothing here resolves a name. What the rule has to survive is a
    /// connection that never gives its slots back, and that is a resolver no
    /// test can conjure on demand — a real one always answers eventually. So
    /// the permits are held directly and the questions asked of them are the
    /// two the design makes: can one connection take everything, and is a
    /// connection that arrives after it has tried still able to resolve
    /// anything at all. The end-to-end version, with an injected resolver that
    /// really does hang, is `tests/it_resolver_pool.rs` (D90).
    mod resolver_budget {
        use super::*;

        use std::task::{Context as TaskContext, Poll};

        /// The value `future` has *without waiting*, or `None` if it would wait.
        ///
        /// One poll is the whole question here: an acquire is either satisfied
        /// from a permit that is free right now or it parks itself in the
        /// semaphore's queue, and those are exactly the two answers the
        /// assertions below are about. Dropping the future on `None` releases
        /// whatever it took on the way, which is what makes a would-wait probe
        /// safe to repeat.
        fn ready<F: Future>(future: F) -> Option<F::Output> {
            let mut future = Box::pin(future);
            let mut cx = TaskContext::from_waker(std::task::Waker::noop());

            match future.as_mut().poll(&mut cx) {
                Poll::Ready(value) => Some(value),
                Poll::Pending => None,
            }
        }

        /// Holds `count` lookup slots on `resolver`, asserting it could.
        fn hold(resolver: &ConnectionResolver, count: usize) -> Vec<LookupSlot> {
            (0..count)
                .map(|held| {
                    ready(resolver.acquire())
                        .unwrap_or_else(|| panic!("slot {held} of {count} was refused"))
                })
                .collect()
        }

        #[test]
        fn a_connection_may_hold_its_reserved_slot_plus_a_burst() {
            let budget = ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS);
            let resolver = budget.per_connection();

            let held = hold(&resolver, BURST_LOOKUPS + 1);

            assert!(
                ready(resolver.acquire()).is_none(),
                "a connection took more than its reserved slot and {BURST_LOOKUPS} burst"
            );
            drop(held);
        }

        /// The guarantee: no number of hostile connections can starve a new one.
        ///
        /// The shared allowance is drained by connections that never let go,
        /// which is what a client aiming at black-holed names does to the
        /// blocking pool. A connection arriving after that still resolves —
        /// serially, on the slot that was never theirs to take.
        #[test]
        fn a_new_connection_still_has_a_slot_when_the_shared_allowance_is_gone() {
            let budget = ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS);

            let hostile: Vec<_> = (0..SHARED_LOOKUPS.div_ceil(BURST_LOOKUPS))
                .map(|_| budget.per_connection())
                .collect();
            let _held: Vec<_> = hostile
                .iter()
                .map(|resolver| hold(resolver, BURST_LOOKUPS + 1))
                .collect();

            assert_eq!(
                budget.shared.available_permits(),
                0,
                "the shared allowance was not actually exhausted"
            );

            let victim = budget.per_connection();
            let slot = ready(victim.acquire());
            assert!(slot.is_some(), "a fresh connection was left with no slot");

            // And exactly one: the guarantee is progress, not parallelism.
            assert!(
                ready(victim.acquire()).is_none(),
                "the reserved slot was not the only thing left"
            );
        }

        /// A lookup parked on the shared queue takes the reserved slot when it
        /// frees.
        ///
        /// The case an entry-time check alone cannot cover: during an attack
        /// the shared allowance never comes back, and a connection's second
        /// concurrent lookup parks while its first — on the reserved slot —
        /// finishes in milliseconds. "Serial at worst" means the parked lookup
        /// runs then, on the slot its own connection just freed, not that it
        /// waits out `connect_timeout` beside an idle slot.
        #[test]
        fn a_parked_lookup_takes_the_reserved_slot_when_it_frees() {
            let budget = ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS);
            let hostile: Vec<_> = (0..SHARED_LOOKUPS.div_ceil(BURST_LOOKUPS))
                .map(|_| budget.per_connection())
                .collect();
            let _held: Vec<_> = hostile
                .iter()
                .map(|resolver| hold(resolver, BURST_LOOKUPS + 1))
                .collect();
            assert_eq!(
                budget.shared.available_permits(),
                0,
                "the shared allowance was not actually exhausted"
            );

            let victim = budget.per_connection();
            let first = ready(victim.acquire()).expect("the reserved slot starts free");

            let mut second = Box::pin(victim.acquire());
            let mut cx = TaskContext::from_waker(std::task::Waker::noop());
            assert!(
                second.as_mut().poll(&mut cx).is_pending(),
                "a second lookup had a slot with the allowance gone and the reserved slot held"
            );

            drop(first);
            assert!(
                second.as_mut().poll(&mut cx).is_ready(),
                "a parked lookup did not take the reserved slot its own connection freed"
            );
        }

        #[test]
        fn a_finished_lookup_gives_its_slot_back() {
            let budget = ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS);
            let resolver = budget.per_connection();

            let held = hold(&resolver, BURST_LOOKUPS + 1);
            let shared_before = budget.shared.available_permits();
            drop(held);

            assert_eq!(
                budget.shared.available_permits(),
                shared_before + BURST_LOOKUPS,
                "the shared allowance did not come back"
            );
            assert!(
                ready(resolver.acquire()).is_some(),
                "the connection could not resolve again after its lookups finished"
            );
        }

        /// An IP literal costs nothing, because it blocks nothing.
        ///
        /// Asserted without a runtime at all: [`System::spawn`] would
        /// reach the blocking pool, and reaching it from here panics. So a literal
        /// answered by a single poll is a literal that never went near a
        /// thread — with every slot this connection has already held.
        #[test]
        fn an_ip_literal_needs_no_slot() {
            let budget = ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS);
            let resolver = budget.per_connection();
            let _held = hold(&resolver, BURST_LOOKUPS + 1);

            let resolved = ready(resolver.lookup("192.0.2.1", 443))
                .expect("a literal must not wait for a slot")
                .expect("a literal resolves");

            assert_eq!(resolved, vec!["192.0.2.1:443".parse().unwrap()]);
        }

        /// A whole connection's worth of lookups giving up at once leaves the
        /// budget exactly as it found it.
        ///
        /// This is the shape a resumed VM produces, and the reason it is worth
        /// a test of its own: on a live migration every `connect_timeout` in
        /// the process expires in the same instant, so every parked
        /// [`ConnectionResolver::acquire`] is dropped together rather than one
        /// at a time. A parked one is not empty-handed — it holds a burst
        /// permit while it queues on the shared allowance, and it is
        /// simultaneously queued on the reserved slot — so a drop that gave
        /// back only part of that would erode the budget one mass expiry at a
        /// time until no connection could resolve anything.
        ///
        /// A lookup that has already reached the blocking pool keeps its slot
        /// on purpose ([`System::spawn`]). What is proved here is the
        /// other half: a lookup that never got a slot keeps no claim on one.
        #[test]
        fn lookups_that_all_give_up_at_once_give_back_everything_they_held() {
            let budget = ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS);

            // The shared allowance gone, the way an attack leaves it.
            let hostile: Vec<_> = (0..SHARED_LOOKUPS.div_ceil(BURST_LOOKUPS))
                .map(|_| budget.per_connection())
                .collect();
            let _held: Vec<_> = hostile
                .iter()
                .map(|resolver| hold(resolver, BURST_LOOKUPS + 1))
                .collect();
            assert_eq!(budget.shared.available_permits(), 0);

            let victim = budget.per_connection();
            // The reserved slot is taken, so everything below has to queue.
            let reserved = ready(victim.acquire()).expect("the reserved slot starts free");
            assert_eq!(victim.burst.available_permits(), BURST_LOOKUPS);

            let mut cx = TaskContext::from_waker(std::task::Waker::noop());
            let mut parked: Vec<_> = (0..BURST_LOOKUPS)
                .map(|_| Box::pin(victim.acquire()))
                .collect();
            for (nth, lookup) in parked.iter_mut().enumerate() {
                assert!(
                    lookup.as_mut().poll(&mut cx).is_pending(),
                    "lookup {nth} had a slot with the allowance gone and the reserved slot held"
                );
            }
            assert_eq!(
                victim.burst.available_permits(),
                0,
                "a parked lookup is meant to be holding its burst permit while it queues"
            );

            // Every one of them gives up in the same instant.
            drop(parked);

            assert_eq!(
                victim.burst.available_permits(),
                BURST_LOOKUPS,
                "burst permits were left behind by lookups that gave up"
            );
            assert_eq!(
                budget.shared.available_permits(),
                0,
                "a lookup that never reached the shared allowance disturbed it"
            );

            // And the reserved slot is still this connection's own, taken by
            // the next lookup the moment the one holding it finishes.
            drop(reserved);
            assert!(
                ready(victim.acquire()).is_some(),
                "the reserved slot did not come back after a mass expiry"
            );
        }

        /// A lookup keeps counting after its connection is gone.
        ///
        /// A slot travels into the blocking thread and outlives the connection
        /// that took it whenever `getaddrinfo` takes longer than the connection
        /// lasts. So a peer that opens connections one after another, takes
        /// every slot each one offers and closes it, must still find the
        /// server's total bounded by the pool, however many connections it
        /// goes through.
        #[test]
        fn slots_held_past_their_connection_never_exceed_the_pool() {
            const MAX_CONNECTIONS: u32 = 4;
            let budget = ResolverBudget::new(MAX_CONNECTIONS);

            let mut held = Vec::new();
            for _ in 0..2 * (reserved_lookups(MAX_CONNECTIONS) + SHARED_LOOKUPS) {
                let connection = budget.per_connection();
                while let Some(slot) = ready(connection.acquire()) {
                    held.push(slot);
                }
                drop(connection);
            }

            let issuable = blocking_pool_size(MAX_CONNECTIONS) - LOOKUP_FREE_THREADS;
            assert!(
                held.len() <= issuable,
                "closed connections hold {} lookup slots against a pool sized for {issuable}",
                held.len()
            );

            // Once those threads return, a new connection resolves again.
            drop(held);
            assert!(
                ready(budget.per_connection().acquire()).is_some(),
                "the allowance did not come back when the lookups finished"
            );
        }

        /// The pool has a thread for every slot the budget can hand out.
        #[test]
        fn the_pool_covers_every_slot_the_budget_can_hand_out() {
            for max_connections in [1, 16, crate::config::DEFAULT_MAX_CONNECTIONS, 4096] {
                let reserved = usize::try_from(max_connections)
                    .expect("a u32 fits a usize")
                    .min(RESERVED_LOOKUP_CEILING);

                assert!(
                    blocking_pool_size(max_connections) >= reserved + SHARED_LOOKUPS,
                    "max_connections = {max_connections}"
                );
                assert_eq!(
                    blocking_pool_size(max_connections) - reserved - SHARED_LOOKUPS,
                    LOOKUP_FREE_THREADS,
                    "max_connections = {max_connections}"
                );

                // And the budget built from the same number hands out exactly
                // those slots, whatever connections they belong to.
                let budget = ResolverBudget::new(max_connections);
                assert_eq!(
                    budget.reserved.available_permits() + budget.shared.available_permits(),
                    reserved + SHARED_LOOKUPS,
                    "max_connections = {max_connections}"
                );
            }

            // `max_connections = 0` is "no cap", so there is nothing to size
            // against and the ceiling is the answer.
            assert_eq!(
                blocking_pool_size(0),
                blocking_pool_size(u32::MAX),
                "an uncapped server is sized like one at the ceiling"
            );
            assert_eq!(
                ResolverBudget::new(0).reserved.available_permits(),
                RESERVED_LOOKUP_CEILING,
                "an uncapped server reserves like one at the ceiling"
            );
        }

        /// The shared allowance, all of it held, the way the hostile
        /// connections of the tests above leave it. Taken in one call rather
        /// than through [`hold`], because inside a runtime tokio's cooperative
        /// budget makes the hundred and twenty-ninth acquire wait.
        fn drain_shared(budget: &ResolverBudget) -> OwnedSemaphorePermit {
            let held = budget
                .shared
                .clone()
                .try_acquire_many_owned(u32::try_from(SHARED_LOOKUPS).unwrap())
                .expect("the shared allowance starts whole");
            assert_eq!(budget.shared.available_permits(), 0);
            held
        }

        /// An idle connection has a slot to spare for the other family, and
        /// it comes from the shared allowance, never from the reserved slot.
        #[test]
        fn an_idle_connection_has_a_shared_slot_to_spare() {
            let budget = ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS);
            let resolver = budget.per_connection();

            let spare = resolver
                .spare()
                .expect("an idle connection has a slot to spare");

            assert!(matches!(spare, LookupSlot::Shared { .. }), "{spare:?}");
            assert_eq!(
                resolver.reserved.available_permits(),
                1,
                "a spare slot took the reserved slot"
            );
            assert_eq!(budget.shared.available_permits(), SHARED_LOOKUPS - 1);
        }

        /// The second lookup starts at once only while fewer than half of the
        /// connection's burst permits are in use.
        #[test]
        fn no_slot_is_spare_once_half_the_burst_is_in_use() {
            let budget = ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS);
            let resolver = budget.per_connection();

            // The reserved slot, then one burst permit short of the line.
            let mut held = hold(&resolver, 1 + SPARE_BURST_IN_USE - 1);
            let spare = resolver.spare();
            assert!(
                spare.is_some(),
                "{} burst permits in use left nothing to spare",
                SPARE_BURST_IN_USE - 1
            );
            drop(spare);

            held.extend(hold(&resolver, 1));
            assert!(
                resolver.spare().is_none(),
                "{SPARE_BURST_IN_USE} burst permits in use still gave a spare slot"
            );

            // A lookup that is needed takes its slot exactly as before.
            assert!(ready(resolver.acquire()).is_some());
            drop(held);
        }

        /// With the shared allowance gone nothing is spare, and asking gives
        /// back the burst permit it tried and leaves the reserved slot free.
        #[test]
        fn no_slot_is_spare_when_the_shared_allowance_is_gone() {
            let budget = ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS);
            let _held = drain_shared(&budget);

            let victim = budget.per_connection();
            assert!(victim.spare().is_none(), "a spare slot came from nowhere");
            assert_eq!(
                victim.burst.available_permits(),
                BURST_LOOKUPS,
                "asking for a spare slot kept a burst permit"
            );
            assert!(
                ready(victim.acquire()).is_some(),
                "asking for a spare slot took the reserved slot"
            );
        }

        /// The lookups a stand-in resolver was asked for, in order.
        type Asked = Arc<std::sync::Mutex<Vec<Option<Family>>>>;

        /// A stand-in that records every lookup and answers each family with
        /// `answer`, which never returns for an address of `None`.
        fn stand_in(
            asked: &Asked,
            answer: fn(Option<Family>) -> Option<io::Result<Vec<std::net::IpAddr>>>,
        ) -> StandIn {
            let asked = asked.clone();
            Arc::new(move |_host, family| {
                asked.lock().unwrap().push(family);
                let answer = answer(family);
                Box::pin(async move {
                    match answer {
                        Some(answer) => answer,
                        None => std::future::pending().await,
                    }
                })
            })
        }

        fn v4_answers_v6_never(
            family: Option<Family>,
        ) -> Option<io::Result<Vec<std::net::IpAddr>>> {
            match family {
                Some(Family::Ipv4) => Some(Ok(vec!["192.0.2.1".parse().unwrap()])),
                _ => None,
            }
        }

        fn both_answer(family: Option<Family>) -> Option<io::Result<Vec<std::net::IpAddr>>> {
            Some(Ok(match family {
                Some(Family::Ipv4) => vec!["192.0.2.1".parse().unwrap()],
                Some(Family::Ipv6) => vec!["2001:db8::1".parse().unwrap()],
                None => vec!["2001:db8::1".parse().unwrap(), "192.0.2.1".parse().unwrap()],
            }))
        }

        /// The preferred family is asked alone and answered without waiting
        /// for the other, whose lookup was started beside it.
        #[tokio::test]
        async fn a_family_lookup_asks_one_family_and_starts_the_other_beside_it() {
            let budget = ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS);
            let asked = Asked::default();
            let resolver = budget.per_connection_with(stand_in(&asked, v4_answers_v6_never));
            let mut other = OtherFamily::new("example.test", 443, Family::Ipv6);

            let addresses = resolver
                .lookup_family("example.test", 443, Family::Ipv4, &mut other)
                .await
                .expect("the preferred family answers");

            assert_eq!(addresses, vec!["192.0.2.1:443".parse().unwrap()]);
            assert_eq!(
                *asked.lock().unwrap(),
                vec![Some(Family::Ipv4), Some(Family::Ipv6)]
            );
            assert!(other.is_started());
        }

        /// Without a spare slot the other family is not asked until a tunnel
        /// awaits it, and then it takes a slot the normal way, here the
        /// connection's reserved slot.
        #[tokio::test]
        async fn without_a_spare_slot_the_other_family_waits_until_it_is_asked_for() {
            let budget = ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS);
            let _held = drain_shared(&budget);
            let asked = Asked::default();
            let victim = budget.per_connection_with(stand_in(&asked, both_answer));
            let mut other = OtherFamily::new("example.test", 443, Family::Ipv6);

            victim
                .lookup_family("example.test", 443, Family::Ipv4, &mut other)
                .await
                .expect("the preferred family answers on the reserved slot");
            assert_eq!(*asked.lock().unwrap(), vec![Some(Family::Ipv4)]);
            assert!(
                !other.is_started(),
                "a lookup started with no slot to spare"
            );

            let later = other
                .addresses(&victim)
                .await
                .expect("the other family answers once it is asked for");
            assert_eq!(later, vec!["[2001:db8::1]:443".parse().unwrap()]);
            assert_eq!(
                *asked.lock().unwrap(),
                vec![Some(Family::Ipv4), Some(Family::Ipv6)]
            );
        }

        /// A second lookup nobody waits for still holds its slot until the
        /// resolver returns, as D90 requires of every lookup.
        #[tokio::test]
        async fn a_second_lookup_holds_its_slot_until_the_resolver_returns() {
            let budget = ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS);
            let (release, released) = tokio::sync::oneshot::channel::<()>();
            let released = std::sync::Mutex::new(Some(released));
            let stand_in: StandIn = Arc::new(move |_host, family| {
                let gate = match family {
                    Some(Family::Ipv6) => released.lock().unwrap().take(),
                    _ => None,
                };
                Box::pin(async move {
                    if let Some(gate) = gate {
                        let _ = gate.await;
                    }
                    Ok(vec!["192.0.2.1".parse().unwrap()])
                })
            });
            let resolver = budget.per_connection_with(stand_in);
            let mut other = OtherFamily::new("example.test", 443, Family::Ipv6);

            resolver
                .lookup_family("example.test", 443, Family::Ipv4, &mut other)
                .await
                .expect("the preferred family answers");
            drop(other);

            assert_eq!(
                budget.shared.available_permits(),
                SHARED_LOOKUPS - 1,
                "a running lookup gave its slot back when nobody was waiting for it"
            );

            release.send(()).expect("the lookup is still running");
            for _ in 0..100 {
                if budget.shared.available_permits() == SHARED_LOOKUPS {
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!("the slot did not come back when the lookup returned");
        }

        /// An IP literal of either family is answered with no lookup at all.
        #[tokio::test]
        async fn a_family_lookup_answers_a_literal_without_a_lookup() {
            let budget = ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS);
            let asked = Asked::default();
            let resolver = budget.per_connection_with(stand_in(&asked, both_answer));
            let mut other = OtherFamily::new("2001:db8::1", 443, Family::Ipv6);

            let addresses = resolver
                .lookup_family("2001:db8::1", 443, Family::Ipv4, &mut other)
                .await
                .expect("a literal resolves");

            assert_eq!(addresses, vec!["[2001:db8::1]:443".parse().unwrap()]);
            assert!(asked.lock().unwrap().is_empty());
            assert!(!other.is_started());
        }
    }

    /// One family's answer keeps the resolver's order, each address once, of
    /// that family alone, with the port set, and skips what it cannot read.
    #[test]
    fn a_family_list_has_each_address_once_with_its_port() {
        let answers = vec![
            Ok("127.0.0.1:0".parse().unwrap()),
            Ok("[::1]:0".parse().unwrap()),
            Err(io::Error::other("an address of an unknown family")),
            Ok("192.0.2.7:0".parse().unwrap()),
            // glibc's second copy of `localhost` under an IPv4 hint.
            Ok("127.0.0.1:0".parse().unwrap()),
        ];

        assert_eq!(
            one_family_list(answers.into_iter(), 443, Family::Ipv4),
            vec![
                "127.0.0.1:443".parse::<SocketAddr>().unwrap(),
                "192.0.2.7:443".parse().unwrap(),
            ]
        );
    }

    /// `EAI_NODATA` is "no address in this family" and keeps the resolver's
    /// text. Nothing else is, an `ENOENT` from `EAI_SYSTEM` included.
    #[test]
    fn only_no_data_is_read_as_no_address_in_the_family() {
        let no_data = dns_lookup::LookupError::new(libc::EAI_NODATA);
        let text = no_data.to_string();
        let error = lookup_error(no_data);
        assert!(is_no_data(&error), "{error}");
        assert_eq!(error.to_string(), text);

        for code in [libc::EAI_NONAME, libc::EAI_AGAIN, libc::EAI_FAIL] {
            let error = lookup_error(dns_lookup::LookupError::new(code));
            assert!(!is_no_data(&error), "{code}: {error}");
        }
        assert!(!is_no_data(&io::Error::from_raw_os_error(libc::ENOENT)));
    }

    /// The real `getaddrinfo`, asked one family of `localhost`: every address
    /// is of that family, once, and carries the port. No query leaves the
    /// host, because `localhost` comes from `/etc/hosts`. A host whose
    /// `/etc/hosts` has no IPv6 line may answer IPv6 with no data.
    #[test]
    fn localhost_is_asked_one_family_at_a_time() {
        for family in [Family::Ipv4, Family::Ipv6] {
            let addresses = match one_family("localhost", 8080, family) {
                Ok(addresses) => addresses,
                Err(error) if family == Family::Ipv6 && is_no_data(&error) => continue,
                Err(error) => panic!("{family:?}: {error}"),
            };

            assert!(!addresses.is_empty(), "{family:?}");
            for address in &addresses {
                assert!(family.holds(address), "{family:?}: {addresses:?}");
                assert!(address.ip().is_loopback(), "{family:?}: {addresses:?}");
                assert_eq!(address.port(), 8080, "{family:?}: {addresses:?}");
            }
            let mut unique = addresses.clone();
            unique.dedup();
            assert_eq!(unique, addresses, "{family:?}");
        }
    }

    /// The budgeted lookup with the real `getaddrinfo` behind it.
    fn real_resolver() -> ConnectionResolver {
        ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS).per_connection()
    }

    #[tokio::test]
    async fn resolves_ipv4_literals_without_a_resolver() {
        let addresses = real_resolver()
            .lookup("192.0.2.1", 443)
            .await
            .expect("literal resolves");
        assert_eq!(addresses, vec!["192.0.2.1:443".parse().unwrap()]);
    }

    /// Bare, which is the only form that reaches here: `tunnel::tcp` takes the
    /// brackets off an RFC 3986 authority and RFC 9298's template never has
    /// them. A bracketed literal is a host name with characters no host name may
    /// contain, and is left to fail as one.
    #[tokio::test]
    async fn resolves_bare_ipv6_literals() {
        let bare = real_resolver()
            .lookup("2001:db8::1", 53)
            .await
            .expect("bare literal");
        assert_eq!(bare, vec!["[2001:db8::1]:53".parse().unwrap()]);
    }

    /// `localhost` through the system resolver, and the slot it held is back
    /// once the answer is: the blocking thread drops it before it returns.
    #[tokio::test]
    async fn resolves_localhost() {
        let budget = ResolverBudget::new(crate::config::DEFAULT_MAX_CONNECTIONS);
        let resolver = budget.per_connection();
        let addresses = resolver
            .lookup("localhost", 80)
            .await
            .expect("localhost resolves");
        assert!(
            addresses.iter().all(|address| address.ip().is_loopback()),
            "{addresses:?}"
        );
        assert_eq!(
            resolver.reserved.available_permits(),
            1,
            "the lookup kept its slot after it answered"
        );
        assert_eq!(
            budget.reserved.available_permits(),
            reserved_lookups(crate::config::DEFAULT_MAX_CONNECTIONS),
            "the lookup kept its server-wide permit after it answered"
        );
    }

    /// A name that cannot resolve *anywhere*, so the assertion is about this code
    /// rather than about the local resolver.
    ///
    /// A plain nonexistent name is unusable as a test: resolvers that hijack
    /// NXDOMAIN, Surge among them with its fake-IP range, make it succeed. A
    /// name longer than the 255 octets DNS allows is rejected by the stub
    /// resolver before any query goes out, on every platform.
    #[tokio::test]
    async fn a_name_too_long_for_dns_fails_to_resolve() {
        let label = "a".repeat(60);
        let host = vec![label; 5].join(".") + ".invalid";
        assert!(host.len() > 255, "{} octets", host.len());

        let error = real_resolver()
            .lookup(&host, 443)
            .await
            .expect_err("must not resolve");
        // Whatever the platform calls it, it must be an error rather than an
        // empty success.
        assert!(!error.to_string().is_empty());
    }

    /// A `/proc/<pid>/limits` file as Linux writes it, with `soft` and `hard`
    /// substituted into the `Max open files` row.
    ///
    /// The other rows are kept because they are what the parser has to walk
    /// past, including `Max locked memory`, whose name also starts with the
    /// word `Max`, and the two priority rows, which have no unit column.
    fn limits_file(row: &str) -> String {
        format!(
            "Limit                     Soft Limit           Hard Limit           Units\n\
             Max cpu time              unlimited            unlimited            seconds\n\
             Max file size             unlimited            unlimited            bytes\n\
             Max stack size            8388608              unlimited            bytes\n\
             Max core file size        0                    unlimited            bytes\n\
             Max processes             15155                15155                processes\n\
             {row}\
             Max locked memory         8388608              8388608              bytes\n\
             Max address space         unlimited            unlimited            bytes\n\
             Max nice priority         0                    0                    \n\
             Max realtime timeout      unlimited            unlimited            us\n"
        )
    }

    /// The row as it reads on a host running the shipped unit, whose
    /// `LimitNOFILE` is 131072.
    #[test]
    fn the_max_open_files_row_gives_both_of_its_numbers() {
        let text = limits_file(
            "Max open files            131072               131072               files\n",
        );

        assert_eq!(max_open_files(&text), Some((Some(131_072), Some(131_072))));
    }

    /// `unlimited` is a value the file really carries, and it means the same
    /// thing `None` means everywhere else here: no ceiling at all.
    #[test]
    fn unlimited_is_read_as_no_ceiling_rather_than_as_a_failure() {
        let text = limits_file(
            "Max open files            1024                 unlimited            files\n",
        );

        assert_eq!(max_open_files(&text), Some((Some(1024), None)));

        let both = limits_file(
            "Max open files            unlimited            unlimited            files\n",
        );

        assert_eq!(max_open_files(&both), Some((None, None)));
    }

    /// A file without the row answers nothing, which is what a kernel that
    /// renamed the row or a file read from the wrong place would look like.
    #[test]
    fn a_file_without_the_row_has_no_answer() {
        assert_eq!(max_open_files(&limits_file("")), None);
        assert_eq!(max_open_files(""), None);
    }

    /// A row whose columns are not what they should be is reported as no
    /// answer, never as a number nobody wrote down.
    #[test]
    fn a_malformed_row_is_not_guessed_at() {
        for row in [
            // A value column that is neither a number nor `unlimited`.
            "Max open files            many                 131072               files\n",
            "Max open files            131072               many                 files\n",
            // A negative number is not a limit either.
            "Max open files            -1                   131072               files\n",
            // Only one value column.
            "Max open files            131072\n",
            // The name with nothing after it at all.
            "Max open files\n",
        ] {
            assert_eq!(
                max_open_files(&limits_file(row)),
                None,
                "this row has no readable pair of values: {row:?}"
            );
        }
    }

    /// The startup fd check is only useful if the probe works on both hosts.
    ///
    /// `None` is not a failure to read the limit — it is `RLIM_INFINITY`, and a
    /// host that grants it is answering the question rather than refusing to.
    /// So what is pinned is the only answer that would be wrong: a finite
    /// ceiling no running process could be under.
    #[test]
    fn the_fd_soft_limit_is_readable() {
        assert!(
            fd_soft_limit().is_none_or(|limit| limit > 0),
            "a process with no descriptors could not run this"
        );
    }

    /// The two answers the bind probe has to get right, on every host this
    /// crate runs on.
    ///
    /// 127.0.0.1 is held by any host that can run this test at all. 192.0.2.1 is
    /// RFC 5737's TEST-NET-1, reserved for documentation, so no interface
    /// carries it and `bind` has nothing to bind to. A host that did carry it
    /// would be misconfigured in a way this test is right to report.
    #[test]
    fn the_bind_probe_tells_this_hosts_addresses_from_everything_else() {
        assert!(
            holds_address("127.0.0.1:0".parse().unwrap()),
            "loopback is held by every host"
        );
        assert!(
            !holds_address("192.0.2.1:0".parse().unwrap()),
            "a documentation address is on no interface"
        );
    }

    #[tokio::test]
    async fn connected_socket_is_bound_to_the_target_family() {
        let socket = connected_udp_socket("127.0.0.1:9".parse().unwrap())
            .await
            .expect("connect udp");
        assert!(socket.local_addr().expect("local addr").is_ipv4());
    }

    /// A target written as an IPv4-mapped IPv6 address is an IPv4 target, as
    /// the destination policy already judges it, and gets an IPv4 socket. On
    /// an IPv6 socket the Linux "don't fragment" setting would be the IPv6
    /// one, which the kernel does not apply to the IPv4 packets it sends.
    #[tokio::test]
    async fn a_mapped_target_gets_an_ipv4_socket() {
        let socket = connected_udp_socket("[::ffff:127.0.0.1]:9".parse().unwrap())
            .await
            .expect("connect udp");

        let local = socket.local_addr().expect("local addr");
        assert!(local.is_ipv4(), "bound as {local}");
        assert_eq!(
            socket.peer_addr().expect("peer addr"),
            "127.0.0.1:9".parse().unwrap()
        );
    }
}
