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
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

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
/// **Unbudgeted** — this takes no slot from the D90 lookup budget, so nothing a
/// client controls may reach it: a tunnel target resolves through
/// [`ConnectionResolver::lookup`] or not at all. What keeps this `pub` is the
/// tests (`it_resolver_pool` proves its injected resolver took hold by watching
/// this very function hang).
///
/// An IP literal resolves to itself without consulting the resolver, and an IPv6
/// one is written bare: the brackets belong to the syntax a target arrived in,
/// and each of the two places a target arrives has already taken them off --
/// `tunnel::tcp` splitting an RFC 3986 authority, `tunnel::udp` decoding an
/// RFC 9298 template, which carries them bare to begin with. Stripping them here
/// as well would mean accepting a host neither of those produced, and answering
/// `example.com]:443` by dialling `example.com`.
pub async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    match literal(host, port) {
        Some(address) => Ok(vec![address]),
        None => on_the_blocking_pool(host, port, None).await,
    }
}

/// `host` read as an IP address, which resolves to itself.
fn literal(host: &str, port: u16) -> Option<SocketAddr> {
    host.parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, port))
}

/// Asks the system resolver about `host`, holding `slot` until it answers.
///
/// The blocking task is spawned here rather than left to
/// `tokio::net::lookup_host`, which spawns exactly this, for one reason: the
/// permit has to be dropped by the *thread*, not by the future. A
/// `connect_timeout` that expires drops the caller, and `getaddrinfo` is not
/// cancellable -- the thread stays in the resolver until the stub gives up. A
/// permit released at that moment would say a slot is free while the thread it
/// stands for is still gone, which is the accounting that lets a client park
/// the pool one `connect_timeout` at a time (D90).
///
/// `None` is the unbudgeted path: [`resolve`] itself, and the tests.
async fn on_the_blocking_pool(
    host: &str,
    port: u16,
    slot: Option<LookupSlot>,
) -> io::Result<Vec<SocketAddr>> {
    let owned = host.to_owned();
    let resolved = tokio::task::spawn_blocking(move || {
        let addresses = std::net::ToSocketAddrs::to_socket_addrs(&(owned.as_str(), port));
        // Explicit, and last: the slot is what the thread is holding, so it is
        // given back where the thread finishes rather than where the caller
        // does.
        drop(slot);
        addresses
    })
    .await;

    let addresses: Vec<SocketAddr> = match resolved {
        Ok(addresses) => addresses?.collect(),
        // The runtime is shutting down, or the resolver call panicked. Neither
        // is an answer about the name.
        Err(error) => return Err(io::Error::other(error)),
    };

    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{host} resolved to no addresses"),
        ));
    }

    Ok(addresses)
}

/// Name lookups the whole process may have in flight beyond the one every
/// connection keeps in reserve.
///
/// The number this bounds is threads, not queries: `tokio::net::lookup_host`
/// hands a name to `getaddrinfo` on the runtime's *blocking* pool, and that call
/// is not cancellable. A `connect_timeout` that expires drops the future and
/// answers the client, but the thread stays in the resolver until the stub gives
/// up on its own — five seconds per attempt on a stock `resolv.conf`, tens of
/// seconds where the nameserver answers nothing at all. So an unbounded proxy
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
/// allowance -- which is the point at which everyone else falls back on their
/// reserved slot rather than on nothing.
pub const BURST_LOOKUPS: usize = 32;

/// Blocking threads the pool keeps clear of name resolution.
///
/// Nothing else in this process uses the blocking pool today. The headroom is
/// for the day something does -- and so that the arithmetic below never has to
/// be exact.
pub const LOOKUP_FREE_THREADS: usize = 64;

/// Connections the blocking pool is sized to reserve a lookup slot for.
///
/// `max_connections` is an operator's number and may be raised without limit (or
/// switched off entirely, which is what `0` means), while a thread is a real
/// resource. Past this ceiling the reservation is best-effort: connections still
/// get their slot, the pool just no longer has a thread standing by for every
/// one of them at the same instant.
pub const RESERVED_LOOKUP_CEILING: usize = 1024;

/// The blocking pool the runtime is built with, in threads.
///
/// Sized from the configuration rather than left at tokio's 512 so that the two
/// numbers that matter are related on purpose: every connection's reserved
/// lookup slot has a thread to run on, the shared allowance has its own, and
/// [`LOOKUP_FREE_THREADS`] are left over. Threads are created on demand and
/// reaped when idle, so this is a ceiling and not an allocation -- a server with
/// three clients holds three of them.
///
/// Startup-only: a `SIGHUP` that raises `max_connections` does not resize the
/// pool, so the reservation for the connections it adds is best-effort in the
/// same way [`RESERVED_LOOKUP_CEILING`] describes.
pub const fn blocking_pool_size(max_connections: u32) -> usize {
    // `0` is "uncapped", so there is nothing to size against and the ceiling is
    // the answer. Written out rather than as `min` because a `const fn` may not
    // call `Ord::min`, and this is a constant in the tests that check it.
    let reserved = if max_connections == 0 || max_connections as usize > RESERVED_LOOKUP_CEILING {
        RESERVED_LOOKUP_CEILING
    } else {
        max_connections as usize
    };

    reserved + SHARED_LOOKUPS + LOOKUP_FREE_THREADS
}

/// The server's share of the blocking pool, handed out one connection at a time.
///
/// Cloned into every connection, which is the whole design: what one connection
/// can take away from the others is bounded, and what it keeps for itself is
/// not takeable at all. See [`ConnectionResolver`].
#[derive(Clone, Debug)]
pub struct ResolverBudget {
    shared: Arc<Semaphore>,
}

impl ResolverBudget {
    /// The budget for one server.
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Semaphore::new(SHARED_LOOKUPS)),
        }
    }

    /// One connection's view of it.
    pub fn per_connection(&self) -> ConnectionResolver {
        ConnectionResolver {
            slots: Arc::new(ConnectionSlots {
                reserved: Arc::new(Semaphore::new(1)),
                burst: Arc::new(Semaphore::new(BURST_LOOKUPS)),
                shared: self.shared.clone(),
            }),
        }
    }
}

impl Default for ResolverBudget {
    fn default() -> Self {
        Self::new()
    }
}

/// What one connection may ask the resolver to do at once.
///
/// Two tiers, because a single shared pool answers only one of the two questions
/// worth asking:
///
/// * **One reserved slot**, held by this connection alone and by nothing else.
///   No number of hostile connections can take it away, so a connection is never
///   starved outright -- at worst its lookups run one at a time. This is the
///   guarantee; the shared allowance is only ever an optimisation on top of it.
/// * **[`BURST_LOOKUPS`] from the shared allowance**, so ordinary use --
///   a client opening thirty tunnels at once -- still resolves them in parallel,
///   while one connection can never hold more than its share of the pool.
///
/// The waiting itself is inside the caller's `connect_timeout`, so a lookup that
/// cannot get a slot in time is refused exactly as a resolver that did not
/// answer in time is, with the same 504 and the same `Proxy-Status` (D90).
/// Cloned with [`crate::tunnel::Context`], and every clone counts against the
/// same slots: a clone that started its own count would be no bound at all.
#[derive(Clone, Debug)]
pub struct ConnectionResolver {
    slots: Arc<ConnectionSlots>,
}

/// What one connection's clones share.
#[derive(Debug)]
struct ConnectionSlots {
    /// This connection's own slot. One permit, never shared.
    reserved: Arc<Semaphore>,
    /// How much of the shared allowance this connection may hold at once.
    burst: Arc<Semaphore>,
    /// The server-wide allowance, from [`ResolverBudget`].
    shared: Arc<Semaphore>,
}

impl ConnectionResolver {
    /// [`resolve`], with a slot in the blocking pool taken for the length of it.
    ///
    /// An IP literal never reaches the resolver and so never occupies a thread:
    /// it is answered without taking a slot at all, which keeps the budget
    /// spent on the only thing that can block.
    pub async fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if let Some(address) = literal(host, port) {
            return Ok(vec![address]);
        }

        let slot = self.acquire().await;
        on_the_blocking_pool(host, port, Some(slot)).await
    }

    /// Takes this connection's reserved slot or a share of the allowance,
    /// whichever is free first.
    ///
    /// A race rather than a check-then-queue, because the reserved slot can
    /// free *while* a lookup waits: the shared allowance may not come back for
    /// tens of seconds under attack, while the reserved slot turns over as
    /// fast as this connection's own lookups finish. A lookup parked on the
    /// shared queue therefore keeps a claim on the reserved slot too — that is
    /// what makes "serial at worst" literally true instead of "one lookup per
    /// burst of arrivals". `biased` puts the reserved slot first so a free one
    /// is taken before the shared allowance is touched.
    ///
    /// Within the shared branch the order is not interchangeable: the per-
    /// connection permit is taken *first*, so a connection already at
    /// [`BURST_LOOKUPS`] queues on its own limit rather than on the server's,
    /// and never sits in the shared queue holding a permit it is not using.
    /// Losing the race drops that branch and gives back whatever it held.
    ///
    /// Neither semaphore is ever closed, and a closed one is the only error
    /// `acquire_owned` has.
    async fn acquire(&self) -> LookupSlot {
        let from_shared = async {
            let burst = self
                .slots
                .burst
                .clone()
                .acquire_owned()
                .await
                .expect("the budget is never closed");
            let shared = self
                .slots
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
            reserved = self.slots.reserved.clone().acquire_owned() => LookupSlot::Reserved {
                _slot: reserved.expect("the budget is never closed"),
            },
            slot = from_shared => slot,
        }
    }
}

/// A lookup's claim on the blocking pool, released when it is dropped.
///
/// Owned rather than borrowed because of where it is dropped: it travels into
/// the blocking task and is released there, outliving the future that asked for
/// it whenever a `connect_timeout` expires first. See [`on_the_blocking_pool`].
#[derive(Debug)]
enum LookupSlot {
    /// The connection's own slot.
    ///
    /// Named with a leading underscore because it is never read: a permit is
    /// held, not consulted, and releasing it is what dropping this does.
    Reserved { _slot: OwnedSemaphorePermit },
    /// One of the connection's burst permits, and the shared one it stands for.
    Shared {
        _burst: OwnedSemaphorePermit,
        _shared: OwnedSemaphorePermit,
    },
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

        use std::future::Future;
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
            let budget = ResolverBudget::new();
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
            let budget = ResolverBudget::new();

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
            let budget = ResolverBudget::new();
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
            let budget = ResolverBudget::new();
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
        /// Asserted without a runtime at all: `lookup_host` would reach the
        /// blocking pool, and reaching it from here panics. So a literal
        /// answered by a single poll is a literal that never went near a
        /// thread — with every slot this connection has already held.
        #[test]
        fn an_ip_literal_needs_no_slot() {
            let budget = ResolverBudget::new();
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
        /// Note what this does *not* say. A lookup that has already reached the
        /// blocking pool keeps its slot when its caller gives up, on purpose:
        /// the permit travels into the blocking task and is released by the
        /// thread, because `getaddrinfo` is not cancellable and a slot freed at
        /// `connect_timeout` would say a thread is free while it is still gone
        /// (D90). What is proved here is the other half — a lookup that never
        /// got a slot must not keep a claim on one.
        #[test]
        fn lookups_that_all_give_up_at_once_give_back_everything_they_held() {
            let budget = ResolverBudget::new();

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
            assert_eq!(victim.slots.burst.available_permits(), BURST_LOOKUPS);

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
                victim.slots.burst.available_permits(),
                0,
                "a parked lookup is meant to be holding its burst permit while it queues"
            );

            // Every one of them gives up in the same instant.
            drop(parked);

            assert_eq!(
                victim.slots.burst.available_permits(),
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

        /// The pool has a thread for every slot the budget can hand out.
        #[test]
        fn the_pool_covers_every_slot_the_budget_can_hand_out() {
            for max_connections in [1, 16, crate::config::DEFAULT_MAX_CONNECTIONS, 4096] {
                let reserved = (max_connections as usize).min(RESERVED_LOOKUP_CEILING);

                assert!(
                    blocking_pool_size(max_connections) >= reserved + SHARED_LOOKUPS,
                    "max_connections = {max_connections}"
                );
                assert_eq!(
                    blocking_pool_size(max_connections) - reserved - SHARED_LOOKUPS,
                    LOOKUP_FREE_THREADS,
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
        }
    }

    #[tokio::test]
    async fn resolves_ipv4_literals_without_a_resolver() {
        let addresses = resolve("192.0.2.1", 443).await.expect("literal resolves");
        assert_eq!(addresses, vec!["192.0.2.1:443".parse().unwrap()]);
    }

    /// Bare, which is the only form that reaches here: `tunnel::tcp` takes the
    /// brackets off an RFC 3986 authority and RFC 9298's template never has
    /// them. A bracketed literal is a host name with characters no host name may
    /// contain, and is left to fail as one.
    #[tokio::test]
    async fn resolves_bare_ipv6_literals() {
        let bare = resolve("2001:db8::1", 53).await.expect("bare literal");
        assert_eq!(bare, vec!["[2001:db8::1]:53".parse().unwrap()]);
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
