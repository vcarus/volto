//! The connections the endpoint is serving, which the accept loop decides
//! `max_connections` against.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::Notify;

use super::transport::AuthGate;

/// One connection this endpoint is serving.
struct Slot {
    /// The peer's address, so the eviction can say whose slot was taken.
    remote: SocketAddr,
    /// Whether a request on this connection has passed the credentials check.
    ///
    /// The very gate [`crate::tunnel::Context`] opens (D76), created here and
    /// handed down, so that the accept loop can read it without reaching into
    /// a connection it does not own.
    authenticated: AuthGate,
    /// Ends this connection. `notify_one` leaves a permit behind, so a slot
    /// evicted before its task has run is still ended by it rather than
    /// missing the signal.
    evict: Arc<Notify>,
}

/// The connections this endpoint is serving, ordered by accept sequence.
///
/// What `max_connections` is decided against, and the reason it is a roster
/// rather than a count: at the cap the newcomer is not the only candidate for
/// refusal. Every bound an unauthenticated connection is under is a bound on
/// *one* connection — one idle timeout for the QUIC handshake, one for the
/// HTTP/3 handshake, then twice one for the first request to authenticate (D76)
/// — and none of them bounds how many slots such connections may hold between
/// them. A peer that completes a handshake about once a second and never sends
/// a credential holds all 256 of the default slots for as long as it likes,
/// each slot legitimately, while every client with credentials is refused
/// (audit 2026-08-23).
///
/// So at the cap the oldest connection that has never authenticated loses its
/// slot to the newcomer, and only a server whose every live connection *has*
/// authenticated refuses. A sub-quota for unauthenticated connections would not
/// do: a legitimate client is unauthenticated at accept time too, so it would be
/// squeezed by the same pool it is trying to join. An authenticated connection
/// is never a candidate, and below the cap none of this runs at all.
///
/// `max_connections` is a soft cap on tasks, and an exact one on slots. A victim
/// leaves the roster the moment it is chosen, while its task takes as long to
/// notice as one poll takes, so for that moment the process is running one more
/// connection than the cap names. That is harmless: what a slot rations is the
/// right to sit here unauthenticated, and a connection in that state holds no
/// tunnel, no target socket and no file descriptor beyond the endpoint's — the
/// resources worth rationing are behind [`crate::tunnel::Quota`], which counts
/// per connection and is not touched by any of this.
///
/// The lock is a `std::sync::Mutex` and is never held across an await — only
/// long enough to walk a map that has at most `max_connections` entries.
#[derive(Clone)]
pub(super) struct Roster {
    /// Keyed by accept sequence, so the first entry is the oldest connection.
    slots: Arc<Mutex<BTreeMap<u64, Slot>>>,
    /// The sequence number the next registration takes.
    next: Arc<AtomicU64>,
}

impl Roster {
    pub(super) fn new() -> Self {
        Self {
            slots: Arc::new(Mutex::new(BTreeMap::new())),
            next: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Poisoning would mean a panic while walking the map; every value in it is
    /// a handle whose own state lives elsewhere, so there is nothing to observe
    /// half-written.
    fn slots(&self) -> MutexGuard<'_, BTreeMap<u64, Slot>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many connections hold a slot right now.
    pub(super) fn len(&self) -> usize {
        self.slots().len()
    }

    /// Enters a connection about to be served, returning its eviction signal
    /// and the guard that takes it off the roster again.
    pub(super) fn register(
        &self,
        remote: SocketAddr,
        authenticated: AuthGate,
    ) -> (Arc<Notify>, Registration) {
        let evict = Arc::new(Notify::new());
        let sequence = self.next.fetch_add(1, Ordering::Relaxed);

        self.slots().insert(
            sequence,
            Slot {
                remote,
                authenticated,
                evict: evict.clone(),
            },
        );

        (
            evict,
            Registration {
                slots: self.slots.clone(),
                sequence,
            },
        )
    }

    /// Evicts until the roster is below `cap`, naming the victims in the order
    /// they were taken.
    ///
    /// A loop rather than a single eviction, because the cap it is measured
    /// against can move. One victim is all a server that has been sitting at a
    /// steady cap ever needs; a `SIGHUP` that lowers `max_connections` below the
    /// number of connections already live leaves the roster over the new cap,
    /// and only this brings it back down — otherwise the reload would be
    /// honoured for the newcomer and quietly ignored for everybody already in,
    /// for the lifetime of those connections.
    ///
    /// It stops when there is nothing left that may be taken, which is the same
    /// condition the caller's refusal tests: an answer that leaves the roster at
    /// the cap means every live connection has authenticated.
    ///
    /// A method rather than the loop written out at the accept path, so that
    /// what the unit tests run is what the server runs (audit follow-up
    /// 2026-08-24): the tests used to walk a copy of it, and changing the
    /// server's own loop back to a single eviction left every one of them green.
    ///
    /// One guard for the whole loop rather than two acquisitions per pass. With
    /// the lock taken and released between the length read and the eviction, a
    /// connection ending on another thread in that window left the roster below
    /// the cap and the next pass evicted somebody who no longer had to go: one
    /// extra unauthenticated connection dropped from a population that is
    /// already churning. Benign, and recorded as F2 of D96 with the instruction
    /// to fix it the next time this file changed.
    pub(super) fn evict_until_below(&self, cap: usize) -> Vec<SocketAddr> {
        let mut victims = Vec::new();
        let mut slots = self.slots();

        while slots.len() >= cap {
            let Some(victim) = evict_oldest_from(&mut slots) else {
                break;
            };
            victims.push(victim);
        }

        victims
    }
}

/// Takes the oldest never-authenticated connection out of `slots` and ends it.
///
/// The victim is removed from the roster here rather than by its own task, so
/// that a burst of accepts at the cap evicts successive connections instead of
/// picking the same one over and over while it winds down. `None` means every
/// entry left has authenticated.
///
/// A free function over the guard rather than a method that takes its own, so
/// that [`Roster::evict_until_below`] can run it repeatedly under one guard and
/// the roster's own tests can run exactly what the server runs.
fn evict_oldest_from(slots: &mut BTreeMap<u64, Slot>) -> Option<SocketAddr> {
    let sequence = *slots
        .iter()
        .find(|(_, slot)| !slot.authenticated.is_open())
        .map(|(sequence, _)| sequence)?;

    let slot = slots.remove(&sequence)?;
    slot.evict.notify_one();

    Some(slot.remote)
}

/// A connection's place on the [`Roster`], given up when its task ends.
///
/// A guard rather than a call at the end of the task, because the task has
/// several endings — a refused handshake, an eviction, a panic — and a slot that
/// outlived any one of them would be a slot nothing can ever give back.
pub(super) struct Registration {
    slots: Arc<Mutex<BTreeMap<u64, Slot>>>,
    sequence: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            // Already gone when an eviction took the entry out; sequence
            // numbers are never reused, so this can only ever remove this
            // connection's own slot.
            .remove(&self.sequence);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // The roster
    // -----------------------------------------------------------------------

    /// A documentation address (RFC 5737 §3) with `n` in its last octet.
    fn peer(n: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, n], 443))
    }

    /// A gate a request has already passed, for the rosters that are about what
    /// an authenticated connection is owed.
    fn authenticated_gate() -> AuthGate {
        let gate = AuthGate::closed();
        assert!(gate.mark(), "the first pass through a gate is the first");
        gate
    }

    /// Registers `count` connections that have never authenticated, keeping the
    /// registrations alive: dropping one gives its slot straight back.
    fn park(roster: &Roster, count: u8) -> Vec<Registration> {
        (0..count)
            .map(|n| {
                let (_evict, registration) = roster.register(peer(n), AuthGate::closed());
                registration
            })
            .collect()
    }

    /// A cap that has just been lowered is caught up with, not lived over.
    ///
    /// One eviction per arrival is all a server sitting at a steady cap needs.
    /// A `SIGHUP` that lowers `max_connections` below the number of connections
    /// already live is the case that is not steady: [`Server::admit`] reads the cap
    /// per accepted connection, so the newcomer is judged against the new value
    /// while everybody already in was admitted under the old one, and without
    /// the loop inside `evict_until_below` -- the accept path's own, called here
    /// rather than copied -- the roster would sit above the new cap for as long
    /// as those connections lasted.
    ///
    /// Five live and a cap of two leaves room for the newcomer, so four go: the
    /// loop stops at one, and the arrival that runs it makes two.
    #[test]
    fn a_lowered_cap_evicts_until_there_is_room() {
        let roster = Roster::new();
        let _parked = park(&roster, 5);

        assert_eq!(
            roster.evict_until_below(2),
            vec![peer(0), peer(1), peer(2), peer(3)],
            "the victims must be the oldest four, oldest first"
        );
        assert_eq!(roster.len(), 1, "one slot is left for the newcomer");
    }

    /// The loop stops when there is nothing left it may take.
    ///
    /// An authenticated connection is never a candidate, so a roster of them is
    /// what makes the accept loop refuse rather than spin.
    #[test]
    fn eviction_stops_when_every_connection_has_authenticated() {
        let roster = Roster::new();

        let mut held = Vec::new();
        for n in 0..3 {
            let (_evict, registration) = roster.register(peer(n), authenticated_gate());
            held.push(registration);
        }

        assert!(
            roster.evict_until_below(1).is_empty(),
            "an authenticated connection must never lose its slot"
        );
        assert_eq!(roster.len(), 3, "and must still be on the roster");
    }

    /// Why the accept loop asks whether there is a cap before applying one.
    ///
    /// `max_connections = 0` means "no limit", and the guard in [`Server::admit`]
    /// is the whole of that meaning. Handed to this arithmetic as a number, zero
    /// is the harshest cap there could be -- every roster is at or above it -- so
    /// each arrival would empty the roster and then be refused for finding it
    /// still full. The configuration would mean the opposite of what it says.
    #[test]
    fn a_cap_of_zero_would_empty_the_roster_if_it_were_ever_applied() {
        let roster = Roster::new();
        let _parked = park(&roster, 3);

        assert_eq!(roster.evict_until_below(0), vec![peer(0), peer(1), peer(2)]);
        assert_eq!(
            roster.len(),
            0,
            "and then there would be nobody left to refuse"
        );
    }

    /// A signal sent before the victim is listening must not be lost.
    ///
    /// A slot is taken in `serve` before the connection's task has polled
    /// anything, so an eviction can arrive between the registration and the
    /// `select!` that waits on it. `Notify::notify_one` leaves a permit behind
    /// for exactly that, and the whole pre-handshake eviction path rests on it:
    /// with a plain channel send, or a `Notify` whose permit did not persist,
    /// the victim would wait out its handshake deadline instead.
    #[tokio::test]
    async fn an_eviction_that_arrives_first_is_still_delivered() {
        let roster = Roster::new();
        let (evict, _registration) = roster.register(peer(0), AuthGate::closed());

        assert_eq!(evict_oldest_from(&mut roster.slots()), Some(peer(0)));

        // Nothing was awaiting the signal when it was sent, and it is still
        // there to be collected.
        tokio::time::timeout(std::time::Duration::from_secs(5), evict.notified())
            .await
            .expect("the permit `notify_one` stored must outlive the send");
    }

    /// An eviction a lost `select!` race consumed is still delivered to the
    /// next wait.
    ///
    /// `serve` waits on this signal *twice* — once beside the QUIC handshake,
    /// once beside the whole connection — and the two waits are separate
    /// futures. So there is a window nothing else in this file covers: the
    /// eviction lands while the first wait is parked, `Notify` hands the
    /// notification to that waiter, and then the handshake completes in the
    /// same wake-up and wins the race. The first wait is dropped holding a
    /// notification it never returned.
    ///
    /// If that were lost, the victim would keep running until its own idle
    /// timeout rather than "as long as one poll takes", which is what the
    /// [`Roster`] documentation promises and what an operator reading
    /// `max_connections` is owed. `Notify` puts an unclaimed notification back
    /// as a permit when its waiter is dropped, and this pins that: the whole
    /// two-wait design rests on it and nothing said so.
    ///
    /// Polled through a bare waker rather than awaited, so the assertion is
    /// about the permit being there and not about a runtime getting round to
    /// it.
    #[tokio::test]
    async fn an_eviction_a_lost_race_consumed_is_still_delivered() {
        use std::task::{Context as TaskContext, Poll, Waker};

        let roster = Roster::new();
        let (evict, _registration) = roster.register(peer(0), AuthGate::closed());

        let mut cx = TaskContext::from_waker(Waker::noop());

        // The wait beside the handshake, parked.
        let mut first = Box::pin(evict.notified());
        assert_eq!(first.as_mut().poll(&mut cx), Poll::Pending);

        // The eviction arrives while it is parked, and is handed to it.
        assert_eq!(evict_oldest_from(&mut roster.slots()), Some(peer(0)));

        // The other arm of that `select!` wins the wake-up: this one is dropped
        // without ever being polled again.
        drop(first);

        // The wait beside the connection must still find it.
        let mut second = Box::pin(evict.notified());
        assert_eq!(
            second.as_mut().poll(&mut cx),
            Poll::Ready(()),
            "an eviction was swallowed by the wait that lost the race"
        );
    }

    /// A dropped registration gives the slot back, and takes nobody else's.
    ///
    /// The guard is what makes the cap survive the several ways a connection
    /// task can end, and sequence numbers are never reused, so a late drop can
    /// only ever remove its own entry — including after an eviction has already
    /// removed it.
    #[test]
    fn a_registration_gives_back_only_its_own_slot() {
        let roster = Roster::new();
        let mut parked = park(&roster, 3);

        // The middle one leaves of its own accord.
        let middle = parked.remove(1);
        drop(middle);
        assert_eq!(roster.len(), 2);

        // The oldest is evicted, and its guard is dropped afterwards: the entry
        // is already gone, and the drop must not reach the third connection's.
        assert_eq!(evict_oldest_from(&mut roster.slots()), Some(peer(0)));
        drop(parked.remove(0));
        assert_eq!(roster.len(), 1);
        assert_eq!(
            evict_oldest_from(&mut roster.slots()),
            Some(peer(2)),
            "the survivor must be the one nobody gave up"
        );
    }
}
