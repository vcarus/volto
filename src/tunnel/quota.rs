//! The per-connection tunnel budget, and the two guards that spend it.
//!
//! One QUIC connection multiplexes as many tunnels as its client asks for, and
//! every one of them costs a file descriptor on the target side, so this is the
//! bound that keeps one client from exhausting the process limit. [`Slot`] is a
//! rationed tunnel and [`Pending`] an accepted request that has not reached the
//! ration yet; the graceful-shutdown drain has to watch both.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

/// One connection's tunnel budget.
///
/// Every tunnel — TCP or UDP — costs a file descriptor on the target side, and a
/// single client multiplexes as many as it likes onto one QUIC connection. This
/// is the bound that keeps one client from exhausting the process fd limit, so
/// both tunnel types draw on the *same* budget rather than one each.
///
/// A semaphore for the admission decision, plus a signal for the drain: the
/// shutdown path needs to *observe* the count reaching zero without competing
/// for it.
///
/// The two used to be one thing — `wait_until_idle` was `acquire_many(limit)`,
/// on the reading that taking every permit at once is the same as waiting for
/// every tunnel to end. It is not. `tokio`'s semaphore is fair, so a waiter that
/// cannot be satisfied yet *takes the permits that are free* and queues for the
/// rest; while the drain waited, `available_permits()` was zero, so `live()`
/// reported the full limit and `acquire()` refused every caller. The connection
/// then answered `503 connection_limit_reached` to requests below the GOAWAY
/// identifier — ones the peer had been told "might have been processed",
/// RFC 9114 §5.2, and this server means to serve — with one tunnel open out of
/// a hundred (adversarial pass 2026-08-29).
pub struct Quota {
    permits: Arc<Semaphore>,
    limit: u32,
    /// Accepted requests that have not finished, whether or not they ever take
    /// a slot.
    ///
    /// The slot is taken late on purpose -- after the credentials check, so an
    /// unauthenticated peer cannot spend one, and after the 400 an RFC 9114 §4.2
    /// violation gets -- which leaves a stretch of every request's life during
    /// which it is being served and holds nothing. The semaphore cannot see that
    /// stretch, and the drain must: a request below the GOAWAY identifier is
    /// one the peer was told "might have been processed" (RFC 9114 §5.2), and
    /// this server serves those rather than rejecting them individually -- so a
    /// request whose HEADERS frame is still arriving is squarely its business
    /// (adversarial pass 2026-08-30).
    pending: Arc<AtomicU32>,
    /// Signalled by every [`Slot`] and every [`Pending`] as it goes, so the
    /// drain can watch the count instead of taking part in it.
    idle: Arc<Notify>,
}

/// One occupied tunnel slot, released when dropped.
///
/// Dropping is the *only* way a slot is returned, which is what makes every exit
/// path — response failure, idle timeout, reset, panic — leak-free by
/// construction, in the same spirit as the [`crate::h3api::DatagramReceiver`] a
/// UDP session holds for as long as its Quarter Stream ID routes.
pub struct Slot {
    /// `None` only inside [`Drop::drop`], which is how the permit is given back
    /// before the announcement that it was; see there.
    permit: Option<OwnedSemaphorePermit>,
    idle: Arc<Notify>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        // Order matters, and is the reason the permit is an `Option` at all:
        // fields are dropped *after* this body runs. On the multi-threaded
        // runtime the server actually uses, waking the drain first lets it
        // re-read a count that has not moved yet on another core and park again
        // with nothing left to wake it. A current-thread runtime -- what the
        // tests below run on -- cannot show the difference, so this ordering is
        // stated rather than asserted.
        drop(self.permit.take());
        self.idle.notify_one();
    }
}

/// One accepted request that has not finished, released when dropped.
///
/// The companion to [`Slot`], and deliberately not the same thing: a slot is
/// rationed and is taken only once a request has proved it deserves one, while
/// this is taken the moment the request stream is accepted and rations nothing.
/// What it buys is the drain being able to see a request that is *between* those
/// two points — headers still arriving, credentials being checked — which is
/// exactly the request a tunnel-count drain used to close the connection on,
/// against the "might have been processed" its own GOAWAY identifier had just
/// signalled (RFC 9114 §5.2).
///
/// Dropping is the only way it is given back, for the reason [`Slot`] gives.
pub struct Pending {
    pending: Arc<AtomicU32>,
    idle: Arc<Notify>,
}

impl Drop for Pending {
    fn drop(&mut self) {
        // Decrement first, announce second, for the reason `Slot` does it in
        // that order: a drain woken by the announcement must not re-read a
        // count that has yet to move.
        //
        // `Relaxed` is enough on the counter itself. Nothing is published
        // through it, and the only reader is the drain -- which either reaches
        // it through `Notify`, whose own synchronisation orders this write
        // before that wake-up, or is about to look again anyway.
        self.pending.fetch_sub(1, Ordering::Relaxed);
        self.idle.notify_one();
    }
}

impl Quota {
    /// Creates a quota allowing `limit` concurrent tunnels.
    pub fn new(limit: u32) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(limit as usize)),
            limit,
            pending: Arc::new(AtomicU32::new(0)),
            idle: Arc::new(Notify::new()),
        }
    }

    /// Takes a slot, or `None` when the connection is at its limit.
    pub fn acquire(&self) -> Option<Slot> {
        let permit = Arc::clone(&self.permits).try_acquire_owned().ok()?;
        Some(Slot {
            permit: Some(permit),
            idle: self.idle.clone(),
        })
    }

    /// Records that a request has been accepted and is being served.
    ///
    /// Held by the task from the moment the request stream is accepted until
    /// that task ends, which is the span [`Self::acquire`] cannot cover: a
    /// request only reaches the semaphore once its headers have arrived and its
    /// credentials have been checked, and the ones that never get that far --
    /// the 400s, the 407s -- never reach it at all. Nothing is rationed here;
    /// the count exists so the drain can tell "no work left" from "no work that
    /// has a slot yet".
    pub fn enter(&self) -> Pending {
        self.pending.fetch_add(1, Ordering::Relaxed);
        Pending {
            pending: self.pending.clone(),
            idle: self.idle.clone(),
        }
    }

    /// How many tunnels are open right now.
    pub fn live(&self) -> u32 {
        self.limit - self.permits.available_permits() as u32
    }

    /// Whether anything on this connection is still being served.
    ///
    /// Both halves count, and the second is the one a tunnel count alone
    /// misses: a request accepted before the GOAWAY whose headers are still
    /// arriving holds no slot, and closing the connection on it contradicts the
    /// "might have been processed" its GOAWAY identifier signalled (RFC 9114
    /// §5.2) without the REQUEST_REJECTED that would let the client retry.
    pub fn is_busy(&self) -> bool {
        self.live() > 0 || self.pending.load(Ordering::Relaxed) > 0
    }

    /// Resolves once every request on this connection has finished.
    ///
    /// Used by the graceful shutdown path. The caller is responsible for
    /// bounding the wait — a tunnel that never ends would otherwise hold
    /// shutdown open forever.
    ///
    /// Cancel-safe, which it has to be: `crate::conn::handle` polls this as one
    /// arm of a `select!` and drops it again on every pass. `notify_one` leaves
    /// a permit behind when nobody is waiting and hands an unclaimed
    /// notification on when a waiter is dropped, so neither a slot released
    /// between the check and the park nor a lost race can wedge the drain.
    pub async fn wait_until_idle(&self) {
        while self.is_busy() {
            self.idle.notified().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn a_quota_hands_out_exactly_its_limit() {
        let quota = Quota::new(2);
        assert_eq!(quota.live(), 0);

        let first = quota.acquire().expect("first slot");
        let second = quota.acquire().expect("second slot");
        assert_eq!(quota.live(), 2);
        assert!(quota.acquire().is_none(), "the limit must be enforced");

        // Slots are returned by dropping them, on every path.
        drop(first);
        assert_eq!(quota.live(), 1);
        let third = quota.acquire().expect("a freed slot is reusable");
        assert!(quota.acquire().is_none());

        drop(second);
        drop(third);
        assert_eq!(quota.live(), 0);
    }

    #[tokio::test]
    async fn waiting_for_idle_resolves_when_the_last_slot_goes() {
        let quota = Arc::new(Quota::new(4));
        let slot = quota.acquire().expect("slot");

        // Still busy: the wait must not resolve yet.
        let idle = quota.clone();
        let waiter = tokio::spawn(async move { idle.wait_until_idle().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), async {})
                .await
                .is_ok(),
            "the timer works"
        );
        assert!(!waiter.is_finished());

        drop(slot);
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("idle within the timeout")
            .expect("waiter task");
    }

    /// Watching for idle must not *take* the budget it is watching.
    ///
    /// `crate::conn::handle` polls `wait_until_idle` for the whole of a GOAWAY
    /// drain, while requests below the GOAWAY identifier are still being
    /// dispatched. When the wait was `acquire_many(limit)` the fair semaphore
    /// handed it every free permit up front, so `live()` reported the limit and
    /// `acquire()` refused everyone until the drain ended -- and the connection
    /// answered `503 connection_limit_reached` to requests below the GOAWAY
    /// identifier (RFC 9114 §5.2).
    #[tokio::test]
    async fn waiting_for_idle_neither_spends_the_budget_nor_miscounts_it() {
        let quota = Quota::new(4);
        let held = quota.acquire().expect("first slot");

        // Parked, exactly as the drain parks it: polled inside a `select!` that
        // it loses.
        let mut waiting = std::pin::pin!(quota.wait_until_idle());
        tokio::select! {
            () = &mut waiting => panic!("one tunnel is still live"),
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }

        assert_eq!(quota.live(), 1, "the wait must not count as a tunnel");
        let during = quota
            .acquire()
            .expect("a slot must still be available while the drain waits");
        assert_eq!(quota.live(), 2);

        drop(during);
        drop(held);
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("the wait resolves once the last slot goes");
    }

    /// The drain's own shape: the wait is rebuilt and dropped on every pass of
    /// a `select!`, and a slot released while it is not parked must still be
    /// noticed.
    #[tokio::test]
    async fn the_idle_wait_survives_being_cancelled_repeatedly() {
        let quota = Arc::new(Quota::new(4));
        let slots: Vec<_> = (0..3).map(|_| quota.acquire().expect("slot")).collect();

        let mut slots = slots.into_iter();
        for _ in 0..3 {
            // One pass of the loop: build the wait, lose the race, drop it --
            // and release a slot in between, which is the notification most
            // easily lost.
            tokio::select! {
                () = quota.wait_until_idle() => panic!("tunnels are still live"),
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            drop(slots.next().expect("a slot to release"));
        }

        tokio::time::timeout(Duration::from_secs(5), quota.wait_until_idle())
            .await
            .expect("every slot is back, so the wait must resolve");
        assert_eq!(quota.live(), 0);
    }

    /// A request that has been accepted and holds no slot yet is still work.
    ///
    /// The whole of the gap `Pending` closes: a request stream is accepted the
    /// moment the peer opens it, and does not reach [`Quota::acquire`] until its
    /// headers have arrived and its credentials have been checked. Between those
    /// two points `live()` is zero while the connection has committed to serving
    /// something -- and after a GOAWAY that something is a request the peer was
    /// told "might have been processed" (RFC 9114 §5.2). A drain reading
    /// `live()` alone closed the connection on it.
    #[tokio::test]
    async fn a_request_that_has_not_taken_a_slot_still_holds_the_drain() {
        let quota = Quota::new(4);
        let pending = quota.enter();

        assert_eq!(quota.live(), 0, "an accepted request is not yet a tunnel");
        assert!(quota.is_busy(), "but the connection is not idle either");

        let mut waiting = std::pin::pin!(quota.wait_until_idle());
        tokio::select! {
            () = &mut waiting => panic!("a request is still being served"),
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }

        // The request reaches the quota, runs, and gives its slot back: still
        // not idle, because the task itself has not finished.
        let slot = quota.acquire().expect("a slot for the accepted request");
        assert_eq!(quota.live(), 1);
        drop(slot);
        tokio::select! {
            () = &mut waiting => panic!("the request's task has not ended"),
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }

        drop(pending);
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("the wait resolves once the request's task ends");
        assert!(!quota.is_busy());
    }

    /// Entering costs no slot, so the tunnel budget is unchanged by it.
    ///
    /// `Pending` rations nothing -- it only records that a request exists -- and
    /// a version of it that spent a permit would refuse tunnels a connection is
    /// entitled to, which is the shape of the bug `wait_until_idle` used to have.
    #[test]
    fn an_accepted_request_does_not_spend_the_tunnel_budget() {
        let quota = Quota::new(2);
        let _entered: Vec<_> = (0..8).map(|_| quota.enter()).collect();

        assert_eq!(quota.live(), 0);
        let first = quota.acquire().expect("the budget is untouched");
        let second = quota.acquire().expect("the budget is untouched");
        assert!(quota.acquire().is_none(), "the limit is still the limit");
        assert_eq!(quota.live(), 2);

        drop((first, second));
        assert_eq!(quota.live(), 0);
        assert!(quota.is_busy(), "the requests themselves are still running");
    }
}
