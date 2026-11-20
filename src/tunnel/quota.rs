//! The per-connection budgets: the tunnel budget and the two guards that spend
//! it, the unanswered-packet allowance of the UDP sessions, the bound on the
//! room in quinn's datagram queue, and the authentication failure buckets.
//!
//! One QUIC connection multiplexes as many tunnels as its client asks for, and
//! every one of them costs a file descriptor on the target side, so this is the
//! bound that keeps one client from exhausting the process limit. [`Slot`] is a
//! rationed tunnel and [`Pending`] an accepted request that has not reached the
//! ration yet; the graceful-shutdown drain has to watch both.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use crate::auth::Authenticator;

/// One connection's tunnel budget.
///
/// Every tunnel, TCP or UDP, costs a file descriptor on the target side, and a
/// single client multiplexes as many as it likes onto one QUIC connection. This
/// is the bound that keeps one client from exhausting the process fd limit, so
/// both tunnel types draw on the *same* budget rather than one each.
///
/// A semaphore for the admission decision, plus a signal for the drain: the
/// shutdown path needs to *observe* the count reaching zero without competing
/// for it.
///
/// The drain must not wait by taking every permit with `acquire_many(limit)`.
/// `tokio`'s semaphore is fair, so a waiter that cannot be satisfied yet *takes
/// the permits that are free* and queues for the rest. While it waited,
/// `available_permits()` would be zero, so `live()` would report the full limit
/// and `acquire()` would refuse every caller. The connection would answer
/// `503 connection_limit_reached` to requests below the GOAWAY identifier, which
/// the peer was told "might have been processed" (RFC 9114 §5.2) and which this
/// server means to serve.
pub struct Quota {
    permits: Arc<Semaphore>,
    limit: u32,
    /// Accepted requests that have not finished, whether or not they ever take
    /// a slot.
    ///
    /// The slot is taken late on purpose: after the credentials check, so an
    /// unauthenticated peer cannot spend one, and after the 400 an RFC 9114 §4.2
    /// violation gets. That leaves a stretch of every request's life during
    /// which it is being served and holds nothing. The semaphore cannot see that
    /// stretch, and the drain must: a request below the GOAWAY identifier is
    /// one the peer was told "might have been processed" (RFC 9114 §5.2), and
    /// this server serves those rather than rejecting them individually. So a
    /// request whose HEADERS frame is still arriving must keep the connection
    /// open.
    pending: Arc<AtomicU32>,
    /// Signalled by every [`Slot`] and every [`Pending`] as it goes, so the
    /// drain can watch the count instead of taking part in it.
    idle: Arc<Notify>,
}

/// One occupied tunnel slot, released when dropped.
///
/// Dropping is the *only* way a slot is returned, which makes every exit path
/// (response failure, idle timeout, reset, panic) leak-free by construction, as
/// with the [`crate::h3api::DatagramReceiver`] a UDP session holds for as long
/// as its Quarter Stream ID routes.
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
        // with nothing left to wake it. A current-thread runtime, which the
        // tests below run on, cannot show the difference, so this ordering is
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
/// It lets the drain see a request that is *between* those two points (headers
/// still arriving, credentials being checked), for the reason `Quota`'s
/// `pending` field gives.
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
        // through it, and the only reader is the drain. The drain either
        // reaches it through `Notify`, whose own synchronisation orders this
        // write before that wake-up, or is about to look again anyway.
        self.pending.fetch_sub(1, Ordering::Relaxed);
        self.idle.notify_one();
    }
}

impl Quota {
    /// Creates a quota allowing `limit` concurrent tunnels.
    pub fn new(limit: u32) -> Self {
        Self {
            // Saturating rather than truncating, though neither is reachable:
            // a `u32` is always a `usize` on both supported targets.
            permits: Arc::new(Semaphore::new(usize::try_from(limit).unwrap_or(usize::MAX))),
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
    /// credentials have been checked, and the ones that never get that far (the
    /// 400s, the 407s) never reach it at all. Nothing is rationed here;
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
        // The semaphore was built with `limit` permits and never gains any, so
        // the count is at most `limit`; a count past a `u32` would mean no
        // tunnel is live, which is what the fallback reads as.
        self.limit - u32::try_from(self.permits.available_permits()).unwrap_or(self.limit)
    }

    /// Whether anything on this connection is still being served.
    ///
    /// Both halves count, and the second is the one a tunnel count alone
    /// misses: a request accepted before the GOAWAY whose headers are still
    /// arriving holds no slot (see `Quota`'s `pending` field). Closing the
    /// connection on it would also send no REQUEST_REJECTED that would let the
    /// client retry.
    pub fn is_busy(&self) -> bool {
        self.live() > 0 || self.pending.load(Ordering::Relaxed) > 0
    }

    /// Resolves once every request on this connection has finished.
    ///
    /// Used by the graceful shutdown path. The caller is responsible for
    /// bounding the wait: a tunnel that never ends would otherwise hold
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

/// Packets one connection's UDP sessions may send towards targets that have
/// never answered (RFC 9298 §7).
///
/// Two halves from one number, `[security] unanswered_packet_budget`. The
/// per-session half ([`Self::per_session`]) is what RFC 9298 §7 asks for, and
/// it is recreated by opening a session, which is free: a client that spends
/// one session's allowance closes the stream and opens another, and the
/// mitigation becomes a constant factor rather than a bound. Stream turnover
/// is not bounded by anything (`max_streams_bidi` bounds how many are open at
/// once and quinn issues fresh credit as streams complete), so the
/// connection's half is the counter an attacker cannot recreate: it is created
/// with the connection, [`super::CONNECTION_UNANSWERED_MULTIPLIER`] session
/// budgets, and it is only ever spent.
///
/// **A session whose target answers repays what that session spent**, and
/// nothing else does (D84, the 2026-09-05 addendum). The repayment is that
/// session's own `charged` count, kept while its target has not answered, and
/// it is capped at the total the connection was created with, so no sequence
/// of sessions can lift the counter above where it started. A client cannot
/// keep one consenting target on the side to buy back, packet for packet, the
/// allowance it spends on a silent one: the refund is per session, so a silent
/// session's spend stays spent, and the bound on packets to targets that never
/// answer holds.
///
/// A connection that spends the total with nothing outstanding to repay it
/// keeps it spent for its own life, and a client that wants another allowance
/// pays for another handshake (D84, the 2026-09-07 addendum).
///
/// Zero switches both halves off: the operator switched the mitigation off,
/// and a session that is never capped must never be closed for having reached
/// a cap.
///
/// `Relaxed` throughout: the counter is ordered against nothing but itself,
/// and `try_update`'s compare-and-swap is what makes two sessions racing for
/// the last packet give it to exactly one of them.
pub(crate) struct Unanswered {
    /// Packets one session may send before its target has answered.
    per_session: u32,
    /// Packets the connection may still send, across every session it opens.
    remaining: AtomicU32,
    /// What `remaining` was created with, which is the ceiling every refund is
    /// capped at. Stored once, so the seed and the cap are one number.
    total: u32,
}

impl Unanswered {
    /// The allowance of a connection whose sessions may each send
    /// `per_session` unanswered packets.
    pub(crate) fn new(per_session: u32) -> Self {
        // Saturating for a value an operator chose; the shipped default is
        // asserted not to saturate beside the multiplier.
        let total = per_session.saturating_mul(super::CONNECTION_UNANSWERED_MULTIPLIER);
        Self {
            per_session,
            remaining: AtomicU32::new(total),
            total,
        }
    }

    /// Packets one session may send before its target has answered. Zero
    /// means they are not counted.
    pub(crate) fn per_session(&self) -> u32 {
        self.per_session
    }

    /// Spends one packet of the connection's allowance, reporting whether there
    /// was one to spend.
    ///
    /// `false` is the end of the session that asked, not of the packet: a
    /// session that finds this empty is closed rather than muted. Muting it
    /// would leave a socket, a routing entry and a stream in place until the
    /// idle timeout for a client that has already shown what it is doing with
    /// them, and it would let the next session pay nothing to be created.
    ///
    /// Charged only where the per-session budget is charged, so a session whose
    /// target has answered spends nothing here, and neither does a session whose
    /// own budget is already spent: a muted session attempts no packet, and
    /// this counts packets a session attempted towards a target that had not
    /// answered. Attempted rather than sent, deliberately: the charge is taken
    /// before `sendto`, so a payload the socket refuses per packet (EMSGSIZE,
    /// EPERM, EACCES, ENOBUFS) is counted without leaving the host. The
    /// direction is the safe one for a counter that bounds reflection.
    pub(crate) fn charge(&self) -> bool {
        if self.per_session == 0 {
            return true;
        }

        self.remaining
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
    }

    /// Gives back what one session charged, once its target has answered.
    ///
    /// The total bounds packets sent to targets that never answer. A session
    /// whose target did answer was not one of those, so what it spent on the
    /// way there is returned, and only that: `charged` is the session's own
    /// count, so a client keeping a consenting target on the side can recover
    /// no more than that side session's own packets, never what another
    /// session spent into silence. Without the refund every session's first
    /// packet is a charge that nothing repays, and a long-lived connection
    /// opening short answered sessions one after another, which is what DNS
    /// through the tunnel is, spends the total by session count alone.
    ///
    /// Capped at the connection's total so a refund can never exceed what was
    /// created with the connection, whatever the caller's count.
    pub(crate) fn refund(&self, charged: u32) {
        if self.per_session == 0 || charged == 0 {
            return;
        }

        let total = self.total;
        let _ = self
            .remaining
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                Some(remaining.saturating_add(charged).min(total))
            });
    }
}

/// What one queued datagram costs quinn's datagram send buffer beyond its own
/// bytes, or more.
///
/// quinn charges `size_of` its frame struct per queued datagram, which wraps
/// one `Bytes` and is 32 bytes on a 64-bit target. The struct is private to
/// quinn, so twice that is used: a cost counted too high leaves
/// [`DatagramRoom::claim`]'s bound lower than the room, which costs a
/// reading and never a wrong grade.
pub(crate) const QUEUED_DATAGRAM_COST: usize = 2 * std::mem::size_of::<bytes::Bytes>();

/// A lower bound of the room left in quinn's outgoing datagram queue, in the
/// units `quinn::Connection::datagram_send_buffer_space` reports.
///
/// The UDP path reads that room only to say when a send evicts older datagrams
/// (`udp::DatagramPath`), and reading it takes the connection's lock. This
/// holds the last reading less what every session on the connection has
/// queued since, which stays a lower bound because quinn only ever adds room:
/// by sending, by evicting, or by dropping what no longer fits the path. A
/// datagram the bound already covers fits, so it is graded without a reading.
/// Starts at zero, so the first datagram reads.
#[derive(Default)]
pub(crate) struct DatagramRoom(AtomicUsize);

impl DatagramRoom {
    /// Counts a datagram of `len` bytes against the bound if the bound shows
    /// room for it, reporting whether it did.
    ///
    /// `true` means quinn's queue has room for the datagram, by the same
    /// `len <= space` comparison quinn makes, and the bound is lowered by what
    /// queuing it costs. `false` changes nothing: the caller reads the real
    /// room and hands the reading to [`Self::reset`].
    ///
    /// `Relaxed`, for the reason [`Unanswered`] gives: the bound is ordered
    /// against nothing but itself, and the compare-and-swap is what makes two
    /// sessions' claims both count.
    pub(crate) fn claim(&self, len: usize) -> bool {
        self.0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |room| {
                (len <= room).then(|| room.saturating_sub(len.saturating_add(QUEUED_DATAGRAM_COST)))
            })
            .is_ok()
    }

    /// Replaces the bound with `space`, read from quinn just before a datagram
    /// of `len` bytes is queued, less what queuing it costs.
    ///
    /// One reading and one queued datagram are not one step, here or in
    /// quinn's own API, so a datagram another session queues between this
    /// session's reading and its store is not counted. The bound can then be
    /// that datagram's cost too high, and a later datagram can be graded as
    /// fitting by that much when it did not. A single session is exact. Two
    /// separate lock acquisitions for the reading and the send would have the
    /// same interleaving.
    pub(crate) fn reset(&self, space: usize, len: usize) {
        self.0.store(
            space.saturating_sub(len.saturating_add(QUEUED_DATAGRAM_COST)),
            Ordering::Relaxed,
        );
    }

    /// The current lower bound, for tests.
    #[cfg(test)]
    pub(crate) fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

/// The authentication failures one connection has run up, in buckets.
///
/// Which bucket a failure lands in is what makes clearing them on success
/// honest. `auth.users` is a list, so a peer can hold one valid credential and
/// guess at another user's password with it: with one counter cleared by any
/// success, it interleaves a good request between guesses and never reaches
/// `max_auth_failures`. One counter *per user-id guessed at* closes that, and
/// keeps the case the clearing exists for: one client, one credential, an app
/// that drops the header now and then.
///
/// A single counter charged to the first failure that named somebody is not
/// enough either: the peer opens each cycle with a deliberate failure as
/// *itself*, which claims the counter, and its success as itself then clears
/// the whole thing, guesses at everybody else included.
///
/// The cap is on the **total** across the buckets, not on any one of them. A
/// per-bucket cap would hand a guesser `max_auth_failures - 1` free guesses for
/// every configured user rather than that many for the whole connection.
///
/// One connection holds at most `|configured users| + 2` counters, and every key
/// is a copy of a name from the configuration file, so a peer cannot grow this
/// by inventing user-ids however many it invents.
#[derive(Default)]
pub struct AuthFailures {
    /// One counter per configured user-id a failure has named, created when
    /// that name is first guessed at.
    ///
    /// A success as that user clears its counter and nothing else. Keyed by a
    /// name that compared equal to a configured one, so the key's length comes
    /// from the configuration file rather than from the peer. A user-id too
    /// long to log is truncated by [`crate::auth::Denied::username`] and
    /// therefore matches nothing here, so its guesses land in `unconfigured`
    /// below.
    configured: std::collections::HashMap<String, u32>,
    /// Failures naming a user-id nobody has.
    ///
    /// One bucket for all of them, and no success ever clears it: succeeding as
    /// a user that does not exist is not a thing that can happen, so a success
    /// says nothing about these at all. This is where a scan lands.
    unconfigured: u32,
    /// Failures that named nobody.
    ///
    /// They carried no user-id this server could read (no credentials field at
    /// all, or one it could not parse), so they are the benign case: the app
    /// that dropped the header, not the peer that guessed. Any success clears
    /// this one, because any success is a client proving it is that client.
    ///
    /// It cannot be used to hide a guess: a guess names somebody and is
    /// charged to that name's bucket however many credential-less requests are
    /// sent around it.
    anonymous: u32,
}

impl AuthFailures {
    /// Records a failure, reporting whether the total has reached `cap`.
    ///
    /// `username` is the user-id the failing request claimed, or `None` when it
    /// carried none this server could read. Which of the three kinds of bucket
    /// it lands in is decided by asking `auth` whether that name is one the
    /// operator configured. A `cap` of zero disables the cap.
    pub(crate) fn record(
        &mut self,
        auth: &Authenticator,
        username: Option<&str>,
        cap: u32,
    ) -> bool {
        match username {
            // A name that exists: its own bucket, which only a success as that
            // user clears. Looked up before it is inserted, so only the first
            // failure as a name copies it.
            Some(username) if auth.is_configured(username) => {
                match self.configured.get_mut(username) {
                    Some(bucket) => *bucket = bucket.saturating_add(1),
                    None => {
                        self.configured.insert(username.to_owned(), 1);
                    }
                }
            }
            // A name nobody has, so nobody can ever succeed as it.
            Some(_) => self.unconfigured = self.unconfigured.saturating_add(1),
            // Nobody named at all: the benign case, cleared by any success.
            None => self.anonymous = self.anonymous.saturating_add(1),
        }

        cap > 0 && self.total() >= cap
    }

    /// Clears what a success as `username` answers for: that user's own
    /// bucket, and the failures that named nobody.
    ///
    /// `None` is a success on a server with no users configured, which has no
    /// user's bucket to clear.
    pub(crate) fn clear_for(&mut self, username: Option<&str>) {
        // The request that forgot its header rather than the one that guessed:
        // any success answers for those.
        self.anonymous = 0;

        if let Some(username) = username {
            self.configured.remove(username);
        }
    }

    /// Failures across every bucket, which is what the cap is measured against.
    ///
    /// Saturating rather than wrapping: `max_auth_failures = 0` disables the cap
    /// and nothing then ever clears a bucket, so a connection left open long
    /// enough could otherwise overflow the sum. Saturated is the correct answer:
    /// a total that large is over any cap there could be.
    fn total(&self) -> u32 {
        self.configured
            .values()
            .copied()
            .chain([self.unconfigured, self.anonymous])
            .fold(0u32, u32::saturating_add)
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

        // Still busy: the wait must not resolve yet. The sleep is what lets
        // the spawned waiter run before it is looked at.
        let idle = quota.clone();
        let waiter = tokio::spawn(async move { idle.wait_until_idle().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !waiter.is_finished(),
            "the wait resolved while a slot was held"
        );

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
    /// dispatched. A wait that took `acquire_many(limit)` would be handed every
    /// free permit up front by the fair semaphore, and every request would be
    /// refused until the drain ended; [`Quota`] has the argument.
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
    /// `live()` alone would close the connection on it.
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
    /// entitled to, the same shape as the wait [`Quota`]'s doc rules out.
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

    /// An authenticator that knows exactly one user.
    fn one_user() -> Authenticator {
        Authenticator::new(&crate::config::Auth {
            users: vec![crate::config::User {
                username: "user1".into(),
                password: "s3cret".into(),
            }],
        })
    }

    /// A cap well above what the bucket tests record, so every failure answers
    /// "not yet" and the buckets are the only subject.
    const CAP: u32 = 100;

    /// A refund returns exactly what one session charged, and never lifts the
    /// counter past the total the connection was created with.
    ///
    /// The three things D84's 2026-09-05 addendum promises, in order: a spent
    /// total buys nothing, a refund of two buys two and no third, and a refund
    /// of everything an attacker could ask for stops at the total. The last one
    /// is the cap `Unanswered::refund` applies; without it a connection could
    /// end up with more allowance than it was created with.
    #[test]
    fn a_refund_returns_a_sessions_own_charge_and_no_more() {
        const BUDGET: u32 = 3;
        const TOTAL: u32 = BUDGET * super::super::CONNECTION_UNANSWERED_MULTIPLIER;

        let unanswered = Unanswered::new(BUDGET);
        for _ in 0..TOTAL {
            assert!(unanswered.charge());
        }
        assert!(!unanswered.charge(), "the total is spent");

        // One answered session hands back the two packets it sent into silence
        // before the answer, and exactly two more packets fit.
        unanswered.refund(2);
        assert!(unanswered.charge());
        assert!(unanswered.charge());
        assert!(!unanswered.charge(), "a refund of two must buy exactly two");

        // A refund past the total is capped at it: the counter is what the
        // connection was created with, never more.
        unanswered.refund(u32::MAX);
        for packet in 0..TOTAL {
            assert!(unanswered.charge(), "packet {packet} after a full refund");
        }
        assert!(
            !unanswered.charge(),
            "a refund cannot lift the counter past the connection's total"
        );

        // Uncapped stays uncapped, and a refund of nothing changes nothing.
        let uncapped = Unanswered::new(0);
        uncapped.refund(5);
        assert!(uncapped.charge());
    }

    /// The connection's allowance is spent once and, with nothing outstanding
    /// to repay it, never given back; and the operator's off switch turns it
    /// off too.
    ///
    /// Charged one packet at a time because that is how a session spends it, and
    /// the number that has to be exact is the last one: the packet after the
    /// total is the one whose session is closed.
    #[test]
    fn the_connections_unanswered_total_is_spent_exactly_once() {
        const BUDGET: u32 = 3;

        let unanswered = Unanswered::new(BUDGET);
        for packet in 0..BUDGET * super::super::CONNECTION_UNANSWERED_MULTIPLIER {
            assert!(
                unanswered.charge(),
                "packet {packet} is inside the connection's total"
            );
        }

        assert!(
            !unanswered.charge(),
            "the packet after the total must find nothing left"
        );
        assert!(
            !unanswered.charge(),
            "and a second session opened afterwards finds the same"
        );

        // Zero is the operator switching the mitigation off, which has to switch
        // off both halves of it: a session that is never capped must never be
        // closed for having reached a cap.
        let uncapped = Unanswered::new(0);
        for _ in 0..1000 {
            assert!(uncapped.charge());
        }
    }

    /// A guess at a user-id nobody has must not become a key.
    ///
    /// The buckets are what make clearing failures on success honest, and this
    /// is the half of them whose input a peer chooses: a failure naming a
    /// configured user gets that user's own counter, and every other name is
    /// charged to the one counter no success clears. One connection therefore
    /// holds at most `|configured users| + 2` counters however many names are
    /// tried against it.
    #[test]
    fn a_guess_at_a_name_nobody_has_never_grows_the_buckets() {
        let auth = one_user();
        let mut failures = AuthFailures::default();

        // Near misses included: what decides the bucket is the comparison
        // `Authenticator` makes, not how close the name looks.
        for guess in ["admin", "root", "user1 ", "USER1", ""] {
            assert!(
                !failures.record(&auth, Some(guess), CAP),
                "{guess:?} must not reach the cap"
            );
        }

        assert_eq!(failures.unconfigured, 5);
        assert!(
            failures.configured.is_empty(),
            "a name nobody has became a key: {:?}",
            failures.configured.keys().collect::<Vec<_>>()
        );
        assert_eq!(failures.anonymous, 0);

        // The other two buckets, so the assertions above can only hold for the
        // right reason: a configured name does get a counter of its own, and a
        // failure that named nobody at all gets the third.
        assert!(!failures.record(&auth, Some("user1"), CAP));
        assert!(!failures.record(&auth, None, CAP));

        assert_eq!(failures.configured.len(), 1);
        assert_eq!(failures.configured.get("user1").copied(), Some(1));
        assert_eq!(failures.unconfigured, 5);
        assert_eq!(failures.anonymous, 1);
    }

    /// Failures as one configured user add up in that user's one bucket.
    #[test]
    fn failures_as_one_user_add_up_in_its_bucket() {
        let auth = one_user();
        let mut failures = AuthFailures::default();
        for _ in 0..3 {
            assert!(!failures.record(&auth, Some("user1"), CAP));
        }

        assert_eq!(failures.configured.len(), 1);
        assert_eq!(failures.configured.get("user1").copied(), Some(3));
    }
}
