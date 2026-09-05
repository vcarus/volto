//! The shutdown signal, from the process down to each connection.
//!
//! Graceful shutdown of a proxy is not "stop the process": every open tunnel is
//! somebody's TCP connection or UDP flow, and dropping them all at once is
//! visible to the user as a burst of broken pages and dead calls. RFC 9114 §5.2
//! provides the polite version, and the sequence the server implements is:
//!
//! 1. stop accepting new QUIC connections;
//! 2. send a GOAWAY on every live HTTP/3 connection, which tells the client to
//!    take its new requests elsewhere while the ones in flight finish;
//! 3. wait for the tunnels to end on their own, up to `server.shutdown_grace`;
//! 4. close the endpoint regardless, so a stuck tunnel cannot hold the process
//!    open forever;
//! 5. stop the runtime, waiting no longer than [`blocking_grace`] for the
//!    blocking tasks that are still running.
//!
//! This module is mostly the signal: a one-way latch that many tasks can wait on
//! and that never un-fires, so a task arriving late still observes it. Steps 1, 3
//! and 4 live in [`crate::quic`]; step 2 lives in [`crate::conn`]; step 5 is
//! [`stop_runtime`] here, called by the binary once the runtime's own work is
//! done.

use std::time::Duration;

use tokio::sync::watch;

/// The margin [`blocking_grace`] adds on top of the shutdown budget.
///
/// A fixed second rather than a fraction of the grace period, because what it
/// covers is fixed work: the scheduling between the accept loop returning and
/// the pool being told to stop, and a blocking task that was about to finish
/// anyway.
pub const EXIT_SLACK: Duration = Duration::from_secs(1);

// D90's 2026-09-04 addendum gives the blocking pool the whole allowance the
// connections got and then a margin on top, so the margin has to be one: at
// zero the pool would be told to stop at the instant the drain ended, with
// nothing left for the scheduling between the two.
const _: () = assert!(!EXIT_SLACK.is_zero());

/// How long the blocking pool gets once the runtime's own work is over.
///
/// `server.shutdown_grace` plus the endpoint's close flush plus [`EXIT_SLACK`],
/// so the allowance a blocking task gets is the whole allowance the connections
/// get and no less. Raising the grace raises both halves, which is what an
/// operator setting that key expects.
///
/// The number matters because the thing being waited for cannot be cancelled.
/// Name resolution runs `getaddrinfo` on the blocking pool and stays there until
/// the stub resolver gives up, tens of seconds on a black-holed nameserver, and
/// the client picks the name (D90). Without a bound the process exits one
/// resolver timeout after the grace period rather than one grace period after
/// the signal, and `script/masque.service` turns that into a SIGKILL at
/// `TimeoutStopSec`.
pub fn blocking_grace(grace: Duration) -> Duration {
    grace
        .saturating_add(crate::quic::CLOSE_FLUSH_TIMEOUT)
        .saturating_add(EXIT_SLACK)
}

/// Stops `runtime`, waiting at most [`blocking_grace`] for its blocking tasks.
///
/// The replacement for dropping the runtime, which tokio documents as blocking
/// indefinitely for blocking tasks that have started. What this buys is a
/// bounded exit; what it costs is that a thread still inside the resolver is
/// left running, and the process exits with it. That is sound because the thread
/// owns nothing the exit needs: its permit is server state that dies with the
/// process, and its answer is for a request that was abandoned when
/// `connect_timeout` expired.
pub fn stop_runtime(runtime: tokio::runtime::Runtime, grace: Duration) {
    runtime.shutdown_timeout(blocking_grace(grace));
}

/// Fires the shutdown signal. Cheap to clone; any clone can fire it.
#[derive(Clone)]
pub struct Trigger {
    sender: std::sync::Arc<watch::Sender<bool>>,
}

/// Observes the shutdown signal.
#[derive(Clone)]
pub struct Shutdown {
    receiver: watch::Receiver<bool>,
}

/// Creates a fresh signal, unfired.
pub fn channel() -> (Trigger, Shutdown) {
    let (sender, receiver) = watch::channel(false);
    (
        Trigger {
            sender: std::sync::Arc::new(sender),
        },
        Shutdown { receiver },
    )
}

impl Trigger {
    /// Starts the shutdown. Idempotent — a second signal changes nothing.
    pub fn fire(&self) {
        // Fails only if every receiver is gone, in which case there is nobody
        // left to shut down.
        let _ = self.sender.send(true);
    }
}

impl Shutdown {
    /// Whether shutdown has already begun.
    pub fn is_fired(&self) -> bool {
        *self.receiver.borrow()
    }

    /// Resolves when shutdown begins, immediately if it already has.
    ///
    /// Cancel-safe, so it can be a `select!` branch that loses the race any
    /// number of times: the latch is sticky, unlike a oneshot that a lost race
    /// would consume.
    pub async fn fired(&mut self) {
        loop {
            if *self.receiver.borrow_and_update() {
                return;
            }
            // Errors mean the trigger is gone, which cannot un-fire the latch but
            // also means it can never fire: wait forever rather than reporting a
            // shutdown that was never asked for.
            if self.receiver.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn firing_wakes_every_waiter() {
        let (trigger, shutdown) = channel();
        assert!(!shutdown.is_fired());

        let waiters: Vec<_> = (0..4)
            .map(|_| {
                let mut shutdown = shutdown.clone();
                tokio::spawn(async move { shutdown.fired().await })
            })
            .collect();

        trigger.fire();

        for waiter in waiters {
            tokio::time::timeout(Duration::from_secs(5), waiter)
                .await
                .expect("waiter woke up")
                .expect("waiter task");
        }
        assert!(shutdown.is_fired());
    }

    /// The latch is sticky: a waiter created after the fact must not block, which
    /// is what makes the connection accept loop safe against the race between a
    /// new connection and the signal.
    #[tokio::test]
    async fn a_late_waiter_sees_a_signal_that_already_fired() {
        let (trigger, shutdown) = channel();
        trigger.fire();
        trigger.fire(); // idempotent

        let mut late = shutdown.clone();
        tokio::time::timeout(Duration::from_secs(5), late.fired())
            .await
            .expect("a late waiter must not block");
        assert!(late.is_fired());
    }

    /// Losing a `select!` race repeatedly must not consume the signal.
    #[tokio::test]
    async fn waiting_is_cancel_safe() {
        let (trigger, mut shutdown) = channel();

        for _ in 0..3 {
            tokio::select! {
                () = shutdown.fired() => panic!("nothing has fired yet"),
                () = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
        }

        trigger.fire();
        tokio::time::timeout(Duration::from_secs(5), shutdown.fired())
            .await
            .expect("the signal survived the cancellations");
    }

    #[tokio::test]
    async fn an_unfired_signal_with_no_trigger_left_never_resolves() {
        let (trigger, mut shutdown) = channel();
        drop(trigger);

        assert!(
            tokio::time::timeout(Duration::from_millis(50), shutdown.fired())
                .await
                .is_err(),
            "a dropped trigger must not be mistaken for a shutdown"
        );
    }

    /// The blocking pool's allowance is the whole of the async side's, so an
    /// operator who raises `server.shutdown_grace` raises both halves.
    #[test]
    fn the_blocking_grace_covers_the_whole_shutdown_budget() {
        // 3600 is `MAX_SHUTDOWN_GRACE`, the largest `Config::validate` accepts.
        for seconds in [0, 5, 60, 3600] {
            let grace = Duration::from_secs(seconds);
            assert_eq!(
                blocking_grace(grace),
                grace + crate::quic::CLOSE_FLUSH_TIMEOUT + EXIT_SLACK,
                "the allowance for a grace of {seconds}s must cover the drain, the \
                 close flush and the slack"
            );
            assert!(
                blocking_grace(grace) > grace,
                "the allowance must be strictly longer than the drain it follows"
            );
        }
    }

    /// The largest configurable grace period is still an arithmetic that cannot
    /// wrap, which is what makes the bound a bound.
    #[test]
    fn the_blocking_grace_cannot_overflow() {
        assert!(blocking_grace(Duration::MAX) >= Duration::MAX - EXIT_SLACK);
    }
}
