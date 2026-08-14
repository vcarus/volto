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
//!    open forever.
//!
//! This module is only the signal: a one-way latch that many tasks can wait on
//! and that never un-fires, so a task arriving late still observes it. Steps 1, 3
//! and 4 live in [`crate::quic`]; step 2 lives in [`crate::conn`].

use tokio::sync::watch;

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
}
