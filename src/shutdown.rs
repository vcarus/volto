//! The shutdown signal, from the process down to each connection.
//!
//! The sequence the server implements (RFC 9114 §5.2):
//!
//! 1. stop accepting new QUIC connections;
//! 2. send a GOAWAY on every live HTTP/3 connection, which tells the client to
//!    take its new requests elsewhere while the ones in flight finish;
//! 3. wait for the tunnels to end on their own, up to `server.shutdown_grace`;
//! 4. close the endpoint regardless, so a stuck tunnel cannot hold the process
//!    open forever;
//! 5. stop the runtime, waiting no longer than [`EXIT_SLACK`] for the
//!    blocking tasks that are still running.
//!
//! This module is mostly the signal: a one-way latch that many tasks can wait on
//! and that never un-fires, so a task arriving late still observes it. Steps 1, 3
//! and 4 live in [`crate::quic`]; step 2 lives in [`crate::conn`]; step 5 is
//! [`stop_runtime`] here, called by the binary once the runtime's own work is
//! done.

use std::time::Duration;

use tokio::sync::watch;

/// How long [`stop_runtime`] waits for the blocking tasks once the server has
/// stopped.
///
/// A fixed second rather than a fraction of the grace period, because what it
/// covers is fixed work: the scheduling between the accept loop returning and
/// the pool being told to stop, and a blocking task that was about to finish
/// anyway.
pub const EXIT_SLACK: Duration = Duration::from_secs(1);

// The margin has to be one: at zero the pool would be told to stop at the
// instant the drain ended, with nothing left for the scheduling between the
// two (D90).
const _: () = assert!(!EXIT_SLACK.is_zero());

/// How long the endpoint waits for its `CONNECTION_CLOSE` frames to be flushed
/// at step 4. With the grace period before it and [`EXIT_SLACK`] after it, this
/// makes the exit bound: `shutdown_grace + CLOSE_FLUSH_TIMEOUT + EXIT_SLACK`.
pub const CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

// Added to a grace period an operator may set to zero, and the drain that
// precedes it may equally have nothing to wait for. At zero a shutdown would
// leave the endpoint no time at all to put the CONNECTION_CLOSE it just wrote
// on the wire.
const _: () = assert!(!CLOSE_FLUSH_TIMEOUT.is_zero());

/// Stops `runtime`, waiting at most [`EXIT_SLACK`] for its blocking tasks.
///
/// The replacement for dropping the runtime, which tokio documents as blocking
/// indefinitely for blocking tasks that have started. Name resolution runs
/// `getaddrinfo` on the blocking pool and stays there until the stub resolver
/// gives up, tens of seconds on a black-holed nameserver, and the client picks
/// the name (D90).
///
/// The wait is the slack alone because nothing can read a blocking task's
/// result once `Server::run` has returned. The endpoint is closed by the drain,
/// or was lost, and the connection tasks that awaited a lookup were aborted
/// when `run` dropped their `JoinSet`. The pool's other user, the `SIGHUP`
/// reload, reads files into a configuration nothing serves from any more. A
/// thread still inside the resolver is left running and the
/// process exits with it: its permit is server state that dies with the
/// process, and its answer is for a request that no longer exists.
pub fn stop_runtime(runtime: tokio::runtime::Runtime) {
    runtime.shutdown_timeout(EXIT_SLACK);
}

/// Fires the shutdown signal. Cheap to clone; any clone can fire it.
///
/// A `watch::Sender` is itself a handle that clones, and the receivers' wait
/// fails only when every clone is gone, so no `Arc` is needed around it.
#[derive(Clone)]
pub struct Trigger {
    sender: watch::Sender<bool>,
}

/// Observes the shutdown signal.
#[derive(Clone)]
pub struct Shutdown {
    receiver: watch::Receiver<bool>,
}

/// Creates a fresh signal, unfired.
pub fn channel() -> (Trigger, Shutdown) {
    let (sender, receiver) = watch::channel(false);
    (Trigger { sender }, Shutdown { receiver })
}

impl Trigger {
    /// Starts the shutdown. Idempotent: a second signal changes nothing.
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
        // `wait_for` checks the current value first, seen or not, and fails only
        // when every trigger is gone and the last value was `false`: the signal
        // can then never fire, so this waits forever rather than reporting a
        // shutdown that was never asked for.
        if self.receiver.wait_for(|&fired| fired).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
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

    /// The whole-number value `script/masque.service` sets for `directive`.
    pub(crate) fn shipped_unit_value(directive: &str) -> u64 {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/script/masque.service"
        ))
        .expect("script/masque.service must exist");
        let prefix = format!("{directive}=");
        let value = text
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("script/masque.service sets no {directive}"));
        value.trim().parse().unwrap_or_else(|_| {
            panic!("script/masque.service sets {directive}={value}, which is not a whole number")
        })
    }

    /// The shipped unit lets the longest exit finish before systemd sends
    /// SIGKILL.
    ///
    /// At the default grace, the exit is the drain (`shutdown_grace`), the close
    /// flush (`CLOSE_FLUSH_TIMEOUT`) and then [`EXIT_SLACK`] for a lookup still
    /// running on the blocking pool. `TimeoutStopSec` has to be above that sum,
    /// not above the grace alone.
    #[test]
    fn the_shipped_unit_waits_out_the_longest_exit() {
        let grace = Duration::from_secs(crate::config::DEFAULT_SHUTDOWN_GRACE);
        let exit = grace + CLOSE_FLUSH_TIMEOUT + EXIT_SLACK;
        let timeout = shipped_unit_value("TimeoutStopSec");
        assert!(
            Duration::from_secs(timeout) > exit,
            "script/masque.service sets TimeoutStopSec={timeout}, which is not above \
             the {}s the exit may take at the default shutdown_grace of {}s \
             (shutdown_grace + CLOSE_FLUSH_TIMEOUT + EXIT_SLACK)",
            exit.as_secs(),
            grace.as_secs()
        );
    }
}
