//! The recovery window after a loss.

use std::time::Instant;

use super::{Bbr, MIN_WINDOW_PACKETS};

/// A recovery after a loss; see the [module documentation](super).
#[derive(Debug, Clone, Copy)]
pub(super) struct Recovery {
    /// The most in-flight data the recovery allows.
    pub(super) window: u64,
    /// The end of the ACK batch that began the recovery. Once a packet sent
    /// after it has been acknowledged, the window grows by the bytes
    /// acknowledged.
    began: Instant,
    /// The end of the last ACK batch that had a loss.
    last_loss: Instant,
}

impl Bbr {
    /// Applies the losses and acknowledgements of the ACK batch that has just
    /// ended to the recovery window. Returns whether the recovery changed.
    pub(super) fn update_recovery(&mut self, now: Instant, in_flight: u64) -> bool {
        let lost = std::mem::take(&mut self.lost);
        let acked = std::mem::take(&mut self.acked);
        let held = in_flight
            .saturating_add(acked)
            .max(MIN_WINDOW_PACKETS * self.mtu);
        let acked_after = |at: Instant| self.rate.acked_sent_after(at);
        match self.recovery {
            None if lost == 0 => return false,
            None => {
                self.recovery = Some(Recovery {
                    window: held,
                    began: now,
                    last_loss: now,
                });
            }
            Some(r) if lost == 0 && acked_after(r.last_loss) => self.recovery = None,
            Some(r) => {
                let grown = if acked_after(r.began) { acked } else { 0 };
                self.recovery = Some(Recovery {
                    window: r
                        .window
                        .saturating_sub(lost)
                        .saturating_add(grown)
                        .max(held),
                    last_loss: if lost > 0 { now } else { r.last_loss },
                    ..r
                });
            }
        }
        true
    }
}
