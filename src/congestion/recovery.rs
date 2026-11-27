//! The recovery window after a loss.
//!
//! A loss holds in-flight data for one round trip, by BBR's packet
//! conservation. The form here is ours, and it has the effect of the recovery
//! window of quinn's BBR. quinn reports a loss after the ACK batch that found
//! it, so the rule acts at the next batch. That batch sets a recovery window
//! of in-flight data plus the bytes it acknowledged, and never less than
//! [`MIN_WINDOW_PACKETS`] packets. Each later batch takes the bytes lost since
//! the previous one off the recovery window. Once a packet sent after the
//! recovery began has been acknowledged, each batch also adds the bytes it
//! acknowledged. In-flight data plus the bytes the batch acknowledged stays
//! the recovery window's lower bound. The recovery ends at the first batch
//! without a loss that acknowledges a packet sent after the last batch with
//! one. The recovery window limits the window only after the startup has
//! ended, as quinn's BBR applies its own only outside its Startup. An ECN mark
//! loses no bytes and starts no recovery.

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
