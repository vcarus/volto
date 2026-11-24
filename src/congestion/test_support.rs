//! The test helpers that more than one test module of the controller uses.

use std::time::Duration;

/// The sample interval in these tests: one smoothed RTT.
pub(super) const SRTT: Duration = Duration::from_millis(100);

pub(super) fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}
