//! Counting the file descriptors this process holds.
//!
//! Two binaries prove that nothing leaks one -- `it_os_faults`, over a burst of
//! requests that each fail on a different exhausted resource, and `it_soak`, over
//! a long run of tunnels that all succeed. Both ask the same two questions, and
//! asked them with the same two functions until this module.
//!
//! A leaf module reached with `#[path = "common/fds.rs"] mod fds;` rather than an
//! item in [`super`], the way `common/alloc.rs` already is for the three binaries
//! that count allocations. Nothing here has anything to do with a running server:
//! it is a directory listing about this process, it uses the standard library and
//! one `tokio::time::sleep`, and keeping it out of `common/mod.rs` is what lets a
//! future binary ask the question without linking rcgen, quinn and rustls to get
//! an answer (D66's QR5, reopened 2026-08-31).

#![allow(dead_code)] // Each of these binaries uses a subset of this.

use std::time::Duration;

/// The descriptors this process holds, if the platform will say.
///
/// `/dev/fd` on macOS and `/proc/self/fd` on Linux are the same directory under
/// two names: one entry per open descriptor of the calling process. Both CI
/// platforms have one, so the assertion built on this is never skipped where it
/// matters; anywhere else it returns `None` and the caller says so rather than
/// passing quietly. Reading it needs a descriptor of its own, so it is only ever
/// called with the budget intact.
pub fn open_fds() -> Option<usize> {
    let listing = if cfg!(target_os = "macos") {
        "/dev/fd"
    } else {
        "/proc/self/fd"
    };

    std::fs::read_dir(listing)
        .ok()
        .map(std::iter::Iterator::count)
}

/// [`open_fds`] once the descriptors a just-finished request or tunnel owned are
/// gone.
///
/// Work is over from the client's point of view as soon as it has read the
/// server's answer; the server task that owned anything is finished a scheduling
/// turn or two later. Sampling the moment the client is done would therefore
/// count descriptors that are on their way out, and would count a different
/// number of them each run. The lowest of eight samples is the steady state;
/// anything above it is that tail.
///
/// `interval` is how long to leave between samples, and is the caller's because
/// what has to drain differs: a refused request's descriptors are gone almost at
/// once, while a tunnel's target socket takes the longer of the two.
pub async fn settled_fds(interval: Duration) -> Option<usize> {
    let mut lowest = open_fds()?;

    for _ in 0..8 {
        tokio::time::sleep(interval).await;
        lowest = lowest.min(open_fds()?);
    }

    Some(lowest)
}
