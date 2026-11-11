//! The global allocator the `volto` binary installs.
//!
//! On the musl targets it is mimalloc. Everywhere else it is the platform
//! allocator, [`std::alloc::System`].
//!
//! The release binaries are static musl builds (`.github/workflows/release.yml`).
//! On the same Linux host, `tests/it_bench.rs` measured a higher CPU cost for
//! the musl build than for the glibc build in every test, with the same
//! allocation counts on both targets. The numbers are in the comment above the
//! `mimalloc` dependency in `Cargo.toml`. The difference is libc, and musl's
//! `malloc` is the part of it this module replaces. A glibc build keeps glibc's
//! allocator, and so does every other platform.
//!
//! The binary installs it with `#[global_allocator]` in `src/main.rs`. The
//! library installs nothing, because the allocator is a choice for the final
//! executable. `tests/it_bench.rs` wraps the same type in its counting
//! allocator, so the benchmark measures the allocator a release ships with.
//!
//! [`Global`] is a type alias, not a wrapper type. Both possible types already
//! implement [`std::alloc::GlobalAlloc`], so nothing here needs `unsafe`, and
//! the crate keeps `#![forbid(unsafe_code)]`.

/// The allocator type: `mimalloc::MiMalloc` on musl, [`std::alloc::System`]
/// otherwise.
#[cfg(target_env = "musl")]
pub type Global = mimalloc::MiMalloc;

/// The allocator type: `mimalloc::MiMalloc` on musl, [`std::alloc::System`]
/// otherwise.
#[cfg(not(target_env = "musl"))]
pub type Global = std::alloc::System;

/// The one value of [`Global`], for a `static` marked `#[global_allocator]`.
#[cfg(target_env = "musl")]
pub const GLOBAL: Global = mimalloc::MiMalloc;

/// The one value of [`Global`], for a `static` marked `#[global_allocator]`.
#[cfg(not(target_env = "musl"))]
pub const GLOBAL: Global = std::alloc::System;
