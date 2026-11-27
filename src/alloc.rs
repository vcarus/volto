//! The global allocator the `volto` binary installs.
//!
//! On the musl targets it is mimalloc. Everywhere else it is the platform
//! allocator, [`std::alloc::System`].
//!
//! The release binaries are static musl builds, and `Cargo.toml` says above the
//! `mimalloc` dependency why their allocator is replaced.
//!
//! The binary installs it with `#[global_allocator]` in `src/main.rs`. The
//! library installs nothing, because the allocator is a choice for the final
//! executable. `tests/it_bench.rs` wraps the same type in its counting
//! allocator, so the benchmark measures the allocator a release ships with.
//!
//! [`Global`] is a type alias, not a wrapper type. Both possible types already
//! implement [`std::alloc::GlobalAlloc`], so nothing here needs `unsafe`, and
//! this module stays under the crate's `#![deny(unsafe_code)]`.

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
