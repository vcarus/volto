//! The pass-through half of the three measuring allocators.
//!
//! `it_bounds`, `it_relay_memory` and `it_bench` each install a
//! [`GlobalAlloc`] that forwards to the system allocator and counts something
//! on the way past. What they count is genuinely different — signed live bytes,
//! allocations at or above the relay's read window, every allocation and its
//! size — and stays in each of those files, next to the measurement it serves.
//! What was written out three times is the forwarding itself: four `unsafe`
//! methods that call [`System`] and report what happened.
//!
//! Reached with `#[path = "common/alloc.rs"] mod alloc;` rather than declared
//! inside `common`, so the binaries that do not measure allocations do not
//! compile it (the same leaf-module route D66's QR5 did not consider).
//!
//! One deliberate difference from the copies this replaces: an allocation is
//! reported only once the system allocator has returned a non-null pointer, the
//! way `it_bounds` already did it and the other two did not. A null return is
//! the allocator failing, and nothing was handed out to count.

#![allow(dead_code)] // Each measuring binary uses a subset of this.

use std::alloc::{GlobalAlloc, Layout, System};
use std::marker::PhantomData;

/// What a [`PassThrough`] tells its owner about each event it forwards.
///
/// Associated functions rather than methods: the allocator is a zero-sized
/// static installed as `#[global_allocator]`, and every counter it feeds is a
/// static too.
pub trait Record {
    /// A block of `size` bytes was handed out.
    fn allocated(size: usize);

    /// A block was moved or resized from `old` bytes to `new`.
    fn reallocated(old: usize, new: usize);

    /// A block of `size` bytes was given back.
    ///
    /// Defaulted to doing nothing, which is what the two counters that only
    /// look at allocations want.
    fn freed(size: usize) {
        let _ = size;
    }
}

/// A `GlobalAlloc` that forwards to [`System`] and reports to `R`.
pub struct PassThrough<R>(PhantomData<fn() -> R>);

impl<R> PassThrough<R> {
    /// The one value of this type, for the `#[global_allocator]` static.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<R> Default for PassThrough<R> {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: every method forwards to `System`, which is a correct `GlobalAlloc`,
// and returns exactly what it returned. The bookkeeping between the calls
// allocates nothing itself -- the implementations of `Record` in the test
// binaries only touch atomics -- so it cannot re-enter the allocator.
unsafe impl<R: Record> GlobalAlloc for PassThrough<R> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            R::allocated(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            R::allocated(layout.size());
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = System.realloc(ptr, layout, new_size);
        if !moved.is_null() {
            R::reallocated(layout.size(), new_size);
        }
        moved
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        R::freed(layout.size());
    }
}
