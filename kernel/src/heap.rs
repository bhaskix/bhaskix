// SPDX-License-Identifier: Apache-2.0
//! The kernel's global allocator.
//!
//! Connects Rust's `alloc` crate to the slab allocator, which is what makes
//! `Box`, `Vec`, and `BTreeMap` usable in the nucleus.
//!
//! # Allocation failure is not a panic
//!
//! `GlobalAlloc::alloc` returns a null pointer when it cannot satisfy a
//! request, and `alloc`'s infallible constructors turn that into a panic. That
//! is unavoidable for `Box::new` and friends, but it is *not* how nucleus code
//! should allocate: `docs/coding-style.md` §4 requires fallible allocation on
//! kernel paths, because a kernel whose out-of-memory policy is "die" is not
//! an enterprise operating system.
//!
//! So the infallible forms exist for convenience in init paths where failure
//! genuinely means the machine cannot boot. Anything that runs after boot uses
//! `try_reserve`, `Vec::try_with_capacity`, or the allocator directly.

use core::alloc::{GlobalAlloc, Layout};

use bhaskix_mm::pmm::Pmm;
use bhaskix_mm::slab::Heap;

use crate::sync::{Rank, SpinLock};

/// The heap, once physical memory is up.
///
/// `None` before [`init`], so an allocation made too early fails cleanly
/// rather than dereferencing something uninitialised. Code that allocates
/// before the memory manager exists is a bug, and a null return surfaces it
/// immediately.
static HEAP: SpinLock<Option<Heap>> = SpinLock::new(Rank::Heap, None);

/// Rust's global allocator hook.
///
/// Only instantiated by the `#[global_allocator]` static below, which is
/// itself absent under `cfg(test)` -- hence the allow.
#[cfg_attr(test, allow(dead_code))]
struct KernelAllocator;

// SAFETY: `alloc` returns either null or a pointer to a block of at least
// `layout.size()` bytes, aligned to `layout.align()`, which no other live
// allocation overlaps -- the slab allocator's own tests assert exactly that.
// `dealloc` is only ever called with a pointer and layout from a previous
// `alloc`, per the trait's contract, and returns the block for reuse.
unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut guard = HEAP.lock();
        let Some(heap) = guard.as_mut() else {
            return core::ptr::null_mut();
        };
        // SAFETY: the returned memory is uninitialised, which is exactly what
        // `GlobalAlloc::alloc` promises its caller.
        match unsafe { heap.allocate(layout.size(), layout.align()) } {
            Ok(address) => address as *mut u8,
            Err(_) => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut guard = HEAP.lock();
        let Some(heap) = guard.as_mut() else {
            return;
        };
        // SAFETY: the trait guarantees `ptr` came from `alloc` with this exact
        // layout and has not been freed.
        let _ = unsafe { heap.free(ptr as u64, layout.size(), layout.align()) };
    }
}

// Registered only in a real kernel build. `#[global_allocator]` applies to the
// whole binary, so under `cargo test` this would replace the *host* test
// harness's allocator with one backed by physical memory that does not exist --
// and the harness would fail to allocate before running a single test.
//
// `cfg(test)` alone is not enough, because it is only set for *this* crate's
// own tests. A host binary that merely depends on the kernel -- the `fuzz/`
// target, which drives `elf::parse` against a byte buffer -- compiles it in
// non-test mode and inherits this allocator, then aborts on its first
// allocation with `memory allocation of 16 bytes failed`. That is the exact
// failure the paragraph above describes, arriving through a door it did not
// cover. The `host` feature is that door, and nothing in a kernel build enables
// it.
#[cfg(all(not(test), not(feature = "host")))]
#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

/// Brings the heap up over `pmm`.
///
/// After this returns, `alloc` types work.
pub fn init(pmm: Pmm, hhdm_base: u64) {
    *HEAP.lock() = Some(Heap::new(pmm, hhdm_base));
}

/// Runs `f` with the heap, if it exists.
pub fn with<R>(f: impl FnOnce(&mut Heap) -> R) -> Option<R> {
    HEAP.lock().as_mut().map(f)
}

/// Runs `f` with the heap, but only if the lock is free.
///
/// For the page-fault path. Demand paging has to allocate a frame, and the
/// allocator is behind this lock — but a fault can interrupt code that already
/// holds it. Spinning there would hang the machine with no output, so the
/// handler uses this and reports an unserviceable fault instead.
///
/// Returns `None` if the heap does not exist *or* the lock is held. Those are
/// different problems, and the caller cannot tell them apart; both mean "not
/// now", which is all the fault path needs.
pub fn try_with<R>(f: impl FnOnce(&mut Heap) -> R) -> Option<R> {
    HEAP.try_lock()?.as_mut().map(f)
}

/// Frames the physical allocator still has free.
#[must_use]
pub fn free_frames() -> u64 {
    with(|heap| heap.pmm().free_frames()).unwrap_or(0)
}

/// Frames that are not in use: free in the allocator, or held in a per-CPU
/// reserve.
///
/// The distinction matters to every leak check. A frame sitting in a reserve
/// has left the allocator's free count without being lost, so a test that
/// compared only `free_frames` across an operation that happened to trigger a
/// refill would report the difference as a leak — and be believed, because
/// that test is the project's most trusted gate.
#[must_use]
pub fn available_frames() -> u64 {
    // Both halves under one hold of the lock, so a refill moving frames from
    // the allocator into a reserve cannot land between them. `refill` does its
    // whole move under this same lock for exactly that reason; reading the two
    // numbers separately made the frame-leak gate report a sixteen-frame gain
    // that had not happened.
    with(|heap| heap.pmm().free_frames() + crate::frames::held()).unwrap_or(0)
}
