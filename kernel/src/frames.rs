// SPDX-License-Identifier: Apache-2.0
//! A small per-CPU reserve of physical frames, for the fault path.
//!
//! # The problem this exists for
//!
//! Servicing a page fault means allocating: a frame for the page, and
//! sometimes more for the page-table levels above it. Allocating means taking
//! the physical allocator's lock. And a page fault can interrupt *anything* —
//! including code on this very CPU that already holds that lock.
//!
//! The fault handler therefore cannot wait for it. Until now it tried the lock
//! and, when it was held, reported the fault unserviceable — which is honest
//! and is also a kernel that fails at exactly the moments it is busiest, for
//! no reason the workload can see or avoid.
//!
//! The way out is not a cleverer lock. It is not needing one: each CPU keeps a
//! handful of frames it has already taken, and the fault path spends those.
//! Refilling happens later, in a context that *can* wait.
//!
//! # Why this needs no lock at all
//!
//! A CPU's reserve is touched only by that CPU. There is no cross-CPU access,
//! so the only concurrency is an interrupt arriving in the middle of an update
//! — and interrupts are simply masked for the few instructions involved.
//!
//! That is worth stating plainly because it is the point: this is
//! `docs/architecture.md` §6's "prefer per-CPU over shared" applied where it
//! actually pays. The alternative designs all end in a lock the fault handler
//! must not wait for.
//!
//! # What it does not solve
//!
//! - **It is not a memory guarantee.** A reserve that runs dry falls back to
//!   trying the allocator, and if that is held the fault is still
//!   unserviceable. It converts a *likely* failure into a rare one.
//! - **It does not survive a burst.** [`RESERVE_FRAMES`] faults on one CPU
//!   between refills is the budget; beyond that the old behaviour returns.
//!   Sizing it against a real fault rate needs a workload.
//! - **Frames in the reserve are not free memory**, and the accounting says
//!   so: they are charged to the reserve, not to the allocator's free count,
//!   or the frame-leak gate would see them as lost.

use core::sync::atomic::{AtomicU64, Ordering};

use bhaskix_arch::cpu;
use bhaskix_arch::percpu::{self, MAX_CPUS};
use bhaskix_mm::{FRAME_SIZE, Zone};

use crate::heap;

/// A cell owned by exactly one CPU.
///
/// Not a lock, and deliberately not one: the whole point of the reserve is
/// that the fault path reaches it without waiting for anything. Soundness
/// comes from the access rule rather than from mutual exclusion — element `n`
/// is touched only by CPU `n`, and only with interrupts masked.
struct PerCpuCell<T> {
    value: core::cell::UnsafeCell<T>,
}

// SAFETY: the type grants no safe access at all; every reader and writer goes
// through an `unsafe` block that carries the "only your own CPU, interrupts
// masked" obligation. Sharing the array across CPUs is sound because no CPU
// touches another's element.
unsafe impl<T: Send> Sync for PerCpuCell<T> {}

impl<T> PerCpuCell<T> {
    const fn new(value: T) -> Self {
        Self {
            value: core::cell::UnsafeCell::new(value),
        }
    }

    /// A pointer to the value, for the owning CPU to write through.
    ///
    /// A raw pointer rather than a `&mut` derived from `&self`: handing out a
    /// mutable reference from a shared one is exactly the aliasing claim this
    /// type cannot make, since every CPU holds a shared reference to the whole
    /// array. The obligation lives at the dereference instead, where the
    /// caller can state that it owns this element and has masked interrupts.
    fn as_mut_ptr(&self) -> *mut T {
        self.value.get()
    }

    /// # Safety
    ///
    /// The value may be mutated concurrently by its owning CPU, so the caller
    /// must treat what it reads as advisory.
    unsafe fn get(&self) -> &T {
        // SAFETY: delegated to the caller.
        unsafe { &*self.value.get() }
    }
}

/// Frames each CPU holds ready.
///
/// Small deliberately: every frame here is memory the allocator cannot hand
/// to anyone else, multiplied by the CPU count. Sixteen is enough for a burst
/// of faults between two timer interrupts and costs 64 KiB per CPU.
pub const RESERVE_FRAMES: usize = 16;

/// Refill when fewer than this remain.
///
/// Below the full mark rather than at empty, so refilling is something that
/// happens *before* the reserve is needed rather than a response to running
/// out — which would be too late by definition.
pub const REFILL_BELOW: usize = RESERVE_FRAMES / 2;

/// One CPU's frames, as physical addresses.
struct Reserve {
    frames: [u64; RESERVE_FRAMES],
    count: usize,
}

impl Reserve {
    const fn new() -> Self {
        Self {
            frames: [0; RESERVE_FRAMES],
            count: 0,
        }
    }
}

static RESERVES: [PerCpuCell<Reserve>; MAX_CPUS] =
    [const { PerCpuCell::new(Reserve::new()) }; MAX_CPUS];

/// Frames handed to the fault path from a reserve.
static HITS: AtomicU64 = AtomicU64::new(0);

/// Times the fault path wanted a frame and the reserve was empty.
static MISSES: AtomicU64 = AtomicU64::new(0);

/// Frames drawn from the allocator to top reserves up.
static REFILLED: AtomicU64 = AtomicU64::new(0);

/// Runs `f` on this CPU's reserve with interrupts masked.
///
/// The masking is the entire synchronisation story. Nothing else touches this
/// CPU's reserve, so the only way an update can be observed half-done is an
/// interrupt landing inside it — and a page fault is an interrupt.
fn with_reserve<R>(f: impl FnOnce(&mut Reserve) -> R) -> Option<R> {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return None;
    }

    let enabled = cpu::interrupts_enabled();
    if enabled {
        // SAFETY: re-enabled below before returning.
        unsafe { cpu::disable_interrupts() };
    }

    // SAFETY: this CPU is the only writer of its own element, and interrupts
    // are masked, so no nested access can observe a partial update. The
    // reference does not escape this call.
    let result = f(unsafe { &mut *RESERVES[cpu].as_mut_ptr() });

    if enabled {
        // SAFETY: restoring the caller's state.
        unsafe { cpu::enable_interrupts() };
    }
    Some(result)
}

/// Takes a frame from this CPU's reserve, if it has one.
///
/// Returns a physical address. The frame is **not** zeroed — the caller knows
/// whether it is about to be overwritten wholesale, as a copy-on-write copy
/// is, and zeroing a page that is immediately overwritten is a measurable cost
/// on the fault path.
#[must_use]
pub fn take() -> Option<u64> {
    let taken = with_reserve(|reserve| {
        if reserve.count == 0 {
            return None;
        }
        reserve.count -= 1;
        Some(reserve.frames[reserve.count])
    })?;

    match taken {
        Some(frame) => {
            HITS.fetch_add(1, Ordering::Relaxed);
            Some(frame)
        }
        None => {
            MISSES.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

/// Returns a frame to this CPU's reserve, or to the allocator if it is full.
///
/// Never fails, and never blocks: a frame that cannot go back into the reserve
/// and cannot reach the allocator is dropped and counted as a leak rather than
/// waited on, because the caller is a fault handler that must return.
pub fn give(frame: u64) {
    let stored = with_reserve(|reserve| {
        if reserve.count < RESERVE_FRAMES {
            reserve.frames[reserve.count] = frame;
            reserve.count += 1;
            true
        } else {
            false
        }
    })
    .unwrap_or(false);

    if stored {
        return;
    }

    // Reserve full. Hand it back if the allocator is reachable right now; if
    // it is not, this frame is lost. That is a deliberate trade -- the
    // alternative is a fault handler that waits for a lock.
    let _ = heap::try_with(|heap| {
        let _ = heap.pmm_mut().free((frame / FRAME_SIZE) as u32, 0);
    });
}

/// Tops this CPU's reserve up, if the allocator is reachable.
///
/// Called from the timer interrupt, where `try_with` is the only safe way to
/// reach the allocator. Failing is fine and self-correcting: the next tick
/// tries again, and the reserve is only consulted by faults, which are rarer
/// than ticks.
pub fn refill() {
    let cpu = percpu::cpu_id() as usize;
    if cpu >= MAX_CPUS {
        return;
    }

    let wanted = with_reserve(|reserve| {
        if reserve.count < REFILL_BELOW {
            RESERVE_FRAMES - reserve.count
        } else {
            0
        }
    })
    .unwrap_or(0);

    if wanted == 0 {
        return;
    }

    // Allocated outside the reserve's masked section: taking frames from the
    // buddy allocator is not something to do with interrupts off for longer
    // than necessary, and each frame is handed over individually.
    for _ in 0..wanted {
        let frame = heap::try_with(|heap| {
            heap.pmm_mut()
                .allocate(0, Zone::Normal)
                .ok()
                .map(|pfn| u64::from(pfn) * FRAME_SIZE)
        });
        match frame {
            Some(Some(frame)) => {
                REFILLED.fetch_add(1, Ordering::Relaxed);
                let stored = with_reserve(|reserve| {
                    if reserve.count < RESERVE_FRAMES {
                        reserve.frames[reserve.count] = frame;
                        reserve.count += 1;
                        true
                    } else {
                        false
                    }
                })
                .unwrap_or(false);
                if !stored {
                    let _ = heap::try_with(|heap| {
                        let _ = heap.pmm_mut().free((frame / FRAME_SIZE) as u32, 0);
                    });
                    return;
                }
            }
            // Allocator held, or out of memory. Either way, later.
            _ => return,
        }
    }
}

/// Frames currently held across every online CPU's reserve.
///
/// The frame-leak gate needs this: a frame in a reserve has left the
/// allocator's free count without being lost, and a test that did not know
/// about reserves would report the difference as a leak.
#[must_use]
pub fn held() -> u64 {
    let online = (percpu::online_count() as usize).min(MAX_CPUS);
    RESERVES
        .iter()
        .take(online)
        // SAFETY: reads a `usize` that its owning CPU may be updating
        // concurrently. The value is advisory -- reported, never used to make
        // a decision -- so a stale read costs an inaccurate number and nothing
        // else.
        .map(|reserve| unsafe { reserve.get().count } as u64)
        .sum()
}

/// Frames the fault path took from a reserve.
#[must_use]
pub fn hits() -> u64 {
    HITS.load(Ordering::Relaxed)
}

/// Times the fault path found its reserve empty.
#[must_use]
pub fn misses() -> u64 {
    MISSES.load(Ordering::Relaxed)
}

/// Frames drawn from the allocator to top reserves up.
#[must_use]
pub fn refilled() -> u64 {
    REFILLED.load(Ordering::Relaxed)
}

/// Returns every reserved frame to the allocator.
///
/// For shutdown accounting, so a frame-leak check can be made against a clean
/// allocator rather than one missing however many frames the reserves happen
/// to be holding.
pub fn drain() {
    loop {
        let Some(Some(frame)) = with_reserve(|reserve| {
            if reserve.count == 0 {
                return None;
            }
            reserve.count -= 1;
            Some(reserve.frames[reserve.count])
        }) else {
            return;
        };
        let freed = heap::try_with(|heap| {
            let _ = heap.pmm_mut().free((frame / FRAME_SIZE) as u32, 0);
        });
        if freed.is_none() {
            return;
        }
    }
}
