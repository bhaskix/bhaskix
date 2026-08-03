// SPDX-License-Identifier: Apache-2.0
//! TLB shootdown.
//!
//! Removing a mapping invalidates it in *this* CPU's translation cache and
//! nowhere else. Every other processor may keep using the old translation for
//! as long as it stays cached — reading memory that has been freed, or writing
//! through a mapping the kernel believes is gone.
//!
//! That is a correctness bug rather than a missing optimisation, and it became
//! a live one the moment a second CPU came online. The fix is to interrupt
//! every other CPU and have it invalidate the address too, then wait until all
//! of them have confirmed. `docs/memory.md` §3 describes the naive version —
//! an IPI per unmap, waiting for all — and says to start there and measure
//! before optimising. This is that version.
//!
//! # Why the sender waits
//!
//! It would be faster not to. It would also be wrong: the caller's next act is
//! usually to free the frame, and a CPU still holding a cached translation
//! would then be writing into memory that has been handed to someone else.
//! The wait is what makes "unmapped" mean unmapped everywhere.
//!
//! # Known limitation
//!
//! One address per shootdown, one shootdown at a time. Unmapping a range costs
//! an IPI round trip per page, which is the wrong shape for tearing down an
//! address space — batching a range into one IPI is the obvious next step, and
//! deliberately not taken before there is a workload to measure it against.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use bhaskix_arch::{apic, paging, percpu};

use crate::sync::SpinLock;

/// Vector the shootdown IPI is delivered on.
///
/// Above the timer, below the spurious and error vectors, and outside the
/// range the legacy PIC was remapped to.
pub const SHOOTDOWN_VECTOR: u8 = 0x40;

/// Address every CPU should invalidate.
static ADDRESS: AtomicU64 = AtomicU64::new(0);

/// CPUs that have not yet acknowledged.
static PENDING: AtomicU32 = AtomicU32::new(0);

/// Serialises shootdowns, since there is one shared address slot.
static SENDER: SpinLock<()> = SpinLock::new(());

/// Shootdowns that completed with every CPU acknowledging.
static COMPLETED: AtomicU64 = AtomicU64::new(0);

/// Shootdowns that gave up waiting.
static TIMED_OUT: AtomicU64 = AtomicU64::new(0);

/// Invalidates `address` on this CPU and every other online CPU.
///
/// Returns whether every CPU acknowledged. A `false` return means some
/// processor may still hold a stale translation, and the caller must not
/// assume the page is safe to reuse.
pub fn shootdown(address: u64) -> bool {
    // SAFETY: `invlpg` is safe at CPL 0 and cannot fault, even for an address
    // that is not mapped.
    unsafe { paging::invalidate(address) };

    let others = percpu::online_count().saturating_sub(1);
    if others == 0 {
        COMPLETED.fetch_add(1, Ordering::Relaxed);
        return true;
    }

    // Held across the IPI because there is a single shared address slot. The
    // receiving side deliberately does *not* take this lock -- if it did, a
    // CPU interrupted while holding it would deadlock against itself.
    let _guard = SENDER.lock();

    ADDRESS.store(address, Ordering::Release);
    PENDING.store(others, Ordering::Release);

    // SAFETY: the APIC is initialised, and every CPU has an IDT gate for this
    // vector -- the IDT is built before any secondary is released.
    unsafe { apic::send_ipi_all_but_self(SHOOTDOWN_VECTOR) };

    // Bounded. A CPU that is wedged, or spinning with interrupts disabled,
    // must not hang the machine here: reporting a shootdown that did not
    // complete is far more useful than a kernel that stops with no output.
    //
    // The bound is deliberately not enormous. A real IPI round trip is
    // microseconds, so anything beyond a fraction of a second means the CPU is
    // not coming — and a bound so large that the failure takes minutes to
    // surface is a bound that makes the failure untestable.
    let mut spins = 0u64;
    while PENDING.load(Ordering::Acquire) > 0 && spins < 20_000_000 {
        spins += 1;
        core::hint::spin_loop();
    }

    if PENDING.load(Ordering::Acquire) == 0 {
        COMPLETED.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        TIMED_OUT.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// Handles a shootdown IPI on a receiving CPU.
///
/// Called from the interrupt dispatcher. Takes no locks, on purpose: this runs
/// on a CPU that may have been interrupted anywhere, including inside a
/// critical section.
pub fn handle_ipi() {
    let address = ADDRESS.load(Ordering::Acquire);
    // SAFETY: `invlpg` is safe at CPL 0 and cannot fault.
    unsafe { paging::invalidate(address) };
    PENDING.fetch_sub(1, Ordering::AcqRel);
}

/// `(completed, timed out)` shootdowns so far.
#[must_use]
pub fn statistics() -> (u64, u64) {
    (
        COMPLETED.load(Ordering::Relaxed),
        TIMED_OUT.load(Ordering::Relaxed),
    )
}
