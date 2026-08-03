// SPDX-License-Identifier: Apache-2.0
//! Core CPU control.
//!
//! Deliberately minimal for M1. Descriptor tables, interrupt handling, and the
//! APIC arrive in M2; see `docs/roadmap.md`.

/// Disables maskable interrupts on this CPU.
///
/// # Safety
///
/// The caller must ensure that running with interrupts disabled is acceptable
/// at this point, and must re-enable them or halt. Leaving interrupts disabled
/// indefinitely on a live system stalls timers and IPIs.
///
/// This does not return the previous state. A proper `IrqState` guard arrives
/// with the lock-ranking infrastructure in M4 (`docs/scheduler.md`), because
/// nesting is only meaningful once there are locks to nest inside.
pub unsafe fn disable_interrupts() {
    // SAFETY: `cli` is always encodable at CPL 0, which is the only privilege
    // level kernel code runs at. The caller owns the policy question of
    // whether disabling here is correct.
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }
}

/// Enables maskable interrupts on this CPU.
///
/// # Safety
///
/// The caller must ensure an IDT is installed and that every enabled interrupt
/// source has a handler. Enabling interrupts before M2 installs the IDT will
/// triple-fault on the first timer tick.
pub unsafe fn enable_interrupts() {
    // SAFETY: `sti` is always encodable at CPL 0. The caller owns the
    // obligation that handlers exist.
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack));
    }
}

/// Whether maskable interrupts are currently enabled on this CPU.
///
/// Reads `RFLAGS.IF`. Needed because the interrupt-enable state is *not* part
/// of a thread's saved context: a thread can yield from ordinary code, with
/// interrupts enabled, and be resumed from inside an interrupt handler, where
/// they are not. It then continues with the timer masked, which stops the
/// clock for the whole machine rather than merely delaying that thread.
#[must_use]
pub fn interrupts_enabled() -> bool {
    let flags: u64;
    // SAFETY: `pushfq` and a pop read the flags register and touch nothing
    // else. The stack is used and restored within the sequence.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {}",
            out(reg) flags,
            options(nomem, preserves_flags)
        );
    }
    flags & (1 << 9) != 0
}

/// Halts this CPU until the next interrupt.
///
/// # Safety
///
/// Safe to execute at CPL 0. Marked `unsafe` because a caller that has
/// interrupts disabled will halt forever, which is a liveness bug rather than
/// a memory-safety one — but is still something the caller must intend.
pub unsafe fn halt() {
    // SAFETY: `hlt` at CPL 0 suspends until an interrupt is delivered. It has
    // no memory effects.
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack));
    }
}

/// Stops this CPU permanently.
///
/// Disables interrupts and halts in a loop. The loop matters: `hlt` can wake
/// on a non-maskable interrupt even with interrupts disabled, and falling
/// through into whatever follows would execute garbage.
///
/// Used by the panic handler and by the end of `kernel_main`.
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: interrupts are disabled immediately before halting, and the
        // enclosing loop means an NMI-driven wakeup re-halts rather than
        // falling through. Nothing after this point needs to run.
        unsafe {
            disable_interrupts();
            halt();
        }
    }
}

/// `CR4.SMEP` — supervisor mode execution prevention.
const CR4_SMEP: u64 = 1 << 20;
/// `CR4.SMAP` — supervisor mode access prevention.
const CR4_SMAP: u64 = 1 << 21;

/// Reads `CR4`.
///
/// # Safety
///
/// Safe at CPL 0; unsafe only because the value is meaningless elsewhere.
#[must_use]
pub unsafe fn read_cr4() -> u64 {
    let value: u64;
    // SAFETY: reading a control register at CPL 0 has no side effects.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Enables SMEP and SMAP where the CPU supports them.
///
/// Returns `(smep, smap)` — which were actually turned on.
///
/// SMEP stops the kernel executing user pages; SMAP stops it *reading or
/// writing* them without deliberately lifting the restriction. Both convert a
/// large class of exploitation primitive into a fault
/// (`docs/security.md` §4).
///
/// # Safety
///
/// Must run during init. Enabling SMAP makes every existing kernel access to a
/// user page fault, so any code that legitimately touches user memory must
/// already go through `uaccess`.
pub unsafe fn enable_supervisor_protections() -> (bool, bool) {
    let features = crate::msr::features();

    let mut bits = 0;
    if features.smep {
        bits |= CR4_SMEP;
    }
    if features.smap {
        bits |= CR4_SMAP;
    }
    if bits == 0 {
        return (false, false);
    }

    // SAFETY: writing CR4 at CPL 0 with bits the CPU reports as supported.
    // Only these two are changed; paging and other enables are preserved,
    // because clearing one of those mid-flight would be immediately fatal.
    unsafe {
        let cr4 = read_cr4();
        core::arch::asm!("mov cr4, {}", in(reg) cr4 | bits, options(nostack, preserves_flags));
    }

    (features.smep, features.smap)
}

/// Lifts SMAP for the current CPU by setting the `AC` flag.
///
/// # Safety
///
/// Leaves user memory accessible from kernel mode until [`clac`] runs. The
/// window must be as short as possible and must close on every path, including
/// error paths — which is why `uaccess` does this inside assembly rather than
/// around a call.
pub unsafe fn stac() {
    // SAFETY: `stac` is only encodable when SMAP is supported; the caller
    // guarantees it has been enabled.
    unsafe { core::arch::asm!("stac", options(nomem, nostack)) };
}

/// Restores SMAP by clearing the `AC` flag.
///
/// # Safety
///
/// Only meaningful on a CPU with SMAP enabled.
pub unsafe fn clac() {
    // SAFETY: as `stac`.
    unsafe { core::arch::asm!("clac", options(nomem, nostack)) };
}
