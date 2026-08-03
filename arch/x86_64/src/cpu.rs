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
