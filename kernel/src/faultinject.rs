// SPDX-License-Identifier: Apache-2.0
//! Deliberate fault injection, for testing the exception path.
//!
//! M2's exit criterion is that every exception produces a clear diagnostic
//! instead of a triple fault. That cannot be asserted by inspection — the only
//! way to know the handler works is to fault on purpose and read what comes
//! out. This module is how `tests/qemu/fault-test.sh` does that.
//!
//! Selected by the kernel command line, so one build covers every case:
//!
//! ```text
//! bhaskix.fault=de   divide error         -- no error code
//! bhaskix.fault=ud   invalid opcode       -- no error code
//! bhaskix.fault=bp   breakpoint           -- no error code
//! bhaskix.fault=gp   general protection   -- error code, selector-shaped
//! bhaskix.fault=pf   page fault           -- error code, plus CR2
//! bhaskix.fault=df   double fault         -- via kernel stack overflow
//! bhaskix.fault=user a page fault **in ring 3** -- survivable by design
//! ```
//!
//! # The last one is different, and deliberately so
//!
//! The first six are faults in the kernel's own execution, and every one of
//! them ends the machine. `user` is a fault in a *program*, which
//! [RFC 0017](../../docs/rfc/0017-process-management.md) step 1 makes
//! survivable: it ends one domain and the boot carries on. So its expectation
//! in the harness is not "the report appeared" — a report appeared before that
//! change too, and then the CPU halted — but that **output continues
//! afterwards**.
//!
//! It lives behind the command line, with the other six, rather than in the
//! boot self-tests. A deliberate exception on every boot would mean every
//! harness that treats `EXCEPTION` as a failure marker — `shell-test.sh` does
//! — has to learn to ignore one, and a failure marker with an exception list
//! is a failure marker that will eventually ignore the wrong thing.
//!
//! # Why this ships in the kernel rather than living in a test harness
//!
//! There is no way to inject a fault from outside: it has to be code running
//! in kernel context. Keeping it in the tree, behind an explicit command-line
//! option that does nothing unless asked, is the honest arrangement — and it
//! stays useful for anyone bringing Bhaskix up on new hardware, where "does
//! the exception path work at all" is the first question.

use crate::println;

/// A fault the kernel can be asked to trigger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Divide by zero (#DE, vector 0).
    DivideError,
    /// Invalid opcode (#UD, vector 6).
    InvalidOpcode,
    /// Breakpoint (#BP, vector 3).
    Breakpoint,
    /// General protection fault (#GP, vector 13).
    GeneralProtection,
    /// Page fault (#PF, vector 14).
    PageFault,
    /// Double fault (#DF, vector 8), reached through an unmapped stack.
    DoubleFault,
    /// A page fault in ring 3 (#PF, vector 14), which ends a domain and not
    /// the machine.
    UserMode,
    /// A #GP taken while this CPU holds its own runqueue lock.
    ///
    /// The shape that wedged the fault report on 2026-08-29: the report read
    /// the running thread through a blocking runqueue lock, so a fault raised
    /// with that lock already held spun for ever on a lock the same CPU was
    /// holding, and the log stopped one line after the banner. This makes that
    /// deterministic, so the report's own guarantee -- that it prints what it
    /// knows before it halts -- has something that can falsify it.
    GeneralProtectionHoldingRunqueue,
}

impl Fault {
    /// Parses the value of `bhaskix.fault=`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "de" => Self::DivideError,
            "ud" => Self::InvalidOpcode,
            "bp" => Self::Breakpoint,
            "gp" => Self::GeneralProtection,
            "pf" => Self::PageFault,
            "df" => Self::DoubleFault,
            "user" => Self::UserMode,
            "gp-held" => Self::GeneralProtectionHoldingRunqueue,
            _ => return None,
        })
    }
}

/// Extracts `bhaskix.fault=<name>` from a kernel command line.
///
/// Deliberately tolerant: an unrecognised or malformed option yields `None`
/// and the kernel boots normally. A boot option that can brick the boot is a
/// bad boot option.
#[must_use]
pub fn from_cmdline(cmdline: &str) -> Option<Fault> {
    cmdline
        .split_ascii_whitespace()
        .find_map(|word| word.strip_prefix("bhaskix.fault="))
        .and_then(Fault::parse)
}

/// Triggers `fault`.
///
/// Returns `true` when the fault was **survivable by design** and the machine
/// should carry on — which is [`Fault::UserMode`] and nothing else.
///
/// For the other six, returning at all means the exception was silently
/// swallowed, and the caller treats that as the failure it is.
#[must_use]
pub fn trigger(fault: Fault) -> bool {
    println!();
    println!("  fault injection: deliberately triggering {fault:?}");
    println!("  (requested by bhaskix.fault= on the kernel command line)");

    match fault {
        Fault::DivideError => divide_error(),
        Fault::InvalidOpcode => invalid_opcode(),
        Fault::Breakpoint => breakpoint(),
        Fault::GeneralProtection => general_protection(),
        Fault::GeneralProtectionHoldingRunqueue => {
            crate::sched::wedge_own_runqueue();
            general_protection();
        }
        Fault::PageFault => page_fault(),
        Fault::DoubleFault => double_fault(),
        // Handled by the kernel proper: it needs a domain, a loader and a
        // scheduler, none of which belong in this module.
        Fault::UserMode => return true,
    }
    false
}

fn divide_error() {
    // Written in assembly, not as `a / b` in Rust.
    //
    // The workspace builds with `overflow-checks = true` even in release
    // (docs/coding-style.md), so Rust emits an explicit zero test and panics
    // before the CPU ever executes a division. That is correct behaviour for
    // kernel code and we do not want to weaken it -- but it means the only way
    // to reach the *hardware* #DE is to issue the instruction directly.
    //
    // SAFETY: `div` by zero is architecturally guaranteed to raise #DE, which
    // is the intent. The explicit register operands cover everything `div`
    // reads and writes.
    unsafe {
        core::arch::asm!(
            "xor edx, edx",
            "div {divisor:e}",
            divisor = in(reg) 0u32,
            inout("eax") 1u32 => _,
            out("edx") _,
            options(nostack),
        );
    }
}

fn invalid_opcode() {
    // SAFETY: `ud2` is architecturally guaranteed to raise #UD. That is the
    // entire point of the instruction, and it is the intent here.
    unsafe { core::arch::asm!("ud2", options(nomem, nostack)) };
}

fn breakpoint() {
    // SAFETY: `int3` raises #BP. Unlike the others this is recoverable in
    // principle, which makes it a useful check that the handler reports
    // rather than that the CPU faults.
    unsafe { core::arch::asm!("int3", options(nomem, nostack)) };
}

fn general_protection() {
    // Loading a segment register with a selector far beyond the GDT limit
    // raises #GP with that selector as the error code -- which also exercises
    // the selector decoding in the reporter.
    //
    // SAFETY: deliberately invalid, and intended to fault. Nothing after this
    // point depends on the register having been loaded.
    unsafe { core::arch::asm!("mov ds, {0:x}", in(reg) 0xdead_u64, options(nostack)) };
}

fn page_fault() {
    // A non-canonical-adjacent unmapped kernel address. Chosen rather than
    // null so the report distinguishes "unmapped" from "null dereference",
    // both of which the reporter special-cases.
    let address = 0xffff_9000_dead_b000 as *mut u64;
    // SAFETY: deliberately unmapped, and intended to fault.
    unsafe { core::ptr::write_volatile(address, 0x1234) };
}

/// Overflows the kernel stack, which faults on its guard page.
///
/// This is the realistic cause of a double fault, and until M3 it could not be
/// tested at all: the kernel ran on the bootloader's stack, which has no guard
/// page, so an overflow silently scribbled over the page tables until the
/// machine died in a way no handler could report. With a guarded stack
/// (`crate::stack`) the overflow faults on the guard instead.
///
/// The escalation is the point. The guard page raises a page fault; delivering
/// it requires pushing an exception frame onto the stack that just ran out, so
/// that faults too; a fault during fault delivery is a double fault, and the
/// double-fault handler runs on `IST1` with a known-good stack. Which is why
/// this reports rather than resetting the machine.
///
/// The unconditional recursion is the mechanism, not an oversight.
#[allow(unconditional_recursion)]
fn double_fault() {
    // A volatile write to a local in every frame, so the recursion cannot be
    // flattened into a loop by tail-call optimisation -- which would spin
    // forever instead of consuming stack.
    let mut anchor = [0u64; 16];
    // SAFETY: `anchor` is a live local; the write is only here to force the
    // frame to be allocated and retained.
    unsafe { core::ptr::write_volatile(&raw mut anchor[0], 1) };
    double_fault();
    // SAFETY: as above. Unreachable, but keeps the frame live across the call.
    unsafe { core::ptr::write_volatile(&raw mut anchor[15], 2) };
}
