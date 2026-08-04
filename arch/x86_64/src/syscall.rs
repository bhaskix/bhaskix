// SPDX-License-Identifier: Apache-2.0
//! The `SYSCALL`/`SYSRET` fast entry path.
//!
//! Implements the machine half of [RFC 0008]; the meaning of the arguments is
//! the kernel's and lives in `bhaskix_kernel::syscall`.
//!
//! [RFC 0008]: ../../../docs/rfc/0008-syscall-and-ipc-shape.md
//!
//! # What `SYSCALL` does not do for you
//!
//! `SYSCALL` is fast because it does almost nothing: it loads `CS` and `SS`
//! from an MSR, masks some flags, and jumps. In particular it does **not**
//! switch the stack. On entry `RSP` still points into user memory, which the
//! kernel must not touch and must not trust, and the very first thing that
//! writes to the stack — including the `push` a compiler emits — would write
//! there.
//!
//! So the entry stub switches stacks by hand, and to find the kernel stack it
//! needs per-CPU data, and to reach per-CPU data it needs `GS` — which also
//! still holds a user value. That is what `swapgs` is for, and it is why the
//! first two instructions of the stub are the two most dangerous instructions
//! in the kernel: everything before `swapgs` runs with user-controlled `RSP`,
//! and everything after it runs with a kernel `GS` that must be swapped back
//! on every path out, including error paths.
//!
//! # Why the GDT layout is checked at compile time
//!
//! `SYSRET` does not take a selector. It computes both from
//! `IA32_STAR[63:48]`: code at `+16`, stack at `+8`. So the GDT must place
//! user data immediately before user code, and a rearrangement that looks
//! harmless silently returns to user mode with the wrong descriptors — which
//! is a privilege escalation, not a crash. [`assert_sysret_layout`] makes that
//! a build failure instead.
//!
//! # Not yet
//!
//! - **No syscall from user mode**, because there is no user mode. The MSRs
//!   are programmed and verified, the stub exists, and the first caller
//!   arrives with ring 3 in M5-04.
//! - **No FPU state.** Nothing in the kernel uses it; see `context.rs`.
//! - **No per-thread kernel stack selection.** The stub uses the CPU's stack,
//!   which is correct only while one thread per CPU can be in a syscall — true
//!   today because nothing can call one.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::gdt;
use crate::msr;

/// `IA32_EFER` — bit 0 enables `SYSCALL`/`SYSRET`.
const IA32_EFER: u32 = 0xc000_0080;
/// `IA32_STAR` — the segment selectors both instructions use.
const IA32_STAR: u32 = 0xc000_0081;
/// `IA32_LSTAR` — the 64-bit entry point.
const IA32_LSTAR: u32 = 0xc000_0082;
/// `IA32_FMASK` — bits cleared from `RFLAGS` on entry.
const IA32_FMASK: u32 = 0xc000_0084;
/// `IA32_KERNEL_GS_BASE` — the value `swapgs` exchanges into `GS`.
const IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;

/// `EFER.SCE`: system call extensions.
const EFER_SCE: u64 = 1 << 0;

/// Flags cleared on entry to the kernel.
///
/// Each one is a way for user mode to change how kernel code behaves, and
/// leaving any of them set is a well-known way to be exploited:
///
/// - `IF` (bit 9): the handler runs with interrupts masked until it chooses
///   otherwise. Without this, an interrupt can arrive between `swapgs` and the
///   stack switch, on a user stack with a kernel `GS`.
/// - `DF` (bit 10): the string instructions' direction. A kernel `rep movsb`
///   with `DF` set copies backwards.
/// - `TF` (bit 8): single-step. User mode must not be able to trap the kernel
///   on every instruction.
/// - `AC` (bit 18): alignment check, and more importantly the flag `stac`
///   sets. Entering with it set would defeat SMAP for the whole syscall.
/// - `NT` (bit 14): nested task, which affects `iret`.
const FMASK: u64 = (1 << 9) | (1 << 10) | (1 << 8) | (1 << 18) | (1 << 14);

/// Whether [`init`] has run on this machine.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Fails the build if the GDT cannot support `SYSRET`.
///
/// `SYSRET` derives both selectors from one MSR field, so the layout is not a
/// convention that can be changed — it is an instruction encoding. Checking it
/// here means a reordering of `gdt.rs` fails to compile rather than returning
/// to user mode with a stack descriptor that is actually code.
const fn assert_sysret_layout() {
    const {
        assert!(
            gdt::USER_DATA == gdt::KERNEL_DATA + 8,
            "SYSRET requires user data at IA32_STAR[63:48] + 8"
        );
    }
    const {
        assert!(
            gdt::USER_CODE == gdt::KERNEL_DATA + 16,
            "SYSRET requires user code at IA32_STAR[63:48] + 16"
        );
    }
    const {
        assert!(
            gdt::KERNEL_DATA == gdt::KERNEL_CODE + 8,
            "SYSCALL requires kernel stack at IA32_STAR[47:32] + 8"
        );
    }
}

const _: () = assert_sysret_layout();

/// Enables `SYSCALL`/`SYSRET` on this CPU.
///
/// # Safety
///
/// Must be called once per CPU, after its GDT is loaded, with interrupts
/// disabled. `kernel_gs_base` must be this CPU's per-CPU area — the value
/// `swapgs` will bring into `GS` on kernel entry.
pub unsafe fn init(kernel_gs_base: u64) {
    // SAFETY: the caller guarantees the CPU state; each MSR below is
    // architectural and this is the only writer of any of them.
    unsafe {
        // The entry point.
        msr::write(IA32_LSTAR, bhaskix_syscall_entry as *const () as u64);

        // Selectors. SYSCALL takes CS from [47:32] and SS from that plus 8;
        // SYSRET takes CS from [63:48] plus 16 and SS from plus 8. The
        // compile-time assertion above is what makes those additions land on
        // the descriptors they are supposed to.
        let star = (u64::from(gdt::KERNEL_DATA) << 48) | (u64::from(gdt::KERNEL_CODE) << 32);
        msr::write(IA32_STAR, star);

        msr::write(IA32_FMASK, FMASK);

        // Where `swapgs` finds the kernel's per-CPU pointer while user code is
        // running. `GS` itself keeps the kernel value for now, because nothing
        // has entered user mode; M5-04 is where the two start alternating.
        msr::write(IA32_KERNEL_GS_BASE, kernel_gs_base);

        // Last: nothing above matters until this bit is set, and setting it
        // first would open the entry point before it had a target.
        let efer = msr::read(IA32_EFER);
        msr::write(IA32_EFER, efer | EFER_SCE);
    }

    ENABLED.store(true, Ordering::Release);
}

/// Whether `SYSCALL` has been enabled on this machine.
#[must_use]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// Reads back what [`init`] programmed, for verification.
///
/// Returns `(efer, star, lstar, fmask)`.
///
/// # Safety
///
/// [`init`] must have run on this CPU.
#[must_use]
pub unsafe fn programmed() -> (u64, u64, u64, u64) {
    // SAFETY: reads four architectural MSRs, which has no side effects.
    unsafe {
        (
            msr::read(IA32_EFER),
            msr::read(IA32_STAR),
            msr::read(IA32_LSTAR),
            msr::read(IA32_FMASK),
        )
    }
}

/// The registers a system call arrives in and returns through.
///
/// `#[repr(C)]` and the field order are load-bearing: the entry stub builds
/// this on the stack with `push` instructions, so the order here is the
/// reverse of the order there.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SyscallFrame {
    /// Fourth argument (`r9`).
    pub arg3: u64,
    /// Third argument (`r8`).
    pub arg2: u64,
    /// Second argument (`r10`, because `SYSCALL` destroys `rcx`).
    pub arg1: u64,
    /// First argument (`rdx`).
    pub arg0: u64,
    /// Method selector (`rsi`).
    pub method: u64,
    /// Capability index (`rdi`).
    pub capability: u64,
    /// Syscall kind on entry, status on return (`rax`).
    pub kind: u64,
    /// User `RFLAGS`, saved by `SYSCALL` into `r11`.
    pub rflags: u64,
    /// User return address, saved by `SYSCALL` into `rcx`.
    pub rip: u64,
}

unsafe extern "C" {
    /// The `SYSCALL` entry point. Never called; `IA32_LSTAR` points at it.
    pub fn bhaskix_syscall_entry();
}

// The entry and exit path.
//
// Written in assembly because the first two instructions run in a state no
// safe language can describe: user-controlled `RSP` and a user `GS`, in kernel
// mode, with a return address in a register the ABI is free to clobber.
core::arch::global_asm!(
    r#"
.section .text
.globl bhaskix_syscall_entry
.align 16
bhaskix_syscall_entry:
    // On entry:
    //   rcx = user rip, r11 = user rflags   (written by SYSCALL itself)
    //   rsp = USER stack -- not ours, not trusted, and not writable safely
    //   gs  = user value
    //
    // Interrupts are already masked: IA32_FMASK clears IF. That is what makes
    // the next three instructions safe to execute as a group -- an interrupt
    // landing between the swapgs and the stack switch would push an interrupt
    // frame onto the user stack with a kernel gs, which is the classic way
    // this path is exploited.
    swapgs

    // Park the user stack in per-CPU data and take the kernel's.
    mov gs:[16], rsp
    mov rsp, gs:[24]

    // Build a SyscallFrame. Pushed in reverse field order, so that the
    // structure reads naturally and the compiler's offsets match.
    push rcx                    // rip
    push r11                    // rflags
    push rax                    // kind
    push rdi                    // capability
    push rsi                    // method
    push rdx                    // arg0
    push r10                    // arg1
    push r8                     // arg2
    push r9                     // arg3

    // The dispatcher takes a pointer to the frame and may modify it.
    mov rdi, rsp
    call bhaskix_syscall_dispatch

    // Unwind the frame, taking the results back out.
    pop r9
    pop r8
    pop r10
    pop rdx                     // arg0 doubles as the second return value
    pop rsi
    pop rdi
    pop rax                     // status
    pop r11                     // rflags for SYSRET
    pop rcx                     // rip for SYSRET

    // Back to the user stack, then to a user gs. Both must happen, in this
    // order, on every path out -- a missed swapgs leaves user mode running
    // with a pointer to kernel per-CPU data in a register it can read.
    mov rsp, gs:[16]
    swapgs
    sysretq
"#
);
