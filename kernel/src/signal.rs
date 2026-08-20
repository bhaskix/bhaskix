// SPDX-License-Identifier: Apache-2.0
//! Linux signal delivery, for domains that speak that dialect.
//!
//! [RFC 0005](../../docs/rfc/0005-linux-abi-compatibility.md) step 4, built
//! before threading because it is where the design is most likely to be
//! wrong. The arithmetic — which handler, which stack, what the frame's bytes
//! are — lives in `bhaskix_personality::signal` and is host-tested there.
//! What lives here is the part that needs the machine: writing the frame into
//! the interrupted thread's own memory, pointing its registers at the
//! handler, and putting them all back when `rt_sigreturn` says so.
//!
//! # The shape of a delivery
//!
//! On a fault in a tagged domain with a handler installed:
//!
//! 1. The interrupted register file is written as a `sigcontext` on the
//!    delivery stack (the alternate one if the handler asked and one is set).
//! 2. The handler's arguments go in `rdi`/`rsi`/`rdx`: signal number,
//!    `siginfo` (a minimal one — the fault address is what Go reads), and the
//!    `ucontext` whose `sigcontext` was just written.
//! 3. `rip` becomes the handler, `rsp` the frame — and the return address on
//!    the stack is the *restorer*, so a handler that simply returns performs
//!    the `rt_sigreturn` its libc or runtime supplied.
//!
//! On `rt_sigreturn`: read the `sigcontext` back — including any `rip` the
//! handler edited, which is exactly how a recovered panic resumes elsewhere —
//! and resume.

use bhaskix_personality::signal::{Registers, sigcontext};

/// How many `rt_sigreturn`s have resumed a thread.
pub static RETURNED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// A `siginfo_t` is 128 bytes on Linux; only `si_addr` is filled.
const SIGINFO_BYTES: usize = 128;
/// Where the `mcontext` starts inside the `ucontext`.
const UCONTEXT_MCONTEXT: usize = 40;

/// Resumes a thread from the frame a handler was given — `rt_sigreturn`.
///
/// Reads the `sigcontext` back out of the thread's own memory, so a handler
/// that edited `rip` resumes where it said — which is the whole mechanism a
/// recovered Go panic depends on. Returns whether the frame was readable; a
/// hosted process that corrupted its own stack gets `false` and the ordinary
/// refusal.
///
/// # The stated narrowing
///
/// `rt_sigreturn` arrives as a *system call*, so what this can write is the
/// system-call frame — which carries exactly the caller-saved registers
/// (`rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`–`r11`), plus `rip`, `rflags` and
/// the user stack pointer. The callee-saved four (`rbx`, `rbp`, `r12`–`r15`)
/// are **not** restored from the frame, and do not need to be while every
/// handler obeys the C ABI it was compiled to: a handler that returns has
/// already preserved them. The trigger for widening this — saving the full
/// register file across the entry stub — is the first handler that
/// *deliberately edits* a callee-saved register in the `ucontext` and expects
/// the edit to take. Go's fault handler edits `rip`; if its preemption path
/// turns out to edit more, this is the paragraph that says what to build.
pub fn sigreturn(frame: &mut bhaskix_arch::syscall::SyscallFrame) -> bool {
    // The handler was entered with `rsp` at the frame base; the `ret` into
    // the restorer consumed the return address, so the process's `rsp` is
    // eight above it.
    let base = frame.user_rsp.wrapping_sub(8);
    let mcontext_at = base + 8 + SIGINFO_BYTES as u64 + UCONTEXT_MCONTEXT as u64;
    let mut bytes = [0u8; sigcontext::SIZE];
    // SAFETY: the fault-protected read; a bad address is reported, not taken.
    let read = unsafe {
        bhaskix_arch::uaccess::copy_from_user(bytes.as_mut_ptr(), mcontext_at, bytes.len())
    };
    if read.is_err() {
        return false;
    }
    let Ok(registers) = Registers::read_sigcontext(&bytes) else {
        return false;
    };
    frame.kind = registers.rax;
    frame.capability = registers.rdi;
    frame.method = registers.rsi;
    frame.arg0 = registers.rdx;
    frame.arg1 = registers.r10;
    frame.arg2 = registers.r8;
    frame.arg3 = registers.r9;
    frame.rip = registers.rip;
    frame.rflags = registers.eflags;
    frame.user_rsp = registers.rsp;
    RETURNED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    true
}
