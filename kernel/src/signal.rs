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

use bhaskix_personality::signal::{Dispositions, Registers, sigcontext};

/// The per-domain signal state, indexed by domain slot.
///
/// A fixed table beside the domain table, for the reason the domain table is
/// fixed: this is the nucleus, and a hosted process's disposition table is
/// bounded by the number of domains that can exist. Rule 1 of RFC 0005 holds
/// — nothing here is a *Linux concept in the object model*; it is state the
/// personality keeps, parked where a fault handler can reach it without a
/// lock it cannot take.
static DISPOSITIONS: crate::sync::SpinLock<[Option<Dispositions>; 32]> =
    crate::sync::SpinLock::new(crate::sync::Rank::Signals, [const { None }; 32]);

/// Installs a handler for `signal` in `domain`'s table, creating the table on
/// first use. Returns the previous handler's entry point.
pub fn install(
    domain: u32,
    signal: u64,
    handler: bhaskix_personality::signal::Handler,
) -> Option<u64> {
    let mut table = DISPOSITIONS.lock();
    let slot = table.get_mut(domain as usize)?;
    let dispositions = slot.get_or_insert_with(Dispositions::new);
    dispositions
        .install(signal, handler)
        .ok()
        .map(|old| old.entry)
}

/// Records an alternate signal stack for `domain`.
pub fn set_alt_stack(domain: u32, alt: bhaskix_personality::signal::AltStack) -> bool {
    let mut table = DISPOSITIONS.lock();
    let Some(slot) = table.get_mut(domain as usize) else {
        return false;
    };
    slot.get_or_insert_with(Dispositions::new)
        .set_alt_stack(alt);
    true
}

/// Forgets everything a domain asked for. Called when it ends, so a reused
/// slot never inherits handlers — the same rule the personality tag follows.
pub fn forget(domain: u32) {
    let mut table = DISPOSITIONS.lock();
    if let Some(slot) = table.get_mut(domain as usize) {
        *slot = None;
    }
}

/// How many signals have been delivered, for the boot report.
pub static DELIVERED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// How many `rt_sigreturn`s have resumed a thread.
pub static RETURNED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Bytes the whole delivery frame occupies: the return address, a minimal
/// `siginfo`, and the `ucontext` whose `sigcontext` the handler reads.
const FRAME_BYTES: usize = 8 + SIGINFO_BYTES + UCONTEXT_BYTES;
/// A `siginfo_t` is 128 bytes on Linux; only `si_addr` is filled.
const SIGINFO_BYTES: usize = 128;
/// Offset of `si_addr` within `siginfo_t` on x86-64.
const SIGINFO_ADDR: usize = 16;
/// The `ucontext` this personality builds: the `sigcontext` at the offset
/// Linux puts it, and nothing else a hosted runtime reads.
const UCONTEXT_BYTES: usize = UCONTEXT_MCONTEXT + sigcontext::SIZE;
/// Where `uc_mcontext` sits inside `ucontext_t` on x86-64.
const UCONTEXT_MCONTEXT: usize = 40;

/// The register file the interrupted thread had, from a trap frame.
fn registers_of(frame: &bhaskix_arch::trap::TrapFrame, fault_address: u64) -> Registers {
    Registers {
        rax: frame.rax,
        rbx: frame.rbx,
        rcx: frame.rcx,
        rdx: frame.rdx,
        rsi: frame.rsi,
        rdi: frame.rdi,
        rbp: frame.rbp,
        rsp: frame.rsp,
        r8: frame.r8,
        r9: frame.r9,
        r10: frame.r10,
        r11: frame.r11,
        r12: frame.r12,
        r13: frame.r13,
        r14: frame.r14,
        r15: frame.r15,
        rip: frame.rip,
        eflags: frame.rflags,
        cr2: fault_address,
    }
}

/// Delivers a `SIGSEGV` for a fault, if this domain speaks Linux and has a
/// handler installed. Returns whether the thread was redirected — `false`
/// means "not ours", and the caller ends the domain as it always did.
pub fn deliver_for_fault(frame: &mut bhaskix_arch::trap::TrapFrame, fault_address: u64) -> bool {
    use bhaskix_personality::signal::number::SIGSEGV;

    let Some(domain) = crate::sched::current_domain() else {
        return false;
    };
    let slot = domain.as_u32();
    if crate::domain::LINUX_DOMAINS.load(core::sync::atomic::Ordering::Relaxed) & (1 << (slot % 32))
        == 0
    {
        return false;
    }

    let (handler, stack_top) = {
        let table = DISPOSITIONS.lock();
        let Some(Some(dispositions)) = table.get(slot as usize) else {
            return false;
        };
        let Some(handler) = dispositions.handler(SIGSEGV) else {
            return false;
        };
        (handler, dispositions.delivery_stack(SIGSEGV, frame.rsp))
    };

    // The frame goes below the delivery stack's top, sixteen-aligned as the
    // ABI requires -- and then the return address is pushed, which is what
    // leaves `rsp % 16 == 8` at the handler's first instruction, exactly as a
    // `call` would.
    let frame_at = (stack_top - FRAME_BYTES as u64) & !15;
    let registers = registers_of(frame, fault_address);

    let mut image = [0u8; FRAME_BYTES];
    image[..8].copy_from_slice(&handler.restorer.to_le_bytes());
    image[8 + SIGINFO_ADDR..8 + SIGINFO_ADDR + 8].copy_from_slice(&fault_address.to_le_bytes());
    let mcontext_at = 8 + SIGINFO_BYTES + UCONTEXT_MCONTEXT;
    if registers
        .write_sigcontext(&mut image[mcontext_at..])
        .is_err()
    {
        return false;
    }

    // Into the thread's own memory, through the fault-protected copy: a
    // hosted process whose stack is unmapped gets a refused delivery and the
    // ordinary ending, not a kernel fault.
    // SAFETY: `copy_to_user` is the fault-protected write; a bad address is
    // an error it reports rather than a fault it takes, and `image` is this
    // function's own buffer.
    let written =
        unsafe { bhaskix_arch::uaccess::copy_to_user(frame_at, image.as_ptr(), image.len()) };
    if written.is_err() {
        return false;
    }

    // The handler's three arguments, and the redirect.
    frame.rdi = SIGSEGV;
    frame.rsi = frame_at + 8;
    frame.rdx = frame_at + 8 + SIGINFO_BYTES as u64;
    frame.rip = handler.entry;
    frame.rsp = frame_at;
    DELIVERED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    true
}

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
