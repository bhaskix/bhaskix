// SPDX-License-Identifier: Apache-2.0
//! Thread contexts and the switch between them.
//!
//! Implements the context switch described in `docs/scheduler.md` §6.
//!
//! # What is saved, and what deliberately is not
//!
//! Only the callee-saved registers and the stack pointer. **Caller-saved
//! registers are not saved**, and that is not an oversight: the compiler
//! already spilled anything live across a call, because [`switch`] *is* a
//! call. Saving them would be work with no observable effect, and it is a
//! mistake hand-written switchers make routinely.
//!
//! The saved registers live on the outgoing thread's own stack rather than in
//! the [`Context`] struct, which is why the struct holds one field. Restoring
//! is then a matter of pointing `RSP` at the other stack and popping.
//!
//! # Not yet handled
//!
//! - **FPU, SSE, and AVX state.** Nothing in the kernel uses floating point —
//!   the target disables SSE entirely — so there is nothing to save. When user
//!   mode arrives in M5 it will need `XSAVE`, done *lazily* via `CR0.TS`:
//!   AVX-512 state is 2.5 KiB, and switching it eagerly for threads that never
//!   touch it is a large invisible cost.
//! - **`CR3`.** Every thread currently shares the kernel address space. Address
//!   space switching belongs with processes in M5.
//!
//! # The hook a scheduler may register
//!
//! Every way out of a switch returns into [`bhaskix_context_switch`]'s caller
//! — except one. A thread that has never run is entered through the
//! trampoline and never returns there at all, so a scheduler has no way to
//! observe that the switch completed. [`set_thread_entered`] registers a
//! callback the trampoline invokes for exactly that case.
//!
//! It matters to anything that migrates threads: a CPU partway through a
//! switch is holding a thread whose registers are not yet saved, and the
//! moment that stops being true is the only safe point to say so.

use core::sync::atomic::{AtomicUsize, Ordering};

/// A suspended thread's saved state.
///
/// One field, because everything else lives on that thread's stack.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Context {
    /// Stack pointer of the suspended thread, pointing at its saved registers.
    pub rsp: u64,
}

impl Context {
    /// An empty context, for a thread that has not been prepared yet.
    #[must_use]
    pub const fn new() -> Self {
        Self { rsp: 0 }
    }

    /// Builds the initial stack for a thread that has never run.
    ///
    /// The trick is to fabricate exactly what [`switch`] expects to find: six
    /// saved callee-saved registers with `entry` sitting above them where a
    /// return address would be. The first switch into this thread pops the six
    /// registers and `ret`s straight into `entry`, so a brand-new thread and a
    /// preempted one are indistinguishable to the switch code.
    ///
    /// The entry point and its argument travel in **callee-saved** registers
    /// — `r12` and `rbx` — because those are the only ones the switch
    /// restores. `rdi`, where the SysV convention wants the argument, is
    /// caller-saved and would arrive holding whatever the previous thread left
    /// there; the trampoline moves it into place at the last moment.
    ///
    /// # Safety
    ///
    /// `stack_top` must be the 16-byte-aligned address one past the top of a
    /// writable, mapped stack with room for at least eight quadwords, and
    /// `entry` must never return — there is no frame beneath it to return to.
    pub unsafe fn prepare(
        &mut self,
        stack_top: u64,
        entry: extern "C" fn(u64) -> !,
        argument: u64,
    ) {
        // One dead slot at the very top. After the `ret` in `switch`, RSP will
        // be `stack_top - 8`, which is 8 modulo 16 -- exactly the alignment
        // the SysV ABI guarantees at a function's first instruction, and so
        // exactly what the trampoline is entitled to assume. Skipping this
        // yields a 16-aligned RSP instead, and the resulting misaligned SSE
        // accesses surface deep inside unrelated code.
        //
        // The trampoline re-aligns from there before calling the entry point,
        // because a `call` needs RSP 0 modulo 16 to hand the callee 8.
        let mut sp = stack_top - 8;

        // SAFETY: the caller guarantees the stack is mapped and large enough;
        // every write below stays within eight quadwords of the top.
        unsafe {
            // What the final `ret` in `switch` will pop. Not the entry point
            // itself but the trampoline, which puts the argument where the ABI
            // wants it before calling through.
            sp -= 8;
            // Via `*const ()`: casting a function *item* straight to an
            // integer is rejected as of Rust 1.97, because the item type is
            // zero-sized and the cast reads as a value conversion when it is
            // really taking an address.
            (sp as *mut u64).write(bhaskix_thread_trampoline as *const () as usize as u64);

            // The six callee-saved registers, in the order `switch` pops them:
            // r15, r14, r13, r12, rbx, rbp -- so they are written in reverse.
            sp -= 8;
            (sp as *mut u64).write(0); // rbp
            sp -= 8;
            (sp as *mut u64).write(argument); // rbx -> rdi
            sp -= 8;
            (sp as *mut u64).write(entry as usize as u64); // r12 -> call target
            sp -= 8;
            (sp as *mut u64).write(0); // r13
            sp -= 8;
            (sp as *mut u64).write(0); // r14
            sp -= 8;
            (sp as *mut u64).write(0); // r15
        }

        self.rsp = sp;
    }
}

unsafe extern "C" {
    /// Saves the current context into `from` and resumes `to`.
    ///
    /// Returns to its caller when the outgoing thread is next scheduled, which
    /// may be much later and on a different CPU.
    ///
    /// # Safety
    ///
    /// Both pointers must be valid `Context` values, `to` must have been
    /// prepared by [`Context::prepare`] or saved by a previous switch, and
    /// interrupts should be disabled — a switch interrupted halfway leaves the
    /// scheduler's idea of the current thread disagreeing with the hardware.
    pub unsafe fn bhaskix_context_switch(from: *mut Context, to: *const Context);

    /// First instruction every new thread executes.
    ///
    /// Never called directly; [`Context::prepare`] arranges for the switch to
    /// `ret` into it.
    pub fn bhaskix_thread_trampoline();
}

/// Registered callback for "a brand-new thread has started".
///
/// A pointer rather than a linker-level override: a weak symbol in this crate
/// and a strong one in the kernel end up in the same object under LTO, which
/// is a link error rather than an override. This keeps the dependency pointing
/// the right way — the kernel knows about the arch crate, not the reverse —
/// without asking the linker to arbitrate.
static THREAD_ENTERED: AtomicUsize = AtomicUsize::new(0);

/// Registers the callback the thread trampoline invokes.
///
/// Idempotent, and safe to call from every CPU. Must be registered before the
/// first thread is created; a switch into a new thread with no callback
/// registered is not an error, it simply reports nothing.
pub fn set_thread_entered(hook: extern "C" fn()) {
    THREAD_ENTERED.store(hook as usize, Ordering::Release);
}

/// Called by the trampoline, with interrupts still disabled.
#[unsafe(no_mangle)]
extern "C" fn bhaskix_thread_entered() {
    let hook = THREAD_ENTERED.load(Ordering::Acquire);
    if hook == 0 {
        return;
    }
    // SAFETY: the value is either zero, handled above, or was written by
    // `set_thread_entered` from an `extern "C" fn()` -- the only writer, and
    // the only type it accepts.
    let hook: extern "C" fn() = unsafe { core::mem::transmute(hook) };
    hook();
}

/// Convenience wrapper over [`bhaskix_context_switch`].
///
/// # Safety
///
/// As [`bhaskix_context_switch`].
pub unsafe fn switch(from: &mut Context, to: &Context) {
    // SAFETY: references are always valid pointers; the rest of the contract
    // is delegated to the caller.
    unsafe { bhaskix_context_switch(from, to) }
}

// The switch itself.
//
// Written in assembly because the transition is not expressible in Rust: for
// the few instructions around the `mov rsp`, the machine has one thread's
// registers and another thread's stack, and no safe language can describe a
// point where locals belong to neither frame.
core::arch::global_asm!(
    r#"
.section .text
.globl bhaskix_context_switch
.align 16
bhaskix_context_switch:
    // rdi = &mut Context (outgoing), rsi = &Context (incoming)

    // Only callee-saved registers. Anything caller-saved was already spilled
    // by the compiler across this call, so saving it would be pure cost.
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov [rdi], rsp          // outgoing.rsp = current stack
    mov rsp, [rsi]          // switch to the incoming stack

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp

    // For a thread that has run before, this returns into the middle of a
    // previous call to this function. For a brand-new one, `Context::prepare`
    // arranged for it to return into the trampoline below.
    ret

// Entry trampoline for threads that have never run.
//
// `prepare` parks the argument in rbx and the entry point in r12, because
// those survive the register restore above while rdi does not. This moves the
// argument into the ABI's register and calls through.
//
// The entry point must not return: there is no frame beneath it. `ud2` makes
// that a fault at the exact instruction rather than a jump into whatever
// happens to follow on the stack.
.globl bhaskix_thread_trampoline
.align 16
bhaskix_thread_trampoline:
    // Align for the two calls below. On entry RSP is 8 modulo 16 -- what the
    // ABI guarantees at a function's first instruction -- and `call` pushes
    // eight more, so RSP must be 0 modulo 16 *before* a call for the callee to
    // see the alignment it is entitled to. Without this the entry point runs
    // one quadword out, which is invisible until the first aligned SSE access
    // and then faults somewhere with no relation to the cause.
    sub rsp, 8

    // Tell the scheduler the switch that brought us here has completed. Every
    // other path out of a switch returns into `bhaskix_context_switch`'s
    // caller, which can do this itself; a brand-new thread never returns
    // there, so without this call its CPU would stay marked mid-switch and no
    // other CPU would steal from it again.
    call bhaskix_thread_entered

    // Interrupts must be re-enabled by hand here, and getting this wrong is a
    // silent hang rather than a crash.
    //
    // A thread that has run before resumes through `iretq`, which restores
    // RFLAGS and with it the interrupt flag. A brand-new thread has no such
    // frame: it is entered by a `ret` from inside the timer's interrupt gate,
    // which cleared IF on entry. Without this `sti` the first thread scheduled
    // would run with interrupts disabled forever -- so the timer that would
    // preempt it never fires again, and the machine simply stops.
    //
    // It comes *after* the call above so that the scheduler bookkeeping runs
    // with interrupts still masked, and cannot be preempted halfway.
    sti
    mov rdi, rbx
    call r12
    ud2

"#
);
