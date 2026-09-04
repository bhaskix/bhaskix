// SPDX-License-Identifier: Apache-2.0
//! Interrupt and exception entry.
//!
//! # A known gap: NMI against `swapgs`
//!
//! The entry path decides whether to `swapgs` by looking at the interrupted
//! `CS`. That is correct for every interrupt except one arriving inside the
//! syscall stub's first instruction — where `CS` is already the kernel's but
//! `GS` is still the user's, so the test says "no swap" and the handler runs
//! with a user `GS`.
//!
//! Only an NMI can arrive there, because `IA32_FMASK` masks `IF` before the
//! stub runs. Nothing in Bhaskix enables an NMI source yet, so the window is
//! unreachable rather than merely unlikely. The standard fix is a separate
//! entry path that reads `IA32_GS_BASE` and decides from its value instead of
//! from `CS`, and it belongs with whatever first enables an NMI.
//!
//! Every one of the 256 vectors enters through a small stub that normalises
//! the stack into a [`TrapFrame`] and jumps to shared code. The stubs exist
//! because the CPU is not consistent: some vectors push an error code and some
//! do not, and none of them push the vector number. Handling that difference
//! once, here, means the rest of the kernel sees a single uniform frame.
//!
//! # Stack layout at the handler
//!
//! ```text
//!   high    SS          <- pushed by the CPU
//!           RSP
//!           RFLAGS
//!           CS
//!           RIP
//!           error code  <- CPU for some vectors; a zero pushed by the stub
//!           vector      <- pushed by the stub, always
//!           RAX             <- pushed by isr_common, in reverse field order
//!           ...
//!   low     R15         <- RSP points here when the Rust handler is called
//! ```
//!
//! The layout is exactly [`TrapFrame`], so the handler receives a pointer to
//! the stack and reads it as a struct. Changing either without the other
//! produces garbage register dumps that look almost plausible, which is worse
//! than a crash — so the field order below is load-bearing.

use core::sync::atomic::{AtomicPtr, Ordering};

/// Interrupts and exceptions taken while the CPU was in user mode.
///
/// Counted so a test can assert that the interrupt-from-ring-3 path was
/// actually taken. A user-mode test that is never interrupted exercises the
/// system-call path and nothing else — and the entry `swapgs` it does not
/// reach is the difference between a working kernel and one that reads a
/// user-controlled `GS` base.
static FROM_USER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// How many interrupts arrived from user mode.
#[must_use]
pub fn interrupts_from_user() -> u64 {
    FROM_USER.load(Ordering::Relaxed)
}

/// A saved processor state, as built by the interrupt stubs.
///
/// Field order matches the push order in `isr_common` and must not be
/// reordered.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TrapFrame {
    /// Callee- and caller-saved general purpose registers.
    pub r15: u64,
    /// See [`TrapFrame::r15`].
    pub r14: u64,
    /// See [`TrapFrame::r15`].
    pub r13: u64,
    /// See [`TrapFrame::r15`].
    pub r12: u64,
    /// See [`TrapFrame::r15`].
    pub r11: u64,
    /// See [`TrapFrame::r15`].
    pub r10: u64,
    /// See [`TrapFrame::r15`].
    pub r9: u64,
    /// See [`TrapFrame::r15`].
    pub r8: u64,
    /// See [`TrapFrame::r15`].
    pub rbp: u64,
    /// See [`TrapFrame::r15`].
    pub rdi: u64,
    /// See [`TrapFrame::r15`].
    pub rsi: u64,
    /// See [`TrapFrame::r15`].
    pub rdx: u64,
    /// See [`TrapFrame::r15`].
    pub rcx: u64,
    /// See [`TrapFrame::r15`].
    pub rbx: u64,
    /// See [`TrapFrame::r15`].
    pub rax: u64,

    /// Which vector fired.
    pub vector: u64,
    /// Architecture-defined error code, or zero for vectors that push none.
    pub error_code: u64,

    /// Instruction pointer at the point of the fault.
    pub rip: u64,
    /// Code segment at the point of the fault.
    pub cs: u64,
    /// Flags at the point of the fault.
    pub rflags: u64,
    /// Stack pointer at the point of the fault.
    pub rsp: u64,
    /// Stack segment at the point of the fault.
    pub ss: u64,
}

impl TrapFrame {
    /// Whether the fault happened in user mode.
    ///
    /// Determined from the saved `CS` privilege level rather than from any
    /// kernel bookkeeping, because bookkeeping is exactly what may be wrong
    /// when a fault is being reported.
    #[must_use]
    pub const fn from_user_mode(&self) -> bool {
        self.cs & 3 != 0
    }
}

/// Signature of the kernel's trap handler.
pub type TrapHandler = fn(&mut TrapFrame);

/// The registered handler.
///
/// A pointer rather than a direct call because `arch` must not depend on the
/// kernel — the dependency direction is `arch -> nothing`
/// (`docs/architecture.md` §5). The kernel registers itself during init.
static HANDLER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Registers the kernel's trap handler.
///
/// Until this is called, a trap prints nothing and halts — which is still
/// better than executing a null pointer.
pub fn set_handler(handler: TrapHandler) {
    HANDLER.store(handler as *mut (), Ordering::Release);
}

/// Called by `isr_common` with a pointer to the frame on the stack.
///
/// # Safety
///
/// Called only from the interrupt stubs, which guarantee `frame` points to a
/// fully populated [`TrapFrame`] on the current stack.
#[unsafe(no_mangle)]
unsafe extern "C" fn bhaskix_trap_dispatch(frame: *mut TrapFrame) {
    // The saved CS's RPL is the only record of what ring was interrupted, and
    // it is the same value the entry stub used to decide whether to `swapgs`.
    // Counting it here means a test can assert the path was taken rather than
    // hoping it was.
    //
    // SAFETY: the stub built this frame on the current stack and it outlives
    // the call.
    if unsafe { (*frame).cs } & 3 != 0 {
        FROM_USER.fetch_add(1, Ordering::Relaxed);
    }

    let handler = HANDLER.load(Ordering::Acquire);

    if handler.is_null() {
        // No handler yet. Halting is the honest response: continuing would
        // return to a faulting instruction and loop forever with no output.
        crate::cpu::halt_forever();
    }

    // SAFETY: `handler` was stored by `set_handler`, which only accepts a
    // `TrapHandler`, so transmuting it back to that type recovers the original
    // function pointer. It was checked non-null above.
    let handler: TrapHandler = unsafe { core::mem::transmute::<*mut (), TrapHandler>(handler) };

    // **What the frame looked like on the way in.** See `implausible` for why
    // this is worth two comparisons.
    //
    // SAFETY: as the read above.
    let arrived = unsafe { implausible(&*frame) };

    // SAFETY: the stubs guarantee `frame` points to a fully initialised
    // `TrapFrame` on the current stack, valid for the duration of this call
    // and not aliased -- interrupts are disabled and this is the only
    // reference taken.
    handler(unsafe { &mut *frame });

    // **And on the way out**, which is the half that has evidence waiting for
    // it. The frame the stub is about to `iretq` through is this one, and a
    // corrupted selector in it faults *there* -- at an address in the entry
    // stub, with no indication of what wrote it or when.
    //
    // Checking both ends brackets the corruption: arriving bad says it
    // happened before this dispatch, leaving bad says it happened inside it.
    // Neither is a fix and neither is a guess; they are the difference between
    // a `#GP` at `iretq` and a line naming the field and the value.
    //
    // SAFETY: as above -- the frame outlives the call.
    let leaving = unsafe { implausible(&*frame) };
    if arrived.is_some() || leaving.is_some() {
        // **Recorded here and printed by the kernel.** This crate is the
        // bottom of the dependency order and has no console; the kernel reads
        // these and says so in its boot report and in its own fault path.
        // Only the first witness is kept: the first is the one that happened
        // before anything else could have been disturbed by it.
        if FRAME_IMPLAUSIBLE.fetch_add(1, Ordering::Relaxed) == 0 {
            // SAFETY: as above.
            let frame = unsafe { &*frame };
            for (slot, value) in FRAME_WITNESS.iter().zip([
                frame.vector,
                frame.rip,
                frame.cs,
                frame.rflags,
                frame.rsp,
                frame.ss,
            ]) {
                slot.store(value, Ordering::Relaxed);
            }
            FRAME_ON_ENTRY.store(arrived.is_some(), Ordering::Relaxed);
        }
    }
}

/// How many frames failed [`implausible`] at either end of a dispatch.
pub static FRAME_IMPLAUSIBLE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The first such frame: vector, rip, cs, rflags, rsp, ss.
static FRAME_WITNESS: [core::sync::atomic::AtomicU64; 6] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 6];

/// Whether that first one was already wrong when the interrupt arrived.
static FRAME_ON_ENTRY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// What the frame checks have seen: how many, the first one's fields, and
/// whether it was already wrong on entry.
///
/// **Read by the kernel, because this crate has no console.** Arriving wrong
/// means the corruption predates the dispatch; leaving wrong means it happened
/// inside it. That bracket is the whole point of checking twice.
#[must_use]
pub fn implausible_frames() -> (u64, [u64; 6], bool) {
    let mut witness = [0u64; 6];
    for (slot, value) in FRAME_WITNESS.iter().zip(witness.iter_mut()) {
        *value = slot.load(Ordering::Relaxed);
    }
    (
        FRAME_IMPLAUSIBLE.load(Ordering::Relaxed),
        witness,
        FRAME_ON_ENTRY.load(Ordering::Relaxed),
    )
}

/// Which field of `frame` could not be returned through, if any.
///
/// # Why this is worth checking twice
///
/// An `iretq` through a corrupted frame faults **at the `iretq`** — the report
/// names the entry stub, which is where every interrupt returns and therefore
/// tells nobody anything. A `#GP` caught on 2026-08-29 said only
/// *"referencing selector index 0x1325 in the GDT"*; which field held it, and
/// whether it was already wrong when the interrupt arrived, the machine could
/// not say.
///
/// **Deliberately not strict.** It rejects only what the processor itself
/// cannot use — a non-canonical `rip`, a selector that is neither of the two
/// this kernel installs, a clear `rflags.IF` where the frame says user mode —
/// because a check that guessed at *policy* would fire on something legitimate
/// and be turned off.
fn implausible(frame: &TrapFrame) -> Option<&'static str> {
    /// The kernel's own code selector, and the only one it ever returns to
    /// ring 0 through.
    const KERNEL_CS: u64 = 0x08;
    /// Its stack selector.
    const KERNEL_SS: u64 = 0x10;
    /// The ring-3 pair, as `sysret` builds them: `gdt::USER_CODE | 3` and
    /// `gdt::USER_DATA | 3`. Written here rather than imported so this file
    /// has no dependency on the descriptor module for a check.
    const USER_CS: u64 = (crate::gdt::USER_CODE | 3) as u64;
    /// See [`USER_CS`].
    const USER_SS: u64 = (crate::gdt::USER_DATA | 3) as u64;

    // **Both rings, which the comment above always claimed and the code did
    // not do.** This said it rejects "a selector that is neither of the two
    // this kernel installs", and then checked only the ring-0 case: a frame
    // whose `cs` merely had its ring bits set passed whatever else was in it,
    // and so did its `ss`. A corrupted frame claiming ring 3 was accepted
    // whole.
    //
    // That matters for the fault this check exists for. Every specimen is a
    // `#GP` at `iretq` naming a selector index in no descriptor table, and the
    // witness has printed nothing on the boots that produced them -- which,
    // with the ring-3 arm checking nothing, is what a garbage `cs` of `0xed03`
    // would also look like. This kernel installs exactly two selectors per
    // ring and returns through no others.
    let user = frame.cs & 3 != 0;
    if user {
        if frame.cs != USER_CS {
            return Some("cs claims ring 3 but is not this kernel's user code selector");
        }
        if frame.ss != USER_SS {
            return Some("ss claims ring 3 but is not this kernel's user stack selector");
        }
    } else {
        if frame.cs != KERNEL_CS {
            return Some("cs is neither the kernel's nor a user selector");
        }
        if frame.ss != KERNEL_SS && frame.ss != 0 {
            return Some("ss is not the kernel's, returning to ring 0");
        }
    }
    if !canonical(frame.rip) {
        return Some("rip is not a canonical address");
    }
    if !canonical(frame.rsp) {
        return Some("rsp is not a canonical address");
    }
    // Bit 1 of `rflags` reads as one on every x86 since the 8086. A frame
    // whose flags have it clear is not a frame the processor wrote.
    if frame.rflags & 0x2 == 0 {
        return Some("rflags bit 1 is clear, which no processor writes");
    }
    // **`VM` set, which is what would make `iretq` fault the way it does.**
    //
    // Every specimen of the open interrupt-frame fault is a `#GP` at
    // `isr_common+0x57` -- `iretq` -- with an error code naming a selector
    // index far outside this kernel's GDT: `0x9928` on 2026-08-29, `0xed00` on
    // 2026-09-04. The checks above pass `cs` and `ss`, and the witness printed
    // nothing on the 2026-09-04 boots, so the two selectors `iretq` normally
    // loads were both fine and it faulted anyway.
    //
    // `iretq` loads *more* than those two if the frame's `rflags` has `VM`
    // (bit 17) set: it takes a virtual-8086 return and loads `ES`, `DS`, `FS`
    // and `GS` from words further up the stack, which in a corrupted frame are
    // whatever happened to be there. That produces exactly this shape -- a
    // fault at `iretq`, naming a selector that appears in no descriptor table,
    // while `cs` and `ss` themselves are ordinary.
    //
    // This kernel never returns to virtual-8086 mode, so `VM` set is
    // impossible rather than merely unusual. Checked here, where it is cheap,
    // and named so a specimen says it outright instead of leaving the error
    // code to be decoded.
    //
    // `NT` (bit 14) goes with it for the same reason: a nested-task return
    // through a task gate is not a thing this kernel does, and it changes what
    // `iretq` reads.
    if frame.rflags & (1 << 17) != 0 {
        return Some("rflags has VM set, so iretq would take a virtual-8086 return");
    }
    if frame.rflags & (1 << 14) != 0 {
        return Some("rflags has NT set, so iretq would take a nested-task return");
    }
    // **The bits no processor sets**, which is a far wider net than bit 1.
    //
    // Bits 3, 5 and 15 read zero on every x86, and bits 22 and above are
    // reserved in 64-bit mode. A frame whose flags have any of them set was
    // not written by this machine. Bit 1 alone catches a *cleared* word;
    // corruption that leaves stack contents behind is far more likely to set
    // something up here, so this is the arm that would notice it.
    const RFLAGS_RESERVED: u64 = (1 << 3) | (1 << 5) | (1 << 15) | 0xffff_ffff_ffc0_0000;
    if frame.rflags & RFLAGS_RESERVED != 0 {
        return Some("rflags has bits set that no processor writes");
    }
    // **A ring-3 frame whose addresses are the kernel's.**
    //
    // `iretq` to ring 3 with a kernel `rip` or `rsp` is a return this machine
    // cannot make: user space is the low half and everything this kernel
    // executes is the high one. Checked only for ring 3, deliberately -- the
    // ring-0 case has no equivalent bound worth asserting, and a check that
    // guessed at one would fire on something legitimate.
    if user && (frame.rip >= HIGH_HALF || frame.rsp >= HIGH_HALF) {
        return Some("a ring-3 frame whose rip or rsp is a kernel address");
    }
    None
}

/// Where the kernel half of the address space begins.
const HIGH_HALF: u64 = 0xffff_8000_0000_0000;

/// Whether `address` is one this processor could load — the halves of the
/// address space, with the hole between them excluded.
const fn canonical(address: u64) -> bool {
    let top = address >> 47;
    top == 0 || top == 0x1_ffff
}

/// Size of each interrupt stub, in bytes.
///
/// Every stub is padded to this so the IDT can be filled by computing
/// `isr_stub_table + vector * STUB_SIZE` rather than needing 256 named
/// symbols. The largest stub is 12 bytes (`push imm32`, `push imm32`,
/// `jmp rel32`), so 16 is both sufficient and a natural alignment.
pub const STUB_SIZE: usize = 16;

unsafe extern "C" {
    /// First byte of the stub table. Stub `n` is at `STUB_SIZE * n`.
    pub unsafe static isr_stub_table: [u8; 0];
}

// The stubs.
//
// Written as assembler rather than generated in Rust because the exact
// instruction sequence and its size matter: the table is indexed by
// arithmetic, so every entry has to occupy exactly STUB_SIZE bytes.
//
// Vectors 8, 10-14, 17, 21, 29, and 30 push an error code. Everything else
// gets a zero pushed in its place so that TrapFrame has one shape.
core::arch::global_asm!(
    r#"
.section .text

.macro ISR_STUB vec, has_error
    .align 16
    .if \has_error == 0
        push 0
    .endif
    push \vec
    jmp isr_common
.endm

.globl isr_stub_table
.align 16
isr_stub_table:
// Bit N set means vector N pushes an error code: 8, 10-14, 17, 21, 29, 30.
// A mask rather than a chain of comparisons because the integrated assembler
// does not accept line continuations inside a .rept body, and a single
// unbroken 300-character condition is unreadable.
.set ERROR_CODE_MASK, 0x60227D00
.set vector_index, 0
.rept 256
    // Guarded by the range test: shifting by more than 31 is not meaningful,
    // and no vector above 31 pushes an error code.
    .if vector_index < 32
        .if (ERROR_CODE_MASK >> vector_index) & 1
            ISR_STUB vector_index, 1
        .else
            ISR_STUB vector_index, 0
        .endif
    .else
        ISR_STUB vector_index, 0
    .endif
    .set vector_index, vector_index + 1
.endr

.align 16
isr_common:
    // Did this interrupt come from user mode? The saved CS's RPL says so, and
    // it is the only thing on the stack that can: the CPU does not tell the
    // handler what ring it interrupted.
    //
    // If it did, GS still holds the *user* value, and every `gs:`-relative
    // access below -- which is most of the scheduler -- would read whatever
    // user mode last put there. `swapgs` brings this CPU's per-CPU area back.
    //
    // At this point the stack is: vector, error code, rip, cs. So cs is at
    // +24, and that offset is only correct here, before any push.
    test qword ptr [rsp + 24], 3
    jz 1f
    swapgs
1:
    // Push in reverse TrapFrame field order, so the frame reads correctly
    // from low address to high.
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    // The SysV ABI requires the direction flag clear on entry to a function.
    // The faulting code may have left it set.
    cld

    // Stack accounting: the CPU aligns RSP to 16 before pushing its frame,
    // then 56 bytes reach here (40 or 48 from the CPU plus 16 or 8 from the
    // stub), plus 120 bytes of registers = 176, which is a multiple of 16.
    // The `call` then pushes 8, giving the callee the RSP%16==8 that SysV
    // expects at function entry.
    mov rdi, rsp
    call bhaskix_trap_dispatch

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    // Discard the vector and error code the stub pushed.
    add rsp, 16

    // Undo the entry swap, on the same condition. The saved CS is now at +8,
    // and it must be re-read rather than remembered: the handler may have
    // switched threads, so nothing that was in a register on entry is
    // necessarily still ours.
    test qword ptr [rsp + 8], 3
    jz 2f
    swapgs
2:
    iretq
"#
);

#[cfg(test)]
mod tests {
    use super::{TrapFrame, implausible};

    /// A frame the processor could have written, returning to ring 0.
    fn kernel_frame() -> TrapFrame {
        TrapFrame {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rbp: 0,
            rdi: 0,
            rsi: 0,
            rdx: 0,
            rcx: 0,
            rbx: 0,
            rax: 0,
            vector: 14,
            error_code: 0,
            rip: 0xffff_ffff_8000_1234,
            cs: 0x08,
            rflags: 0x202,
            rsp: 0xffff_8000_0ec8_d000,
            ss: 0x10,
        }
    }

    /// The same, returning to ring 3.
    fn user_frame() -> TrapFrame {
        TrapFrame {
            rip: 0x0000_0000_0040_1234,
            cs: (crate::gdt::USER_CODE | 3) as u64,
            ss: (crate::gdt::USER_DATA | 3) as u64,
            rsp: 0x0000_7fff_ffff_e000,
            ..kernel_frame()
        }
    }

    /// **The half that matters most.** A check that rejects something the
    /// machine does legitimately gets switched off, and then the fault it was
    /// built for arrives unwitnessed. Both rings must pass untouched.
    #[test]
    fn the_frames_this_machine_actually_writes_are_not_rejected() {
        assert_eq!(implausible(&kernel_frame()), None);
        assert_eq!(implausible(&user_frame()), None);
    }

    #[test]
    fn flags_bits_no_processor_sets_are_rejected() {
        // Bit 1 alone catches a cleared word. Corruption that leaves stack
        // contents behind sets bits instead, and these are the ones that
        // cannot legitimately be set.
        for bit in [3u32, 5, 15, 22, 40, 63] {
            let mut frame = kernel_frame();
            frame.rflags |= 1 << bit;
            assert!(
                implausible(&frame).is_some(),
                "rflags bit {bit} should be impossible"
            );
        }
    }

    #[test]
    fn a_ring_three_frame_returning_to_a_kernel_address_is_rejected() {
        let mut rip = user_frame();
        rip.rip = 0xffff_ffff_8000_1234;
        assert!(implausible(&rip).is_some());

        let mut rsp = user_frame();
        rsp.rsp = 0xffff_8000_0000_1000;
        assert!(implausible(&rsp).is_some());

        // And a ring-0 frame keeps its kernel addresses, which is the whole
        // reason that check is not applied to both rings.
        assert_eq!(implausible(&kernel_frame()), None);
    }

    #[test]
    fn a_ring_three_frame_with_selectors_this_kernel_never_installs_is_rejected() {
        // The arm that checked nothing until 2026-09-04: ring bits set was
        // enough to pass whatever else the frame held.
        let mut cs = user_frame();
        cs.cs = 0xed03;
        assert!(implausible(&cs).is_some());

        let mut ss = user_frame();
        ss.ss = 0xed03;
        assert!(implausible(&ss).is_some());
    }

    #[test]
    fn a_selector_the_kernel_never_installs_is_rejected() {
        // The 2026-08-29 specimen: `#GP` at `iretq`, "referencing selector
        // index 0x1325 in the GDT". Ring bits clear, so it claims ring 0, and
        // it is not this kernel's one code selector.
        let mut frame = kernel_frame();
        frame.cs = 0x9928;
        assert!(implausible(&frame).is_some());
    }

    #[test]
    fn a_ring_zero_return_through_a_foreign_stack_selector_is_rejected() {
        let mut frame = kernel_frame();
        frame.ss = 0x28;
        assert!(implausible(&frame).is_some());
        // Zero is allowed on purpose: the processor writes it for a ring-0
        // interrupt that did not change stacks, and rejecting it would fire on
        // ordinary kernel faults.
        frame.ss = 0;
        assert_eq!(implausible(&frame), None);
    }

    #[test]
    fn a_non_canonical_rip_or_rsp_is_rejected() {
        let mut frame = kernel_frame();
        frame.rip = 0x0001_0000_0000_0000;
        assert!(implausible(&frame).is_some());

        let mut frame = kernel_frame();
        frame.rsp = 0xdead_0000_0000_0000;
        assert!(implausible(&frame).is_some());
    }

    #[test]
    fn a_frame_iretq_would_take_a_v8086_or_task_return_through_is_rejected() {
        // The open `#GP` at `iretq` names a selector in no descriptor table
        // while `cs` and `ss` are ordinary. `VM` is how `iretq` comes to load
        // selectors that are not those two.
        let mut vm = kernel_frame();
        vm.rflags |= 1 << 17;
        assert!(implausible(&vm).is_some());

        let mut nt = kernel_frame();
        nt.rflags |= 1 << 14;
        assert!(implausible(&nt).is_some());

        // And the flags this machine really does set stay acceptable:
        // interrupts enabled, plus the always-one bit.
        let mut ordinary = kernel_frame();
        ordinary.rflags = 0x202;
        assert_eq!(implausible(&ordinary), None);
    }

    #[test]
    fn flags_no_processor_writes_are_rejected() {
        // Bit 1 reads as one on every x86 since the 8086, so a frame without
        // it was not written by the processor.
        let mut frame = kernel_frame();
        frame.rflags = 0x200;
        assert!(implausible(&frame).is_some());
    }

    /// Each rejection names a *different* field, so a witness line says which
    /// one rather than only that something was wrong.
    #[test]
    fn each_rejection_names_the_field_it_found() {
        let mut cs = kernel_frame();
        cs.cs = 0x9928;
        let mut ss = kernel_frame();
        ss.ss = 0x28;
        let mut rip = kernel_frame();
        rip.rip = 1 << 63;
        let mut rflags = kernel_frame();
        rflags.rflags = 0;

        let reasons = [
            implausible(&cs).unwrap(),
            implausible(&ss).unwrap(),
            implausible(&rip).unwrap(),
            implausible(&rflags).unwrap(),
        ];
        for (index, reason) in reasons.iter().enumerate() {
            for other in &reasons[index + 1..] {
                assert_ne!(reason, other, "two fields share one message");
            }
        }
    }
}
