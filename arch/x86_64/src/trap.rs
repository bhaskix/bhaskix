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

    let user = frame.cs & 3 != 0;
    if !user && frame.cs != KERNEL_CS {
        return Some("cs is neither the kernel's nor a user selector");
    }
    if !user && frame.ss != KERNEL_SS && frame.ss != 0 {
        return Some("ss is not the kernel's, returning to ring 0");
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
    None
}

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
