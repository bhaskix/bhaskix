// SPDX-License-Identifier: Apache-2.0
//! Handing a hosted program's fault to its personality.
//!
//! [RFC 0032](../../docs/rfc/0032-a-supervisor-interface.md) step 6. A Linux
//! program's fault is not necessarily its end: Go installs a `SIGSEGV`
//! handler and turns a null dereference into a recovered panic, which is why
//! [RFC 0005](../../docs/rfc/0005-linux-abi-compatibility.md) built signal
//! delivery before threading. Deciding what a fault *means* is the
//! personality's business, and the personality is leaving the nucleus — so
//! the fault has to leave with it.
//!
//! # Why this is a module and not three lines in the trap handler
//!
//! **A fault cannot simply become an IPC call**, and the reason took reading
//! rather than guessing. Two facts decide the design, and both are recorded
//! in the code they come from:
//!
//! - The IDT uses **interrupt gates**, so a fault arrives with `IF` clear
//!   (`arch/x86_64/src/idt.rs`). Blocking with interrupts masked is the exact
//!   hazard that once made this kernel hang with every CPU deaf — a system
//!   call spun with the mask still up and no tick, wake or shootdown could
//!   reach it. So interrupts are enabled here, deliberately and with the same
//!   argument the syscall entry makes for doing it there.
//! - The page fault is **deliberately not on an IST**
//!   (`arch/x86_64/src/idt.rs`: *"IST stacks do not nest — a second page
//!   fault while handling the first would overwrite the first one's frame"*).
//!   It runs on the faulting thread's own kernel stack, which is what makes
//!   blocking sound at all: the frame is the thread's, so switching away
//!   preserves it exactly as a blocked system call's is preserved.
//!
//! Enabling interrupts is safe here for the reason `trap.rs` already gives
//! for taking locks: the faulting thread was executing *user* code, so it
//! held no kernel lock, and nothing this interrupts can be waiting on it.
//!
//! # The exchange
//!
//! A page shared with the adapter, in slots. The kernel writes the faulting
//! register file and the fault address into a slot it claimed, calls the
//! adapter, and the adapter answers *resume* — having edited the registers in
//! place — or *end this program*. One slot per fault in flight, claimed
//! atomically, because two CPUs can fault at once and a single buffer would
//! give one of them the other's registers.

use core::sync::atomic::{AtomicU64, Ordering};

/// The method number a fault arrives under.
///
/// Not a Linux system-call number and unreachable as one: every number in
/// that table is small, and a hosted program cannot choose this because it
/// never chooses the method at all — the kernel does.
pub const FAULT_METHOD: u64 = u64::MAX;

/// The method a *retry with the register frame* arrives under.
///
/// **The kernel does not know which calls need more than four arguments**,
/// and this is how it avoids having to. A message carries four words; some
/// Linux calls take five or six. Rather than teach the nucleus which ones —
/// which would be Linux knowledge arriving through the back door — the
/// adapter answers [`reply::NEED_FRAME`], the kernel writes the caller's
/// whole register frame into a slot and asks again under this method, and
/// only the calls that need it pay for it.
pub const FRAME_METHOD: u64 = u64::MAX - 2;

/// What the adapter's reply *means*, in the reply's method word.
pub mod reply {
    /// The first word is the answer, for `rax`.
    pub const VALUE: u64 = 0;
    /// The adapter needs the caller's register frame; ask again with one.
    pub const NEED_FRAME: u64 = 2;
    /// Resume the caller from the registers in the slot the first word
    /// names, rather than from a value — `rt_sigreturn`.
    pub const RESTORE: u64 = 3;
    /// Give up the caller's slice, then answer it the first word.
    ///
    /// A scheduling act on the *caller*, which only the kernel can perform —
    /// but *whether* to perform it is the dialect's business, and this is how
    /// the dialect says so.
    pub const YIELD: u64 = 4;
    /// End the calling thread. It does not return.
    pub const END_THREAD: u64 = 5;
    /// End the caller's whole domain. It does not return.
    ///
    /// A Linux thread group's exit is every thread of it, and a hosted
    /// process is a domain — so `exit_group` is this, and the exactness Go
    /// depends on is the kernel's ordinary teardown rather than anything the
    /// personality has to reproduce.
    pub const END_DOMAIN: u64 = 6;
    /// Park the calling thread on a notification the *adapter* holds, and
    /// answer zero when it is signalled.
    ///
    /// **The reply that blocks, and the reason it has to be a reply.** A
    /// server may hold exactly one outstanding reply — `Thread::reply_to` is
    /// one `Option` — so an adapter that simply did not answer a sleeper
    /// would answer nobody else either. Instead it always replies, and when
    /// the answer is "sleep" the reply *is* the instruction to sleep: policy
    /// (which word, which waiters, how many to wake) stays in ring 3, and
    /// parking a thread stays in the kernel, which is the only thing that can
    /// do it.
    ///
    /// The word beside this one is a capability index **in the adapter's own
    /// CSpace**, not the caller's: a hosted process holds no capabilities and
    /// can name none, which is RFC 0031's interface I3.
    ///
    /// The compare-and-block race is closed by an existing decision rather
    /// than by anything here: [`crate::notify::signal`] publishes its bits
    /// before waking, so a wake that arrives between the adapter's reply and
    /// this park leaves the bit set and the park returns at once.
    pub const BLOCK_ON: u64 = 7;
    /// Park the calling thread, and when it wakes **ask the same question
    /// again** rather than answering it.
    ///
    /// [RFC 0033](../../docs/rfc/0033-what-a-hosted-process-is.md) step 7. The
    /// difference from [`BLOCK_ON`] is what the caller gets on waking: a
    /// `futex` is answered zero, which is what Linux's futex returns, but a
    /// `read` answered zero has been told *end of file* — and a shell pipeline
    /// whose reader is told that at its producer's first pause exits. So a
    /// blocking read parks with this and the adapter answers the second time
    /// with the bytes that woke it.
    pub const BLOCK_ON_RETRY: u64 = 8;
}

/// What the adapter answered.
pub mod verdict {
    /// End the program. The fault was fatal, or nothing wanted it.
    pub const END: u64 = 0;
    /// Resume, with the registers the adapter left in the slot.
    pub const RESUME: u64 = 1;
}

/// Faults in flight at once, and therefore slots in the page.
///
/// Eight, which is one per CPU twice over. A fault that finds none free is
/// answered as though the adapter refused it — the program ends — because the
/// alternative is a thread waiting for a slot while holding nothing, which is
/// a hang with no diagnosis.
pub const SLOTS: usize = 8;

/// Bytes each slot occupies. Two words of fault description and nineteen of
/// register file, rounded up to something a reader can find in a dump.
pub const SLOT_BYTES: u64 = 512;

/// How many words the register image occupies, and the order they are in.
///
/// **The order is this file's, not the trap frame's**, and it is written down
/// because the adapter reads it from the other side of a page: a translator
/// that had them in a different order would resume a program with its stack
/// pointer in `rax`, and nothing would say so until it faulted somewhere
/// unrelated.
pub const REGISTERS: usize = 19;

/// Where the slot's words live.
pub mod word {
    /// The address the fault was on — `CR2`.
    pub const ADDRESS: usize = 0;
    /// The architectural error code.
    pub const ERROR: usize = 1;
    /// The first register word; [`super::REGISTERS`] of them follow.
    pub const FIRST_REGISTER: usize = 2;
}

/// Which slots are taken. One bit each, claimed with a compare-and-swap.
static CLAIMED: AtomicU64 = AtomicU64::new(0);

/// The object the slots live in, or `u64::MAX` before the adapter exists.
pub static PAGE: AtomicU64 = AtomicU64::new(u64::MAX);

/// Faults handed over, resumed, and ended.
pub static HANDED: AtomicU64 = AtomicU64::new(0);
/// Faults the adapter asked to resume.
pub static RESUMED: AtomicU64 = AtomicU64::new(0);
/// Faults that found no free slot.
pub static CROWDED: AtomicU64 = AtomicU64::new(0);

/// Claims a slot, or `None` when all are in flight.
fn claim() -> Option<usize> {
    loop {
        let taken = CLAIMED.load(Ordering::Relaxed);
        let free = (0..SLOTS).find(|slot| taken & (1 << slot) == 0)?;
        let wanted = taken | (1 << free);
        if CLAIMED
            .compare_exchange_weak(taken, wanted, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return Some(free);
        }
    }
}

/// Gives a slot back.
fn release(slot: usize) {
    CLAIMED.fetch_and(!(1 << slot), Ordering::AcqRel);
}

/// The register file, in the order both sides agree on.
fn image(frame: &bhaskix_arch::trap::TrapFrame) -> [u64; REGISTERS] {
    [
        frame.rax,
        frame.rbx,
        frame.rcx,
        frame.rdx,
        frame.rsi,
        frame.rdi,
        frame.rbp,
        frame.r8,
        frame.r9,
        frame.r10,
        frame.r11,
        frame.r12,
        frame.r13,
        frame.r14,
        frame.r15,
        frame.rip,
        frame.rflags,
        frame.rsp,
        frame.error_code,
    ]
}

/// Puts an edited register file back into the frame the CPU will resume from.
///
/// **`cs`, `ss` and the error code are not restored from the image**, and
/// that is the containment: an adapter that could write those could resume a
/// hosted program in ring 0. It may move the program's instruction pointer
/// and its stack — which is what a signal handler is — and nothing else.
fn restore(frame: &mut bhaskix_arch::trap::TrapFrame, image: &[u64; REGISTERS]) {
    frame.rax = image[0];
    frame.rbx = image[1];
    frame.rcx = image[2];
    frame.rdx = image[3];
    frame.rsi = image[4];
    frame.rdi = image[5];
    frame.rbp = image[6];
    frame.r8 = image[7];
    frame.r9 = image[8];
    frame.r10 = image[9];
    frame.r11 = image[10];
    frame.r12 = image[11];
    frame.r13 = image[12];
    frame.r14 = image[13];
    frame.r15 = image[14];
    frame.rip = image[15];
    // The flags a hosted program may set, and no others. Letting it choose
    // `IF` would let a program disable interrupts; letting it choose `IOPL`
    // would let it reach the ports.
    frame.rflags = (frame.rflags & !USER_FLAGS) | (image[16] & USER_FLAGS);
    frame.rsp = image[17];
}

/// The `rflags` bits a hosted program is allowed to choose when it resumes.
///
/// Carry, parity, adjust, zero, sign, direction and overflow. Not `IF`, not
/// `IOPL`, not `TF`, not `NT` — a signal handler edits arithmetic state and
/// its own control flow, and anything else it could set would be authority it
/// was never given.
const USER_FLAGS: u64 = 0x0000_0CD5;

/// Hands `frame`'s fault to the personality, and says whether to resume.
///
/// `false` means the program should end — because the adapter said so,
/// because there is no adapter, or because no slot was free.
///
/// # Safety of the blocking call
///
/// See this module's own documentation: interrupts are enabled first, and
/// that is sound because a user-mode fault holds no kernel lock and runs on
/// the faulting thread's own stack.
pub fn hand_over(frame: &mut bhaskix_arch::trap::TrapFrame, address: u64) -> bool {
    let page = PAGE.load(Ordering::Acquire);
    if page == u64::MAX {
        return false;
    }
    let Some(domain) = crate::sched::current_domain() else {
        return false;
    };
    let Some(slot) = claim() else {
        CROWDED.fetch_add(1, Ordering::Relaxed);
        return false;
    };

    let object = crate::shared::MemoryId::from_u64(page);
    let at = slot as u64 * SLOT_BYTES;
    let registers = image(frame);
    let mut bytes = [0u8; (word::FIRST_REGISTER + REGISTERS) * 8];
    bytes[..8].copy_from_slice(&address.to_le_bytes());
    bytes[8..16].copy_from_slice(&frame.error_code.to_le_bytes());
    for (index, value) in registers.iter().enumerate() {
        let start = (word::FIRST_REGISTER + index) * 8;
        bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }
    let mut written = 0usize;
    let filled = crate::shared::fill_from(
        object,
        at as usize,
        bytes.len(),
        &mut |slot: &mut [u8]| {
            let take = slot.len().min(bytes.len() - written);
            slot[..take].copy_from_slice(&bytes[written..written + take]);
            written += take;
            take
        },
    );
    if filled.is_none() {
        release(slot);
        return false;
    }

    HANDED.fetch_add(1, Ordering::Relaxed);
    // **Interrupts on, before anything blocks.** See the module documentation:
    // the fault arrived through an interrupt gate with `IF` clear, and a
    // thread that blocks with the mask still up leaves its CPU deaf to the
    // tick, the wake and the shootdown that would let it be resumed.
    //
    // SAFETY: the faulting thread was executing user code, so it holds no
    // kernel lock; the IDT has been installed since bring-up; and this runs on
    // the thread's own kernel stack, not an IST, so being switched away
    // preserves the frame exactly as a blocked system call's is preserved.
    unsafe { bhaskix_arch::cpu::enable_interrupts() };

    let answered = crate::syscall::ask_adapter(
        u64::from(domain.as_u32()),
        FAULT_METHOD,
        [slot as u64, address, frame.error_code, 0],
    );

    let resume = match answered {
        Some(verdict::RESUME) => {
            let mut back = [0u8; REGISTERS * 8];
            let mut read = 0usize;
            let drained = crate::shared::drain_into(
                object,
                (at as usize) + (word::FIRST_REGISTER * 8) + back.len(),
                &mut |chunk: &[u8]| {
                    // `drain_into` starts at the object's beginning, so the
                    // bytes before this slot's register words are walked past
                    // rather than copied.
                    let skip = ((at as usize) + word::FIRST_REGISTER * 8).saturating_sub(read);
                    let start = skip.min(chunk.len());
                    let take = (chunk.len() - start).min(back.len());
                    if take > 0 {
                        back[..take].copy_from_slice(&chunk[start..start + take]);
                    }
                    read += chunk.len();
                    chunk.len()
                },
            );
            if drained.is_some() {
                let mut edited = [0u64; REGISTERS];
                for (index, value) in edited.iter_mut().enumerate() {
                    let mut eight = [0u8; 8];
                    eight.copy_from_slice(&back[index * 8..index * 8 + 8]);
                    *value = u64::from_le_bytes(eight);
                }
                restore(frame, &edited);
                RESUMED.fetch_add(1, Ordering::Relaxed);
                true
            } else {
                false
            }
        }
        _ => false,
    };
    release(slot);
    resume
}

/// Writes a *system call's* register frame into a slot, for a call whose
/// arguments do not fit in a message.
///
/// **The image has holes, and they are the truth rather than an omission.**
/// A system call arrives through the `SYSCALL` entry stub, which saves what
/// the ABI says is caller-saved and nothing else — so `rbx`, `rbp` and
/// `r12`–`r15` are not in the frame and read as zero here. Every Linux call
/// that needs a fifth or sixth argument takes it in `r10`, `r8` or `r9`,
/// which *are* saved; a call that wanted a callee-saved register would be a
/// call this cannot serve, and the zero says so rather than inventing one.
///
/// Answers the slot, or `None` when none is free.
pub fn stage_frame(frame: &bhaskix_arch::syscall::SyscallFrame) -> Option<usize> {
    let page = PAGE.load(Ordering::Acquire);
    if page == u64::MAX {
        return None;
    }
    let slot = claim()?;
    let mut image = [0u64; REGISTERS];
    image[0] = frame.kind; //        rax
    image[2] = 0; //                 rcx -- destroyed by SYSCALL itself
    image[3] = frame.arg0; //        rdx
    image[4] = frame.method; //      rsi
    image[5] = frame.capability; //  rdi
    image[7] = frame.arg2; //        r8
    image[8] = frame.arg3; //        r9
    image[9] = frame.arg1; //        r10
    image[15] = frame.rip;
    image[16] = frame.rflags;
    image[17] = frame.user_rsp;

    let object = crate::shared::MemoryId::from_u64(page);
    let at = slot as u64 * SLOT_BYTES;
    let mut bytes = [0u8; (word::FIRST_REGISTER + REGISTERS) * 8];
    for (index, value) in image.iter().enumerate() {
        let start = (word::FIRST_REGISTER + index) * 8;
        bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }
    let mut written = 0usize;
    let filled = crate::shared::fill_from(
        object,
        at as usize,
        bytes.len(),
        &mut |into: &mut [u8]| {
            let take = into.len().min(bytes.len() - written);
            into[..take].copy_from_slice(&bytes[written..written + take]);
            written += take;
            take
        },
    );
    if filled.is_none() {
        release(slot);
        return None;
    }
    Some(slot)
}

/// Reads a slot's register image back, for a caller that is being resumed.
pub fn take_frame(slot: usize) -> Option<[u64; REGISTERS]> {
    let page = PAGE.load(Ordering::Acquire);
    if page == u64::MAX || slot >= SLOTS {
        return None;
    }
    let object = crate::shared::MemoryId::from_u64(page);
    let at = slot as u64 * SLOT_BYTES;
    let mut back = [0u8; REGISTERS * 8];
    let mut read = 0usize;
    let drained = crate::shared::drain_into(
        object,
        (at as usize) + (word::FIRST_REGISTER * 8) + back.len(),
        &mut |chunk: &[u8]| {
            let skip = ((at as usize) + word::FIRST_REGISTER * 8).saturating_sub(read);
            let start = skip.min(chunk.len());
            let take = (chunk.len() - start).min(back.len());
            if take > 0 {
                back[..take].copy_from_slice(&chunk[start..start + take]);
            }
            read += chunk.len();
            chunk.len()
        },
    )?;
    let _ = drained;
    let mut image = [0u64; REGISTERS];
    for (index, value) in image.iter_mut().enumerate() {
        let mut eight = [0u8; 8];
        eight.copy_from_slice(&back[index * 8..index * 8 + 8]);
        *value = u64::from_le_bytes(eight);
    }
    Some(image)
}

/// Gives a staged slot back.
pub fn give_back(slot: usize) {
    release(slot);
}

/// What the fault path has done: handed over, resumed, and crowded out.
#[must_use]
pub fn statistics() -> (u64, u64, u64) {
    (
        HANDED.load(Ordering::Relaxed),
        RESUMED.load(Ordering::Relaxed),
        CROWDED.load(Ordering::Relaxed),
    )
}
