// SPDX-License-Identifier: Apache-2.0
//! The Linux personality, in ring 3.
//!
//! [RFC 0005](../../../docs/rfc/0005-linux-abi-compatibility.md) §"Where it
//! lives" has required since it was drafted that this run in **a service
//! domain, not the nucleus**, and gives the reason: it is a parser for some
//! three hundred system calls whose pointer and length arguments come from the
//! process being contained, which makes it the largest single piece of attack
//! surface this project will ever have. In a domain, a bug in it costs that
//! domain's authority. In the nucleus, it is a kernel bug.
//!
//! Steps 2 to 8 built it in the nucleus anyway. This program is where that is
//! corrected, and it is corrected **one call at a time** rather than in one
//! move: every call the kernel still answers keeps working exactly as it did,
//! and the boundary report says how many are left.
//!
//! # How a call gets here
//!
//! A hosted thread traps. The kernel decides — from one relaxed load — that
//! the domain speaks a foreign dialect, and tries the handlers it still has.
//! **What none of them answers is sent here**, as an ordinary IPC call made by
//! the hosted thread itself, which blocks until this program replies. So the
//! kernel needs no list of what this program handles: as calls move out of the
//! kernel they simply stop being answered there and start arriving here.
//!
//! The Linux call number arrives as the message's `method`, its first four
//! arguments as the message's four words, and the *badge* says which hosted
//! domain is asking — stamped by the kernel from the capability actually used,
//! never by anything the caller supplied.
//!
//! # What it holds
//!
//! A console to report through, and the endpoint it serves on. That is all,
//! and it is the point: this program has no filesystem, no device, and no way
//! to obtain either. When it grows a hosted process's files and sockets it
//! will hold *those* capabilities, and a bug in it will reach exactly them.

#![no_std]
#![no_main]

use bhaskix_abi::{limits, method, status, syscall};
use bhaskix_personality::call::{Answer, Dialect, PersonalityCall};
use bhaskix_personality::file::Kind;
use bhaskix_personality::memory;
use bhaskix_personality::pipe::Pipe;
use bhaskix_personality::proc::File as ProcFile;
use bhaskix_personality::process::layout;
use bhaskix_personality::process::{Exit, Process, Processes, Region};
use bhaskix_personality::report;
use bhaskix_personality::signal::{self, Dispositions, Registers, number::SIGSEGV};
use bhaskix_personality::thread::{self, ClonePlan};

/// One page to report through, written by this program and read by the
/// kernel. Not a console: this program is started before the console service
/// exists, and every other service that must say something that early says it
/// the same way.
const REPORT: u64 = bhaskix_abi::adapter::REPORT as u64;
/// Where the report page is mapped in this program's own space.
const REPORT_AT: u64 = 0x0000_0000_1E00_0000;

/// The endpoint hosted domains' calls arrive on, and the first of the two
/// capabilities
///
/// Not even a console. It is started before the console service exists —
/// its first callers are the Linux self-tests, which run long before
/// `user_shell` — and rather than reorder the boot to give an adapter
/// somewhere to print, it holds nothing and the kernel reports on its behalf
/// from the counters it keeps. That is better evidence anyway: what matters is
/// that a hosted program got the right answer, not that this program said so.
const ENDPOINT: u64 = bhaskix_abi::adapter::ENDPOINT as u64;

/// The machine's console, **write-only** — RFC 0032 step 10.
///
/// Granted at boot with `Rights::WRITE` and nothing else, so a hosted
/// program's `write` reaches a console and this program cannot take a byte
/// somebody typed at the shell. It is the whole of what this program may do
/// to the machine outside the domains it serves.
///
/// The paragraph above [`ENDPOINT`] said "not even a console" and was true
/// until this step; what made it stop being true is that `write` was the last
/// Linux number the *nucleus* was printing on a hosted program's behalf.
const CONSOLE: u64 = bhaskix_abi::adapter::CONSOLE as u64;

/// The first of the notifications a hosted `futex(WAIT)` parks on, and how
/// many there are — RFC 0032 step 10.
///
/// Granted at boot with `Rights::WRITE` and nothing else: this program may
/// **wake** a sleeper and may not become one. A single-threaded server that
/// could block on a notification could stop answering, and nothing a futex
/// needs asks it to.
///
/// One notification per parked waiter rather than one per futex word. That is
/// what makes `futex(WAKE, n)` exact — waking *n* means signalling *n* of
/// them — where a notification shared by every sleeper on one word could only
/// wake all or none.
const WAKE_SLOT: u64 = bhaskix_abi::adapter::WAKES as u64;
/// The console's own notification, for a hosted `read` that must wait.
///
/// Granted at boot beside the futex pool and **`READ` where those are `WRITE`**
/// — RFC 0054. This program may park a hosted thread on it and may not signal
/// it, which is the difference between waiting for a keystroke and inventing
/// one. Taking the byte is still `POLL_INPUT` on the domain, which the nucleus
/// refuses without the input grant.
const INPUT_WAKE: u64 = bhaskix_abi::adapter::INPUT_WAKE as u64;
const WAKES: usize = bhaskix_abi::adapter::WAKE_COUNT;

/// One hosted thread asleep in a futex: whose memory, which word, and which
/// notification it is parked on.
#[derive(Clone, Copy)]
struct Sleeper {
    /// Zero means the slot is free. Domains are numbered from zero, so the
    /// hosted domain is kept as `domain + 1` — the same offset the badge
    /// carries, and for the same reason.
    domain: u32,
    address: u64,
    /// The order this sleeper arrived in, so a `WAKE` of one wakes the
    /// *oldest* — Linux does not promise an order, but a queue that always
    /// woke the newest can starve a waiter for ever under contention.
    arrived: u64,
}

/// There is nothing to unwind and nowhere useful to print to.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. An adapter that panicked
    // has no correct answer to give, and stopping is visible to the kernel
    // where a wrong answer would not be.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Issues one system call, returning the status and the four reply words.
fn call(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> Reply {
    let status: u64;
    let badge: u64;
    let answered: u64;
    let (mut a0, mut a1, mut a2, mut a3) = (args[0], args[1], args[2], args[3]);
    // SAFETY: RFC 0008's system-call convention. Nothing is dereferenced on
    // this side: every argument is a number or a slot index, and the kernel
    // reads them from registers. Every argument register is declared an output
    // too, because the kernel writes the whole frame back on the way out;
    // `rcx` and `r11` are destroyed by the instruction itself.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            inlateout("rdi") capability => badge,
            inlateout("rsi") method => answered,
            inlateout("rdx") a0,
            inlateout("r10") a1,
            inlateout("r8") a2,
            inlateout("r9") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    Reply {
        status,
        badge,
        method: answered,
        args: [a0, a1, a2, a3],
    }
}

/// What a system call answered.
///
/// A struct rather than a tuple because `RECV` returns four different things
/// and three of them are `u64`: a receive loop that mixed up the badge and the
/// method would compile, and would answer the wrong question about the wrong
/// caller.
struct Reply {
    /// The status word.
    status: u64,
    /// For `RECV`, who is calling — stamped by the kernel from the capability
    /// actually used, never by anything the caller supplied.
    badge: u64,
    /// For `RECV`, which operation the caller asked for. This is where the
    /// kernel puts a foreign call's **Linux syscall number**.
    method: u64,
    /// The four message words.
    args: [u64; 4],
}

/// Reports the first few `mmap` requests, through the kernel's own report
/// channel rather than a console this program does not hold.
///
/// **The RFC's instruction restated: trace the binary, do not reason about
/// it.** Moving `mmap` here changed what the Go corpus does — 212 calls
/// became 401, and its complaint changed from "cannot allocate memory" to
/// "out of memory" — and no amount of reading the diff would have said why.
fn trace(addr: u64, length: u64, pages: u64, protection: u64, fixed: bool, hinted: bool) {
    let seen = TRACED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if seen >= 8 {
        return;
    }
    let at = REPORT_AT + seen * 32;
    // SAFETY: `REPORT_AT` is where `ATTACH` mapped a writable page of this
    // program's own object at start-up, and `seen` is bounded to eight
    // records of four words, which is 256 bytes inside a 4,096-byte page.
    unsafe {
        core::ptr::write_volatile(at as *mut u64, addr);
        core::ptr::write_volatile((at + 8) as *mut u64, length);
        core::ptr::write_volatile((at + 16) as *mut u64, pages);
        core::ptr::write_volatile(
            (at + 24) as *mut u64,
            protection | (u64::from(fixed) << 8) | (u64::from(hinted) << 9),
        );
    }
}

/// How many `mmap` requests have been traced.
static TRACED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// What an `execve` did, for the kernel to read out of the same page.
///
/// **Three numbers and a witness** — RFC 0033 step 5. The pid, the domain it
/// was in, and the domain it is in now. The kernel prints them and the boot
/// test compares the pid against what the exec'd *program* says its pid is,
/// which it learns by asking `getpid` in the new domain: two witnesses that
/// have to agree, one of them this program's own claim and the other a hosted
/// program's own observation.
///
/// A fixed record rather than a ring: there is one exec in this machine's
/// self-tests, and a second would overwrite the first loudly rather than
/// scroll it away quietly.
///
/// **Past the scratch area, and the first version was not.** It sat at
/// `REPORT_AT + 8 * 32`, which is exactly where `copy_in` and `copy_out` stage
/// their bytes — so every copy after the exec overwrote it, and the kernel
/// printed the tail of a path as a pid. The scratch area's own bound is what
/// this is placed after, so moving one moves the other.
const EXEC_RECORD_AT: u64 = REPORT_AT + report::EXEC_AT as u64;

/// Where the file record sits, three words past the exec record.
const FILE_RECORD_AT: u64 = REPORT_AT + report::FILE_AT as u64;

/// Records what the last `open` and `read` did, for the kernel's report.
///
/// **The same evidence shape as the exec record, and for the same reason**:
/// what a hosted program's file calls did is this program's to say, and a boot
/// where the bytes did not appear needs to distinguish "the open was refused"
/// from "the read found nothing" from "the write went somewhere else". The
/// first version of step 6 had no such line and cost a boot working out which
/// of the three it was.
fn trace_file(opened: i64, read: i64, size: u64) {
    // SAFETY: inside the page `ATTACH` mapped from this program's own object,
    // past the mmap records, the scratch area and the exec record.
    unsafe {
        core::ptr::write_volatile(FILE_RECORD_AT as *mut u64, opened as u64);
        core::ptr::write_volatile((FILE_RECORD_AT + 8) as *mut u64, read as u64);
        core::ptr::write_volatile((FILE_RECORD_AT + 16) as *mut u64, size);
    }
}

/// Where the fork record sits, three words past the file record.
const FORK_RECORD_AT: u64 = REPORT_AT + report::FORK_AT as u64;

/// Records what a `fork` cost: the child's pid and the bytes copied.
///
/// **The number step 8 exists to produce.** RFC 0033 writes stage two — a
/// copy-on-write `COPY_SPACE` in the nucleus — as something to build only if a
/// measurement says so, and this is the measurement's own half of it: how much
/// was moved, by a fork that moved all of it.
fn trace_fork(pid: u32, copied: u64) {
    // SAFETY: inside the page `ATTACH` mapped from this program's own object,
    // past the mmap records, the scratch area, the exec record and the file
    // record.
    unsafe {
        core::ptr::write_volatile(FORK_RECORD_AT as *mut u64, u64::from(pid));
        core::ptr::write_volatile((FORK_RECORD_AT + 8) as *mut u64, copied);
    }
}

/// Where the wait record sits, two words past the fork record.
const WAIT_RECORD_AT: u64 = REPORT_AT + report::WAIT_AT as u64;

/// Where the supervised-copy measurement lands: cycles, then bytes.
///
/// [RFC 0036](../../docs/rfc/0036-a-relocatable-program-in-ring-3.md) step 2.
/// The RFC's question 1 — who chooses a program's load address — turns on
/// whether this adapter could load an image itself, and that turns on what a
/// page costs through `COPY_OUT` against the kernel's own `copy_nonoverlapping`
/// through the direct map. **The RFC declined to choose a design before this
/// number existed**, so here it is measured rather than guessed.
const COPY_RECORD_AT: u64 = REPORT_AT + report::COPY_AT as u64;

/// Where the cost of giving a lent page back lands: cold cycles, then warm.
///
/// [RFC 0044](../../docs/rfc/0044-revocation-that-reaches-the-mapping.md)
/// made `dir::RELEASE` do more work — the revocation inside it now takes the
/// page out of this program's address space and gives the address back — and
/// shipped **without a number**, having claimed in its own performance section
/// that the boot report already priced this pair. It did not. This is that
/// number, taken where the cost is actually paid.
///
/// **What is inside the span, said plainly, because it is more than the
/// revocation:** one `CALL` to `bin/fsd`, which mounts, finds the frame the
/// block is in, invokes `REVOKE` on its lending — which is the part RFC 0044
/// changed — unpins the frame, and replies. A reader comparing this against
/// the revocation alone would be comparing against something this program
/// cannot measure from here.
///
/// Cold and warm, for the reason [`COPY_RECORD_AT`] gives at length: a single
/// figure would be the first execution of the path and not the cost of using
/// it. **And taking a warm one is only possible because of the change being
/// measured** — before it, a second read on the machine was refused.
const LEND_RECORD_AT: u64 = REPORT_AT + report::LEND_AT as u64;

/// Records what a `wait4` answered: the child collected and its status word.
///
/// Written on every outcome, including the refusals, because a boot where
/// nothing was printed has to say *which* of four answers the parent got --
/// the lesson `open` learned twice and `read` once.
fn trace_wait(collected: i64, status: u64) {
    // SAFETY: inside the page `ATTACH` mapped from this program's own object,
    // past every other record.
    unsafe {
        core::ptr::write_volatile(WAIT_RECORD_AT as *mut u64, collected as u64);
        core::ptr::write_volatile((WAIT_RECORD_AT + 8) as *mut u64, status);
    }
}

/// Records an exec for the kernel's report.
fn trace_exec(pid: u32, from: u32, to: u32) {
    // SAFETY: inside the page `ATTACH` mapped from this program's own object,
    // at an offset past the eight mmap records and well inside 4,096 bytes.
    unsafe {
        core::ptr::write_volatile(EXEC_RECORD_AT as *mut u64, u64::from(pid));
        core::ptr::write_volatile((EXEC_RECORD_AT + 8) as *mut u64, u64::from(from));
        core::ptr::write_volatile((EXEC_RECORD_AT + 16) as *mut u64, u64::from(to));
    }
}

/// Turns a fault into a signal, or says the program should end.
///
/// **This is the decision RFC 0005 built signal delivery for**: Go installs a
/// `SIGSEGV` handler and turns a null dereference into a recovered panic, and
/// until 2026-08-20 the nucleus made this call. Everything it needs is here
/// now — the dispositions this program keeps, the frame layout
/// `bhaskix_personality::signal` has always owned, and two capability
/// invocations to reach the faulting process's memory and registers.
fn deliver(domain: u32, slot: u64, address: u64) -> u64 {
    let Some(handler) = dispositions_of(domain).handler(SIGSEGV) else {
        // Nothing wanted it. Ending is the honest answer, and the kernel says
        // so in one line rather than narrating an exception the machine did
        // not suffer.
        //
        // **And the status is recorded, because a parent may be waiting** —
        // RFC 0033 step 9. A process killed by a signal is not one that
        // exited: `wait` encodes the two differently, and a shell prints
        // "Segmentation fault" from exactly that difference.
        note_exit(
            domain,
            Exit::Signalled {
                signal: SIGSEGV as u8,
                core: false,
            },
        );
        return FAULT_END;
    };

    let mut image = [0u64; FAULT_REGISTERS];
    if !read_slot(slot, &mut image) {
        note_exit(
            domain,
            Exit::Signalled {
                signal: SIGSEGV as u8,
                core: false,
            },
        );
        return FAULT_END;
    }
    let registers = Registers {
        rax: image[0],
        rbx: image[1],
        rcx: image[2],
        rdx: image[3],
        rsi: image[4],
        rdi: image[5],
        rbp: image[6],
        r8: image[7],
        r9: image[8],
        r10: image[9],
        r11: image[10],
        r12: image[11],
        r13: image[12],
        r14: image[13],
        r15: image[14],
        rip: image[15],
        eflags: image[16],
        rsp: image[17],
        cr2: address,
    };

    // Below the delivery stack's top, sixteen-aligned as the ABI requires --
    // and the return address then leaves `rsp % 16 == 8` at the handler's
    // first instruction, exactly as a `call` would.
    let top = dispositions_of(domain).delivery_stack(SIGSEGV, registers.rsp);
    let frame_at = (top - FRAME_BYTES as u64) & !15;

    let mut frame = [0u8; FRAME_BYTES];
    frame[..8].copy_from_slice(&handler.restorer.to_le_bytes());
    frame[8 + SIGINFO_ADDR..8 + SIGINFO_ADDR + 8].copy_from_slice(&address.to_le_bytes());
    if registers
        .write_sigcontext(&mut frame[8 + SIGINFO_BYTES + UCONTEXT_MCONTEXT..])
        .is_err()
    {
        return FAULT_END;
    }
    // Into the hosted process's own stack. A process whose stack is unmapped
    // gets an ending rather than a delivery, which is what the kernel did.
    if !copy_out(domain, frame_at, &frame) {
        return FAULT_END;
    }

    // The handler's three arguments and the redirect, written back into the
    // slot the kernel will resume from. It may move this program's
    // instruction pointer and stack and nothing else -- the kernel refuses
    // `cs`, `ss` and the interrupt flag whatever is written here.
    let mut edited = image;
    edited[5] = SIGSEGV;
    edited[4] = frame_at + 8;
    edited[3] = frame_at + 8 + SIGINFO_BYTES as u64;
    edited[15] = handler.entry;
    edited[17] = frame_at;
    if !write_slot(slot, &edited) {
        return FAULT_END;
    }
    FAULT_RESUME
}

/// Answers a call whose arguments did not fit in a message.
///
/// The register file is in `slot`, in the kernel's order — which is the one
/// place both sides must agree and the reason that order is written down on
/// each of them.
fn answer_with_frame(domain: u32, slot: u64, number: u64) -> (u64, Answer) {
    let mut image = [0u64; FAULT_REGISTERS];
    if !read_slot(slot, &mut image) {
        return (REPLY_VALUE, Answer::error(memory::errno::EINVAL));
    }
    // Linux's argument registers, out of the frame: rdi, rsi, rdx, r10, r8.
    let (rdi, rsi, rdx, r10, r8, r9) = (image[5], image[4], image[3], image[9], image[7], image[8]);

    match number {
        // Six arguments, which is two more than a message carries.
        SENDTO | RECVFROM => {
            let request = PersonalityCall::new(
                Dialect::Linux,
                number,
                [rdi, rsi, rdx, r10, r8, r9],
                0,
                domain,
            );
            (
                REPLY_VALUE,
                if number == SENDTO {
                    answer_sendto(&request)
                } else {
                    answer_recvfrom(&request)
                },
            )
        }
        CLONE => {
            let plan = thread::plan_clone(rdi, rsi, rdx, r10, r8);
            let ClonePlan::Thread { stack, tls, .. } = plan else {
                let ClonePlan::Refuse(errno) = plan else {
                    return (REPLY_VALUE, Answer::error(memory::errno::EINVAL));
                };
                return (REPLY_VALUE, Answer::error(errno));
            };
            // **The entry is `r9`, and that is this personality's own
            // contract rather than Linux's.** Linux resumes the child after
            // its own `syscall` instruction, which needs the child to start
            // with the parent's whole register file; this system starts it at
            // an address the caller named in the sixth slot. Stated here as
            // it was stated in the nucleus, because moving code is not the
            // moment to quietly change what it promises.
            if r9 == 0 {
                return (REPLY_VALUE, Answer::error(memory::errno::ENOSYS));
            }
            let made = call(
                syscall::INVOKE,
                handle_of(domain),
                method::SPAWN_THREAD,
                [r9, stack, tls.unwrap_or(0), 0],
            );
            if made.status != status::OK {
                return (REPLY_VALUE, Answer::error(-11));
            }
            // Linux's `clone` returns the child's tid to the parent and zero
            // to the child. The child never returns through here at all -- it
            // starts where the caller said -- so the zero is delivered by
            // construction, and this is only the parent's half.
            (REPLY_VALUE, Answer::ok(made.args[0] + 1))
        }
        RT_SIGRETURN => {
            // The handler was entered with `rsp` at the frame base; the `ret`
            // into the restorer consumed the return address, so the process's
            // `rsp` is eight above it.
            let base = image[17].wrapping_sub(8);
            let mcontext = base + 8 + SIGINFO_BYTES as u64 + UCONTEXT_MCONTEXT as u64;
            let mut bytes = [0u8; signal::sigcontext::SIZE];
            if !copy_in(domain, mcontext, &mut bytes) {
                return (REPLY_VALUE, Answer::error(memory::errno::EINVAL));
            }
            let Ok(registers) = Registers::read_sigcontext(&bytes) else {
                return (REPLY_VALUE, Answer::error(memory::errno::EINVAL));
            };
            let mut edited = image;
            edited[0] = registers.rax;
            edited[3] = registers.rdx;
            edited[4] = registers.rsi;
            edited[5] = registers.rdi;
            edited[7] = registers.r8;
            edited[8] = registers.r9;
            edited[9] = registers.r10;
            edited[15] = registers.rip;
            edited[16] = registers.eflags;
            edited[17] = registers.rsp;
            if !write_slot(slot, &edited) {
                return (REPLY_VALUE, Answer::error(memory::errno::EINVAL));
            }
            (REPLY_RESTORE, Answer::ok(slot))
        }
        FORK => (
            REPLY_VALUE,
            answer_fork(
                &PersonalityCall::new(
                    Dialect::Linux,
                    number,
                    [0; bhaskix_personality::call::ARGUMENTS],
                    0,
                    domain,
                ),
                &image,
            ),
        ),
        _ => (REPLY_VALUE, bhaskix_personality::call::ENOSYS),
    }
}

/// How many register words a fault slot carries, in the kernel's order.
const FAULT_REGISTERS: usize = 19;
/// Where a slot's register words begin, after the address and error code.
const FAULT_FIRST_REGISTER: u64 = 16;

/// Reads a fault slot's register image.
fn read_slot(slot: u64, out: &mut [u64; FAULT_REGISTERS]) -> bool {
    if slot >= 8 {
        return false;
    }
    let at = FAULTS_AT + slot * FAULT_SLOT_BYTES + FAULT_FIRST_REGISTER;
    for (index, word) in out.iter_mut().enumerate() {
        // SAFETY: inside the fault page this program mapped from the object
        // it holds; `slot` is bounded above and the image is nineteen words
        // inside a 512-byte slot.
        *word = unsafe { core::ptr::read_volatile((at + index as u64 * 8) as *const u64) };
    }
    true
}

/// Writes a fault slot's register image back.
fn write_slot(slot: u64, image: &[u64; FAULT_REGISTERS]) -> bool {
    if slot >= 8 {
        return false;
    }
    let at = FAULTS_AT + slot * FAULT_SLOT_BYTES + FAULT_FIRST_REGISTER;
    for (index, word) in image.iter().enumerate() {
        // SAFETY: as `read_slot`, in the other direction.
        unsafe { core::ptr::write_volatile((at + index as u64 * 8) as *mut u64, *word) };
    }
    true
}

/// Reads bytes out of a hosted process's memory, through the capability this
/// program holds for its domain.
///
/// Via the scratch area of the report page: a copy names an **object** rather
/// than an address, so the kernel is never asked to validate two addresses in
/// two address spaces — RFC 0032's shape, and the reason this program cannot
/// ask for bytes to land anywhere it could not already write.
fn copy_in(domain: u32, address: u64, out: &mut [u8]) -> bool {
    if out.len() > SCRATCH_BYTES as usize {
        return false;
    }
    let moved = call(
        syscall::INVOKE,
        handle_of(domain),
        method::COPY_IN,
        [REPORT, SCRATCH_AT_OFFSET, address, out.len() as u64],
    );
    if moved.status != status::OK {
        return false;
    }
    for (index, byte) in out.iter_mut().enumerate() {
        // SAFETY: inside the page `ATTACH` mapped from this program's own
        // object, at the scratch area, bounded by the check above.
        *byte = unsafe {
            core::ptr::read_volatile((REPORT_AT + SCRATCH_AT_OFFSET + index as u64) as *const u8)
        };
    }
    true
}

/// Writes bytes into a hosted process's memory, the same way round.
fn copy_out(domain: u32, address: u64, bytes: &[u8]) -> bool {
    copy_out_through(handle_of(domain), address, bytes)
}

/// The same, naming the capability rather than the domain.
///
/// For `execve`, which writes into a domain it is *building* and holds in a
/// slot of its own rather than one the kernel has named yet — the handle
/// arrives from `SPAWN`, and the kernel's own grant for that domain does not
/// exist until the program in it makes its first call.
/// Moves a whole page out, in as many crossings as the scratch area allows.
///
/// The count is the point: `MAX_SUPERVISED_COPY` permits a page in one
/// `COPY_OUT`, and what stops this being one call is the size of the scratch
/// area, not the interface. RFC 0036 step 2's measurement is what noticed.
fn copy_page_out(handle: u64, address: u64, page: &[u8]) -> bool {
    let mut moved = 0usize;
    while moved < page.len() {
        let take = (page.len() - moved).min(SCRATCH_BYTES as usize);
        if !copy_out_through(handle, address + moved as u64, &page[moved..moved + take]) {
            return false;
        }
        moved += take;
    }
    true
}

fn copy_out_through(handle: u64, address: u64, bytes: &[u8]) -> bool {
    if bytes.len() > SCRATCH_BYTES as usize {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        // SAFETY: as `copy_in`, in the other direction.
        unsafe {
            core::ptr::write_volatile(
                (REPORT_AT + SCRATCH_AT_OFFSET + index as u64) as *mut u8,
                *byte,
            );
        }
    }
    let moved = call(
        syscall::INVOKE,
        handle,
        method::COPY_OUT,
        [REPORT, SCRATCH_AT_OFFSET, address, bytes.len() as u64],
    );
    moved.status == status::OK
}

/// How much of the report page the copies may use.
const SCRATCH_BYTES: u64 = report::SCRATCH_BYTES as u64;

/// Records that a fault was handed over, in the report page the kernel reads.
///
/// The adapter has no console; this is how it says anything at all. Two words
/// — the slot and the address — are enough to prove the exchange happened and
/// to say where, which is what this step is for.
///
/// **"The report page the kernel reads" was true of the page and false of this
/// record until 2026-08-26.** The kernel read six of the eight records here and
/// never this one, so every address written below was discarded at the end of
/// every boot. It is read now, and printed beside `fault::statistics` — the
/// kernel counts the handovers and this says where they were, which is the only
/// evidence that exists when a hosted program dies before it can print.
fn faults_seen(slot: u64, address: u64) {
    let seen = FAULTS_TAKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if seen >= 4 {
        return;
    }
    let at = REPORT_AT + FAULT_LOG_OFFSET + seen * 16;
    // SAFETY: inside the page `ATTACH` mapped from this program's own object,
    // past the trace records and the scratch word, and bounded to four
    // sixteen-byte entries well inside 4,096 bytes.
    unsafe {
        core::ptr::write_volatile(at as *mut u64, slot);
        core::ptr::write_volatile((at + 8) as *mut u64, address);
    }
}

/// How many faults have been handed to this program.
static FAULTS_TAKEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Where the fault log sits in the report page, after the trace and scratch.
const FAULT_LOG_OFFSET: u64 = report::FAULT_LOG_AT as u64;

/// Where in the report page the scratch word lives.
///
/// After the eight trace records, so a trace and a copy cannot overwrite each
/// other. The same page serves both because it is the only memory this
/// program owns, and a second object would be a second thing to explain in
/// the manifest for no gain.
const SCRATCH_AT_OFFSET: u64 = report::SCRATCH_AT as u64;

/// Writes the scratch word this program copies out of.
fn write_scratch(value: u64) {
    // SAFETY: `REPORT_AT + SCRATCH_AT_OFFSET` is inside the page `ATTACH`
    // mapped from this program's own object, past the trace records and well
    // inside 4,096 bytes.
    unsafe { core::ptr::write_volatile((REPORT_AT + SCRATCH_AT_OFFSET) as *mut u64, value) };
}

/// `brk(address)` — reports or moves the break.
///
/// **The heap every C program starts with**, and the last mechanism BusyBox
/// needed that this adapter did not have. A libc calls `brk(0)` to learn where
/// its heap begins and then `brk(higher)` to grow it; BusyBox does exactly that
/// four times before it prints anything.
///
/// # The shape, and what it is not
///
/// The region is **reserved once**, lazily, from this process's own mapping
/// base -- the same `advance_mapping` an `mmap` uses, so a heap and a mapping
/// cannot be drawn over each other. Moving the break is then arithmetic: no
/// call into the nucleus, and nothing charged until the program touches a page.
///
/// It is **not** an unbounded heap. Linux grows the break until memory runs
/// out; this reserves [`BRK_BYTES`] and refuses past it. A refusal answers with
/// the break the caller still has, which is what Linux answers on failure and
/// what a libc checks for -- returning an errno here would be the wrong shape
/// and is the classic way to make a working allocator think it succeeded.
fn answer_brk(request: &PersonalityCall) -> Answer {
    let wanted = request.first();
    let domain = handle_of(request.domain);
    let Some(process) = process_for(request.domain) else {
        return Answer::error(memory::errno::ENOMEM);
    };

    if process.brk_base == 0 {
        let Some(base) = advance_mapping(request.domain, BRK_BYTES) else {
            return Answer::error(memory::errno::ENOMEM);
        };
        // Re-fetch: `advance_mapping` takes the record too, and holding one
        // reference across it would be two live borrows of the same static.
        let pages = BRK_BYTES / memory::PAGE;
        if !map_at(domain, base, pages, PROT_READ_WRITE, MAP_LAZY) {
            return Answer::error(memory::errno::ENOMEM);
        }
        let Some(process) = process_for(request.domain) else {
            return Answer::error(memory::errno::ENOMEM);
        };
        process.brk_base = base;
        process.brk_current = base;
    }

    let Some(process) = process_for(request.domain) else {
        return Answer::error(memory::errno::ENOMEM);
    };
    let (base, current) = (process.brk_base, process.brk_current);
    // `brk(0)` is the question rather than a move, and a request below the
    // base or past the reservation is refused *by answering the current
    // break* -- see the note above on why this is not an errno.
    if wanted < base || wanted > base + BRK_BYTES {
        return Answer::ok(current);
    }
    process.brk_current = wanted;
    Answer::ok(wanted)
}

/// Reads standard input for a domain that was granted it — RFC 0053.
///
/// One byte per call, because that is what the console confers and because a
/// line editor wants them one at a time anyway. A domain with no grant is
/// refused with `EIO` rather than told the console is empty: a program told
/// "nothing yet" asks again for ever, and a shell would spin on a keyboard it
/// is never going to be allowed to read.
fn read_console(request: &PersonalityCall) -> (u64, Answer) {
    let (buffer, count) = (request.second(), request.third());
    if count == 0 {
        return (REPLY_VALUE, Answer::ok(0));
    }
    // **`POLL_INPUT` and not `TAKE_INPUT`, and the reason is this program's
    // shape.** `TAKE_INPUT` blocks in the nucleus until somebody types — on the
    // *calling* thread, which is this one. This adapter is single-threaded and
    // serves every hosted domain from one receive loop, so a blocking take
    // stops the whole personality until a key arrives. It was written that way
    // first and the typing lane found it: BusyBox sat in `read`, the adapter
    // sat in BusyBox, and the boot only moved on when the corpus timed out and
    // killed the domain.
    //
    // So this asks whether a byte is *already* waiting, and when none is it
    // parks **the caller** — RFC 0054. `BLOCK_ON_RETRY` naming
    // [`INPUT_WAKE`]: the nucleus blocks the hosted thread on the console's own
    // notification, this program returns to its receive loop and keeps serving
    // every other domain, and when a key arrives the same `read` is asked
    // again. The retry shape and not `BLOCK_ON`, for the reason written at its
    // declaration: a woken read must come back with *bytes*, and the zero a
    // woken futex is answered with would be end of file.
    //
    // `call` rather than `invoke`, because the byte is the *value* and `invoke`
    // keeps only whether the call worked.
    let taken = call(
        syscall::INVOKE,
        handle_of(request.domain),
        method::POLL_INPUT,
        [0, 0, 0, 0],
    );
    if taken.status != status::OK {
        return (REPLY_VALUE, Answer::error(-5)); // EIO
    }
    if taken.args[0] == NOTHING {
        // **Park, do not spin.** An ungranted domain never reaches here — its
        // `POLL_INPUT` is refused above with `EIO` — so this is a granted
        // reader with an empty console, which is what waiting is for.
        return (REPLY_BLOCK_ON_RETRY, Answer::ok(INPUT_WAKE));
    }
    let byte = [taken.args[0] as u8];
    if !copy_out(request.domain, buffer, &byte) {
        return (REPLY_VALUE, Answer::error(-14)); // EFAULT
    }
    (REPLY_VALUE, Answer::ok(1))
}

/// `getcwd(buffer, size)` — where relative paths resolve from.
///
/// **Always `/`, and that is the truth rather than a placeholder.** A hosted
/// process resolves every relative path against the one directory capability it
/// was given, and it has no way to change that: there is no `chdir` here, and
/// there could not be a meaningful one, because moving "up" out of a directory
/// capability is the thing capabilities exist to make impossible. So the
/// directory it resolves against *is* its root, and `/` is what a program
/// asking where it stands should be told.
///
/// **Not the host path of that directory**, which would be a leak: the name the
/// filesystem service knows it by says where in a larger tree this process's
/// world sits, and nothing in this process is entitled to that.
///
/// BusyBox's `sh` printed `sh: getcwd: Function not implemented` and then a
/// prompt reading `(unknown) #` before this existed.
fn answer_getcwd(request: &PersonalityCall) -> Answer {
    const PATH: &[u8] = b"/\0";
    let (buffer, size) = (request.first(), request.second());
    if size < PATH.len() as u64 {
        return Answer::error(-34); // ERANGE, which is what Linux says
    }
    if !copy_out(request.domain, buffer, PATH) {
        return Answer::error(-14); // EFAULT
    }
    // Linux answers the length *including* the terminator.
    Answer::ok(PATH.len() as u64)
}

/// `access(path, mode)` — may this process reach that name.
///
/// **Answered by trying, not by reading a mode bit.** This adapter holds a
/// directory capability and no permission table; the only honest way to say
/// whether a name is reachable is to reach for it. So the file is opened and
/// closed again, and whatever `open` would have said is what `access` says --
/// `ENOENT` for a name that is not there, and nothing invented for one that is.
///
/// `W_OK` is refused without looking. The directory capability this program
/// holds carries no `WRITE` right (RFC 0033), so a writable answer would be a
/// lie that a program acts on -- it would go on to open the file for writing
/// and fail there instead, further from the cause.
fn answer_access(request: &PersonalityCall) -> Answer {
    const W_OK: u64 = 2;
    if request.second() & W_OK != 0 {
        return Answer::error(-13); // EACCES
    }
    let opened = open_the_file(request, request.first(), 0);
    if opened.is_error() {
        return opened;
    }
    // Closed again, or `access` leaks a descriptor per call and a program that
    // checks many names stops after thirty-two of them.
    let mut closing = *request;
    closing.args[0] = opened.value;
    let _ = answer_close(&closing);
    Answer::ok(0)
}

/// `writev(fd, iov, iovcnt)` — one write from several buffers.
///
/// **Through `write` rather than beside it.** Each vector is handed to the same
/// call, so a pipe is a pipe and a read-only file is still `EROFS`, and there is
/// one place that decides what a descriptor means. Writing this out separately
/// would be a second descriptor table's worth of rules to keep in step.
///
/// It is what BusyBox's error path uses, and its absence is why BusyBox
/// **aborted** on this machine: it wrote its complaint with `writev`, was told
/// `ENOSYS`, and raised a signal at itself -- the `getpid, gettid, tgkill`
/// tail its own trace ends with, twice.
///
/// # Short writes are the caller's to notice
///
/// A vector that writes short stops the loop, and the total so far is returned.
/// That is what `writev` promises: it does not promise all of it.
fn answer_writev(request: &PersonalityCall) -> Answer {
    /// `struct iovec` is two words: base, then length.
    const IOVEC_BYTES: usize = 16;
    /// How many vectors are read in one call. Linux allows 1024; this reads
    /// what a bounded buffer holds and says so by refusing more, rather than
    /// silently writing a prefix.
    const MAX_VECTORS: usize = 16;

    let (fd, iov_at, count) = (request.first(), request.second(), request.third());
    let Ok(vectors) = usize::try_from(count) else {
        return Answer::error(-22); // EINVAL
    };
    if vectors == 0 {
        return Answer::ok(0);
    }
    if vectors > MAX_VECTORS {
        return Answer::error(-22); // EINVAL
    }
    let mut raw = [0u8; MAX_VECTORS * IOVEC_BYTES];
    let wanted = vectors * IOVEC_BYTES;
    if !copy_in(request.domain, iov_at, &mut raw[..wanted]) {
        return Answer::error(-14); // EFAULT
    }

    let mut written = 0u64;
    for vector in raw[..wanted].as_chunks::<IOVEC_BYTES>().0 {
        let mut base = [0u8; 8];
        let mut length = [0u8; 8];
        base.copy_from_slice(&vector[..8]);
        length.copy_from_slice(&vector[8..]);
        let (base, length) = (u64::from_le_bytes(base), u64::from_le_bytes(length));
        if length == 0 {
            continue;
        }
        let mut one = *request;
        one.number = WRITE;
        one.args = [fd, base, length, 0, 0, 0];
        let (_, answer) = answer(&one);
        if answer.is_error() {
            // Nothing written yet means the error is the answer; something
            // written means the caller is told how much, which is what a
            // partial `writev` is.
            return if written == 0 {
                answer
            } else {
                Answer::ok(written)
            };
        }
        written += answer.value;
        if answer.value < length {
            break;
        }
    }
    Answer::ok(written)
}

/// `tgkill(tgid, tid, signal)` — a libc raising a signal at itself.
///
/// **Only at itself, and only the ones that end it.** This personality has no
/// signal delivery: RFC 0033 gave hosted processes `rt_sigaction` so a runtime
/// can install handlers it will never be called with, and that gap is written
/// down rather than papered over. What `abort()` needs is not delivery -- it
/// needs the process to *stop*, which this can do honestly.
///
/// So a fatal signal aimed at the caller's own thread ends its domain, with the
/// signal recorded as the reason. Anything else is refused: a program that
/// signalled another process and was told it worked would be lied to, and there
/// is no other process here to signal.
fn answer_tgkill(request: &PersonalityCall) -> (u64, Answer) {
    const SIGABRT: u64 = 6;
    const SIGKILL: u64 = 9;
    const SIGSEGV: u64 = 11;

    let (tid, signal) = (request.second(), request.third());
    let itself = u32::try_from(tid).is_ok_and(|tid| tid == request.thread);
    let fatal = matches!(signal, SIGABRT | SIGKILL | SIGSEGV);
    if itself && fatal {
        note_exit(
            request.domain,
            Exit::Signalled {
                signal: signal as u8,
                core: false,
            },
        );
        return (REPLY_END_DOMAIN, Answer::ok(0));
    }
    (REPLY_VALUE, bhaskix_personality::call::ENOSYS)
}

/// Maps `pages` lazily at `address` in a hosted domain.
///
/// Lazily, because a hosted `mmap` is a *reservation*: a runtime that asks for
/// a gigabyte and touches a page should pay for a page, which is what Go's
/// allocator assumes and what an eager mapping would refuse on a machine with
/// ample memory.
fn map_at(domain: u64, address: u64, pages: u64, protection: u64, extra: u64) -> bool {
    let reply = call(
        syscall::INVOKE,
        domain,
        method::MAP_AT,
        [address, pages, protection, MAP_LAZY | extra],
    );
    reply.status == status::OK
}

/// Invokes a method on a capability, and turns the answer into an `errno`.
///
/// A hosted program is told `-EINVAL` when the invocation was refused: this
/// program holds the authority or it does not, and a refusal here is not a
/// distinction a Linux process has any way to act on.
fn invoke(capability: u64, what: u64, args: [u64; 4]) -> Answer {
    let reply = call(syscall::INVOKE, capability, what, args);
    if reply.status == status::OK {
        Answer::ok(0)
    } else {
        Answer::error(memory::errno::EINVAL)
    }
}

/// Answers one foreign call.
///
/// **This is the whole of the personality that has moved so far, and its size
/// is the honest measure of the move.** Everything else is still answered in
/// the nucleus and will arrive here as it is taken out — at which point this
/// function grows and `mod linux`'s declared count shrinks. The boundary
/// report prints that count on every boot, so the progress is a number rather
/// than a claim.
fn answer(request: &PersonalityCall) -> (u64, Answer) {
    // The two that cannot be answered from a message alone say so, and the
    // kernel asks again with the caller's register frame.
    // **`fork` needs the frame too**, and for the plainest reason: the child
    // resumes where the parent's call returns, and only the staged register
    // image says where that is.
    // **`sendto` and `recvfrom` are here for a structural reason, not a
    // stylistic one.** The boundary message carries *four* arguments; both of
    // those calls take six, and their fifth and sixth -- the address and its
    // length -- arrive as hard zeros in a message. The first version of this
    // wiring read them from the message anyway and every `sendto` refused
    // `EFAULT` on a null address, which the socket probe found because its
    // datagram never came back.
    if matches!(
        request.number,
        CLONE | RT_SIGRETURN | FORK | SENDTO | RECVFROM
    ) {
        return (REPLY_NEED_FRAME, Answer::ok(0));
    }
    // Acts on the caller that only the kernel can perform. **Which** of them,
    // and whether at all, is this dialect's decision -- so the reply says
    // what to do rather than the nucleus knowing what the number meant.
    match request.number {
        // The one call whose answer may be "sleep", and the only one that
        // reads the caller's memory to decide.
        FUTEX => return answer_futex(request),
        // The one call that ends the caller and starts a program in its place.
        EXECVE => return answer_execve(request),
        PIPE2 => {
            return (
                REPLY_VALUE,
                answer_pipe(request, request.first(), request.second()),
            );
        }
        PIPE => return (REPLY_VALUE, answer_pipe(request, request.first(), 0)),
        // The file surface — RFC 0033 step 6. Each reads or writes the
        // caller's memory, so each needs the `Domain` capability rather than
        // only the message.
        OPENAT => {
            return (
                REPLY_VALUE,
                answer_openat(request, request.second(), request.third()),
            );
        }
        OPEN => {
            return (
                REPLY_VALUE,
                answer_openat(request, request.first(), request.second()),
            );
        }
        READ => {
            // **Standard input is the domain's, not this program's** — RFC
            // 0053. The console capability this adapter holds is `WRITE` alone
            // and stays that way; a byte somebody typed is taken through the
            // *domain* capability, and the nucleus refuses unless that domain
            // was granted input. So a hosted program reads keystrokes only if
            // somebody decided it should, and a compromise of this program does
            // not change that.
            if request.first() == 0 {
                return read_console(request);
            }
            // **Routed by what the descriptor *is*.** A pipe may have to park
            // the caller, which is a reply shape rather than a value, so the
            // choice has to be made here rather than inside an answer.
            return match descriptor_kind(request, request.first()) {
                Some((Kind::Pipe, handle)) => {
                    read_from_pipe(request, handle as usize, request.second(), request.third())
                }
                Some((Kind::Proc, handle)) => (
                    REPLY_VALUE,
                    read_proc(request, handle, request.second(), request.third()),
                ),
                _ => (REPLY_VALUE, answer_read(request)),
            };
        }
        // Reading a directory, and stat in both its shapes. Each writes the
        // caller's memory, so each belongs in this block rather than among
        // the calls a message alone can answer.
        GETDENTS64 => return (REPLY_VALUE, answer_getdents64(request)),
        UNAME => return (REPLY_VALUE, answer_uname(request)),
        // Tier 2's first four — RFC 0005 step 9. Each reads or writes the
        // caller's memory, so each belongs in this block.
        SOCKET => return (REPLY_VALUE, answer_socket(request)),
        BIND => return (REPLY_VALUE, answer_bind(request)),

        IOCTL => return (REPLY_VALUE, answer_ioctl(request)),
        FSTAT => return (REPLY_VALUE, answer_fstat(request)),
        NEWFSTATAT => return (REPLY_VALUE, answer_newfstatat(request)),
        CLOSE => return (REPLY_VALUE, answer_close(request)),
        DUP | DUP2 | DUP3 => return (REPLY_VALUE, answer_dup(request)),
        SCHED_YIELD => return (REPLY_YIELD, Answer::ok(0)),
        EXIT => return (REPLY_END_THREAD, Answer::ok(0)),
        // A Linux thread group's exit is every thread of it, and a hosted
        // process is a domain.
        //
        // **The status is recorded before the domain ends** — RFC 0033 step 9.
        // It is in `rdi`, here, now: the adapter is answering the call that
        // carries it. Until this step the record was given an invented zero,
        // because the only other moment to learn a status was the domain's
        // death, and a death carries none. A parent that reads `$?` reads this.
        EXIT_GROUP => {
            note_exit(request.domain, Exit::Status(request.first() as u8));
            return (REPLY_END_DOMAIN, Answer::ok(0));
        }
        // Beside `exit_group` because it is the same act by another name: a
        // libc's `abort()` raises a fatal signal at its own thread, and what
        // that has to do here is end the process. It lives in *this* dispatcher
        // and not the one below because only this one can answer
        // `REPLY_END_DOMAIN`.
        // **In this dispatcher and not the one below**, for the same reason
        // `read` is: only this one can answer a reply shape, and an infinite
        // `poll` on the console has to park exactly as a blocking read does.
        POLL => return answer_poll(request),
        PPOLL => return answer_ppoll(request),
        SELECT => return answer_select(request),
        PSELECT6 => return answer_pselect(request),
        // `clock_nanosleep(clock, flags, request, remain)` -- RFC 0055.
        //
        // Answered because `poll` gave a shell a reason to ask: BusyBox's line
        // editor sleeps between retries once it believes `poll` works, and a
        // sleep refused with `ENOSYS` is what made it give up and exit.
        CLOCK_NANOSLEEP => return answer_nanosleep(request),
        NANOSLEEP => return answer_nanosleep_relative(request, request.first()),
        TGKILL => return answer_tgkill(request),
        // `wait4(pid, status, options, rusage)`.
        WAIT4 => return answer_wait(request),
        _ => {}
    }
    (REPLY_VALUE, answer_from_message(request))
}

/// The scheduler's own name for the calling thread.
///
/// Every tid this personality hands a hosted program is the nucleus's thread
/// id **plus one** — `clone` returns the child that way and `gettid` answers
/// that way, because Linux never issues tid zero and a runtime that sees one
/// treats it as an error. The badge is stamped the same way, so that zero can
/// mean *no thread*. Naming the thread back to the nucleus undoes the offset,
/// and it is done here, once, rather than at each call site.
fn nucleus_thread(request: &PersonalityCall) -> u64 {
    u64::from(request.thread.saturating_sub(1))
}

/// Everything that can be decided from four words and this program's own
/// tables.
fn answer_from_message(request: &PersonalityCall) -> Answer {
    match request.number {
        // `getpid`. A Linux process id is a *number a program compares and
        // prints*, not authority — so a personality may invent one, and as of
        // RFC 0033 step 4 this one invents it properly: a counter in the
        // process record, never reused within a boot, and **not the domain
        // id**.
        //
        // It answered `domain + 1` until then, which was wrong in two ways
        // that only matter once a hosted program can `execve`. It leaked a
        // Bhaskix identifier into a hosted process — cheap to remove now,
        // expensive after software depends on the number. And it tied a Linux
        // pid to a Bhaskix lifetime: `START` refuses a domain that has
        // threads, so an exec must build a *new* domain, and a pid that moved
        // with it would break `wait`, `$!` and every shell ever written.
        //
        // A machine with no room for another record answers `EAGAIN`, which is
        // what Linux answers a `fork` it cannot serve.
        GETPID => match process_for(request.domain) {
            Some(process) => Answer::ok(u64::from(process.pid)),
            None => Answer::error(bhaskix_personality::process::errno::EAGAIN),
        },
        // The memory calls that fit in a message — RFC 0032 step 4. What each
        // *means* is decided by `bhaskix_personality::memory`, host-tested and
        // unchanged by the move; what it *does* is a capability invocation on
        // the hosted domain. That split is the whole design: policy here,
        // mechanism in the kernel, and the authority in hand rather than
        // ambient.
        //
        // `mmap` is deliberately absent and still answered in the nucleus. It
        // takes six arguments and a message carries four, so moving it needs a
        // page shared with the kernel rather than a message — which is also
        // what signal delivery will need, and is therefore one piece of work
        // rather than two.
        // `mmap`, and the one place this personality's arguments do not all
        // fit in a message.
        //
        // Linux passes six: address, length, protection, flags, **fd** and
        // offset. An IPC message carries four, and the two that do not fit are
        // the two that only matter for a *file* mapping — which this
        // personality refuses whole (RFC 0005 step 5: a file mapping needs a
        // filesystem capability and a translation from a Linux fd to it, which
        // is Tier 1's work). So the adapter passes `fd = -1` and refuses
        // anything without `MAP_ANONYMOUS`, which reaches the same answer for
        // every request either could have refused.
        //
        // **One behaviour changes, and it moves toward Linux rather than
        // away.** The nucleus also refused an anonymous mapping that carried a
        // non-negative fd; Linux ignores fd when `MAP_ANONYMOUS` is set, and
        // now so does this. When file mappings arrive they will need all six
        // arguments and therefore a page shared with the kernel rather than a
        // message — which is written down here so it is a known cost and not a
        // surprise.
        MMAP => match memory::plan_mmap(
            request.first(),
            request.second(),
            request.third(),
            request.fourth(),
            -1,
        ) {
            memory::MapPlan::Refuse(errno) => Answer::error(errno),
            memory::MapPlan::Map {
                at,
                hint,
                pages,
                read,
                write,
                execute,
            } => {
                let protection = protection_of(read, write, execute);
                let domain = handle_of(request.domain);
                trace(
                    request.first(),
                    request.second(),
                    pages,
                    protection,
                    at.is_some(),
                    hint.is_some(),
                );
                // A demand is honoured or refused; a *hint* is tried and then
                // given up on. Trying it matters: an allocator that asked for
                // its heap near one address and got another hands the mapping
                // back, and after enough of those gives up entirely.
                // A *demand* discards whatever is at the address; a hint does
                // not. That difference is `MAP_FIXED`, and it is the whole of
                // the reserve-then-commit pattern a Go runtime uses: reserve
                // an arena `PROT_NONE`, then map the same range read-write
                // over the top of it. Refusing the second is what stopped the
                // corpus at "out of memory", which the adapter's own trace is
                // what showed.
                let replace = if at.is_some() { MAP_REPLACE } else { 0 };
                if let Some(wanted) = at.or(hint)
                    && map_at(domain, wanted, pages, protection, replace)
                {
                    remember_mapping(request.domain, wanted, pages, protection);
                    return Answer::ok(wanted);
                }
                if at.is_some() {
                    return Answer::error(memory::errno::ENOMEM);
                }
                let bytes = pages * memory::PAGE;
                // **From this process's own base, not a shared bump** --
                // `security.md` §1 gap 3. One global allocator meant every
                // hosted layout was fixed *and* that each process's addresses
                // were predictable from any other's; a base per record ends
                // both. A record with no base has not been drawn one, which is
                // a refusal rather than a fixed address quietly used.
                let Some(address) = advance_mapping(request.domain, bytes) else {
                    return Answer::error(memory::errno::ENOMEM);
                };
                if map_at(domain, address, pages, protection, 0) {
                    remember_mapping(request.domain, address, pages, protection);
                    Answer::ok(address)
                } else {
                    Answer::error(memory::errno::ENOMEM)
                }
            }
        },
        MUNMAP => match memory::plan_munmap(request.first(), request.second()) {
            Ok((address, pages)) => {
                let _ = pages;
                let answer = invoke(
                    handle_of(request.domain),
                    method::UNMAP_AT,
                    [address, 0, 0, 0],
                );
                // The list follows the mapping, or a `fork` after an unmap
                // would copy memory that is not there any more.
                if answer.value == 0
                    && let Some(process) = process_for(request.domain)
                {
                    process.unmapped(address);
                }
                answer
            }
            Err(errno) => Answer::error(errno),
        },
        MPROTECT => {
            match memory::plan_mprotect(request.first(), request.second(), request.third()) {
                Ok((address, pages, read, write, execute)) => {
                    let protection = protection_of(read, write, execute);
                    let answer = invoke(
                        handle_of(request.domain),
                        method::PROTECT_AT,
                        [address, pages, protection, 0],
                    );
                    // The list follows the mapping here too, and this one is
                    // not bookkeeping for its own sake: a `fork` maps the
                    // child's copy with the protection this list holds, so a
                    // page made executable after it was mapped would be copied
                    // as writable-and-not-executable and the child would fault
                    // on its first instruction.
                    if answer.value == 0
                        && let Some(process) = process_for(request.domain)
                    {
                        process.protected(address, protection);
                    }
                    answer
                }
                Err(errno) => Answer::error(errno),
            }
        }
        // Advice, and this system takes none: every hint Go gives is about a
        // page-reclaim policy that does not exist here. Answered rather than
        // refused, because a runtime told its advice was rejected may take a
        // slower path for no reason.
        // **No memory, so no `Domain` capability** — the whole of `lseek` is
        // arithmetic on a row this program already holds, which is why it is
        // here and `fstat` is not.
        LSEEK => answer_lseek(request),
        FCNTL => answer_fcntl(request),
        // **Refused, and with the errno that says why.** The directory this
        // adapter holds carries `READ` and `DERIVE` and no `WRITE` -- RFC 0033
        // step 6 granted it that way on purpose -- so a hosted program cannot
        // create or remove anything, and `EROFS` is the answer that tells it
        // the truth. `ENOSYS` would say the call is unimplemented, which would
        // send a program looking for another way to do it.
        MKDIRAT | UNLINKAT => Answer::error(-30), // EROFS
        MADVISE => Answer::ok(memory::plan_madvise() as u64),
        // Signal masking is recorded nowhere and honoured nowhere yet. Zero
        // rather than `-ENOSYS`, because a runtime told it cannot mask signals
        // takes a slower path for a promise nothing here breaks: no signal is
        // delivered asynchronously, so a mask has nothing to hide from.
        RT_SIGPROCMASK => Answer::ok(0),
        // A thread id a hosted program can tell apart from its neighbours,
        // and stable for the life of the thread. **It arrives in the badge**,
        // whose high half the kernel stamps with the calling thread — a
        // caller cannot supply one, which is why it can be believed.
        GETTID => Answer::ok(u64::from(request.thread)),
        // **The two older `stat` forms, mapped onto the one path resolution.**
        // BusyBox's `sh` stats `.` and `/tmp` before it does anything else, and
        // `ls` stats every name it lists. Both are `newfstatat` with `AT_FDCWD`
        // and a flag, so they are that call rather than a second copy of it.
        STAT => stat_at(request, AT_FDCWD, request.first(), request.second(), 0),
        LSTAT => stat_at(
            request,
            AT_FDCWD,
            request.first(),
            request.second(),
            AT_SYMLINK_NOFOLLOW,
        ),
        // **A number every program reads and nothing here acts on.** RFC 0031:
        // Linux UID 0 is not Bhaskix authority. Programs compare against it --
        // BusyBox's `sh` calls it before its first prompt -- and what a hosted
        // process may actually do is what its domain holds, which this does not
        // change. Refusing it stops shells for no gain in safety.
        GETUID => Answer::ok(0),
        BRK => answer_brk(request),
        // The effective uid, which is the real one: nothing here can change it,
        // because nothing here reads it to decide anything. See `GETUID`.
        GETEUID => Answer::ok(0),
        ACCESS => answer_access(request),
        GETCWD => answer_getcwd(request),
        WRITEV => answer_writev(request),
        // The parent this process was forked from.
        //
        // **Zero when there is none, and Linux would say 1.** Linux reparents
        // an orphan to init and answers `1`; there is no init here to name, and
        // answering `1` would point at a process that does not exist. The record
        // already means "no parent" by zero, so that is what is passed on --
        // a shell reading `$PPID` sees a number it can print and cannot signal,
        // which is true rather than convenient.
        GETPPID => match process_for(request.domain) {
            Some(process) => Answer::ok(u64::from(process.ppid)),
            None => Answer::error(-3), // ESRCH
        },
        // **Accepted for the one option that is advisory, refused otherwise.**
        // `PR_SET_NAME` is how a program labels its own thread and BusyBox sets
        // it to `busybox` at start-up; Linux itself treats it as a hint. It is
        // accepted and **not acted on**, which is the honest shape: this
        // personality has no name to set that anything here would read. Every
        // other option is refused rather than answered `0`, because a program
        // that asked to change its own behaviour and was told "done" would be
        // lied to.
        PRCTL => {
            const PR_SET_NAME: u64 = 15;
            if request.first() == PR_SET_NAME {
                Answer::ok(0)
            } else {
                bhaskix_personality::call::ENOSYS
            }
        }
        // The one call a hosted program needs before it can say anything.
        // Only the two standard streams, and only to this machine's console: a
        // hosted program writing to a descriptor it never opened is asking for
        // authority, and 1 and 2 are the two Linux hands every process without
        // being asked. A real descriptor table is Tier 1's.
        WRITE => {
            let (fd, buffer, count) = (request.first(), request.second(), request.third());
            // **A pipe's write end is a descriptor like any other** — RFC 0033
            // step 7. Before this, `write` knew only the two standard streams
            // and answered `EBADF` for everything else, which is what a
            // personality with no descriptor table can say. There is a table
            // now, so what a number *means* is a lookup.
            match descriptor_kind(request, fd) {
                Some((Kind::Pipe, handle)) => {
                    return write_to_pipe(request, handle as usize, buffer, count);
                }
                Some((Kind::File | Kind::Directory, _)) => {
                    // The directory capability this program holds carries no
                    // `WRITE` right, so this is a truth rather than a refusal
                    // to try.
                    return Answer::error(-30); // EROFS
                }
                _ => {}
            }
            if fd != 1 && fd != 2 {
                return Answer::error(-9); // EBADF
            }
            let take = (count as usize).min(WRITE_BYTES);
            if take == 0 {
                return Answer::ok(0);
            }
            let mut bytes = [0u8; WRITE_BYTES];
            if !copy_in(request.domain, buffer, &mut bytes[..take]) {
                return Answer::error(-14); // EFAULT
            }
            // **One invocation, because a line has to arrive whole** --
            // RFC 0050.
            //
            // This was a character at a time, and the comment here called that
            // *"the honest cost of a console that is a capability rather than a
            // kernel function this program may call"*. The cost was honest and
            // the correctness was not: `console::_print` locks per call, so
            // each `PUT` took and released the console on its own and any CPU
            // printing in between split the line. It did. A preserved log of
            // 2026-08-26 has a program's `execed pid 3` arriving as `e`, then a
            // whole kernel report, then `xeced pid 3` -- which is the
            // `exec`/pid intermittent filed on 2026-08-21, and why two rounds
            // of hypothesis about a *failing* write found nothing. The write
            // never failed. It arrived in two pieces.
            //
            // `PUT_RUN` is the same authority -- `WRITE` on a `Console`, the
            // same right `PUT` needs -- and the same rendering, byte by byte.
            // What it removes is the gap. It is also thirteen crossings fewer
            // per line, which the boundary instrument will show and which is a
            // side effect rather than the reason.
            let put = call(
                syscall::INVOKE,
                CONSOLE,
                method::PUT_RUN,
                [bytes.as_ptr() as u64, take as u64, 0, 0],
            );
            if put.status != status::OK {
                return Answer::error(-5); // EIO
            }
            Answer::ok(put.args[0])
        }
        // The thread-local base. Per *thread*, because the register holding
        // it is per *CPU*: a value written straight to the MSR is gone at the
        // first switch, which is what Go's `rt0` catches three instructions
        // later.
        ARCH_PRCTL => {
            if request.first() != ARCH_SET_FS {
                return bhaskix_personality::call::ENOSYS;
            }
            let set = call(
                syscall::INVOKE,
                handle_of(request.domain),
                method::SET_TLS,
                [nucleus_thread(request), request.second(), 0, 0],
            );
            if set.status == status::OK {
                Answer::ok(0)
            } else {
                bhaskix_personality::call::ENOSYS
            }
        }
        // Both need more than a message carries: `clone` takes five
        // arguments, and `rt_sigreturn` takes none but needs the interrupted
        // stack pointer to find the frame its handler was given. Asking for
        // the register file is how this program says so, and the kernel
        // stages one without learning why.
        CLONE | RT_SIGRETURN => Answer::ok(0),
        // Installing a handler. The `struct sigaction` is in the hosted
        // process's memory, so it is read the only way this program can read
        // anything of a process it hosts: through the capability it holds for
        // that domain.
        //
        // **Querying is answered as success with nothing written.** A caller
        // asking about an unset handler would see exactly that anyway, and
        // pretending to write the old one would be worse than not.
        RT_SIGACTION => {
            let (number, act) = (request.first(), request.second());
            if act == 0 {
                return Answer::ok(0);
            }
            let mut bytes = [0u8; 32];
            if !copy_in(request.domain, act, &mut bytes) {
                return Answer::error(bhaskix_personality::socket::errno::EFAULT);
            }
            let word = |index: usize| -> u64 {
                let mut eight = [0u8; 8];
                eight.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
                u64::from_le_bytes(eight)
            };
            // The x86-64 order, and `sa_restorer` between the flags and the
            // mask is the part a translator gets wrong from memory.
            let handler = signal::Handler {
                entry: word(0),
                flags: word(1),
                restorer: word(2),
                mask: word(3),
            };
            if dispositions_of(request.domain)
                .install(number, handler)
                .is_err()
            {
                return Answer::error(memory::errno::EINVAL);
            }
            Answer::ok(0)
        }
        SIGALTSTACK => {
            let new = request.first();
            if new == 0 {
                return Answer::ok(0);
            }
            let mut bytes = [0u8; 24];
            if !copy_in(request.domain, new, &mut bytes) {
                return Answer::error(bhaskix_personality::socket::errno::EFAULT);
            }
            let word = |index: usize| -> u64 {
                let mut eight = [0u8; 8];
                eight.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
                u64::from_le_bytes(eight)
            };
            dispositions_of(request.domain).set_alt_stack(signal::AltStack {
                base: word(0),
                flags: word(1),
                size: word(2),
            });
            Answer::ok(0)
        }
        // The affinity mask, written into the caller's own memory through the
        // one capability this program holds for it. **This is the first call
        // to reach into a hosted process's memory from ring 3** — everything
        // before it either answered a number or changed a mapping.
        SCHED_GETAFFINITY => {
            let (length, mask) = (request.second(), request.third());
            if mask == 0 || length < 8 {
                return Answer::error(memory::errno::EINVAL);
            }
            let bits: u64 = if CPUS_REPORTED >= 64 {
                u64::MAX
            } else {
                (1u64 << CPUS_REPORTED) - 1
            };
            write_scratch(bits);
            let moved = call(
                syscall::INVOKE,
                handle_of(request.domain),
                method::COPY_OUT,
                [REPORT, SCRATCH_AT_OFFSET, mask, 8],
            );
            if moved.status == status::OK {
                Answer::ok(8)
            } else {
                Answer::error(bhaskix_personality::socket::errno::EFAULT)
            }
        }
        // Everything else, for now. Not an omission — the RFC's tiering: a
        // refusal a runtime can *see*, logged with its number, so the set of
        // calls a real workload needs is discovered rather than guessed.
        _ => bhaskix_personality::call::ENOSYS,
    }
}

/// `getpid()`, from Linux's `x86_64` table.
const GETPID: u64 = 39;
/// `mmap(addr, length, prot, flags, fd, offset)` — six arguments, of which
/// this personality needs four. See [`answer`] for why that is sound and
/// what changes when file mappings arrive.
const MMAP: u64 = 9;
/// `munmap(addr, length)`.
const MUNMAP: u64 = 11;
/// `mprotect(addr, length, prot)`.
const MPROTECT: u64 = 10;
/// `madvise(addr, length, advice)`.
const MADVISE: u64 = 28;
/// `rt_sigprocmask(how, set, oldset, sigsetsize)`.
const RT_SIGPROCMASK: u64 = 14;
/// `sched_getaffinity(pid, length, mask)`.
const SCHED_GETAFFINITY: u64 = 204;

/// The method a *fault* arrives under, rather than a system call.
///
/// `u64::MAX`, which no Linux number can collide with — and which a hosted
/// program could not choose anyway, because it never chooses the method: the
/// kernel does.
const FAULT_METHOD: u64 = u64::MAX;
/// End the faulting program.
const FAULT_END: u64 = 0;
/// Resume it, with the registers left in the slot.
const FAULT_RESUME: u64 = 1;
/// The method that says a domain slot has been reused, so whatever this
/// program remembers about it belongs to somebody else.
///
/// **A domain id is reused and this program keeps state keyed by it.** A new
/// domain 3 inheriting the old domain 3's signal handlers would let a program
/// that never installed one survive a fault it should have died on — which is
/// worse than a crash, because it is a crash that did not happen.
const FORGET_METHOD: u64 = u64::MAX - 1;

/// The method a retry carrying the caller's register frame arrives under.
///
/// Some Linux calls take five or six arguments and a message carries four.
/// Rather than teach the nucleus which ones — Linux knowledge arriving by the
/// back door — this program answers [`REPLY_NEED_FRAME`], and the kernel asks
/// again under this method with the frame staged in a slot.
const FRAME_METHOD: u64 = u64::MAX - 2;

/// What a reply *means*, in the reply's method word.
const REPLY_VALUE: u64 = 0;
/// Ask again with the caller's register frame.
const REPLY_NEED_FRAME: u64 = 2;
/// Resume the caller from the registers in the slot named, not from a value.
const REPLY_RESTORE: u64 = 3;

/// Give up the caller's slice, then answer it.
const REPLY_YIELD: u64 = 4;
/// End the calling thread.
const REPLY_END_THREAD: u64 = 5;
/// End the caller's whole domain.
const REPLY_END_DOMAIN: u64 = 6;
/// Park the caller on the notification this program names.
const REPLY_BLOCK_ON: u64 = 7;
/// Park the caller, and ask this question again when it wakes.
///
/// What a blocking `read` needs: it must come back with *bytes*, and the zero
/// a woken `futex` is answered with would be end of file.
const REPLY_BLOCK_ON_RETRY: u64 = 8;
/// Park the caller on a notification **and** a deadline — RFC 0057.
///
/// The slot in the first word and the deadline in the second, which the reply
/// message has always had room for. The nucleus arms the deadline on the very
/// notification the caller parks on, so a key and the timer arrive by the same
/// door and whichever is first wins — and it arms it, rather than this program,
/// because the console's notification is held here with `READ` precisely so a
/// keystroke cannot be invented.
const REPLY_BLOCK_ON_UNTIL: u64 = 9;

/// `poll(fds, nfds, timeout)` — RFC 0055.
const POLL: u64 = 7;
/// `select(nfds, readfds, writefds, exceptfds, timeout)`.
const SELECT: u64 = 23;
/// `pselect6(nfds, readfds, writefds, exceptfds, timespec, sigmask)`.
const PSELECT6: u64 = 270;
/// `ppoll(fds, nfds, timespec, sigmask, sigsetsize)`.
const PPOLL: u64 = 271;
/// How many descriptors one `poll` may name.
///
/// Every entry is copied in and back out through the report page's scratch
/// area, so a bound is needed whatever the number is. Sixteen because the
/// adapter holds thirty-two file slots and eight pipes, so a program cannot
/// usefully poll more, and because the measured caller passes **one**.
const POLL_MAX: u64 = 16;
/// `struct pollfd` — `int fd`, `short events`, `short revents`.
const POLLFD_BYTES: usize = 8;

/// Answers `poll` for a hosted process — RFC 0055.
///
/// # What it waits for, and what it does not
///
/// `timeout == 0` is answered now, exactly. A **negative** timeout parks on the
/// console notification when the set names the console for reading and the
/// domain holds the input grant, and is otherwise answered now. A **positive**
/// timeout is answered as if it were zero.
///
/// That last is a stated limit rather than an oversight. This machine cannot
/// park a thread with a deadline: `BLOCK_ON_RETRY` carries a slot and no time.
/// The caller this exists for was *measured* before the limit was accepted —
/// every call it makes is one descriptor, `POLLIN` on standard input, with a
/// timeout of either `0` or `-1` and never anything else. The failure a
/// positive timeout can cause here is a caller that spins, not one that hangs.
/// The instant each domain's timed wait ends: `(domain, deadline)`.
///
/// **A wait that is retried is still one wait.** `BLOCK_ON_UNTIL` asks the
/// question again when it wakes, and the first version computed a fresh
/// deadline each time — so a caller that asked to wait fifty milliseconds
/// waited fifty milliseconds *per retry*, for ever, until the nucleus's
/// sixteen-retry backstop answered it `EAGAIN`. BusyBox printed
/// `poll: Resource temporarily unavailable` and abandoned the line, and that
/// backstop is the only reason it was a visible failure rather than a hang.
///
/// So the instant is recorded on the first park and consulted on every retry:
/// past it, the wait is over and the answer is whatever is ready now; before
/// it, the same deadline is named again.
static mut UNTIL: [(u32, u64); 4] = [(0, 0); 4];

fn until() -> &'static mut [(u32, u64); 4] {
    // SAFETY: single-threaded by construction, as `dispositions_of`.
    unsafe { &mut *core::ptr::addr_of_mut!(UNTIL) }
}

/// The deadline this domain's timed wait ends at, starting one if `nanos` is
/// given and none is running.
///
/// `None` means the wait is over — either it just expired, or this machine
/// cannot time it.
fn deadline_for(domain: u32, nanos: u64) -> Option<u64> {
    let table = until();
    if let Some(entry) = table.iter_mut().find(|entry| entry.0 == domain) {
        if bhaskix_sock::time::now() >= entry.1 {
            *entry = (0, 0);
            return None;
        }
        return Some(entry.1);
    }
    let deadline = deadline_in(nanos)?;
    let slot = table.iter_mut().find(|entry| entry.0 == 0)?;
    *slot = (domain, deadline);
    Some(deadline)
}

/// Forgets a domain's timed wait, for the paths that end one early.
fn forget_deadline(domain: u32) {
    if let Some(entry) = until().iter_mut().find(|entry| entry.0 == domain) {
        *entry = (0, 0);
    }
}

/// The deadline the next reply carries, if it is a `BLOCK_ON_UNTIL`.
///
/// **A static rather than a third element of every answer.** One reply in
/// hundreds names a deadline; widening `Answer` would have put a word nobody
/// reads on every path, and threading it through would have touched every
/// `return` in the dispatcher. Written immediately before the reply that uses
/// it and cleared by reading, so a stale one cannot ride out on the next.
static mut DEADLINE: u64 = 0;

fn park_deadline(deadline: u64) {
    // SAFETY: single-threaded by construction, as `dispositions_of`.
    unsafe { DEADLINE = deadline };
}

fn deadline_word() -> u64 {
    // SAFETY: as above. Taken rather than read: a deadline left behind would
    // ride out on the next reply, and the nucleus would arm a timer for a park
    // that did not ask for one.
    unsafe {
        let held = DEADLINE;
        DEADLINE = 0;
        held
    }
}

/// How long a caller is prepared to wait.
///
/// Named rather than a signed number, because the three cases are decided by
/// different arguments in `poll`, `ppoll` and `select` — milliseconds, a
/// `timespec`, a `timeval`, and a null pointer meaning for ever — and the
/// waiting underneath must not be written three times to find out.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wait {
    /// Answer immediately, whatever the answer is.
    Now,
    /// Wait until something is ready.
    Forever,
    /// Wait this many nanoseconds.
    For(u64),
}

fn answer_poll(request: &PersonalityCall) -> (u64, Answer) {
    // Milliseconds here, nanoseconds inside, because `ppoll` beside this one
    // brings a `timespec` and the waiting has to be the same waiting.
    let timeout = match request.third() as i64 {
        negative if negative < 0 => Wait::Forever,
        0 => Wait::Now,
        milliseconds => Wait::For((milliseconds as u64).saturating_mul(1_000_000)),
    };
    poll_with(request, request.first(), request.second(), timeout)
}

/// `ppoll(fds, nfds, timespec, sigmask, sigsetsize)` — RFC 0055.
///
/// `poll` with a `timespec` instead of milliseconds and a signal mask this
/// system has nothing to do with: **a parked hosted thread is not woken by a
/// signal here**, so a mask that changes which signals would interrupt the wait
/// changes nothing, and pretending to honour it would be the lie. The argument
/// is accepted and ignored, and that is said here rather than left to be
/// discovered.
fn answer_ppoll(request: &PersonalityCall) -> (u64, Answer) {
    let timeout = match timespec_at(request, request.third()) {
        Err(errno) => return (REPLY_VALUE, Answer::error(errno)),
        Ok(wait) => wait,
    };
    poll_with(request, request.first(), request.second(), timeout)
}

/// Reads a `timespec`, or [`Wait::Forever`] for a null pointer.
fn timespec_at(request: &PersonalityCall, at: u64) -> Result<Wait, i64> {
    if at == 0 {
        return Ok(Wait::Forever);
    }
    let mut spec = [0u8; 16];
    if !copy_in(request.domain, at, &mut spec) {
        return Err(-14); // EFAULT
    }
    let seconds = u64::from_le_bytes(spec[0..8].try_into().unwrap_or([0; 8]));
    let nanos = u64::from_le_bytes(spec[8..16].try_into().unwrap_or([0; 8]));
    if nanos >= 1_000_000_000 {
        return Err(-22); // EINVAL
    }
    Ok(
        match seconds.saturating_mul(1_000_000_000).saturating_add(nanos) {
            0 => Wait::Now,
            total => Wait::For(total),
        },
    )
}

/// Reads a `timeval` — `select`'s spelling, microseconds rather than nanos.
fn timeval_at(request: &PersonalityCall, at: u64) -> Result<Wait, i64> {
    if at == 0 {
        return Ok(Wait::Forever);
    }
    let mut spec = [0u8; 16];
    if !copy_in(request.domain, at, &mut spec) {
        return Err(-14); // EFAULT
    }
    let seconds = u64::from_le_bytes(spec[0..8].try_into().unwrap_or([0; 8]));
    let micros = u64::from_le_bytes(spec[8..16].try_into().unwrap_or([0; 8]));
    if micros >= 1_000_000 {
        return Err(-22); // EINVAL
    }
    Ok(
        match seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(micros.saturating_mul(1_000))
        {
            0 => Wait::Now,
            total => Wait::For(total),
        },
    )
}

fn poll_with(request: &PersonalityCall, at: u64, count: u64, timeout: Wait) -> (u64, Answer) {
    use bhaskix_personality::poll::{self, Condition};

    if count == 0 {
        return (REPLY_VALUE, Answer::ok(0));
    }
    if count > POLL_MAX {
        return (REPLY_VALUE, Answer::error(-22)); // EINVAL
    }
    let bytes = count as usize * POLLFD_BYTES;
    let mut entries = [0u8; POLL_MAX as usize * POLLFD_BYTES];
    let entries = &mut entries[..bytes];
    if !copy_in(request.domain, at, entries) {
        return (REPLY_VALUE, Answer::error(-14)); // EFAULT
    }

    // Whether the console has a byte, asked **once** however many descriptors
    // name it: it is a system call, and the answer cannot differ between two
    // entries of one array.
    let mut console_state: Option<(bool, bool)> = None;
    let mut ready = 0u64;
    let mut waits_on_console = false;
    let mut waits_on_socket = false;

    for index in 0..count as usize {
        let entry = &entries[index * POLLFD_BYTES..(index + 1) * POLLFD_BYTES];
        let fd = i32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let events = u16::from_le_bytes([entry[4], entry[5]]);
        let condition = condition_of(request, fd as u64, &mut console_state);
        if events & poll::POLLIN != 0 {
            if matches!(condition, Condition::Console { granted: true, .. }) {
                waits_on_console = true;
            }
            if matches!(condition, Condition::Socket { .. }) {
                waits_on_socket = true;
            }
        }
        let revents = poll::revents(events, condition);
        entries[index * POLLFD_BYTES + 6] = revents as u8;
        entries[index * POLLFD_BYTES + 7] = (revents >> 8) as u8;
        if revents != 0 {
            ready += 1;
        }
    }

    if ready == 0 && timeout != Wait::Now && !took_timed_wait(request.domain) {
        // **A positive timeout waits, and does not return early.** The caller
        // is parked on a deadline; a key arriving sooner does not cut it short,
        // because a thread here waits on one notification and the deadline is
        // on the other one. So this is at *least* as long as asked -- late,
        // never early -- and the set is re-examined when it expires. Answering
        // it instantly instead, which is what the first version did, tells a
        // caller that the interval elapsed when no time passed at all, and
        // turns its retry loop into a spin.
        // **A timed wait for a key wakes on the key** -- RFC 0057. Parked on
        // the console's own notification with the deadline armed on it, so the
        // keystroke and the timer arrive by the same door. Before this, a
        // positive timeout parked on a timer alone and a key pressed a
        // millisecond in was not noticed until the interval ended.
        if let Wait::For(nanos) = timeout
            && (waits_on_console || waits_on_socket)
            && let Some(deadline) = deadline_for(request.domain, nanos)
        {
            // The console wins a set naming both: only one notification can be
            // parked on, and the interactive one is the one a person is waiting
            // at. A datagram for such a set is noticed when the deadline
            // expires, which RFC 0058 states rather than hides.
            let bell = if waits_on_console {
                INPUT_WAKE
            } else {
                DATAGRAM_BELL
            };
            park_deadline(deadline);
            return (REPLY_BLOCK_ON_UNTIL, Answer::ok(bell));
        }
        if let Wait::For(nanos) = timeout
            && let Some(slot) = park_until(request.domain, nanos)
        {
            return (REPLY_BLOCK_ON_RETRY, Answer::ok(slot));
        }
        // Everything else is an **unbounded** wait: a negative timeout, and
        // equally one so long this machine cannot name the instant it ends. The
        // second is not a special case to be clever about -- a program that
        // asked to wait for days wants to be woken by what it is waiting for,
        // not at an arbitrary earlier moment this program picked.
        if waits_on_console {
            // The console is the thing being waited for. Park and be asked
            // again -- the same reply a blocking `read` gives, for the same
            // reason: this program has one thread and must not be the one that
            // sleeps.
            return (REPLY_BLOCK_ON_RETRY, Answer::ok(INPUT_WAKE));
        }
        // **A datagram is a thing to wait for too** -- RFC 0058 Part B, which
        // granted this program the bell `bin/ipd` rings and then, until now,
        // never waited on it. The constant sat unused and the compiler said so
        // in as many words; it shipped because the adapter was the one crate
        // `make clippy` did not cover.
        if waits_on_socket {
            return (REPLY_BLOCK_ON_RETRY, Answer::ok(DATAGRAM_BELL));
        }
        // Nothing here can be waited for. Answering now is a spin rather than a
        // park on a wake that would never come, and RFC 0055 says so.
    }
    // The wait, however it ended, is over: the next `poll` from this domain
    // starts its own.
    forget_deadline(request.domain);
    if !copy_out(request.domain, at, entries) {
        return (REPLY_VALUE, Answer::error(-14)); // EFAULT
    }
    (REPLY_VALUE, Answer::ok(ready))
}

/// What one descriptor is doing, for `poll` and `select` alike.
///
/// `console` caches the console's answer across the descriptors of one call:
/// asking is a system call, and it cannot honestly differ between two entries
/// of one array.
fn condition_of(
    request: &PersonalityCall,
    fd: u64,
    console: &mut Option<(bool, bool)>,
) -> bhaskix_personality::poll::Condition {
    use bhaskix_personality::file::Kind;
    use bhaskix_personality::poll::Condition;

    let Some(entry) = descriptor_row(request, fd) else {
        return Condition::Unknown;
    };
    match entry.kind {
        Kind::Console => {
            let (byte_waiting, granted) = match *console {
                Some(known) => known,
                None => {
                    let asked = call(
                        syscall::INVOKE,
                        handle_of(request.domain),
                        method::PEEK_INPUT,
                        [0, 0, 0, 0],
                    );
                    // A refusal here is the grant's refusal: the nucleus answers
                    // `InsufficientRights` for a domain nobody gave the console
                    // to, which is a different fact from "no byte" and must not
                    // be flattened into one.
                    let known = (
                        asked.status == status::OK && asked.args[0] != 0,
                        asked.status == status::OK,
                    );
                    *console = Some(known);
                    known
                }
            };
            Condition::Console {
                byte_waiting,
                granted,
            }
        }
        Kind::File | Kind::Directory | Kind::Proc => Condition::File,
        Kind::Pipe => pipe_condition(entry.handle, entry.readable, entry.writable),
        // **Asked, not guessed** -- RFC 0056. `pending` takes nothing, which is
        // the whole reason it exists: `recv_from` consumes, so a readiness
        // check built on it would eat a datagram every time a program wondered
        // whether there was one.
        //
        // An unbound socket has no service to ask -- `bind` is what claims the
        // capability -- and nothing can arrive on it, so it is quiet rather
        // than an error.
        Kind::Socket if entry.handle != u64::MAX => {
            let port = entry.size as u16;
            let waiting = if entry.offset != 0 {
                bhaskix_sock::udp6::Socket6::from_slot(entry.handle, port).pending()
            } else {
                bhaskix_sock::udp::Socket::from_slot(entry.handle, port).pending()
            };
            Condition::Socket {
                // A service that will not answer is not a datagram waiting.
                // Reporting it readable would send the caller into a `recvfrom`
                // that fails, which is worse than reporting it quiet.
                datagram_waiting: waiting.is_ok_and(|bytes| bytes > 0),
            }
        }
        Kind::Socket => Condition::Socket {
            datagram_waiting: false,
        },
        Kind::Epoll => Condition::Unanswered,
    }
}

/// `select(nfds, readfds, writefds, exceptfds, timeout)` — RFC 0055.
fn answer_select(request: &PersonalityCall) -> (u64, Answer) {
    let timeout = match timeval_at(request, request.fifth()) {
        Err(errno) => return (REPLY_VALUE, Answer::error(errno)),
        Ok(wait) => wait,
    };
    select_with(request, timeout)
}

/// `pselect6(nfds, readfds, writefds, exceptfds, timespec, sigmask)`.
///
/// `select` with a `timespec` and a signal mask, and the mask is ignored for
/// the reason [`answer_ppoll`] gives: nothing wakes a parked hosted thread here
/// except what it is waiting for and its own domain ending.
fn answer_pselect(request: &PersonalityCall) -> (u64, Answer) {
    let timeout = match timespec_at(request, request.fifth()) {
        Err(errno) => return (REPLY_VALUE, Answer::error(errno)),
        Ok(wait) => wait,
    };
    select_with(request, timeout)
}

/// The body both spellings share.
///
/// # Why the sets are read and written whole
///
/// `select` answers by **rewriting the caller's bitmaps in place**, so a
/// descriptor left set that is not ready is a caller told to act on something
/// that will block. Each set is therefore cleared as it is rebuilt, and written
/// back even when nothing is ready — which is the case a careless
/// implementation forgets, leaving yesterday's bits in place.
fn select_with(request: &PersonalityCall, timeout: Wait) -> (u64, Answer) {
    use bhaskix_personality::poll::{Watched, selected};

    let highest = request.first();
    let sets = [request.second(), request.third(), request.fourth()];
    if highest > SELECT_MAX {
        return (REPLY_VALUE, Answer::error(-22)); // EINVAL
    }
    let bytes = highest.div_ceil(8) as usize;
    let mut held = [[0u8; SELECT_BYTES]; 3];
    for (which, at) in sets.iter().enumerate() {
        if *at != 0 && !copy_in(request.domain, *at, &mut held[which][..bytes]) {
            return (REPLY_VALUE, Answer::error(-14)); // EFAULT
        }
    }
    let watching = |which: usize, fd: u64| {
        sets[which] != 0 && held[which][(fd / 8) as usize] & (1 << (fd % 8)) != 0
    };

    let mut answer = [[0u8; SELECT_BYTES]; 3];
    let mut console_state: Option<(bool, bool)> = None;
    let mut ready = 0u64;
    let mut waits_on_console = false;
    let mut waits_on_socket = false;
    for fd in 0..highest {
        let watched = Watched {
            read: watching(0, fd),
            write: watching(1, fd),
            except: watching(2, fd),
        };
        if !watched.read && !watched.write && !watched.except {
            continue;
        }
        let condition = condition_of(request, fd, &mut console_state);
        let out = selected(watched, condition);
        if out.invalid {
            // **The whole call, not the one descriptor.** This is where
            // `select` and `poll` differ rather than merely spelling the same
            // thing twice.
            return (REPLY_VALUE, Answer::error(-9)); // EBADF
        }
        if watched.read {
            if matches!(
                condition,
                bhaskix_personality::poll::Condition::Console { granted: true, .. }
            ) {
                waits_on_console = true;
            }
            if matches!(
                condition,
                bhaskix_personality::poll::Condition::Socket { .. }
            ) {
                waits_on_socket = true;
            }
        }
        for (which, set) in [out.read, out.write, out.except].iter().enumerate() {
            if *set {
                answer[which][(fd / 8) as usize] |= 1 << (fd % 8);
                ready += 1;
            }
        }
    }

    if ready == 0 && timeout != Wait::Now && !took_timed_wait(request.domain) {
        // Both wake sources when the console is what is being waited for, as
        // `poll` does and for the same reason -- RFC 0057.
        if let Wait::For(nanos) = timeout
            && (waits_on_console || waits_on_socket)
            && let Some(deadline) = deadline_for(request.domain, nanos)
        {
            // The console wins a set naming both: only one notification can be
            // parked on, and the interactive one is the one a person is waiting
            // at. A datagram for such a set is noticed when the deadline
            // expires, which RFC 0058 states rather than hides.
            let bell = if waits_on_console {
                INPUT_WAKE
            } else {
                DATAGRAM_BELL
            };
            park_deadline(deadline);
            return (REPLY_BLOCK_ON_UNTIL, Answer::ok(bell));
        }
        if let Wait::For(nanos) = timeout
            && let Some(slot) = park_until(request.domain, nanos)
        {
            return (REPLY_BLOCK_ON_RETRY, Answer::ok(slot));
        }
        if waits_on_console {
            return (REPLY_BLOCK_ON_RETRY, Answer::ok(INPUT_WAKE));
        }
        if waits_on_socket {
            return (REPLY_BLOCK_ON_RETRY, Answer::ok(DATAGRAM_BELL));
        }
    }
    forget_deadline(request.domain);
    for (which, at) in sets.iter().enumerate() {
        if *at != 0 && !copy_out(request.domain, *at, &answer[which][..bytes]) {
            return (REPLY_VALUE, Answer::error(-14)); // EFAULT
        }
    }
    (REPLY_VALUE, Answer::ok(ready))
}

/// The highest descriptor number `select` will look at.
///
/// `FD_SETSIZE`, which is what a Linux program's `fd_set` is, so a caller
/// passing the conventional 1024 is answered rather than refused. Nothing here
/// opens anything like that many; the cost is the bitmaps below.
const SELECT_MAX: u64 = 1024;
/// One `fd_set`, in bytes.
const SELECT_BYTES: usize = (SELECT_MAX / 8) as usize;

/// What a pipe end is doing, for [`answer_poll`].
///
/// **Which end it is comes from the descriptor and not from the handle.** A
/// pipe's handle is its ring's index and nothing else — both ends carry the
/// same one — and `Entry::readable`/`writable` is what tells them apart. This
/// was written first with the end packed into the handle's low bit, which
/// compiled, and would have reported the write end's room as the read end's
/// bytes on every second pipe.
fn pipe_condition(
    handle: u64,
    readable_end: bool,
    writable_end: bool,
) -> bhaskix_personality::poll::Condition {
    use bhaskix_personality::poll::Condition;

    // SAFETY: single-threaded by construction, as `dispositions_of`.
    let pipes = pipes_held();
    match pipes.get(handle as usize).and_then(Option::as_ref) {
        Some(pipe) => Condition::Pipe {
            bytes: pipe.held(),
            room: pipe.room(),
            readers: pipe.readers,
            writers: pipe.writers,
            readable_end,
            writable_end,
        },
        // The descriptor named a pipe slot holding nothing, which is this
        // program's own bookkeeping being wrong rather than the caller's.
        None => Condition::Unknown,
    }
}

/// A descriptor's whole row — what `poll` needs and [`descriptor_kind`] does
/// not carry.
///
/// The row rather than a widening tuple of its fields: this wanted the kind and
/// the handle, then which end of a pipe it is, then a socket's family and port.
/// Each arrived as one more element, and the fourth was where the tuple stopped
/// being readable.
fn descriptor_row(request: &PersonalityCall, fd: u64) -> Option<bhaskix_personality::file::Entry> {
    let descriptor = i32::try_from(fd).ok()?;
    let process = process_for(request.domain)?;
    process.descriptors.get(descriptor).copied()
}

/// `nanosleep(request, remain)`.
const NANOSLEEP: u64 = 35;
/// `clock_nanosleep(clock, flags, request, remain)`.
const CLOCK_NANOSLEEP: u64 = 230;
/// `TIMER_ABSTIME` — the requested time is a point, not a duration.
const TIMER_ABSTIME: u64 = 1;

/// `clock_nanosleep`, whose duration is its **third** argument.
fn answer_nanosleep(request: &PersonalityCall) -> (u64, Answer) {
    // An absolute deadline is refused rather than treated as a duration, which
    // would sleep until roughly the epoch plus now. `EINVAL` is what Linux
    // answers for an unsupported combination, and a caller can retry relative.
    if request.second() & TIMER_ABSTIME != 0 {
        return (REPLY_VALUE, Answer::error(-22)); // EINVAL
    }
    answer_nanosleep_relative(request, request.third())
}

/// The sleep both spellings share, given where each keeps its `timespec`.
///
/// # What it does not do
///
/// **It does not report the remaining time** in the caller's `remain` buffer.
/// Nothing here interrupts a sleep — there are no signals delivered to a parked
/// hosted thread — so a sleep either completes or its domain ends, and a
/// remainder would always be zero. Writing a zero would be indistinguishable
/// from a real short sleep, so nothing is written at all.
fn answer_nanosleep_relative(request: &PersonalityCall, at: u64) -> (u64, Answer) {
    // Already slept: this is the retry after the deadline fired.
    if took_timed_wait(request.domain) {
        return (REPLY_VALUE, Answer::ok(0));
    }
    let mut spec = [0u8; 16];
    if !copy_in(request.domain, at, &mut spec) {
        return (REPLY_VALUE, Answer::error(-14)); // EFAULT
    }
    let seconds = u64::from_le_bytes(spec[0..8].try_into().unwrap_or([0; 8]));
    let nanos = u64::from_le_bytes(spec[8..16].try_into().unwrap_or([0; 8]));
    if nanos >= 1_000_000_000 {
        return (REPLY_VALUE, Answer::error(-22)); // EINVAL
    }
    let total = seconds.saturating_mul(1_000_000_000).saturating_add(nanos);
    if total == 0 {
        return (REPLY_VALUE, Answer::ok(0));
    }
    match park_until(request.domain, total) {
        Some(slot) => (REPLY_BLOCK_ON_RETRY, Answer::ok(slot)),
        // No clock, or no slot left. Answering success without sleeping would
        // be a lie a caller cannot detect; `EINTR` is the honest one -- the
        // sleep did not complete, and a caller that cares retries.
        None => (REPLY_VALUE, Answer::error(-4)), // EINTR
    }
}

/// `wait4(pid, status, options, rusage)`.
const WAIT4: u64 = 61;
/// `fork()`.
const FORK: u64 = 57;
/// The name a forked child's domain is created under.
const FORK_NAME_LOW: u64 = u64::from_le_bytes(*b"forked\0\0");
/// Where the child's trampoline is written, in its own space.
///
/// Above everything a hosted program maps for itself: `mmap` hands out
/// addresses from `0x7000_0000_0000` and a program's own image sits far below
/// this. A collision would be a region copied over the trampoline, which is
/// why the address is out of both ranges rather than merely unlikely.
const FORK_TRAMPOLINE_AT: u64 = 0x0000_0000_3000_0000;

/// `execve(path, argv, envp)`.
const EXECVE: u64 = 59;
/// The authority to create a domain, granted at boot — RFC 0033 step 5.
const CONTROL: u64 = bhaskix_abi::adapter::CONTROL as u64;
/// Where the domain an `execve` is building is held, one at a time.
///
/// This program has one thread, so no second exec can be in flight while the
/// first is between its `SPAWN` and its reply. The handle is given back with
/// `DELETE` either way — a slot left occupied would refuse the *next* exec for
/// a reason that has nothing to do with it.
const CHILD: u64 = bhaskix_abi::adapter::CHILD as u64;
/// The name the new domain is created under, packed as `SPAWN` wants it.
const EXEC_NAME_LOW: u64 = u64::from_le_bytes(*b"execed\0\0");

/// The one program this personality carries inside itself.
///
/// **A synthetic path, and it stays one** — exactly as `/proc/self/*` is
/// synthetic, and for the same reason: what it answers is this adapter's own
/// business and no filesystem has, or should have, a file by that name. It was
/// the *only* path `execve` had until RFC 0059; it is now the only one that
/// does not go to the filesystem.
///
/// It is kept rather than deleted because it is the exec that works on a
/// machine with **no filesystem service at all**, which is four of this
/// project's five boot lanes. Deleting it would move RFC 0033 step 5's gate
/// from every lane to one, which is a loss of coverage disguised as a tidy-up.
const EXEC_PATH: &[u8; 11] = b"/bin/execed";

/// Where the exec'd program's code and stack land in its own space.
const EXEC_CODE_AT: u64 = 0x0000_0000_2000_0000;
const EXEC_STACK_AT: u64 = 0x0000_0000_2001_0000;
/// Where the string sits inside the image, as an offset from its start.
const EXEC_STRING_AT: u64 = 80;

/// Where a program read off the filesystem gets its stack — RFC 0059.
///
/// **Well clear of three things, and each one is a real collision avoided.**
/// Below it are the fixed addresses this adapter maps into a hosted domain:
/// [`EXEC_CODE_AT`], [`EXEC_STACK_AT`] and [`FORK_TRAMPOLINE_AT`]. Above it is
/// the `mmap` window, which starts at `layout::MMAP_FLOOR` and runs for a
/// terabyte — a stack inside it would be handed out again by the first
/// `mmap` whose draw landed there. And the program's own segments are checked
/// against this range at load time rather than assumed to be elsewhere,
/// because the program is a file and its link address is whatever it says.
const EXEC_STACK_BASE: u64 = 0x0000_6000_0000_0000;
/// Sixteen pages: fifteen to grow down into, and the top one holding the
/// initial process image the program is entered on.
const EXEC_STACK_PAGES: u64 = 16;

/// Where the staging object is mapped in **this** program's space.
///
/// Chosen after checking every other window this program owns, which is not a
/// formality: the obvious next address, `0x1D00_0000`, is where the kernel
/// puts this program's own **stack** (`LINUXD_STACK`), and attaching there
/// would have been discovered as something far stranger than a refused
/// mapping.
const STAGE_AT: u64 = 0x0000_0000_1A00_0000;
/// The staging slot, and how much it holds.
const STAGING: u64 = bhaskix_abi::adapter::STAGING as u64;
/// Sixteen pages, which is what the kernel granted and what `shared::create`
/// can make at most. It is the largest program a hosted `execve` can load.
const STAGING_BYTES: u64 = 16 * 4096;

/// The most pages one eager [`method::MAP_AT`] may ask for.
///
/// The kernel's `MAX_SUPERVISED_PAGES`. A segment larger than this is mapped
/// in several calls rather than refused — a 64-page bound on a *call* is not a
/// bound on a program.
const MAX_EAGER_PAGES: u64 = 64;

/// The program `/bin/execed` *is*: hand-assembled, and small on purpose.
///
/// It writes one line and ends its group. That is enough to prove what step 5
/// claims — an `execve` that ran the new image, in a new domain, with the pid
/// the old one had — and every byte of it is a Linux system call answered by
/// this program, so nothing about the test can pass through a path the
/// personality does not own.
///
/// `rdi` carries the address of its string, handed over by `SPAWN_THREAD`,
/// because a program built by a supervisor has no other way to be told where
/// anything is.
#[rustfmt::skip]
const EXEC_IMAGE: [u8; 96] = [
    // The template is copied to the stack first, because the page it lives in
    // is read-execute -- `W^X` is not suspended for a program's own data, so
    // the byte this patches has to be patched somewhere writable.
    0x48, 0x89, 0xfe,                    // mov rsi, rdi          ; the template
    0x48, 0x8b, 0x06,                    // mov rax, [rsi]
    0x48, 0x89, 0x44, 0x24, 0xe0,        // mov [rsp-32], rax
    0x48, 0x8b, 0x46, 0x08,              // mov rax, [rsi+8]
    0x48, 0x89, 0x44, 0x24, 0xe8,        // mov [rsp-24], rax
    0xb8, 0x27, 0x00, 0x00, 0x00,        // mov eax, 39           ; getpid
    0x0f, 0x05,                          // syscall
    0x04, 0x30,                          // add al, '0'           ; one digit
    0x88, 0x44, 0x24, 0xeb,              // mov [rsp-21], al      ; into the copy
    0x48, 0x8d, 0x74, 0x24, 0xe0,        // lea rsi, [rsp-32]
    0xbf, 0x01, 0x00, 0x00, 0x00,        // mov edi, 1            ; fd 1
    0xba, 0x0d, 0x00, 0x00, 0x00,        // mov edx, 13
    0xb8, 0x01, 0x00, 0x00, 0x00,        // mov eax, 1            ; write
    0x0f, 0x05,                          // syscall
    0x31, 0xff,                          // xor edi, edi          ; status 0
    0xb8, 0xe7, 0x00, 0x00, 0x00,        // mov eax, 231          ; exit_group
    0x0f, 0x05,                          // syscall
    0xeb, 0xfe,                          // jmp $                 ; unreachable
    // Padding to offset 80, where the template starts. `SPAWN_THREAD` hands
    // that address over in `rdi`, and it is the one number this blob's
    // arithmetic shares with the code that starts it.
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    // Offset 80: sixteen bytes, of which thirteen are written. The digit at
    // index 11 is the placeholder.
    b'e', b'x', b'e', b'c', b'e', b'd', b' ', b'p',
    b'i', b'd', b' ', b'?', b'\n', 0x00, 0x00, 0x00,
];

/// `openat(dirfd, path, flags, mode)`, and `open(path, flags, mode)`.
const OPENAT: u64 = 257;
/// `lseek(fd, offset, whence)`.
const LSEEK: u64 = 8;
/// `fstat(fd, statbuf)`.
const FSTAT: u64 = 5;
/// `newfstatat(dirfd, path, statbuf, flags)` — `stat` and `lstat` as every
/// current libc issues them.
const NEWFSTATAT: u64 = 262;
/// `getdents64(fd, buffer, count)`.
const GETDENTS64: u64 = 217;
/// `uname(buf)`.
const UNAME: u64 = 63;
/// `stat(path, buf)` — the older form BusyBox emits, not the `at` one.
const STAT: u64 = 4;
/// `lstat(path, buf)` — `stat` that does not follow a final symlink.
const LSTAT: u64 = 6;
/// `getuid()`.
///
/// **Answered, and the answer carries no authority** — [RFC 0031](../../../docs/rfc/0031-linux-compatibility-as-an-adapter.md)
/// is explicit that Linux UID 0 is not Bhaskix authority. A hosted program is
/// told it is uid 0 because that is what the programs expect to see and what
/// they compare against; nothing in this system reads it to decide anything,
/// and what a hosted process may do is what its domain holds.
const GETUID: u64 = 102;
/// `getppid()`.
const GETPPID: u64 = 110;
/// `prctl(option, ...)`.
const PRCTL: u64 = 157;
/// `brk(address)` — the oldest way a program grows its heap.
const BRK: u64 = 12;
/// `geteuid()` — the effective uid, which here is the real one.
const GETEUID: u64 = 107;
/// `access(path, mode)`.
const ACCESS: u64 = 21;
/// `writev(fd, iov, iovcnt)` — one write from several buffers.
const WRITEV: u64 = 20;
/// `tgkill(tgid, tid, signal)` — how a libc raises a signal at itself.
const TGKILL: u64 = 234;
/// `getcwd(buffer, size)`.
const GETCWD: u64 = 79;
/// How much address space a `brk` heap is reserved, lazily.
///
/// **Reserved once and grown into**, rather than extended a page at a time:
/// the region is mapped `MAP_LAZY`, so nothing is charged until the program
/// touches it, and the break moving is then arithmetic rather than a system
/// call into the nucleus. Four mebibytes because BusyBox's `sh` wants about
/// 140 KiB of it and this is the first hosted heap in the project's history --
/// a program that wants more is refused, and told so by `brk` answering with
/// the break it still has, which is what Linux does on failure.
const BRK_BYTES: u64 = 4 * 1024 * 1024;
/// `fcntl(fd, command, argument)`.
const FCNTL: u64 = 72;
/// `ioctl(fd, request, argument)`.
const IOCTL: u64 = 16;
/// `mkdirat(dirfd, path, mode)`.
const MKDIRAT: u64 = 258;
/// `unlinkat(dirfd, path, flags)`.
const UNLINKAT: u64 = 263;
/// `socket(family, type, protocol)`.
const SOCKET: u64 = 41;
/// `bind(fd, sockaddr, length)`.
const BIND: u64 = 49;
/// `sendto(fd, buffer, length, flags, sockaddr, addrlen)`.
const SENDTO: u64 = 44;
/// `recvfrom(fd, buffer, length, flags, sockaddr, addrlen)`.
const RECVFROM: u64 = 45;

/// The protocol service, granted by the kernel — RFC 0005 step 9.
///
/// **Slot 88, and the number is what was left.** This program's CSpace is
/// crowded: 0 and 1 are its endpoint and report, 2 the fault page, 3 the
/// console, 4 to 19 its futex wakes, 20 to 23 the supervisor control, the
/// child handle, the root directory and the lent page; hosted domains climb
/// from 24 and open files fall from 127. Eighty-eight to ninety-five is the
/// gap between them, and two attempts at tidier numbers were refused by
/// `install_at` before this one.
const NETWORK: u64 = bhaskix_abi::adapter::NETWORK as u64;
/// One page of this program's own memory, which datagrams cross in.
///
/// `SEND_TO` drains its payload from **offset zero** of a memory object, so
/// the report page cannot serve: its first bytes are the `mmap` trace records.
const PAYLOAD: u64 = bhaskix_abi::adapter::PAYLOAD as u64;
/// Where that page is mapped while bytes are staged in it.
const PAYLOAD_AT: u64 = 0x0000_0000_1B00_0000;
/// Where a hosted socket's capability lands: 90 up to 95, six of them.
const SOCKET_SLOT: u64 = bhaskix_abi::adapter::SOCKETS as u64;
/// The datagram bell — RFC 0058 Part B, `READ` so this program may wait for a
/// datagram and cannot claim one arrived.
///
/// Slot 95, the one the socket pool gave up. There was no gap: 0–24 are fixed
/// grants, 25 upward is where the kernel allocates a handle per hosted domain,
/// 88 and 89 are the network and its page, 90 up is the socket pool and 96 up
/// is the file pool counting down from 127.
const DATAGRAM_BELL: u64 = bhaskix_abi::adapter::DATAGRAM_BELL as u64;
/// How many sockets one machine's hosted programs may hold at once.
///
/// Five, because five is what the CSpace has left — and a limit met as `EMFILE`
/// is a limit a program can act on, which is why it is checked rather than
/// discovered by an `install_at` failing somewhere less legible.
///
/// **Six until 2026-08-28**, when RFC 0058's datagram bell took slot 95. It
/// costs nothing real: `bin/ipd` serves four sockets in total, so five slots
/// here were already one more than the service can fill. The bell was put at
/// 90 first — the *first* of these — and the collision presented as a hosted
/// `bind` answering `EADDRINUSE`, which is the third slot collision in this
/// CSpace in one day and the second found by a boot rather than by reading the
/// map.
const SOCKETS: usize = bhaskix_abi::adapter::SOCKET_COUNT;

/// Which socket slots are taken.
static mut SOCKET_HELD: [bool; SOCKETS] = [false; SOCKETS];

/// Takes a free socket slot, or `None` when all six are in use.
fn claim_socket_slot() -> Option<u64> {
    // SAFETY: single-threaded by construction, as `claim_file_slot`.
    let held = unsafe { &mut *core::ptr::addr_of_mut!(SOCKET_HELD) };
    let index = held.iter().position(|taken| !*taken)?;
    held[index] = true;
    Some(SOCKET_SLOT + index as u64)
}

/// Gives a socket slot back: tells the service, then drops the capability.
///
/// **Both halves, and dropping the capability alone is not enough.**
/// `bin/ipd` holds four sockets in a table of its own, and nothing tells it a
/// client has stopped caring: a `DELETE` here takes the adapter's name for the
/// socket away and leaves the service's entry, its port, and one of its four
/// slots occupied until the machine restarts.
///
/// That is not a hypothetical either. The socket probe leaked one, it was the
/// fourth of four, and the *shell* could no longer bind -- a leak in a hosted
/// program surfacing as an unrelated program losing its network, which is the
/// failure shape a shared adapter produces (RFC 0031 I5). The first attempt at
/// a fix reclaimed the slot without telling the service and changed nothing,
/// which is how the difference between the two halves got noticed.
/// **The mirrored outcome words must still match the ABI's.**
///
/// `bhaskix-personality` may not depend on `bhaskix-abi` — they share a layer
/// and `tools/check-deps.py` enforces that dependencies point downward — so it
/// keeps its own copy of the socket service's answers. This program legitimately
/// speaks both, so it is where the two are held together: a drift is a build
/// failure here rather than a wrong errno delivered to a hosted program.
const _: () = {
    use bhaskix_personality::socket::outcome;
    assert!(outcome::OK == bhaskix_abi::socket::OK);
    assert!(outcome::NO_PORT == bhaskix_abi::socket::NO_PORT);
    assert!(outcome::GONE == bhaskix_abi::socket::GONE);
    assert!(outcome::EMPTY == bhaskix_abi::socket::EMPTY);
    assert!(outcome::NOWHERE == bhaskix_abi::socket::NOWHERE);
    assert!(outcome::NO_NETWORK == bhaskix_abi::socket::NO_NETWORK);
    assert!(outcome::WRONG_FAMILY == bhaskix_abi::socket::WRONG_FAMILY);
    assert!(outcome::NO_SOCKET == bhaskix_abi::socket::NO_SOCKET);
};

/// Sockets this program could not persuade the service to close.
///
/// Always zero. A non-zero value is a port held for the rest of the boot by a
/// program that no longer exists.
static mut CLOSES_REFUSED: u64 = 0;

/// The most attempts any one close has needed, successful or not.
///
/// The retry above allows four. This says how much of that budget the machine
/// has actually used, which is the difference between "the retry is working"
/// and "the retry is one attempt from not working".
static mut CLOSE_ATTEMPTS_WORST: u64 = 0;

/// Where the socket record lives in the page the kernel reads.
const SOCKET_RECORD_AT: u64 = REPORT_AT + report::SOCKET_AT as u64;

/// Publishes both numbers where the boot report can read them.
///
/// **This is the wiring that was missing.** `closes_refused` has existed since
/// RFC 0058 with the doc comment "for the boot report" and no caller, so the
/// counter kept specifically to make a lost port visible was never printed.
fn write_socket_record() {
    // SAFETY: inside the page `ATTACH` mapped from this program's own object,
    // at an offset `personality::report` asserts is before the scratch area.
    unsafe {
        core::ptr::write_volatile(SOCKET_RECORD_AT as *mut u64, CLOSES_REFUSED);
        core::ptr::write_volatile((SOCKET_RECORD_AT + 8) as *mut u64, CLOSE_ATTEMPTS_WORST);
    }
}

/// How many closes were refused, for the boot report.
#[must_use]
pub fn closes_refused() -> u64 {
    // SAFETY: single-threaded by construction, as `dispositions_of`.
    unsafe { CLOSES_REFUSED }
}

fn release_socket_slot(slot: u64) {
    // The family does not matter for closing -- both crates send the same
    // message to the same service -- so the v4 constructor serves for either.
    //
    // **Retried, because the answer used to be discarded.** A refused close
    // leaves the binding in `bin/ipd` while this program marks its own slot
    // free: the port stays held by a program that is gone, and the next caller
    // to want it is told `EADDRINUSE` for a reason that has nothing to do with
    // it. The service refuses when it is busy, not when it disagrees, so the
    // refusal is transient and a few attempts is the whole fix.
    //
    // Found as a one-in-nine intermittent in the reclaim gate: everything the
    // gate asserted about *learning* of the dead domain was true, and the close
    // that followed simply did not land.
    let mut closed = false;
    let mut attempts = 0u64;
    for _ in 0..4 {
        attempts += 1;
        if bhaskix_sock::udp::Socket::from_slot(slot, 0)
            .close()
            .is_ok()
        {
            closed = true;
            break;
        }
    }
    if !closed {
        // Counted rather than shrugged at: a socket this program believes it
        // gave back and the service still holds is a port lost for the boot.
        // SAFETY: single-threaded by construction, as `dispositions_of`.
        unsafe { CLOSES_REFUSED += 1 };
    }
    // **And how hard it was**, which nothing recorded. A close that succeeded
    // on its fourth attempt and one that succeeded on its first are the same
    // silence to every gate here, and the difference between them is the
    // entire margin this retry has. If the failing boots turn out to be
    // spending all four, the loop is too short; if they are spending one and
    // failing anyway, the refusal is not congestion and the retry was never
    // the fix.
    // SAFETY: as above.
    unsafe {
        if attempts > CLOSE_ATTEMPTS_WORST {
            CLOSE_ATTEMPTS_WORST = attempts;
        }
    }
    write_socket_record();
    let _ = call(syscall::INVOKE, slot, method::DELETE, [0; 4]);
    let index = (slot - SOCKET_SLOT) as usize;
    // SAFETY: as `claim_socket_slot`.
    let held = unsafe { &mut *core::ptr::addr_of_mut!(SOCKET_HELD) };
    if let Some(taken) = held.get_mut(index) {
        *taken = false;
    }
}
/// `newfstatat`'s flag meaning "the path is empty; stat the descriptor" —
/// which is how a libc turns `fstat` into this call.
///
/// Read from this machine's `/usr/include/linux/fcntl.h`, not recalled, as
/// was [`AT_FDCWD`](answer_newfstatat)'s `-100` beside it.
const AT_EMPTY_PATH: u64 = 0x1000;
/// `AT_FDCWD` — resolve against the current directory rather than a descriptor.
///
/// At module scope since 2026-08-27, because `stat` and `lstat` name it too.
const AT_FDCWD: u64 = (-100i64) as u64;
/// `AT_SYMLINK_NOFOLLOW` — what makes `lstat` different from `stat`.
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const OPEN: u64 = 2;
/// `read(fd, buffer, count)`.
const READ: u64 = 0;
/// `close(fd)`.
const CLOSE: u64 = 3;
/// `dup(fd)`, `dup2(old, new)`, `dup3(old, new, flags)`.
const DUP: u64 = 32;
const DUP2: u64 = 33;
const DUP3: u64 = 292;

/// `pipe2(fds, flags)`, and `pipe(fds)`.
const PIPE2: u64 = 293;
const PIPE: u64 = 22;

/// How many pipes this adapter can hold at once.
///
/// Eight, and each is half a kilobyte of ring — four kilobytes of this
/// program's memory whether or not anything uses them, because a server that
/// cannot allocate pays for its tables up front. A ninth `pipe2` is `EMFILE`,
/// which is a Linux answer a program already handles.
const PIPES: usize = 8;

/// The pipes, and who is asleep on each.
///
/// **A pipe is a ring buffer in this program**, not a kernel object: both ends
/// belong to processes this program serves, so nothing about joining them needs
/// authority it does not already hold. The moment a pipe became an `Endpoint`
/// the kernel would be holding state for a dialect it does not interpret.
static mut PIPES_HELD: [Option<Pipe>; PIPES] = [None; PIPES];

/// Which futex wake slot a reader is parked on, per pipe, plus one.
///
/// **The same notification pool the futex uses**, because parking a thread is
/// parking a thread: a reader waiting for bytes and a thread waiting on a word
/// want the same mechanism, and having two would mean two ways to get the
/// wake-up wrong. Zero means nobody is waiting.
static mut PIPE_WAITERS: [u32; PIPES] = [0; PIPES];

/// The directory a hosted process's `/` **is** — RFC 0033 step 6.
///
/// A badged endpoint capability to the filesystem service, granted by the
/// kernel once that service exists. **This is a hosted process's whole
/// filesystem**: it can open what is inside this directory and cannot name
/// anything above it, because it holds nothing that names anything above it.
/// That is `chroot` by construction rather than by check.
///
/// `READ` and `DERIVE` and no `WRITE`, so a hosted program opening a file for
/// writing is told `EROFS` rather than being lied to.
const ROOT_DIR: u64 = bhaskix_abi::adapter::ROOT_DIR as u64;
/// Where a page lent by the filesystem service lands, one at a time.
const LENT: u64 = bhaskix_abi::adapter::LENT as u64;
/// Where a lent page is mapped in this program's own space while it is read.
///
/// **Not `0x1D00_0000`, which is this program's own stack** — eight pages of
/// it, mapped by the kernel before this program ever ran. `ATTACH` refused the
/// overlap with `SlotUnavailable`, which is the one answer it gives for every
/// unusable address on purpose, and the refusal reached a hosted program as a
/// `read` that returned `EFAULT`.
const LENT_AT: u64 = 0x0000_0000_1C00_0000;

/// The slots open files are held in, allocated **downward** from the top.
///
/// The kernel allocates hosted-domain handles *upward* from slot 25, and this
/// allocates from 127 down, so the two cannot meet: sixty-four domains and
/// thirty-two open files is ninety-six of a hundred and twenty-eight. Written
/// as a pair of directions rather than as two ranges, because a range is a
/// number somebody will change on one side only.
const FILE_SLOT_TOP: u64 = bhaskix_abi::adapter::FILE_TOP as u64;
const FILE_SLOTS: usize = bhaskix_abi::adapter::FILE_COUNT;

/// Which file slots are taken.
static mut FILE_HELD: [bool; FILE_SLOTS] = [false; FILE_SLOTS];

/// Whether the staging object has been attached yet — RFC 0059.
///
/// `ATTACH` refuses an address that is already mapped, with the same
/// `SlotUnavailable` it gives for every unusable address, so a second `execve`
/// would be refused for a reason that has nothing to do with it. That exact
/// bug was paid for once already, on the datagram payload page, and the flag
/// below is the same fix.
static mut STAGE_MAPPED: bool = false;

/// The `argv` and `envp` of the exec in flight.
///
/// **A static rather than a local**, and the reason is arithmetic: this
/// program's stack is eight pages, and `Arguments` plus the initial image page
/// plus two arrays of sixty-four slices is over eight kilobytes in one call
/// chain. The kernel gives a server exactly one outstanding reply, so there is
/// no second caller inside `answer_execve` and no lock here could be
/// contended — the same promise every other table in this program makes.
static mut EXEC_ARGUMENTS: bhaskix_personality::exec::Arguments =
    bhaskix_personality::exec::Arguments::new();

/// The page the initial process image is built in, for the same reason.
static mut EXEC_IMAGE_PAGE: [u8; bhaskix_personality::exec::IMAGE_BYTES] =
    [0; bhaskix_personality::exec::IMAGE_BYTES];

/// How many argument or environment strings one exec may carry.
const ARGUMENT_SLOTS: usize = bhaskix_personality::exec::MAX_STRINGS;

/// The vectors of the exec in flight.
fn exec_arguments() -> &'static mut bhaskix_personality::exec::Arguments {
    // SAFETY: single-threaded, as the note above.
    unsafe { &mut *core::ptr::addr_of_mut!(EXEC_ARGUMENTS) }
}

/// The page the initial process image is built in.
fn exec_image_page() -> &'static mut [u8; bhaskix_personality::exec::IMAGE_BYTES] {
    // SAFETY: single-threaded, as the note above.
    unsafe { &mut *core::ptr::addr_of_mut!(EXEC_IMAGE_PAGE) }
}

/// Takes a free slot for an open file, or `None` when there are none left.
fn claim_file_slot() -> Option<u64> {
    // SAFETY: single-threaded by construction, as `dispositions_of`.
    let held = file_held();
    let index = held.iter().position(|taken| !*taken)?;
    held[index] = true;
    Some(FILE_SLOT_TOP - index as u64)
}

/// Gives a file slot back, and drops whatever capability was in it.
fn release_file_slot(slot: u64) {
    let _ = call(syscall::INVOKE, slot, method::DELETE, [0; 4]);
    let index = (FILE_SLOT_TOP - slot) as usize;
    // SAFETY: as `claim_file_slot`.
    let held = file_held();
    if let Some(taken) = held.get_mut(index) {
        *taken = false;
    }
}

/// `futex(address, operation, value, ...)`.
const FUTEX: u64 = 202;
/// `write(fd, buffer, count)`.
const WRITE: u64 = 1;
/// As much of one `write` as this program will carry in a call.
///
/// A hosted program that writes more is told how much was taken, which is what
/// a short write means in Linux and what every correct caller already handles.
/// The bound is the scratch area's, because that is what the copy travels
/// through.
const WRITE_BYTES: usize = 256;
/// `gettid()`.
const GETTID: u64 = 186;
/// `sched_yield()`.
const SCHED_YIELD: u64 = 24;
/// `exit(status)` — this thread only.
const EXIT: u64 = 60;
/// `exit_group(status)` — every thread of the group.
const EXIT_GROUP: u64 = 231;
/// `arch_prctl(code, addr)`.
const ARCH_PRCTL: u64 = 158;
/// `ARCH_SET_FS`, the one code that matters.
const ARCH_SET_FS: u64 = 0x1002;

/// `clone(flags, stack, parent_tid, child_tid, tls)` — five arguments.
const CLONE: u64 = 56;
/// `rt_sigreturn()` — no arguments, and needs the interrupted stack pointer.
const RT_SIGRETURN: u64 = 15;

/// Where the fault exchange page sits in this program's own space.
const FAULTS: u64 = bhaskix_abi::adapter::FAULTS as u64;
const FAULTS_AT: u64 = 0x0000_0000_1F00_0000;
/// Bytes per fault slot, and how many faults were handed over.
const FAULT_SLOT_BYTES: u64 = 512;

/// `rt_sigaction(sig, act, oldact, sigsetsize)`.
const RT_SIGACTION: u64 = 13;
/// `sigaltstack(ss, old_ss)`.
const SIGALTSTACK: u64 = 131;

/// What each hosted domain has asked for, by domain id.
///
/// **This is the personality's own state, and its being here rather than in
/// the nucleus is the whole of RFC 0005's "where it lives".** A bug in this
/// table is a bug in one ring 3 program that holds one endpoint, two pages
/// and a handle to each domain it hosts. It was a kernel table until
/// 2026-08-20.
static mut DISPOSITIONS: [Dispositions; limits::MAX_DOMAINS] =
    [const { Dispositions::new() }; limits::MAX_DOMAINS];

/// Who is asleep in a futex, by wake slot.
///
/// Same shape and same justification as [`DISPOSITIONS`]: one thread, one
/// request at a time, so the compare-and-park below is atomic against every
/// other futex operation without a lock. That is not a happy accident — it is
/// the reason a futex can live in a single-threaded server at all.
static mut SLEEPERS: [Sleeper; WAKES] = [Sleeper {
    domain: 0,
    address: 0,
    arrived: 0,
}; WAKES];

/// Counts arrivals, so a `WAKE` of one takes the oldest sleeper.
static mut ARRIVALS: u64 = 0;

/// Every hosted process this adapter serves — [RFC 0033](../../../docs/rfc/0033-what-a-hosted-process-is.md).
///
/// **The identity of a Linux process lives here, in ring 3, and the domain is
/// only what it runs in.** The arithmetic — which pid, what survives an exec,
/// how a status is encoded — is `bhaskix_personality::process`, host-tested
/// and with no way to name a capability. This is where it is kept.
///
/// Same `static mut` justification as [`DISPOSITIONS`]: one thread, one
/// request at a time.
static mut PROCESSES: Processes = Processes::new();

/// How many times each domain slot has been handed to this program.
///
/// **A domain id is reused, and a record found by id alone would answer for
/// whoever holds the slot now.** The kernel says when that happens — the
/// `FORGET` message is exactly "this slot is somebody else now" — so this
/// counter is bumped there, and a record is matched on the pair. The counter
/// is this program's own: it need not agree with the kernel's generation, only
/// change when the kernel says the slot did.
static mut INCARNATION: [u32; limits::MAX_DOMAINS] = [0; limits::MAX_DOMAINS];

/// The process record for a hosted domain, admitted on first sight.
///
/// **Admission is lazy because there is no other moment to do it in.** Nothing
/// tells this program that a hosted domain has started; the first foreign call
/// is the introduction, and a program that makes no call has no record and
/// needs none. A table that is full answers `None`, and the caller turns that
/// into the refusal Linux has for it.
/// How many records `process_for` has admitted, and how many it found.
///
/// See `bhaskix_personality::report::PROCESS_AT` for why these exist. Written
/// to the report page so the boot can be asked rather than reasoned about.
static ADMITTED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static FOUND: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static LAST_ADMITTED_DOMAIN: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);
static LAST_ADMITTED_HELD: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Where the process record sits.
const PROCESS_RECORD_AT: u64 = REPORT_AT + report::PROCESS_AT as u64;

/// Publishes what `process_for` has been doing.
fn trace_process() {
    use core::sync::atomic::Ordering::Relaxed;
    let words = [
        ADMITTED.load(Relaxed),
        FOUND.load(Relaxed),
        LAST_ADMITTED_DOMAIN.load(Relaxed),
        LAST_ADMITTED_HELD.load(Relaxed),
    ];
    // A loop rather than four statements, because each one would be a line of
    // `unsafe` against this program's budget and they say the same thing.
    //
    // SAFETY: inside the page `ATTACH` mapped from this program's own object,
    // past the socket record and before the scratch -- the layout is asserted
    // in `bhaskix_personality::report`.
    unsafe {
        for (index, word) in words.into_iter().enumerate() {
            core::ptr::write_volatile((PROCESS_RECORD_AT + index as u64 * 8) as *mut u64, word);
        }
    }
}

fn process_for(domain: u32) -> Option<&'static mut Process> {
    // SAFETY: single-threaded by construction, as `dispositions_of`.
    let incarnations = incarnation();
    let generation = incarnations[domain as usize % limits::MAX_DOMAINS];
    // SAFETY: as above.
    let processes = processes();
    if processes.by_domain(domain, generation).is_none() {
        ADMITTED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        LAST_ADMITTED_DOMAIN.store(u64::from(domain), core::sync::atomic::Ordering::Relaxed);
        // Parent zero: nothing hosted started it, so nothing will wait for it.
        // When `fork` and `execve` exist, the parent is the process that asked.
        let pid = processes.admit(0, domain, generation).ok()?;
        // Drawn here, at the one place a process first exists.
        if let Some(fresh) = processes.by_pid_mut(pid) {
            fresh.mmap_next = drawn_base();
        }
        // **The three descriptors a Linux program is entitled to assume.** It
        // does not open standard output; it writes to descriptor 1 and is
        // entitled to find something there. Without them the first file a
        // program opened became descriptor *zero* — its own standard input —
        // which is the kind of wrong that runs for a while and then reads a
        // file when it meant to read a terminal.
        processes
            .by_pid_mut(pid)?
            .descriptors
            .install_standard(CONSOLE);
        // How many descriptors the fresh record actually ended up holding. The
        // reclaim gate's specimen showed a socket landing on descriptor 1, and
        // a table with the three standard descriptors installed hands out 3 --
        // so this is the number that says whether that record had stdio.
        LAST_ADMITTED_HELD.store(
            processes
                .by_pid_mut(pid)
                .map_or(0, |fresh| fresh.descriptors.open_count() as u64),
            core::sync::atomic::Ordering::Relaxed,
        );
        trace_process();
    } else {
        FOUND.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        trace_process();
    }
    processes.by_domain_mut(domain, generation)
}

/// A base for a hosted process's `mmap` region, drawn from the hardware.
///
/// [security.md](../../docs/security.md) §1 gap 3. `RDRAND` is unprivileged, so
/// a ring 3 program can draw for itself without holding anything — which is
/// [RFC 0021](../../docs/rfc/0021-unpredictability.md)'s finding, and why there
/// is no capability to ask for.
///
/// **A machine with no entropy gets the floor, and the boot says so.** Refusing
/// to start a hosted process would be a worse answer than starting one with a
/// known layout: the layout is a hardening measure, not a correctness one, and
/// a machine that cannot randomise can still run programs. What it must not do
/// is *pretend* — so the kernel's `linux aslr` line reports which world the
/// machine is in, read off the address the hosted program actually received
/// rather than from a flag this program sets about itself. A boot gate accepts
/// either line and refuses silence.
fn drawn_base() -> u64 {
    match bhaskix_rand::u64() {
        Some(draw) => layout::base_from(draw),
        None => layout::MMAP_FLOOR,
    }
}

/// Takes `bytes` from a process's own `mmap` region.
///
/// Answers `None` when the record has no base — a record admitted without a
/// draw, which cannot happen through `admit_hosted` and is refused here rather
/// than silently allocating from the bottom of the address space — or when the
/// region would run past its window.
fn advance_mapping(domain: u32, bytes: u64) -> Option<u64> {
    // Through `process_for`, which is the one door that creates a record and
    // draws its base. Looking the record up directly was the first version and
    // was wrong twice over: it indexed `incarnation` without the mask
    // `process_for` applies, and it refused an `mmap` that arrived *before* any
    // other call from that domain — which is exactly what a program that maps
    // memory first does, and what the memory probe does.
    let process = process_for(domain)?;
    if process.mmap_next == 0 {
        return None;
    }
    let address = process.mmap_next;
    // The window is 1 TiB and a hosted process that walked out of it has asked
    // for more address space than this adapter will hand one program.
    let next = address.checked_add(bytes)?;
    if next > layout::ceiling() + (1u64 << 40) {
        return None;
    }
    process.mmap_next = next;
    Some(address)
}

/// The sleeper table, borrowed for the length of one request.
fn sleepers() -> &'static mut [Sleeper; WAKES] {
    // SAFETY: single-threaded by construction, as `dispositions_of`.
    unsafe { &mut *core::ptr::addr_of_mut!(SLEEPERS) }
}

// ---------------------------------------------------------------------------
// One accessor per static, and every reader goes through it.
//
// **This is the `unsafe` cap made structural rather than promised.** This
// program is the largest concentration of authority in the system --
// `security.md` §1's T11 note lists what it holds -- and its `unsafe` budget
// went 42 -> 85 in a single day while RFC 0033 was being built. The reassessment
// of 2026-08-20 named it gap 2 and observed that "the concentration point" is a
// property with no completion state, so the actionable thing is the number.
//
// Twenty of those lines were the *same* line: `&mut` to a `static mut`, written
// out wherever a table was wanted. Each one restated an invariant that is a
// property of the whole program -- **this server is single-threaded, so there is
// no second borrower to race with** -- and twenty restatements of one invariant
// is twenty places to get it wrong and one place nobody looks.
//
// So the promise is made once per table, here, and the rest of the file asks by
// name. It is the argument [RFC 0014](../../docs/rfc/0014-driver-framework.md)
// made for `register_block!` and M8-02 measured: forty-two blocks making the
// same promise became two, and the kernel's `unsafe` count *fell*.
//
// The invariant, stated once for all of them: `bin/linuxd` runs one thread. It
// answers one foreign call at a time, and every accessor below hands out a
// borrow that ends before the next call begins. If this program ever grows a
// second thread, every function here becomes wrong at the same moment -- which
// is the point of them being together.
// ---------------------------------------------------------------------------

/// The process table.
fn processes() -> &'static mut Processes {
    // SAFETY: single-threaded, as the note above.
    unsafe { &mut *core::ptr::addr_of_mut!(PROCESSES) }
}

/// The pipes this adapter holds for hosted processes.
fn pipes_held() -> &'static mut [Option<Pipe>; PIPES] {
    // SAFETY: single-threaded, as the note above.
    unsafe { &mut *core::ptr::addr_of_mut!(PIPES_HELD) }
}

/// Which thread is parked on which pipe.
fn pipe_waiters() -> &'static mut [u32; PIPES] {
    // SAFETY: single-threaded, as the note above.
    unsafe { &mut *core::ptr::addr_of_mut!(PIPE_WAITERS) }
}

/// Who is waiting in `wait4`, and for whom.
fn waiters() -> &'static mut [(u32, u32); 4] {
    // SAFETY: single-threaded, as the note above.
    unsafe { &mut *core::ptr::addr_of_mut!(WAITERS) }
}

/// Which open-file slots are taken.
fn file_held() -> &'static mut [bool; FILE_SLOTS] {
    // SAFETY: single-threaded, as the note above.
    unsafe { &mut *core::ptr::addr_of_mut!(FILE_HELD) }
}

/// How many times each domain slot has been reused.
fn incarnation() -> &'static mut [u32; limits::MAX_DOMAINS] {
    // SAFETY: single-threaded, as the note above.
    unsafe { &mut *core::ptr::addr_of_mut!(INCARNATION) }
}

/// The supervisor handle held for each hosted domain.
fn handles() -> &'static mut [u32; limits::MAX_DOMAINS] {
    // SAFETY: single-threaded, as the note above.
    unsafe { &mut *core::ptr::addr_of_mut!(HANDLES) }
}

/// How many notifications have arrived.
fn arrivals() -> &'static mut u64 {
    // SAFETY: single-threaded, as the note above.
    unsafe { &mut *core::ptr::addr_of_mut!(ARRIVALS) }
}

/// Answers a hosted `pipe2` — RFC 0033 step 7.
///
/// Two descriptors into one ring: the low one reads, the high one writes,
/// which is the order every program that has ever called `pipe` assumes. The
/// ring is claimed from this program's own table and named by both rows, so
/// closing one end is a count rather than a teardown.
fn answer_pipe(request: &PersonalityCall, at: u64, flags: u64) -> Answer {
    use bhaskix_personality::file::{Entry, Kind, open};

    let close_on_exec = flags & open::CLOEXEC != 0;
    // SAFETY: single-threaded by construction, as `dispositions_of`.
    let pipes = pipes_held();
    let Some(index) = pipes.iter().position(Option::is_none) else {
        return Answer::error(-24); // EMFILE
    };
    pipes[index] = Some(Pipe::new());

    let row = |readable: bool| Entry {
        handle: index as u64,
        // A pipe is not on any filesystem, so it has no inode to report and
        // says so rather than borrowing its ring's index for one.
        inode: 0,
        kind: Kind::Pipe,
        close_on_exec,
        offset: 0,
        size: 0,
        readable,
        writable: !readable,
    };
    let Some(process) = process_for(request.domain) else {
        pipes[index] = None;
        return Answer::error(-11);
    };
    let Ok(reader) = process.descriptors.insert(row(true), 0) else {
        pipes[index] = None;
        return Answer::error(-24);
    };
    let Ok(writer) = process.descriptors.insert(row(false), 0) else {
        let _ = process.descriptors.close(reader);
        pipes[index] = None;
        return Answer::error(-24);
    };

    // The pair goes back in the caller's memory, which is what makes this call
    // need a `Domain` capability at all.
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&reader.to_le_bytes());
    bytes[4..].copy_from_slice(&writer.to_le_bytes());
    if !copy_out(request.domain, at, &bytes) {
        let _ = process.descriptors.close(reader);
        let _ = process.descriptors.close(writer);
        pipes[index] = None;
        return Answer::error(-14); // EFAULT
    }
    Answer::ok(0)
}

/// Reads from a pipe, parking the caller when there is nothing yet.
///
/// **Three answers, and choosing wrongly between them breaks a shell.** Bytes,
/// if there are any. End of file — zero — only when no writer remains, because
/// a reader told "finished" at its producer's first pause ends the pipeline.
/// Otherwise the caller *waits*, on the same notification pool a `futex`
/// sleeper uses, and a writer signals it.
fn read_from_pipe(
    request: &PersonalityCall,
    index: usize,
    buffer: u64,
    count: u64,
) -> (u64, Answer) {
    // SAFETY: single-threaded by construction, as elsewhere here.
    let pipes = pipes_held();
    let Some(pipe) = pipes.get_mut(index).and_then(Option::as_mut) else {
        return (REPLY_VALUE, Answer::error(-9)); // EBADF
    };
    if pipe.would_block() {
        // SAFETY: as above.
        let waiters = pipe_waiters();
        let Some(slot) = claim_wake() else {
            return (REPLY_VALUE, Answer::error(-11)); // EAGAIN
        };
        waiters[index] = slot as u32 + 1;
        return (REPLY_BLOCK_ON_RETRY, Answer::ok(WAKE_SLOT + slot as u64));
    }
    let mut bytes = [0u8; SCRATCH_BYTES as usize];
    let take = (count as usize).min(bytes.len());
    let moved = pipe.read(&mut bytes[..take]);
    if moved == 0 {
        // At end of file: no writer, nothing left. Zero is the answer, and it
        // is the one every `cat | wc` in history stops on.
        return (REPLY_VALUE, Answer::ok(0));
    }
    if !copy_out(request.domain, buffer, &bytes[..moved]) {
        return (REPLY_VALUE, Answer::error(-14)); // EFAULT
    }
    (REPLY_VALUE, Answer::ok(moved as u64))
}

/// Wakes whoever is parked on this pipe, if anybody is.
///
/// One waiter per pipe, which is what a pipe with one reader has. A second
/// reader parking would overwrite the first's slot and strand it — stated
/// rather than guarded, because nothing here creates a second reader yet and a
/// guard for a case that cannot arise is a guard nobody can test.
fn wake_pipe_reader(index: usize) {
    // SAFETY: single-threaded by construction, as elsewhere here.
    let waiters = pipe_waiters();
    let Some(slot) = waiters.get_mut(index) else {
        return;
    };
    let Some(wake) = slot.checked_sub(1) else {
        return;
    };
    *slot = 0;
    let _ = call(
        syscall::INVOKE,
        WAKE_SLOT + u64::from(wake),
        method::SIGNAL,
        [0; 4],
    );
    release_wake(wake as usize);
}

/// Writes into a pipe, waking a reader that was waiting for it.
fn write_to_pipe(request: &PersonalityCall, index: usize, buffer: u64, count: u64) -> Answer {
    let mut bytes = [0u8; SCRATCH_BYTES as usize];
    let take = (count as usize).min(bytes.len());
    if !copy_in(request.domain, buffer, &mut bytes[..take]) {
        return Answer::error(-14); // EFAULT
    }
    // SAFETY: single-threaded by construction, as elsewhere here.
    let pipes = pipes_held();
    let Some(pipe) = pipes.get_mut(index).and_then(Option::as_mut) else {
        return Answer::error(-9);
    };
    let written = match pipe.write(&bytes[..take]) {
        Ok(written) => written,
        Err(errno) => return Answer::error(errno),
    };
    // **The wake comes after the bytes**, which is the same ordering
    // `notify::signal` keeps for the same reason: a reader woken before the
    // ring was written would find it empty and park again, holding the wake it
    // was given.
    wake_pipe_reader(index);
    Answer::ok(written as u64)
}

/// Records that a hosted process has a mapping — RFC 0033 step 8.
///
/// **Nothing needed this list until `fork`.** The kernel holds the mapping and
/// answers the faults; this program answered `mmap` and forgot. A fork has to
/// *copy* an address space, and the only thing that knows what is in one is
/// whoever answered every `mmap` for it.
///
/// A table that is full is not an error here: the mapping was made, and the
/// honest consequence is that a later `fork` cannot copy that region. Said in
/// the record rather than by refusing a call that has already succeeded.
fn remember_mapping(domain: u32, at: u64, pages: u64, protection: u64) {
    if let Some(process) = process_for(domain) {
        let _ = process.mapped(Region {
            at,
            pages,
            protection,
        });
    }
}

/// Answers a hosted `openat` — RFC 0033 step 6.
///
/// **One component, against the directory this program was given.** The
/// filesystem protocol resolves a *name* inside a directory a caller holds
/// (RFC 0016); there is no method that takes a path, deliberately, because a
/// path is a request to walk somewhere the caller may not hold. So a hosted
/// program's `/inner` is the name `inner` inside the one directory this
/// program has, and `/a/b` is `ENOENT` until a hosted process carries a
/// working directory of its own.
///
/// The capability that comes back is held **here**, in a slot the hosted
/// program cannot name, and what the program gets is a small integer into its
/// own descriptor table. That is interface I3 in one function.
fn answer_openat(request: &PersonalityCall, path_at: u64, flags: u64) -> Answer {
    open_the_file(request, path_at, flags)
}

/// Where an `open` stopped, for the record's second word. A hosted program
/// sees one `ENOENT`; whoever is debugging sees which of four it was.
const STAGE_BAD_NAME: i64 = -101;
const STAGE_NO_DIRECTORY: i64 = -102;
const STAGE_SERVICE_SILENT: i64 = -103;
const STAGE_SERVICE_REFUSED: i64 = -104;
/// And where a `read` stopped.
const STAGE_NO_EXPECT: i64 = -105;
/// And which of the directory calls last answered, so a probe that stops
/// halfway says *which* call it stopped in rather than only that it did.
const STAGE_LISTED: i64 = -120;
const STAGE_STATTED: i64 = -121;
const STAGE_SEEKED: i64 = -122;
const STAGE_NOT_A_DIRECTORY: i64 = -123;
/// And where a socket call stopped -- RFC 0005 step 9. Same record, because a
/// probe uses one or the other and never both.
const STAGE_SOCKET: i64 = -130;
const STAGE_NO_EXPECT_SOCKET: i64 = -131;
const STAGE_NOT_BOUND: i64 = -132;
const STAGE_SENT: i64 = -133;
const STAGE_SEND_REFUSED: i64 = -134;
const STAGE_NOTHING_YET: i64 = -135;
const STAGE_RECEIVED: i64 = -136;
const STAGE_MAP_SILENT: i64 = -106;
const STAGE_MAP_REFUSED: i64 = -107;
const STAGE_NOT_ATTACHED: i64 = -109;
const STAGE_NOT_COPIED: i64 = -110;
/// And where a hosted `execve` stopped — RFC 0059. The value beside each says
/// what it stopped *on*: the size that was refused, the service's outcome, or
/// how many bytes had arrived.
const STAGE_EXEC_REFUSED: i64 = -140;
const STAGE_EXEC_READ: i64 = -141;
const STAGE_EXEC_SHORT: i64 = -142;

/// The work behind [`answer_openat`], so that every path through it is traced.
fn open_the_file(request: &PersonalityCall, path_at: u64, flags: u64) -> Answer {
    use bhaskix_personality::file::{Entry, Kind, open, plan_openat};

    // **The plan is used now** — RFC 0060. Until then this refused every
    // non-read-only open with `EROFS` before looking at anything, computed the
    // plan, and threw it away with `let _ = plan;`.
    let plan = match plan_openat(flags) {
        Ok(plan) => plan,
        Err(errno) => return Answer::error(errno),
    };

    let mut name = [0u8; MAX_NAME];
    if !copy_in(request.domain, path_at, &mut name) {
        return Answer::error(-14); // EFAULT
    }
    // **`/proc` is answered here and asked of nobody** — RFC 0033 step 10.
    // The filesystem service has no such directory and should not: what a
    // hosted process may read about itself is this personality's business, and
    // a synthetic file generated in a crate that has never seen a capability
    // cannot leak one.
    if let Some(file) = ProcFile::from_path(&name) {
        return open_proc(request, file, flags);
    }
    // `/tmp/<name>` resolves in the writable capability, and only there.
    if let Some(component) = writable_component(&name) {
        return open_writable(request, component, flags, plan);
    }
    // A write outside the writable directory is refused where it always was.
    if plan.writable {
        return Answer::error(-30); // EROFS
    }
    let Some(component) = one_component(&name) else {
        // **`/` and `.` are this process's own root**, and answering them is
        // what makes a directory readable at all: `getdents64` needs a
        // descriptor, and until now the only way to get one was to name a
        // directory *inside* the root -- so the root itself, which is the
        // one directory every hosted process has, was the one it could not
        // list.
        if names_own_root(&name) {
            return open_own_root(request, flags);
        }
        // **Three different refusals answered `-2` and the record could not
        // tell them apart** -- the mistake this project has now made five
        // times, and the reason the second word of the record is a *stage*
        // rather than more of the same number. The hosted program still sees
        // `ENOENT`, which is the truth it can act on.
        trace_file(-2, STAGE_BAD_NAME, 0);
        return Answer::error(-2); // ENOENT
    };

    let Some(slot) = claim_file_slot() else {
        return Answer::error(-24); // EMFILE
    };
    let opened = match resolve_into(slot, component) {
        Ok(opened) => opened,
        Err(errno) => {
            release_file_slot(slot);
            return Answer::error(errno);
        }
    };
    let entry = Entry {
        handle: slot,
        // The filesystem's own name for what was opened, which `fstat`
        // answers with and this program cannot derive from anything else it
        // holds -- the slot is reused between files.
        inode: opened.inode,
        kind: if opened.directory {
            Kind::Directory
        } else {
            Kind::File
        },
        close_on_exec: flags & open::CLOEXEC != 0,
        offset: 0,
        size: opened.size,
        readable: true,
        writable: false,
    };
    let Some(process) = process_for(request.domain) else {
        release_file_slot(slot);
        return Answer::error(-11); // EAGAIN
    };
    match process.descriptors.insert(entry, 0) {
        Ok(descriptor) => {
            trace_file(i64::from(descriptor), 0, entry.size);
            Answer::ok(descriptor as u64)
        }
        Err(errno) => {
            release_file_slot(slot);
            Answer::error(errno)
        }
    }
}

/// Whether this name is the root of what this process can see.
///
/// `/`, `//`, and `.` — the three spellings a program reaches for when it
/// means "here". **Not the empty string**, which Linux answers `ENOENT` and
/// which is what a program passes when it has lost track of its own path;
/// treating that as the root would turn a bug into a successful listing.
fn names_own_root(name: &[u8]) -> bool {
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    let name = &name[..end];
    !name.is_empty() && (name == b"." || name.iter().all(|byte| *byte == b'/'))
}

/// Opens the directory capability this process was given, as a descriptor.
///
/// **The handle is [`ROOT_DIR`] itself and no slot is claimed**, because
/// there is nothing to claim: the capability is already held, at a fixed
/// slot, for the life of this program. That makes `close` a special case,
/// and [`answer_close`] carries the guard — releasing this handle would
/// `DELETE` the adapter's only directory and every hosted process on the
/// machine would stop finding files.
/// Opens a name inside the one writable directory — RFC 0060.
///
/// The mirror of the read path against a different capability: it resolves
/// through [`WRITABLE_DIR`], whose badge carries `dir::WRITABLE`, a bit only
/// the kernel mints. What makes this writable is which capability is used, not
/// a flag the caller passed.
fn open_writable(
    request: &PersonalityCall,
    component: &[u8],
    flags: u64,
    plan: bhaskix_personality::file::OpenPlan,
) -> Answer {
    use bhaskix_personality::file::{Entry, Kind, open};

    let Some(slot) = claim_file_slot() else {
        return Answer::error(-24); // EMFILE
    };
    let (chunk, rest) = bhaskix_abi::Chunk::take(component);
    if !rest.is_empty() {
        release_file_slot(slot);
        return Answer::error(-36); // ENAMETOOLONG
    }
    // **This is also the "is a writable directory held" check.** An empty slot
    // has no capability to invoke, so one round trip answers both questions —
    // and a first attempt that probed with `method::INFO` first answered
    // `EROFS` on every machine, because `INFO` is a *domain* method.
    if call(
        syscall::INVOKE,
        WRITABLE_DIR,
        method::EXPECT,
        [slot, 0, 0, 0],
    )
    .status
        != status::OK
    {
        release_file_slot(slot);
        trace_file(-30, STAGE_NO_DIRECTORY, 1);
        return Answer::error(-30); // EROFS: none is held
    }
    let wanted = if plan.create {
        bhaskix_abi::dir::CREATE_AT
    } else {
        bhaskix_abi::dir::OPEN_AT
    };
    let reply = call(syscall::CALL, WRITABLE_DIR, wanted, chunk.pack(0));
    if reply.status != status::OK {
        release_file_slot(slot);
        trace_file(-5, STAGE_SERVICE_SILENT, reply.status);
        return Answer::error(-5); // EIO
    }
    let outcome = reply.args[0];
    if outcome == bhaskix_abi::dir::EXISTS {
        release_file_slot(slot);
        if plan.exclusive {
            return Answer::error(-17); // EEXIST
        }
        // **Open it instead, and say so in the plan as well as the flags.**
        // Clearing only the flag would leave `plan.create` true and recurse for
        // ever, because the plan is what decides which method is sent.
        let mut again = plan;
        again.create = false;
        return open_writable(request, component, flags & !open::CREAT, again);
    }
    if outcome != bhaskix_abi::dir::OK {
        release_file_slot(slot);
        trace_file(-2, STAGE_SERVICE_REFUSED, outcome);
        return Answer::error(-2); // ENOENT
    }

    let entry = Entry {
        handle: slot,
        inode: reply.args[3],
        kind: if reply.args[2] != 0 {
            Kind::Directory
        } else {
            Kind::File
        },
        close_on_exec: flags & open::CLOEXEC != 0,
        offset: 0,
        size: reply.args[1],
        readable: plan.readable,
        writable: plan.writable,
    };
    let Some(process) = process_for(request.domain) else {
        release_file_slot(slot);
        return Answer::error(-11);
    };
    match process.descriptors.insert(entry, 0) {
        Ok(descriptor) => {
            trace_file(i64::from(descriptor), 0, entry.size);
            Answer::ok(descriptor as u64)
        }
        Err(errno) => {
            release_file_slot(slot);
            Answer::error(errno)
        }
    }
}

fn open_own_root(request: &PersonalityCall, flags: u64) -> Answer {
    use bhaskix_personality::file::{Entry, Kind, open};

    // No access-mode check here: [`open_the_file`] refuses anything but
    // `O_RDONLY` with `EROFS` before it reaches this, and a second check that
    // cannot fire is a check nobody can watch fail.
    let entry = Entry {
        handle: ROOT_DIR,
        // **Zero, and it is a gap rather than a value.** The filesystem's
        // name for this directory is in the badge of the capability above,
        // which is the *service's* to read: a holder cannot see inside a
        // capability, and no method asks a directory about itself. Every
        // entry *inside* it carries a real inode, which is what a listing
        // needs; what is missing is `st_ino` on the root alone. The trigger
        // for a `dir::STAT_AT` is the first program that compares it.
        inode: 0,
        kind: Kind::Directory,
        close_on_exec: flags & open::CLOEXEC != 0,
        offset: 0,
        size: 0,
        readable: true,
        writable: false,
    };
    let Some(process) = process_for(request.domain) else {
        return Answer::error(-11); // EAGAIN
    };
    match process.descriptors.insert(entry, 0) {
        Ok(descriptor) => {
            trace_file(i64::from(descriptor), 0, 0);
            Answer::ok(descriptor as u64)
        }
        Err(errno) => Answer::error(errno),
    }
}

/// Opens one of the `/proc` files this personality generates.
///
/// The descriptor names *which* file, and nothing else: the text is generated
/// again on every `read`, from the record and the region list, because a
/// snapshot kept between calls would be a second copy of the truth and the
/// wrong one by the time anybody read it.
fn open_proc(request: &PersonalityCall, file: ProcFile, flags: u64) -> Answer {
    use bhaskix_personality::file::{Entry, Kind, open};

    if flags & open::ACCMODE != open::RDONLY {
        return Answer::error(-30); // EROFS
    }
    let mut bytes = [0u8; bhaskix_personality::proc::MAX_BYTES];
    let Some(size) = generate_proc(request.domain, file, &mut bytes) else {
        return Answer::error(-11); // EAGAIN
    };
    let entry = Entry {
        // Generated here and on no filesystem: a synthetic `/proc` file has
        // no inode, and inventing one would make two of them compare equal
        // to each other rather than to nothing.
        inode: 0,
        handle: match file {
            ProcFile::Status => 0,
            ProcFile::Maps => 1,
        },
        kind: Kind::Proc,
        close_on_exec: flags & open::CLOEXEC != 0,
        offset: 0,
        size: size as u64,
        readable: true,
        writable: false,
    };
    let Some(process) = process_for(request.domain) else {
        return Answer::error(-11);
    };
    match process.descriptors.insert(entry, 0) {
        Ok(descriptor) => Answer::ok(descriptor as u64),
        Err(errno) => Answer::error(errno),
    }
}

/// Generates one `/proc` file's text, and answers its length.
fn generate_proc(domain: u32, file: ProcFile, out: &mut [u8]) -> Option<usize> {
    let process = process_for(domain)?;
    Some(match file {
        ProcFile::Status => bhaskix_personality::proc::write_status(
            out,
            process.pid,
            process.ppid,
            process.credentials.uid,
        ),
        // The protection word is the kernel's, and the personality carries it
        // without interpreting it -- so the one value `maps` has to name,
        // read-execute, is passed in rather than assumed there.
        ProcFile::Maps => {
            bhaskix_personality::proc::write_maps(out, &process.regions, PROT_READ_EXECUTE)
        }
    })
}

/// Reads from a `/proc` file, generating it afresh.
fn read_proc(request: &PersonalityCall, handle: u64, buffer: u64, count: u64) -> Answer {
    let file = if handle == 0 {
        ProcFile::Status
    } else {
        ProcFile::Maps
    };
    let mut bytes = [0u8; bhaskix_personality::proc::MAX_BYTES];
    let Some(length) = generate_proc(request.domain, file, &mut bytes) else {
        return Answer::error(-11);
    };
    let Ok(descriptor) = i32::try_from(request.first()) else {
        return Answer::error(-9);
    };
    let Some(process) = process_for(request.domain) else {
        return Answer::error(-11);
    };
    let Some(entry) = process.descriptors.get(descriptor).copied() else {
        return Answer::error(-9);
    };
    let offset = entry.offset as usize;
    if offset >= length {
        return Answer::ok(0);
    }
    let take = (count as usize)
        .min(length - offset)
        .min(SCRATCH_BYTES as usize);
    if !copy_out(request.domain, buffer, &bytes[offset..offset + take]) {
        return Answer::error(-14); // EFAULT
    }
    if let Some(process) = process_for(request.domain)
        && let Some(entry) = process.descriptors.get_mut(descriptor)
    {
        entry.offset += take as u64;
    }
    Answer::ok(take as u64)
}

/// Answers a hosted `read` — RFC 0033 step 6.
///
/// **The bytes are never carried through a message.** The filesystem service
/// lends the page of its own cache the file's first block is in, read-only;
/// this program maps it, copies what the caller asked for straight into the
/// caller's memory with `COPY_OUT`, and gives the page back. Two capability
/// invocations and one copy, and the service never reads the file on anybody's
/// behalf.
///
/// **The first block only**, which is what `MAP` lends: a read past 4,096
/// bytes answers zero, as a read at the end of a file does. That is a
/// narrowing rather than a bug, and it is the protocol's — a file surface that
/// reads a second block needs a method that lends a second page.
fn answer_read(request: &PersonalityCall) -> Answer {
    let (fd, buffer, count) = (request.first(), request.second(), request.third());
    let Ok(descriptor) = i32::try_from(fd) else {
        return Answer::error(-9); // EBADF
    };
    let Some(process) = process_for(request.domain) else {
        return Answer::error(-11);
    };
    let Some(entry) = process.descriptors.get(descriptor).copied() else {
        return Answer::error(-9);
    };
    if !entry.readable || entry.kind != bhaskix_personality::file::Kind::File {
        return Answer::error(-9);
    }
    let left = entry.size.saturating_sub(entry.offset);
    let take = count.min(left).min(SCRATCH_BYTES);
    if take == 0 {
        return Answer::ok(0);
    }

    // The page, lent for as long as this call takes.
    let _ = call(syscall::INVOKE, LENT, method::DELETE, [0; 4]);
    let declared = call(
        syscall::INVOKE,
        entry.handle,
        method::EXPECT,
        [LENT, 0, 0, 0],
    );
    if declared.status != status::OK {
        // Every refusal in this function is recorded with *where*, for the
        // reason `open` learned twice over: three paths answering one errno
        // is a record that cannot tell the next reader anything.
        trace_file(-5, STAGE_NO_EXPECT, declared.status);
        return Answer::error(-5); // EIO
    }
    let lent = call(syscall::CALL, entry.handle, bhaskix_abi::dir::MAP, [0; 4]);
    if lent.status != status::OK {
        trace_file(-5, STAGE_MAP_SILENT, lent.status);
        return Answer::error(-5);
    }
    if lent.args[0] != bhaskix_abi::dir::OK {
        // **Four numbers in one word, because one was not enough twice.** The
        // service answers `NOWHERE` from three different places -- no frame
        // left to pin, no slot to derive into, nothing to hand to -- and the
        // outcome alone cannot tell them apart, so a refusal on this path read
        // the same whether the fault was here or there. `args[2]` is the site,
        // `args[1]` the status it stopped with, and the handle says which open
        // file was asking. That is what turned "the second read fails" from a
        // symptom into `SlotUnavailable` at the hand, in one boot instead of
        // three.
        trace_file(
            -5,
            STAGE_MAP_REFUSED,
            lent.args[0] | (lent.args[1] << 8) | (lent.args[2] << 16) | (entry.handle << 32),
        );
        return Answer::error(-5);
    }
    // **Attached read-only, and the second argument is why.** A non-zero word
    // there asks for a *writable* mapping and needs `Rights::WRITE`, which a
    // page of the service's own cache does not carry. Asking for one anyway
    // was refused, and the refusal reached this test as a `read` that moved
    // nothing.
    let attached = call(syscall::INVOKE, LENT, method::ATTACH, [LENT_AT, 0, 0, 0]);
    let moved = if attached.status == status::OK {
        let mut bytes = [0u8; SCRATCH_BYTES as usize];
        let take = take as usize;
        for (index, byte) in bytes.iter_mut().take(take).enumerate() {
            // SAFETY: inside the page `ATTACH` mapped read-only from the
            // capability the service lent, bounded by the file's own size.
            *byte = unsafe {
                core::ptr::read_volatile((LENT_AT + entry.offset + index as u64) as *const u8)
            };
        }
        let out = copy_out(request.domain, buffer, &bytes[..take]);
        if !out {
            trace_file(-14, STAGE_NOT_COPIED, 0);
        }
        out
    } else {
        trace_file(-5, STAGE_NOT_ATTACHED, attached.status);
        false
    };
    // Given back either way: the service unpins the frame and revokes what it
    // lent, which unmaps it from here. A page kept is a page its cache cannot
    // evict.
    // Timed, because RFC 0044 made this call do more and shipped without a
    // number for it. The counter is `bhaskix-sock`'s for the reason the
    // supervised-copy measurement gives: an `rdtsc` written here would cost
    // `unsafe` lines in the most authority-concentrated program in the system,
    // and that crate already owns the read.
    let released_at = bhaskix_sock::time::now();
    let _ = call(
        syscall::CALL,
        entry.handle,
        bhaskix_abi::dir::RELEASE,
        [0; 4],
    );
    record_release(bhaskix_sock::time::now().saturating_sub(released_at));
    let _ = call(syscall::INVOKE, LENT, method::DELETE, [0; 4]);
    if !moved {
        // **Not traced here.** The two branches above each recorded *where*
        // they stopped, and a record written at the join would overwrite the
        // specific answer with a general one -- which it did, for one boot,
        // and cost the very distinction the stages were added to make.
        return Answer::error(-14); // EFAULT
    }
    if let Some(process) = process_for(request.domain)
        && let Some(entry) = process.descriptors.get_mut(descriptor)
    {
        entry.offset += take;
    }
    trace_file(i64::from(descriptor), take as i64, entry.size);
    Answer::ok(take)
}

/// Answers a hosted `lseek`.
///
/// **A directory's offset is an entry index, not a byte count**, and that is
/// deliberate: `LIST_AT` is addressed by index, so `lseek(dirfd, 0, SEEK_SET)`
/// — which is how `rewinddir` is written — lands back at the first entry
/// without this program having to keep a second kind of cursor. A byte offset
/// on a directory would mean nothing to either side.
fn answer_lseek(request: &PersonalityCall) -> Answer {
    use bhaskix_personality::file::{Kind, plan_lseek};

    let Ok(descriptor) = i32::try_from(request.first()) else {
        return Answer::error(-9); // EBADF
    };
    let Some(process) = process_for(request.domain) else {
        return Answer::error(-11);
    };
    let Some(entry) = process.descriptors.get(descriptor).copied() else {
        return Answer::error(-9);
    };
    // **`ESPIPE` and not `EINVAL`**, and the difference is load-bearing: a
    // program that seeks a pipe to find out whether it can is reading exactly
    // this errno, and `EINVAL` would tell it the *arguments* were wrong.
    if !matches!(entry.kind, Kind::File | Kind::Directory | Kind::Proc) {
        return Answer::error(-29); // ESPIPE
    }
    match plan_lseek(
        entry.offset,
        entry.size,
        request.second() as i64,
        request.third(),
    ) {
        Ok(landed) => {
            if let Some(process) = process_for(request.domain)
                && let Some(entry) = process.descriptors.get_mut(descriptor)
            {
                entry.offset = landed;
            }
            trace_file(i64::from(descriptor), STAGE_SEEKED, landed);
            Answer::ok(landed)
        }
        Err(errno) => Answer::error(errno),
    }
}

/// Writes one `struct stat` describing `entry` into the caller's memory.
fn stat_out(
    request: &PersonalityCall,
    entry: &bhaskix_personality::file::Entry,
    at: u64,
) -> Answer {
    use bhaskix_personality::file::{STAT_BYTES, stat_of, write_stat};

    let mut bytes = [0u8; STAT_BYTES];
    if write_stat(&mut bytes, &stat_of(entry)).is_err() {
        trace_file(-22, STAGE_STATTED, 1);
        return Answer::error(-22); // EINVAL
    }
    if !copy_out(request.domain, at, &bytes) {
        trace_file(-14, STAGE_NOT_COPIED, at);
        return Answer::error(-14); // EFAULT
    }
    trace_file(entry.inode as i64, STAGE_STATTED, entry.size);
    Answer::ok(0)
}

/// Answers a hosted `fstat`.
fn answer_fstat(request: &PersonalityCall) -> Answer {
    let Ok(descriptor) = i32::try_from(request.first()) else {
        return Answer::error(-9);
    };
    let Some(process) = process_for(request.domain) else {
        return Answer::error(-11);
    };
    let Some(entry) = process.descriptors.get(descriptor).copied() else {
        return Answer::error(-9);
    };
    stat_out(request, &entry, request.second())
}

/// Answers a hosted `newfstatat` — which is how a current libc issues `stat`,
/// `lstat` and often `fstat` as well.
///
/// **The path form opens, stats and closes**, because this system has no way
/// to ask about a name without resolving it, and resolving it *is* opening it
/// here. That costs a descriptor for the length of the call and can therefore
/// fail with `EMFILE` where Linux would not — said rather than hidden, and the
/// trigger for a `dir::STAT_AT` method is the first program that stats in a
/// loop while holding its table full.
fn answer_newfstatat(request: &PersonalityCall) -> Answer {
    stat_at(
        request,
        request.first(),
        request.second(),
        request.third(),
        request.fourth(),
    )
}

/// `newfstatat`'s body, with its four arguments passed rather than read.
///
/// **So that `stat` and `lstat` are this call and not a second copy of it.**
/// BusyBox emits the two older forms — `stat(path, buf)` is
/// `newfstatat(AT_FDCWD, path, buf, 0)` and `lstat` the same with
/// `AT_SYMLINK_NOFOLLOW` — and a personality that reimplemented them would have
/// two path resolutions to keep in step. Whatever this refuses, they refuse.
fn stat_at(request: &PersonalityCall, dirfd: u64, path_at: u64, out_at: u64, flags: u64) -> Answer {
    let mut name = [0u8; MAX_NAME];
    if !copy_in(request.domain, path_at, &mut name) {
        return Answer::error(-14); // EFAULT
    }
    let empty = name.first() == Some(&0);
    // `AT_EMPTY_PATH` with an empty path is `fstat` written the modern way,
    // and it is what a libc emits for `fstat` itself.
    if empty && flags & AT_EMPTY_PATH != 0 {
        let Ok(descriptor) = i32::try_from(dirfd) else {
            return Answer::error(-9);
        };
        let Some(process) = process_for(request.domain) else {
            return Answer::error(-11);
        };
        let Some(entry) = process.descriptors.get(descriptor).copied() else {
            return Answer::error(-9);
        };
        return stat_out(request, &entry, out_at);
    }
    if empty {
        // An empty path without the flag is `ENOENT` in Linux, and a version
        // that treated it as "this directory" would make every mistaken
        // `stat("")` succeed.
        return Answer::error(-2);
    }
    // Every path here is resolved from the one directory this process was
    // given, so `dirfd` names nothing this program can act on differently.
    // **Refused rather than ignored** when it is not `AT_FDCWD`: silently
    // resolving a relative path against the wrong directory is how a program
    // reads a file it did not ask for, and this system has no second
    // directory to resolve against yet.
    if dirfd != AT_FDCWD && !name.starts_with(b"/") {
        return Answer::error(-38); // ENOSYS
    }
    let opened = open_the_file(request, path_at, 0);
    if opened.is_error() {
        return opened;
    }
    let Ok(descriptor) = i32::try_from(opened.value) else {
        return Answer::error(-9);
    };
    let entry = process_for(request.domain)
        .and_then(|process| process.descriptors.get(descriptor).copied());
    let answer = match entry {
        Some(entry) => stat_out(request, &entry, out_at),
        None => Answer::error(-9),
    };
    // Closed whatever the stat did, or the descriptor leaks on every failed
    // one -- which is the shape of bug that turns a working program into one
    // that stops after thirty-two files.
    let mut closing = *request;
    closing.args[0] = descriptor as u64;
    let _ = answer_close(&closing);
    answer
}

/// Answers a hosted `getdents64` — RFC 0005 step 8's directory read.
///
/// **The listing is index-addressed and holds no session**, so the descriptor's
/// offset is the index of the next entry and nothing in this program or in the
/// filesystem service remembers a partly-read directory. A caller that seeks
/// back to zero starts again; two callers reading the same directory cannot
/// disturb each other; and a process that dies mid-listing leaves nothing
/// behind.
fn answer_getdents64(request: &PersonalityCall) -> Answer {
    use bhaskix_abi::dir;
    use bhaskix_personality::file::{Kind, dirent_bytes, dirent_type, write_dirent};

    let (fd, buffer, count) = (request.first(), request.second(), request.third());
    let Ok(descriptor) = i32::try_from(fd) else {
        return Answer::error(-9);
    };
    let Some(process) = process_for(request.domain) else {
        return Answer::error(-11);
    };
    let Some(entry) = process.descriptors.get(descriptor).copied() else {
        return Answer::error(-9);
    };
    if entry.kind != Kind::Directory {
        trace_file(-20, STAGE_NOT_A_DIRECTORY, entry.kind as u64);
        return Answer::error(-20); // ENOTDIR
    }

    let room = (count as usize).min(SCRATCH_BYTES as usize);
    let mut out = [0u8; SCRATCH_BYTES as usize];
    let mut written = 0usize;
    let mut index = entry.offset;
    loop {
        let reply = call(syscall::CALL, entry.handle, dir::LIST_AT, [index, 0, 0, 0]);
        if reply.status != status::OK {
            return Answer::error(-5); // EIO
        }
        match reply.args[0] {
            dir::OK => {}
            dir::END => break,
            // A name the listing cannot carry stops the read where it is
            // rather than skipping it: a directory silently missing one entry
            // is a worse answer than a directory that says it cannot be read.
            _ => return Answer::error(-5),
        }
        let length = dir::listing_length(reply.args[3]).min(16);
        let mut name = [0u8; 16];
        name[..8].copy_from_slice(&reply.args[1].to_le_bytes());
        name[8..].copy_from_slice(&reply.args[2].to_le_bytes());

        // **The room is checked here rather than read off a failed write**,
        // because `write_dirent` answers a full buffer and an illegal name
        // with the same number -- `EINVAL_SHORT` *is* `EINVAL` -- and a
        // caller that could not tell them apart would report a corrupt name
        // as a short buffer and truncate the listing without saying so.
        if written + dirent_bytes(length) > room {
            if written == 0 {
                // Linux's answer for a buffer too small for even one record.
                return Answer::error(-22); // EINVAL
            }
            break;
        }
        let kind = if dir::listing_is_directory(reply.args[3]) {
            dirent_type::DIR
        } else {
            dirent_type::REG
        };
        let Ok(bytes) = write_dirent(
            &mut out[written..],
            u64::from(dir::listing_inode(reply.args[3])),
            // `d_off` is where the *next* entry is, which for an
            // index-addressed listing is this index plus one. A caller that
            // seeks to it and reads on must not see this entry twice.
            index + 1,
            kind,
            &name[..length],
        ) else {
            // The room was checked, so this can only be a name the filesystem
            // should never have produced: empty, or holding a separator or a
            // NUL. Not skipped -- see above.
            return Answer::error(-5);
        };
        written += bytes;
        index += 1;
    }

    if written == 0 {
        // The end of the directory, which `getdents64` reports as zero bytes
        // and not as an error.
        return Answer::ok(0);
    }
    if !copy_out(request.domain, buffer, &out[..written]) {
        return Answer::error(-14); // EFAULT
    }
    if let Some(process) = process_for(request.domain)
        && let Some(entry) = process.descriptors.get_mut(descriptor)
    {
        entry.offset = index;
    }
    trace_file(i64::from(descriptor), STAGE_LISTED, written as u64);
    Answer::ok(written as u64)
}

/// Records what giving a lent page back cost — the first one on the machine,
/// then the first one after that.
///
/// **Two slots and no averaging.** The first execution of this path is
/// dominated by whatever the emulator has not translated yet, which the
/// supervised-copy measurement learned the expensive way: a first attempt
/// there read an ordering artefact as a per-byte cost. Keeping the two
/// separate lets a reader see the difference rather than have it averaged
/// away.
///
/// A zero slot means "not taken yet", which is safe because a call that took
/// no cycles did not happen.
fn record_release(cycles: u64) {
    for slot in 0..2u64 {
        let at = LEND_RECORD_AT + slot * 8;
        // SAFETY: inside the page `ATTACH` mapped from this program's own
        // object, at an offset the crate asserts is before the scratch area.
        let taken = unsafe { core::ptr::read_volatile(at as *const u64) };
        if taken == 0 {
            // SAFETY: as above.
            unsafe { core::ptr::write_volatile(at as *mut u64, cycles.max(1)) };
            return;
        }
    }
}

/// Answers a hosted `uname`.
fn answer_uname(request: &PersonalityCall) -> Answer {
    use bhaskix_personality::file::{UTSNAME_BYTES, write_utsname};

    let mut bytes = [0u8; UTSNAME_BYTES];
    if write_utsname(&mut bytes).is_err() {
        return Answer::error(-22); // EINVAL
    }
    if !copy_out(request.domain, request.first(), &bytes) {
        return Answer::error(-14); // EFAULT
    }
    Answer::ok(0)
}

/// Answers a hosted `ioctl`, against an allow-list of two.
fn answer_ioctl(request: &PersonalityCall) -> Answer {
    use bhaskix_personality::file::{Ioctl, plan_ioctl};

    let Ok(descriptor) = i32::try_from(request.first()) else {
        return Answer::error(-9); // EBADF
    };
    let Some(process) = process_for(request.domain) else {
        return Answer::error(-11);
    };
    let Some(entry) = process.descriptors.get(descriptor).copied() else {
        return Answer::error(-9);
    };
    match plan_ioctl(request.second(), entry.kind) {
        // **Nothing is written back for `TCGETS`**, and that is deliberate:
        // `isatty` reads the *return value*, not the `termios` it passed, and
        // this adapter has no terminal settings it could honestly report.
        // Filling the caller's buffer with plausible ones would be inventing
        // a baud rate and a line discipline.
        Ok(Ioctl::AskIfTerminal) => Answer::ok(0),
        Ok(Ioctl::WindowSize) => {
            // Four `u16`s: rows, columns, and two pixel counts. Zeroes,
            // because this console's size is not something the adapter knows
            // -- and zero is what Linux reports for a terminal that cannot
            // say, which programs already handle by falling back to 80x24.
            let zeroes = [0u8; 8];
            if !copy_out(request.domain, request.third(), &zeroes) {
                return Answer::error(-14);
            }
            Answer::ok(0)
        }
        Err(errno) => Answer::error(errno),
    }
}

/// Answers a hosted `fcntl`.
fn answer_fcntl(request: &PersonalityCall) -> Answer {
    use bhaskix_personality::file::{Entry, Fcntl, Kind, fcntl, open, plan_fcntl};

    let Ok(descriptor) = i32::try_from(request.first()) else {
        return Answer::error(-9);
    };
    let plan = match plan_fcntl(request.second(), request.third()) {
        Ok(plan) => plan,
        Err(errno) => return Answer::error(errno),
    };
    let Some(process) = process_for(request.domain) else {
        return Answer::error(-11);
    };
    let Some(entry) = process.descriptors.get(descriptor).copied() else {
        return Answer::error(-9);
    };
    match plan {
        Fcntl::Duplicate {
            floor,
            close_on_exec,
        } => {
            let Ok(floor) = usize::try_from(floor) else {
                return Answer::error(-22);
            };
            match process.descriptors.insert(
                Entry {
                    close_on_exec,
                    ..entry
                },
                floor,
            ) {
                Ok(made) => Answer::ok(made as u64),
                Err(errno) => Answer::error(errno),
            }
        }
        Fcntl::ReadDescriptorFlags => Answer::ok(u64::from(entry.close_on_exec)),
        Fcntl::WriteDescriptorFlags { close_on_exec } => {
            if let Some(process) = process_for(request.domain)
                && let Some(entry) = process.descriptors.get_mut(descriptor)
            {
                entry.close_on_exec = close_on_exec;
            }
            Answer::ok(0)
        }
        // **Derived from what the descriptor is, not from what was asked
        // for.** A program that set `O_NONBLOCK` with `F_SETFL` and read it
        // back here would find it absent, which is the honest answer: this
        // adapter has no non-blocking descriptors, and reporting the flag
        // would be agreeing to something it does not do.
        Fcntl::ReadStatusFlags => {
            let access = if entry.writable && entry.readable {
                open::RDWR
            } else if entry.writable {
                open::WRONLY
            } else {
                open::RDONLY
            };
            let directory = if entry.kind == Kind::Directory {
                open::DIRECTORY
            } else {
                0
            };
            let _ = fcntl::FD_CLOEXEC;
            Answer::ok(access | directory)
        }
        Fcntl::WriteStatusFlags => Answer::ok(0),
    }
}

/// Answers a hosted `socket` — RFC 0005 step 9, Tier 2's first call.
///
/// **No capability is taken here**, and that is not laziness: `bin/ipd` hands
/// a socket back when it is *bound*, so there is nothing to hold until then.
/// The descriptor exists so that `bind` has something to name and `close` has
/// something to drop, which is what Linux's own split between the two calls
/// means.
fn answer_socket(request: &PersonalityCall) -> Answer {
    use bhaskix_personality::file::{Entry, Kind};
    use bhaskix_personality::socket::plan_socket;

    let plan = match plan_socket(request.first(), request.second(), request.third()) {
        Ok(plan) => plan,
        Err(errno) => return Answer::error(errno),
    };
    // **Streams are refused and datagrams are not.** A descriptor handed back
    // for a TCP socket would fail at `connect` with something that says
    // nothing about why; RFC 0022's three-leg handover is step 9's second half
    // and is not here.
    if plan.stream {
        return Answer::error(-93); // EPROTONOSUPPORT
    }
    let Some(process) = process_for(request.domain) else {
        return Answer::error(-11);
    };
    let entry = Entry {
        // Unbound: no slot claimed until `bind` gets one from the service.
        handle: u64::MAX,
        inode: 0,
        kind: Kind::Socket,
        close_on_exec: plan.close_on_exec,
        // **The family, on the row.** `bind` and `sendto` reach two different
        // services' calls -- `udp` and `udp6` -- and the descriptor is the
        // only place that choice is remembered between them.
        offset: u64::from(plan.v6),
        size: 0,
        readable: true,
        writable: true,
    };
    match process.descriptors.insert(entry, 0) {
        Ok(descriptor) => Answer::ok(descriptor as u64),
        Err(errno) => Answer::error(errno),
    }
}

/// Answers a hosted `bind`.
fn answer_bind(request: &PersonalityCall) -> Answer {
    use bhaskix_personality::file::Kind;
    use bhaskix_personality::socket::{Endpoint, parse_endpoint};

    let Ok(descriptor) = i32::try_from(request.first()) else {
        return Answer::error(-9);
    };
    let mut address = [0u8; 32];
    if !copy_in(request.domain, request.second(), &mut address) {
        return Answer::error(-14); // EFAULT
    }
    let given = request.third() as usize;
    let (port, v6) = match parse_endpoint(&address, given.min(address.len())) {
        Ok(Endpoint::V4 { port, .. }) => (port, false),
        Ok(Endpoint::V6 { port, .. }) => (port, true),
        Err(errno) => return Answer::error(errno),
    };
    let Some(process) = process_for(request.domain) else {
        return Answer::error(-11);
    };
    let Some(entry) = process.descriptors.get(descriptor).copied() else {
        return Answer::error(-9);
    };
    if entry.kind != Kind::Socket {
        return Answer::error(-88); // ENOTSOCK
    }
    if entry.handle != u64::MAX {
        return Answer::error(-22); // EINVAL: already bound
    }
    let Some(slot) = claim_socket_slot() else {
        return Answer::error(-24); // EMFILE
    };
    // The address family the socket was made with decides which service call
    // this is; binding a v6 address to a v4 socket is the caller's mistake and
    // is refused rather than silently reinterpreted.
    if v6 != (entry.offset != 0) {
        release_socket_slot(slot);
        return Answer::error(-97); // EAFNOSUPPORT
    }
    // **Where the capability may land, declared before asking for one.** The
    // service hands the socket back with `HAND`, which puts it in the slot the
    // caller declared and nowhere else; `bind6` does not do this for you, and
    // its documentation says so. Omitting it does not fail loudly -- the bind
    // is refused and a probe that only checked "did the program finish" sails
    // past, which is what happened here before this line existed.
    let declared = if v6 {
        bhaskix_sock::udp6::expect_socket(NETWORK, slot)
    } else {
        bhaskix_sock::udp::expect_socket(NETWORK, slot)
    };
    if declared.is_err() {
        trace_file(-5, STAGE_NO_EXPECT_SOCKET, slot);
        release_socket_slot(slot);
        return Answer::error(-5); // EIO
    }
    let bound = if v6 {
        bhaskix_sock::udp6::bind6(NETWORK, slot, port).map(|socket| socket.slot())
    } else {
        bhaskix_sock::udp::bind(NETWORK, slot, port).map(|socket| socket.slot())
    };
    match bound {
        Ok(held) => {
            // The capability is the socket. Recording the slot on the row is
            // what makes `sendto` and `close` able to find it again.
            if let Some(process) = process_for(request.domain)
                && let Some(entry) = process.descriptors.get_mut(descriptor)
            {
                entry.handle = held;
                entry.size = u64::from(port);
            }
            trace_file(i64::from(descriptor), STAGE_SOCKET, u64::from(port));
            Answer::ok(0)
        }
        Err(refusal) => {
            // **The service's own word, turned into the truth.** Every failed
            // bind used to answer `EADDRINUSE` because that was the only errno
            // this could honestly guess at while `bin/ipd` had one word for
            // several refusals. That guess misdirected three investigations in
            // one day, twice pointing at a port number with nothing to do with
            // the failure. The service distinguishes now, and this maps what it
            // says rather than guessing -- `ENFILE` when it is full,
            // `ENETDOWN` when there is no network, `EADDRINUSE` only when that
            // port really does belong to somebody.
            let errno = bhaskix_personality::socket::errno_for(match refusal {
                bhaskix_sock::udp::Refusal::Service(word) => word,
                // The call never reached the service, so it said nothing.
                bhaskix_sock::udp::Refusal::Kernel(_) => u64::MAX,
            });
            trace_file(
                errno,
                STAGE_NOT_BOUND,
                refusal.word() << 16 | u64::from(port),
            );
            release_socket_slot(slot);
            Answer::error(errno)
        }
    }
}

/// Whether the datagram page has been mapped yet.
static mut PAYLOAD_MAPPED: bool = false;

/// Maps the datagram page, once.
///
/// **`ATTACH` refuses an address that is already mapped**, and it refuses it
/// with `SlotUnavailable` — the same answer it gives for every unusable
/// address, which says nothing about which kind. So a second `ATTACH` at a
/// working address looks exactly like a broken one. `sendto` mapped this page
/// and then `recvfrom` mapped it again, and the second call failed `EFAULT`
/// for a reason that had nothing to do with the caller's memory: the datagram
/// went out and the reply was never read.
///
/// This is the third time in this tree that mapping twice has been the bug —
/// RFC 0044 was the last — and the shape is always the same: an operation with
/// no inverse, called as though it had one.
fn payload_ready() -> bool {
    // SAFETY: single-threaded by construction, as elsewhere here.
    let mapped = unsafe { &mut *core::ptr::addr_of_mut!(PAYLOAD_MAPPED) };
    if *mapped {
        return true;
    }
    if call(
        syscall::INVOKE,
        PAYLOAD,
        method::ATTACH,
        [PAYLOAD_AT, 1, 0, 0],
    )
    .status
        != status::OK
    {
        return false;
    }
    *mapped = true;
    true
}

/// Stages bytes in the datagram page and answers whether they got there.
fn stage_payload(domain: u32, at: u64, length: usize) -> bool {
    if length > bhaskix_mm_frame() {
        return false;
    }
    if !payload_ready() {
        return false;
    }
    let mut bytes = [0u8; SCRATCH_BYTES as usize];
    if !copy_in(domain, at, &mut bytes[..length]) {
        return false;
    }
    for (index, byte) in bytes.iter().take(length).enumerate() {
        // SAFETY: inside the page just mapped writable from this program's own
        // object, bounded by the frame check above.
        unsafe { core::ptr::write_volatile((PAYLOAD_AT + index as u64) as *mut u8, *byte) };
    }
    true
}

/// One frame, named once rather than spelled at each use.
const fn bhaskix_mm_frame() -> usize {
    4096
}

/// The port an endpoint names, for the record.
fn from_port(endpoint: &bhaskix_personality::socket::Endpoint) -> u16 {
    use bhaskix_personality::socket::Endpoint;
    match endpoint {
        Endpoint::V4 { port, .. } | Endpoint::V6 { port, .. } => *port,
    }
}

/// Answers a hosted `sendto`.
fn answer_sendto(request: &PersonalityCall) -> Answer {
    use bhaskix_personality::file::Kind;
    use bhaskix_personality::socket::{Endpoint, parse_endpoint};

    let Ok(descriptor) = i32::try_from(request.first()) else {
        return Answer::error(-9);
    };
    let length = request.third() as usize;
    let mut address = [0u8; 32];
    if !copy_in(request.domain, request.fifth(), &mut address) {
        trace_file(-14, STAGE_SEND_REFUSED, 1);
        return Answer::error(-14);
    }
    let given = request.sixth() as usize;
    let destination = match parse_endpoint(&address, given.min(address.len())) {
        Ok(endpoint) => endpoint,
        // **`EDESTADDRREQ` and not the parser's own errno.** A `sendto` with
        // no address on an unconnected socket is a program that meant
        // `connect` first, and this is the answer that says so.
        Err(errno) => {
            trace_file(-89, STAGE_SEND_REFUSED, (-errno) as u64 | 0x200);
            return Answer::error(-89);
        }
    };
    let Some(process) = process_for(request.domain) else {
        return Answer::error(-11);
    };
    let Some(entry) = process.descriptors.get(descriptor).copied() else {
        return Answer::error(-9);
    };
    if entry.kind != Kind::Socket {
        trace_file(-88, STAGE_SEND_REFUSED, 3);
        return Answer::error(-88); // ENOTSOCK
    }
    if entry.handle == u64::MAX {
        // Linux auto-binds here. This does not, and says so rather than
        // inventing an ephemeral port the service never agreed to.
        trace_file(-22, STAGE_SEND_REFUSED, 4);
        return Answer::error(-22); // EINVAL
    }
    if length > bhaskix_mm_frame() {
        return Answer::error(-90); // EMSGSIZE
    }
    if !stage_payload(request.domain, request.second(), length) {
        trace_file(-14, STAGE_SEND_REFUSED, 5);
        return Answer::error(-14);
    }
    let port = entry.size as u16;
    let sent = match (destination, entry.offset != 0) {
        // The parser gives four bytes; the v4 service speaks the wire word.
        // Converted here and named, because getting it backwards sends every
        // datagram to a mirrored address and nothing says so.
        (Endpoint::V4 { address, port: to }, false) => bhaskix_sock::udp::Socket::from_slot(
            entry.handle,
            port,
        )
        .send_to(PAYLOAD, u32::from_be_bytes(address), to, length),
        (
            Endpoint::V6 {
                address, port: to, ..
            },
            true,
        ) => bhaskix_sock::udp6::Socket6::from_slot(entry.handle, port)
            .send_to(PAYLOAD, address, to, length),
        // A v6 address down a v4 socket, or the reverse. Linux answers this
        // rather than translating, and so does this.
        _ => {
            trace_file(-97, STAGE_SEND_REFUSED, 6);
            return Answer::error(-97); // EAFNOSUPPORT
        }
    };
    match sent {
        Ok(()) => {
            trace_file(length as i64, STAGE_SENT, u64::from(port));
            Answer::ok(length as u64)
        }
        Err(_) => {
            trace_file(-101, STAGE_SEND_REFUSED, u64::from(port));
            Answer::error(-101) // ENETUNREACH
        }
    }
}

/// Answers a hosted `recvfrom`.
///
/// **Non-blocking, and that is a limitation rather than a design.** `bin/ipd`
/// answers "nothing yet" and this adapter passes that on as `EAGAIN`; a
/// hosted program that blocks on a datagram would need this call to park it
/// the way `read` on a pipe already does, which is a reply shape rather than
/// a value and belongs with `epoll`. Recorded in the step, not smoothed over:
/// a program looping on `EAGAIN` is spinning.
fn answer_recvfrom(request: &PersonalityCall) -> Answer {
    use bhaskix_personality::file::Kind;
    use bhaskix_personality::socket::{Endpoint, write_endpoint};

    let Ok(descriptor) = i32::try_from(request.first()) else {
        return Answer::error(-9);
    };
    let wanted = (request.third() as usize).min(bhaskix_mm_frame());
    let Some(process) = process_for(request.domain) else {
        return Answer::error(-11);
    };
    let Some(entry) = process.descriptors.get(descriptor).copied() else {
        return Answer::error(-9);
    };
    if entry.kind != Kind::Socket {
        return Answer::error(-88);
    }
    if entry.handle == u64::MAX {
        return Answer::error(-22);
    }
    if !payload_ready() {
        trace_file(-14, STAGE_NOTHING_YET, 2);
        return Answer::error(-14);
    }
    let port = entry.size as u16;
    let sender = if entry.offset != 0 {
        bhaskix_sock::udp6::Socket6::from_slot(entry.handle, port)
            .recv_from(PAYLOAD)
            .map(|taken| {
                taken.map(|from| Endpoint::V6 {
                    address: from.address,
                    port: from.port,
                    scope: 0,
                })
            })
    } else {
        bhaskix_sock::udp::Socket::from_slot(entry.handle, port)
            .recv_from(PAYLOAD)
            .map(|taken| {
                taken.map(|from| Endpoint::V4 {
                    address: from.address.to_be_bytes(),
                    port: from.port,
                })
            })
    };
    let from = match sender {
        Ok(Some(from)) => from,
        Ok(None) => {
            trace_file(-11, STAGE_NOTHING_YET, u64::from(port));
            return Answer::error(-11); // EAGAIN: nothing yet
        }
        Err(_) => {
            trace_file(-5, STAGE_NOTHING_YET, 1);
            return Answer::error(-5); // EIO
        }
    };
    trace_file(0, STAGE_RECEIVED, u64::from(from_port(&from)));
    let mut bytes = [0u8; SCRATCH_BYTES as usize];
    let take = wanted.min(bytes.len());
    for (index, byte) in bytes.iter_mut().take(take).enumerate() {
        // SAFETY: inside the page `ATTACH` mapped from this program's own
        // object, bounded by the frame size above.
        *byte = unsafe { core::ptr::read_volatile((PAYLOAD_AT + index as u64) as *const u8) };
    }
    if !copy_out(request.domain, request.second(), &bytes[..take]) {
        return Answer::error(-14);
    }
    // The sender's address, if the caller asked where it came from. A caller
    // that passed no buffer is not told, which is what a null pointer means.
    if request.fifth() != 0 {
        let mut out = [0u8; bhaskix_personality::socket::SOCKADDR_IN6_BYTES];
        if let Ok(written) = write_endpoint(&mut out, &from)
            && !copy_out(request.domain, request.fifth(), &out[..written])
        {
            return Answer::error(-14);
        }
    }
    Answer::ok(take as u64)
}

/// Answers a hosted `close`, giving the capability back with the descriptor.
/// Gives back whatever a closed descriptor named, if it was the last to name it.
///
/// **Extracted rather than copied**, because it now has two callers and the
/// second one is what this exists for: `close` has always done this, and
/// `execve` — which closes every `FD_CLOEXEC` row — did not, and leaked one of
/// this program's thirty-two file slots per descriptor for the life of the
/// boot. Two copies of these three arms would be two places for the next arm
/// to be added to only one of them.
///
/// `last` is the caller's answer to "does any surviving row still name this
/// handle", which `Descriptors::holders` decides. It is a parameter rather
/// than a question asked here because the two callers learn it at different
/// moments: `close` after removing one row, `close_on_exec` after removing one
/// of possibly several.
fn give_back_descriptor(entry: bhaskix_personality::file::Entry, last: bool) {
    use bhaskix_personality::file::Kind;

    // **Except the root**, which was never claimed from the pool and must
    // never be given back to it: `release_file_slot` `DELETE`s the capability
    // in the slot, and the capability in this one is the directory the kernel
    // granted this program at boot. One hosted `close(dirfd)` would take every
    // hosted process's filesystem away for the life of the machine.
    if entry.handle != ROOT_DIR && last && matches!(entry.kind, Kind::File | Kind::Directory) {
        release_file_slot(entry.handle);
    }
    // **And a socket's slot, which comes from a different pool.** A socket
    // that was never bound holds nothing -- `u64::MAX` is the row's way of
    // saying so -- and releasing that would compute an index far outside the
    // six.
    if entry.kind == Kind::Socket && entry.handle != u64::MAX && last {
        release_socket_slot(entry.handle);
    }
    // **A pipe end closing is a count, not a teardown** — RFC 0033 step 7.
    // Which end matters: with no reader left a writer is told `EPIPE`, and
    // with no writer left a reader is told end of file. Getting the two the
    // wrong way round would make a pipeline either hang for ever or stop at
    // its first pause.
    //
    // **Not gated on `last`**, and that is deliberate: a pipe end is a *count*
    // of readers and writers, so every row that closes decrements it. The two
    // arms above hand back a capability, which may happen once; this one
    // records that one holder of many has gone.
    if entry.kind == Kind::Pipe {
        // SAFETY: single-threaded by construction, as elsewhere here.
        let pipes = pipes_held();
        if let Some(slot) = pipes.get_mut(entry.handle as usize)
            && let Some(pipe) = slot.as_mut()
        {
            if entry.readable {
                pipe.close_read_end();
            } else {
                pipe.close_write_end();
            }
            // A reader waiting on a pipe whose last writer has just gone must
            // be woken to be told so, or it waits for bytes nobody will ever
            // write.
            if pipe.at_end() {
                wake_pipe_reader(entry.handle as usize);
            }
            if pipe.abandoned() {
                *slot = None;
            }
        }
    }
}

fn answer_close(request: &PersonalityCall) -> Answer {
    let Ok(descriptor) = i32::try_from(request.first()) else {
        return Answer::error(-9);
    };
    let Some(process) = process_for(request.domain) else {
        return Answer::error(-11);
    };
    match process.descriptors.close(descriptor) {
        Ok(entry) => {
            // **The capability goes with the row**, and this is the whole
            // reason `close` is not just a table edit: a descriptor closed
            // without dropping what it named would leak one of this program's
            // hundred and twenty-eight slots per open file, for the life of
            // the machine.
            // **Except the root**, which was never claimed from the pool
            // and must never be given back to it: `release_file_slot`
            // `DELETE`s the capability in the slot, and the capability in
            // this one is the directory the kernel granted this program at
            // boot. One hosted `close(dirfd)` would take every hosted
            // process's filesystem away for the life of the machine.
            let last = process.descriptors.holders(entry.handle) == 0;
            give_back_descriptor(entry, last);
            Answer::ok(0)
        }
        Err(errno) => Answer::error(errno),
    }
}

/// Answers `dup`, `dup2` and `dup3` — RFC 0033 step 6.
///
/// **Two descriptors, one open file, one capability.** A duplicate names the
/// same handle this program holds; nothing is derived and nothing is asked of
/// the filesystem service, because the authority is already held and a second
/// integer pointing at it confers nothing new. What it does change is when the
/// capability may be given back, which is why `close` counts the rows that
/// name a handle rather than assuming it is the last.
fn answer_dup(request: &PersonalityCall) -> Answer {
    let Ok(from) = i32::try_from(request.first()) else {
        return Answer::error(-9); // EBADF
    };
    let close_on_exec = request.number == DUP3 && request.third() & 0o2_000_000 != 0;
    let Some(process) = process_for(request.domain) else {
        return Answer::error(-11);
    };
    if request.number == DUP {
        // The lowest free number, which is `dup`'s whole definition.
        let Some(entry) = process.descriptors.get(from).copied() else {
            return Answer::error(-9);
        };
        return match process.descriptors.insert(
            bhaskix_personality::file::Entry {
                close_on_exec: false,
                ..entry
            },
            0,
        ) {
            Ok(descriptor) => Answer::ok(descriptor as u64),
            Err(errno) => Answer::error(errno),
        };
    }
    let Ok(to) = i32::try_from(request.second()) else {
        return Answer::error(-9);
    };
    // `dup2(fd, fd)` succeeds and does nothing; `dup3` refuses it. The
    // difference is Linux's and is kept rather than smoothed over: a program
    // using `dup3` to set `O_CLOEXEC` on a descriptor is told that is not what
    // this call does.
    if from == to && request.number == DUP2 {
        return match process.descriptors.get(from) {
            Some(_) => Answer::ok(to as u64),
            None => Answer::error(-9),
        };
    }
    match process.descriptors.dup3(from, to, close_on_exec) {
        Ok((descriptor, displaced)) => {
            // Whatever `to` named is closed silently, which is `dup2`'s
            // contract -- and its capability goes with it unless another
            // descriptor still names the same file.
            if let Some(entry) = displaced
                && process.descriptors.holders(entry.handle) == 0
                && matches!(
                    entry.kind,
                    bhaskix_personality::file::Kind::File
                        | bhaskix_personality::file::Kind::Directory
                )
            {
                release_file_slot(entry.handle);
            }
            Answer::ok(descriptor as u64)
        }
        Err(errno) => Answer::error(errno),
    }
}

/// The one path component this personality resolves, or `None`.
///
/// Leading slashes are skipped and a trailing `NUL` ends it. A name with a
/// separator *inside* it is refused rather than walked: walking is what a
/// working directory and a second directory capability are for, and neither
/// exists yet.
fn one_component(name: &[u8]) -> Option<&[u8]> {
    let start = name.iter().position(|byte| *byte != b'/')?;
    let rest = &name[start..];
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(rest.len());
    let component = &rest[..end];
    if component.is_empty() || component.contains(&b'/') {
        return None;
    }
    Some(component)
}

/// The longest path this personality reads out of a hosted program.
const MAX_NAME: usize = 64;

/// The one **writable** directory a hosted process has — RFC 0060.
const WRITABLE_DIR: u64 = bhaskix_abi::adapter::WRITABLE_DIR as u64;

/// The name it answers to inside a hosted process's root.
const WRITABLE_NAME: &[u8] = b"tmp";

/// Splits `/tmp/<name>` into its second component, when that is what it is.
///
/// **Two components, not general path walking.** `one_component` refuses
/// separators, which is what confines a hosted process to the directory it was
/// granted; this is the one exception and it is narrow on purpose — the first
/// component must be exactly [`WRITABLE_NAME`], and what comes back is resolved
/// in the *writable* capability. Deeper paths, `..`, or any other first
/// component are still refused, so the exception cannot be widened by a caller.
fn writable_component(name: &[u8]) -> Option<&[u8]> {
    let start = name.iter().position(|byte| *byte != b'/')?;
    let rest = &name[start..];
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(rest.len());
    let rest = &rest[..end];
    let slash = rest.iter().position(|byte| *byte == b'/')?;
    if &rest[..slash] != WRITABLE_NAME {
        return None;
    }
    let tail = &rest[slash + 1..];
    if tail.is_empty() || tail.contains(&b'/') || tail == b"." || tail == b".." {
        return None;
    }
    Some(tail)
}

/// What the filesystem service said about a name it resolved.
#[derive(Clone, Copy)]
struct Opened {
    /// The filesystem's own name for it, which `fstat` answers with.
    inode: u64,
    /// Its size in bytes.
    size: u64,
    /// Whether it is a directory rather than a file.
    directory: bool,
}

/// Resolves one name in this process's root directory into `slot`.
///
/// **Extracted at RFC 0059 rather than copied.** `execve` has to resolve a
/// name exactly the way `open` does — same directory, same one component, same
/// four refusals told apart by stage — and a second copy of this sequence
/// would be a second place for the `CALL`-versus-`INVOKE` mistake below to be
/// made again.
///
/// The caller owns the slot: on any error nothing was installed into it, and
/// releasing it is the caller's business because only the caller knows whether
/// it came from the file pool or somewhere else.
///
/// # Errors
///
/// The Linux errno to answer with. `ENOENT` for every way the service can say
/// no, because that is the truth a hosted program can act on; *which* way it
/// was goes into the trace record, for whoever is reading a boot.
fn resolve_into(slot: u64, component: &[u8]) -> Result<Opened, i64> {
    // Where the answer may land, said before asking and addressed to the
    // service being asked -- the protocol's own rule, and what stops a
    // capability arriving somewhere the caller did not choose.
    let declared = call(syscall::INVOKE, ROOT_DIR, method::EXPECT, [slot, 0, 0, 0]);
    if declared.status != status::OK {
        trace_file(-2, STAGE_NO_DIRECTORY, declared.status);
        return Err(-2);
    }
    let (chunk, rest) = bhaskix_abi::Chunk::take(component);
    if !rest.is_empty() {
        return Err(-36); // ENAMETOOLONG
    }
    // **`CALL` and not `INVOKE`.** A directory is a *badged endpoint to the
    // filesystem service*, so opening a name is a message to that service
    // rather than an operation the kernel performs. Invoking it asked the
    // kernel to do something to an endpoint and was refused with
    // `InsufficientRights` -- a refusal that says nothing about directories,
    // and cost a boot to read.
    let reply = call(
        syscall::CALL,
        ROOT_DIR,
        bhaskix_abi::dir::OPEN_AT,
        chunk.pack(0),
    );
    if reply.status != status::OK {
        trace_file(-2, STAGE_SERVICE_SILENT, reply.status);
        return Err(-2);
    }
    if reply.args[0] != bhaskix_abi::dir::OK {
        trace_file(-2, STAGE_SERVICE_REFUSED, reply.args[0]);
        return Err(-2); // ENOENT
    }
    Ok(Opened {
        inode: reply.args[3],
        size: reply.args[1],
        directory: reply.args[2] != 0,
    })
}

/// Records how a hosted process ended, for whoever waits for it.
///
/// **The record becomes a zombie rather than disappearing**, because the exit
/// status belongs to the parent and nothing else knows it. A process nobody
/// started — every hosted probe in this tree — has a parent of zero, and
/// `Processes::ended` reparents its children and leaves it collectable; the
/// adapter drops such a record when the domain slot is reused, because nobody
/// will ever read it.
///
/// And whoever is *waiting* is woken here, because a parent parked in `wait4`
/// is parked on a notification this program holds and nothing else will signal
/// it.
fn note_exit(domain: u32, exit: Exit) {
    let Some(process) = process_for(domain) else {
        return;
    };
    let (pid, parent) = (process.pid, process.ppid);

    // **A dead process's sockets come back, and nothing else would bring
    // them.** `bin/ipd` holds four; a hosted program that exits without
    // closing one keeps it for the life of the machine, because the
    // capability sits in *this* program's CSpace rather than the dead
    // domain's, and the service has no signal that a caller has gone --
    // RFC 0016 says so about its own sessions and the same is true here.
    //
    // Found the hard way: the socket probe leaked its one socket, that was
    // the fourth of four, and the *shell* could no longer bind. A leak in a
    // hosted program showed up as an unrelated program losing its network,
    // which is exactly the failure shape a shared adapter produces
    // (RFC 0031 I5).
    //
    // Files are not released here and that is not an oversight: a file's slot
    // is per-open and `close` returns it, and a hosted process that dies
    // holding one leaks a slot from a pool of thirty-two rather than a
    // service's scarce table. Recorded as a difference rather than made
    // uniform, because the two pools are not the same size or the same kind.
    release_sockets_of(domain);

    // SAFETY: single-threaded by construction, as elsewhere here.
    let processes = processes();
    let _ = processes.ended(pid, exit);
    wake_waiter(parent);
}

/// Gives back every socket a domain still holds.
///
/// Called from both ways a hosted process can stop mattering: `note_exit`, for
/// one that exits, and the `FORGET` message, for one killed from outside. It
/// was inside `note_exit` alone until RFC 0058, which is why a killed domain
/// kept its socket.
///
/// **The last holder only.** A descriptor duplicated by `dup` names the same
/// capability, and releasing on the first of them would take the socket from
/// the second.
fn release_sockets_of(domain: u32) {
    let Some(process) = process_for(domain) else {
        return;
    };
    for descriptor in 0..bhaskix_personality::file::MAX_DESCRIPTORS {
        let Ok(number) = i32::try_from(descriptor) else {
            break;
        };
        let Some(entry) = process.descriptors.get(number).copied() else {
            continue;
        };
        if entry.kind == bhaskix_personality::file::Kind::Socket
            && entry.handle != u64::MAX
            && process.descriptors.holders(entry.handle) == 1
        {
            release_socket_slot(entry.handle);
            // **Forgotten as well as released, or the second caller releases it
            // again.** This runs from two places now -- `note_exit` when a
            // process exits, and `FORGET` when its slot is reused -- and a
            // record that survives the first is walked again by the second. The
            // slot is reused between them, so the second release closes a
            // socket belonging to whoever holds it now: a live program losing
            // its network because a dead one was cleaned up twice.
            //
            // Found by the socket probe answering `EADDRINUSE` on the boot
            // after this function gained its second caller.
            if let Some(process) = process_for(domain)
                && let Some(entry) = process.descriptors.get_mut(number)
            {
                entry.handle = u64::MAX;
            }
        }
    }
}

/// Wakes a process parked in `wait4`, if that is where it is.
fn wake_waiter(pid: u32) {
    if pid == 0 {
        return;
    }
    // SAFETY: as above.
    let waiters = waiters();
    let Some(entry) = waiters.iter_mut().find(|entry| entry.0 == pid) else {
        return;
    };
    let slot = entry.1;
    *entry = (0, 0);
    let _ = call(
        syscall::INVOKE,
        WAKE_SLOT + u64::from(slot),
        method::SIGNAL,
        [0; 4],
    );
    release_wake(slot as usize);
}

/// Who is parked in `wait4`, and on which wake slot: `(pid, slot)`.
///
/// One entry per waiting parent. Four, because a machine with more hosted
/// processes waiting at once than that has other problems first — and a fifth
/// is answered `EAGAIN` rather than left unwoken.
static mut WAITERS: [(u32, u32); 4] = [(0, 0); 4];

/// Answers a hosted `wait4` — RFC 0033 step 9.
///
/// **Three answers, and the middle one is why this needs a reply shape.** A
/// dead child: its pid, and Linux's status word written where the caller
/// asked. No children at all: `ECHILD`. Children, none dead: the caller
/// *waits* — parked on a notification, woken by whichever child ends, and then
/// asked again — unless it said `WNOHANG`, which answers zero.
fn answer_wait(request: &PersonalityCall) -> (u64, Answer) {
    use bhaskix_personality::process::{WaitFor, WaitOutcome};

    const WNOHANG: u64 = 1;
    let (which, status_at, options) = (request.first(), request.second(), request.third());
    let Some(process) = process_for(request.domain) else {
        return (REPLY_VALUE, Answer::error(-11));
    };
    let (pid, group) = (process.pid, process.pgid);
    let wanted = WaitFor::from_argument(which as i64, group);
    // SAFETY: single-threaded by construction, as elsewhere here.
    let processes = processes();
    match processes.collect(pid, wanted) {
        Ok(WaitOutcome::Collected { pid: child, status }) => {
            trace_wait(i64::from(child), u64::from(status));
            // The status word goes where the caller asked, if it asked: a
            // `wait4` with a null pointer is a reap and nothing more, which is
            // what `wait(NULL)` has always meant.
            if status_at != 0 && !copy_out(request.domain, status_at, &status.to_le_bytes()) {
                return (REPLY_VALUE, Answer::error(-14)); // EFAULT
            }
            (REPLY_VALUE, Answer::ok(u64::from(child)))
        }
        Ok(WaitOutcome::WouldBlock) if options & WNOHANG != 0 => {
            trace_wait(-1, 0);
            (REPLY_VALUE, Answer::ok(0))
        }
        Ok(WaitOutcome::WouldBlock) => {
            let Some(slot) = claim_wake() else {
                return (REPLY_VALUE, Answer::error(-11));
            };
            // SAFETY: as above.
            let waiters = waiters();
            let Some(entry) = waiters.iter_mut().find(|entry| entry.0 == 0) else {
                release_wake(slot);
                return (REPLY_VALUE, Answer::error(-11));
            };
            *entry = (pid, slot as u32);
            trace_wait(-2, u64::from(pid));
            (REPLY_BLOCK_ON_RETRY, Answer::ok(WAKE_SLOT + slot as u64))
        }
        Err(errno) => {
            trace_wait(errno, 0);
            (REPLY_VALUE, Answer::error(errno))
        }
    }
}

/// Answers a hosted `fork` — RFC 0033 step 8, stage one.
///
/// **By copying, and the copying is the point.** The RFC's stage two is a
/// copy-on-write `COPY_SPACE` in the nucleus, and it is written down as
/// something to build *only if a measurement says so* — so this is the
/// measurement: every region the parent has is mapped in the child and its
/// bytes moved through an object this program owns, a kilobyte at a time,
/// with no new kernel mechanism at all.
///
/// The child's first instruction is a **trampoline**, three instructions this
/// program writes into a page of the child's own memory: zero `rax`, and jump
/// to where the parent's `fork` returns. That is what makes `fork` answer
/// **0 in the child and the child's pid in the parent** without the kernel
/// having to start a thread from a register image.
///
/// ## What this fork does not carry, said plainly
///
/// The child arrives with `rax` zero, the parent's stack pointer, and the
/// parent's instruction pointer. **Every other register is empty**, because
/// the only place the parent's registers exist is the CPU and the entry stub
/// saves the caller-saved set alone (RFC 0032 step 8 recorded that narrowing
/// and named its price: widening the stub means widening the hottest path in
/// the system). A hand-written program that expects nothing else survives it;
/// a compiled one does not, because a Linux `syscall` preserves the
/// callee-saved registers and its caller relies on that.
///
/// So this is a fork that **copies an address space correctly** and hands the
/// child a register file it should not have to accept. The measurement is
/// real; the call is not yet one a real program can use, and L2 is where that
/// has to be true.
fn answer_fork(request: &PersonalityCall, image: &[u64; FAULT_REGISTERS]) -> Answer {
    // The parent's own `rip` and `rsp`, out of the frame the kernel staged --
    // the same two words `rt_sigreturn` reads, at the same offsets, because
    // there is one register order and both sides write it down.
    let rip = image[15];
    let rsp = image[17];

    let made = call(
        syscall::INVOKE,
        CONTROL,
        method::SPAWN,
        [CHILD, FORK_NAME_LOW, 0, 0],
    );
    if made.status != status::OK {
        return Answer::error(-11); // EAGAIN
    }
    let child_domain = made.args[0] as u32;
    let outcome = build_fork_child(request, rip, rsp);
    let _ = call(syscall::INVOKE, CHILD, method::DELETE, [0; 4]);
    let Some(copied) = outcome else {
        return Answer::error(-12); // ENOMEM
    };

    // The record last, so that a child which fails to build leaves none.
    let generation = incarnation_of(child_domain);
    let Some(parent) = process_for(request.domain) else {
        return Answer::error(-11);
    };
    let pid = {
        // SAFETY: single-threaded by construction, as elsewhere here.
        let processes = processes();
        let Ok(pid) = processes.admit(parent.pid, child_domain, generation) else {
            return Answer::error(-11);
        };
        let parent = *parent;
        if let Some(child) = processes.by_pid_mut(pid) {
            let identity = (child.pid, child.ppid, child.domain, child.generation);
            *child = parent.fork_into(identity.0, identity.2, identity.3);
            child.ppid = identity.1;
        }
        pid
    };
    trace_fork(pid, copied);
    Answer::ok(u64::from(pid))
}

/// Builds the child of a `fork`: its space, its memory, its first thread.
///
/// Answers how many bytes were copied, which is the number step 8 exists to
/// produce.
fn build_fork_child(request: &PersonalityCall, rip: u64, rsp: u64) -> Option<u64> {
    if call(syscall::INVOKE, CHILD, method::PERSONALITY, [1, 0, 0, 0]).status != status::OK {
        return None;
    }
    if call(syscall::INVOKE, CHILD, method::MAKE_SPACE, [0; 4]).status != status::OK {
        return None;
    }

    let mut copied = 0u64;
    let process = process_for(request.domain)?;
    let regions = process.regions;
    let parent = request.domain;
    for region in regions.iter().flatten() {
        if !map_at_eager(CHILD, region.at, region.pages, region.protection) {
            return None;
        }
        // A kilobyte at a time, because that is what the scratch object holds
        // and what one `COPY_IN` may move. Two invocations per kilobyte is the
        // price stage two exists to argue with.
        let bytes = region.pages * 4096;
        let mut moved = 0;
        while moved < bytes {
            let take = (bytes - moved).min(SCRATCH_BYTES) as usize;
            let mut chunk = [0u8; SCRATCH_BYTES as usize];
            if !copy_in(parent, region.at + moved, &mut chunk[..take]) {
                // A region with a hole in it -- a lazily mapped page nothing
                // has touched -- is not an error: there is nothing there to
                // copy, and the child's own page is already zero.
                moved += take as u64;
                continue;
            }
            if !copy_out_through(CHILD, region.at + moved, &chunk[..take]) {
                return None;
            }
            moved += take as u64;
            copied += take as u64;
        }
    }

    // The trampoline: `xor eax, eax; movabs rcx, rip; jmp rcx`, in a page of
    // the child's own memory. Three instructions rather than a kernel method
    // to start a thread from a register image -- and `rcx` because a `syscall`
    // destroys it anyway, so no program can be relying on what is in it here.
    let mut code = [0u8; 16];
    code[0] = 0x31;
    code[1] = 0xc0; // xor eax, eax
    code[2] = 0x48;
    code[3] = 0xb9; // movabs rcx, imm64
    code[4..12].copy_from_slice(&rip.to_le_bytes());
    code[12] = 0xff;
    code[13] = 0xe1; // jmp rcx
    if !map_at_eager(CHILD, FORK_TRAMPOLINE_AT, 1, PROT_READ_EXECUTE)
        || !copy_out_through(CHILD, FORK_TRAMPOLINE_AT, &code)
    {
        return None;
    }
    let started = call(
        syscall::INVOKE,
        CHILD,
        method::SPAWN_THREAD,
        [FORK_TRAMPOLINE_AT, rsp, 0, 0],
    );
    if started.status != status::OK {
        return None;
    }
    Some(copied)
}

/// Answers a hosted `execve` — [RFC 0033](../../../docs/rfc/0033-what-a-hosted-process-is.md) step 5.
///
/// **A hosted process cannot exec in place**, and the reason is structural
/// rather than incidental: `START` refuses a domain that has threads, and the
/// thread asking is one of them. So an exec *builds a new domain* and ends the
/// old one — and the pid, the parent, the group and everything else Linux says
/// survives an exec goes with the record rather than with the domain. That is
/// the whole reason RFC 0033 moved identity into this program.
///
/// The sequence, all of it through capabilities this program holds:
///
/// ```text
///   SPAWN        a domain, from DomainControl and the envelope's allowance
///   PERSONALITY  Linux, so its calls arrive here
///   MAP_AT       code (read-execute) and stack (read-write), eagerly
///   COPY_OUT     the image into the code pages
///   SPAWN_THREAD at the entry, on the stack
///   exec_into    the record: same pid, new domain
///   REPLY_END_DOMAIN   which is what ends the *caller's* domain
/// ```
///
/// **The last line is the one worth reading twice.** Nothing here can kill a
/// domain — RFC 0017 deliberately left that out, and a supervisor holding a
/// child's handle still cannot. What ends the old domain is the *reply*: the
/// caller is told "end your domain", and the kernel does it to the thread that
/// asked. An exec is therefore the caller's own last act, which is exactly
/// what `execve` is in Linux.
fn answer_execve(request: &PersonalityCall) -> (u64, Answer) {
    // The path, read out of the caller's memory through the `Domain`
    // capability -- **to its NUL, not to a fixed width**. A `[u8; MAX_NAME]`
    // copy refuses a short path that happens to sit in the last bytes of a
    // mapping, because the copy reaches past it into a page the process does
    // not have; `exec::read_string` stops at each page boundary for exactly
    // that case and is host-tested against it.
    let mut path = [0u8; MAX_NAME];
    let length =
        match bhaskix_personality::exec::read_string(request.first(), &mut path, &mut |at, out| {
            copy_in(request.domain, at, out)
        }) {
            Ok(length) => length,
            // `E2BIG` from a *path* is Linux's `ENAMETOOLONG`; `EFAULT` passes
            // through as itself.
            Err(bhaskix_personality::exec::errno::E2BIG) => {
                return (REPLY_VALUE, Answer::error(-36));
            }
            Err(errno) => return (REPLY_VALUE, Answer::error(errno)),
        };
    let path = &path[..length];

    // **The two vectors, before anything is created.** An `execve` refused for
    // its arguments must leave the caller running and unchanged, and the
    // cheapest way to guarantee that is to do every refusable read before the
    // first act that would have to be undone. A hosted process chose every one
    // of these pointers, so this is the untrusted-input parser of the call and
    // it lives in `bhaskix-personality`, host-tested, with no capability
    // anywhere near it.
    let arguments = exec_arguments();
    if let Err(errno) = arguments.read(request.second(), request.third(), &mut |at, out| {
        copy_in(request.domain, at, out)
    }) {
        return (REPLY_VALUE, Answer::error(errno));
    }

    // Where the image comes from: this program carries one, and the filesystem
    // holds the rest.
    let staged = if path == EXEC_PATH.as_slice() {
        None
    } else {
        match stage_from_filesystem(path) {
            Ok(bytes) => Some(bytes),
            Err(errno) => return (REPLY_VALUE, Answer::error(errno)),
        }
    };

    // A domain to become. The slot is this program's own scratch, and one at a
    // time is enough: this program has one thread, so no second exec can be in
    // flight while this one is between its first call and its last.
    let made = call(
        syscall::INVOKE,
        CONTROL,
        method::SPAWN,
        [CHILD, EXEC_NAME_LOW, 0, 0],
    );
    if made.status != status::OK {
        // The envelope's allowance is spent, which is a real limit and not a
        // failure to be hidden: `EAGAIN` is what Linux answers when it cannot
        // make a process.
        return (REPLY_VALUE, Answer::error(-11));
    }

    // **The errno is the builder's to choose.** The built-in image can only
    // fail for want of memory; a program off the filesystem can be refused by
    // the ELF parser, or for a segment that would land on its own stack, and
    // answering `ENOMEM` to either would send whoever is debugging it looking
    // for memory pressure that is not there.
    let built = match staged {
        None if build_exec_image() => Ok(()),
        None => Err(-12), // ENOMEM
        Some(bytes) => build_staged_image(bytes, arguments),
    };
    // The handle is given back either way. A slot left occupied would refuse
    // the *next* exec for a reason that has nothing to do with it.
    // **The record is looked up before anything moves it**, and the first
    // version of this got that wrong: it bumped the old domain's incarnation
    // first, so the lookup below found nothing, admitted a *fresh* record, and
    // exec'd that — the exec'd program printed a pid one higher than the
    // program it replaced, which is the exact failure this step exists to
    // prevent. The old slot's incarnation moves when the kernel says it has
    // been reused (`FORGET`), which is the only moment that is true.
    let outcome = match built {
        Ok(()) => (REPLY_END_DOMAIN, Answer::ok(0)),
        Err(errno) => (REPLY_VALUE, Answer::error(errno)),
    };
    if built.is_ok() {
        // The record moves to the new domain *before* the old one ends, so a
        // call arriving from the new domain finds the same process. The
        // generation is this program's own count of how often the slot has
        // been handed over -- see `INCARNATION`.
        let child = made.args[0] as u32;
        let generation = incarnation_of(child);
        if let Some(process) = process_for(request.domain) {
            let pid = process.pid;
            let from = process.domain;
            // **The capabilities go with the rows** — the defect filed on
            // 2026-08-30 and fixed here. This was `|_| {}`, so every
            // `FD_CLOEXEC` descriptor carried across an `execve` leaked one of
            // this program's thirty-two file slots for the rest of the boot.
            // `last` is `close_on_exec`'s own answer to whether a surviving
            // row still names the handle, which is the part `dup` makes
            // impossible for a caller to work out for itself.
            process.exec_into(child, generation, drawn_base(), give_back_descriptor);
            trace_exec(pid, from, child);
        }
    }
    let _ = call(syscall::INVOKE, CHILD, method::DELETE, [0; 4]);
    outcome
}

/// Reads a program out of this process's root directory into the staging
/// object, and says how many bytes arrived — RFC 0059 step 3.
///
/// **Nothing is created before this succeeds.** It is called with no child
/// domain in existence, so every refusal here leaves the calling process
/// exactly as it was, which is what `execve` promises for a failed exec.
///
/// # Errors
///
/// `ENOENT` for a name that is not there, `EACCES` for a directory (Linux's
/// answer for `execve` of one), `ENOEXEC` for an empty file, `E2BIG` for one
/// larger than the staging object, and `EIO` if the service stops answering
/// part way through.
fn stage_from_filesystem(name: &[u8]) -> Result<u64, i64> {
    let Some(component) = one_component(name) else {
        return Err(-2); // ENOENT
    };
    let Some(slot) = claim_file_slot() else {
        return Err(-24); // EMFILE
    };
    let opened = match resolve_into(slot, component) {
        Ok(opened) => opened,
        Err(errno) => {
            release_file_slot(slot);
            return Err(errno);
        }
    };
    let refusal = if opened.directory {
        Some(-13) // EACCES: a directory is not a program
    } else if opened.size == 0 {
        Some(-8) // ENOEXEC: nothing is not a program either
    } else if opened.size > STAGING_BYTES {
        // **Said, not truncated.** Loading the first 64 KiB of a larger
        // program would produce a domain that faults somewhere unrelated, and
        // the limit is a property of this adapter rather than of the file.
        Some(-7) // E2BIG
    } else {
        None
    };
    if let Some(errno) = refusal {
        release_file_slot(slot);
        trace_file(errno, STAGE_EXEC_REFUSED, opened.size);
        return Err(errno);
    }

    // **`READ_INTO` lands the bytes at the file's own offset**, which is what
    // makes a linear read reassemble the file in place — and also why the
    // staging object has to be as large as the file rather than a window that
    // could be slid along it. The service moves at most a page per call and
    // says how much went; the loop is the caller's, as the protocol says.
    let mut done = 0u64;
    while done < opened.size {
        let reply = call(
            syscall::CALL,
            slot,
            bhaskix_abi::dir::READ_INTO,
            [STAGING, 4096, done, 0],
        );
        if reply.status != status::OK || reply.args[0] != bhaskix_abi::dir::OK {
            release_file_slot(slot);
            trace_file(-5, STAGE_EXEC_READ, reply.args[0] | (reply.status << 32));
            return Err(-5); // EIO
        }
        let moved = reply.args[1];
        if moved == 0 {
            // The service says end of file before the size it reported. That
            // is a disagreement inside the filesystem, not something the
            // calling program did, and a short image would fail later as
            // something stranger.
            break;
        }
        done += moved;
    }
    release_file_slot(slot);
    if done != opened.size {
        trace_file(-5, STAGE_EXEC_SHORT, done);
        return Err(-5); // EIO
    }
    Ok(done)
}

/// The staged bytes, as a slice, mapping the staging object on first use.
///
/// # Errors
///
/// `EIO` if the object will not attach — which would mean this program's own
/// address space, not anything the caller did.
fn staged_bytes(length: u64) -> Result<&'static [u8], i64> {
    // SAFETY: single-threaded by construction, as every other table here.
    let mapped = unsafe { &mut *core::ptr::addr_of_mut!(STAGE_MAPPED) };
    if !*mapped {
        // Read-only: this program parses the image and never edits it, and
        // `READ_INTO` fills the object through the kernel rather than through
        // this mapping, so no write right is wanted here.
        if call(
            syscall::INVOKE,
            STAGING,
            method::ATTACH,
            [STAGE_AT, 0, 0, 0],
        )
        .status
            != status::OK
        {
            return Err(-5); // EIO
        }
        *mapped = true;
    }
    let length = (length.min(STAGING_BYTES)) as usize;
    // SAFETY: inside the window `ATTACH` mapped from the object the kernel
    // granted this program at boot, bounded by the object's own size — and by
    // the file size, which `stage_from_filesystem` refused above if larger.
    Ok(unsafe { core::slice::from_raw_parts(STAGE_AT as *const u8, length) })
}

/// Loads a program off the filesystem into the child domain and starts it —
/// RFC 0059 step 4.
///
/// **Every segment arrives through a mapping this program never holds
/// writable**, which is how `W^X` survives a loader in ring 3: `COPY_OUT`
/// writes through the *kernel's* view of the child's frames, so a read-execute
/// segment is filled without ever being writable in any address space. That is
/// the same mechanism the built-in image has always used, applied to a file.
///
/// # Errors
///
/// `ENOEXEC` for anything the ELF parser refuses or that would land on the
/// stack this loader is about to map, `E2BIG` if the initial image does not
/// fit its page, and `ENOMEM` for a kernel call that refuses.
fn build_staged_image(
    length: u64,
    arguments: &bhaskix_personality::exec::Arguments,
) -> Result<(), i64> {
    use bhaskix_personality::stack::{Builder, ProcessInfo};

    let bytes = staged_bytes(length)?;
    let Ok(parsed) = bhaskix_elf::parse(bytes) else {
        return Err(-8); // ENOEXEC
    };

    if call(syscall::INVOKE, CHILD, method::PERSONALITY, [1, 0, 0, 0]).status != status::OK {
        return Err(-12);
    }
    if call(syscall::INVOKE, CHILD, method::MAKE_SPACE, [0; 4]).status != status::OK {
        return Err(-12);
    }

    let stack_end = EXEC_STACK_BASE + EXEC_STACK_PAGES * 4096;
    for segment in parsed.segments() {
        let Some((start, end)) = bhaskix_elf::page_span(segment) else {
            return Err(-8);
        };
        // **A program may not be linked over its own stack.** The parser
        // checks a segment against the address space; it has no idea where
        // this loader is about to put a stack, so that check is here. Refused
        // rather than relocated: moving the stack to suit an image would make
        // the layout a function of the file, and a program that asked for this
        // address is asking for something it will not get.
        if start < stack_end && end > EXEC_STACK_BASE {
            return Err(-8); // ENOEXEC
        }
        let protection = match segment.protection {
            bhaskix_elf::Protection::ReadOnly => PROT_READ,
            bhaskix_elf::Protection::ReadWrite => PROT_READ_WRITE,
            bhaskix_elf::Protection::ReadExecute => PROT_READ_EXECUTE,
        };
        // Eagerly, and in runs the kernel will accept in one call: `COPY_OUT`
        // writes through the kernel's own view of the frames, so a lazily
        // mapped page has nothing to write into yet.
        let mut mapped = start;
        while mapped < end {
            let pages = ((end - mapped) / 4096).min(MAX_EAGER_PAGES);
            if !map_at_eager(CHILD, mapped, pages, protection) {
                return Err(-12); // ENOMEM
            }
            mapped += pages * 4096;
        }
        // Then its contents, straight out of the staging object: the source is
        // an *object and an offset*, so the bytes never pass through this
        // program's own scratch and no part of the image is dereferenced here.
        // A segment's `memory_size` may exceed its `file_size` — that is
        // `.bss`, and it is already the zero a fresh mapping is.
        if !copy_from_staging(
            segment.file_offset as u64,
            segment.address,
            segment.file_size as u64,
        ) {
            return Err(-12);
        }
    }

    // The stack, and the initial image at the top of it.
    if !map_at_eager(CHILD, EXEC_STACK_BASE, EXEC_STACK_PAGES, PROT_READ_WRITE) {
        return Err(-12);
    }
    let image_at = stack_end - 4096;

    let mut argv: [&[u8]; ARGUMENT_SLOTS] = [b""; ARGUMENT_SLOTS];
    let mut envp: [&[u8]; ARGUMENT_SLOTS] = [b""; ARGUMENT_SLOTS];
    let argc = arguments.arguments(&mut argv)?;
    let envc = arguments.environment(&mut envp)?;

    let (phdr, phent, phnum) = program_headers(bytes, &parsed);
    let mut entropy = [0u8; 16];
    // A machine with no `RDRAND` gets a fixed block rather than no block: a
    // runtime that reads `AT_RANDOM` and finds nothing there is worse off than
    // one that reads something predictable, and the fallback is the same
    // shape `drawn_base` already uses for the same reason.
    entropy[..8].copy_from_slice(
        &bhaskix_rand::u64()
            .unwrap_or(0x5eed_0000_5eed_0000)
            .to_le_bytes(),
    );
    entropy[8..].copy_from_slice(
        &bhaskix_rand::u64()
            .unwrap_or(0x0dd0_5eed_0dd0_5eed)
            .to_le_bytes(),
    );

    let builder = Builder::new(
        &argv[..argc],
        &envp[..envc],
        ProcessInfo {
            entry: parsed.entry,
            phdr,
            phent,
            phnum,
            page_size: 4096,
            hwcap: 0,
            random: entropy,
        },
    );
    let image = exec_image_page();
    if builder.build(image, image_at).is_err() {
        return Err(-7); // E2BIG
    }
    let size = builder.size();
    if !copy_page_out(CHILD, image_at, &image[..size]) {
        return Err(-12);
    }

    // `rsp` is where `argc` sits, which is the offset `build` returns and is
    // zero by construction: the vectors are at the bottom of the image and the
    // strings above them.
    if call(
        syscall::INVOKE,
        CHILD,
        method::SPAWN_THREAD,
        [parsed.entry, image_at, 0, 0],
    )
    .status
        != status::OK
    {
        return Err(-12);
    }
    Ok(())
}

/// Copies `length` bytes of the staged image into the child at `address`.
///
/// The kernel moves at most a page per `COPY_OUT`, so the loop is here; the
/// offset into the staging object *is* the file offset, because that is where
/// `READ_INTO` put the bytes.
fn copy_from_staging(from: u64, address: u64, length: u64) -> bool {
    let mut done = 0u64;
    while done < length {
        let take = (length - done).min(4096);
        let moved = call(
            syscall::INVOKE,
            CHILD,
            method::COPY_OUT,
            [STAGING, from + done, address + done, take],
        );
        if moved.status != status::OK {
            return false;
        }
        done += take;
    }
    true
}

/// Where the program headers land in the process's own space, and how many.
///
/// `AT_PHDR` is a **virtual address in the program's space**, and the loader
/// does not track it — so it is computed from the file's own header and the
/// segment that carries it, exactly as the kernel does for the boot corpus. A
/// runtime that walks its own headers reads this and nothing else.
fn program_headers(bytes: &[u8], parsed: &bhaskix_elf::Image) -> (u64, u64, u64) {
    let word_at = |at: usize, width: usize| -> u64 {
        let mut value = [0u8; 8];
        let Some(slice) = bytes.get(at..at + width) else {
            return 0;
        };
        value[..width].copy_from_slice(slice);
        u64::from_le_bytes(value)
    };
    // ELF64: `e_phoff` at 32, `e_phentsize` at 54, `e_phnum` at 56.
    let phoff = word_at(32, 8) as usize;
    let phdr = parsed
        .segments()
        .find(|segment| {
            phoff >= segment.file_offset && phoff < segment.file_offset + segment.file_size
        })
        .map(|segment| segment.address + (phoff - segment.file_offset) as u64)
        .unwrap_or(0);
    (phdr, word_at(54, 2), word_at(56, 2))
}

/// Maps and fills the exec'd program's memory, and starts its thread.
///
/// Split out because the failure path is the same for all of it: whatever went
/// wrong, the child is unusable and the caller is told `ENOMEM`.
fn build_exec_image() -> bool {
    if call(syscall::INVOKE, CHILD, method::PERSONALITY, [1, 0, 0, 0]).status != status::OK {
        return false;
    }
    // **An address space, before anything can be put in it.** A domain that
    // has just been created has none: every other way to get one is to be a
    // thread inside the domain, and there is no thread until this program
    // starts one — which it cannot do before the pages that thread will run in
    // exist. `MAKE_SPACE` is the primitive that breaks the circle, added for
    // exactly this call (RFC 0033 step 5).
    if call(syscall::INVOKE, CHILD, method::MAKE_SPACE, [0; 4]).status != status::OK {
        return false;
    }
    // Eagerly, both of them: `COPY_OUT` writes through the kernel's own view of
    // the frames, so a lazily mapped page has nothing to write into yet.
    // Read-execute for the code and read-write for the stack, which is `W^X`
    // kept by construction rather than by promise -- the bytes arrive through
    // a mapping this program never has writable.
    if !map_at_eager(CHILD, EXEC_CODE_AT, 1, PROT_READ_EXECUTE)
        || !map_at_eager(CHILD, EXEC_STACK_AT, 1, PROT_READ_WRITE)
    {
        return false;
    }
    // RFC 0036 step 2, measured here because this is the one place this program
    // already moves a program image into another domain. **The counter comes
    // from `bhaskix-sock`, not from an `rdtsc` written here**: a first attempt
    // added the instruction locally and cost twelve `unsafe` lines in the most
    // authority-concentrated program in the system, which the exact budget
    // reported immediately. `bhaskix-sock` already owns that read, written once
    // so it is not copied — which is the reason that crate exists. The cost has two
    // halves and only one of them is `COPY_OUT`: the bytes are staged into the
    // scratch area **one volatile write at a time**, and the scratch is 1 KiB,
    // so a page is four calls and four thousand stores. Both halves are inside
    // the span below, which is what a loader would actually pay.
    // **First touch and steady state, because the first version of this
    // measured neither and reported a slope that did not exist.**
    //
    // The first attempt timed a 96-byte copy and a 1,024-byte copy to the same
    // page, wide one first, and read the difference as a per-byte cost: about
    // 1,100 cycles a byte. It was an artefact of the order. Putting the *narrow*
    // copy first made **it** the expensive one — 1,107,710 cycles for 96 bytes,
    // against 103,034 for 1,024 immediately afterwards. The cost is the first
    // execution of the path, not the bytes crossing it, which is what TCG's
    // translation cache looks like from inside the guest.
    //
    // So both numbers are taken, and named for what they are. Neither is a
    // measurement of hardware: this machine has never booted on any
    // (M1-17).
    // **A page, not a kilobyte**, because a page is the unit a loader moves and
    // the unit `MAX_SUPERVISED_COPY` allows in one crossing. How many crossings
    // that takes is `SCRATCH_BYTES`' business: at 1,024 it was four, and at
    // 3,584 it is two.
    let page = [0x90u8; report::PAGE];

    let cold_started = bhaskix_sock::time::now();
    let cold_ok = copy_page_out(CHILD, EXEC_CODE_AT, &page);
    let cold_cycles = bhaskix_sock::time::now().saturating_sub(cold_started);

    // Then the same page again, warm, which is what a loader moving its second
    // page would actually pay.
    let warm_started = bhaskix_sock::time::now();
    let warm_ok = copy_page_out(CHILD, EXEC_CODE_AT, &page);
    let warm_cycles = bhaskix_sock::time::now().saturating_sub(warm_started);

    // The real image last, so the page ends up holding the program.
    if !copy_out_through(CHILD, EXEC_CODE_AT, &EXEC_IMAGE) {
        return false;
    }
    let cycles = if cold_ok { cold_cycles } else { 0 };
    let wide_cycles = if warm_ok { warm_cycles } else { 0 };
    // SAFETY: inside the page `ATTACH` mapped from this program's own object,
    // past every other record and well inside 4,096 bytes.
    unsafe {
        core::ptr::write_volatile(COPY_RECORD_AT as *mut u64, cycles);
        core::ptr::write_volatile((COPY_RECORD_AT + 8) as *mut u64, wide_cycles);
    }
    let started = call(
        syscall::INVOKE,
        CHILD,
        method::SPAWN_THREAD,
        [
            EXEC_CODE_AT,
            EXEC_STACK_AT + 0x0f00,
            EXEC_CODE_AT + EXEC_STRING_AT,
            0,
        ],
    );
    started.status == status::OK
}

/// Maps pages that must be readable by the kernel's copy immediately.
fn map_at_eager(domain: u64, address: u64, pages: u64, protection: u64) -> bool {
    call(
        syscall::INVOKE,
        domain,
        method::MAP_AT,
        [address, pages, protection, 0],
    )
    .status
        == status::OK
}

/// This program's own count of how often a domain slot has been handed to it.
fn incarnation_of(domain: u32) -> u32 {
    // SAFETY: single-threaded by construction, as `dispositions_of`.
    let incarnations = incarnation();
    incarnations[domain as usize % limits::MAX_DOMAINS]
}

/// What a descriptor names, and the handle behind it.
///
/// The one lookup `read` and `write` share: both have to know whether a number
/// is a file, a pipe or the console before they can do anything with it, and
/// neither should have to reach into the process table itself to find out.
fn descriptor_kind(request: &PersonalityCall, fd: u64) -> Option<(Kind, u64)> {
    let descriptor = i32::try_from(fd).ok()?;
    let process = process_for(request.domain)?;
    let entry = process.descriptors.get(descriptor)?;
    Some((entry.kind, entry.handle))
}

/// Takes a wake slot for something that is not a futex.
///
/// **One pool, because parking a thread is parking a thread.** A pipe reader
/// waiting for bytes and a thread waiting on a futex word want the same
/// mechanism, and two pools would mean two ways to get a wake-up wrong. The
/// slot is marked with a domain no hosted domain can have, so a `futex(WAKE)`
/// — which matches on the domain and address a sleeper gave — can never find
/// it.
fn claim_wake() -> Option<usize> {
    let table = sleepers();
    let index = table.iter().position(|sleeper| sleeper.domain == 0)?;
    table[index] = Sleeper {
        domain: u32::MAX,
        address: 0,
        arrived: 0,
    };
    Some(index)
}

/// Gives a wake slot back.
fn release_wake(index: usize) {
    if let Some(sleeper) = sleepers().get_mut(index) {
        sleeper.domain = 0;
    }
}

/// Answers a hosted `futex` — RFC 0032 step 10.
///
/// **The whole contract is the compare-and-park**, and it is why this is the
/// last call to leave the nucleus: a `WAIT` whose word has already changed
/// must not sleep, or it sleeps through the wake that changed it. Here the
/// word is read out of the hosted process's memory through the `Domain`
/// capability this program holds, compared, and — if it still matches — a
/// notification is claimed and the reply tells the kernel to park the caller
/// on it.
///
/// The window between that reply and the park is closed by the kernel rather
/// than here: `notify::signal` publishes its bits before waking, so a wake
/// arriving in the gap leaves the bit set and the park returns at once.
fn answer_futex(request: &PersonalityCall) -> (u64, Answer) {
    use bhaskix_personality::thread::{FutexPlan, plan_futex};

    match plan_futex(request.first(), request.second(), request.third()) {
        FutexPlan::Wait { address, expected } => {
            let mut word = [0u8; 4];
            if !copy_in(request.domain, address, &mut word) {
                return (REPLY_VALUE, Answer::error(-14)); // EFAULT
            }
            if u32::from_le_bytes(word) != expected {
                // Linux's EAGAIN: "the value was not what you said". The
                // caller re-reads and decides; it must not sleep.
                return (REPLY_VALUE, Answer::error(-11));
            }
            let arrived = {
                // SAFETY: single-threaded, as above.
                let counter = arrivals();
                *counter += 1;
                *counter
            };
            let table = sleepers();
            let Some(slot) = table.iter().position(|s| s.domain == 0) else {
                // Every notification is spoken for. A refusal a caller can
                // act on beats a sleeper the adapter cannot account for.
                return (REPLY_VALUE, Answer::error(-11));
            };
            table[slot] = Sleeper {
                domain: request.domain + 1,
                address,
                arrived,
            };
            (REPLY_BLOCK_ON, Answer::ok(WAKE_SLOT + slot as u64))
        }
        FutexPlan::Wake { address, count } => {
            let table = sleepers();
            let mut woken = 0u64;
            while woken < u64::from(count) {
                // The oldest sleeper on this word, so a contended futex does
                // not starve whoever has been waiting longest.
                let next = table
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.domain == request.domain + 1 && s.address == address)
                    .min_by_key(|(_, s)| s.arrived)
                    .map(|(index, _)| index);
                let Some(index) = next else { break };
                let signalled = call(
                    syscall::INVOKE,
                    WAKE_SLOT + index as u64,
                    method::SIGNAL,
                    [0; 4],
                );
                table[index].domain = 0;
                if signalled.status != status::OK {
                    // The sleeper is unparked or unreachable either way; the
                    // slot is freed rather than leaked, and the count says
                    // what actually happened.
                    continue;
                }
                woken += 1;
            }
            (REPLY_VALUE, Answer::ok(woken))
        }
        FutexPlan::Refuse(errno) => (REPLY_VALUE, Answer::error(errno)),
    }
}

/// The dispositions of one domain.
///
/// # Safety of the `static mut`
///
/// This program has **one thread** and answers one request at a time: the
/// kernel's IPC gives a server exactly one outstanding reply, so there is no
/// second caller inside this function and no interrupt that runs its code.
/// A lock here would be a lock nothing can contend.
fn dispositions_of(domain: u32) -> &'static mut Dispositions {
    let index = (domain as usize) % limits::MAX_DOMAINS;
    // SAFETY: single-threaded by construction, as above; the index is masked
    // into the array's own length.
    unsafe { &mut *core::ptr::addr_of_mut!(DISPOSITIONS[index]) }
}

/// The bytes of the frame a signal handler is entered on.
const FRAME_BYTES: usize = 8 + SIGINFO_BYTES + UCONTEXT_BYTES;
/// A `siginfo_t` is 128 bytes on Linux; only `si_addr` is filled.
const SIGINFO_BYTES: usize = 128;
/// Where `si_addr` sits within it.
const SIGINFO_ADDR: usize = 16;
/// The part of a `ucontext_t` this builds, up to and including the
/// `sigcontext` a handler reads and edits.
const UCONTEXT_BYTES: usize = UCONTEXT_MCONTEXT + signal::sigcontext::SIZE;
/// Where the `mcontext` starts inside the `ucontext`.
const UCONTEXT_MCONTEXT: usize = 40;

/// How many processors a hosted program is told it has.
///
/// **Four, and written down as a stated narrowing rather than asked.** The
/// adapter has no way to count them: `online_count` is the scheduler's and
/// there is no capability that reports it. Telling a runtime the wrong number
/// costs it parallelism, not correctness — Go sizes its scheduler by this and
/// then blocks on futexes either way — and the trigger for making it real is
/// the first workload whose *throughput* is measured, at which point a
/// capability that answers "how big is this machine" is the honest fix rather
/// than a constant that happens to be right.
const CPUS_REPORTED: u64 = 4;

/// The method that says where a hosted domain's `Domain` capability landed.
///
/// `u64::MAX - 3`, beside [`FORGET_METHOD`] and for the same reason: no Linux
/// number can collide with it. Sent by the kernel once per incarnation,
/// before the first foreign call of that domain arrives — the message is a
/// call made by the hosted thread itself, so it is answered before the call
/// that provoked it.
const HANDLE_METHOD: u64 = u64::MAX - 3;

/// Where each hosted domain's `Domain` capability sits in this program's
/// CSpace, plus one — zero meaning "none, and nothing may be done to it".
///
/// **It used to be `32 + domain id`, and the arithmetic was the problem** —
/// RFC 0033 step 3. Computing the slot needed no table on either side, and
/// reserved one slot per domain *whether or not that domain existed*: half a
/// CSpace held against a machine running two hosted programs. A descriptor is
/// a capability this program holds, so that reservation is precisely what L1
/// would have run out of. The kernel allocates now and says where.
///
/// **This capability is the whole of the authority to touch a hosted
/// process's memory** — [RFC 0032](../../../docs/rfc/0032-a-supervisor-interface.md).
/// Without it this program can answer questions about numbers and nothing
/// else.
static mut HANDLES: [u32; limits::MAX_DOMAINS] = [0; limits::MAX_DOMAINS];

/// The slot holding `domain`'s handle, or [`NO_HANDLE`] if the kernel has not
/// said.
///
/// Answering a sentinel rather than refusing to compile is deliberate: an
/// invocation on `NO_HANDLE` is refused by the kernel as an empty slot, which
/// is exactly what "this program cannot touch that domain" should look like
/// from every call site, and it costs no branch at any of them.
fn handle_of(domain: u32) -> u64 {
    // SAFETY: one thread, one request at a time -- as `dispositions_of`.
    let handles = handles();
    match handles.get(domain as usize % limits::MAX_DOMAINS) {
        Some(0) | None => NO_HANDLE,
        Some(slot) => u64::from(slot - 1),
    }
}

/// A slot index no CSpace has, so an invocation on it is refused.
const NO_HANDLE: u64 = u64::MAX;

/// What `POLL_INPUT` answers when nobody has typed — out of a byte's range.
const NOTHING: u64 = 0x100;

/// `MAP_AT`'s lazy flag: record the region, take no frame until it is touched.
const MAP_LAZY: u64 = 1;
/// `MAP_AT`'s replace flag — Linux's `MAP_FIXED`: this address, and whatever
/// is there is discarded.
const MAP_REPLACE: u64 = 2;

/// `MAP_AT`/`PROTECT_AT`'s protection encoding.
const PROT_NONE: u64 = 0;
const PROT_READ: u64 = 1;
const PROT_READ_WRITE: u64 = 2;
const PROT_READ_EXECUTE: u64 = 3;

/// Translates a plan's three permission bits into the kernel's encoding.
///
/// **Writable-and-executable is not expressible on either side**, which is
/// why this is a translation and not a check: `bhaskix_mm::Protection` has no
/// such value, so a hosted program asking for both is refused by
/// `plan_mprotect` before it ever reaches here.
fn protection_of(read: bool, write: bool, execute: bool) -> u64 {
    match (read, write, execute) {
        (_, true, _) => PROT_READ_WRITE,
        (_, _, true) => PROT_READ_EXECUTE,
        (true, _, _) => PROT_READ,
        _ => PROT_NONE,
    }
}

/// How fast the timestamp counter runs, from this program's start argument.
///
/// **Kept as of RFC 0055, having been ignored until then.** A `poll` with a
/// positive timeout and a `clock_nanosleep` both have to turn a duration into
/// the absolute counter value `method::ARM` wants, and neither can without
/// this. Zero on a machine that did not measure one, which is answered by
/// refusing to wait rather than by waiting a made-up length of time.
static mut HERTZ: u64 = 0;

fn hertz() -> u64 {
    // SAFETY: written once at entry, read afterwards, single-threaded.
    unsafe { HERTZ }
}

/// An absolute deadline `nanos` from now, or `None` if this machine cannot name
/// that instant — no calibrated clock, or a duration too long to convert.
///
/// The counter comes from `bhaskix-sock`, which owns that read already, rather
/// than being written here again. This crate's `unsafe` budget records the last
/// time somebody wrote their own `rdtsc` in it and had to take it back out.
///
/// # Why the overflow is a refusal and not a saturation
///
/// It was `saturating_mul` first, on the reasoning that a huge duration should
/// become a huge deadline. What it actually produced was `u64::MAX / 1_000_000_000`
/// ticks — about **fifteen seconds** on this machine, whatever was asked for.
/// A `poll` given a timeout of days therefore waited fifteen seconds and
/// answered "nothing happened", and the boot that found it had BusyBox parked
/// at its first prompt until the corpus lost patience and killed the domain.
///
/// A duration this cannot represent is *unbounded* as far as this program is
/// concerned, and saying so lets the caller do the right thing with it —
/// which, for a `poll` naming the console, is to wait for a key instead.
fn deadline_in(nanos: u64) -> Option<u64> {
    let hertz = hertz();
    if hertz == 0 {
        return None;
    }
    let ticks = nanos.checked_mul(hertz)? / 1_000_000_000;
    bhaskix_sock::time::now().checked_add(ticks)
}

/// Who is parked on a deadline, and on which wake slot: `(domain, slot + 1)`.
///
/// **What tells a first call from the retry after it.** `BLOCK_ON_RETRY` asks
/// the same question again, so a `poll` that armed a timer and parked would,
/// on waking, arm another and park again — for ever. An entry here means this
/// domain has already done its waiting, and the answer it gets now is the
/// answer.
///
/// Four, matching `WAITERS` beside it and for the same reason: a fifth is
/// answered without waiting rather than left unwoken.
static mut TIMED: [(u32, u32); 4] = [(0, 0); 4];

fn timed() -> &'static mut [(u32, u32); 4] {
    // SAFETY: single-threaded by construction, as `dispositions_of`.
    unsafe { &mut *core::ptr::addr_of_mut!(TIMED) }
}

/// Takes this domain's finished timed wait, if it has one.
fn took_timed_wait(domain: u32) -> bool {
    let table = timed();
    let Some(entry) = table.iter_mut().find(|entry| entry.0 == domain) else {
        return false;
    };
    let slot = entry.1 - 1;
    *entry = (0, 0);
    release_wake(slot as usize);
    true
}

/// Arms a wake slot `nanos` from now and records it, answering the slot to
/// park on — or `None` if this machine cannot time it or has none left.
///
/// The wake pool is granted `WRITE`, which is exactly what `ARM` needs, so this
/// asks the nucleus for nothing it was not already given. The console's own
/// notification is `READ` and deliberately cannot be armed: a program that
/// could set a timer on the keyboard could fake a keystroke's wake.
fn park_until(domain: u32, nanos: u64) -> Option<u64> {
    let deadline = deadline_in(nanos)?;
    let table = timed();
    let index = table.iter().position(|entry| entry.0 == 0)?;
    let slot = claim_wake()?;
    let armed = call(
        syscall::INVOKE,
        WAKE_SLOT + slot as u64,
        method::ARM,
        [deadline, 0, 0, 0],
    );
    if armed.status != status::OK {
        release_wake(slot);
        return None;
    }
    table[index] = (domain, slot as u32 + 1);
    Some(WAKE_SLOT + slot as u64)
}

/// The entry point. `hertz` arrives as every packaged program's manifest
/// declares, and is kept: RFC 0055 gave this program two reasons to time
/// something.
#[unsafe(no_mangle)]
extern "C" fn linuxd_main(hertz: u64) -> ! {
    // SAFETY: before anything else runs here, and single-threaded.
    unsafe { HERTZ = hertz };
    // The report page, into this program's own space. If it will not map the
    // adapter still serves — a trace is a convenience and refusing to work
    // without one would be the wrong priority.
    let _ = call(
        syscall::INVOKE,
        REPORT,
        method::ATTACH,
        [REPORT_AT, 1, 0, 0],
    );
    // The fault exchange page, likewise. A fault arrives as a slot index into
    // this; nothing else about it travels in the message.
    let _ = call(
        syscall::INVOKE,
        FAULTS,
        method::ATTACH,
        [FAULTS_AT, 1, 0, 0],
    );
    let _ = FAULT_SLOT_BYTES;

    loop {
        let received = call(syscall::RECV, ENDPOINT, 0, [0; 4]);
        if received.status == status::CONGESTED {
            // Back-pressure is not a reason to die, and the receive queue
            // filling is back-pressure: yield and ask again, which is what
            // every other service on this machine does.
            let _ = call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        }
        if received.status != status::OK {
            break;
        }

        // The kernel put the Linux call number in `method` and the caller's
        // first four arguments in the message. Calls that need five or six --
        // `mmap` is the one that matters -- are still answered in the nucleus,
        // and moving them is what will need a page rather than a message.
        //
        // `badge` is the hosted domain, stamped by the kernel from the
        // capability actually used. A caller cannot supply it, which is the
        // entire reason it can be trusted to say who is asking.
        let args = received.args;

        // **A fault, not a system call.** RFC 0032 step 6: deciding what a
        // fault *means* is the personality's business, so the kernel hands it
        // over the same way it hands over a call — same endpoint, same badge,
        // a method no Linux number can be.
        //
        // Answered `END` for now, and the reason is a boundary rather than a
        // shrug: this program does not yet own the signal dispositions, so it
        // cannot know whether the program had a handler. While `rt_sigaction`
        // is still in the nucleus the kernel's own delivery runs first and
        // this only ever sees faults nothing wanted — which is exactly the
        // set that should end. When the dispositions move, this arm grows a
        // decision and the kernel's delivery goes away.
        // Where this program's handle for a hosted domain is — RFC 0033 step
        // 3. Recorded and acknowledged; the capability itself was installed
        // by the kernel before this message was sent.
        if received.method == HANDLE_METHOD {
            let domain = (received.badge as u32) as usize % limits::MAX_DOMAINS;
            // SAFETY: one thread, one request at a time -- as `sleepers`.
            let handles = handles();
            handles[domain] = (args[0] as u32).saturating_add(1);
            let _ = call(syscall::REPLY, 0, 0, [0; 4]);
            continue;
        }
        if received.method == FORGET_METHOD {
            // **And its sockets** -- RFC 0058 Part A. `note_exit` releases them
            // for a process that *exits*; a domain killed from outside reaches
            // neither `exit_group` nor a fatal fault, so this message is the
            // only thing that ever learns of it. `bin/ipd` holds four sockets
            // and one held by a domain nobody can name refuses every later
            // bind -- which showed up as a *different* program losing its
            // network, the failure shape a shared adapter produces.
            //
            // Late rather than never: this arrives when the slot is reused, so
            // a socket held by a domain killed and not replaced stays held.
            // That bound is stated in RFC 0058 rather than rounded to "fixed".
            release_sockets_of(received.badge as u32);
            *dispositions_of(received.badge as u32) = Dispositions::new();
            // And whatever it left asleep. A sleeper keyed by a domain id
            // that now names somebody else would let a `WAKE` from the new
            // domain wake a notification the old one parked on -- the same
            // class of mistake the dispositions above are cleared for.
            let gone = (received.badge as u32) + 1;
            for sleeper in sleepers().iter_mut().filter(|s| s.domain == gone) {
                sleeper.domain = 0;
            }
            // And the process record, which is the identity itself — RFC 0033
            // step 4. The record is dropped rather than left as a zombie:
            // nothing hosted is its parent yet, so nobody will ever read its
            // status. When `fork` exists, a process whose parent is alive
            // becomes a zombie here instead, and `Exit::Status(0)` becomes a
            // lie that matters — the real status has to come from the domain's
            // own `Ending`, which this message does not carry.
            //
            // **The incarnation counter is not observable yet, and that is
            // stated rather than implied.** Bumping it makes a stale record
            // unfindable; dropping the record makes it unfindable too, and the
            // drop always succeeds while no hosted process has a parent. So
            // removing the bump changes nothing a test can see today. It stops
            // being decoration the moment `discard` can refuse — which is the
            // moment a parent exists to read the status.
            let domain = received.badge as u32;
            let slot = domain as usize % limits::MAX_DOMAINS;
            // SAFETY: single-threaded by construction, as elsewhere here.
            let incarnations = incarnation();
            let generation = incarnations[slot];
            incarnations[slot] = generation.wrapping_add(1);
            // SAFETY: as above.
            let processes = processes();
            // **A domain slot reused means whoever was in it is gone**, and
            // by now its status has either been recorded — `exit_group` and
            // the fault path both do it before the domain ends — or there is
            // none to record, because something outside ended it. The invented
            // `Exit::Status(0)` that used to be written here was a lie with no
            // reader while nothing could `wait4`; step 9 gave it one, so it is
            // gone. What is left is the reap: a record whose parent cannot
            // read it any more.
            if let Some(pid) = processes.by_domain(domain, generation).map(|p| p.pid) {
                let _ = processes.ended(
                    pid,
                    Exit::Signalled {
                        signal: 9,
                        core: false,
                    },
                );
                let _ = processes.discard(pid);
            }
            let _ = call(syscall::REPLY, 0, 0, [0; 4]);
            continue;
        }
        // The retry, carrying the register frame this program asked for.
        if received.method == FRAME_METHOD {
            let (how, reply) = answer_with_frame(received.badge as u32, args[0], args[1]);
            // The deadline too: a call that needed its register frame can still
            // answer a park, and a `BLOCK_ON_UNTIL` replied from here without
            // one would ask the nucleus to arm a timer for the epoch.
            let _ = call(syscall::REPLY, 0, how, [reply.value, deadline_word(), 0, 0]);
            continue;
        }
        if received.method == FAULT_METHOD {
            faults_seen(args[0], args[1]);
            let verdict = deliver(received.badge as u32, args[0], args[1]);
            let _ = call(syscall::REPLY, 0, 0, [verdict, 0, 0, 0]);
            continue;
        }

        // The badge's low half is the hosted domain and its high half the
        // calling thread, both stamped by the kernel from the capability
        // actually used. A caller can forge neither.
        let request = PersonalityCall::new(
            Dialect::Linux,
            received.method,
            [args[0], args[1], args[2], args[3], 0, 0],
            (received.badge >> 32) as u32,
            received.badge as u32,
        );
        let (how, reply) = answer(&request);
        // The second word is the deadline a `BLOCK_ON_UNTIL` names, and zero
        // for every other shape -- see [`REPLY_BLOCK_ON_UNTIL`].
        let _ = call(syscall::REPLY, 0, how, [reply.value, deadline_word(), 0, 0]);
    }

    // The endpoint went away, which happens when the machine is taking itself
    // down. There is nowhere to say so.
    let _ = call(syscall::EXIT, 0, 0, [0; 4]);
    #[allow(clippy::empty_loop)]
    loop {}
}

// The entry stub. `rbp` zeroed so a walker stops here rather than in whatever
// the loader left, and `rsp` aligned because the ABI says a function may
// assume it: the kernel enters ring 3 with the stack top it was given, which
// is page-aligned and therefore already right, and doing it anyway costs one
// instruction and removes a dependency on that staying true.
core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    xor rbp, rbp
    and rsp, -16
    call linuxd_main
    ud2
"#
);
