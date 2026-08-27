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
const REPORT: u64 = 1;
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
const ENDPOINT: u64 = 0;

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
const CONSOLE: u64 = 3;

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
const WAKE_SLOT: u64 = 4;
const WAKES: usize = 16;

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
            return (
                REPLY_VALUE,
                if number == SENDTO {
                    answer_sendto(&request)
                } else {
                    answer_recvfrom(&request)
                },
            );
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
fn read_console(request: &PersonalityCall) -> Answer {
    let (buffer, count) = (request.second(), request.third());
    if count == 0 {
        return Answer::ok(0);
    }
    // `call` rather than `invoke`, because the byte is the *value* and `invoke`
    // keeps only whether the call worked.
    let taken = call(
        syscall::INVOKE,
        handle_of(request.domain),
        method::TAKE_INPUT,
        [0, 0, 0, 0],
    );
    if taken.status != status::OK {
        return Answer::error(-5); // EIO
    }
    let byte = [taken.args[0] as u8];
    if !copy_out(request.domain, buffer, &byte) {
        return Answer::error(-14); // EFAULT
    }
    Answer::ok(1)
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
    for vector in raw[..wanted].chunks_exact(IOVEC_BYTES) {
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
            return if written == 0 { answer } else { Answer::ok(written) };
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
                return (REPLY_VALUE, read_console(request));
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
const CONTROL: u64 = 20;
/// Where the domain an `execve` is building is held, one at a time.
///
/// This program has one thread, so no second exec can be in flight while the
/// first is between its `SPAWN` and its reply. The handle is given back with
/// `DELETE` either way — a slot left occupied would refuse the *next* exec for
/// a reason that has nothing to do with it.
const CHILD: u64 = 21;
/// The name the new domain is created under, packed as `SPAWN` wants it.
const EXEC_NAME_LOW: u64 = u64::from_le_bytes(*b"execed\0\0");

/// The one program this personality can exec, and the whole of its filesystem.
///
/// **A path with one answer is still a path.** There is no file surface yet —
/// that is RFC 0033 step 6 — so `execve` resolves exactly this name and answers
/// `ENOENT` for everything else, which is a Linux answer a program can act on
/// and is not a lie about what is there. When directories arrive, this constant
/// is what they replace.
const EXEC_PATH: &[u8; 11] = b"/bin/execed";

/// Where the exec'd program's code and stack land in its own space.
const EXEC_CODE_AT: u64 = 0x0000_0000_2000_0000;
const EXEC_STACK_AT: u64 = 0x0000_0000_2001_0000;
/// Where the string sits inside the image, as an offset from its start.
const EXEC_STRING_AT: u64 = 80;

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
const NETWORK: u64 = 88;
/// One page of this program's own memory, which datagrams cross in.
///
/// `SEND_TO` drains its payload from **offset zero** of a memory object, so
/// the report page cannot serve: its first bytes are the `mmap` trace records.
const PAYLOAD: u64 = 89;
/// Where that page is mapped while bytes are staged in it.
const PAYLOAD_AT: u64 = 0x0000_0000_1B00_0000;
/// Where a hosted socket's capability lands: 90 up to 95, six of them.
const SOCKET_SLOT: u64 = 90;
/// How many sockets one machine's hosted programs may hold at once.
///
/// Six, because six is what the CSpace has left — and a limit met as `EMFILE`
/// is a limit a program can act on, which is why it is checked rather than
/// discovered by an `install_at` failing somewhere less legible.
const SOCKETS: usize = 6;

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
fn release_socket_slot(slot: u64) {
    // The family does not matter for closing -- both crates send the same
    // message to the same service -- so the v4 constructor serves for either.
    let _ = bhaskix_sock::udp::Socket::from_slot(slot, 0).close();
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
const ROOT_DIR: u64 = 22;
/// Where a page lent by the filesystem service lands, one at a time.
const LENT: u64 = 23;
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
/// The kernel allocates hosted-domain handles *upward* from slot 24, and this
/// allocates from 127 down, so the two cannot meet: sixty-four domains and
/// thirty-two open files is ninety-six of a hundred and twenty-eight. Written
/// as a pair of directions rather than as two ranges, because a range is a
/// number somebody will change on one side only.
const FILE_SLOT_TOP: u64 = 127;
const FILE_SLOTS: usize = 32;

/// Which file slots are taken.
static mut FILE_HELD: [bool; FILE_SLOTS] = [false; FILE_SLOTS];

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
const FAULTS: u64 = 2;
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
fn process_for(domain: u32) -> Option<&'static mut Process> {
    // SAFETY: single-threaded by construction, as `dispositions_of`.
    let incarnations = incarnation();
    let generation = incarnations[domain as usize % limits::MAX_DOMAINS];
    // SAFETY: as above.
    let processes = processes();
    if processes.by_domain(domain, generation).is_none() {
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

/// The work behind [`answer_openat`], so that every path through it is traced.
fn open_the_file(request: &PersonalityCall, path_at: u64, flags: u64) -> Answer {
    use bhaskix_personality::file::{Entry, Kind, open, plan_openat};

    // Writing is refused before anything else, because the capability this
    // program holds carries no `WRITE` right and a program told otherwise
    // would discover it at the write.
    if flags & open::ACCMODE != open::RDONLY {
        return Answer::error(-30); // EROFS
    }
    let plan = match plan_openat(flags) {
        Ok(plan) => plan,
        Err(errno) => return Answer::error(errno),
    };
    let _ = plan;

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
    // Where the answer may land, said before asking and addressed to the
    // service being asked -- the protocol's own rule, and what stops a
    // capability arriving somewhere the caller did not choose.
    let declared = call(syscall::INVOKE, ROOT_DIR, method::EXPECT, [slot, 0, 0, 0]);
    if declared.status != status::OK {
        release_file_slot(slot);
        trace_file(-2, STAGE_NO_DIRECTORY, declared.status);
        return Answer::error(-2);
    }
    let (chunk, rest) = bhaskix_abi::Chunk::take(component);
    if !rest.is_empty() {
        release_file_slot(slot);
        return Answer::error(-36); // ENAMETOOLONG
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
        release_file_slot(slot);
        trace_file(-2, STAGE_SERVICE_SILENT, reply.status);
        return Answer::error(-2);
    }
    if reply.args[0] != bhaskix_abi::dir::OK {
        release_file_slot(slot);
        trace_file(-2, STAGE_SERVICE_REFUSED, reply.args[0]);
        return Answer::error(-2); // ENOENT
    }
    let directory = reply.args[2] != 0;
    let entry = Entry {
        handle: slot,
        // The filesystem's own name for what was opened, which `fstat`
        // answers with and this program cannot derive from anything else it
        // holds -- the slot is reused between files.
        inode: reply.args[3],
        kind: if directory {
            Kind::Directory
        } else {
            Kind::File
        },
        close_on_exec: flags & open::CLOEXEC != 0,
        offset: 0,
        size: reply.args[1],
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
    let end = name.iter().position(|byte| *byte == 0).unwrap_or(name.len());
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
fn stat_out(request: &PersonalityCall, entry: &bhaskix_personality::file::Entry, at: u64) -> Answer {
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
fn stat_at(
    request: &PersonalityCall,
    dirfd: u64,
    path_at: u64,
    out_at: u64,
    flags: u64,
) -> Answer {
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
        Err(_) => {
            trace_file(-98, STAGE_NOT_BOUND, u64::from(port));
            release_socket_slot(slot);
            Answer::error(-98) // EADDRINUSE
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
        (Endpoint::V4 { address, port: to }, false) => {
            bhaskix_sock::udp::Socket::from_slot(entry.handle, port).send_to(
                PAYLOAD,
                u32::from_be_bytes(address),
                to,
                length,
            )
        }
        (Endpoint::V6 { address, port: to, .. }, true) => {
            bhaskix_sock::udp6::Socket6::from_slot(entry.handle, port)
                .send_to(PAYLOAD, address, to, length)
        }
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
            if entry.handle != ROOT_DIR
                && process.descriptors.holders(entry.handle) == 0
                && matches!(entry.kind, Kind::File | Kind::Directory)
            {
                release_file_slot(entry.handle);
            }
            // **And a socket's slot, which comes from a different pool.** A
            // socket that was never bound holds nothing -- `u64::MAX` is the
            // row's way of saying so -- and releasing that would compute an
            // index far outside the six.
            if entry.kind == Kind::Socket
                && entry.handle != u64::MAX
                && process.descriptors.holders(entry.handle) == 0
            {
                release_socket_slot(entry.handle);
            }
            // **A pipe end closing is a count, not a teardown** — RFC 0033
            // step 7. Which end matters: with no reader left a writer is told
            // `EPIPE`, and with no writer left a reader is told end of file.
            // Getting the two the wrong way round would make a pipeline either
            // hang for ever or stop at its first pause.
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
                    // A reader waiting on a pipe whose last writer has just
                    // gone must be woken to be told so, or it waits for bytes
                    // nobody will ever write.
                    if pipe.at_end() {
                        wake_pipe_reader(entry.handle as usize);
                    }
                    if pipe.abandoned() {
                        *slot = None;
                    }
                }
            }
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
        }
    }

    // SAFETY: single-threaded by construction, as elsewhere here.
    let processes = processes();
    let _ = processes.ended(pid, exit);
    wake_waiter(parent);
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
    // capability. **There is one program**, and asking for anything else is
    // `ENOENT` rather than a lie -- see `EXEC_PATH`.
    let mut path = [0u8; EXEC_PATH.len()];
    if !copy_in(request.domain, request.first(), &mut path) {
        return (REPLY_VALUE, Answer::error(-14)); // EFAULT
    }
    if path != *EXEC_PATH {
        return (REPLY_VALUE, Answer::error(-2)); // ENOENT
    }

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

    let built = build_exec_image();
    // The handle is given back either way. A slot left occupied would refuse
    // the *next* exec for a reason that has nothing to do with it.
    // **The record is looked up before anything moves it**, and the first
    // version of this got that wrong: it bumped the old domain's incarnation
    // first, so the lookup below found nothing, admitted a *fresh* record, and
    // exec'd that — the exec'd program printed a pid one higher than the
    // program it replaced, which is the exact failure this step exists to
    // prevent. The old slot's incarnation moves when the kernel says it has
    // been reused (`FORGET`), which is the only moment that is true.
    let outcome = if built {
        (REPLY_END_DOMAIN, Answer::ok(0))
    } else {
        (REPLY_VALUE, Answer::error(-12)) // ENOMEM
    };
    if built {
        // The record moves to the new domain *before* the old one ends, so a
        // call arriving from the new domain finds the same process. The
        // generation is this program's own count of how often the slot has
        // been handed over -- see `INCARNATION`.
        let child = made.args[0] as u32;
        let generation = incarnation_of(child);
        if let Some(process) = process_for(request.domain) {
            let pid = process.pid;
            let from = process.domain;
            process.exec_into(child, generation, drawn_base(), |_| {});
            trace_exec(pid, from, child);
        }
    }
    let _ = call(syscall::INVOKE, CHILD, method::DELETE, [0; 4]);
    outcome
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

/// The entry point. `hertz` arrives as every packaged program's manifest
/// declares; this one has nothing to time and ignores it.
#[unsafe(no_mangle)]
extern "C" fn linuxd_main(_hertz: u64) -> ! {
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
            let _ = call(syscall::REPLY, 0, how, [reply.value, 0, 0, 0]);
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
        let _ = call(syscall::REPLY, 0, how, [reply.value, 0, 0, 0]);
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
