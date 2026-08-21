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
use bhaskix_personality::process::{Exit, Process, Processes, Region};
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
const EXEC_RECORD_AT: u64 = REPORT_AT + SCRATCH_AT_OFFSET + SCRATCH_BYTES;

/// Where the file record sits, three words past the exec record.
const FILE_RECORD_AT: u64 = EXEC_RECORD_AT + 24;

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
const FORK_RECORD_AT: u64 = FILE_RECORD_AT + 24;

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
const WAIT_RECORD_AT: u64 = FORK_RECORD_AT + 16;

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
const SCRATCH_BYTES: u64 = 1024;

/// Records that a fault was handed over, in the report page the kernel reads.
///
/// The adapter has no console; this is how it says anything at all. Two words
/// — the slot and the address — are enough to prove the exchange happened and
/// to say where, which is what this step is for.
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
const FAULT_LOG_OFFSET: u64 = 8 * 32 + 64;

/// Where in the report page the scratch word lives.
///
/// After the eight trace records, so a trace and a copy cannot overwrite each
/// other. The same page serves both because it is the only memory this
/// program owns, and a second object would be a second thing to explain in
/// the manifest for no gain.
const SCRATCH_AT_OFFSET: u64 = 8 * 32;

/// Writes the scratch word this program copies out of.
fn write_scratch(value: u64) {
    // SAFETY: `REPORT_AT + SCRATCH_AT_OFFSET` is inside the page `ATTACH`
    // mapped from this program's own object, past the trace records and well
    // inside 4,096 bytes.
    unsafe { core::ptr::write_volatile((REPORT_AT + SCRATCH_AT_OFFSET) as *mut u64, value) };
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
    if matches!(request.number, CLONE | RT_SIGRETURN | FORK) {
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
                let address = NEXT_MAPPING.fetch_add(bytes, core::sync::atomic::Ordering::Relaxed);
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
            // A character at a time, because that is what a `Console`
            // capability confers: the authority to put one. The cost is real
            // and is priced by the boundary instrument like everything else
            // here -- and it is the honest cost of a console that is a
            // capability rather than a kernel function this program may call.
            for byte in &bytes[..take] {
                call(
                    syscall::INVOKE,
                    CONSOLE,
                    method::PUT,
                    [u64::from(*byte), 0, 0, 0],
                );
            }
            Answer::ok(take as u64)
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
        trace_file(-5, STAGE_MAP_REFUSED, lent.args[0]);
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
    let _ = call(
        syscall::CALL,
        entry.handle,
        bhaskix_abi::dir::RELEASE,
        [0; 4],
    );
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
            if process.descriptors.holders(entry.handle) == 0
                && matches!(entry.kind, Kind::File | Kind::Directory)
            {
                release_file_slot(entry.handle);
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
            process.exec_into(child, generation, |_| {});
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
    if !copy_out_through(CHILD, EXEC_CODE_AT, &EXEC_IMAGE) {
        return false;
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

/// Where an `mmap` with no address of its own is put.
///
/// A bump, and it is **the personality's policy rather than the kernel's** —
/// which is the whole point of the call having moved. Addresses are per
/// address space, so one counter serves every hosted domain: the same number
/// in two of them names two different pages.
///
/// The base is the same one the nucleus used, so a hosted program sees no
/// change of layout across the move.
static NEXT_MAPPING: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0x0000_7000_0000_0000);

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
