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

use bhaskix_abi::{method, status, syscall};
use bhaskix_personality::call::{Answer, Dialect, PersonalityCall};
use bhaskix_personality::memory;
use bhaskix_personality::signal::{self, Dispositions, Registers, number::SIGSEGV};

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
        return FAULT_END;
    };

    let mut image = [0u64; FAULT_REGISTERS];
    if !read_slot(slot, &mut image) {
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
        SLOT_BASE + u64::from(domain),
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
        SLOT_BASE + u64::from(domain),
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
fn answer(request: &PersonalityCall) -> Answer {
    match request.number {
        // `getpid`. A Linux process id is a *number a program compares and
        // prints*, not authority — so a personality may invent one, and this
        // one is the hosted domain's own id, offset so that no process is
        // zero. It is the first call to be answered outside the kernel, and it
        // was chosen for exactly that reason: nothing about it needs the
        // hosted process's memory, its registers, or anything this program
        // cannot yet reach.
        //
        // The number matches what the nucleus answered before the move, so a
        // hosted program cannot tell that anything changed. That is the test.
        GETPID => Answer::ok(u64::from(request.domain) + 1),
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
                let domain = SLOT_BASE + u64::from(request.domain);
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
                    return Answer::ok(wanted);
                }
                if at.is_some() {
                    return Answer::error(memory::errno::ENOMEM);
                }
                let bytes = pages * memory::PAGE;
                let address = NEXT_MAPPING.fetch_add(bytes, core::sync::atomic::Ordering::Relaxed);
                if map_at(domain, address, pages, protection, 0) {
                    Answer::ok(address)
                } else {
                    Answer::error(memory::errno::ENOMEM)
                }
            }
        },
        MUNMAP => match memory::plan_munmap(request.first(), request.second()) {
            Ok((address, pages)) => {
                let _ = pages;
                invoke(
                    SLOT_BASE + u64::from(request.domain),
                    method::UNMAP_AT,
                    [address, 0, 0, 0],
                )
            }
            Err(errno) => Answer::error(errno),
        },
        MPROTECT => {
            match memory::plan_mprotect(request.first(), request.second(), request.third()) {
                Ok((address, pages, read, write, execute)) => invoke(
                    SLOT_BASE + u64::from(request.domain),
                    method::PROTECT_AT,
                    [address, pages, protection_of(read, write, execute), 0],
                ),
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
                SLOT_BASE + u64::from(request.domain),
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
#[expect(
    dead_code,
    reason = "the kernel's half of step 6 exists before the adapter's"
)]
const FAULT_RESUME: u64 = 1;
/// The method that says a domain slot has been reused, so whatever this
/// program remembers about it belongs to somebody else.
///
/// **A domain id is reused and this program keeps state keyed by it.** A new
/// domain 3 inheriting the old domain 3's signal handlers would let a program
/// that never installed one survive a fault it should have died on — which is
/// worse than a crash, because it is a crash that did not happen.
const FORGET_METHOD: u64 = u64::MAX - 1;

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
static mut DISPOSITIONS: [Dispositions; 32] = [const { Dispositions::new() }; 32];

/// The dispositions of one domain.
///
/// # Safety of the `static mut`
///
/// This program has **one thread** and answers one request at a time: the
/// kernel's IPC gives a server exactly one outstanding reply, so there is no
/// second caller inside this function and no interrupt that runs its code.
/// A lock here would be a lock nothing can contend.
fn dispositions_of(domain: u32) -> &'static mut Dispositions {
    let index = (domain as usize) % 32;
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

/// Where a hosted domain's `Domain` capability sits in this program's CSpace.
///
/// Slot `SLOT_BASE + id`, computed from the badge the kernel stamped, so no
/// table has to be kept in step with anything. A CSpace holds 64 slots and
/// there are 32 domains, which is exactly one each in the upper half.
///
/// **This capability is the whole of the authority to touch a hosted
/// process's memory** — [RFC 0032](../../../docs/rfc/0032-a-supervisor-interface.md).
/// Without it this program can answer questions about numbers and nothing
/// else, which is what it could do an hour ago.
const SLOT_BASE: u64 = 32;

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
        if received.method == FORGET_METHOD {
            *dispositions_of(received.badge as u32) = Dispositions::new();
            let _ = call(syscall::REPLY, 0, 0, [0; 4]);
            continue;
        }
        if received.method == FAULT_METHOD {
            faults_seen(args[0], args[1]);
            let verdict = deliver(received.badge as u32, args[0], args[1]);
            let _ = call(syscall::REPLY, 0, 0, [verdict, 0, 0, 0]);
            continue;
        }

        let request = PersonalityCall::new(
            Dialect::Linux,
            received.method,
            [args[0], args[1], args[2], args[3], 0, 0],
            0,
            received.badge as u32,
        );
        let reply = answer(&request);
        let _ = call(syscall::REPLY, 0, 0, [reply.value, 0, 0, 0]);
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
