// SPDX-License-Identifier: Apache-2.0
//! A supervisor: starts a program, notices it end, and starts it again.
//!
//! [RFC 0017](../../../docs/rfc/0017-process-management.md)'s second unresolved
//! question is *what restarts a service that died*, and its answer is that
//! restart policy is **policy** — it belongs in userspace, and writing one is
//! the RFC's own test of whether its six steps were the right six.
//!
//! This is that test, and it adds nothing to the kernel. Every call below
//! existed before this program did.
//!
//! # The policy
//!
//! Restart on exit, twelve times, then report and stop. Twelve rather than for
//! ever because a policy that never finishes cannot be asserted by a boot test,
//! and what is being demonstrated is that the *loop* closes — that reaping a
//! dead child frees the budget the next one needs. A real policy would decide
//! by [`Ending`]: a program that exited did what it was asked, one that faulted
//! has a bug, one that was killed was killed on purpose. This one restarts
//! regardless, and says so rather than pretending to be more.
//!
//! # What it is given, and what it is not
//!
//! Five capabilities, in slots it does not choose. It cannot open a file: the
//! program it starts arrives as **memory it was handed**, which is the shape
//! `START` requires anyway — the kernel has no business opening files on a
//! program's behalf, so a supervisor that named one would be naming authority
//! it does not hold.
//!
//! It holds no filesystem, no device, and no way to obtain either.

#![no_std]
#![no_main]

use bhaskix_abi::{Chunk, console, method, rights, status, syscall};

/// The console this program reports through.
const CONSOLE: u64 = 0;
/// Authority to create a domain. Necessary and not sufficient: the envelope
/// allows one child at a time, which is what makes the reap below load-bearing.
const DOMAIN_CONTROL: u64 = 1;
/// Memory holding the program to start, staged by the kernel.
const IMAGE: u64 = 2;
/// A notification this program owns. `BIND` names a slot that already holds
/// one — the domain signals something the caller has, so a supervisor with no
/// notification could not be told about anything.
const SIGNAL: u64 = 3;
/// Where each child's `Domain` capability lands, and is given back from.
const CHILD: u64 = 4;
/// One page of scratch, and the only memory this program owns.
///
/// [RFC 0032](../../../docs/rfc/0032-a-supervisor-interface.md)'s copies move
/// through an **object**, never a raw address: a supervisor names memory it
/// already holds, so the kernel is never asked to validate two addresses in
/// two address spaces, and this program cannot ask for a child's bytes to land
/// anywhere it could not already write.
const SCRATCH: u64 = 5;

/// Where the child's memory is reached, and with what.
///
/// Chosen to be somewhere the child has **not** mapped, so `MAP_AT` is what
/// makes it exist — which is the claim being tested, and not one that could be
/// satisfied by writing to a page the loader happened to leave there.
const REACH_AT: u64 = 0x0000_0000_4400_0000;
/// Read and write, in `MAP_AT`'s encoding. There is deliberately no value
/// meaning writable-and-executable.
const READ_WRITE: u64 = 2;
/// The word written into the child and read back out of it.
const WITNESS: u64 = 0x0000_5250_5553_5550;
/// The entry word `bin/probe` reads as "stay a while, then go" -- a child that
/// is there long enough to be supervised and ends without being killed.
const LINGER: u64 = 8;
/// How many yields to spend waiting for a child to arrive or depart.
///
/// Generous against a *loaded* machine, not a quiet one: the whole suite runs
/// four placements and a shell test alongside this, and a bound that is ample
/// on an idle boot is the kind that fails once in twenty runs and reads as a
/// defect in whatever it was waiting for.
const MAX_WAIT: u64 = 16384;
/// Where the scratch page is mapped in this program's own space.
const SCRATCH_AT: u64 = 0x0000_0000_1300_0000;

/// How many times to start it.
///
/// That the second one is possible is the first claim: it is possible only
/// because the first child was **reaped**, which returns the envelope's single
/// child slot — so a supervisor that forgot to reap would get one start and a
/// refusal.
///
/// Twelve rather than two because the number is load-bearing against a second
/// resource. The kernel holds installed address spaces in a table of
/// `vm::MAX_SPACES`, which is eight, and until a domain that ended gave its slot
/// back a loop this long could not finish — three was enough to exhaust it, and
/// what failed was not the supervisor but whatever started ninth. A restart
/// count above the table size is the assertion that the slot comes back.
const RESTARTS: u64 = 12;

/// The badge a child's ending carries, so a wake can be told from any other.
const CHILD_BADGE: u64 = 0x5;
/// The entry word `bin/probe` reads as "say so through the capability you were
/// given, and exit".
const SAY_AND_EXIT: u64 = 7;
/// The badge the console gave this program, which a grant must carry unchanged.
///
/// **This program's own**, not the shell's. A badge is what a service is told
/// about a caller, and a holder may not invent one — passing a different value
/// is refused, which is how the first version of this failed: it carried the
/// shell's badge and the grant was told no.
const BADGE_CONSOLE: u64 = 0x0000_0000_0050_0000;
/// Every right this program holds, which is the most a grant may pass on.
const EVERYTHING_HELD: u64 = rights::READ
    | rights::WRITE
    | rights::EXECUTE
    | rights::GRANT
    | rights::REVOKE
    | rights::DERIVE;
/// The name each child is created with, packed little-endian: `restart`.
const NAME_LOW: u64 = 0x0074_7261_7473_6572;

/// There is nothing to unwind and nowhere to print to.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. A supervisor that
    // panicked has no correct answer to give, and stopping is visible to the
    // kernel where a wrong answer would not be.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Issues one system call, returning the status and the first reply register.
fn call(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> (u64, u64) {
    let status: u64;
    let value: u64;
    // SAFETY: the system-call convention from RFC 0008. Nothing is
    // dereferenced on this side: every argument is a number or a slot index,
    // and the kernel reads them from registers.
    //
    // Every argument register is declared as an output too, because the kernel
    // writes the whole frame back on the way out. `rcx` and `r11` are destroyed
    // by the instruction itself.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            in("rdi") capability,
            inlateout("rsi") method => _,
            inlateout("rdx") args[0] => value,
            inlateout("r10") args[1] => _,
            inlateout("r8") args[2] => _,
            inlateout("r9") args[3] => _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, value)
}

/// Writes bytes to the console, sixteen at a time.
fn write(bytes: &[u8]) {
    let mut rest = bytes;
    loop {
        let (chunk, tail) = Chunk::take(rest);
        let (status, _) = call(syscall::CALL, CONSOLE, console::WRITE, chunk.pack(0));
        if status != status::OK {
            // The thing that failed is the way to report things. Giving up on
            // the write is all there is.
            return;
        }
        if tail.is_empty() {
            return;
        }
        rest = tail;
    }
}

/// Writes a small decimal number.
fn write_number(value: u64) {
    if value >= 10 {
        write_number(value / 10);
    }
    write(&[b'0' + (value % 10) as u8]);
}

/// Starts the program once, and waits for it to end.
///
/// Returns the reason it ended, or `None` if any step was refused. Each step is
/// an ask on a capability, and any of them may be told no — which is the point,
/// and why the caller reports rather than assumes.
fn run_once(image_bytes: u64) -> Option<u64> {
    // A domain, empty: no threads, no capabilities, no address space.
    let (made, _) = call(
        syscall::INVOKE,
        DOMAIN_CONTROL,
        method::SPAWN,
        [CHILD, NAME_LOW, 0, 0],
    );
    if made != status::OK {
        write(b"sup: could not make a domain, status ");
        write_number(made);
        write(b"\n");
        return None;
    }

    // The console, into the child's slot 0. Without this the child runs and
    // says nothing, which is indistinguishable from a child that never ran --
    // so this grant is what makes the child's own line evidence.
    let (granted, _) = call(
        syscall::INVOKE,
        CHILD,
        method::GRANT,
        [CONSOLE, 0, EVERYTHING_HELD, BADGE_CONSOLE],
    );
    if granted != status::OK {
        write(b"sup: could not grant the console\n");
        return None;
    }

    // Ask to be told it ended **before** starting it. A binding made afterwards
    // races the program: a short-lived one can be gone before its supervisor
    // gets round to watching, and the kernel refuses a watch for an event that
    // has already happened rather than accepting a wait that never ends.
    let (bound, _) = call(
        syscall::INVOKE,
        CHILD,
        method::BIND,
        [SIGNAL, CHILD_BADGE, 0, 0],
    );
    if bound != status::OK {
        write(b"sup: could not ask to be told it ended\n");
        return None;
    }

    let (started, _) = call(
        syscall::INVOKE,
        CHILD,
        method::START,
        // The length is not optional: `START` refuses zero, and this program
        // cannot measure memory it was handed -- it holds a capability, not a
        // mapping, and no method reports an object's size. The kernel tells it
        // at entry, which is the one thing that cannot arrive through a CSpace.
        [IMAGE, image_bytes, SAY_AND_EXIT, 0],
    );
    if started != status::OK {
        write(b"sup: could not start it, status ");
        write_number(started);
        write(b"\n");
        return None;
    }

    let (woken, _) = call(syscall::INVOKE, SIGNAL, method::WAIT, [0; 4]);
    if woken != status::OK {
        write(b"sup: the wait was refused\n");
        return None;
    }

    // Why it ended, then give the slot back. **The reap is what makes the next
    // start possible**: the envelope allows one child, and a supervisor that
    // never reaped would be refused its second spawn for the budget.
    let (asked, reason) = call(syscall::INVOKE, CHILD, method::INFO, [0; 4]);
    let (reaped, _) = call(syscall::INVOKE, CHILD, method::RELEASE, [0; 4]);
    if reaped != status::OK {
        write(b"sup: could not give the domain back\n");
        return None;
    }
    if asked != status::OK {
        None
    } else {
        Some(reason)
    }
}

/// Maps a page into the running child, writes a word through it, reads it back,
/// and checks the refusals — [RFC 0032](../../../docs/rfc/0032-a-supervisor-interface.md).
///
/// Answers whether every step did what it should, including the four that
/// should be refused. Reports once, on the first child only: this runs twelve
/// times and a line per attempt would say the same thing eleven more times.
fn supervise(image_bytes: u64) -> bool {
    let (made, _) = call(
        syscall::INVOKE,
        DOMAIN_CONTROL,
        method::SPAWN,
        [CHILD, NAME_LOW, 0, 0],
    );
    if made != status::OK {
        write(b"sup: could not make a domain to supervise\n");
        return false;
    }
    let (started, _) = call(
        syscall::INVOKE,
        CHILD,
        method::START,
        [IMAGE, image_bytes, LINGER, 0],
    );
    if started != status::OK {
        write(b"sup: could not start the child to supervise\n");
        call(syscall::INVOKE, CHILD, method::RELEASE, [0; 4]);
        return false;
    }

    let held = supervise_child();

    // The child ends by itself -- that is what mode 8 is for -- so this waits
    // rather than killing, and reaps when it has. A supervisor cannot kill a
    // child it holds a handle to (RFC 0017 leaves that open), and this
    // demonstration deliberately does not need it to.
    let mut reaped = false;
    for _ in 0..MAX_WAIT {
        let (gone, _) = call(syscall::INVOKE, CHILD, method::RELEASE, [0; 4]);
        if gone == status::OK {
            reaped = true;
            break;
        }
        call(syscall::YIELD, 0, 0, [0; 4]);
    }
    if !reaped {
        write(b"sup: the supervised child would not be reaped\n");
        return false;
    }
    held
}

/// The five methods, against a child that is running.
fn supervise_child() -> bool {
    if !attach_scratch() {
        write(b"sup: could not map its own scratch page\n");
        return false;
    }

    // Map somewhere the child has not mapped, so the page exists because this
    // asked for it.
    //
    // Retried, because a domain that has been *told* to start does not have an
    // address space until its own first thread has built one: `START` parks
    // the image and returns, and the loading happens in the child. A
    // supervisor reaching in before that is refused, correctly, and the
    // refusal is the signal to wait rather than a failure to report.
    let mut mapped = 0;
    for _ in 0..MAX_WAIT {
        let (outcome, _) = call(
            syscall::INVOKE,
            CHILD,
            method::MAP_AT,
            [REACH_AT, 2, READ_WRITE, 0],
        );
        mapped = outcome;
        if mapped == status::OK {
            break;
        }
        call(syscall::YIELD, 0, 0, [0; 4]);
    }
    if mapped != status::OK {
        write(b"sup: MAP_AT into the child was refused, status ");
        write_number(mapped);
        write(b"\n");
        return false;
    }

    // Put the witness word in the scratch page, then push it into the child.
    // The page is this program's own object mapped into this program's own
    // space, so writing it is an ordinary store; the *copy* is what carries it
    // across a domain boundary, and that is the thing being tested.
    write_scratch(WITNESS);
    let (out, moved) = call(
        syscall::INVOKE,
        CHILD,
        method::COPY_OUT,
        [SCRATCH, 0, REACH_AT, 8],
    );
    if out != status::OK || moved != 8 {
        write(b"sup: COPY_OUT into the child was refused, status ");
        write_number(out);
        write(b", moved ");
        write_number(moved);
        write(b"\n");
        return false;
    }

    // Scrub the scratch page, so what comes back cannot be what went out.
    // Without this the read below would pass against a copy that did nothing —
    // which is the shape of test that convinces nobody twice.
    write_scratch(0);
    let (back, returned) = call(
        syscall::INVOKE,
        CHILD,
        method::COPY_IN,
        [SCRATCH, 0, REACH_AT, 8],
    );
    if back != status::OK || returned != 8 {
        write(b"sup: COPY_IN out of the child was refused, status ");
        write_number(back);
        write(b", moved ");
        write_number(returned);
        write(b"\n");
        return false;
    }
    if read_scratch() != WITNESS {
        write(b"sup: the word did not survive the round trip\n");
        return false;
    }

    // The refusals, which are the half worth more than the successes. Each
    // asks for something the interface must not do.
    let (unmapped_read, _) = call(
        syscall::INVOKE,
        CHILD,
        method::COPY_IN,
        [SCRATCH, 0, REACH_AT + 0x0100_0000, 8],
    );
    // And one the child does hold but this program does not: reaching into a
    // domain needs the capability, and holding *a* capability is not holding
    // *this* one.
    let (not_held, _) = call(
        syscall::INVOKE,
        SCRATCH,
        method::COPY_IN,
        [SCRATCH, 0, REACH_AT, 8],
    );
    // Two pages are mapped above **so that this asks for something oversized
    // and nothing else**. A length past the mapping would be refused for being
    // unmapped, which is the previous check wearing a different hat -- and it
    // was, until arming the gate showed this arm passing for the wrong reason.
    let (too_long, _) = call(
        syscall::INVOKE,
        CHILD,
        method::COPY_OUT,
        [SCRATCH, 0, REACH_AT, 8192],
    );
    // `DomainControl` and not the console, and the difference is the whole
    // strength of this arm. Both are "not a `Domain`" -- but a `DomainControl`
    // capability's object id is **zero**, and domain zero is a live domain
    // with an address space. So if the kind check were dropped, this call
    // would map a page into somebody else's program rather than being refused
    // for having nowhere to go. Aimed at the console first, it passed with the
    // check deleted, which is what arming the gate is for.
    let (not_a_domain, _) = call(
        syscall::INVOKE,
        DOMAIN_CONTROL,
        method::MAP_AT,
        [REACH_AT, 1, READ_WRITE, 0],
    );
    // 5 is not a protection. Writable-and-executable has no encoding at all,
    // which is `W^X` inherited by type rather than checked for.
    let (no_such_protection, _) = call(
        syscall::INVOKE,
        CHILD,
        method::MAP_AT,
        [REACH_AT + 0x1_0000, 1, 5, 0],
    );
    // **The kind check is asserted by its *status*, not by "it was refused".**
    // Every one of these fails somehow; what makes this one evidence is that
    // it fails as `NoSuchMethod` -- the supervisor handler declining the
    // capability outright, so the number is offered to the kinds that own it
    // -- rather than as the `NoSuchCapability` a domain with no address space
    // gives. Deleting the kind check turns this into the latter, and only an
    // assertion on the value can tell. A boolean could not, and did not: the
    // check was deleted and this gate stayed green.
    let refused = unmapped_read != status::OK
        && not_held != status::OK
        && too_long != status::OK
        && not_a_domain == status::NO_SUCH_METHOD
        && no_such_protection != status::OK;
    if !refused {
        // **Which one, and what it answered.** A line saying only that
        // something was allowed sends the next reader back to the source to
        // guess; under a loaded suite this failed once and said nothing about
        // where, which cost a rebuild to find out.
        write(b"sup: a refusal did not refuse -- unmapped ");
        write_number(unmapped_read);
        write(b", not-held ");
        write_number(not_held);
        write(b", oversized ");
        write_number(too_long);
        write(b", not-a-domain ");
        write_number(not_a_domain);
        write(b" (wanted ");
        write_number(status::NO_SUCH_METHOD);
        write(b"), protection ");
        write_number(no_such_protection);
        write(b"\n");
        return false;
    }

    // And give the page back, so twelve children do not leave twelve pages.
    let (gone, _) = call(
        syscall::INVOKE,
        CHILD,
        method::UNMAP_AT,
        [REACH_AT, 0, 0, 0],
    );
    if gone != status::OK {
        write(b"sup: UNMAP_AT was refused\n");
        return false;
    }

    write(
        b"sup: supervised a running child -- mapped a page into it, wrote a word across, \
read it back, and was refused an unmapped address, a domain it \
does not hold, an oversized copy, a capability that is not a domain, and a protection that \
does not exist\n",
    );
    true
}

/// Maps the scratch object into this program's own space.
///
/// `ATTACH` is how a domain maps what it *holds*, at an address of its own
/// choosing in its own space — the frames come from the object rather than
/// from anything this program said, which is what makes naming an address here
/// safe. Answers whether the page is there to be used.
fn attach_scratch() -> bool {
    let (mapped, _) = call(
        syscall::INVOKE,
        SCRATCH,
        method::ATTACH,
        [SCRATCH_AT, 1, 0, 0],
    );
    mapped == status::OK
}

/// Writes the first word of the scratch page.
fn write_scratch(value: u64) {
    // SAFETY: `SCRATCH_AT` is where `ATTACH` mapped a writable page of this
    // program's own object, checked before this is reached, and one aligned
    // `u64` is inside a page.
    unsafe { core::ptr::write_volatile(SCRATCH_AT as *mut u64, value) };
}

/// Reads the first word of the scratch page.
fn read_scratch() -> u64 {
    // SAFETY: as `write_scratch` — a page this program mapped from an object
    // it holds, at an address it chose.
    unsafe { core::ptr::read_volatile(SCRATCH_AT as *const u64) }
}

/// Where the program starts.
#[unsafe(no_mangle)]
extern "C" fn _start(image_bytes: u64) -> ! {
    write(b"sup: restart-on-exit, ");
    write_number(RESTARTS);
    write(b" times\n");

    // RFC 0032's supervisor interface, before the restart loop and on a child
    // of its own.
    //
    // **Proved here rather than by the Linux personality that motivated it**,
    // and that is the point of doing it in this program: the five methods are
    // meant to be generic -- a debugger, a checkpointer and a container
    // runtime want the same ones -- and a demonstration that only ever ran
    // under Linux would prove nothing but that Linux plumbing works. Nothing
    // in it mentions Linux.
    if !supervise(image_bytes) {
        write(b"sup: the supervisor interface did not hold\n");
    }

    let mut started = 0;
    let mut ended = 0;
    for attempt in 1..=RESTARTS {
        write(b"sup: starting child ");
        write_number(attempt);
        write(b" of ");
        write_number(RESTARTS);
        write(b"\n");

        match run_once(image_bytes) {
            Some(reason) => {
                started += 1;
                ended += 1;
                write(b"sup: child ended, reason ");
                write_number(reason);
                write(b"\n");
            }
            None => break,
        }
    }

    // One line with both counts, so a partial run cannot read as a whole one.
    write(b"sup: ");
    write_number(started);
    write(b" started, ");
    write_number(ended);
    write(b" ended, of ");
    write_number(RESTARTS);
    write(b"\n");

    call(syscall::EXIT, 0, 0, [0; 4]);
    // The kernel does not return from `Exit`. Stopping here is better than
    // running into whatever follows.
    #[allow(clippy::empty_loop)]
    loop {}
}
