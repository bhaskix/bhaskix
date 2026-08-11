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

/// Where the program starts.
#[unsafe(no_mangle)]
extern "C" fn _start(image_bytes: u64) -> ! {
    write(b"sup: restart-on-exit, ");
    write_number(RESTARTS);
    write(b" times\n");

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
