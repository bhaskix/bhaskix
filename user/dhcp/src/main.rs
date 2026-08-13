// SPDX-License-Identifier: Apache-2.0
//! A DHCP client, holding a socket and nothing else.
//!
//! [RFC 0018](../../../docs/rfc/0018-networking.md) step 6, and the answer to
//! that RFC's own first unresolved question. It asks *what owns the interface's
//! address*, and observes that DHCP "is a client holding a socket, which would
//! be the more capability-shaped answer".
//!
//! This is that answer built rather than argued. The kernel hardcodes an
//! address today and hands it to `bin/ipd`; this program asks a server for one
//! instead, and it needs no authority to do so beyond a socket and a page.
//!
//! # What it holds, which is the argument
//!
//! Four capabilities: the endpoint it binds a socket on, the slot the socket
//! lands in, one page of memory, and a page to report through. **No device, no
//! DMA window, no interrupt, no filesystem, no console.** A program that can
//! obtain an address for the machine turns out to need almost nothing, and that
//! is only true because a socket is a capability rather than an ambient right.
//!
//! # Why it is not a shell command
//!
//! It was one first. That meant linking `bhaskix-net` into a program that also
//! holds domain control, a filesystem and a device window — and the shell grew
//! until the kernel would not load it. The failure was loud but the reason was
//! not: every socket assertion went red at once because the machine fell back
//! to the kernel shell. A client that needs a socket and a page should hold a
//! socket and a page.
#![no_std]
#![no_main]

use bhaskix_abi::{method, socket, status, syscall};
use bhaskix_net::{MacAddr, dhcp};

/// Slot: the endpoint this program binds a socket on.
const NETWORK: u64 = 0;
/// Slot: where the socket lands, declared with `EXPECT` before asking.
const SOCKET: u64 = 1;
/// Slot: one page, which the datagram is built in and delivered into.
const MEMORY: u64 = 2;
/// Slot: the page this program leaves its findings in.
const REPORT: u64 = 3;
/// Slot: a notification this program arms a deadline on, and waits on.
///
/// **RFC 0019 step 3, and the point of that RFC.** This program used to wait by
/// counting: four hundred passes round a loop was too few to catch a reply, and
/// a million kept a processor busy long enough that the shell test timed out.
/// Neither number meant anything — both were "how long is a loop", which
/// depends on the machine.
///
/// It waits for a *duration* now. Read to wait on, write to arm; both are
/// itself, and the badge is what the wake carries.
const TIMER: u64 = 4;

/// How long to wait for an offer, and how long between asks.
///
/// **Durations, in the source, in units a reader has.** The retry interval is
/// not tuning: `bin/ipd` drains its ring when a client asks, so asking is what
/// makes the service look at the wire, and this is how often that happens.
const PATIENCE_MS: u64 = 3_000;
const RETRY_MS: u64 = 20;

/// Where this program maps what it holds.
const MEMORY_AT: u64 = 0x2200_0000;
const REPORT_AT: u64 = 0x2210_0000;

/// The port a DHCP client is answered on, and the one a server listens on.
///
/// Fixed by the protocol rather than chosen: binding anything else means the
/// reply is delivered to a socket nobody holds.
const CLIENT_PORT: u64 = 68;
const SERVER_PORT: u64 = 67;

/// The marker the kernel looks for before believing the report.
const MARKER: u64 = 0x3145_4e4f_5044_4844;

/// There is nothing to unwind and nowhere to print to.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. Stopping where the kernel
    // can see it beats carrying on with a half-built request.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Issues one system call, and returns `(status, value, second)`.
fn call(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> (u64, u64, u64) {
    let status: u64;
    let mut value = args[0];
    let mut second = args[1];
    // SAFETY: the system call convention from RFC 0008. Nothing is
    // dereferenced on this side, and every argument register is declared as an
    // output because the kernel writes the whole frame back on the way out.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            inlateout("rdi") capability => _,
            inlateout("rsi") method => _,
            inlateout("rdx") value,
            inlateout("r10") second,
            inlateout("r8") args[2] => _,
            inlateout("r9") args[3] => _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, value, second)
}

/// Maps a capability at an address, and says whether it worked.
fn attach(slot: u64, at: u64, writable: u64) -> bool {
    call(syscall::INVOKE, slot, method::ATTACH, [at, writable, 0, 0]).0 == status::OK
}

/// Ends this program. Never returns.
fn exit() -> ! {
    call(syscall::EXIT, 0, 0, [0; 4]);
    #[allow(clippy::empty_loop)]
    loop {}
}

/// The page a request is built in and a reply is delivered into.
///
/// # Safety
///
/// [`MEMORY`] must have been attached at [`MEMORY_AT`] first.
unsafe fn page() -> &'static mut [u8] {
    // SAFETY: one page of memory this program holds and mapped writable, which
    // nothing else in this program uses.
    unsafe { core::slice::from_raw_parts_mut(MEMORY_AT as *mut u8, 4096) }
}

/// Leaves the findings where the kernel granted memory for them.
fn report(address: u32, server: u32, outcome: u64) {
    let words = [MARKER, u64::from(address), u64::from(server), outcome];
    // SAFETY: the page this program mapped writable, which nothing else
    // reaches. The marker is written last, so a kernel reading a partial report
    // sees no marker rather than half the fields.
    unsafe {
        for (index, word) in words.iter().enumerate().skip(1) {
            core::ptr::write_volatile((REPORT_AT + index as u64 * 8) as *mut u64, *word);
        }
        core::ptr::write_volatile(REPORT_AT as *mut u64, words[0]);
    }
}

/// Outcome: an address was offered.
const OFFERED: u64 = 0;
/// Outcome: there is no network to ask.
const NO_NETWORK: u64 = 1;
/// Outcome: nobody answered.
const SILENT: u64 = 2;
/// Outcome: something answered and it was not an offer.
const NOT_AN_OFFER: u64 = 3;
/// Outcome: the slot to be answered in was refused. Carries the status.
const NO_EXPECT: u64 = 4;
/// Outcome: no socket was bound. Carries the status and what the service said.
const NO_BIND: u64 = 5;
/// Outcome: the datagram was not sent. Carries the status and the service's.
const NO_SEND: u64 = 6;

/// Reads the cycle counter. Unprivileged: `CR4.TSD` is clear on this machine.
fn rdtsc() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: reads a counter and touches no memory. RFC 0019 records that this
    // is readable at every privilege level here, which is why reading time needs
    // no capability and being *woken* does.
    unsafe {
        core::arch::asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack));
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Sleeps until `deadline`. Says whether it actually slept.
///
/// A machine that could not give this program a notification is one where
/// asking again immediately is all that is left, and saying so beats spinning
/// silently.
fn sleep_until(deadline: u64) -> bool {
    if call(syscall::INVOKE, TIMER, method::ARM, [deadline, 0, 0, 0]).0 != status::OK {
        return false;
    }
    // Blocks until the word is non-zero, which the kernel makes it when the
    // deadline passes. No endpoint is needed: this program serves nobody.
    call(syscall::INVOKE, TIMER, method::WAIT, [0; 4]).0 == status::OK
}

/// The entry point.
///
/// `hertz` is the cycle counter's rate, handed over at entry because it is the
/// one thing about the clock that cannot arrive through a CSpace.
#[unsafe(no_mangle)]
extern "C" fn dhcp_main(hertz: u64) -> ! {
    if !attach(MEMORY, MEMORY_AT, 1) || !attach(REPORT, REPORT_AT, 1) {
        exit()
    }
    report(0, 0, NO_NETWORK);

    // Where a capability may land. Declared by *this* program, one-shot, and
    // the service cannot name another slot.
    //
    // **Each failure below reports which one it was, carrying the number the
    // kernel or the service actually returned.** One outcome covered all three
    // once, and "no network to ask" was then true of a client that had a
    // network, an endpoint and a service — it said where the program stopped,
    // not why, and cost a boot cycle per guess.
    let expected = call(syscall::INVOKE, NETWORK, method::EXPECT, [SOCKET, 0, 0, 0]);
    if expected.0 != status::OK {
        // No endpoint means no network, and no network is a state rather than a
        // failure: a machine with no device still boots.
        report(expected.0 as u32, 0, NO_EXPECT);
        exit()
    }
    // **Retried, because a service that is not answering yet is not a service
    // that refused.** This gave up on the first attempt, and the first attempt
    // lands while `bin/ipd` is still finishing the demonstration it does before
    // it starts serving — so the client reported "no network to ask" about a
    // network that was seconds away from existing.
    //
    // A yield between attempts rather than a spin: this program is pinned like
    // every other, and a client busy-waiting for a service to start would be
    // the third poll loop this system has paid for today.
    let per_retry = hertz.saturating_mul(RETRY_MS) / 1000;
    let give_up_at = rdtsc().saturating_add(hertz.saturating_mul(PATIENCE_MS) / 1000);

    let mut bound;
    loop {
        bound = call(
            syscall::CALL,
            NETWORK,
            socket::BIND_UDP,
            [CLIENT_PORT, 0, 0, 0],
        );
        if bound.0 == status::OK && bound.1 == socket::OK {
            break;
        }
        // A service that is not answering yet is not a service that refused,
        // and the wait for it is a length of time now rather than a count.
        if rdtsc() >= give_up_at || !sleep_until(rdtsc().saturating_add(per_retry)) {
            break;
        }
    }
    if bound.0 != status::OK || bound.1 != socket::OK {
        report(bound.0 as u32, bound.1 as u32, NO_BIND);
        exit()
    }

    // SAFETY: attached above.
    let buffer = unsafe { page() };
    // The hardware address goes in as zero: the *service* puts the real one on
    // the frame, and this program holds no device to ask what it is. A server
    // answers the broadcast either way, which is what makes a client that knows
    // nothing about the interface possible at all.
    let Ok(length) = dhcp::write_discover(buffer, MacAddr([0; 6]), 0x0b_1a_5c_01) else {
        exit()
    };

    let sent = call(
        syscall::CALL,
        SOCKET,
        socket::SEND_TO,
        [u64::from(u32::MAX), SERVER_PORT, MEMORY, length as u64],
    );
    if sent.0 != status::OK || sent.1 != socket::OK {
        report(sent.0 as u32, sent.1 as u32, NO_SEND);
        exit()
    }

    // Asking is what makes the service look at the wire, so asking repeatedly
    // is how a client waits without a timer it does not have.
    //
    // **With a yield between asks, and a bound that is deliberately modest.**
    // Four hundred calls in a row cost less than a millisecond and cannot
    // outlast a driver that is asleep, so this yields. It was briefly a million
    // attempts, which was tuning against a bug rather than against the network:
    // frames larger than sixty-four bytes were not being delivered at all, so
    // no amount of patience would have helped and more of it only hid how long
    // the client stayed alive. With `QUEUE_SIZE` written the offer arrives in
    // milliseconds.
    //
    // The bound matters because this is a **spin**, and a spinning program on a
    // pinned thread is a processor the rest of the machine cannot have. The
    // shell test found exactly that once for `netd` and `ipd`, and it found it
    // again here: with a million attempts the shell's own commands timed out.
    let wait_until = rdtsc().saturating_add(hertz.saturating_mul(PATIENCE_MS) / 1000);
    loop {
        let got = call(syscall::CALL, SOCKET, socket::RECV_FROM, [MEMORY, 0, 0, 0]);
        if got.0 != status::OK || got.1 != socket::OK {
            if rdtsc() >= wait_until {
                break;
            }
            // **Asleep, not spinning.** Asking is what makes `bin/ipd` look at
            // the wire, so this asks again after a while rather than as fast as
            // the scheduler will let it.
            if !sleep_until(rdtsc().saturating_add(per_retry)) {
                call(syscall::YIELD, 0, 0, [0; 4]);
            }
            continue;
        }
        // SAFETY: the same page, still attached.
        let reply = unsafe { page() };
        match dhcp::parse_offer(reply) {
            Ok(offer) => {
                report(offer.address.0, offer.server.0, OFFERED);
                exit()
            }
            Err(_) => {
                // Something answered and it was not an offer. Reported rather
                // than retried silently: a client that ignored what it could
                // not read looks identical to one nobody answered.
                report(0, 0, NOT_AN_OFFER);
                exit()
            }
        }
    }
    report(0, 0, SILENT);
    exit()
}

core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    xor rbp, rbp
    and rsp, -16
    call dhcp_main
    ud2
"#
);
