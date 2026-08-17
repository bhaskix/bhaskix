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
//!
//! # The first program ported onto `bhaskix-sock`
//!
//! RFC 0027 step 1. The exchange — the `EXPECT`, the bind and its refusal
//! decoding, `SEND_TO`, `RECV_FROM`, the sleep between asks — is the crate's
//! now; what remains here is what is genuinely this program's: the DHCP
//! payloads, the report page, and the patience policy. The lessons this file
//! used to carry as comments (retry the bind, sleep rather than spin, report
//! the exact word that refused) are the crate's behaviour.
#![no_std]
#![no_main]

use bhaskix_net::{MacAddr, dhcp};
use bhaskix_sock::call::{attach, call};
use bhaskix_sock::time::{Pace, now};
use bhaskix_sock::wait::doze;
use bhaskix_sock::{udp, udp::Refusal};

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
/// RFC 0019 step 3, and the point of that RFC: this program waits for a
/// *duration*, not a loop count. The waiting itself is `bhaskix-sock`'s now.
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
const CLIENT_PORT: u16 = 68;
const SERVER_PORT: u16 = 67;

/// The marker the kernel looks for before believing the report.
const MARKER: u64 = 0x3145_4e4f_5044_4844;

/// There is nothing to unwind and nowhere to print to.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. Stopping where the kernel
    // can see it beats carrying on with a half-built request.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Ends this program. Never returns.
fn exit() -> ! {
    let _ = call(bhaskix_abi::syscall::EXIT, 0, 0, [0; 4]);
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

/// The two halves a refusal reports: the kernel's word and the service's.
/// The crate keeps both; the report page has always shown both.
const fn halves(refusal: &Refusal) -> (u32, u32) {
    match refusal {
        Refusal::Kernel(word) => (*word as u32, 0),
        Refusal::Service(word) => (bhaskix_abi::status::OK as u32, *word as u32),
    }
}

/// The entry point.
///
/// `hertz` is the cycle counter's rate, handed over at entry because it is the
/// one thing about the clock that cannot arrive through a CSpace.
#[unsafe(no_mangle)]
extern "C" fn dhcp_main(hertz: u64) -> ! {
    if !attach(MEMORY, MEMORY_AT, true) || !attach(REPORT, REPORT_AT, true) {
        exit()
    }
    report(0, 0, NO_NETWORK);

    // Where a capability may land: declared by *this* program, one-shot, and
    // the service cannot name another slot. No endpoint means no network,
    // and no network is a state rather than a failure — a machine with no
    // device still boots.
    if let Err(refusal) = udp::expect_socket(NETWORK, SOCKET) {
        report(refusal.word() as u32, 0, NO_EXPECT);
        exit()
    }

    // Retried, because a service that is not answering yet is not a service
    // that refused: the first attempt lands while `bin/ipd` is still
    // finishing the demonstration it does before it starts serving. Asleep
    // between attempts, not spinning — the crate's `doze` yields on a
    // machine that cannot sleep.
    let pace = Pace::new(hertz);
    let give_up_at = now().saturating_add(pace.cycles(PATIENCE_MS));
    let socket = loop {
        match udp::bind(NETWORK, SOCKET, CLIENT_PORT) {
            Ok(socket) => break socket,
            Err(refusal) => {
                if now() >= give_up_at {
                    let (kernel, service) = halves(&refusal);
                    report(kernel, service, NO_BIND);
                    exit()
                }
                doze(TIMER, &pace, RETRY_MS);
            }
        }
    };

    // SAFETY: attached above.
    let buffer = unsafe { page() };
    // The hardware address goes in as zero: the *service* puts the real one on
    // the frame, and this program holds no device to ask what it is. A server
    // answers the broadcast either way, which is what makes a client that knows
    // nothing about the interface possible at all.
    let Ok(length) = dhcp::write_discover(buffer, MacAddr([0; 6]), 0x0b_1a_5c_01) else {
        exit()
    };

    if let Err(refusal) = socket.send_to(MEMORY, u32::MAX, SERVER_PORT, length) {
        let (kernel, service) = halves(&refusal);
        report(kernel, service, NO_SEND);
        exit()
    }

    // Asking is what makes the service look at the wire, so asking repeatedly
    // is how a client waits — asleep between asks, bounded by patience rather
    // than by a loop count that means nothing.
    let wait_until = now().saturating_add(pace.cycles(PATIENCE_MS));
    loop {
        match socket.recv_from(MEMORY) {
            Ok(Some(_from)) => {
                // SAFETY: the same page, still attached.
                let reply = unsafe { page() };
                match dhcp::parse_offer(reply) {
                    Ok(offer) => {
                        report(offer.address.0, offer.server.0, OFFERED);
                        exit()
                    }
                    Err(_) => {
                        // Something answered and it was not an offer. Reported
                        // rather than retried silently: a client that ignored
                        // what it could not read looks identical to one nobody
                        // answered.
                        report(0, 0, NOT_AN_OFFER);
                        exit()
                    }
                }
            }
            Ok(None) | Err(_) => {
                if now() >= wait_until {
                    break;
                }
                doze(TIMER, &pace, RETRY_MS);
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
