// SPDX-License-Identifier: Apache-2.0
//! One v6 datagram to loopback and back, through sockets and nothing else.
//!
//! [RFC 0029](../../../docs/rfc/0029-ipv6.md) step 4's live proof. Two v6
//! sockets in one program: a datagram leaves through `SEND_TO6` addressed
//! to `[::1]`, the service delivers it locally to the second socket —
//! loopback is *stack behaviour*, not a shortcut: self-addressed traffic
//! never touches a wire on any correct stack — and `RECV_FROM6` brings it
//! back with the source the loopback convention names. That is the whole
//! v6 face of the socket ABI, exercised across a real domain boundary in
//! both directions: `BIND_UDP6` twice, the four-word send packing, the
//! family-matched delivery, and the port-above-outcome reply.
//!
//! # Why the peer is `::1` and not the network
//!
//! Because this emulator has no other one. slirp answers ICMPv6 echo (step
//! 3's wire proof) but its DNS proxy has no v6 face and a hairpinned
//! datagram to the guest's own address is dropped — both measured on the
//! wire with a pcap, 2026-08-18, the question leaving well-formed and
//! decoded by `tcpdump` itself. An off-box v6 UDP reply therefore carries
//! the same written trigger as inbound TCP: a newer emulator, or hardware.
//!
//! # What it holds
//!
//! `bin/dhcp`'s inventory plus one empty slot: the endpoint, two socket
//! slots, one page, a report page, a timer. No device, no window, no
//! `bhaskix-net` — seventeen fixed bytes need no protocol library.

#![no_std]
#![no_main]

use bhaskix_sock::call::{attach, call};
use bhaskix_sock::time::{Pace, now};
use bhaskix_sock::udp::Refusal;
use bhaskix_sock::udp6;
use bhaskix_sock::wait::doze;

/// Slot: the endpoint this program binds sockets on.
const NETWORK: u64 = 0;
/// Slot: where the sending socket lands.
const SENDER: u64 = 1;
/// Slot: one page, which the datagram is built in and delivered into.
const MEMORY: u64 = 2;
/// Slot: the page this program leaves its findings in.
const REPORT: u64 = 3;
/// Slot: a notification this program arms a deadline on, and waits on.
const TIMER: u64 = 4;
/// Slot: where the receiving socket lands. Above the kernel-granted five,
/// in space that is this program's own to lay out.
const RECEIVER: u64 = 5;

/// How long to wait, and how long between asks.
const PATIENCE_MS: u64 = 3_000;
const RETRY_MS: u64 = 20;

/// Where this program maps what it holds.
const MEMORY_AT: u64 = 0x2300_0000;
const REPORT_AT: u64 = 0x2310_0000;

/// The loopback address, which is the one v6 peer every stack has.
const LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// The payload, fixed at build time and compared byte-for-byte on return.
const PAYLOAD: [u8; 17] = *b"bhaskix-udp6-0001";

/// The marker the kernel looks for before believing the report.
const MARKER: u64 = 0x3136_5044_5544_5844;

/// There is nothing to unwind and nowhere to print to.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. Stopping where the
    // kernel can see it beats carrying on half-built.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Ends this program. Never returns.
fn exit() -> ! {
    let _ = call(bhaskix_abi::syscall::EXIT, 0, 0, [0; 4]);
    #[allow(clippy::empty_loop)]
    loop {}
}

/// The page the datagram is built in and delivered into.
///
/// # Safety
///
/// [`MEMORY`] must have been attached at [`MEMORY_AT`] first.
unsafe fn page() -> &'static mut [u8] {
    // SAFETY: one page of memory this program holds and mapped writable,
    // which nothing else in this program uses.
    unsafe { core::slice::from_raw_parts_mut(MEMORY_AT as *mut u8, 4096) }
}

/// Outcome: the datagram came back — right source, right port, right
/// bytes. The first detail word is the receiver's port.
const RETURNED: u64 = 0;
/// Outcome: there is no network service to ask.
const NO_NETWORK: u64 = 1;
/// Outcome: sent, and nothing was delivered.
const SILENT: u64 = 2;
/// Outcome: something was delivered and it was not ours — wrong source,
/// wrong port, or altered bytes. The detail words carry what arrived.
const NOT_OURS: u64 = 3;
/// Outcome: a slot to be answered in was refused. Carries the status.
const NO_EXPECT: u64 = 4;
/// Outcome: a socket was not bound. Carries the two refusal halves.
const NO_BIND: u64 = 5;
/// Outcome: the datagram was not sent. Carries the two refusal halves.
const NO_SEND: u64 = 6;

/// Leaves the findings where the kernel granted memory for them.
fn report(first: u64, second: u64, outcome: u64) {
    let words = [MARKER, first, second, outcome];
    // SAFETY: the page this program mapped writable, which nothing else
    // reaches. The marker is written last, so a kernel reading a partial
    // report sees no marker rather than half the fields.
    unsafe {
        for (index, word) in words.iter().enumerate().skip(1) {
            core::ptr::write_volatile((REPORT_AT + index as u64 * 8) as *mut u64, *word);
        }
        core::ptr::write_volatile(REPORT_AT as *mut u64, words[0]);
    }
}

/// The two halves a refusal reports: the kernel's word and the service's.
const fn halves(refusal: &Refusal) -> (u64, u64) {
    match refusal {
        Refusal::Kernel(word) => (*word, 0),
        Refusal::Service(word) => (bhaskix_abi::status::OK, *word),
    }
}

/// The entry point.
///
/// `hertz` is the cycle counter's rate, handed over at entry because it is
/// the one thing about the clock that cannot arrive through a CSpace.
#[unsafe(no_mangle)]
extern "C" fn udp6_main(hertz: u64) -> ! {
    if !attach(MEMORY, MEMORY_AT, true) || !attach(REPORT, REPORT_AT, true) {
        exit()
    }
    report(0, 0, NO_NETWORK);

    let pace = Pace::new(hertz);
    let give_up_at = now().saturating_add(pace.cycles(PATIENCE_MS));

    // Two sockets, each landing where this program said. Retried asleep,
    // for bin/dhcp's stated reason: a service not answering yet is not a
    // service that refused.
    let mut bound = [None, None];
    for (which, slot) in [(0, SENDER), (1, RECEIVER)] {
        if let Err(refusal) = udp6::expect_socket(NETWORK, slot) {
            report(refusal.word(), 0, NO_EXPECT);
            exit()
        }
        bound[which] = loop {
            match udp6::bind6(NETWORK, slot, 0) {
                Ok(socket) => break Some(socket),
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
    }
    let (Some(sender), Some(receiver)) = (bound[0], bound[1]) else {
        report(0, 0, NO_BIND);
        exit()
    };

    // SAFETY: attached above.
    let buffer = unsafe { page() };
    buffer[..PAYLOAD.len()].copy_from_slice(&PAYLOAD);

    if let Err(refusal) = sender.send_to(MEMORY, LOOPBACK, receiver.port(), PAYLOAD.len()) {
        let (kernel, service) = halves(&refusal);
        report(kernel, service, NO_SEND);
        exit()
    }

    // Asking is what makes the service look; asleep between asks, bounded
    // by patience rather than by a loop count.
    let wait_until = now().saturating_add(pace.cycles(PATIENCE_MS));
    loop {
        match receiver.recv_from(MEMORY) {
            Ok(Some(from)) => {
                // SAFETY: the same page, still attached.
                let answer = unsafe { page() };
                if from.address == LOOPBACK
                    && from.port == sender.port()
                    && answer[..PAYLOAD.len()] == PAYLOAD
                {
                    report(
                        u64::from(receiver.port()),
                        u64::from(sender.port()),
                        RETURNED,
                    );
                    exit()
                }
                report(u64::from(from.port), u64::from(from.address[15]), NOT_OURS);
                exit()
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
    call udp6_main
    ud2
"#
);
