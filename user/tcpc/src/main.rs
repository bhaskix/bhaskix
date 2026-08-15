// SPDX-License-Identifier: Apache-2.0
//
//! The TCP demonstration client — the first program to open a connection the
//! way every program will.
//!
//! RFC 0020 says a connection's stream lives in the *program's* pages: two
//! `Memory` objects, supplied at `CONNECT`, mapped by the service. RFC 0022
//! is the mechanism that makes the sentence sayable — a capability crosses in
//! a call — and this program is the sentence said. It holds two rings its own
//! domain owns, hands one across each of two `CONNECT` calls, and receives
//! the connection capability in the reply of a third, landing in the slot it
//! declared with `EXPECT`. Both directions of RFC 0016's mechanism in one
//! exchange, from ring 3, with nothing wired by the kernel but the
//! capabilities this program starts with.
//!
//! Step 4a carries the *capabilities*; the bytes still ride the service's
//! demonstration connection. Step 4b moves the stream onto these rings and
//! retires that demonstration. The split is why this program asserts that the
//! rings were accepted and the connection capability landed — not yet that
//! data flowed through them.
//!
//! What lands in the report page is read by the kernel after boot and gated
//! in `tests/qemu/boot-test.sh`, like every service report.

#![no_std]
#![no_main]

use bhaskix_abi::{method, rights, status, syscall, tcp};

/// The capability to the TCP service's endpoint, badged as this client.
const SERVICE: u64 = 0;
/// The report page, written for the kernel to read.
const REPORT: u64 = 1;
/// The send ring: a `Memory` object this domain owns, gifted at leg 0.
const SEND_RING: u64 = 2;
/// The receive ring: gifted at leg 1.
const RECV_RING: u64 = 3;
/// Where the connection capability may land, declared with `EXPECT`.
const CONNECTION: u64 = 4;

/// Where the report page maps in this program's space.
const REPORT_AT: u64 = 0x2300_0000;

/// First eight bytes of the report: "TCPC_RPT" says the mapping worked.
const MARKER: u64 = 0x5450_525f_4350_4354;

/// The echo peer the demonstration talks to, and its port. The same peer the
/// service's own demonstration uses, because `tests/qemu/devices.sh` wires
/// exactly one and the point of a deterministic peer is that everything
/// tests against it.
const PEER: u32 = u32::from_be_bytes([10, 0, 2, 100]);
const PEER_PORT: u64 = 9;

/// How this run ended, in the report's outcome word.
mod outcome {
    /// Started; nothing has happened yet.
    pub const STARTING: u64 = 0;
    /// Both rings were handed across `CONNECT` and accepted.
    pub const RINGS_ACCEPTED: u64 = 1;
    /// The connection capability landed where `EXPECT` said. Terminal
    /// success for step 4a.
    pub const CONNECTED: u64 = 2;
    /// A handover leg was refused with a status that will not change.
    pub const REFUSED: u64 = 3;
    /// The service kept answering `LATER` until patience ran out.
    pub const STUCK: u64 = 4;
    /// The reply said the rings arrived, but the declared slot is empty —
    /// the reply-carried half of the exchange failed.
    pub const UNLANDED: u64 = 5;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. Stopping where the
    // kernel can see it beats reporting a success that did not happen.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Issues one system call, and returns `(status, value, second)` — the
/// status, the reply's first word, and its second, which the handover
/// protocol uses for detail.
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

/// Ends this program. Never returns.
fn exit() -> ! {
    call(syscall::EXIT, 0, 0, [0; 4]);
    #[allow(clippy::empty_loop)]
    loop {}
}

/// Writes one word of the report page.
fn report_word(index: usize, value: u64) {
    // SAFETY: the report page is this program's slot 1, mapped read-write at
    // `REPORT_AT` before anything is reported; the index stays within it.
    unsafe {
        core::ptr::write_volatile((REPORT_AT + (index as u64) * 8) as *mut u64, value);
    }
}

/// Publishes progress: which step, and how it ended so far.
fn report(step: u64, outcome: u64, detail: u64) {
    report_word(1, step);
    report_word(2, outcome);
    report_word(3, detail);
}

/// One `CONNECT` leg, with a staged gift if `gift_slot` names one.
///
/// Staging and calling are two invocations by design — RFC 0022's `HAND`
/// attaches one capability to the *next* call on that endpoint, so the pair
/// reads exactly like the sentence it implements. Retried while the service
/// answers `SLOT_UNAVAILABLE`, because the service declares where a gift may
/// land just before it listens, and this program may call first.
fn leg(gift_slot: Option<u64>, leg_number: u64) -> (u64, u64, u64) {
    for _ in 0..50_000 {
        if let Some(slot) = gift_slot {
            let (staged, _, _) = call(
                syscall::INVOKE,
                SERVICE,
                method::HAND,
                [slot, rights::READ | rights::WRITE, 0, 0],
            );
            if staged != status::OK {
                return (0xFFFF, staged, 0);
            }
        }
        let (called, value, second) = call(
            syscall::CALL,
            SERVICE,
            tcp::CONNECT,
            [u64::from(PEER), PEER_PORT, leg_number, 0],
        );
        // The service has not declared yet (its `EXPECT` races this call), or
        // has not started serving. Both answer with a status that a later
        // try can change, so yield and try again.
        if called == status::SLOT_UNAVAILABLE || value == tcp::LATER {
            let _ = call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        }
        return (called, value, second);
    }
    (STUCK_STATUS, 0, 0)
}

/// The status `leg` invents for "patience ran out" — outside the kernel's
/// status space, so it cannot be mistaken for an answer.
const STUCK_STATUS: u64 = 0xFFFE;

#[unsafe(no_mangle)]
extern "C" fn tcpc_main() -> ! {
    // The report page first, so every later failure has somewhere to be seen.
    if call(
        syscall::INVOKE,
        REPORT,
        method::ATTACH,
        [REPORT_AT, 1, 0, 0],
    )
    .0 != status::OK
    {
        exit();
    }
    report_word(0, MARKER);
    report(0, outcome::STARTING, 0);

    // Leg 0: the send ring crosses. Leg 1: the receive ring. Each is one
    // `HAND` and one `CONNECT`, and each ring is a `Memory` object this
    // domain owns — which is what makes RFC 0022 step 3 mean something here:
    // if this program dies mid-connection, the service's copies die with it.
    let (status_0, value_0, detail_0) = leg(Some(SEND_RING), 0);
    if status_0 == STUCK_STATUS {
        report(1, outcome::STUCK, 0);
        exit();
    }
    if status_0 != status::OK || value_0 != tcp::OK {
        report(
            1,
            outcome::REFUSED,
            status_0 << 32 | value_0 << 16 | detail_0,
        );
        exit();
    }

    let (status_1, value_1, detail_1) = leg(Some(RECV_RING), 1);
    if status_1 == STUCK_STATUS {
        report(2, outcome::STUCK, 0);
        exit();
    }
    if status_1 != status::OK || value_1 != tcp::OK {
        report(
            2,
            outcome::REFUSED,
            status_1 << 32 | value_1 << 16 | detail_1,
        );
        exit();
    }
    report(2, outcome::RINGS_ACCEPTED, 0);

    // Leg 2: the connection capability comes back. Declared before the call,
    // one-shot and addressed to this endpoint, so a hostile service could not
    // fill a slot this program was keeping empty — and this service, asked
    // properly, can fill exactly the one it was offered.
    let (declared, _, _) = call(
        syscall::INVOKE,
        SERVICE,
        method::EXPECT,
        [CONNECTION, 0, 0, 0],
    );
    if declared != status::OK {
        report(3, outcome::REFUSED, declared << 8);
        exit();
    }
    let (status_2, value_2, detail_2) = leg(None, 2);
    if status_2 == STUCK_STATUS {
        report(3, outcome::STUCK, 0);
        exit();
    }
    if status_2 != status::OK || value_2 != tcp::OK {
        report(
            3,
            outcome::REFUSED,
            status_2 << 32 | value_2 << 16 | detail_2,
        );
        exit();
    }

    // The reply said yes; the slot says whether the capability truly landed.
    // Both halves are asserted because either alone can lie: a reply without
    // a landing is the exchange half-done, and a landing without a reply was
    // never offered. The probe reads by *refusal shape*: an empty slot fails
    // to resolve at all (`NO_SUCH_CAPABILITY`), while an occupied one reaches
    // method dispatch — `INFO` is not a method on an endpoint, and that
    // refusal is itself the proof something is there to refuse it.
    let (landed, kind, _) = call(syscall::INVOKE, CONNECTION, method::INFO, [0; 4]);
    if landed == status::NO_SUCH_CAPABILITY {
        report(4, outcome::UNLANDED, landed);
    } else {
        report(4, outcome::CONNECTED, kind ^ value_2);
    }
    exit()
}

core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    xor rbp, rbp
    and rsp, -16
    call tcpc_main
    ud2
"#
);
