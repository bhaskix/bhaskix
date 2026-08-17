// SPDX-License-Identifier: Apache-2.0
//! `bin/traced` — the telemetry plane's first consumer, RFC 0026 steps 3–4.
//!
//! This program holds exactly two authorities: the per-CPU event rings,
//! **read-only**, and the tails page, read-write. It maps them through
//! `ATTACH` like any memory it is granted, drains every ring through the
//! protocol `bhaskix-telemetry` defines — acquire the head, read the slots
//! below it, publish the tail — and proves the round trip: the marked probe
//! events the kernel emitted on every CPU must all come back through pages
//! this program mapped itself, decoded against the same registry the kernel
//! hashed into every ring's header.
//!
//! A ring whose marker or registry hash disagrees is refused and counted,
//! never decoded — the "a stale tool says so instead of lying" rule, running
//! in its first consumer.

#![no_std]
#![no_main]

use bhaskix_abi::{method, status, syscall};
use bhaskix_telemetry::{EVENT_BYTES, EventClass, Refusal, decode, ring, schema};

/// Slot: this program's report page, read by the kernel.
const REPORT: u64 = 1;
/// Slot: the wake this program arms deadlines on between drain passes.
const WAKE: u64 = 2;
/// Slot: the tails page — the one word per CPU this program may write.
const TAILS: u64 = 7;
/// Slot of the first CPU's ring; CPU `n`'s ring is at `FIRST_RING + n`.
const FIRST_RING: u64 = 8;

/// Where the report page maps.
const REPORT_AT: u64 = 0x2400_0000;
/// Where the tails page maps.
const TAILS_AT: u64 = 0x2410_0000;
/// Where CPU 0's ring maps; each further CPU is one stride up.
const RINGS_AT: u64 = 0x2420_0000;
/// Bytes between ring mappings — roomy, so a ring that grows does not move
/// its neighbours.
const RING_STRIDE: u64 = 0x10_0000;
/// Bytes one ring region spans, matching the kernel's nine pages.
const RING_REGION: usize = 9 * 4096;

/// First eight bytes of the report: `b"TRACED01"`, the mapping worked.
const MARKER: u64 = u64::from_le_bytes(*b"TRACED01");

/// The payload mark the kernel's round-trip probes carry. Distinct from the
/// boot report's own instrument probes, so this count means "the marked
/// set" and nothing else.
const PROBE_MARK: u64 = u64::from_le_bytes(*b"TRACEPRB");

/// There is nothing to unwind and nowhere to print to.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. Stopping where the
    // kernel can see it beats reporting numbers from an unknown state.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Issues one system call, and returns `(status, value)`.
fn call(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> (u64, u64) {
    let status: u64;
    let mut value = args[0];
    // SAFETY: the system call convention from RFC 0008. Nothing is
    // dereferenced on this side, and every argument register is declared as
    // an output because the kernel writes the whole frame back on the way
    // out.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            inlateout("rdi") capability => _,
            inlateout("rsi") method => _,
            inlateout("rdx") value,
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

/// Reads one word of memory this program mapped.
fn word_at(address: u64) -> u64 {
    // SAFETY: every caller passes an address inside a region `ATTACH`
    // accepted for this program — a ring, or the tails page — bounded by the
    // arithmetic of `bhaskix_telemetry::ring`.
    unsafe { core::ptr::read_volatile(address as *const u64) }
}

/// What this program concluded, cumulative across passes, written as it
/// goes so a wedge mid-drain still shows how far it came.
struct Tally {
    probes: u64,
    decoded: u64,
    refused: u64,
    bad_rings: u64,
    wrong_cpu: u64,
    sched: u64,
    syscalls: u64,
    passes: u64,
}

impl Tally {
    fn publish(&self) {
        report_word(2, self.probes);
        report_word(3, self.decoded);
        report_word(4, self.refused);
        report_word(5, self.bad_rings);
        report_word(6, self.wrong_cpu);
        report_word(7, self.sched);
        report_word(8, self.syscalls);
        report_word(9, self.passes);
    }
}

/// The cycle counter, for arming the between-passes deadline.
fn rdtsc() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: `rdtsc` reads the counter and touches nothing else.
    unsafe {
        core::arch::asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack));
    }
    u64::from(high) << 32 | u64::from(low)
}

/// Drains one ring: everything between the stored tail and the acquired
/// head, decoded, counted, consumed.
fn drain(cpu: u64, layout: ring::Layout, tally: &mut Tally) {
    let base = RINGS_AT + cpu * RING_STRIDE;
    let slots = layout.slots();
    // The consumer's ordering half: the head is read before any slot, with
    // an acquire fence between, pairing with the producer's release publish
    // — so no slot this loop reads was half-written when the head admitted
    // it.
    let head = word_at(base + ring::HEAD_OFFSET as u64);
    core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
    let tail_address = TAILS_AT + ring::tail_offset(cpu as usize) as u64;
    let tail = word_at(tail_address);
    let readable = ring::readable(head, tail, slots);

    for sequence in tail..tail + readable {
        let slot = base + layout.slot_offset(sequence) as u64;
        let mut bytes = [0u8; EVENT_BYTES];
        for (word, chunk) in bytes.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&word_at(slot + word as u64 * 8).to_le_bytes());
        }
        match decode(&bytes) {
            Ok((event, found)) => {
                tally.decoded += 1;
                if u64::from(event.cpu) != cpu {
                    tally.wrong_cpu += 1;
                }
                if event.class == EventClass::Sched as u32 {
                    tally.sched += 1;
                } else if event.class == EventClass::Syscall as u32 {
                    tally.syscalls += 1;
                }
                let mut mark = [0u8; 8];
                mark.copy_from_slice(&event.payload[..8]);
                if found.id == schema::PROBE.id && u64::from_le_bytes(mark) == PROBE_MARK {
                    tally.probes += 1;
                }
            }
            Err(Refusal::UnknownClass(_) | Refusal::UnknownSchema(_)) => tally.refused += 1,
        }
    }

    // Consumption, published — exactly what was read, not the head, which
    // may have advanced while this pass decoded.
    if readable > 0 {
        // SAFETY: this program's own tail word, mapped read-write at start.
        unsafe { core::ptr::write_volatile(tail_address as *mut u64, tail + readable) };
    }
}

#[unsafe(no_mangle)]
extern "C" fn traced_main(cpus: u64, hertz: u64) -> ! {
    // The report page first, so every later failure has somewhere to be
    // seen. Outcome zero means "attached and no further" until the first
    // full pass finishes.
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
    report_word(1, 0);

    // The tails page, writable: the consumer's half of the protocol.
    if call(syscall::INVOKE, TAILS, method::ATTACH, [TAILS_AT, 1, 0, 0]).0 != status::OK {
        report_word(1, 2);
        exit();
    }

    let mut tally = Tally {
        probes: 0,
        decoded: 0,
        refused: 0,
        bad_rings: 0,
        wrong_cpu: 0,
        sched: 0,
        syscalls: 0,
        passes: 0,
    };
    let Some(layout) = ring::Layout::for_region(RING_REGION) else {
        report_word(1, 3);
        exit();
    };

    // Attach and validate each ring once. A ring is believed only when it
    // says what this build says: the marker, the registry hash, and a slot
    // count matching the region's own arithmetic. Anything else is counted
    // and never decoded, on any pass.
    let mut believed = [false; 64];
    for cpu in 0..cpus.min(64) {
        let base = RINGS_AT + cpu * RING_STRIDE;
        // Read-only on purpose, and the grant enforces it: the capability
        // carries no WRITE, so asking for a writable mapping here would be
        // refused rather than quietly narrowed.
        if call(
            syscall::INVOKE,
            FIRST_RING + cpu,
            method::ATTACH,
            [base, 0, 0, 0],
        )
        .0 != status::OK
        {
            report_word(1, 4 | (cpu << 8));
            exit();
        }
        let marker = word_at(base + ring::MARKER_OFFSET as u64);
        let hash = word_at(base + ring::HASH_OFFSET as u64);
        let slots = word_at(base + ring::SLOTS_OFFSET as u64);
        if marker == ring::MARKER && hash == schema::registry_hash() && slots == layout.slots() {
            believed[cpu as usize] = true;
        } else {
            tally.bad_rings += 1;
        }
    }

    // The consumer loop: drain, publish, sleep on an armed deadline, again
    // — RFC 0026 step 5's live reader, draining for the life of the boot so
    // the rings stop saturating the moment this program starts. A machine
    // with no calibrated clock (or no wake granted) gets one honest pass
    // and a clean exit rather than a spinning yield loop.
    loop {
        for cpu in 0..cpus.min(64) {
            if believed[cpu as usize] {
                drain(cpu, layout, &mut tally);
            }
        }
        tally.passes += 1;
        tally.publish();
        report_word(1, 1);

        if hertz == 0 {
            break;
        }
        let deadline = rdtsc().wrapping_add(hertz / 20);
        if call(syscall::INVOKE, WAKE, method::ARM, [deadline, 0, 0, 0]).0 != status::OK {
            break;
        }
        let _ = call(syscall::INVOKE, WAKE, method::WAIT, [0; 4]);
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
    call traced_main
    ud2
"#
);
