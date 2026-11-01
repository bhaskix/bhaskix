// SPDX-License-Identifier: Apache-2.0
//! `bin/auditd` -- the audit log's reader and writer, RFC 0101 step 2.
//!
//! It holds the audit ring **read-only**, the ring's tail read-write, one page
//! of its own to write from, and -- where the machine has a kept disk -- a
//! writable directory, `/audit`, and nothing else. It drains the ring in the
//! kernel's order, chains every record to the one before it with
//! `bhaskix-auditlog`, and appends the chained entries to a file named for the
//! boot. Where there is no kept disk it keeps the chain's head in memory, and
//! its report says the log is not persisted.
//!
//! **What it is trusted for, stated rather than discovered** (RFC 0101's
//! security implications): from the moment it is compromised it can withhold
//! or invent records. What it cannot do is make the kernel act unrecorded --
//! the kernel refuses, or counts a gap -- or edit a record already kept
//! without breaking the chain at that record.

#![no_std]
#![no_main]

use bhaskix_abi::{Chunk, dir, method, status, syscall};
use bhaskix_auditlog::{Chain, ENTRY_BYTES};
use bhaskix_telemetry::audit::{self, Kind, RECORD_BYTES, Record};
use bhaskix_telemetry::ring;

/// Slot: this program's report page, read by the kernel.
const REPORT: u64 = 1;
/// Slot: the wake this program arms deadlines on between passes.
const WAKE: u64 = 2;
/// Slot: the ring's tail page -- the one word this program may write there.
const TAIL: u64 = 7;
/// Slot: the audit ring, read-only.
const RING: u64 = 8;
/// Slot: one page of this program's own, which `dir::WRITE_FROM` drains.
const TRANSFER: u64 = 9;
/// Slot: the writable `/audit` directory, granted only on a kept disk.
const DIRECTORY: u64 = 10;
/// Slot: where the boot's file handle lands when it is created.
const FILE: u64 = 11;

const REPORT_AT: u64 = 0x2400_0000;
const TAIL_AT: u64 = 0x2410_0000;
const RING_AT: u64 = 0x2420_0000;
const TRANSFER_AT: u64 = 0x2440_0000;

/// Bytes the ring spans: the kernel's nine pages.
const RING_REGION: usize = 9 * 4096;
/// Bytes one write may carry, and one block holds: 32 entries.
const BLOCK: usize = 4096;
/// Entries in one block.
const PER_BLOCK: u64 = (BLOCK / ENTRY_BYTES) as u64;

/// First eight bytes of the report: `b"AUDITD01"`.
const MARKER: u64 = u64::from_le_bytes(*b"AUDITD01");

/// Report words. The kernel reads them by these indices.
mod word {
    pub const MARKER: usize = 0;
    /// 1 once draining, or why it stopped (see `Stopped`).
    pub const STATE: usize = 1;
    pub const RECORDS: usize = 2;
    /// Four words: the chain's head.
    pub const HEAD: usize = 3;
    /// 0 not persisted (no directory), 1 persisting, 2 the file would not be
    /// created, 3 a write was refused.
    pub const PERSISTED: usize = 7;
    pub const BYTES_KEPT: usize = 8;
    pub const GAPS: usize = 9;
    pub const BOOT: usize = 10;
    pub const PASSES: usize = 12;
    /// Records whose sequence was not the next one: the ring's order broken.
    pub const OUT_OF_ORDER: usize = 13;
    pub const BEFORE: usize = 14;
}

/// Why it stopped before draining, in [`word::STATE`].
mod stopped {
    pub const TAIL: u64 = 2;
    pub const RING: u64 = 3;
    pub const RING_REFUSED: u64 = 4;
    pub const TRANSFER: u64 = 5;
    /// Running and told not to drain: the fail-closed lane's stall.
    pub const STALLED: u64 = 6;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately: stopping where the
    // kernel can see it beats reporting numbers from an unknown state.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Issues one system call, and returns `(status, value)`.
fn call(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> (u64, [u64; 4]) {
    let status: u64;
    let mut a0 = args[0];
    let mut a1 = args[1];
    let mut a2 = args[2];
    let mut a3 = args[3];
    // SAFETY: the system call convention from RFC 0008. Nothing is
    // dereferenced on this side, and every argument register is declared as
    // an output because the kernel writes the whole frame back.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") kind => status,
            inlateout("rdi") capability => _,
            inlateout("rsi") method => _,
            inlateout("rdx") a0,
            inlateout("r10") a1,
            inlateout("r8") a2,
            inlateout("r9") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, [a0, a1, a2, a3])
}

/// A call to the filesystem service, retried while its queue is full:
/// `CONGESTED` means the message was never queued, so sending it again cannot
/// repeat a write. Bounded, as the shell's is.
fn ipc(capability: u64, method: u64, args: [u64; 4]) -> (u64, [u64; 4]) {
    let mut attempts = 0;
    loop {
        let reply = call(syscall::CALL, capability, method, args);
        if reply.0 != status::CONGESTED || attempts >= 128 {
            return reply;
        }
        attempts += 1;
        call(syscall::YIELD, 0, 0, [0; 4]);
    }
}

fn exit() -> ! {
    call(syscall::EXIT, 0, 0, [0; 4]);
    #[allow(clippy::empty_loop)]
    loop {}
}

fn report_word(index: usize, value: u64) {
    // SAFETY: the report page is slot 1, mapped read-write at `REPORT_AT`
    // before anything is reported; every index used is below 512.
    unsafe { core::ptr::write_volatile((REPORT_AT + (index as u64) * 8) as *mut u64, value) }
}

fn word_at(address: u64) -> u64 {
    // SAFETY: every caller passes an address inside a region `ATTACH`
    // accepted for this program -- the ring or the tail page -- bounded by
    // `bhaskix_telemetry`'s layout arithmetic.
    unsafe { core::ptr::read_volatile(address as *const u64) }
}

fn rdtsc() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: `rdtsc` reads the counter and touches nothing else.
    unsafe {
        core::arch::asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack));
    }
    u64::from(high) << 32 | u64::from(low)
}

/// The boot's file, and where the next entry goes in it.
struct Kept {
    /// Entries written so far.
    entries: u64,
    /// The state word: see [`word::PERSISTED`].
    state: u64,
}

impl Kept {
    /// Creates the boot's file, named by the first half of the boot's
    /// identity in hexadecimal: sixteen bytes, the directory's limit.
    fn create(boot: u64) -> Self {
        let mut name = [0u8; 16];
        for (index, byte) in name.iter_mut().enumerate() {
            let nibble = (boot >> (60 - 4 * index)) & 0xF;
            *byte = b"0123456789abcdef"[nibble as usize];
        }
        let (chunk, _) = Chunk::take(&name);
        let _ = call(syscall::INVOKE, FILE, method::DELETE, [0; 4]);
        let declared = call(syscall::INVOKE, DIRECTORY, method::EXPECT, [FILE, 0, 0, 0]);
        let created = ipc(DIRECTORY, dir::CREATE_AT, chunk.pack(0));
        let state =
            if declared.0 == status::OK && created.0 == status::OK && created.1[0] == dir::OK {
                1
            } else {
                2
            };
        Self { entries: 0, state }
    }

    /// Places one entry in the transfer page, and writes the block when it
    /// is full.
    fn push(&mut self, bytes: &[u8; ENTRY_BYTES]) {
        if self.state != 1 {
            return;
        }
        let at = (self.entries % PER_BLOCK) as usize * ENTRY_BYTES;
        // SAFETY: the transfer page is slot 9, mapped read-write at
        // `TRANSFER_AT`; `at + ENTRY_BYTES` is at most `BLOCK`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (TRANSFER_AT as usize + at) as *mut u8,
                ENTRY_BYTES,
            );
        }
        self.entries += 1;
        if self.entries.is_multiple_of(PER_BLOCK) {
            self.write(PER_BLOCK);
        }
    }

    /// Writes the block being filled, from its start: `count` entries. A
    /// partial block is rewritten whole each pass until it fills, so what is
    /// on the disk is always a whole number of entries.
    fn write(&mut self, count: u64) {
        let start = (self.entries - 1) / PER_BLOCK * PER_BLOCK;
        let length = count * ENTRY_BYTES as u64;
        let offset = start * ENTRY_BYTES as u64;
        let wrote = ipc(FILE, dir::WRITE_FROM, [TRANSFER, length, offset, 0]);
        if wrote.0 != status::OK || wrote.1[0] != dir::OK {
            self.state = 3;
        }
    }

    /// The pass ended: the partial block, if it holds anything new.
    fn flush(&mut self) {
        let partial = self.entries % PER_BLOCK;
        if self.state == 1 && partial != 0 {
            self.write(partial);
        }
    }

    fn bytes(&self) -> u64 {
        self.entries * ENTRY_BYTES as u64
    }
}

#[unsafe(no_mangle)]
extern "C" fn auditd_main(hertz: u64, flags: u64) -> ! {
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
    report_word(word::MARKER, MARKER);
    report_word(word::STATE, 0);

    if call(syscall::INVOKE, TAIL, method::ATTACH, [TAIL_AT, 1, 0, 0]).0 != status::OK {
        report_word(word::STATE, stopped::TAIL);
        exit();
    }
    // Read-only, and the grant enforces it.
    if call(syscall::INVOKE, RING, method::ATTACH, [RING_AT, 0, 0, 0]).0 != status::OK {
        report_word(word::STATE, stopped::RING);
        exit();
    }
    let Some(layout) = ring::Layout::for_region(RING_REGION) else {
        report_word(word::STATE, stopped::RING_REFUSED);
        exit();
    };
    if word_at(RING_AT + audit::MARKER_OFFSET as u64) != audit::MARKER
        || word_at(RING_AT + audit::SLOTS_OFFSET as u64) != layout.slots()
    {
        report_word(word::STATE, stopped::RING_REFUSED);
        exit();
    }
    if call(
        syscall::INVOKE,
        TRANSFER,
        method::ATTACH,
        [TRANSFER_AT, 1, 0, 0],
    )
    .0 != status::OK
    {
        report_word(word::STATE, stopped::TRANSFER);
        exit();
    }
    let persist = flags & 1 != 0;
    let stall = flags & 2 != 0;

    let mut chain = Chain::new();
    let mut kept: Option<Kept> = None;
    let mut gaps = 0u64;
    let mut passes = 0u64;
    let mut out_of_order = 0u64;
    report_word(word::STATE, if stall { stopped::STALLED } else { 1 });

    loop {
        if !stall {
            let head = word_at(RING_AT + audit::HEAD_OFFSET as u64);
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            let tail = word_at(TAIL_AT);
            let readable = ring::readable(head, tail, layout.slots());
            for sequence in tail..tail + readable {
                let slot = RING_AT + layout.slot_offset(sequence) as u64;
                let mut bytes = [0u8; RECORD_BYTES];
                for (index, chunk) in bytes.as_chunks_mut::<8>().0.iter_mut().enumerate() {
                    *chunk = word_at(slot + index as u64 * 8).to_le_bytes();
                }
                let record = Record::from_bytes(&bytes);
                if record.sequence != chain.records() {
                    out_of_order += 1;
                }
                if record.kind == Kind::Attach as u8 {
                    report_word(word::BOOT, record.subject);
                    report_word(word::BOOT + 1, record.source);
                    report_word(word::BEFORE, u64::from(record.count));
                    if persist && kept.is_none() {
                        kept = Some(Kept::create(record.subject));
                    }
                } else if record.kind == Kind::Gap as u8 {
                    gaps += u64::from(record.count);
                }
                let entry = chain.append(&bytes);
                if let Some(kept) = kept.as_mut() {
                    kept.push(&entry.to_bytes());
                }
            }
            if readable > 0 {
                if let Some(kept) = kept.as_mut() {
                    kept.flush();
                }
                // SAFETY: this program's own tail word, mapped read-write.
                unsafe { core::ptr::write_volatile(TAIL_AT as *mut u64, tail + readable) };
            }
        }
        passes += 1;
        report_word(word::RECORDS, chain.records());
        for (index, chunk) in chain.head().as_chunks::<8>().0.iter().enumerate() {
            report_word(word::HEAD + index, u64::from_le_bytes(*chunk));
        }
        report_word(word::PERSISTED, kept.as_ref().map_or(0, |kept| kept.state));
        report_word(word::BYTES_KEPT, kept.as_ref().map_or(0, Kept::bytes));
        report_word(word::GAPS, gaps);
        report_word(word::PASSES, passes);
        report_word(word::OUT_OF_ORDER, out_of_order);

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
    call auditd_main
    ud2
"#
);
