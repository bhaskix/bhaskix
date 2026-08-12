// SPDX-License-Identifier: Apache-2.0
//! The protocol service, in a domain with no device.
//!
//! [RFC 0018](../../../docs/rfc/0018-networking.md) step 3. It takes frames
//! from `bin/netd` through a shared ring and, for now, counts them. ARP and
//! IPv4 are step 4; keeping them out is what makes this step a test of the
//! *ring* rather than of a ring and a parser at once.
//!
//! # What it does not hold, which is the whole argument
//!
//! No device. No DMA window. No interrupt. No configuration space. Two
//! capabilities: the ring it reads and a page it writes findings into.
//!
//! That asymmetry is why RFC 0018 splits the stack across two domains. Every
//! byte this program will eventually parse arrives from whoever can reach the
//! wire, continuously, at line rate — and a parser bug here cannot be turned
//! into a device pointed anywhere, because there is no device within reach.
//!
//! # The ring is `abi::ring`, and this is its first caller
//!
//! That module was written for RFC 0009 step 5 and had no user until now. Its
//! shape carries a rule worth restating: **copy out, validate the copy, use the
//! copy.** `Cursor` is built from numbers rather than from the region, so a
//! reader physically cannot validate one value and then use a different one
//! that the writer changed in between. The producer is another domain and can
//! write whatever it likes into the header; nothing here may be trusted twice.
#![no_std]
#![no_main]

use bhaskix_abi::{method, ring, status, syscall};

/// Slot: the ring `bin/netd` writes frames into.
const RING: u64 = 0;
/// Slot: the page this program leaves its findings in.
const REPORT: u64 = 1;

/// Where this program maps what it holds.
const RING_AT: u64 = 0x2100_0000;
const REPORT_AT: u64 = 0x2110_0000;

/// Bytes in the ring, matching what the kernel granted.
const RING_BYTES: usize = 16 * 4096;

/// The largest frame this program will take out of the ring.
///
/// A length is a number the *other side* wrote, so it is bounded here before
/// it is used for anything. Without this a producer could name a length that
/// reached past the ring, and the bound is what makes that a refusal rather
/// than a read of whatever follows.
const MAX_FRAME: usize = 2048;

/// The marker the kernel looks for before believing the report.
const MARKER: u64 = 0x3154_5052_4450_4931;

/// There is nothing to unwind and nowhere to print to.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. Stopping where the kernel
    // can see it beats carrying on with a ring in an unknown state.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Issues one system call, and returns `(status, value)`.
fn call(kind: u64, capability: u64, method: u64, args: [u64; 4]) -> (u64, u64) {
    let status: u64;
    let mut value = args[0];
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

/// Copies `length` bytes out of the ring at free-running `tail` into `into`.
///
/// # Safety
///
/// The ring must be mapped at [`RING_AT`] and `into` writable for `length`.
unsafe fn ring_copy_out(
    layout: ring::Layout,
    cursor: ring::Cursor,
    into: *mut u8,
    length: usize,
) -> bool {
    if cursor.readable() < length {
        return false;
    }
    let (first, second) = ring::read_runs(layout, cursor, length);
    if first.length + second.length != length {
        return false;
    }
    // SAFETY: both runs are offsets `abi::ring` computed inside the region this
    // program mapped, `into` is writable for `length` by the caller's
    // obligation, and the two runs are the halves one transfer wraps into.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (RING_AT + first.offset as u64) as *const u8,
            into,
            first.length,
        );
        if !second.is_empty() {
            core::ptr::copy_nonoverlapping(
                (RING_AT + second.offset as u64) as *const u8,
                into.add(first.length),
                second.length,
            );
        }
    }
    true
}

/// The entry point.
#[unsafe(no_mangle)]
extern "C" fn ipd_main() -> ! {
    if !attach(RING, RING_AT, 1) || !attach(REPORT, REPORT_AT, 1) {
        exit()
    }
    let Some(layout) = ring::Layout::for_region(RING_BYTES) else {
        exit()
    };

    let mut frames = 0u64;
    let mut bytes = 0u64;
    let mut first_source = 0u64;
    let mut refused = 0u64;
    let mut buffer = [0u8; MAX_FRAME];
    // Only this program advances the tail, so it is kept here and written out
    // rather than read back. A consumer that re-read its own index would be
    // trusting the producer with it.
    let mut tail = 0u64;

    // A report before anything has arrived, so that "this program never ran"
    // and "this program ran and saw nothing" are different findings. Without
    // it the kernel reads an absent marker for both, and the two have entirely
    // different causes.
    report(0, 0, 0, 0);

    // No wakeup, and this is a gap rather than a choice. RFC 0018 step 3 asked
    // for a notification here; RFC 0010's notifications can only be signalled
    // by the *kernel* -- a program holding one may `WAIT` and `PEEK` and there
    // is no method that signals -- so a domain cannot wake another domain
    // today. Polling with a yield between looks is what is available, and the
    // missing half is recorded in TRACKER rather than invented here.
    loop {
        // SAFETY: the ring's header, in the region this program mapped. Read
        // volatile because the producer is another domain and takes no lock.
        let head =
            unsafe { core::ptr::read_volatile((RING_AT + ring::HEAD_OFFSET as u64) as *const u64) };

        // Copied out, then validated, then used. `Cursor::new` refuses a pair
        // that cannot be true -- a head behind the tail, or a gap wider than
        // the ring -- which is the one thing standing between a hostile
        // producer and this program reading its own memory as a frame.
        let Some(cursor) = ring::Cursor::new(layout, head, tail) else {
            refused += 1;
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        };
        if cursor.is_empty() {
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        }

        // The four-byte length first.
        let mut prefix = [0u8; 4];
        // SAFETY: the ring is mapped and `prefix` is four writable bytes.
        if !unsafe { ring_copy_out(layout, cursor, prefix.as_mut_ptr(), 4) } {
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        }
        let length = u32::from_le_bytes(prefix) as usize;
        // A number the other side chose. Bounded before it is used, and a
        // refusal rather than a clamp: a frame that does not fit is not a
        // shorter frame, it is a producer this program has stopped believing.
        if length == 0 || length > MAX_FRAME {
            refused += 1;
            tail = tail.wrapping_add(4);
            publish(tail);
            continue;
        }

        let Some(after_prefix) = ring::Cursor::new(layout, head, tail + 4) else {
            refused += 1;
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        };
        // SAFETY: the ring is mapped and `buffer` is `MAX_FRAME` writable
        // bytes, which `length` is bounded by above.
        if !unsafe { ring_copy_out(layout, after_prefix, buffer.as_mut_ptr(), length) } {
            // The producer has published a length but not yet the bytes. Not
            // an error and not a refusal: look again without moving the tail.
            call(syscall::YIELD, 0, 0, [0; 4]);
            continue;
        }

        frames += 1;
        bytes += length as u64;
        if first_source == 0 && length >= 12 {
            // The source address, six bytes in. Reported rather than parsed:
            // this program has no idea what an Ethernet header means, and the
            // number exists so the kernel can check that the *same* frame
            // crossed two domain boundaries rather than that a counter moved.
            let mut value = 0u64;
            for octet in &buffer[6..12] {
                value = (value << 8) | u64::from(*octet);
            }
            first_source = value;
        }

        tail = tail.wrapping_add(4 + length as u64);
        publish(tail);
        report(frames, bytes, first_source, refused);
    }
}

/// Tells the producer how far this program has read.
fn publish(tail: u64) {
    // The bytes are finished with before the index that frees them is written,
    // which is the mirror of the producer's fence: a producer that saw the new
    // tail first could overwrite a frame still being read.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the ring's header, which only this program writes.
    unsafe {
        core::ptr::write_volatile((RING_AT + ring::TAIL_OFFSET as u64) as *mut u64, tail);
    }
}

/// Leaves the findings where the kernel granted memory for them.
fn report(frames: u64, bytes: u64, first_source: u64, refused: u64) {
    let words = [MARKER, frames, bytes, first_source, refused];
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

core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    xor rbp, rbp
    and rsp, -16
    call ipd_main
    ud2
"#
);
