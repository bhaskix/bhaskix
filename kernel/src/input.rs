// SPDX-License-Identifier: Apache-2.0
//! Console input: the path from a UART with a byte to a thread that wants one.
//!
//! Until M6-04 the console could only write. Nothing was wired to notice an
//! inbound byte — the local APIC delivers the timer and messages between CPUs,
//! and a device interrupt needs an I/O APIC, which the kernel had never
//! programmed. `bhaskix_arch::ioapic` is the other half of this module.
//!
//! # The ring is lock-free on purpose
//!
//! One producer (the interrupt handler) and one consumer (whichever thread is
//! reading). A lock would be the obvious choice and the wrong one: the handler
//! can interrupt the consumer *between* its acquire and release, and would
//! then wait for a lock held by a thread that cannot run until the handler
//! returns. Disjoint indices make that impossible rather than unlikely.
//!
//! # One reader
//!
//! [`read`] records the calling thread as *the* reader, so a second caller
//! would displace the first and leave it asleep with nobody to wake it. There
//! is one console and one shell, so that is a description rather than a
//! limitation — but it is a real one, and a second reader needs a list here
//! before it needs anything else.
//!
//! # Why the reader and the interrupt share a CPU
//!
//! The serial interrupt is routed to the bootstrap CPU and the shell is pinned
//! there. That pairing is what makes the wake-up argument below hold, and it
//! is a requirement rather than a convenience — [`install`] says so, and
//! `shell::start` is the only caller.
//!
//! # Why no wakeup can be lost
//!
//! The reader marks itself blocked *before* it looks at the ring, which is the
//! rule M4-09 established and M5-05 had to relearn. Then:
//!
//! - A byte pushed before the reader looks is found by the look, and the
//!   reader cancels its own block.
//! - A byte pushed after the look arrives when the reader holds no runqueue
//!   lock, so the handler's `try_lock` wake succeeds.
//! - A byte pushed while the reader is inside `block_self` cannot happen on
//!   this CPU: `block_self` masks interrupts for exactly that reason.
//!
//! The remaining case — the handler interrupting the reader *inside*
//! `mark_blocked`, where the runqueue lock is held — loses the wake and is
//! caught by the recheck: the reader's look happens after `mark_blocked`
//! returns, so it sees the byte.

use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use bhaskix_arch::SerialPort;

/// Vector the serial interrupt is delivered on.
///
/// Above the exceptions, clear of the timer (`0x20`), the reschedule IPI
/// (`0x41`) and the shootdown IPI. The number itself does not matter; that it
/// is written down in one place does.
pub const SERIAL_VECTOR: u8 = 0x42;

/// The legacy ISA interrupt a PC's first serial port raises.
pub const SERIAL_IRQ: u8 = 4;

/// Bytes the ring holds.
///
/// A power of two so the index arithmetic is a mask. 256 is far more than a
/// human types between reads and more than the UART's own sixteen-byte FIFO,
/// so an overrun means the reader has stopped, not that it was slow.
const CAPACITY: usize = 256;

/// The bytes themselves.
static RING: [AtomicU8; CAPACITY] = [const { AtomicU8::new(0) }; CAPACITY];
/// Written by the producer only.
static HEAD: AtomicUsize = AtomicUsize::new(0);
/// Written by the consumer only.
static TAIL: AtomicUsize = AtomicUsize::new(0);

/// Bytes that arrived.
static RECEIVED: AtomicU64 = AtomicU64::new(0);
/// Bytes dropped because the ring was full.
static DROPPED: AtomicU64 = AtomicU64::new(0);
/// Times the handler ran.
static INTERRUPTS: AtomicU64 = AtomicU64::new(0);

/// The thread to wake when a byte arrives, or zero.
static READER: AtomicU32 = AtomicU32::new(0);

/// I/O port of the UART the handler drains, or zero if there is none.
///
/// A port number rather than a `SerialPort`, so the handler can read it with
/// one atomic load and no lock. The type is a thin wrapper over exactly this
/// number, so nothing is lost by rebuilding it per interrupt.
static PORT_BASE: AtomicU16 = AtomicU16::new(0);

/// Names the port console input arrives on, and asks it to interrupt.
///
/// # Safety
///
/// Must be called once, during boot, with the base of a UART whose `init`
/// succeeded. The caller must also route [`SERIAL_IRQ`] to [`SERIAL_VECTOR`]
/// on the bootstrap CPU and pin every reader there — see the module header.
pub unsafe fn install(base: u16) {
    PORT_BASE.store(base, Ordering::Release);
    // SAFETY: the caller guarantees the port is initialised. From here the
    // UART raises its line, which is why routing is the caller's job and is
    // done before this.
    unsafe { SerialPort::new(base).enable_receive_interrupt() };
}

/// Services the serial interrupt.
///
/// Drains the whole FIFO. Stopping after one byte would leave the rest behind
/// an interrupt that has already been acknowledged and will not be raised
/// again for bytes already in the buffer — a console that loses everything a
/// person types faster than one character per interrupt.
pub fn on_interrupt() {
    INTERRUPTS.fetch_add(1, Ordering::Relaxed);

    let base = PORT_BASE.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    let port = SerialPort::new(base);

    // SAFETY: `install` stored a port whose `init` succeeded, and reading is
    // the documented way to clear the condition that raised this interrupt.
    while let Some(byte) = unsafe { port.read_byte() } {
        push(byte);
    }

    // The wake is last, after every byte is visible. A reader woken before the
    // bytes were published would look, find nothing, and sleep again.
    let reader = READER.load(Ordering::Acquire);
    if reader != 0 {
        crate::sched::wake_from_interrupt(reader);
    }
}

/// Adds a byte, dropping it if there is no room.
///
/// Dropping the newest rather than overwriting the oldest: a full ring means
/// nobody is reading, and in that case the first thing typed is more likely to
/// be what someone wants than the last.
fn push(byte: u8) {
    let head = HEAD.load(Ordering::Relaxed);
    let tail = TAIL.load(Ordering::Acquire);
    if head.wrapping_sub(tail) >= CAPACITY {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    RING[head % CAPACITY].store(byte, Ordering::Relaxed);
    // Release, so the byte is visible before the index that publishes it.
    HEAD.store(head.wrapping_add(1), Ordering::Release);
    RECEIVED.fetch_add(1, Ordering::Relaxed);
}

/// Takes a byte if one is waiting.
#[must_use]
pub fn try_read() -> Option<u8> {
    let tail = TAIL.load(Ordering::Relaxed);
    if HEAD.load(Ordering::Acquire) == tail {
        return None;
    }
    let byte = RING[tail % CAPACITY].load(Ordering::Relaxed);
    TAIL.store(tail.wrapping_add(1), Ordering::Release);
    Some(byte)
}

/// Whether anything is waiting to be read.
#[must_use]
pub fn pending() -> bool {
    HEAD.load(Ordering::Acquire) != TAIL.load(Ordering::Relaxed)
}

/// Waits for a byte.
///
/// Blocks rather than polls: a shell spinning on an empty ring would keep a
/// CPU out of idle for as long as nobody typed, which is most of the time, and
/// would undo M4-10's tickless idle single-handedly.
pub fn read() -> u8 {
    // Claim the wake before the first look, not after: a byte arriving in
    // between would otherwise find no reader recorded and wake nobody.
    if let Some(id) = crate::sched::current_thread_id() {
        READER.store(id, Ordering::Release);
    }

    loop {
        // Mark blocked first, look second. See the module header.
        crate::sched::mark_blocked();
        if let Some(byte) = try_read() {
            crate::sched::cancel_block();
            return byte;
        }
        crate::sched::block_self();
    }
}

/// How much has arrived, been dropped, and how many interrupts delivered it.
#[must_use]
pub fn statistics() -> (u64, u64, u64) {
    (
        RECEIVED.load(Ordering::Relaxed),
        DROPPED.load(Ordering::Relaxed),
        INTERRUPTS.load(Ordering::Relaxed),
    )
}

/// Line editing, shared with the user-mode shell.
///
/// Re-exported rather than defined here since M6-05: both shells edit lines,
/// and two implementations of backspace would disagree the first time either
/// was touched. The definition lives in `bhaskix_abi`, which is compiled into
/// the kernel and into unprivileged programs alike.
pub use bhaskix_abi::{Edit, LineEditor, MAX_LINE};
