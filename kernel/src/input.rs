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

/// Longest line the editor will accept.
///
/// A line that reaches this stops accepting rather than wrapping or
/// truncating silently: the shell has no scrollback and a command the operator
/// cannot see the end of is worse than one that refuses to grow.
pub const MAX_LINE: usize = 128;

/// What a byte did to the line being edited.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Edit {
    /// Nothing. A control character with no meaning here, or a full line.
    Ignored,
    /// The byte was appended, and should be echoed.
    Inserted(u8),
    /// The last byte was removed.
    Erased,
    /// The line is finished.
    Complete,
    /// The operator abandoned the line.
    Cancelled,
}

/// A line being typed.
///
/// Separate from the reading above so that it is a pure state machine over
/// bytes: the interesting behaviour — backspace at the start of a line, a line
/// that grows too long, `\r\n` arriving as two bytes — is then testable on the
/// host without a UART, an interrupt, or a machine.
pub struct LineEditor {
    buffer: [u8; MAX_LINE],
    length: usize,
    /// Set after `\r`, so the `\n` that follows it does not end a second,
    /// empty line. Terminals send both and mean one.
    swallow_newline: bool,
}

impl Default for LineEditor {
    fn default() -> Self {
        Self::new()
    }
}

impl LineEditor {
    /// An empty line.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buffer: [0; MAX_LINE],
            length: 0,
            swallow_newline: false,
        }
    }

    /// The bytes typed so far.
    #[must_use]
    pub fn line(&self) -> &[u8] {
        &self.buffer[..self.length]
    }

    /// Discards the line.
    pub const fn clear(&mut self) {
        self.length = 0;
    }

    /// Feeds one byte in.
    pub fn accept(&mut self, byte: u8) -> Edit {
        let swallow = self.swallow_newline;
        self.swallow_newline = byte == b'\r';

        match byte {
            b'\n' if swallow => Edit::Ignored,
            b'\r' | b'\n' => Edit::Complete,
            // Backspace and delete. Terminals disagree about which they send,
            // and a shell that honoured only one is a shell where the
            // operator's mistakes are permanent.
            0x08 | 0x7f => {
                if self.length == 0 {
                    Edit::Ignored
                } else {
                    self.length -= 1;
                    Edit::Erased
                }
            }
            // Ctrl-C: abandon the line.
            0x03 => {
                self.length = 0;
                Edit::Cancelled
            }
            // Ctrl-U: erase it, silently.
            0x15 => {
                self.length = 0;
                Edit::Ignored
            }
            // Printable ASCII only. Anything else -- an escape sequence from
            // an arrow key, a stray high byte from a mismatched baud rate --
            // is dropped rather than inserted, because a command line
            // containing a byte the operator cannot see is a command they did
            // not mean to type.
            0x20..=0x7e => {
                if self.length == MAX_LINE {
                    Edit::Ignored
                } else {
                    self.buffer[self.length] = byte;
                    self.length += 1;
                    Edit::Inserted(byte)
                }
            }
            _ => Edit::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_in(editor: &mut LineEditor, text: &[u8]) -> Edit {
        let mut last = Edit::Ignored;
        for byte in text {
            last = editor.accept(*byte);
        }
        last
    }

    #[test]
    fn a_line_is_complete_at_a_carriage_return_or_a_newline() {
        let mut editor = LineEditor::new();
        assert_eq!(type_in(&mut editor, b"ls /etc\r"), Edit::Complete);
        assert_eq!(editor.line(), b"ls /etc");

        editor.clear();
        assert_eq!(type_in(&mut editor, b"cat\n"), Edit::Complete);
        assert_eq!(editor.line(), b"cat");
    }

    #[test]
    fn a_carriage_return_and_newline_together_end_one_line_not_two() {
        // Terminals send both. A shell that treated them as two lines would
        // print a second prompt for every command, and run an empty line
        // between every pair of real ones.
        let mut editor = LineEditor::new();
        assert_eq!(type_in(&mut editor, b"help\r"), Edit::Complete);
        editor.clear();
        assert_eq!(editor.accept(b'\n'), Edit::Ignored);
    }

    #[test]
    fn a_newline_alone_still_ends_a_line_after_an_earlier_one() {
        // The swallow must not persist: `\r` then a typed character then `\n`
        // is two lines' worth of input, and the second must end.
        let mut editor = LineEditor::new();
        assert_eq!(type_in(&mut editor, b"a\r"), Edit::Complete);
        editor.clear();
        assert_eq!(type_in(&mut editor, b"b\n"), Edit::Complete);
        assert_eq!(editor.line(), b"b");
    }

    #[test]
    fn backspace_and_delete_both_erase_and_neither_underflows() {
        let mut editor = LineEditor::new();
        assert_eq!(editor.accept(0x08), Edit::Ignored, "nothing to erase");
        assert_eq!(editor.accept(0x7f), Edit::Ignored);
        assert_eq!(editor.line(), b"");

        type_in(&mut editor, b"lst");
        assert_eq!(editor.accept(0x08), Edit::Erased);
        assert_eq!(editor.line(), b"ls");
        assert_eq!(editor.accept(0x7f), Edit::Erased);
        assert_eq!(editor.line(), b"l");
    }

    #[test]
    fn a_line_that_grows_too_long_stops_accepting_rather_than_overflowing() {
        let mut editor = LineEditor::new();
        for _ in 0..MAX_LINE {
            assert_eq!(editor.accept(b'x'), Edit::Inserted(b'x'));
        }
        assert_eq!(editor.line().len(), MAX_LINE);
        assert_eq!(editor.accept(b'x'), Edit::Ignored, "no room, and no panic");
        assert_eq!(editor.line().len(), MAX_LINE);
        // And it is still editable afterwards.
        assert_eq!(editor.accept(0x08), Edit::Erased);
        assert_eq!(editor.accept(b'y'), Edit::Inserted(b'y'));
    }

    #[test]
    fn control_c_abandons_the_line_and_control_u_erases_it() {
        let mut editor = LineEditor::new();
        type_in(&mut editor, b"rm -rf");
        assert_eq!(editor.accept(0x03), Edit::Cancelled);
        assert_eq!(editor.line(), b"");

        type_in(&mut editor, b"cat x");
        assert_eq!(editor.accept(0x15), Edit::Ignored);
        assert_eq!(editor.line(), b"");
    }

    #[test]
    fn bytes_that_cannot_be_seen_are_not_inserted() {
        // An arrow key is an escape sequence; a mismatched baud rate produces
        // high bytes. Either would otherwise become part of a command the
        // operator did not type and cannot see.
        let mut editor = LineEditor::new();
        for byte in [0x1b, b'[', b'A'] {
            let _ = editor.accept(byte);
        }
        assert_eq!(editor.line(), b"[A", "the escape itself is dropped");

        editor.clear();
        for byte in [0x00, 0x1f, 0x80, 0xff] {
            assert_eq!(editor.accept(byte), Edit::Ignored);
        }
        assert_eq!(editor.line(), b"");
    }
}
