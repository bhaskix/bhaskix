// SPDX-License-Identifier: Apache-2.0
//! The interface between Bhaskix and the programs that run on it.
//!
//! Everything here is compiled into the kernel *and* into unprivileged
//! programs. That is the whole reason it exists: a protocol written down twice
//! is a protocol whose two halves disagree the first time either is edited,
//! and the disagreement shows up as a message that means something slightly
//! different on each side rather than as a build failure.
//!
//! # What may live here
//!
//! Constants, arithmetic on message registers, and pure state machines. No
//! pointers, no `unsafe`, no allocation — the `unsafe` budget for this crate
//! is zero and is meant to stay there. Code here is trusted by the kernel and
//! *supplied to* untrusted programs, so anything with an obligation attached
//! would owe it on both sides of the privilege boundary at once.
//!
//! # Why messages carry bytes in registers
//!
//! [RFC 0008](../../docs/rfc/0008-syscall-and-ipc-shape.md) fixes a message at
//! four machine words. A shell has to move more than that — a path, a line of
//! text, a directory listing — so [`Chunk`] packs sixteen bytes into two of
//! them and says whether more follows.
//!
//! Sixteen bytes per round trip is slow, and deliberately so for now: the
//! alternative is shared memory, which means a page granted across a domain
//! boundary and a whole capability type to describe it. That is a design
//! decision with an RFC's worth of consequences, and this milestone does not
//! need it. What it buys in the meantime is worth stating: **no pointer ever
//! crosses the boundary.** The kernel never dereferences a user address on
//! behalf of a caller, so the entire class of confused-deputy bugs that
//! `copy_from_user` exists to contain cannot occur here.

#![no_std]
// Tests are exempt from the `unwrap`/`expect`/`panic` bans, as
// docs/coding-style.md §4 specifies: those bans exist to stop a fallible
// operation taking down the nucleus, and a test that cannot panic cannot
// fail. Deliberately *not* exempting `undocumented_unsafe_blocks`, which the
// other crates do — there is no `unsafe` in this crate and its budget is zero,
// so an exemption here would be permission for something that must not appear.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod ring;

/// The six system calls. See `docs/rfc/0008-syscall-and-ipc-shape.md`.
///
/// The kernel keeps its own `Kind` enum whose discriminants are checked
/// against these at compile time. Two definitions with a static assertion
/// between them is not duplication — it is the assertion that makes the
/// duplication safe, and it fails the build rather than a message.
pub mod syscall {
    /// Perform a method on the object a capability names.
    pub const INVOKE: u64 = 0;
    /// Invoke, then block for a reply.
    pub const CALL: u64 = 1;
    /// Answer a `Call`, consuming the reply capability.
    ///
    /// All four argument registers are the reply. Nothing says *who* to
    /// answer: the kernel remembers the caller this thread received from and
    /// has not yet answered, and refuses a reply to anyone else. A server that
    /// could name its own reply target could plant a message in a thread it
    /// never heard from and wake it holding an answer to a question it did not
    /// ask. The badge is not settable either — a server that could stamp an
    /// identity on its answer would defeat every caller that checks one.
    pub const REPLY: u64 = 2;
    /// Block until a message arrives on an endpoint.
    ///
    /// Returns the method and all four argument registers as they were sent,
    /// and the badge in the capability register. Four arguments, and not one,
    /// because a message *is* four registers: a server that received fewer
    /// could not implement the protocols this system already has, which made
    /// "the same service in either placement" false at the boundary rather
    /// than in the service.
    ///
    /// The caller is not returned, because [`REPLY`] does not accept one.
    pub const RECV: u64 = 3;
    /// Give up the rest of this thread's slice.
    pub const YIELD: u64 = 4;
    /// Terminate this thread.
    pub const EXIT: u64 = 5;
}

/// Methods invoked on a capability, for the programs that need to name one.
///
/// Only the ones an unprivileged program uses are here. The kernel keeps the
/// full set and a static assertion between the two definitions, which is what
/// makes having two of them safe.
pub mod method {
    /// Write bytes into memory the caller of this endpoint named.
    ///
    /// Only on an `Endpoint` capability, and only from the thread answering a
    /// message taken from it. `arg0` = the *caller's* slot holding the
    /// `Memory` capability, `arg1` = the address of the bytes in this domain,
    /// `arg2` = how many.
    ///
    /// The bulk path a service gets when it runs in its own domain. Which
    /// caller is not an argument: it is the one being answered, and a service
    /// that could name it could write a file's contents into a third party's
    /// memory.
    pub const FILL: u64 = 38;

    /// Put one character on the console this capability names.
    ///
    /// Only on a `Console` capability. `arg0` = the character.
    pub const PUT: u64 = 39;
    /// Take a byte that was typed, waiting until there is one.
    ///
    /// Only on a `Console` capability, and it blocks: a holder waiting here is
    /// not answering anything else while it waits.
    pub const TAKE: u64 = 40;
    /// Take a byte only if one is already waiting.
    ///
    /// Returns the byte, or [`NOTHING`].
    pub const POLL: u64 = 41;
    /// What [`POLL`] returns when nobody has typed.
    ///
    /// Out of a byte's range on purpose, so "nothing" cannot be confused with
    /// a byte that was read.
    pub const NOTHING: u64 = 0x100;
}

/// What a system call returned in `rax`.
pub mod status {
    /// The call succeeded.
    pub const OK: u64 = 0;
    /// The capability index named nothing in this domain's CSpace.
    pub const NO_SUCH_CAPABILITY: u64 = 2;
    /// The capability was revoked, or its slot has been reused.
    pub const REVOKED: u64 = 3;
    /// The object does not answer that method.
    pub const NO_SUCH_METHOD: u64 = 10;
}

/// Methods the console service answers.
///
/// Raw bytes in both directions. The service does no line editing, because
/// line editing is a shell's job and a shell that could not do it would not be
/// one — it would be a program typing at a shell that lives in the kernel.
pub mod console {
    /// Write the chunk's bytes. Replies with how many were accepted.
    pub const WRITE: u64 = 1;
    /// Read whatever has been typed. Blocks until at least one byte has.
    pub const READ: u64 = 2;
}

/// Methods the filesystem service answers.
///
/// Stateful per caller, keyed by the badge on the capability used. A path is
/// accumulated across as many [`Chunk`]s as it takes, and the operation that
/// follows consumes it — so a caller cannot open a path it did not finish
/// sending, and the service never has to guess where a name ends.
pub mod fs {
    /// Append a chunk to this caller's path.
    pub const PATH: u64 = 1;
    /// Open the accumulated path. Replies with the size in `args[3]`.
    pub const OPEN: u64 = 2;
    /// Read the next bytes of the open file. A count of zero is end of file.
    pub const READ: u64 = 3;
    /// Begin listing the accumulated path, then return one entry per call.
    pub const LIST: u64 = 4;
    /// Read into a shared region instead of into registers.
    ///
    /// `arg0` = the caller's own capability slot holding a `Memory` object,
    /// `arg1` = how many bytes at most. Returns the number written.
    ///
    /// The register path stays for short transfers: RFC 0009 measured it at
    /// sixteen bytes a round trip, which is right for a path that reads a
    /// filename and wrong for one that reads a file.
    pub const READ_INTO: u64 = 6;

    // Two methods with one number is a service answering the wrong question,
    // and the compiler only noticed because one arm became unreachable. Said
    // here as an assertion so the next one fails the build instead.
    const _: () = {
        assert!(PATH != OPEN && PATH != READ && PATH != LIST && PATH != RESET && PATH != READ_INTO);
        assert!(OPEN != READ && OPEN != LIST && OPEN != RESET && OPEN != READ_INTO);
        assert!(READ != LIST && READ != RESET && READ != READ_INTO);
        assert!(LIST != RESET && LIST != READ_INTO);
        assert!(RESET != READ_INTO);
    };
    /// Forget this caller's path, open file, and listing.
    pub const RESET: u64 = 5;
}

/// Service-defined outcomes, returned in `args[0]`'s high half.
pub mod outcome {
    /// The operation succeeded.
    pub const OK: u64 = 0;
    /// No such file.
    pub const NOT_FOUND: u64 = 1;
    /// The path is one the filesystem will not resolve.
    pub const BAD_PATH: u64 = 2;
    /// The name is a directory, or the operation needs one and it is not.
    pub const WRONG_KIND: u64 = 3;
    /// Nothing is open, or nothing is being listed.
    pub const NOTHING_OPEN: u64 = 4;
    /// The service has no room for another caller.
    pub const BUSY: u64 = 5;
    /// The caller reached the service through a capability with no badge, so
    /// it cannot be told apart from any other such caller.
    pub const UNIDENTIFIED: u64 = 6;
    /// The caller named a capability it does not hold, or one of the wrong
    /// kind.
    ///
    /// Distinct from `BAD_PATH`: the request was well formed and the caller
    /// was not entitled to it, which is the answer a service must be able to
    /// give without saying anything about what it was asked for.
    pub const NOT_YOURS: u64 = 7;
}

/// Bytes one message carries.
///
/// Two of the four registers, because the other two say how many bytes there
/// are and carry whatever the method needs besides.
pub const CHUNK_BYTES: usize = 16;

/// Set in `args[0]` when the sender has more to send.
const MORE: u64 = 1 << 8;
/// Mask selecting the byte count from `args[0]`.
const COUNT: u64 = 0xff;
/// Where a service outcome sits in `args[0]`.
const OUTCOME_SHIFT: u64 = 16;

/// Up to [`CHUNK_BYTES`] bytes, and whether more follow.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Chunk {
    bytes: [u8; CHUNK_BYTES],
    length: usize,
    more: bool,
}

impl Default for Chunk {
    fn default() -> Self {
        Self::empty()
    }
}

impl Chunk {
    /// A chunk carrying nothing, and nothing to follow.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            bytes: [0; CHUNK_BYTES],
            length: 0,
            more: false,
        }
    }

    /// Takes the first [`CHUNK_BYTES`] of `bytes`, and returns the rest.
    ///
    /// Returning the remainder rather than an index is what makes the sending
    /// loop hard to write wrongly: a caller iterates until the remainder is
    /// empty, and cannot lose track of how far it has got.
    #[must_use]
    pub fn take(bytes: &[u8]) -> (Self, &[u8]) {
        let length = bytes.len().min(CHUNK_BYTES);
        let (head, tail) = bytes.split_at(length);
        let mut chunk = Self::empty();
        chunk.bytes[..length].copy_from_slice(head);
        chunk.length = length;
        chunk.more = !tail.is_empty();
        (chunk, tail)
    }

    /// The bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    /// How many bytes it carries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length
    }

    /// Whether it carries none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Whether the sender said more follows.
    #[must_use]
    pub const fn more(&self) -> bool {
        self.more
    }

    /// Sets the "more follows" flag.
    #[must_use]
    pub const fn with_more(mut self, more: bool) -> Self {
        self.more = more;
        self
    }

    /// Packs into message registers, with `extra` in `args[3]`.
    #[must_use]
    pub fn pack(&self, extra: u64) -> [u64; 4] {
        let mut low = 0u64;
        let mut high = 0u64;
        for (index, byte) in self.bytes[..self.length].iter().enumerate() {
            let shift = (index % 8) * 8;
            if index < 8 {
                low |= u64::from(*byte) << shift;
            } else {
                high |= u64::from(*byte) << shift;
            }
        }
        let count = self.length as u64 | if self.more { MORE } else { 0 };
        [count, low, high, extra]
    }

    /// Unpacks from message registers.
    ///
    /// A count larger than [`CHUNK_BYTES`] is clamped rather than trusted.
    /// This is the one function here that reads a value the *other* side of a
    /// privilege boundary chose, and a length is exactly the field that must
    /// not be believed: on the kernel's side it would otherwise index past a
    /// sixteen-byte array on behalf of a caller who asked it to.
    #[must_use]
    pub fn unpack(args: &[u64; 4]) -> Self {
        let length = ((args[0] & COUNT) as usize).min(CHUNK_BYTES);
        let mut chunk = Self::empty();
        for index in 0..length {
            let word = if index < 8 { args[1] } else { args[2] };
            let shift = (index % 8) * 8;
            chunk.bytes[index] = ((word >> shift) & 0xff) as u8;
        }
        chunk.length = length;
        chunk.more = args[0] & MORE != 0;
        chunk
    }
}

/// Puts a service outcome into `args[0]` alongside a count.
#[must_use]
pub const fn with_outcome(args0: u64, outcome: u64) -> u64 {
    args0 | (outcome << OUTCOME_SHIFT)
}

/// Reads a service outcome out of `args[0]`.
#[must_use]
pub const fn outcome_of(args0: u64) -> u64 {
    (args0 >> OUTCOME_SHIFT) & 0xff
}

/// Packs a directory entry's size and kind for `args[3]`.
#[must_use]
pub const fn entry_metadata(size: u64, directory: bool) -> u64 {
    (size << 1) | (directory as u64)
}

/// Unpacks [`entry_metadata`] into `(size, is_directory)`.
#[must_use]
pub const fn entry_of(metadata: u64) -> (u64, bool) {
    (metadata >> 1, metadata & 1 != 0)
}

/// Longest line either shell will accept.
///
/// A line that reaches this stops accepting rather than wrapping or
/// truncating silently: neither shell has scrollback, and a command whose end
/// the operator cannot see is worse than one that refuses to grow.
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
/// Shared between the kernel shell and the user-mode one, because they edit
/// lines identically and two implementations would disagree about backspace —
/// which is the sort of difference nobody notices until they have been typing
/// into the wrong one for a minute.
///
/// A pure state machine over bytes, so the interesting behaviour — backspace
/// at the start of a line, a line that grows too long, `\r\n` arriving as two
/// bytes — is testable on the host with no UART, no interrupt and no machine.
pub struct LineEditor {
    buffer: [u8; MAX_LINE],
    length: usize,
    /// Set after `\r`, so the `\n` that follows does not end a second, empty
    /// line. Terminals send both and mean one.
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
            // Printable ASCII only. Anything else -- an escape sequence from an
            // arrow key, a stray high byte from a mismatched baud rate -- is
            // dropped rather than inserted, because a command line containing a
            // byte the operator cannot see is a command they did not mean to
            // type.
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

    #[test]
    fn a_chunk_survives_a_round_trip_at_every_length() {
        let source: [u8; CHUNK_BYTES] = core::array::from_fn(|index| index as u8 + 1);
        for length in 0..=CHUNK_BYTES {
            let (chunk, rest) = Chunk::take(&source[..length]);
            assert!(rest.is_empty());
            let packed = chunk.pack(0);
            let back = Chunk::unpack(&packed);
            assert_eq!(back.bytes(), &source[..length], "length {length}");
            assert_eq!(back.len(), length);
            assert!(!back.more());
        }
    }

    #[test]
    fn taking_returns_the_remainder_so_a_sender_cannot_lose_its_place() {
        let source = b"abcdefghijklmnopqrstuvwxyz";
        let (first, rest) = Chunk::take(source);
        assert_eq!(first.bytes(), b"abcdefghijklmnop");
        assert!(first.more(), "there is more, and the flag says so");

        let (second, rest) = Chunk::take(rest);
        assert_eq!(second.bytes(), b"qrstuvwxyz");
        assert!(!second.more(), "and there is not, and the flag says that");
        assert!(rest.is_empty());
    }

    #[test]
    fn a_count_larger_than_the_chunk_is_clamped_rather_than_believed() {
        // The field the *other* side of a privilege boundary chooses. Trusting
        // it means indexing past a sixteen-byte array because a caller asked.
        let packed = [0xffu64, u64::MAX, u64::MAX, 0];
        let chunk = Chunk::unpack(&packed);
        assert_eq!(chunk.len(), CHUNK_BYTES);
        assert_eq!(chunk.bytes(), &[0xff; CHUNK_BYTES]);
    }

    #[test]
    fn an_outcome_and_a_count_share_a_register_without_colliding() {
        let args0 = with_outcome(CHUNK_BYTES as u64 | MORE, outcome::NOT_FOUND);
        assert_eq!(args0 & COUNT, CHUNK_BYTES as u64);
        assert_eq!(outcome_of(args0), outcome::NOT_FOUND);
        assert!(Chunk::unpack(&[args0, 0, 0, 0]).more());
    }

    #[test]
    fn entry_metadata_survives_a_round_trip() {
        for (size, directory) in [(0u64, false), (1, true), (4096, false), (1 << 40, true)] {
            assert_eq!(entry_of(entry_metadata(size, directory)), (size, directory));
        }
    }

    #[test]
    fn a_line_is_complete_at_a_carriage_return_or_a_newline() {
        let mut editor = LineEditor::new();
        for byte in b"ls /etc\r" {
            editor.accept(*byte);
        }
        assert_eq!(editor.line(), b"ls /etc");
    }

    #[test]
    fn a_carriage_return_and_newline_together_end_one_line_not_two() {
        let mut editor = LineEditor::new();
        assert_eq!(editor.accept(b'a'), Edit::Inserted(b'a'));
        assert_eq!(editor.accept(b'\r'), Edit::Complete);
        editor.clear();
        assert_eq!(editor.accept(b'\n'), Edit::Ignored);
        // And the swallow does not persist into the next line.
        assert_eq!(editor.accept(b'b'), Edit::Inserted(b'b'));
        assert_eq!(editor.accept(b'\n'), Edit::Complete);
        assert_eq!(editor.line(), b"b");
    }

    #[test]
    fn backspace_and_delete_both_erase_and_neither_underflows() {
        let mut editor = LineEditor::new();
        assert_eq!(editor.accept(0x08), Edit::Ignored, "nothing to erase");
        assert_eq!(editor.accept(0x7f), Edit::Ignored);

        for byte in b"lst" {
            editor.accept(*byte);
        }
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
        assert_eq!(editor.accept(b'x'), Edit::Ignored, "no room, and no panic");
        assert_eq!(editor.line().len(), MAX_LINE);
        assert_eq!(editor.accept(0x08), Edit::Erased, "still editable");
    }

    #[test]
    fn control_c_abandons_the_line_and_control_u_erases_it() {
        let mut editor = LineEditor::new();
        for byte in b"rm -rf" {
            editor.accept(*byte);
        }
        assert_eq!(editor.accept(0x03), Edit::Cancelled);
        assert_eq!(editor.line(), b"");

        for byte in b"cat x" {
            editor.accept(*byte);
        }
        assert_eq!(editor.accept(0x15), Edit::Ignored);
        assert_eq!(editor.line(), b"");
    }

    #[test]
    fn bytes_that_cannot_be_seen_are_not_inserted() {
        let mut editor = LineEditor::new();
        for byte in [0x00, 0x1b, 0x1f, 0x80, 0xff] {
            assert_eq!(editor.accept(byte), Edit::Ignored);
        }
        assert_eq!(editor.line(), b"");
    }
}
