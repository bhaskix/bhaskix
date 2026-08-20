// SPDX-License-Identifier: Apache-2.0
//! A pipe, as arithmetic.
//!
//! [RFC 0033](../../docs/rfc/0033-what-a-hosted-process-is.md) step 7: a pipe
//! joins two hosted processes, both served by the same adapter, so it is a
//! **ring buffer in that adapter** and not a kernel object. Nothing about a
//! pipe needs authority the adapter does not already hold, and the moment one
//! became an `Endpoint` the kernel would be holding state for a dialect it does
//! not interpret — which is the thing RFC 0031's interface I1 exists to stop.
//!
//! What lives here is the part Linux specifies exactly and a translator gets
//! subtly wrong: **what a short read means, what an empty pipe means, and what
//! happens when one end is closed.** Three answers, none of them obvious:
//!
//! - A read of an **empty** pipe whose write end is still open must *block*.
//!   Returning zero would tell the reader the pipe is finished, and a shell
//!   pipeline would exit at the first moment its producer was slow.
//! - A read of an **empty** pipe whose write end is **closed** returns zero,
//!   which is end of file, which is how every `cat | wc` in history stops.
//! - A write to a pipe whose read end is closed is `EPIPE` (and a `SIGPIPE`
//!   this personality does not yet raise). Not a silent success: a program
//!   that believes bytes were delivered to a reader that has gone is worse off
//!   than one told plainly.
//!
//! This module holds no capability, allocates nothing, and cannot block. The
//! adapter decides *how* to block; this says *whether* a reader must.

/// Linux `errno` values this module returns, negated at the register.
pub mod errno {
    /// The read end is closed and nobody will ever read what is written.
    pub const EPIPE: i64 = -32;
    /// Nothing to read yet, for a pipe opened non-blocking.
    pub const EAGAIN: i64 = -11;
}

/// How many bytes one pipe holds.
///
/// **512, and small on purpose.** Linux's is 64 KiB and grows; this one lives
/// in a `static` inside a single-threaded server that cannot allocate, so its
/// size is a fixed cost paid per pipe whether or not anything uses it. A
/// larger buffer is one constant and a measurement — and the measurement to
/// take first is whether a hosted pipeline ever fills it, because a reader that
/// keeps up never notices the size at all.
pub const CAPACITY: usize = 512;

/// One pipe: a ring, and which of its two ends are still open.
#[derive(Clone, Copy, Debug)]
pub struct Pipe {
    bytes: [u8; CAPACITY],
    /// Where the next byte will be read from.
    read_at: usize,
    /// How many bytes are in the ring.
    held: usize,
    /// Whether any descriptor still names the read end.
    pub readers: u32,
    /// Whether any descriptor still names the write end.
    pub writers: u32,
}

impl Default for Pipe {
    fn default() -> Self {
        Self::new()
    }
}

impl Pipe {
    /// An empty pipe with one end of each kind open.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; CAPACITY],
            read_at: 0,
            held: 0,
            readers: 1,
            writers: 1,
        }
    }

    /// How many bytes are waiting.
    #[must_use]
    pub const fn held(&self) -> usize {
        self.held
    }

    /// How much room is left.
    #[must_use]
    pub const fn room(&self) -> usize {
        CAPACITY - self.held
    }

    /// Puts as much of `bytes` in as will fit, and answers how much.
    ///
    /// **A short write is not an error**, and a program that treats it as one
    /// is broken on Linux too: `write` returns what it took, and a writer loops.
    /// What *is* an error is a pipe nobody can read from.
    ///
    /// # Errors
    ///
    /// [`errno::EPIPE`] when the read end is closed.
    pub fn write(&mut self, bytes: &[u8]) -> Result<usize, i64> {
        if self.readers == 0 {
            return Err(errno::EPIPE);
        }
        let take = bytes.len().min(self.room());
        for (index, byte) in bytes.iter().take(take).enumerate() {
            let at = (self.read_at + self.held + index) % CAPACITY;
            self.bytes[at] = *byte;
        }
        self.held += take;
        Ok(take)
    }

    /// Takes as much as is there into `out`, and answers how much.
    ///
    /// Zero means the pipe was empty. **Whether that is end of file or a
    /// reason to wait is [`Self::at_end`]'s question**, and the two are
    /// deliberately separate: this function cannot block and must not decide
    /// on the caller's behalf.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let take = out.len().min(self.held);
        for (index, byte) in out.iter_mut().take(take).enumerate() {
            *byte = self.bytes[(self.read_at + index) % CAPACITY];
        }
        self.read_at = (self.read_at + take) % CAPACITY;
        self.held -= take;
        take
    }

    /// Whether a reader finding it empty has reached end of file.
    ///
    /// True only when **no writer remains**. An empty pipe with a writer still
    /// open is a reader's cue to wait; answering end of file there would end
    /// every pipeline at its producer's first pause.
    #[must_use]
    pub const fn at_end(&self) -> bool {
        self.held == 0 && self.writers == 0
    }

    /// Whether a reader must wait: empty, and somebody may still write.
    #[must_use]
    pub const fn would_block(&self) -> bool {
        self.held == 0 && self.writers > 0
    }

    /// Records that a descriptor naming the read end has closed.
    pub const fn close_read_end(&mut self) {
        self.readers = self.readers.saturating_sub(1);
    }

    /// Records that a descriptor naming the write end has closed.
    pub const fn close_write_end(&mut self) {
        self.writers = self.writers.saturating_sub(1);
    }

    /// Records another descriptor naming the read end — `dup`, or a `fork`.
    pub const fn open_read_end(&mut self) {
        self.readers += 1;
    }

    /// Records another descriptor naming the write end.
    pub const fn open_write_end(&mut self) {
        self.writers += 1;
    }

    /// Whether both ends are closed, so the pipe may be reused.
    #[must_use]
    pub const fn abandoned(&self) -> bool {
        self.readers == 0 && self.writers == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_goes_in_comes_out_in_order() {
        let mut pipe = Pipe::new();
        assert_eq!(pipe.write(b"hello ").expect("room"), 6);
        assert_eq!(pipe.write(b"world").expect("room"), 5);
        let mut out = [0u8; 11];
        assert_eq!(pipe.read(&mut out), 11);
        assert_eq!(&out, b"hello world");
        assert_eq!(pipe.held(), 0);
    }

    #[test]
    fn the_ring_wraps_without_losing_or_reordering_a_byte() {
        let mut pipe = Pipe::new();
        // Fill it, drain most of it, then write past the end of the buffer so
        // the next write wraps. A ring that wrapped wrongly would pass every
        // test that never crossed the seam.
        let full = [b'a'; CAPACITY];
        assert_eq!(pipe.write(&full).expect("room"), CAPACITY);
        let mut out = [0u8; CAPACITY - 8];
        assert_eq!(pipe.read(&mut out), CAPACITY - 8);
        assert_eq!(pipe.held(), 8);

        assert_eq!(pipe.write(b"0123456789").expect("room"), 10);
        let mut tail = [0u8; 18];
        assert_eq!(pipe.read(&mut tail), 18);
        assert_eq!(&tail[..8], &[b'a'; 8]);
        assert_eq!(&tail[8..], b"0123456789");
    }

    #[test]
    fn a_write_that_does_not_fit_is_short_and_not_an_error() {
        let mut pipe = Pipe::new();
        let too_much = [b'x'; CAPACITY + 100];
        assert_eq!(pipe.write(&too_much).expect("some room"), CAPACITY);
        assert_eq!(pipe.room(), 0);
        assert_eq!(pipe.write(b"more").expect("no room"), 0);
    }

    #[test]
    fn an_empty_pipe_with_a_writer_is_a_wait_and_not_an_end() {
        let pipe = Pipe::new();
        assert!(pipe.would_block(), "a reader must wait");
        assert!(!pipe.at_end(), "this is not end of file");
    }

    #[test]
    fn an_empty_pipe_with_no_writer_is_end_of_file() {
        let mut pipe = Pipe::new();
        pipe.close_write_end();
        assert!(pipe.at_end());
        assert!(!pipe.would_block(), "nothing will ever arrive");
    }

    #[test]
    fn bytes_already_written_survive_the_writers_leaving() {
        let mut pipe = Pipe::new();
        pipe.write(b"last words").expect("room");
        pipe.close_write_end();
        assert!(!pipe.at_end(), "there is still something to read");
        let mut out = [0u8; 10];
        assert_eq!(pipe.read(&mut out), 10);
        assert_eq!(&out, b"last words");
        assert!(pipe.at_end(), "and now there is not");
    }

    #[test]
    fn writing_to_a_pipe_nobody_reads_is_epipe() {
        let mut pipe = Pipe::new();
        pipe.close_read_end();
        assert_eq!(pipe.write(b"into the void"), Err(errno::EPIPE));
    }

    #[test]
    fn a_pipe_is_abandoned_only_when_both_ends_have_gone() {
        let mut pipe = Pipe::new();
        pipe.open_read_end();
        pipe.close_read_end();
        assert!(!pipe.abandoned(), "one reader is left");
        pipe.close_read_end();
        assert!(!pipe.abandoned(), "and a writer");
        pipe.close_write_end();
        assert!(pipe.abandoned());
    }
}
