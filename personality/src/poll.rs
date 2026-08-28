// SPDX-License-Identifier: Apache-2.0
//! What a descriptor is doing, and what `poll` should say about it —
//! [RFC 0055](../../docs/rfc/0055-a-poll-that-tells-the-truth.md).
//!
//! # Why this is a pure function in a library
//!
//! `poll`'s whole difficulty is the table: which descriptor is ready for what,
//! and which conditions are reported whether or not they were asked for. That
//! is arithmetic over facts the adapter already holds, and arithmetic belongs
//! where it can be tested without booting a machine.
//!
//! What is *not* here is how those facts are learned. Whether a byte is waiting
//! at the console is a question for the nucleus, because only it knows and only
//! it may say — see `method::PEEK_INPUT`.

/// There is data to read.
pub const POLLIN: u16 = 0x001;
/// There is urgent data. Never set here: nothing in this system has any.
pub const POLLPRI: u16 = 0x002;
/// Writing will not block.
pub const POLLOUT: u16 = 0x004;
/// An error condition. **Reported whether or not it was asked for.**
pub const POLLERR: u16 = 0x008;
/// The other end is gone. **Reported whether or not it was asked for.**
pub const POLLHUP: u16 = 0x010;
/// The descriptor names nothing. **Reported whether or not it was asked for.**
pub const POLLNVAL: u16 = 0x020;

/// What the adapter can see about one descriptor.
///
/// Deliberately *facts* rather than flags: the mapping from facts to flags is
/// the thing being tested, so a caller that could pass flags straight through
/// would be able to bypass it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Condition {
    /// No descriptor of that number is open.
    Unknown,
    /// The console. `granted` is whether this domain may read input at all —
    /// [RFC 0053](../../docs/rfc/0053-input-a-domain-was-given.md).
    Console {
        /// Whether a byte is already waiting to be read.
        byte_waiting: bool,
        /// Whether this domain may read input at all.
        granted: bool,
    },
    /// A file, a directory or a `/proc` entry.
    ///
    /// Always readable, and never writable: the directory capability a hosted
    /// process resolves through is `READ` and `DERIVE`, so a write is refused
    /// with `EROFS` and reporting it writable would be a lie with a system
    /// call's worth of delay in it.
    File,
    /// One end of a pipe, with what its ring holds and who still has it open.
    Pipe {
        /// Bytes waiting in the ring.
        bytes: usize,
        /// Room left in the ring.
        room: usize,
        /// Descriptors still naming the read end.
        readers: u32,
        /// Descriptors still naming the write end.
        writers: u32,
        /// Whether *this* descriptor is the readable end.
        readable_end: bool,
        /// Whether *this* descriptor is the writable end.
        writable_end: bool,
    },
    /// A descriptor this adapter cannot answer for — a socket, today.
    ///
    /// **Zero, and not a guess.** RFC 0055 unresolved question 1: a socket's
    /// readiness lives in the network service, and inventing one here would be
    /// inventing a fact.
    Unanswered,
}

/// What `poll` should report for one descriptor.
///
/// `requested` is the caller's `events`. `POLLERR`, `POLLHUP` and `POLLNVAL`
/// are returned whether or not they were asked for, which is POSIX's rule and
/// the one a caller relies on to notice a descriptor going wrong while it waits
/// for something else.
#[must_use]
pub fn revents(requested: u16, condition: Condition) -> u16 {
    match condition {
        Condition::Unknown => POLLNVAL,
        // **The answer to RFC 0053's unresolved question 3.** Not "not
        // implemented", which makes a shell complain and guess; not "never
        // readable", which is a lie it believes. There is an error condition on
        // this descriptor, and a `read` of it returns `EIO` by a nucleus check
        // the adapter cannot lift.
        Condition::Console { granted: false, .. } => POLLERR,
        Condition::Console {
            byte_waiting,
            granted: true,
        } => {
            let mut out = requested & POLLOUT;
            if byte_waiting {
                out |= requested & POLLIN;
            }
            out
        }
        Condition::File => requested & POLLIN,
        Condition::Pipe {
            bytes,
            room,
            readers,
            writers,
            readable_end,
            writable_end,
        } => {
            let mut out = 0;
            if readable_end {
                if bytes > 0 {
                    out |= requested & POLLIN;
                }
                // Every writer gone and nothing left to read is end of file,
                // which a reader must be told about even though it asked about
                // data. Bytes still in the ring are not a hangup yet: they are
                // readable, and the hangup is what the reader finds after them.
                if writers == 0 && bytes == 0 {
                    out |= POLLHUP;
                }
            }
            if writable_end {
                if room > 0 {
                    out |= requested & POLLOUT;
                }
                // Nobody can ever read what is written here. `write` answers
                // `EPIPE`; this is the same fact one call earlier.
                if readers == 0 {
                    out |= POLLERR;
                }
            }
            out
        }
        Condition::Unanswered => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_descriptor_is_invalid_whatever_was_asked() {
        assert_eq!(revents(0, Condition::Unknown), POLLNVAL);
        assert_eq!(revents(POLLIN | POLLOUT, Condition::Unknown), POLLNVAL);
    }

    #[test]
    fn an_ungranted_console_is_an_error_and_not_a_quiet_never() {
        // The whole point of RFC 0053's question 3: a caller must be able to
        // tell "nothing yet" from "not yours", and zero cannot say the second.
        let ungranted = Condition::Console {
            byte_waiting: false,
            granted: false,
        };
        assert_eq!(revents(POLLIN, ungranted), POLLERR);
        // Asked for or not.
        assert_eq!(revents(0, ungranted), POLLERR);
        // And it is *not* readable, which is the other half of the mistake.
        assert_eq!(revents(POLLIN, ungranted) & POLLIN, 0);
    }

    #[test]
    fn a_granted_console_is_readable_only_when_a_byte_is_waiting() {
        let empty = Condition::Console {
            byte_waiting: false,
            granted: true,
        };
        let waiting = Condition::Console {
            byte_waiting: true,
            granted: true,
        };
        assert_eq!(revents(POLLIN, empty), 0);
        assert_eq!(revents(POLLIN, waiting), POLLIN);
        // Always writable, and only when asked.
        assert_eq!(revents(POLLOUT, empty), POLLOUT);
        assert_eq!(revents(POLLIN, waiting) & POLLOUT, 0);
    }

    #[test]
    fn a_file_is_readable_and_never_writable() {
        assert_eq!(revents(POLLIN, Condition::File), POLLIN);
        // Read-only by the capability it resolves through, so reporting it
        // writable would promise something the next call refuses.
        assert_eq!(revents(POLLOUT, Condition::File), 0);
        assert_eq!(revents(POLLIN | POLLOUT, Condition::File), POLLIN);
    }

    /// A pipe end, with the fields a test does not care about filled in.
    fn pipe(bytes: usize, room: usize, readers: u32, writers: u32, read_end: bool) -> Condition {
        Condition::Pipe {
            bytes,
            room,
            readers,
            writers,
            readable_end: read_end,
            writable_end: !read_end,
        }
    }

    #[test]
    fn a_pipe_read_end_follows_its_ring() {
        assert_eq!(revents(POLLIN, pipe(0, 16, 1, 1, true)), 0);
        assert_eq!(revents(POLLIN, pipe(3, 13, 1, 1, true)), POLLIN);
    }

    #[test]
    fn a_pipe_whose_writers_have_gone_hangs_up_only_once_it_is_empty() {
        // Bytes first, hangup after: a reader told POLLHUP with data still in
        // the ring is a reader that may stop before reading it.
        assert_eq!(revents(POLLIN, pipe(3, 13, 1, 0, true)), POLLIN);
        assert_eq!(revents(POLLIN, pipe(0, 16, 1, 0, true)), POLLHUP);
        // Reported whether or not it was asked for.
        assert_eq!(revents(0, pipe(0, 16, 1, 0, true)), POLLHUP);
    }

    #[test]
    fn a_pipe_write_end_follows_its_room_and_its_readers() {
        assert_eq!(revents(POLLOUT, pipe(0, 16, 1, 1, false)), POLLOUT);
        assert_eq!(revents(POLLOUT, pipe(16, 0, 1, 1, false)), 0);
        // No reader left is EPIPE one call early, asked for or not.
        assert_eq!(
            revents(POLLOUT, pipe(0, 16, 0, 1, false)),
            POLLOUT | POLLERR
        );
        assert_eq!(revents(0, pipe(0, 16, 0, 1, false)), POLLERR);
    }

    #[test]
    fn what_cannot_be_answered_claims_nothing() {
        assert_eq!(revents(POLLIN | POLLOUT, Condition::Unanswered), 0);
    }

    #[test]
    fn nothing_ever_reports_urgent_data() {
        // There is no out-of-band data anywhere in this system, and a caller
        // that was told there was would go looking for it.
        for condition in [
            Condition::Unknown,
            Condition::File,
            Condition::Unanswered,
            Condition::Console {
                byte_waiting: true,
                granted: true,
            },
            pipe(4, 12, 1, 1, true),
            pipe(4, 12, 1, 1, false),
        ] {
            assert_eq!(revents(u16::MAX, condition) & POLLPRI, 0, "{condition:?}");
        }
    }
}
