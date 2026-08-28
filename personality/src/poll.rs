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
    /// A bound UDP socket, with whether a datagram is waiting — RFC 0056.
    ///
    /// **Always writable, and that is the truth rather than a convenience.** A
    /// hosted socket is UDP — a stream is refused at `socket()` — and `sendto`
    /// hands the payload to the service and answers. There is no buffer to fill
    /// and no state in which a write would wait.
    Socket {
        /// Whether a datagram is waiting to be received.
        datagram_waiting: bool,
    },
    /// A descriptor this adapter cannot answer for.
    ///
    /// **Zero, and not a guess.** One holder left: `epoll`, which has no
    /// readiness of its own until something implements it. Sockets were here
    /// until RFC 0056 gave the service a way to be asked without being
    /// emptied.
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
        Condition::Socket { datagram_waiting } => {
            let mut out = requested & POLLOUT;
            if datagram_waiting {
                out |= requested & POLLIN;
            }
            out
        }
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

/// Which of `select`'s three sets a descriptor was named in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Watched {
    /// Named in `readfds`.
    pub read: bool,
    /// Named in `writefds`.
    pub write: bool,
    /// Named in `exceptfds`.
    pub except: bool,
}

/// Which of them it should be reported ready in.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Ready {
    /// Report it in `readfds`.
    pub read: bool,
    /// Report it in `writefds`.
    pub write: bool,
    /// Report it in `exceptfds`.
    pub except: bool,
    /// The descriptor names nothing, and **the whole call fails** with `EBADF`.
    ///
    /// This is where `select` and `poll` genuinely differ rather than merely
    /// spelling the same thing twice: `poll` reports `POLLNVAL` on the one
    /// entry and answers the rest normally, and `select` refuses the call
    /// outright. A caller that watches eight descriptors and closes one gets a
    /// per-descriptor flag from the first and nothing at all from the second.
    pub invalid: bool,
}

/// What `select` should report for one descriptor.
///
/// **Built on [`revents`] rather than beside it**, so there is one table and
/// not two that agree until somebody edits one. The mapping back out is where
/// `select`'s own rules live:
///
/// - an error condition makes a descriptor ready for **reading and writing**,
///   in whichever of those the caller asked about — because `select` has no way
///   to say "error" and a caller must be able to find out by acting;
/// - a hangup makes it ready for reading, for the same reason: the read that
///   follows returns zero, which is how the caller learns;
/// - `exceptfds` means urgent data here and nothing else, so nothing in this
///   system is ever reported in it.
#[must_use]
pub fn selected(watched: Watched, condition: Condition) -> Ready {
    let mut asked = 0;
    if watched.read {
        asked |= POLLIN;
    }
    if watched.write {
        asked |= POLLOUT;
    }
    if watched.except {
        asked |= POLLPRI;
    }
    let revents = revents(asked, condition);
    if revents & POLLNVAL != 0 {
        return Ready {
            invalid: true,
            ..Ready::default()
        };
    }
    Ready {
        read: watched.read && revents & (POLLIN | POLLERR | POLLHUP) != 0,
        write: watched.write && revents & (POLLOUT | POLLERR) != 0,
        except: watched.except && revents & POLLPRI != 0,
        invalid: false,
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
    fn a_socket_is_readable_only_once_a_datagram_is_waiting() {
        let empty = Condition::Socket {
            datagram_waiting: false,
        };
        let waiting = Condition::Socket {
            datagram_waiting: true,
        };
        assert_eq!(revents(POLLIN, empty), 0);
        assert_eq!(revents(POLLIN, waiting), POLLIN);
        // Always writable: `sendto` hands the payload over and answers, so
        // there is no state in which a write would wait.
        assert_eq!(revents(POLLOUT, empty), POLLOUT);
        assert_eq!(revents(POLLIN | POLLOUT, waiting), POLLIN | POLLOUT);
    }

    #[test]
    fn what_cannot_be_answered_claims_nothing() {
        assert_eq!(revents(POLLIN | POLLOUT, Condition::Unanswered), 0);
    }

    /// Every set asked about at once.
    const ALL: Watched = Watched {
        read: true,
        write: true,
        except: true,
    };

    #[test]
    fn select_refuses_the_whole_call_for_a_descriptor_that_names_nothing() {
        // The difference from `poll`, which reports it on the one entry and
        // answers the rest.
        let out = selected(ALL, Condition::Unknown);
        assert!(out.invalid);
        assert!(!out.read && !out.write && !out.except);
    }

    #[test]
    fn select_reports_an_errored_console_ready_for_both_directions() {
        // `select` cannot say "error", so a caller finds out by acting -- and
        // it can only act if it is told the descriptor is ready. An ungranted
        // console reported as *not* ready is a caller that waits for ever for
        // permission it will never get.
        let ungranted = Condition::Console {
            byte_waiting: false,
            granted: false,
        };
        let out = selected(ALL, ungranted);
        assert!(out.read && out.write, "{out:?}");
        assert!(!out.invalid);
    }

    #[test]
    fn select_reports_only_the_sets_it_was_asked_about() {
        let waiting = Condition::Console {
            byte_waiting: true,
            granted: true,
        };
        let read_only = Watched {
            read: true,
            write: false,
            except: false,
        };
        let out = selected(read_only, waiting);
        assert!(out.read);
        assert!(!out.write, "a set nobody asked about must stay empty");
    }

    #[test]
    fn select_reports_a_drained_pipe_whose_writers_have_gone_as_readable() {
        // The hangup reaches the caller as readability, and the read that
        // follows returns zero. Reporting it unready would hang a caller on a
        // pipe that will never have anything again.
        let out = selected(ALL, pipe(0, 16, 1, 0, true));
        assert!(out.read, "{out:?}");
    }

    #[test]
    fn select_never_reports_an_exceptional_condition() {
        for condition in [
            Condition::File,
            Condition::Unanswered,
            Condition::Console {
                byte_waiting: true,
                granted: true,
            },
            Condition::Console {
                byte_waiting: false,
                granted: false,
            },
            pipe(4, 12, 1, 1, true),
            pipe(0, 16, 0, 1, false),
        ] {
            assert!(!selected(ALL, condition).except, "{condition:?}");
        }
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
