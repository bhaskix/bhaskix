// SPDX-License-Identifier: Apache-2.0
//! `eventfd` — [RFC 0086](../../docs/rfc/0086-the-motivating-workload.md)
//! step 5.
//!
//! A 64-bit counter behind a descriptor. **Go's runtime cannot start a network
//! server without one**: `netpollinit` creates it and throws if that fails,
//! registers it in its `epoll` set for `EPOLLIN`, and throws again if it is
//! ever reported ready for anything else; `netpollBreak` writes to it to wake a
//! thread blocked in `epoll_wait`. All read from go 1.27.1's
//! `runtime/netpoll_epoll.go` on 2026-10-01.
//!
//! The rules are Linux's, from the build host's `eventfd(2)` and
//! `bits/eventfd.h`, read the same day:
//!
//! - a read wants at least 8 bytes and takes the whole counter, resetting it
//!   to zero — or, with `EFD_SEMAPHORE`, takes 1 and decrements;
//! - a read of a zero counter waits, or answers `EAGAIN` when non-blocking;
//! - a write wants at least 8 bytes and adds them; `u64::MAX` is refused
//!   `EINVAL`; a sum past `u64::MAX - 1` waits, or answers `EAGAIN`;
//! - readable while the counter is non-zero, writable while a 1 would fit.

/// `eventfd2` flags.
pub mod flag {
    /// Reads take 1 at a time.
    pub const SEMAPHORE: u64 = 0o1;
    /// `O_NONBLOCK`.
    pub const NONBLOCK: u64 = 0o4_000;
    /// `O_CLOEXEC`.
    pub const CLOEXEC: u64 = 0o2_000_000;
}

/// The largest value the counter holds.
pub const MAX: u64 = u64::MAX - 1;

/// The errnos an eventfd answers, from the build host's `errno` headers.
pub mod errno {
    /// A buffer under 8 bytes, a write of `u64::MAX`, or an unknown flag.
    pub const EINVAL: i64 = -22;
    /// Nothing to read, or no room, and the caller would wait.
    pub const EAGAIN: i64 = -11;
}

/// Checks `eventfd2`'s flags, answering whether the counter is a semaphore,
/// whether the descriptor is non-blocking and whether it closes on exec.
///
/// # Errors
///
/// `EINVAL` for a flag Linux does not define here.
pub const fn plan(flags: u64) -> Result<(bool, bool, bool), i64> {
    if flags & !(flag::SEMAPHORE | flag::NONBLOCK | flag::CLOEXEC) != 0 {
        return Err(errno::EINVAL);
    }
    Ok((
        flags & flag::SEMAPHORE != 0,
        flags & flag::NONBLOCK != 0,
        flags & flag::CLOEXEC != 0,
    ))
}

/// One eventfd's counter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Counter {
    value: u64,
    semaphore: bool,
}

/// What a read or a write would do now.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Done: the value a read returns, or the 8 a write reports.
    Done(u64),
    /// It must wait — or answer `EAGAIN` when non-blocking.
    Wait,
    /// Refused with this errno.
    Refused(i64),
}

impl Counter {
    /// A counter starting at `initial`.
    #[must_use]
    pub const fn new(initial: u64, semaphore: bool) -> Self {
        Self {
            value: initial,
            semaphore,
        }
    }

    /// The count now.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// A read of `length` bytes.
    pub const fn read(&mut self, length: u64) -> Outcome {
        if length < 8 {
            return Outcome::Refused(errno::EINVAL);
        }
        if self.value == 0 {
            return Outcome::Wait;
        }
        if self.semaphore {
            self.value -= 1;
            Outcome::Done(1)
        } else {
            let taken = self.value;
            self.value = 0;
            Outcome::Done(taken)
        }
    }

    /// A write of `length` bytes carrying `add`.
    pub const fn write(&mut self, length: u64, add: u64) -> Outcome {
        if length < 8 || add == u64::MAX {
            return Outcome::Refused(errno::EINVAL);
        }
        if add > MAX - self.value {
            return Outcome::Wait;
        }
        self.value += add;
        Outcome::Done(8)
    }

    /// Whether a read would return now.
    #[must_use]
    pub const fn readable(&self) -> bool {
        self.value > 0
    }

    /// Whether a write of 1 would return now.
    #[must_use]
    pub const fn writable(&self) -> bool {
        self.value < MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_takes_the_whole_count_and_a_second_would_wait() {
        let mut counter = Counter::new(0, false);
        assert_eq!(counter.read(8), Outcome::Wait);
        assert_eq!(counter.write(8, 1), Outcome::Done(8));
        assert_eq!(counter.write(8, 2), Outcome::Done(8));
        assert!(counter.readable());
        assert_eq!(counter.read(8), Outcome::Done(3));
        assert!(
            !counter.readable(),
            "reset to zero, as Go's netpoll relies on"
        );
        assert_eq!(counter.read(8), Outcome::Wait);
    }

    #[test]
    fn a_semaphore_hands_out_one_at_a_time() {
        let mut counter = Counter::new(2, true);
        assert_eq!(counter.read(8), Outcome::Done(1));
        assert_eq!(counter.read(8), Outcome::Done(1));
        assert_eq!(counter.read(8), Outcome::Wait);
    }

    #[test]
    fn short_buffers_and_the_forbidden_value_are_refused() {
        let mut counter = Counter::new(5, false);
        assert_eq!(counter.read(7), Outcome::Refused(errno::EINVAL));
        assert_eq!(counter.write(4, 1), Outcome::Refused(errno::EINVAL));
        assert_eq!(counter.write(8, u64::MAX), Outcome::Refused(errno::EINVAL));
        assert_eq!(counter.value(), 5, "a refusal changes nothing");
    }

    #[test]
    fn a_write_past_the_maximum_waits_and_the_full_counter_is_not_writable() {
        let mut counter = Counter::new(MAX - 1, false);
        assert!(counter.writable());
        assert_eq!(counter.write(8, 2), Outcome::Wait);
        assert_eq!(counter.write(8, 1), Outcome::Done(8));
        assert_eq!(counter.value(), MAX);
        assert!(!counter.writable());
        assert_eq!(counter.write(8, 1), Outcome::Wait);
    }

    #[test]
    fn flags_are_the_three_linux_defines_and_nothing_else() {
        assert_eq!(plan(0), Ok((false, false, false)));
        assert_eq!(
            plan(flag::SEMAPHORE | flag::NONBLOCK | flag::CLOEXEC),
            Ok((true, true, true))
        );
        assert_eq!(plan(0o10), Err(errno::EINVAL));
    }

    #[test]
    fn go_s_eventfd_reports_exactly_epollin_when_written() {
        use crate::epoll::{flag as ep, requested};
        use crate::poll::{Condition, revents};
        // Go registers it `EPOLLIN` alone, and throws on anything else.
        let asked = requested(ep::IN);
        let written = Condition::EventFd {
            readable: true,
            writable: true,
        };
        assert_eq!(u32::from(revents(asked, written)), ep::IN);
        let quiet = Condition::EventFd {
            readable: false,
            writable: true,
        };
        assert_eq!(revents(asked, quiet), 0);
    }
}
