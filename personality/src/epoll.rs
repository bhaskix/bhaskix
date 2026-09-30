// SPDX-License-Identifier: Apache-2.0
//! `epoll` — [RFC 0086](../../docs/rfc/0086-the-motivating-workload.md) step 4.
//!
//! The interest set and the arithmetic of what to report, with nothing about
//! how readiness is learned: that is the adapter's, and it arrives here as
//! [`crate::poll::Condition`] facts turned into bits by
//! [`crate::poll::revents`], exactly as `poll` and `select` already have them.
//!
//! # Edge-triggered, for real
//!
//! Go's runtime registers every connection with `EPOLLET` and reads until it
//! is told `EAGAIN` before it waits again — and it waits in a loop, often
//! without blocking. Reporting level-triggered to it would hand the netpoller
//! the same readable descriptor on every look while a goroutine has not yet
//! read, which is a spin. So each interest keeps a **watermark** of the news it
//! was last told about — the adapter's count of what has happened on that
//! descriptor, which only grows — and an edge-triggered interest is reported
//! only when the count has moved past it.
//!
//! The constants are the build host's, read from `sys/epoll.h` and
//! `bits/epoll.h` on 2026-09-30: an `epoll_event` is **packed** on x86-64, a
//! 32-bit mask and 64 bits of the caller's data in twelve bytes.

/// Event bits, which for the four `poll` shares are the same numbers.
pub mod flag {
    /// Readable.
    pub const IN: u32 = 0x001;
    /// Urgent data; never set here.
    pub const PRI: u32 = 0x002;
    /// Writable.
    pub const OUT: u32 = 0x004;
    /// An error; reported whether asked for or not.
    pub const ERR: u32 = 0x008;
    /// Hung up; reported whether asked for or not.
    pub const HUP: u32 = 0x010;
    /// The peer closed its writing half.
    pub const RDHUP: u32 = 0x2000;
    /// Wake one waiter of several; accepted and meaningless here, where a set
    /// has one waiter.
    pub const EXCLUSIVE: u32 = 1 << 28;
    /// Report once, then stay quiet until `EPOLL_CTL_MOD` re-arms it.
    pub const ONESHOT: u32 = 1 << 30;
    /// Edge-triggered.
    pub const ET: u32 = 1 << 31;
}

/// `epoll_ctl` operations.
pub mod op {
    /// Add a descriptor.
    pub const ADD: u64 = 1;
    /// Remove one.
    pub const DEL: u64 = 2;
    /// Change one's events or data.
    pub const MOD: u64 = 3;
}

/// `EPOLL_CLOEXEC`, which is `O_CLOEXEC`.
pub const CLOEXEC: u64 = 0o2_000_000;

/// Bytes in one `struct epoll_event` on x86-64: packed.
pub const EVENT_BYTES: usize = 12;

/// Descriptors one set may watch — as many as a process may hold.
pub const MAX_INTERESTS: usize = crate::file::MAX_DESCRIPTORS;

/// What `epoll_ctl` answers wrong, from the build host's `errno` headers.
pub mod errno {
    /// No such descriptor, or not an `epoll` one.
    pub const EBADF: i64 = -9;
    /// `DEL` or `MOD` of a descriptor not in the set.
    pub const ENOENT: i64 = -2;
    /// `ADD` of one already in it.
    pub const EEXIST: i64 = -17;
    /// The set is full.
    pub const ENOSPC: i64 = -28;
    /// An unknown operation, or a set asked to watch itself.
    pub const EINVAL: i64 = -22;
}

/// One watched descriptor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Interest {
    /// The descriptor.
    pub fd: i32,
    /// What the caller asked for, flags included.
    pub events: u32,
    /// What the caller wants handed back with each event.
    pub data: u64,
    /// The news last reported — see the module note.
    seen: u64,
    /// A one-shot interest that has fired and not been re-armed.
    spent: bool,
}

/// An `epoll` set.
#[derive(Clone, Copy, Debug)]
pub struct Set {
    interests: [Option<Interest>; MAX_INTERESTS],
}

impl Default for Set {
    fn default() -> Self {
        Self::new()
    }
}

impl Set {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            interests: [None; MAX_INTERESTS],
        }
    }

    /// `epoll_ctl(op, fd, events, data)`. `own` is the set's own descriptor,
    /// which it may not watch.
    ///
    /// # Errors
    ///
    /// See [`errno`].
    pub fn control(
        &mut self,
        op: u64,
        fd: i32,
        events: u32,
        data: u64,
        own: i32,
    ) -> Result<(), i64> {
        if fd == own || fd < 0 {
            return Err(errno::EINVAL);
        }
        let found = self
            .interests
            .iter()
            .position(|held| held.is_some_and(|held| held.fd == fd));
        match (op, found) {
            (op::ADD, Some(_)) => Err(errno::EEXIST),
            (op::ADD, None) => {
                let free = self
                    .interests
                    .iter()
                    .position(Option::is_none)
                    .ok_or(errno::ENOSPC)?;
                self.interests[free] = Some(Interest {
                    fd,
                    events,
                    data,
                    seen: 0,
                    spent: false,
                });
                Ok(())
            }
            (op::MOD, Some(index)) => {
                // A modification re-arms: a one-shot interest fires again, and
                // an edge-triggered one is told the present state afresh, which
                // is what Linux does and what a caller re-arming expects.
                self.interests[index] = Some(Interest {
                    fd,
                    events,
                    data,
                    seen: 0,
                    spent: false,
                });
                Ok(())
            }
            (op::DEL, Some(index)) => {
                self.interests[index] = None;
                Ok(())
            }
            (op::MOD | op::DEL, None) => Err(errno::ENOENT),
            _ => Err(errno::EINVAL),
        }
    }

    /// Forgets a descriptor the process closed, as Linux does when the last
    /// reference to an open file goes.
    pub fn forget(&mut self, fd: i32) {
        for slot in &mut self.interests {
            if slot.is_some_and(|held| held.fd == fd) {
                *slot = None;
            }
        }
    }

    /// The descriptors watched, in no particular order.
    pub fn watched(&self) -> impl Iterator<Item = &Interest> {
        self.interests.iter().flatten()
    }

    /// Decides whether `fd` is reported, given `level` — the bits its
    /// condition answers for what the interest asked — and `news`, the
    /// adapter's count of what has happened on it.
    ///
    /// Answers the bits to report, or `None`. Level-triggered reports whenever
    /// `level` is non-zero; edge-triggered only when `news` has moved past the
    /// last report; a one-shot interest goes quiet once it has reported.
    ///
    /// **`news` of `None` is a descriptor with no count of its own** — a pipe,
    /// the console, a datagram socket, whose readiness is asked of a service
    /// that keeps no such number. An edge-triggered interest in one is
    /// reported as level-triggered: too often rather than never, which costs a
    /// caller a read that answers `EAGAIN` rather than a wait that never ends.
    pub fn report(&mut self, fd: i32, level: u32, news: Option<u64>) -> Option<u32> {
        let interest = self
            .interests
            .iter_mut()
            .flatten()
            .find(|held| held.fd == fd)?;
        if interest.spent || level == 0 {
            return None;
        }
        if interest.events & flag::ET != 0
            && let Some(news) = news
        {
            if news <= interest.seen {
                return None;
            }
            interest.seen = news;
        }
        if interest.events & flag::ONESHOT != 0 {
            interest.spent = true;
        }
        Some(level)
    }
}

/// One `struct epoll_event`, as a program reads it.
#[must_use]
pub fn event_bytes(events: u32, data: u64) -> [u8; EVENT_BYTES] {
    let mut out = [0u8; EVENT_BYTES];
    out[..4].copy_from_slice(&events.to_le_bytes());
    out[4..].copy_from_slice(&data.to_le_bytes());
    out
}

/// A `struct epoll_event` a program wrote: its mask and its data.
#[must_use]
pub fn parse_event(bytes: &[u8; EVENT_BYTES]) -> (u32, u64) {
    let mut events = [0u8; 4];
    events.copy_from_slice(&bytes[..4]);
    let mut data = [0u8; 8];
    data.copy_from_slice(&bytes[4..]);
    (u32::from_le_bytes(events), u64::from_le_bytes(data))
}

/// The bits `poll::revents` understands, from an interest's mask: the flags
/// that are not events are removed, and `ERR` and `HUP` are always asked.
#[must_use]
pub const fn requested(events: u32) -> u16 {
    let wanted = events & (flag::IN | flag::PRI | flag::OUT | flag::RDHUP);
    (wanted | flag::ERR | flag::HUP) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_modify_delete_answer_as_linux_does() {
        let mut set = Set::new();
        assert_eq!(set.control(op::ADD, 5, flag::IN, 7, 3), Ok(()));
        assert_eq!(set.control(op::ADD, 5, flag::IN, 7, 3), Err(errno::EEXIST));
        assert_eq!(set.control(op::MOD, 6, flag::IN, 0, 3), Err(errno::ENOENT));
        assert_eq!(set.control(op::DEL, 6, 0, 0, 3), Err(errno::ENOENT));
        assert_eq!(
            set.control(op::ADD, 3, flag::IN, 0, 3),
            Err(errno::EINVAL),
            "a set watching itself"
        );
        assert_eq!(
            set.control(9, 5, flag::IN, 0, 3),
            Err(errno::EINVAL),
            "an unknown operation"
        );
        assert_eq!(set.control(op::MOD, 5, flag::OUT, 9, 3), Ok(()));
        assert_eq!(
            set.watched().next().map(|held| (held.events, held.data)),
            Some((flag::OUT, 9))
        );
        assert_eq!(set.control(op::DEL, 5, 0, 0, 3), Ok(()));
        assert_eq!(set.watched().count(), 0);
    }

    #[test]
    fn a_full_set_refuses_rather_than_dropping_one() {
        let mut set = Set::new();
        for fd in 0..MAX_INTERESTS as i32 {
            assert_eq!(set.control(op::ADD, fd + 100, flag::IN, 0, 1), Ok(()));
        }
        assert_eq!(set.control(op::ADD, 99, flag::IN, 0, 1), Err(errno::ENOSPC));
    }

    #[test]
    fn edge_triggered_reports_news_once_and_level_triggered_reports_the_level() {
        let mut set = Set::new();
        set.control(op::ADD, 5, flag::IN | flag::ET, 0, 1).unwrap();
        set.control(op::ADD, 6, flag::IN, 0, 1).unwrap();
        // Sixteen bytes arrive on both.
        assert_eq!(set.report(5, flag::IN, Some(16)), Some(flag::IN));
        assert_eq!(set.report(6, flag::IN, Some(16)), Some(flag::IN));
        // Nobody read: the level is unchanged and so is the news.
        assert_eq!(
            set.report(5, flag::IN, Some(16)),
            None,
            "no new edge, however long it stays readable"
        );
        assert_eq!(
            set.report(6, flag::IN, Some(16)),
            Some(flag::IN),
            "level-triggered says so every time"
        );
        // More bytes: a new edge.
        assert_eq!(set.report(5, flag::IN, Some(32)), Some(flag::IN));
        // Nothing is never reported, edge or level.
        assert_eq!(set.report(6, 0, Some(40)), None);
        // A descriptor with no count of its own: edge-triggered degrades to
        // level rather than to silence.
        set.control(op::ADD, 7, flag::IN | flag::ET, 0, 1).unwrap();
        assert_eq!(set.report(7, flag::IN, None), Some(flag::IN));
        assert_eq!(set.report(7, flag::IN, None), Some(flag::IN));
    }

    #[test]
    fn a_one_shot_interest_goes_quiet_until_modified() {
        let mut set = Set::new();
        set.control(op::ADD, 5, flag::IN | flag::ONESHOT, 0, 1)
            .unwrap();
        assert_eq!(set.report(5, flag::IN, Some(1)), Some(flag::IN));
        assert_eq!(set.report(5, flag::IN, Some(2)), None);
        set.control(op::MOD, 5, flag::IN | flag::ONESHOT, 0, 1)
            .unwrap();
        assert_eq!(set.report(5, flag::IN, Some(2)), Some(flag::IN), "re-armed");
    }

    #[test]
    fn an_event_is_twelve_packed_bytes_both_ways() {
        let bytes = event_bytes(flag::IN | flag::RDHUP, 0x1122_3344_5566_7788);
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[..4], &(flag::IN | flag::RDHUP).to_le_bytes());
        assert_eq!(
            parse_event(&bytes),
            (flag::IN | flag::RDHUP, 0x1122_3344_5566_7788)
        );
    }

    #[test]
    fn what_is_asked_of_poll_drops_the_mode_flags_and_always_asks_err_and_hup() {
        let asked = requested(flag::IN | flag::OUT | flag::RDHUP | flag::ET | flag::ONESHOT);
        assert_eq!(
            u32::from(asked),
            flag::IN | flag::OUT | flag::RDHUP | flag::ERR | flag::HUP
        );
    }

    #[test]
    fn a_stream_condition_answers_through_poll_as_epoll_expects() {
        use crate::poll::{Condition, revents};
        let asked = requested(flag::IN | flag::OUT | flag::RDHUP | flag::ET);
        let quiet = revents(
            asked,
            Condition::Stream {
                unread: 0,
                peer_closed: false,
            },
        );
        assert_eq!(
            u32::from(quiet),
            flag::OUT,
            "connected and nothing to read: writable only"
        );
        let data = revents(
            asked,
            Condition::Stream {
                unread: 16,
                peer_closed: false,
            },
        );
        assert_eq!(u32::from(data), flag::IN | flag::OUT);
        let gone = revents(
            asked,
            Condition::Stream {
                unread: 0,
                peer_closed: true,
            },
        );
        assert_eq!(
            u32::from(gone),
            flag::IN | flag::OUT | flag::RDHUP,
            "the end is readable"
        );
        let listener = revents(requested(flag::IN), Condition::Listener { waiting: 2 });
        assert_eq!(u32::from(listener), flag::IN);
        assert_eq!(
            revents(requested(flag::IN), Condition::Listener { waiting: 0 }),
            0
        );
    }
}
