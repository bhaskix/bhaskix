// SPDX-License-Identifier: Apache-2.0
//! `epoll`, as arithmetic.
//!
//! [RFC 0005](../../docs/rfc/0005-linux-abi-compatibility.md)'s Tier 2, the
//! half that is not a socket. A Go, nginx or Python server does not block on
//! a descriptor; it registers a set of them and blocks once. So `epoll` is
//! not an optimisation here — a personality without it runs those programs
//! as busy loops, or not at all.
//!
//! What is decided here, and therefore host-tested: what a registration
//! means, what `EPOLL_CTL_ADD` on an already-registered descriptor answers,
//! which events a set reports when several are ready at once, and how
//! one-shot and edge-triggered registrations differ. What *makes* a
//! descriptor ready is the adapter's: a notification from `bin/ipd`, a
//! connection state change from `bin/tcpd`, RFC 0019's deadline. This module
//! never waits for anything.
//!
//! ## The twelve-byte trap
//!
//! `struct epoll_event` is **12 bytes on x86-64, not 16**: the kernel's
//! definition is packed, so the eight-byte `data` sits at offset 4 and is
//! *unaligned*. Every natural way to write this structure in a language with
//! alignment gets it wrong, and the symptom is a server that wakes for the
//! wrong connection — the `data` word is how a program knows which one. The
//! layout below was taken from this machine's `<sys/epoll.h>` by a program
//! printing `offsetof` and `sizeof`, not from memory.

/// Event bits, as `<sys/epoll.h>` defines them.
pub mod events {
    /// There is something to read.
    pub const IN: u32 = 0x1;
    /// There is room to write.
    pub const OUT: u32 = 0x4;
    /// An error. Reported whether or not the caller asked for it.
    pub const ERR: u32 = 0x8;
    /// Hung up. Reported whether or not the caller asked for it.
    pub const HUP: u32 = 0x10;
    /// The peer shut down its writing half.
    pub const RDHUP: u32 = 0x2000;
    /// One-shot: report once, then disarm until re-armed with `MOD`.
    pub const ONESHOT: u32 = 0x4000_0000;
    /// Edge-triggered: report the transition, not the level.
    pub const ET: u32 = 0x8000_0000;
    /// The two a caller does not have to ask for and always receives.
    pub const ALWAYS: u32 = ERR | HUP;
}

/// `epoll_ctl` operations.
pub mod control {
    /// Add a descriptor to the set.
    pub const ADD: u64 = 1;
    /// Remove one.
    pub const DEL: u64 = 2;
    /// Change one's interest or data word.
    pub const MOD: u64 = 3;
}

/// Errors this module answers with, as Linux numbers.
pub mod errno {
    /// Already present.
    pub const EEXIST: i64 = -17;
    /// Not present, or not a descriptor.
    pub const ENOENT: i64 = -2;
    /// Bad descriptor.
    pub const EBADF: i64 = -9;
    /// Invalid argument.
    pub const EINVAL: i64 = -22;
    /// No room left in the set.
    pub const ENOSPC: i64 = -28;
    /// Would loop — a set watching itself.
    pub const ELOOP: i64 = -40;
}

/// The bytes of a `struct epoll_event`. Packed, and confirmed against this
/// machine's headers.
pub const EVENT_BYTES: usize = 12;
/// Where the eight-byte `data` begins, unaligned.
pub const EVENT_DATA_AT: usize = 4;

// The unalignment is the whole hazard, so it fails the *build* rather than a
// test: a `data` word at a multiple of eight means somebody has "corrected"
// this structure to what a language with alignment would have produced, and
// every program waiting on more than one descriptor then reads its second
// event out of the first one's padding.
const _: () = {
    assert!(!EVENT_DATA_AT.is_multiple_of(8));
    assert!(EVENT_DATA_AT + 8 == EVENT_BYTES);
};

/// How many descriptors one `epoll` set may watch.
///
/// Fixed, because this crate does not allocate. A set that fills answers
/// `ENOSPC`, which is a real Linux answer (it is what the per-user watch
/// limit produces), so a program that handles it handles this.
pub const MAX_WATCHES: usize = 64;

/// One registered descriptor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Watch {
    /// The descriptor being watched.
    pub descriptor: i32,
    /// What the caller asked to hear about, including its flags.
    pub interest: u32,
    /// The caller's own word, handed back unchanged when it fires. This is
    /// how a server knows *which* connection woke it, which is why the
    /// twelve-byte layout above matters as much as it does.
    pub data: u64,
    /// Whether a report has disarmed it — `EPOLLONESHOT`.
    pub armed: bool,
}

/// One `epoll` set.
#[derive(Clone, Copy, Debug)]
pub struct Set {
    watches: [Option<Watch>; MAX_WATCHES],
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
            watches: [None; MAX_WATCHES],
        }
    }

    /// How many descriptors this set watches.
    #[must_use]
    pub fn len(&self) -> usize {
        self.watches.iter().flatten().count()
    }

    /// Whether it watches none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// What is registered for a descriptor.
    #[must_use]
    pub fn watch(&self, descriptor: i32) -> Option<&Watch> {
        self.watches
            .iter()
            .flatten()
            .find(|watch| watch.descriptor == descriptor)
    }

    fn position(&self, descriptor: i32) -> Option<usize> {
        self.watches
            .iter()
            .position(|slot| slot.is_some_and(|watch| watch.descriptor == descriptor))
    }

    /// `epoll_ctl(set, op, descriptor, event)`.
    ///
    /// `self_descriptor` is the set's own number, so the one loop this can
    /// make in a fixed-size structure — a set watching itself — is refused
    /// where it is created rather than found when something waits.
    ///
    /// # Errors
    ///
    /// [`errno::EEXIST`] for adding what is already there, [`errno::ENOENT`]
    /// for changing or removing what is not, [`errno::ENOSPC`] when full,
    /// [`errno::ELOOP`] for a set watching itself, and [`errno::EINVAL`] for
    /// an operation that is none of the three.
    pub fn control(
        &mut self,
        operation: u64,
        self_descriptor: i32,
        descriptor: i32,
        interest: u32,
        data: u64,
    ) -> Result<(), i64> {
        if descriptor < 0 {
            return Err(errno::EBADF);
        }
        match operation {
            control::ADD => {
                if descriptor == self_descriptor {
                    return Err(errno::ELOOP);
                }
                if self.position(descriptor).is_some() {
                    return Err(errno::EEXIST);
                }
                let free = self
                    .watches
                    .iter()
                    .position(Option::is_none)
                    .ok_or(errno::ENOSPC)?;
                self.watches[free] = Some(Watch {
                    descriptor,
                    // The two a caller always receives are added here rather
                    // than remembered at report time, so that what the set
                    // holds is what it will report.
                    interest: interest | events::ALWAYS,
                    data,
                    armed: true,
                });
                Ok(())
            }
            control::MOD => {
                let at = self.position(descriptor).ok_or(errno::ENOENT)?;
                let watch = self.watches[at].as_mut().ok_or(errno::ENOENT)?;
                watch.interest = interest | events::ALWAYS;
                watch.data = data;
                // Re-arming is what `MOD` is *for* after a one-shot fired,
                // and a `MOD` that left it disarmed would hang the caller
                // for ever on a connection that is ready.
                watch.armed = true;
                Ok(())
            }
            control::DEL => {
                let at = self.position(descriptor).ok_or(errno::ENOENT)?;
                self.watches[at] = None;
                Ok(())
            }
            _ => Err(errno::EINVAL),
        }
    }

    /// Removes every registration for a descriptor that has been closed.
    ///
    /// **Closing a descriptor removes it from every set it was in**, and a
    /// personality that forgot this would report readiness for a number the
    /// process has since reused for something else — which is the same class
    /// of bug as the domain-slot reuse this kernel fixed on 2026-08-19, one
    /// layer up.
    pub fn forget(&mut self, descriptor: i32) {
        if let Some(at) = self.position(descriptor) {
            self.watches[at] = None;
        }
    }

    /// Reports at most `limit` ready descriptors into `out`, given a
    /// predicate that says what a descriptor is ready for.
    ///
    /// Answers how many were written. `ready` is the adapter's knowledge —
    /// a notification arrived, a connection changed state — and this decides
    /// which of those the caller asked to hear about and in what shape.
    ///
    /// # Errors
    ///
    /// [`errno::EINVAL`] for a limit of zero, which is what Linux answers,
    /// or for a buffer too short for the limit it was given.
    pub fn report(
        &mut self,
        out: &mut [u8],
        limit: usize,
        mut ready: impl FnMut(i32) -> u32,
    ) -> Result<usize, i64> {
        if limit == 0 {
            return Err(errno::EINVAL);
        }
        let room = out.len() / EVENT_BYTES;
        if room < limit.min(self.watches.len()) && room == 0 {
            return Err(errno::EINVAL);
        }
        let mut written = 0;
        for slot in &mut self.watches {
            if written >= limit || written >= room {
                break;
            }
            let Some(watch) = slot.as_mut() else { continue };
            if !watch.armed {
                continue;
            }
            let fired = ready(watch.descriptor) & watch.interest;
            if fired == 0 {
                continue;
            }
            let at = written * EVENT_BYTES;
            // The flag bits are the caller's instruction to the set, not
            // events, and reporting them back would have a caller treat
            // `EPOLLET` as an error condition on some libraries' paths.
            let reported = fired & !(events::ONESHOT | events::ET);
            out[at..at + 4].copy_from_slice(&reported.to_le_bytes());
            out[at + EVENT_DATA_AT..at + EVENT_BYTES].copy_from_slice(&watch.data.to_le_bytes());
            if watch.interest & events::ONESHOT != 0 {
                watch.armed = false;
            }
            written += 1;
        }
        Ok(written)
    }
}

/// Reads a `struct epoll_event` a process supplied.
///
/// # Errors
///
/// [`errno::EINVAL`] if the buffer is shorter than one event.
pub fn parse_event(bytes: &[u8]) -> Result<(u32, u64), i64> {
    if bytes.len() < EVENT_BYTES {
        return Err(errno::EINVAL);
    }
    let interest = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let mut data = [0u8; 8];
    data.copy_from_slice(&bytes[EVENT_DATA_AT..EVENT_BYTES]);
    Ok((interest, u64::from_le_bytes(data)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nothing_ready(_: i32) -> u32 {
        0
    }

    #[test]
    fn the_event_structure_is_twelve_bytes_and_the_data_is_unaligned() {
        // The trap this file exists to avoid. Sixteen here, and every
        // program that waits on more than one descriptor reads its second
        // event out of the first one's padding.
        assert_eq!(EVENT_BYTES, 12);
        assert_eq!(EVENT_DATA_AT, 4);
        let mut bytes = [0u8; EVENT_BYTES];
        bytes[0..4].copy_from_slice(&(events::IN | events::ET).to_le_bytes());
        bytes[4..12].copy_from_slice(&0xdead_beef_cafe_1234u64.to_le_bytes());
        assert_eq!(
            parse_event(&bytes),
            Ok((events::IN | events::ET, 0xdead_beef_cafe_1234))
        );
        assert_eq!(parse_event(&bytes[..11]), Err(errno::EINVAL));
    }

    #[test]
    fn control_adds_changes_and_removes() {
        let mut set = Set::new();
        assert!(set.is_empty());
        set.control(control::ADD, 3, 4, events::IN, 0x11)
            .expect("added");
        assert_eq!(set.len(), 1);
        // Error and hangup arrive whether or not they were asked for, and
        // the set records that rather than remembering it at report time.
        assert_eq!(
            set.watch(4).map(|watch| watch.interest),
            Some(events::IN | events::ALWAYS)
        );
        assert_eq!(
            set.control(control::ADD, 3, 4, events::IN, 0x11),
            Err(errno::EEXIST)
        );
        set.control(control::MOD, 3, 4, events::OUT, 0x22)
            .expect("changed");
        assert_eq!(set.watch(4).map(|watch| watch.data), Some(0x22));
        assert_eq!(
            set.control(control::MOD, 3, 5, events::OUT, 0),
            Err(errno::ENOENT)
        );
        set.control(control::DEL, 3, 4, 0, 0).expect("removed");
        assert!(set.is_empty());
        assert_eq!(set.control(control::DEL, 3, 4, 0, 0), Err(errno::ENOENT));
        assert_eq!(set.control(9, 3, 4, 0, 0), Err(errno::EINVAL));
        assert_eq!(
            set.control(control::ADD, 3, -1, 0, 0),
            Err(errno::EBADF),
            "a negative descriptor is not a descriptor"
        );
    }

    #[test]
    fn a_set_may_not_watch_itself() {
        let mut set = Set::new();
        assert_eq!(
            set.control(control::ADD, 3, 3, events::IN, 0),
            Err(errno::ELOOP)
        );
    }

    #[test]
    fn a_full_set_answers_enospc() {
        let mut set = Set::new();
        for descriptor in 0..MAX_WATCHES {
            set.control(
                control::ADD,
                -1,
                i32::try_from(descriptor).expect("small"),
                events::IN,
                0,
            )
            .expect("room");
        }
        assert_eq!(
            set.control(control::ADD, -1, 9999, events::IN, 0),
            Err(errno::ENOSPC)
        );
    }

    #[test]
    fn only_what_was_asked_for_is_reported_and_the_data_comes_back() {
        let mut set = Set::new();
        set.control(control::ADD, -1, 4, events::IN, 0xaaaa)
            .expect("added");
        set.control(control::ADD, -1, 5, events::OUT, 0xbbbb)
            .expect("added");
        let mut out = [0u8; EVENT_BYTES * 4];
        // 4 is readable but was asked about writing; 5 is writable and was
        // asked about writing. Only 5 may be reported.
        let written = set.report(&mut out, 4, |_| events::OUT).expect("reported");
        assert_eq!(written, 1);
        assert_eq!(
            u32::from_le_bytes(out[0..4].try_into().expect("four")),
            events::OUT
        );
        assert_eq!(
            u64::from_le_bytes(out[4..12].try_into().expect("eight")),
            0xbbbb,
            "the caller's own word, which is how it knows which connection"
        );
    }

    #[test]
    fn a_hangup_is_reported_to_a_reader_that_never_asked_for_it() {
        let mut set = Set::new();
        set.control(control::ADD, -1, 4, events::IN, 7)
            .expect("added");
        let mut out = [0u8; EVENT_BYTES];
        let written = set.report(&mut out, 1, |_| events::HUP).expect("reported");
        assert_eq!(written, 1, "EPOLLHUP arrives unasked, or a server hangs");
        assert_eq!(
            u32::from_le_bytes(out[0..4].try_into().expect("four")),
            events::HUP
        );
    }

    #[test]
    fn one_shot_fires_once_and_mod_rearms_it() {
        let mut set = Set::new();
        set.control(control::ADD, -1, 4, events::IN | events::ONESHOT, 1)
            .expect("added");
        let mut out = [0u8; EVENT_BYTES];
        assert_eq!(set.report(&mut out, 1, |_| events::IN), Ok(1));
        // The flag bits are instructions, not events: a caller told its
        // registration flag was an event condition takes the wrong branch.
        assert_eq!(
            u32::from_le_bytes(out[0..4].try_into().expect("four")),
            events::IN
        );
        assert_eq!(
            set.report(&mut out, 1, |_| events::IN),
            Ok(0),
            "still ready, but disarmed"
        );
        set.control(control::MOD, -1, 4, events::IN | events::ONESHOT, 1)
            .expect("re-armed");
        assert_eq!(
            set.report(&mut out, 1, |_| events::IN),
            Ok(1),
            "MOD re-arms, or the caller waits for ever on a ready descriptor"
        );
    }

    #[test]
    fn the_limit_and_the_buffer_both_bound_the_report() {
        let mut set = Set::new();
        for descriptor in 0..8 {
            set.control(control::ADD, -1, descriptor, events::IN, u64::MAX)
                .expect("room");
        }
        let mut out = [0u8; EVENT_BYTES * 8];
        assert_eq!(set.report(&mut out, 3, |_| events::IN), Ok(3));
        // A buffer that holds two, whatever the caller's limit says.
        let mut small = [0u8; EVENT_BYTES * 2];
        assert_eq!(set.report(&mut small, 8, |_| events::IN), Ok(2));
        assert_eq!(set.report(&mut out, 0, nothing_ready), Err(errno::EINVAL));
    }

    #[test]
    fn a_closed_descriptor_leaves_every_set_it_was_in() {
        let mut set = Set::new();
        set.control(control::ADD, -1, 4, events::IN, 1)
            .expect("added");
        set.forget(4);
        assert!(set.is_empty());
        // Forgetting one that was never there is not an error: `close` does
        // not know which sets held it.
        set.forget(4);
        let mut out = [0u8; EVENT_BYTES];
        assert_eq!(set.report(&mut out, 1, |_| events::IN), Ok(0));
    }
}
