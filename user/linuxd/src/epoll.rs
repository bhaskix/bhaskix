// SPDX-License-Identifier: Apache-2.0
//! `epoll` for hosted programs — [RFC 0086](../../../docs/rfc/0086-the-motivating-workload.md)
//! step 4.
//!
//! What an interest set *means* — the operations, the packed event, the
//! edge-triggered watermark — is `bhaskix_personality::epoll`, host-tested.
//! This is where the sets live and how a caller waits on one.
//!
//! # How a wait waits
//!
//! Readiness is asked of the same places `poll` asks, and a hosted TCP stream
//! or listener of `bin/tcpd` besides (`stream::condition`). When nothing is
//! ready:
//!
//! - **A set of nothing but hosted streams parks on the TCP wake** `tcpd`
//!   rings on every connection's news, if no other thread holds it — with the
//!   caller's deadline armed on it for a bounded wait.
//! - **Anything else waits ten milliseconds at a time**, because a set naming
//!   a pipe or the console as well has no single notification that covers it.
//!   A Go program's netpoller registers a pipe or an `eventfd` of its own to
//!   interrupt itself, so this is the path it takes: correct, and slower than
//!   it will need to be. Stated here rather than discovered in step 5.
//!
//! # Never the sixteenth park
//!
//! The nucleus parks one hosted call **at most sixteen times** and then answers
//! the hosted thread `EAGAIN` itself, without asking this program. An
//! `epoll_wait` answered `EAGAIN` is not something a caller expects — Go's
//! runtime treats any error but `EINTR` from it as fatal (recalled from its
//! source, not read here). So each waiting thread's parks are counted and the
//! wait is answered **zero events** before the count reaches the nucleus's
//! limit: a wait for ever that returns early with nothing, which every caller
//! written against Linux's spurious wake-ups already loops on.
//!
//! # A set belongs to the domain that made it
//!
//! Linux shares an `epoll` instance across `fork`. Here a set is answered only
//! for the domain that created it, and a child that inherited the descriptor is
//! told `EINVAL` — because the set names descriptor *numbers*, and a number in
//! the child names the child's own descriptor, so sharing it would report one
//! process's readiness with another's data words. Refused rather than
//! half-shared, and no hosted program measured so far forks with one open.

use bhaskix_abi::adapter;
use bhaskix_personality::call::{Answer, PersonalityCall};
use bhaskix_personality::epoll::{
    self as rules, EVENT_BYTES, MAX_INTERESTS, Set, event_bytes, flag, parse_event, requested,
};
use bhaskix_personality::file::{Entry, Kind};
use bhaskix_personality::poll::{self, Condition};

use super::{REPLY_BLOCK_ON_RETRY, REPLY_BLOCK_ON_UNTIL, REPLY_VALUE, Wait, stream};

/// Sets at once, machine-wide.
const SETS: usize = 8;
/// Events one wait reports at most, whatever `maxevents` says. The rest are
/// reported by the next wait: an edge is only spent when it is reported.
const MAX_EVENTS: usize = 32;
/// Threads waiting at once whose parks are counted.
const WAITERS: usize = 8;
/// Parks before a wait is answered with nothing — below the nucleus's
/// sixteen, with room for the parks a signal delivery can add.
const PARKS_BEFORE_ANSWER: u32 = 12;
/// How long a wait that cannot park on a wake waits before it looks again.
const RETRY_NANOS: u64 = 10_000_000;
/// `ENFILE`, `EPERM`, `EFAULT`: from the build host's `errno` headers.
const ENFILE: i64 = -23;
const EPERM: i64 = -1;
const EFAULT: i64 = -14;

#[derive(Clone, Copy)]
struct Held {
    owner: u32,
    set: Set,
}

struct Table {
    sets: [Option<Held>; SETS],
    /// `(key, parks)` for each thread parked in a wait; a key of 0 is free.
    waiters: [(u64, u32); WAITERS],
}

static mut TABLE: Table = Table {
    sets: [None; SETS],
    waiters: [(0, 0); WAITERS],
};

fn table() -> &'static mut Table {
    // SAFETY: single-threaded by construction, as every table in this program:
    // it has one thread, which runs one call to completion before the next.
    unsafe { &mut *core::ptr::addr_of_mut!(TABLE) }
}

const fn waiter_key(domain: u32, thread: u32) -> u64 {
    ((domain as u64 + 1) << 32) | thread as u64
}

/// `epoll_create1(flags)`, and `epoll_create(size)` as `flags` of zero.
pub(crate) fn create(request: &PersonalityCall, flags: u64) -> Answer {
    if flags & !rules::CLOEXEC != 0 {
        return Answer::error(rules::errno::EINVAL);
    }
    let sets = &mut table().sets;
    let Some(index) = sets.iter().position(Option::is_none) else {
        return Answer::error(ENFILE);
    };
    let Some(process) = super::process_for(request.domain) else {
        return Answer::error(-11); // EAGAIN
    };
    let entry = Entry {
        handle: index as u64,
        inode: 0,
        kind: Kind::Epoll,
        close_on_exec: flags & rules::CLOEXEC != 0,
        offset: 0,
        size: 0,
        readable: true,
        writable: false,
    };
    match process.descriptors.insert(entry, 0) {
        Ok(descriptor) => {
            sets[index] = Some(Held {
                owner: request.domain,
                set: Set::new(),
            });
            Answer::ok(descriptor as u64)
        }
        Err(code) => Answer::error(code),
    }
}

/// The set `epfd` names, for this caller.
fn set_of(request: &PersonalityCall, epfd: u64) -> Result<usize, i64> {
    let Some(entry) = super::descriptor_row(request, epfd) else {
        return Err(rules::errno::EBADF);
    };
    if entry.kind != Kind::Epoll {
        return Err(rules::errno::EINVAL);
    }
    match table().sets.get(entry.handle as usize) {
        Some(Some(held)) if held.owner == request.domain => Ok(entry.handle as usize),
        // Inherited across `fork`: see the module note.
        _ => Err(rules::errno::EINVAL),
    }
}

/// `epoll_ctl(epfd, op, fd, event)`.
pub(crate) fn control(request: &PersonalityCall) -> Answer {
    let index = match set_of(request, request.first()) {
        Ok(index) => index,
        Err(code) => return Answer::error(code),
    };
    let op = request.second();
    let fd = request.third();
    let Some(target) = super::descriptor_row(request, fd) else {
        return Answer::error(rules::errno::EBADF);
    };
    match target.kind {
        // A regular file is always ready, and Linux refuses to watch one.
        Kind::File | Kind::Directory | Kind::Proc => return Answer::error(EPERM),
        // Linux nests sets; this does not answer a set's own readiness yet,
        // and watching one would be watching something that never fires.
        Kind::Epoll => return Answer::error(rules::errno::EINVAL),
        _ => {}
    }
    let (events, data) = if op == rules::op::DEL {
        (0, 0)
    } else {
        let mut bytes = [0u8; EVENT_BYTES];
        if !super::copy_in(request.domain, request.fourth(), &mut bytes) {
            return Answer::error(EFAULT);
        }
        parse_event(&bytes)
    };
    let own = request.first() as i32;
    let Some(Some(held)) = table().sets.get_mut(index) else {
        return Answer::error(rules::errno::EBADF);
    };
    match held.set.control(op, fd as i32, events, data, own) {
        Ok(()) => Answer::ok(0),
        Err(code) => Answer::error(code),
    }
}

/// `epoll_wait(epfd, events, maxevents, timeout)`, and `epoll_pwait` with its
/// signal mask ignored for the reason `answer_ppoll` gives.
pub(crate) fn wait(request: &PersonalityCall, timeout: Wait) -> (u64, Answer) {
    let key = waiter_key(request.domain, request.thread);
    // Whatever this thread parked on last time, it is back.
    stream::wake_returned(request.domain, request.thread);
    let _ = super::took_timed_wait(request.domain);

    let finish = |ready: usize, out: &[u8]| -> (u64, Answer) {
        forget_waiter(key);
        super::forget_deadline(request.domain);
        if ready > 0 && !super::copy_out(request.domain, request.second(), out) {
            return (REPLY_VALUE, Answer::error(EFAULT));
        }
        (REPLY_VALUE, Answer::ok(ready as u64))
    };

    let wanted = bhaskix_personality::call::int_arg(request.third());
    if wanted <= 0 {
        forget_waiter(key);
        return (REPLY_VALUE, Answer::error(rules::errno::EINVAL));
    }
    let limit = (wanted as usize).min(MAX_EVENTS);
    let index = match set_of(request, request.first()) {
        Ok(index) => index,
        Err(code) => {
            forget_waiter(key);
            return (REPLY_VALUE, Answer::error(code));
        }
    };

    // The interests, copied out first: asking a descriptor's condition calls
    // other services, and nothing here should be holding the set meanwhile.
    let mut watched = [(0i32, 0u32); MAX_INTERESTS];
    let mut count = 0;
    if let Some(Some(held)) = table().sets.get(index) {
        for interest in held.set.watched() {
            watched[count] = (interest.fd, interest.events);
            count += 1;
        }
    }

    let mut out = [0u8; MAX_EVENTS * EVENT_BYTES];
    let mut ready = 0;
    let mut only_streams = true;
    let mut console = None;
    for &(fd, events) in &watched[..count] {
        if ready == limit {
            break;
        }
        let (condition, news) = match super::descriptor_row(request, fd as u64) {
            Some(entry) if stream::is_stream(&entry) => stream::condition(&entry),
            Some(_) => {
                only_streams = false;
                (super::condition_of(request, fd as u64, &mut console), None)
            }
            None => (Condition::Unknown, None),
        };
        // `POLLNVAL` has no `epoll` spelling: a descriptor closed under the
        // set was forgotten by it, so one seen here is simply not ready.
        let level = u32::from(poll::revents(requested(events), condition))
            & (flag::IN | flag::PRI | flag::OUT | flag::ERR | flag::HUP | flag::RDHUP);
        let Some(Some(held)) = table().sets.get_mut(index) else {
            break;
        };
        let Some(bits) = held.set.report(fd, level, news) else {
            continue;
        };
        let data = held
            .set
            .watched()
            .find(|interest| interest.fd == fd)
            .map_or(0, |interest| interest.data);
        out[ready * EVENT_BYTES..(ready + 1) * EVENT_BYTES]
            .copy_from_slice(&event_bytes(bits, data));
        ready += 1;
    }

    if ready > 0 || timeout == Wait::Now {
        return finish(ready, &out[..ready * EVENT_BYTES]);
    }
    let deadline = match timeout {
        Wait::For(nanos) => match super::deadline_for(request.domain, nanos) {
            Some(deadline) => Some(deadline),
            // The wait is over, or this machine cannot time it.
            None => return finish(0, &[]),
        },
        _ => None,
    };
    let Some(parks) = note_park(key) else {
        // Nowhere to count this thread's parks, so it must not park at all.
        return finish(0, &[]);
    };
    if parks > PARKS_BEFORE_ANSWER {
        return finish(0, &[]);
    }
    if only_streams && stream::park_on_wake(request.domain, request.thread) {
        let wake = adapter::TCP_WAKE as u64;
        return match deadline {
            Some(deadline) => {
                super::park_deadline(deadline);
                (REPLY_BLOCK_ON_UNTIL, Answer::ok(wake))
            }
            None => (REPLY_BLOCK_ON_RETRY, Answer::ok(wake)),
        };
    }
    match super::park_until(request.domain, RETRY_NANOS) {
        Some(slot) => (REPLY_BLOCK_ON_RETRY, Answer::ok(slot)),
        None => finish(0, &[]),
    }
}

/// Counts one more park for `key`, answering the count, or `None` if there is
/// no room to count it.
fn note_park(key: u64) -> Option<u32> {
    let waiters = &mut table().waiters;
    let index = waiters
        .iter()
        .position(|waiter| waiter.0 == key)
        .or_else(|| waiters.iter().position(|waiter| waiter.0 == 0))?;
    let parks = if waiters[index].0 == key {
        waiters[index].1 + 1
    } else {
        1
    };
    waiters[index] = (key, parks);
    Some(parks)
}

fn forget_waiter(key: u64) {
    for waiter in &mut table().waiters {
        if waiter.0 == key {
            *waiter = (0, 0);
        }
    }
}

/// A domain -- or one thread of it -- will not come back to its wait.
pub(crate) fn abandon(domain: u32, thread: Option<u32>) {
    for waiter in &mut table().waiters {
        let same_domain = waiter.0 >> 32 == u64::from(domain) + 1;
        let same_thread = thread.is_none_or(|thread| waiter.0 & 0xffff_ffff == u64::from(thread));
        if waiter.0 != 0 && same_domain && same_thread {
            *waiter = (0, 0);
        }
    }
}

/// A set's last descriptor closed in the domain that owns it.
pub(crate) fn close(entry: &Entry, domain: u32) {
    if let Some(slot) = table().sets.get_mut(entry.handle as usize)
        && slot.is_some_and(|held| held.owner == domain)
    {
        *slot = None;
    }
}

/// A descriptor closed: no set of its domain watches it any longer, which is
/// what Linux does when the last reference to an open file goes.
pub(crate) fn forget_descriptor(domain: u32, fd: i32) {
    for held in table().sets.iter_mut().flatten() {
        if held.owner == domain {
            held.set.forget(fd);
        }
    }
}

/// A domain is gone: its sets with it.
pub(crate) fn forget_domain(domain: u32) {
    for slot in &mut table().sets {
        if slot.is_some_and(|held| held.owner == domain) {
            *slot = None;
        }
    }
}
