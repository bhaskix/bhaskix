// SPDX-License-Identifier: Apache-2.0
//! `eventfd` for hosted programs — [RFC 0086](../../../docs/rfc/0086-the-motivating-workload.md)
//! step 5.
//!
//! The counter's rules are `bhaskix_personality::eventfd`, host-tested; this is
//! where the counters live and how a caller waits on one.
//!
//! # Waking
//!
//! - **A blocked `read` parks on a wake slot of its own**, claimed and held the
//!   way a pipe reader's is (see `HELD` in `main.rs`), and a `write` signals
//!   it. Go never does this -- its eventfd is non-blocking -- but a blocking
//!   read is what the call means.
//! - **A write also rings the TCP wake** when a thread holds it, because the
//!   thread holding it is parked in `epoll_wait` on a set this eventfd may be in.
//!   That is Go's `netpollBreak`: without this the wait it interrupts would not
//!   notice for up to ten milliseconds.
//!
//! # What is not Linux here, said
//!
//! - A **blocking write that would overflow** is answered `EAGAIN` rather than
//!   parked: reaching it takes a counter of `2^64 - 2`.
//! - A counter is **freed when the domain that made it closes its last
//!   descriptor or ends**. A child that inherited one across `fork` shares it
//!   while the parent keeps it, and holds a stale number afterwards: the same
//!   bound `epoll.rs` states, and no hosted program measured forks with one.

use bhaskix_abi::{adapter, method, syscall};
use bhaskix_personality::call::{Answer, PersonalityCall};
use bhaskix_personality::eventfd::{self as rules, Counter, Outcome};
use bhaskix_personality::file::{Entry, Kind};
use bhaskix_personality::poll::Condition;

use super::{ParkKind, REPLY_BLOCK_ON_RETRY, REPLY_VALUE, WAKE_SLOT, stream};

/// Counters at once, machine-wide.
const EVENTFDS: usize = 16;
const EFAULT: i64 = -14;
const EBADF: i64 = -9;
const ENFILE: i64 = -23;

#[derive(Clone, Copy)]
struct Held {
    owner: u32,
    counter: Counter,
    nonblocking: bool,
    /// The wake slot a blocked reader is parked on, plus one; 0 for none.
    waiter: u32,
}

static mut TABLE: [Option<Held>; EVENTFDS] = [None; EVENTFDS];

fn table() -> &'static mut [Option<Held>; EVENTFDS] {
    // SAFETY: single-threaded by construction, as every table in this program:
    // it has one thread, which runs one call to completion before the next.
    unsafe { &mut *core::ptr::addr_of_mut!(TABLE) }
}

/// `eventfd2(initval, flags)`, and `eventfd(initval)` with `flags` of zero.
pub(crate) fn create(request: &PersonalityCall, initial: u64, flags: u64) -> Answer {
    let (semaphore, nonblocking, close_on_exec) = match rules::plan(flags) {
        Ok(plan) => plan,
        Err(code) => return Answer::error(code),
    };
    let held = table();
    let Some(index) = held.iter().position(Option::is_none) else {
        return Answer::error(ENFILE);
    };
    let Some(process) = super::process_for(request.domain) else {
        return Answer::error(-11); // EAGAIN
    };
    let entry = Entry {
        handle: index as u64,
        inode: 0,
        kind: Kind::EventFd,
        close_on_exec,
        offset: 0,
        size: 0,
        readable: true,
        writable: true,
    };
    match process.descriptors.insert(entry, 0) {
        Ok(descriptor) => {
            held[index] = Some(Held {
                owner: request.domain,
                // `initval` is an `unsigned int`.
                counter: Counter::new(initial & 0xffff_ffff, semaphore),
                nonblocking,
                waiter: 0,
            });
            Answer::ok(descriptor as u64)
        }
        Err(code) => Answer::error(code),
    }
}

/// A `read` of an eventfd.
pub(crate) fn read(
    request: &PersonalityCall,
    index: usize,
    buffer: u64,
    count: u64,
) -> (u64, Answer) {
    let returning = super::take_slot(ParkKind::EventFd, request.domain, request.thread);
    let Some(Some(held)) = table().get_mut(index) else {
        if let Some(slot) = returning {
            super::release_wake(slot);
        }
        return (REPLY_VALUE, Answer::error(EBADF));
    };
    match held.counter.read(count) {
        Outcome::Done(value) => {
            if let Some(slot) = returning {
                super::release_wake(slot);
            }
            if !super::copy_out(request.domain, buffer, &value.to_le_bytes()) {
                return (REPLY_VALUE, Answer::error(EFAULT));
            }
            (REPLY_VALUE, Answer::ok(8))
        }
        Outcome::Refused(code) => {
            if let Some(slot) = returning {
                super::release_wake(slot);
            }
            (REPLY_VALUE, Answer::error(code))
        }
        Outcome::Wait if held.nonblocking => {
            if let Some(slot) = returning {
                super::release_wake(slot);
            }
            (REPLY_VALUE, Answer::error(rules::errno::EAGAIN))
        }
        Outcome::Wait => {
            let slot = match returning {
                Some(slot) => slot,
                None => match super::claim_wake() {
                    Some(slot) => slot,
                    None => return (REPLY_VALUE, Answer::error(rules::errno::EAGAIN)),
                },
            };
            held.waiter = slot as u32 + 1;
            super::hold_slot(ParkKind::EventFd, request.domain, request.thread, slot);
            (REPLY_BLOCK_ON_RETRY, Answer::ok(WAKE_SLOT + slot as u64))
        }
    }
}

/// A `write` to an eventfd.
pub(crate) fn write(request: &PersonalityCall, index: usize, buffer: u64, count: u64) -> Answer {
    let mut word = [0u8; 8];
    if count >= 8 && !super::copy_in(request.domain, buffer, &mut word) {
        return Answer::error(EFAULT);
    }
    let Some(Some(held)) = table().get_mut(index) else {
        return Answer::error(EBADF);
    };
    match held.counter.write(count, u64::from_le_bytes(word)) {
        Outcome::Done(written) => {
            // **The wakes come after the count**, for the reason
            // `write_to_pipe` gives: a reader woken first would find zero.
            if let Some(slot) = held.waiter.checked_sub(1) {
                held.waiter = 0;
                let _ = super::call(
                    syscall::INVOKE,
                    WAKE_SLOT + u64::from(slot),
                    method::SIGNAL,
                    [0; 4],
                );
            }
            if stream::wake_is_held() {
                let _ = super::call(
                    syscall::INVOKE,
                    adapter::TCP_WAKE as u64,
                    method::SIGNAL,
                    [0; 4],
                );
            }
            Answer::ok(written)
        }
        Outcome::Refused(code) => Answer::error(code),
        // See the module note: an overflow is answered, never parked.
        Outcome::Wait => Answer::error(rules::errno::EAGAIN),
    }
}

/// What an eventfd descriptor is doing, for `poll`, `select` and `epoll`.
pub(crate) fn condition(entry: &Entry) -> Condition {
    match table().get(entry.handle as usize) {
        Some(Some(held)) => Condition::EventFd {
            readable: held.counter.readable(),
            writable: held.counter.writable(),
        },
        _ => Condition::Unknown,
    }
}

/// An eventfd's last descriptor closed in the domain that made it.
pub(crate) fn close(entry: &Entry, domain: u32) {
    if let Some(slot) = table().get_mut(entry.handle as usize)
        && slot.is_some_and(|held| held.owner == domain)
    {
        *slot = None;
    }
}

/// A domain is gone: its counters with it.
pub(crate) fn forget_domain(domain: u32) {
    for slot in table().iter_mut() {
        if slot.is_some_and(|held| held.owner == domain) {
            *slot = None;
        }
    }
}

/// A wake slot given back by a reader that will never return: nothing may
/// signal it on that reader's behalf again.
pub(crate) fn forget_waiter_slot(slot: usize) {
    for held in table().iter_mut().flatten() {
        if held.waiter == slot as u32 + 1 {
            held.waiter = 0;
        }
    }
}
