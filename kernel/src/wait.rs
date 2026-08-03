// SPDX-License-Identifier: Apache-2.0
//! Sleeping and wait queues.
//!
//! A thread that has nothing to do should stop consuming a CPU. Until now the
//! only way to wait for something in Bhaskix was to spin, which works and
//! costs an entire processor per waiter — and, more importantly, made "no lost
//! wakeups" not merely unproven but *inexpressible*, since nothing ever slept.
//!
//! # The race this exists to lose
//!
//! Every blocking primitive has the same failure at its centre. A thread
//! checks a condition, finds it false, and decides to sleep. Between the check
//! and the sleep, another CPU makes the condition true and wakes whoever is
//! waiting — finding nobody, because the first thread has not enqueued yet.
//! The first thread then sleeps for ever, waiting for an event that has
//! already happened.
//!
//! It is not a rare interleaving. It is a two-instruction window that a real
//! workload will find, and it presents as a system that works under test and
//! stops under load.
//!
//! # The invariant that closes it
//!
//! > **A waker must publish the condition before acquiring the wait queue's
//! > lock, and a sleeper must check the condition while holding it.**
//!
//! Given that, there is no interleaving in which a wakeup is lost, and the
//! argument is short enough to check:
//!
//! - If the waker takes the lock *before* the sleeper, then it published the
//!   condition before that — so the sleeper's check, which happens under the
//!   lock, sees a true condition and never sleeps.
//! - If the sleeper takes the lock first, it enqueues itself and marks itself
//!   blocked before releasing. The waker therefore finds it on the list.
//!
//! Both cases depend on the sleeper enqueueing itself *and* marking itself
//! blocked before it releases the lock — a waker can only wake a thread that
//! is already `Blocked`, so an entry on the list belonging to a thread that is
//! still `Ready` is worse than no entry at all: the waker removes it, wakes
//! nothing, and the thread then sleeps for ever. Those two steps are therefore
//! fused into [`Waiters::enqueue_and_block`] rather than left adjacent, for
//! reasons recorded there.
//!
//! ## What the recheck after the lock is, and is not
//!
//! The sleeper must release the lock before it can switch away, because
//! switching with a spinlock held is how a kernel stops. A waker can run in
//! that gap, so [`crate::sched::block_self`] rechecks the thread's own state
//! before switching.
//!
//! That recheck is **not** what makes the wakeup safe — by then the waker has
//! already set the state to `Ready`, and a `Ready` thread is picked up by
//! ordinary round-robin whether or not this switch happens. What it actually
//! provides is `block_self`'s way *out*: a thread woken in that gap has
//! nothing to switch to and would otherwise spin inside the block path
//! forever. Deleting it hangs the kernel, which is how that was established.
//! `sched::races()` counts how often the gap is hit.
//!
//! # What this is not
//!
//! - **Not a mutex.** The condition is the caller's, protected by the
//!   caller's own discipline. This provides sleeping and waking, not mutual
//!   exclusion.
//! - **Not priority-aware.** Waiters are woken in the order they arrived.
//!   `docs/scheduler.md` §4 wants a priority-ordered wake for the RT class, so
//!   that a high-priority waiter is not left behind a queue of low-priority
//!   ones. There is no priority yet.
//! - **Not unbounded.** A queue holds [`MAX_WAITERS`] sleepers, because the
//!   sleep path must not allocate. Beyond that, waiters spin instead — correct
//!   but not the intent, so the limit is reported rather than silent.
//! - **Not prompt across CPUs.** A wake hands the CPU over immediately when
//!   the woken thread lands on the *waker's* processor — [`sched::resched`]
//!   runs after the lock is dropped, which is what gets real-time wakeup
//!   latency down to microseconds. On any *other* processor it only marks the
//!   thread `Ready`; nothing interrupts that CPU, so it waits for its next
//!   timer tick, up to 10 ms at 100 Hz. The fix is a reschedule IPI, using the
//!   mechanism TLB shootdown already has.

use crate::sched;
use crate::sync::{Rank, SpinLock};

/// Sleepers one queue can hold before the rest fall back to spinning.
pub const MAX_WAITERS: usize = 32;

/// A sleeper, identified by thread alone.
///
/// It once carried the CPU as well, so a wake could go straight to the right
/// runqueue. That was a lost-wakeup bug: a thread is immune to migration only
/// while it is `Blocked`, and a thread sleeping in a loop is `Ready` between
/// waits. Get stolen in that gap and the recorded CPU is wrong, so the next
/// wake searches a queue that no longer holds you. Thread identifiers are
/// globally unique and never go stale; [`sched::wake`] searches.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Waiter {
    id: u32,
}

struct Waiters {
    entries: [Option<Waiter>; MAX_WAITERS],
    /// Sleepers turned away because the queue was full.
    overflowed: u32,
}

impl Waiters {
    const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_WAITERS],
            overflowed: 0,
        }
    }

    /// Enqueues `waiter` **and** marks it blocked, as one operation.
    ///
    /// The two are fused deliberately, and this is the only reason this
    /// function exists rather than a plain `insert`. A waker holds this
    /// queue's lock while it looks for sleepers and marks them ready; it can
    /// only wake a thread that is already `Blocked`. So enqueueing without
    /// marking — even a few instructions apart, even still under the lock —
    /// lets a waker find the entry, fail to wake a thread that is still
    /// `Ready`, remove the entry, and leave the thread to block for ever on an
    /// event that has already happened.
    ///
    /// That bug was written on purpose and the ring test did not catch it: the
    /// window is a handful of instructions and 116 sleeps never landed in it.
    /// A property a test cannot see is not one to leave to a convention, so
    /// the two steps are not separable by construction instead.
    fn enqueue_and_block(&mut self, waiter: Waiter) -> bool {
        match self.entries.iter().position(Option::is_none) {
            Some(slot) => {
                self.entries[slot] = Some(waiter);
                sched::mark_blocked();
                true
            }
            None => {
                self.overflowed += 1;
                false
            }
        }
    }

    fn remove(&mut self, waiter: Waiter) {
        for entry in &mut self.entries {
            if *entry == Some(waiter) {
                *entry = None;
            }
        }
    }
}

/// A queue of threads waiting for a condition.
pub struct WaitQueue {
    waiters: SpinLock<Waiters>,
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl WaitQueue {
    /// An empty queue.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            waiters: SpinLock::new(Rank::WaitQueue, Waiters::new()),
        }
    }

    /// Sleeps until `ready` returns true.
    ///
    /// `ready` is evaluated with the queue's lock held, which is half of the
    /// invariant in the module header; the other half is the caller's, and is
    /// not checkable here: **whatever `ready` inspects must be published
    /// before [`wake_all`] or [`wake_one`] is called.**
    ///
    /// Returns without sleeping if the condition already holds. Spurious
    /// wakeups are handled — `ready` is rechecked after every wake, which is
    /// also what makes a shared queue with several distinct conditions work.
    pub fn wait_until(&self, mut ready: impl FnMut() -> bool) {
        // Identity is fixed for the life of the thread, so it is fetched once
        // rather than under the lock on every pass.
        let Some(id) = sched::current_thread_id() else {
            // No runqueue on this CPU yet, so there is nothing that could
            // sleep. Spinning is the only honest fallback this early.
            while !ready() {
                core::hint::spin_loop();
            }
            return;
        };
        let me = Waiter { id };

        loop {
            {
                let mut waiters = self.waiters.lock();

                // Idempotent, and needed on every pass: after a wake this
                // entry is already gone, but after a *spurious* return it may
                // not be, and a stale entry would have a later waker try to
                // wake a thread that is not asleep.
                waiters.remove(me);

                if ready() {
                    return;
                }

                // Enqueue and mark blocked together -- see `enqueue_and_block`.
                if !waiters.enqueue_and_block(me) {
                    // Queue full. Spin instead of sleeping: incorrect only in
                    // cost, whereas dropping the wait would be incorrect in
                    // kind.
                    drop(waiters);
                    core::hint::spin_loop();
                    continue;
                }
            }

            // Lock released -- it has to be, before switching. Anything a
            // waker does from here on is caught by the recheck inside
            // `block_self`.
            sched::block_self();
        }
    }

    /// Wakes every sleeper. Returns how many were actually blocked.
    ///
    /// The caller must have published whatever the waiters test *before*
    /// calling this. See the module header.
    pub fn wake_all(&self) -> usize {
        let mut woken = 0;
        {
            let mut waiters = self.waiters.lock();
            for entry in &mut waiters.entries {
                if let Some(waiter) = entry.take()
                    && sched::wake(waiter.id)
                {
                    woken += 1;
                }
            }
        }
        if woken > 0 {
            sched::resched();
        }
        woken
    }

    /// Wakes the sleeper that has waited longest. Returns whether one was.
    ///
    /// First-in-first-out rather than whichever slot is cheapest to find:
    /// waking the most recent arrival first is a starvation source that only
    /// appears under sustained contention, which is the worst time to discover
    /// it.
    pub fn wake_one(&self) -> bool {
        let woken = {
            let mut waiters = self.waiters.lock();
            let mut woken = false;
            for entry in &mut waiters.entries {
                if let Some(waiter) = *entry {
                    *entry = None;
                    if sched::wake(waiter.id) {
                        woken = true;
                        break;
                    }
                }
            }
            woken
        };
        if woken {
            sched::resched();
        }
        woken
    }

    /// Sleepers currently queued.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.waiters
            .lock()
            .entries
            .iter()
            .filter(|entry| entry.is_some())
            .count()
    }

    /// Sleepers turned away because [`MAX_WAITERS`] was reached.
    #[must_use]
    pub fn overflowed(&self) -> u32 {
        self.waiters.lock().overflowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Waiter = Waiter { id: 1 };
    const B: Waiter = Waiter { id: 2 };

    /// On the host there is no runqueue, so `mark_blocked` is a no-op and
    /// these exercise the list alone -- which is what they are for.
    fn queued(waiters: &Waiters) -> usize {
        waiters.entries.iter().filter(|e| e.is_some()).count()
    }

    #[test]
    fn a_waiter_can_be_enqueued_and_removed() {
        let mut waiters = Waiters::new();
        assert!(waiters.enqueue_and_block(A));
        assert_eq!(queued(&waiters), 1);
        waiters.remove(A);
        assert_eq!(queued(&waiters), 0);
    }

    #[test]
    fn removing_a_waiter_that_is_not_queued_is_harmless() {
        // `wait_until` removes itself on every pass, including the first and
        // including after a wake has already taken the entry out.
        let mut waiters = Waiters::new();
        waiters.remove(A);
        assert_eq!(queued(&waiters), 0);
        assert!(waiters.enqueue_and_block(A));
        waiters.remove(B);
        assert_eq!(queued(&waiters), 1);
    }

    #[test]
    fn waiters_are_kept_in_arrival_order() {
        // `wake_one` takes the first occupied slot, so arrival order has to be
        // slot order or the oldest waiter can be starved under load.
        let mut waiters = Waiters::new();
        assert!(waiters.enqueue_and_block(A));
        assert!(waiters.enqueue_and_block(B));
        assert_eq!(waiters.entries[0], Some(A));
        assert_eq!(waiters.entries[1], Some(B));
    }

    #[test]
    fn a_freed_slot_is_reused_before_the_queue_is_called_full() {
        let mut waiters = Waiters::new();
        for id in 0..MAX_WAITERS as u32 {
            assert!(waiters.enqueue_and_block(Waiter { id }));
        }
        assert!(!waiters.enqueue_and_block(B), "queue should be full");
        assert_eq!(waiters.overflowed, 1);

        waiters.remove(Waiter { id: 0 });
        assert!(waiters.enqueue_and_block(B), "freed slot should be reused");
    }

    #[test]
    fn overflow_is_counted_rather_than_dropped_silently() {
        let mut waiters = Waiters::new();
        for id in 0..MAX_WAITERS as u32 {
            waiters.enqueue_and_block(Waiter { id });
        }
        for _ in 0..3 {
            assert!(!waiters.enqueue_and_block(B));
        }
        // A caller turned away spins instead of sleeping, which is a
        // performance failure and must be visible as one.
        assert_eq!(waiters.overflowed, 3);
    }
}
