// SPDX-License-Identifier: Apache-2.0
//! Notifications: one word of pending bits, and a thread waiting for them.
//!
//! [RFC 0010](../../../docs/rfc/0010-notifications.md), accepted. **Signal**
//! never blocks and may be called from an interrupt handler; **wait** blocks
//! until the word is non-zero and then takes all of it. Signals coalesce, so
//! two before a wait are one wake — which is what makes this a fixed-size
//! object rather than a queue, and therefore safe to signal from a handler
//! that must not allocate.
//!
//! # Nothing here takes a lock on the signal path
//!
//! Every field an interrupt handler touches is an atomic, and the one lock in
//! this module is taken only to create and destroy. A waiter *list* would need
//! a lock; a lock taken from a handler must be `try_lock`; and a `try_lock`
//! that fails on a wake is a lost wakeup — the bug this project has now made
//! twice. Hence RFC 0010's decision: **at most one waiter, refused rather than
//! queued.**
//!
//! # Why no wakeup can be lost
//!
//! The same ordering `input` states in full and M4-09 established: the waiter
//! marks itself blocked *before* it looks at the word, so a signal arriving in
//! between is found by the look rather than lost. The signal publishes its
//! bits *before* it wakes, so a waiter woken by it cannot look and find
//! nothing.
//!
//! # The badge is a bitmask
//!
//! For an endpoint a badge identifies a caller; here it identifies a *source*,
//! because it is OR-ed into the word. One notification therefore distinguishes
//! up to 64 senders, and the sixty-fifth aliases onto an existing bit — a
//! choice the granter makes when it sets the badge, which is the right place
//! for it. A badge of zero is refused: a signal that sets no bits is a wake
//! that says nothing.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::sync::{Rank, SpinLock};

/// Notifications the kernel can have at once.
///
/// Fixed, because the signal path indexes this array from an interrupt
/// handler and must not chase an allocation.
pub const MAX_NOTIFICATIONS: usize = 32;

/// Names a notification, with the generation that was current when it was
/// named. A stale name does not address a reused slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NotificationId {
    index: u32,
    generation: u32,
}

impl NotificationId {
    /// The slot this names, for reporting.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// The generation, for storing alongside the index.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// Rebuilds a name from its parts.
    ///
    /// `pub(crate)` and not public: an interrupt handler cannot hold a
    /// `NotificationId` behind a lock, so it keeps the two halves in atomics
    /// and reassembles them. Nothing outside the kernel may construct one,
    /// because a constructible name would be a forgeable one — and the
    /// generation check in `resolve` is what makes a *stale* one harmless
    /// rather than a way to address somebody else's notification.
    pub(crate) const fn from_parts(index: u32, generation: u32) -> Self {
        Self { index, generation }
    }
}

/// Why an operation on a notification failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NotifyError {
    /// No free slot.
    Exhausted,
    /// The notification has been destroyed, or the name is stale.
    Gone,
    /// Another thread is already waiting on it.
    Congested,
    /// A badge of zero says nothing.
    EmptyBadge,
}

/// One notification. Every field the signal path touches is atomic.
struct Slot {
    /// Badge bits signalled and not yet taken.
    pending: AtomicU64,
    /// The one thread blocked in [`wait`], or zero.
    waiter: AtomicU32,
    /// Bumped on destruction, so a stale [`NotificationId`] cannot address a
    /// reused slot.
    generation: AtomicU32,
    live: AtomicBool,
}

impl Slot {
    const fn new() -> Self {
        Self {
            pending: AtomicU64::new(0),
            waiter: AtomicU32::new(0),
            generation: AtomicU32::new(0),
            live: AtomicBool::new(false),
        }
    }
}

static SLOTS: [Slot; MAX_NOTIFICATIONS] = [const { Slot::new() }; MAX_NOTIFICATIONS];

/// Serialises creation and destruction only. The signal path never takes it.
static ALLOCATION: SpinLock<()> = SpinLock::new(Rank::Notifications, ());

/// Signals delivered, and signals that found no waiter.
static SIGNALS: AtomicU64 = AtomicU64::new(0);
static UNWAITED: AtomicU64 = AtomicU64::new(0);
/// Waiters woken because their notification was destroyed under them.
static STRANDED: AtomicU64 = AtomicU64::new(0);

/// Creates a notification.
///
/// # Errors
///
/// [`NotifyError::Exhausted`] when every slot is live.
pub fn create() -> Result<NotificationId, NotifyError> {
    let _guard = ALLOCATION.lock();
    for (index, slot) in SLOTS.iter().enumerate() {
        if slot.live.load(Ordering::Acquire) {
            continue;
        }
        slot.pending.store(0, Ordering::Relaxed);
        slot.waiter.store(0, Ordering::Relaxed);
        // Live last: it is what every other path takes as "this slot is
        // real", so it must not be visible before the state it describes.
        slot.live.store(true, Ordering::Release);
        return Ok(NotificationId {
            index: index as u32,
            generation: slot.generation.load(Ordering::Acquire),
        });
    }
    Err(NotifyError::Exhausted)
}

/// Destroys a notification, waking whoever was waiting on it.
///
/// Returns whether a waiter had to be stranded. A thread blocked on an object
/// that no longer exists must not stay blocked — the same rule `ipc::destroy`
/// follows, and the same counter, because a thread woken by a teardown is a
/// fact worth seeing rather than discovering.
pub fn destroy(id: NotificationId) -> bool {
    let _guard = ALLOCATION.lock();
    let Some(slot) = resolve(id) else {
        return false;
    };

    slot.live.store(false, Ordering::Release);
    slot.generation.fetch_add(1, Ordering::AcqRel);
    slot.pending.store(0, Ordering::Relaxed);

    let waiter = slot.waiter.swap(0, Ordering::AcqRel);
    if waiter != 0 {
        STRANDED.fetch_add(1, Ordering::Relaxed);
        crate::sched::wake(waiter);
        return true;
    }
    false
}

fn resolve(id: NotificationId) -> Option<&'static Slot> {
    let slot = SLOTS.get(id.index as usize)?;
    if !slot.live.load(Ordering::Acquire) {
        return None;
    }
    if slot.generation.load(Ordering::Acquire) != id.generation {
        return None;
    }
    Some(slot)
}

/// Whether a notification is live.
#[must_use]
pub fn live(id: NotificationId) -> bool {
    resolve(id).is_some()
}

/// ORs `badge` into the pending word and wakes the waiter, if there is one.
///
/// **Callable from an interrupt handler.** It takes no lock, allocates
/// nothing, and the wake it performs is `sched::wake_from_interrupt`, which
/// records what it could not deliver rather than waiting for a runqueue lock
/// the interrupted thread may be holding.
///
/// # Errors
///
/// [`NotifyError::Gone`] if the notification has been destroyed, or
/// [`NotifyError::EmptyBadge`] for a badge of zero.
pub fn signal(id: NotificationId, badge: u64) -> Result<(), NotifyError> {
    if badge == 0 {
        return Err(NotifyError::EmptyBadge);
    }
    let slot = resolve(id).ok_or(NotifyError::Gone)?;

    // Bits first, waiter second. A reader woken before the bits were published
    // would look, find nothing, and sleep again holding an event that had
    // already happened.
    slot.pending.fetch_or(badge, Ordering::Release);
    SIGNALS.fetch_add(1, Ordering::Relaxed);

    let waiter = slot.waiter.load(Ordering::Acquire);
    if waiter == 0 {
        UNWAITED.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }
    crate::sched::wake_from_interrupt(waiter);
    Ok(())
}

/// Takes the pending word without blocking. Zero means nothing is pending.
#[must_use]
pub fn poll(id: NotificationId) -> u64 {
    resolve(id).map_or(0, |slot| slot.pending.swap(0, Ordering::AcqRel))
}

/// Blocks until the word is non-zero, then takes all of it.
///
/// # Errors
///
/// [`NotifyError::Congested`] if another thread is already waiting — RFC 0010
/// allows one, and refuses rather than queueing. [`NotifyError::Gone`] if the
/// notification is destroyed while waiting.
pub fn wait(id: NotificationId) -> Result<u64, NotifyError> {
    let slot = resolve(id).ok_or(NotifyError::Gone)?;
    let me = crate::sched::current_thread_id().unwrap_or(0);

    // Claim the waiter slot. A second waiter is refused, and the refusal is
    // atomic: two threads racing here cannot both believe they own it.
    slot.waiter
        .compare_exchange(0, me, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| NotifyError::Congested)?;

    let outcome = loop {
        // Mark blocked first, look second. A signal landing in between is
        // found by the look; one landing after it finds a thread that is
        // already `Blocked` and wakes it.
        crate::sched::mark_blocked();

        let word = slot.pending.swap(0, Ordering::AcqRel);
        if word != 0 {
            crate::sched::cancel_block();
            break Ok(word);
        }
        if !slot.live.load(Ordering::Acquire) {
            crate::sched::cancel_block();
            break Err(NotifyError::Gone);
        }
        crate::sched::block_self();
    };

    // Released whichever way this ended, or the next waiter is refused for
    // ever by a thread that has gone.
    slot.waiter.store(0, Ordering::Release);
    outcome
}

/// Blocks once, and returns whatever is pending afterwards — possibly nothing.
///
/// [`wait`] loops until the word is non-zero, which is what a caller with no
/// deadline wants. A driver has a deadline: a device that stops answering must
/// not stop the kernel. This returns after a *single* block, so a caller can
/// arm a timer, block, and find out whether it was the device or the clock
/// that woke it.
///
/// RFC 0008 and RFC 0010 both record "a wait needs a timeout eventually" as
/// unresolved. This is not that answer — it is the smaller thing that lets a
/// caller build one out of the timer it already has, without the kernel taking
/// a position on whose policy the deadline is.
///
/// # Errors
///
/// As [`wait`].
pub fn wait_once(id: NotificationId) -> Result<u64, NotifyError> {
    let slot = resolve(id).ok_or(NotifyError::Gone)?;
    let me = crate::sched::current_thread_id().unwrap_or(0);

    slot.waiter
        .compare_exchange(0, me, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| NotifyError::Congested)?;

    // Mark blocked first, look second -- the rule, once more.
    crate::sched::mark_blocked();
    let word = slot.pending.swap(0, Ordering::AcqRel);
    if word != 0 {
        crate::sched::cancel_block();
        slot.waiter.store(0, Ordering::Release);
        return Ok(word);
    }
    crate::sched::block_self();

    let word = slot.pending.swap(0, Ordering::AcqRel);
    slot.waiter.store(0, Ordering::Release);
    if !slot.live.load(Ordering::Acquire) {
        return Err(NotifyError::Gone);
    }
    Ok(word)
}

/// Signals delivered, signals that found nobody waiting, and waiters stranded
/// by a destruction.
#[must_use]
pub fn statistics() -> (u64, u64, u64) {
    (
        SIGNALS.load(Ordering::Relaxed),
        UNWAITED.load(Ordering::Relaxed),
        STRANDED.load(Ordering::Relaxed),
    )
}

/// How many notifications are live.
#[must_use]
pub fn count() -> usize {
    SLOTS
        .iter()
        .filter(|slot| slot.live.load(Ordering::Acquire))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test, because the slots are a global and cargo runs tests in
    /// parallel. A shared arena raced by two tests is exactly the failure that
    /// gets blamed on something else.
    #[test]
    fn the_object_behaves_as_rfc_0010_specifies() {
        let id = create().expect("a fresh table has room");
        assert!(live(id));
        assert_eq!(poll(id), 0, "nothing signalled yet");

        // Signals accumulate when nobody is waiting, and coalesce.
        assert_eq!(signal(id, 0b0001), Ok(()));
        assert_eq!(signal(id, 0b0100), Ok(()));
        assert_eq!(signal(id, 0b0001), Ok(()), "the same bit again");
        assert_eq!(
            poll(id),
            0b0101,
            "three signals, one word, every bit that was set"
        );
        assert_eq!(poll(id), 0, "and taking it clears it");

        // A badge of zero is refused: a wake that says nothing is
        // indistinguishable from a spurious one.
        assert_eq!(signal(id, 0), Err(NotifyError::EmptyBadge));

        // Destruction invalidates the name, and a stale name does not address
        // whatever takes the slot next.
        assert!(!destroy(id), "nobody was waiting");
        assert!(!live(id));
        assert_eq!(signal(id, 1), Err(NotifyError::Gone));
        assert_eq!(poll(id), 0);

        let reused = create().expect("the slot is free again");
        assert_ne!(reused, id, "a new generation is a different name");
        assert_eq!(
            signal(id, 1),
            Err(NotifyError::Gone),
            "the old name is dead"
        );
        assert_eq!(signal(reused, 1), Ok(()));
        assert_eq!(poll(reused), 1);
        destroy(reused);
    }

    #[test]
    fn every_slot_can_be_used_and_exhaustion_is_reported() {
        let mut held = alloc::vec::Vec::new();
        while let Ok(id) = create() {
            held.push(id);
            if held.len() > MAX_NOTIFICATIONS {
                break;
            }
        }
        assert_eq!(held.len(), MAX_NOTIFICATIONS, "no more, and no fewer");
        assert_eq!(create(), Err(NotifyError::Exhausted));

        for id in held {
            destroy(id);
        }
        assert_eq!(count(), 0);
    }
}
