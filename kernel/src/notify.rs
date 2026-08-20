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
    /// The one thread that has **bound** this notification, or zero.
    ///
    /// RFC 0010 question 1, answered 2026-08-13. A bound thread is not waiting
    /// *here* — it is blocked in `ipc::recv` on an endpoint, and wants to be
    /// woken by whichever arrives first. Kept beside [`Slot::waiter`] rather
    /// than sharing it because they are woken for different reasons and a
    /// thread may not be both.
    bound: AtomicU32,
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
            bound: AtomicU32::new(0),
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

    // RFC 0026 step 5: every signal is a crossing — the doorbells and wakes
    // each cross-domain hop rides — and emit is legal here even from
    // interrupt context, which signalling explicitly is.
    let mut crossing = [0u8; 16];
    crossing[..4].copy_from_slice(&id.index().to_le_bytes());
    crossing[8..].copy_from_slice(&badge.to_le_bytes());
    let domain = crate::telemetry::domain_hint();
    crate::telemetry::emit(
        bhaskix_telemetry::EventClass::Syscall,
        bhaskix_telemetry::schema::SIGNAL.id,
        domain,
        &crossing,
    );

    // The bound thread, if any, is blocked on an *endpoint* and wants waking for
    // this. Woken before the direct waiter is looked at, and by the same
    // lock-free call, because a lock here would have to be `try_lock` and a
    // failed `try_lock` on a wake is a lost wakeup -- this RFC's own reason for
    // allowing one waiter.
    let bound = slot.bound.load(Ordering::Acquire);
    if bound != 0 {
        crate::sched::wake_from_interrupt(bound);
    }

    let waiter = slot.waiter.load(Ordering::Acquire);
    {
        let at = SIGNAL_AT.fetch_add(1, Ordering::Relaxed) as usize;
        SIGNAL_TRACE[at % SIGNAL_TRACE_LEN].store(
            u64::from(id.index()) << 32 | u64::from(waiter),
            Ordering::Relaxed,
        );
    }
    if waiter == 0 {
        UNWAITED.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }
    crate::sched::wake_from_interrupt(waiter);
    Ok(())
}

/// The last few signals, as `(notification, waiter at the time)`.
///
/// `UNWAITED` says how often a signal found nobody waiting; it cannot say
/// *which* notification, and with a console and a block device both signalling
/// that is the whole question. A waiter of zero here is a signal that arrived
/// before anyone asked for it — benign if the bits are collected afterwards,
/// and the reason a wait hangs if they are not.
static SIGNAL_TRACE: [AtomicU64; SIGNAL_TRACE_LEN] =
    [const { AtomicU64::new(u64::MAX) }; SIGNAL_TRACE_LEN];
static SIGNAL_AT: AtomicU64 = AtomicU64::new(0);

const SIGNAL_TRACE_LEN: usize = 12;

/// Replays the signal ring, oldest first, as `(notification, waiter)`.
pub fn replay_signals(mut visit: impl FnMut(u32, u32)) {
    let at = SIGNAL_AT.load(Ordering::Relaxed) as usize;
    let first = at.saturating_sub(SIGNAL_TRACE_LEN);
    for index in first..at {
        let packed = SIGNAL_TRACE[index % SIGNAL_TRACE_LEN].load(Ordering::Relaxed);
        if packed == u64::MAX {
            continue;
        }
        visit((packed >> 32) as u32, packed as u32);
    }
}

/// Names a notification with a capability, so it can be granted to a domain.
///
/// A delegated driver needs one to bind its interrupt to: RFC 0011's `BIND`
/// takes the notification the holder wants signalled, and a domain can only
/// name one it holds.
///
/// # Errors
///
/// [`NotifyError::Gone`] if it has been destroyed, or [`NotifyError::Exhausted`]
/// if the capability arena is full.
pub fn name(id: NotificationId) -> Result<crate::cap::SlotRef, NotifyError> {
    if resolve(id).is_none() {
        return Err(NotifyError::Gone);
    }
    let identity = u64::from(id.index()) | (u64::from(id.generation()) << 32);
    crate::cap::with_arena(|arena| {
        arena.insert_root(
            crate::cap::ObjectRef::new(crate::cap::ObjectKind::Notification, identity),
            crate::cap::Rights::ALL,
            0,
        )
    })
    .map_err(|_| NotifyError::Exhausted)
}

/// Deadlines the kernel can have armed at once.
///
/// Fixed, like every other table this system exposes to something it does not
/// control: a program that could make the kernel allocate by asking for another
/// timer would hold a denial of service dressed as a feature. Full is a
/// refusal.
///
/// **Fewer than there are notifications**, and deliberately: most notifications
/// never carry a deadline — a device's interrupt and a ring's doorbell are
/// signalled by something that already knows when — and this table is scanned
/// where the timer interrupt runs, so its length is a cost paid on every tick.
///
/// **RFC 0019 step 1.** The arithmetic only — nothing arms these from a system
/// call yet, and nothing expires them from the timer interrupt. That is step 2,
/// and keeping them apart is what lets every rule below be tested on the host
/// with no kernel running.
pub const MAX_DEADLINES: usize = 16;

/// One armed deadline: a notification, and when it should be signalled.
struct Armed {
    /// The notification's index, plus one. Zero means this slot is free.
    ///
    /// Plus one because index zero is a real notification, and a table whose
    /// "empty" and "the first one" are the same value is a table that arms a
    /// timer for somebody who did not ask.
    who: AtomicU32,
    /// The generation that was current when it was armed.
    ///
    /// A notification can be destroyed and its slot reused while a deadline is
    /// armed against it. Without this the timer would fire at whoever took the
    /// slot next, which is the same mistake `NotificationId` exists to prevent
    /// one level up.
    generation: AtomicU32,
    /// When to signal, on the same monotonic scale `rdtsc` reads.
    deadline: AtomicU64,
    /// The bits to signal with, taken from the badge of the capability that
    /// armed it.
    ///
    /// **Recorded at arming rather than chosen at expiry**, because by the time
    /// this fires the caller is gone and the kernel has no business inventing a
    /// source. It is the same rule `SIGNAL` follows: the bits say who, and the
    /// holder did not pick them.
    badge: AtomicU64,
}

impl Armed {
    const fn new() -> Self {
        Self {
            who: AtomicU32::new(0),
            generation: AtomicU32::new(0),
            deadline: AtomicU64::new(0),
            badge: AtomicU64::new(0),
        }
    }
}

static DEADLINES: [Armed; MAX_DEADLINES] = [const { Armed::new() }; MAX_DEADLINES];

/// Arms `id` to be signalled at `deadline`, replacing any deadline it has.
///
/// **A second arming replaces the first**, which is the opposite of the
/// second-waiter rule and deliberately so: two waiters each want a wake and
/// only one can have it, whereas re-arming is how every timer user in practice
/// says "not then, this instead".
///
/// # Errors
///
/// [`NotifyError::Gone`] if the notification is not live, and
/// [`NotifyError::Exhausted`] if every slot is armed for somebody else.
pub fn arm(id: NotificationId, deadline: u64, badge: u64) -> Result<(), NotifyError> {
    if resolve(id).is_none() {
        return Err(NotifyError::Gone);
    }
    let want = id.index() + 1;

    // Replace first, so a caller re-arming does not consume a second slot and
    // then find the table full of its own timers.
    for slot in &DEADLINES {
        if slot.who.load(Ordering::Acquire) == want
            && slot.generation.load(Ordering::Acquire) == id.generation()
        {
            slot.badge.store(badge, Ordering::Release);
            slot.deadline.store(deadline, Ordering::Release);
            return Ok(());
        }
    }

    for slot in &DEADLINES {
        if slot
            .who
            .compare_exchange(0, want, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            slot.generation.store(id.generation(), Ordering::Release);
            slot.badge.store(badge, Ordering::Release);
            slot.deadline.store(deadline, Ordering::Release);
            return Ok(());
        }
    }
    Err(NotifyError::Exhausted)
}

/// Forgets any deadline armed for `id`. Whether one was armed is the answer.
pub fn disarm(id: NotificationId) -> bool {
    let want = id.index() + 1;
    let mut found = false;
    for slot in &DEADLINES {
        if slot.who.load(Ordering::Acquire) == want
            && slot.generation.load(Ordering::Acquire) == id.generation()
        {
            slot.deadline.store(0, Ordering::Release);
            slot.who.store(0, Ordering::Release);
            found = true;
        }
    }
    found
}

/// Hands every deadline that has passed to `visit`, and clears it.
///
/// **`now` is compared with `>=`, and never the other way round.** A timer that
/// fires early is a bug that looks like success: the waiter wakes, finds what it
/// was waiting for has not happened, and goes back to sleep — or worse, acts.
/// "Not before the deadline" is the half of the promise correctness rests on.
///
/// Cleared before `visit` is called, so a handler that arms a new deadline for
/// the same notification does not have it taken away again on the way out.
pub fn expire(now: u64, mut visit: impl FnMut(NotificationId, u64)) {
    for slot in &DEADLINES {
        let who = slot.who.load(Ordering::Acquire);
        if who == 0 || slot.deadline.load(Ordering::Acquire) > now {
            continue;
        }
        let generation = slot.generation.load(Ordering::Acquire);
        let badge = slot.badge.load(Ordering::Acquire);

        // **Claimed, not merely cleared.** This runs from the timer interrupt
        // on every processor, so two of them can reach the same expired slot at
        // once. A plain store would let both fire it, and a timer that fires
        // twice is a retransmission nobody asked for. Whoever wins the exchange
        // owns the wake; the loser moves on.
        if slot
            .who
            .compare_exchange(who, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            continue;
        }
        slot.deadline.store(0, Ordering::Release);
        visit(NotificationId::from_parts(who - 1, generation), badge);
    }
}

/// The soonest armed deadline, if any.
///
/// **The tickless path needs this or the promise is worthless.** Expiry runs on
/// the timer interrupt, and a processor with nothing else to do arms for its own
/// backstop — a whole second. A deadline armed for twenty milliseconds then
/// fired after a hundred and forty, which is "not before the deadline" kept to
/// the letter and useless in practice.
#[must_use]
pub fn earliest_deadline() -> Option<u64> {
    DEADLINES
        .iter()
        .filter(|slot| slot.who.load(Ordering::Acquire) != 0)
        .map(|slot| slot.deadline.load(Ordering::Acquire))
        .min()
}

/// How many deadlines are armed, for reporting.
#[must_use]
pub fn armed_deadlines() -> usize {
    DEADLINES
        .iter()
        .filter(|slot| slot.who.load(Ordering::Acquire) != 0)
        .count()
}

/// Binds this notification to `thread`, so a blocking receive also wakes for it.
///
/// RFC 0010 question 1. Returns `false` if the notification is gone or already
/// bound to a different thread — **refused rather than replaced**, because
/// substituting one silently loses whoever was relying on it.
///
/// # Errors
///
/// `false` on a gone or already-bound notification.
pub fn bind_to(id: NotificationId, thread: u32) -> bool {
    if thread == 0 {
        return false;
    }
    let Some(slot) = resolve(id) else {
        return false;
    };
    slot.bound
        .compare_exchange(0, thread, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
        || slot.bound.load(Ordering::Acquire) == thread
}

/// Forgets every binding `thread` held. Called when a thread stops.
///
/// A binding outliving its thread is a wake sent for ever to somebody who is
/// not there, and — worse — a slot that can never be bound again.
pub fn unbind_thread(thread: u32) {
    if thread == 0 {
        return;
    }
    for slot in &SLOTS {
        let _ = slot
            .bound
            .compare_exchange(thread, 0, Ordering::AcqRel, Ordering::Acquire);
    }
}

/// What `thread` has bound, and whatever it has pending, taken.
///
/// Scans, because the table is [`MAX_NOTIFICATIONS`] entries and this runs on
/// the receive path rather than the signal path. A per-thread index would be a
/// second structure to keep in step with this one, for a saving of thirty-two
/// atomic loads.
#[must_use]
pub fn take_bound(thread: u32) -> u64 {
    if thread == 0 {
        return 0;
    }
    for slot in &SLOTS {
        if slot.live.load(Ordering::Acquire) && slot.bound.load(Ordering::Acquire) == thread {
            return slot.pending.swap(0, Ordering::AcqRel);
        }
    }
    0
}

/// Whether `thread` has a notification bound at all.
#[must_use]
pub fn has_bound(thread: u32) -> bool {
    if thread == 0 {
        return false;
    }
    SLOTS.iter().any(|slot| {
        slot.live.load(Ordering::Acquire) && slot.bound.load(Ordering::Acquire) == thread
    })
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
        // Look and mark under one hold of the runqueue lock. A signal landing
        // before the look is found by it; one landing after finds a thread
        // already `Blocked` and wakes it.
        //
        // The two must not come apart, and this is why: the look *consumes*
        // the pending word. A thread that took the bits and was then preempted
        // while still marked blocked has spent the only signal that was coming
        // -- the block driver raises exactly one interrupt per request -- and
        // sleeps for ever holding the event it was woken for. That is the
        // failure the IPC rendezvous had, in a place with an atomic instead of
        // a mailbox.
        if let Some(outcome) = crate::sched::block_unless(|| {
            let word = slot.pending.swap(0, Ordering::AcqRel);
            if word != 0 {
                Some(Ok(word))
            } else if slot.live.load(Ordering::Acquire) {
                None
            } else {
                Some(Err(NotifyError::Gone))
            }
        }) {
            break outcome;
        }
        // **A thread that has been told to stop must stop waiting.**
        // `block_unless` refuses to mark a dying thread blocked -- sleeping is
        // the one thing it must not do -- so without this check the loop keeps
        // deciding to block, is refused, and spins through the scheduler for
        // ever: a thread that cannot die because it is waiting for something
        // nobody will send. Reachable since RFC 0032 step 10, when a hosted
        // `futex(WAIT)` became an ordinary waiter here and `exit_group` from a
        // sibling became an ordinary way for its domain to end underneath it.
        if crate::sched::should_die() {
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

    // Look and mark together -- the rule, once more, and for the same reason:
    // the look takes the bits, so a thread preempted between taking them and
    // clearing its own blocked mark has nothing left to wake it.
    if let Some(word) = crate::sched::block_unless(|| {
        let word = slot.pending.swap(0, Ordering::AcqRel);
        (word != 0).then_some(word)
    }) {
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
    extern crate std;

    use std::sync::{Mutex, MutexGuard, PoisonError};

    use super::*;

    /// Held by every test in this module, one at a time.
    ///
    /// The slots are a global and cargo runs tests in parallel. This module
    /// used to say "one test" for that reason and then acquired a second one,
    /// which raced the first: the exhaustion test drains the arena and asserts
    /// it comes back empty, and it does not if another test is holding a slot
    /// at that moment. It failed once in a full suite run and passed on every
    /// re-run, which is the shape of a race and the reason a comment asking
    /// people to keep to one test was never going to hold.
    static ARENA: Mutex<()> = Mutex::new(());

    fn alone() -> MutexGuard<'static, ()> {
        ARENA.lock().unwrap_or_else(PoisonError::into_inner)
    }
    #[test]
    fn the_object_behaves_as_rfc_0010_specifies() {
        let _alone = alone();
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
        let _alone = alone();
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

    /// Arming, and the wake arriving only once the deadline has passed.
    #[test]
    fn a_deadline_fires_at_its_time_and_not_before() {
        let _alone = alone();
        let id = create().expect("a notification");
        arm(id, 100, 1).expect("armed");

        // **The half correctness rests on.** A timer that fires early wakes a
        // waiter for something that has not happened yet.
        let mut fired = std::vec::Vec::new();
        expire(99, |who, _| fired.push(who));
        assert!(fired.is_empty(), "fired before its deadline");

        expire(100, |who, _| fired.push(who));
        assert_eq!(fired, std::vec![id], "did not fire at its deadline");

        assert_eq!(armed_deadlines(), 0, "an expired deadline stays armed");
        destroy(id);
    }

    /// A second arming replaces the first rather than taking a second slot.
    #[test]
    fn arming_again_replaces_and_does_not_accumulate() {
        let _alone = alone();
        let id = create().expect("a notification");
        arm(id, 100, 1).expect("armed");
        arm(id, 500, 1).expect("re-armed");
        assert_eq!(armed_deadlines(), 1, "re-arming consumed a second slot");

        let mut fired = std::vec::Vec::new();
        expire(100, |who, _| fired.push(who));
        assert!(fired.is_empty(), "the replaced deadline still fired");

        expire(500, |who, _| fired.push(who));
        assert_eq!(fired, std::vec![id]);
        destroy(id);
    }

    /// Disarming, and the absence of a wake afterwards.
    #[test]
    fn a_disarmed_deadline_never_fires() {
        let _alone = alone();
        let id = create().expect("a notification");
        arm(id, 100, 1).expect("armed");
        assert!(disarm(id), "disarm did not find it");
        assert!(!disarm(id), "disarm found it twice");

        let mut fired = std::vec::Vec::new();
        expire(u64::MAX, |who, _| fired.push(who));
        assert!(fired.is_empty(), "a disarmed deadline fired");
        destroy(id);
    }

    /// **A full table refuses rather than allocating**, and an armed slot is not
    /// stolen from whoever holds it.
    #[test]
    fn a_full_table_is_a_refusal() {
        let _alone = alone();
        let mut held = std::vec::Vec::new();
        for _ in 0..MAX_DEADLINES {
            let id = create().expect("a notification");
            arm(id, 100, 1).expect("armed");
            held.push(id);
        }
        let extra = create().expect("a notification");
        assert_eq!(arm(extra, 100, 1), Err(NotifyError::Exhausted));

        // The ones already armed are untouched by the refusal.
        assert_eq!(armed_deadlines(), MAX_DEADLINES);
        for id in &held {
            disarm(*id);
            destroy(*id);
        }
        destroy(extra);
    }

    /// A deadline armed against a notification that has since been destroyed
    /// must not fire at whoever took its slot.
    #[test]
    fn a_deadline_does_not_outlive_the_notification_it_named() {
        let _alone = alone();
        let first = create().expect("a notification");
        arm(first, 100, 1).expect("armed");
        destroy(first);

        // Whatever takes the slot next has a different generation, so the armed
        // entry names nobody. This is the same rule `NotificationId` enforces
        // one level up, and it is why the generation is stored beside the index.
        let second = create().expect("a notification");

        // The reuse is what makes this test mean something, but it is the
        // arena's choice rather than this test's. Said rather than asserted: a
        // run where the slot is not reused proves nothing and should not fail.
        let reused = first.index() == second.index();

        let mut fired = std::vec::Vec::new();
        expire(u64::MAX, |who, _| fired.push(who));
        assert!(
            !fired.contains(&second),
            "a stale deadline fired at the notification that took the slot"
        );
        assert!(
            reused || fired.is_empty(),
            "the stale deadline fired at somebody"
        );
        disarm(second);
        destroy(second);
    }

    /// Arming against a notification that is gone is refused, not recorded.
    #[test]
    fn arming_a_dead_notification_is_refused() {
        let _alone = alone();
        let id = create().expect("a notification");
        destroy(id);
        assert_eq!(arm(id, 100, 1), Err(NotifyError::Gone));
        assert_eq!(armed_deadlines(), 0);
    }
}
