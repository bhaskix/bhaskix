// SPDX-License-Identifier: Apache-2.0
//! Synchronisation primitives, and the lock ordering they enforce.
//!
//! # Lock ranking
//!
//! `docs/architecture.md` §6 and `docs/coding-style.md` §7 require that lock
//! ordering be *declared rather than remembered*. Every [`SpinLock`] carries a
//! [`Rank`], and a blocking acquisition of a lock ranked at or below one this
//! execution context already holds is reported as an ordering violation.
//!
//! The point is not to catch deadlocks when they happen — a deadlocked kernel
//! prints nothing and there is nothing to catch. It is to catch the *ordering*
//! that would one day deadlock, on the run where the timing happened to be
//! benign. Nearly every acquisition order in this kernel is currently safe by
//! accident of which code paths overlap; ranking makes it safe on purpose.
//!
//! ## Why `try_lock` is exempt from *ranking*
//!
//! [`SpinLock::try_lock`] neither checks the order nor records the
//! acquisition, and that exemption is load-bearing rather than a convenience.
//!
//! A deadlock is a cycle in which *every* edge is a blocking wait. A
//! `try_lock` never waits, so it can never be such an edge, and an order that
//! contains one cannot close a cycle. This matters because interrupt handlers
//! acquire locks at points chosen by the hardware rather than by the code:
//! a timer interrupt can land while any lock at all is held, so *every* lock
//! taken in interrupt context is out of rank with respect to something. That
//! is precisely why [`crate::sched::preempt`] and the page-fault handler use
//! `try_lock` — and it is why ranking them would produce a flood of reports
//! about orders that cannot deadlock.
//!
//! ## And why it is *not* exempt from holding
//!
//! The paragraph above is about ordering, and for a long time its conclusion
//! was quietly read as a second one: that a `try_lock` holder is safe to
//! deschedule. It does not follow, and the difference cost a stall.
//!
//! `preempt` refuses to take the CPU from a thread holding a lock, because a
//! preempted holder can only release by running again. It decided that by
//! asking whether the ranked set was empty — and a `try_lock` is not in the
//! ranked set, so its holder looked like a thread holding nothing at all. It
//! was holding a lock. `sched::exit` reaches two functions that `try_lock`
//! *every* runqueue with interrupts enabled, so a tick landing in that scan
//! could carry the exiting thread off its CPU still holding a **remote**
//! runqueue, which nothing would then release.
//!
//! [`holds_unranked`] answers the question the rank set cannot: not *where in
//! the order* this CPU is, but *whether it is holding anything at all*. Taking
//! no rank and holding no lock are different claims, and only the first is
//! true of `try_lock`.
//!
//! ## What this did not do
//!
//! **It did not fix the bring-up stall, which is why it was written.** The
//! hypothesis was that the stall *was* this: a soak had one stalled boot
//! reporting a switch made while holding a remote runqueue, against 54 healthy
//! boots reporting none. That is a correlation on a single sample, and it did
//! not survive. With the guard in place 3 boots in 500 stalled, against 4 in
//! 500 without it — the same rate — and one of them arrived with the identical
//! signature the guard was supposed to make impossible.
//!
//! Kept anyway, because descheduling a lock holder is wrong whether or not it
//! is the cause of *this* fault. Written down because a rule whose
//! justification is a bug it did not fix will otherwise be remembered as
//! having fixed it.
//!
//! ## Why a violation reports rather than panics
//!
//! `docs/coding-style.md` §7 says debug builds should panic. This reports and
//! continues instead, for the reason `lockdep` does the same: the report is
//! the entire value, and halting on the first one discards the coverage of the
//! rest of the boot. A rank violation is a latent risk, not present corruption
//! — turning it into a guaranteed crash trades a possible future deadlock for
//! a certain immediate one. The boot test asserts the count is zero, which is
//! the same guarantee with more information when it fails.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use bhaskix_arch::percpu::{self, MAX_CPUS};

/// No CPU holds the lock. Matches the `NO_DOMAIN` convention in `irq.rs`.
///
/// `u32::MAX` rather than `0`, because `0` is a CPU.
const NO_OWNER: u32 = u32::MAX;

/// Every lock in the kernel, ordered by the sequence in which they may be
/// acquired: a context holding one may only block on a lock declared *below*
/// it here.
///
/// The order is not aesthetic. It is what the code already does, recovered by
/// reading every nesting site, and two entries are placed where intuition
/// would not put them:
///
/// - **`Heap` above `TlbSender`**, because unmapping frees frames inside
///   `heap::with`, and a shootdown must happen before a frame is handed back —
///   so the TLB lock is genuinely taken under the heap's.
/// - **`SchedRunqueue` below `Heap`**, which looks backwards for something as
///   central as the scheduler. A thread can be preempted while holding the
///   heap, and the switch path then blocks on the incoming CPU's runqueue: the
///   runqueue lock is an inner lock. `sched::spawn_on` already allocates
///   *outside* the runqueue lock for exactly this reason, which is the same
///   constraint arrived at independently.
///
/// Discriminants are bit indices into the per-CPU held set, so they must stay
/// distinct and below 64.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Rank {
    /// `vm::ACTIVE` — the address space this CPU has loaded.
    AddressSpace = 0,
    /// `vm::PREVIOUS_ROOT` — the page-table root to restore on deactivate.
    AddressSpacePrevious = 1,
    /// `iommu::WINDOW` — the device windows a unit translates through.
    ///
    /// **Outside the heap**, because mapping a page into a device's window may
    /// have to allocate a level of its page tables, and allocating takes the
    /// heap while this is held. It was ranked innermost at first, on the
    /// reasoning that revocation reaches it last — and the detector reported
    /// the inversion on the first boot that mapped anything.
    ///
    /// Nothing is held when this is taken: `shared::revoke` releases the arena
    /// before unmapping from a device, and the syscall path resolves its
    /// capabilities and lets go before it maps.
    DmaWindow = 2,
    /// `heap::HEAP` — the kernel allocator, and the physical allocator inside it.
    Heap = 3,
    /// `tlb::SENDER` — serialises shootdowns over the one shared address slot.
    TlbSender = 4,
    /// `time::TIMERS` — one CPU's pending timer deadlines.
    ///
    /// Outside the runqueues for the same reason the wait queues are: expiring
    /// a timer wakes a thread, which takes a runqueue lock while this is held.
    Timers = 5,
    /// `domain::TABLE` — the domain table.
    ///
    /// Outside the capability arena: destroying a domain revokes its root
    /// capability, so the table lock is taken first and the arena second.
    /// Nothing goes the other way.
    Domains = 6,
    /// `cap::ARENA` — the global capability derivation tree.
    ///
    /// Outside the wait queues: revoking a capability to an endpoint will need
    /// to wake whoever is blocked on it, and that takes a wait queue and then a
    /// runqueue. Nothing goes the other way — the IPC paths resolve
    /// capabilities before they block, never after.
    Capabilities = 7,
    /// `ipc::TABLE` — the endpoint table.
    ///
    /// Inside the capability arena, because a syscall resolves the endpoint
    /// capability before it touches the endpoint; outside the runqueues,
    /// because completing a rendezvous wakes the thread on the other side.
    Endpoints = 8,
    /// `wait::WaitQueue` — the waiter list of a blocking primitive.
    ///
    /// Outside the runqueues, because both halves of a sleep take them in that
    /// order: a sleeper holds this while marking itself blocked, and a waker
    /// holds it while marking a sleeper ready. Either one taking them the
    /// other way round is the deadlock this ordering exists to make visible.
    WaitQueue = 9,
    /// `sched::QUEUES` — one runqueue per CPU.
    SchedRunqueue = 10,
    /// `notify::ALLOCATION` — creation and destruction of notifications.
    ///
    /// Outside the runqueues, because destroying one wakes whoever was
    /// waiting. The *signal* path takes no lock at all, which is what lets an
    /// interrupt handler call it.
    Notifications = 11,
    /// `shared::ARENA` — memory objects (RFC 0009).
    ///
    /// Outside the heap, because creating one allocates frames while it is
    /// held; inside the domain table, because charging an envelope happens
    /// before the arena is taken. Nothing goes the other way.
    SharedMemory = 12,
    /// `irq::HANDLERS` — claimed interrupt sources.
    ///
    /// Outside `vectors::TABLE`, because claiming a source takes this and then
    /// allocates a vector. Nothing goes the other way. They were briefly the
    /// same rank, which the checker reported on the first boot: two locks of
    /// one rank have no declared order and can close a cycle just as easily as
    /// an inversion.
    IrqHandlers = 13,
    /// `vectors::TABLE` — who owns which interrupt vector.
    ///
    /// A leaf: taken at boot and when a driver claims a source, with nothing
    /// acquired while it is held. Inside the scheduler's queues because a
    /// claim never wakes anything.
    Vectors = 14,
    /// `virtio::DEVICE` — the one block device.
    ///
    /// Inside the scheduler's queues because nothing here wakes a thread: the
    /// driver waits for its device by spinning on a ring the device writes,
    /// not by blocking. Outside the console, because a driver reports what it
    /// found while holding itself.
    Block = 15,
    /// `console::CONSOLE` — the innermost lock. Anything may print.
    Console = 16,
}

impl Rank {
    /// This rank's bit in a held set.
    const fn bit(self) -> u64 {
        1u64 << (self as u8)
    }

    /// Every rank at or *inside* this one, as a mask.
    ///
    /// Holding any of these when blocking on `self` is a violation. Strictly
    /// inside is the inversion; equal means two locks of the same rank, which
    /// have no declared order relative to each other and so can close a cycle
    /// just as easily.
    const fn at_or_inside(self) -> u64 {
        // Bits `self..64`. Note the direction: a *lower* discriminant is
        // acquired earlier, so the ranks that must not already be held are the
        // ones numbered at or above this.
        u64::MAX << (self as u8)
    }

    /// For reports.
    const fn name(self) -> &'static str {
        match self {
            Self::AddressSpace => "vm::ACTIVE",
            Self::AddressSpacePrevious => "vm::PREVIOUS_ROOT",
            Self::Heap => "heap::HEAP",
            Self::TlbSender => "tlb::SENDER",
            Self::Timers => "time::TIMERS",
            Self::Domains => "domain::TABLE",
            Self::Capabilities => "cap::ARENA",
            Self::Endpoints => "ipc::TABLE",
            Self::WaitQueue => "wait::WaitQueue",
            Self::SchedRunqueue => "sched::QUEUES",
            Self::Notifications => "notify::ALLOCATION",
            Self::SharedMemory => "shared::ARENA",
            Self::IrqHandlers => "irq::HANDLERS",
            Self::Vectors => "vectors::TABLE",
            Self::Block => "virtio::DEVICE",
            Self::DmaWindow => "iommu::WINDOW",
            Self::Console => "console::CONSOLE",
        }
    }
}

/// Whether blocking on `rank` is legal while `held` is held.
///
/// Pure, so that the policy can be tested exhaustively on the host rather than
/// inferred from whether a particular boot happened to deadlock.
#[must_use]
pub const fn would_violate(held: u64, rank: Rank) -> bool {
    held & rank.at_or_inside() != 0
}

/// The set of ranks each CPU currently holds, one bit per [`Rank`].
///
/// A bitmask rather than a stack: it is a single atomic, it makes "is anything
/// at or below this held" one `and`, and it stays correct when guards are
/// dropped out of order, which a stack would not.
static HELD: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Ordering violations observed since boot.
static VIOLATIONS: AtomicU64 = AtomicU64::new(0);

/// Rank-checked acquisitions since boot.
///
/// Reported alongside the violation count because zero violations is equally
/// consistent with a correct kernel and with a checker that never ran. The
/// acquisition count distinguishes them.
static ACQUISITIONS: AtomicU64 = AtomicU64::new(0);

/// Whether to print each violation. Cleared while the self-test provokes one
/// deliberately, so the expected report does not read like a real failure.
static REPORT: AtomicBool = AtomicBool::new(true);

fn slot() -> &'static AtomicU64 {
    let cpu = percpu::cpu_id() as usize;
    // Before per-CPU data exists, `cpu_id` answers 0 -- which is correct, since
    // everything that early runs on the bootstrap CPU.
    &HELD[if cpu < MAX_CPUS { cpu } else { 0 }]
}

/// The ranks this CPU currently holds.
#[must_use]
pub fn held_mask() -> u64 {
    slot().load(Ordering::Relaxed)
}

/// Locks this CPU holds that are *not* in the ranked set — the `try_lock`s.
///
/// A count rather than a mask: `try_lock` takes no position in the order, so
/// there is nothing to record but how many are outstanding, and they nest.
static UNRANKED: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

fn unranked_slot() -> &'static AtomicU32 {
    let cpu = percpu::cpu_id() as usize;
    &UNRANKED[if cpu < MAX_CPUS { cpu } else { 0 }]
}

/// Whether this CPU holds any lock taken with [`SpinLock::try_lock`].
///
/// **Exists because the rank exemption was quietly doing a second job it does
/// not support.** `try_lock` stays out of the ranked set for a sound reason: a
/// non-blocking acquisition can never be an edge in a deadlock cycle, so
/// ranking it would report orders that cannot deadlock. `sched::preempt` then
/// used that same emptiness to decide a thread was safe to deschedule — and
/// those are different claims. A `try_lock` cannot *deadlock*, but its holder
/// still holds the lock, and descheduling one strands every CPU waiting on it.
///
/// **Not verified by the stall going away, because it did not.** See the
/// module header: the guard this feeds was written to end the bring-up stall
/// and did not, at 3 boots in 500 against 4 in 500 without it. It is kept for
/// the argument above, which stands on its own.
#[must_use]
pub fn holds_unranked() -> bool {
    unranked_slot().load(Ordering::Relaxed) != 0
}

/// Replaces the held set for this CPU.
///
/// For the context switch: held locks belong to the *thread*, not the
/// processor, so the scheduler saves the outgoing thread's set and installs
/// the incoming one. Without this, a thread preempted while holding the heap
/// would leave its ranks behind, and the next thread to run on that CPU would
/// be reported for an order it had nothing to do with.
pub fn set_held_mask(mask: u64) {
    slot().store(mask, Ordering::Relaxed);
}

/// Violations observed since boot. The boot test requires this to be zero.
#[must_use]
pub fn violations() -> u64 {
    VIOLATIONS.load(Ordering::Relaxed)
}

/// Rank-checked acquisitions since boot.
#[must_use]
pub fn acquisitions() -> u64 {
    ACQUISITIONS.load(Ordering::Relaxed)
}

/// Discards violations counted so far.
///
/// Exists for the self-test, which provokes one on purpose and must not leave
/// it behind for the boot gate to trip over.
pub fn reset_violations() {
    VIOLATIONS.store(0, Ordering::Relaxed);
}

/// Silences violation reports, for a test that provokes one on purpose.
pub fn set_reporting(on: bool) {
    REPORT.store(on, Ordering::Relaxed);
}

fn record(held: u64, rank: Rank) {
    VIOLATIONS.fetch_add(1, Ordering::Relaxed);
    if !REPORT.load(Ordering::Relaxed) {
        return;
    }
    // Naming both ends matters: "out of order" without saying against what
    // sends the reader to read every lock site, which is the work the rank
    // list exists to avoid.
    crate::println!(
        "    LOCK ORDER     blocking on {} (rank {}) while holding mask {:#08b}",
        rank.name(),
        rank as u8,
        held
    );
}

/// A spinlock protecting a value.
///
/// Naming what it protects in the type — `SpinLock<Console>` rather than a
/// `SpinLock<()>` next to a `Console` — is the convention in
/// `docs/coding-style.md` §7, because it makes the protected data
/// unreachable without acquiring.
///
/// The [`Rank`] is a constructor argument rather than something registered
/// elsewhere, so that a lock cannot be added without declaring where it sits.
pub struct SpinLock<T> {
    locked: AtomicBool,
    /// The CPU that took the lock, or [`NO_OWNER`] when it is free.
    ///
    /// Diagnostic only — nothing in the locking protocol reads it. It exists
    /// because a held lock could say *that* it was held and not *by whom*: the
    /// bring-up watchdog could report a runqueue stuck for two seconds and had
    /// to state in the same breath that the CPU it named was where the lock
    /// was, not who took it. `spawn_on` and the wake paths block on a remote
    /// runqueue, so those are different questions.
    owner: AtomicU32,
    rank: Rank,
    value: UnsafeCell<T>,
}

// SAFETY: `SpinLock` grants access to its interior only through `lock()`,
// which returns a guard after winning an atomic compare-exchange, and only one
// guard can exist at a time. That makes concurrent access to `T` mutually
// exclusive, so sharing the lock across threads is sound whenever `T` may be
// sent across threads.
unsafe impl<T: Send> Sync for SpinLock<T> {}
// SAFETY: sending the lock sends the contained value; no reference to the
// interior can outlive a guard, so there is nothing left behind on the old
// thread.
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Creates a new unlocked `SpinLock` at `rank`.
    pub const fn new(rank: Rank, value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            owner: AtomicU32::new(NO_OWNER),
            rank,
            value: UnsafeCell::new(value),
        }
    }

    /// The CPU currently holding this lock, or `None` if it is free.
    ///
    /// **A snapshot, and only worth reading when the answer cannot change.**
    /// On a live lock the holder may release before this returns, so a caller
    /// that acts on it is racing. It is meant for the case where a lock has
    /// been observed stuck — there the value is as stable as the fault is, and
    /// it names the CPU to go and look at.
    ///
    /// Reports the CPU that *acquired* the lock, which before per-CPU areas
    /// are installed is `0` for everyone, since [`percpu::cpu_id`] has no
    /// better answer that early. Every caller so far runs long after that.
    #[must_use]
    pub fn owner(&self) -> Option<u32> {
        match self.owner.load(Ordering::Relaxed) {
            NO_OWNER => None,
            cpu => Some(cpu),
        }
    }

    /// Acquires the lock if it is free, without spinning.
    ///
    /// Exists for the page-fault path and for every other acquisition made
    /// from interrupt context. A fault can interrupt code that already holds
    /// this lock, and a fault handler that then spins for it would hang the
    /// machine with no diagnostic. Returning `None` lets the handler say what
    /// happened instead — a clear report of an unserviceable fault beats a
    /// silent lock-up every time.
    ///
    /// Exempt from rank checking, and does not record the acquisition: see the
    /// module header.
    ///
    /// **It does count towards [`holds_unranked`]**, which is a different
    /// question from ranking and was for a long time answered by accident. The
    /// order it takes is nothing; the lock it holds is real.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| {
                self.owner.store(percpu::cpu_id(), Ordering::Relaxed);
                unranked_slot().fetch_add(1, Ordering::Relaxed);
                SpinLockGuard {
                    lock: self,
                    ranked: false,
                }
            })
    }

    /// Acquires the lock, spinning until it is free.
    ///
    /// Checks the declared order first. The check happens *before* the spin,
    /// not after: once this blocks on a lock it should not have, the report
    /// would never be printed.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let held = held_mask();
        ACQUISITIONS.fetch_add(1, Ordering::Relaxed);
        if would_violate(held, self.rank) {
            record(held, self.rank);
        }
        slot().fetch_or(self.rank.bit(), Ordering::Relaxed);

        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Spin on a relaxed load rather than hammering the bus with
            // read-modify-write cycles: the exchange only retries once the
            // lock actually looks free.
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        self.owner.store(percpu::cpu_id(), Ordering::Relaxed);
        SpinLockGuard {
            lock: self,
            ranked: true,
        }
    }
}

/// Grants access to the value protected by a [`SpinLock`], and releases it on
/// drop.
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    /// Whether acquisition was recorded in the held set, and so must be
    /// cleared. False for `try_lock`, which does not participate.
    ranked: bool,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: this guard exists, so the compare-exchange in `lock()`
        // succeeded and no other guard exists. The shared reference cannot
        // outlive the guard, so no aliasing mutable reference can be created
        // while it lives.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above, and `&mut self` means no shared reference derived
        // from this guard is live either.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        if self.ranked {
            slot().fetch_and(!self.lock.rank.bit(), Ordering::Relaxed);
        } else {
            // Decremented on the CPU that runs the drop, which is the CPU that
            // took it: a `try_lock` holder cannot now be moved, because that is
            // exactly what this count prevents.
            unranked_slot().fetch_sub(1, Ordering::Relaxed);
        }
        // Cleared *before* the release below, not after. Between the release
        // and a later clear the lock is free, so another CPU may take it and
        // record itself -- and this store would then erase a live owner and
        // leave the lock reading as unheld while somebody holds it. The
        // diagnostic would be wrong in exactly the case it exists for.
        self.lock.owner.store(NO_OWNER, Ordering::Relaxed);
        // Release ordering pairs with the Acquire in `lock()`, so everything
        // written under the lock is visible to the next holder.
        self.lock.locked.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guards_provide_access_to_the_value() {
        let lock = SpinLock::new(Rank::Console, 41);
        *lock.lock() += 1;
        assert_eq!(*lock.lock(), 42);
    }

    #[test]
    fn lock_is_released_on_drop() {
        let lock = SpinLock::new(Rank::Console, ());
        drop(lock.lock());
        // Would spin forever if the guard had not released it.
        drop(lock.lock());
    }

    #[test]
    fn try_lock_keeps_its_holder_on_the_cpu() {
        // The fix for the bring-up stall, as a property: `try_lock` takes no
        // rank -- it cannot be an edge in a deadlock cycle -- but it *is*
        // holding a lock, and `sched::preempt` must not deschedule its holder.
        set_held_mask(0);
        let lock = SpinLock::new(Rank::Console, ());
        assert!(!holds_unranked(), "nothing held to begin with");
        let guard = lock.try_lock().expect("free");
        assert_eq!(held_mask(), 0, "still takes no rank");
        assert!(holds_unranked(), "but is held, so its holder must not move");
        drop(guard);
        assert!(!holds_unranked(), "released");
    }

    #[test]
    fn unranked_holds_nest() {
        set_held_mask(0);
        let a = SpinLock::new(Rank::Console, ());
        let b = SpinLock::new(Rank::Heap, ());
        let first = a.try_lock().expect("free");
        let second = b.try_lock().expect("free");
        drop(second);
        assert!(
            holds_unranked(),
            "one is still held after the inner release"
        );
        drop(first);
        assert!(!holds_unranked());
    }

    #[test]
    fn a_failed_try_lock_leaves_no_hold_behind() {
        // A losing attempt must not count, or a CPU that probed a busy lock
        // would refuse preemption for ever.
        set_held_mask(0);
        let lock = SpinLock::new(Rank::Console, ());
        let held = lock.try_lock().expect("free");
        assert!(lock.try_lock().is_none(), "already held");
        drop(held);
        assert!(!holds_unranked(), "the failed attempt counted nothing");
    }

    #[test]
    fn a_lock_records_its_holder_and_forgets_on_release() {
        let lock = SpinLock::new(Rank::Console, ());
        assert_eq!(lock.owner(), None, "a free lock has no owner");
        let guard = lock.lock();
        assert!(lock.owner().is_some(), "a held lock names its holder");
        drop(guard);
        assert_eq!(lock.owner(), None, "release clears the owner");
    }

    #[test]
    fn try_lock_records_its_holder_too() {
        // `try_lock` is exempt from *ranking*, which is a statement about
        // deadlock cycles. It is not exempt from holding the lock, and a
        // stuck `try_lock` holder is as worth naming as any other.
        let lock = SpinLock::new(Rank::Console, ());
        let guard = lock.try_lock().expect("free");
        assert!(lock.owner().is_some());
        drop(guard);
        assert_eq!(lock.owner(), None);
    }

    #[test]
    fn a_failed_try_lock_does_not_disturb_the_recorded_owner() {
        let lock = SpinLock::new(Rank::Console, ());
        let held = lock.lock();
        let owner = lock.owner().expect("held");
        assert!(lock.try_lock().is_none(), "already held");
        assert_eq!(
            lock.owner(),
            Some(owner),
            "a losing attempt records nothing"
        );
        drop(held);
    }

    #[test]
    fn an_empty_context_may_take_anything() {
        assert!(!would_violate(0, Rank::AddressSpace));
        assert!(!would_violate(0, Rank::Console));
    }

    #[test]
    fn acquiring_downwards_is_a_violation() {
        // Holding the heap and blocking on the address space lock is the
        // inversion of the order vm::unmap_range establishes.
        let held = Rank::Heap.bit();
        assert!(would_violate(held, Rank::AddressSpace));
    }

    #[test]
    fn acquiring_upwards_is_allowed() {
        let held = Rank::AddressSpace.bit();
        assert!(!would_violate(held, Rank::Heap));
        assert!(!would_violate(held, Rank::Console));
    }

    #[test]
    fn two_locks_of_the_same_rank_are_a_violation() {
        // Two runqueues have no declared order relative to each other, so
        // blocking on one while holding another can close a cycle. Stealing
        // takes the second with `try_lock` precisely because of this.
        let held = Rank::SchedRunqueue.bit();
        assert!(would_violate(held, Rank::SchedRunqueue));
    }

    #[test]
    fn the_whole_declared_order_is_legal_end_to_end() {
        // The order the kernel actually uses, walked in one pass.
        let order = [
            Rank::AddressSpace,
            Rank::AddressSpacePrevious,
            Rank::Heap,
            Rank::TlbSender,
            Rank::Timers,
            Rank::Domains,
            Rank::Capabilities,
            Rank::Endpoints,
            Rank::WaitQueue,
            Rank::SchedRunqueue,
            Rank::Console,
        ];
        let mut held = 0;
        for rank in order {
            assert!(!would_violate(held, rank), "{rank:?} rejected in order");
            held |= rank.bit();
        }
        // ...and every reverse step is rejected.
        let mut held = 0;
        for rank in order.into_iter().rev() {
            if held != 0 {
                assert!(would_violate(held, rank), "{rank:?} accepted out of order");
            }
            held |= rank.bit();
        }
    }

    #[test]
    fn releasing_out_of_order_leaves_the_set_correct() {
        // Guards are usually dropped last-in-first-out, but nothing enforces
        // it. A bitmask stays right either way; a stack would not.
        let outer = SpinLock::new(Rank::Heap, ());
        let inner = SpinLock::new(Rank::Console, ());
        set_held_mask(0);

        let a = outer.lock();
        let b = inner.lock();
        assert_eq!(held_mask(), Rank::Heap.bit() | Rank::Console.bit());

        drop(a); // the *outer* one first
        assert_eq!(held_mask(), Rank::Console.bit());
        drop(b);
        assert_eq!(held_mask(), 0);
    }

    #[test]
    fn try_lock_does_not_join_the_held_set() {
        let lock = SpinLock::new(Rank::Heap, ());
        set_held_mask(0);
        let guard = lock.try_lock().expect("free");
        assert_eq!(held_mask(), 0, "try_lock must not record");
        drop(guard);
        assert_eq!(held_mask(), 0);
    }
}
