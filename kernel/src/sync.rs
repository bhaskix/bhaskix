// SPDX-License-Identifier: Apache-2.0
//! Minimal synchronisation primitives.
//!
//! M1 runs on one CPU with interrupts disabled, so strictly speaking no lock
//! is needed yet. This exists anyway because `docs/architecture.md` §6 commits
//! to SMP from the start: single-CPU shortcuts are technical debt with a long
//! tail, and code written against a global mutable static has to be rewritten
//! rather than extended when the second CPU appears.
//!
//! # Not yet implemented
//!
//! Lock **ranking** (`docs/coding-style.md` §7) arrives in M4 alongside the
//! scheduler. Ranks are only meaningful once there is more than one lock to
//! order, and the debug-build rank assertions need per-CPU state that does not
//! exist yet. Until then this is a plain spinlock, and the only lock in the
//! kernel is the console's — so there is nothing it can deadlock against.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// A spinlock protecting a value.
///
/// Naming what it protects in the type — `SpinLock<Console>` rather than a
/// `SpinLock<()>` next to a `Console` — is the convention in
/// `docs/coding-style.md` §7, because it makes the protected data
/// unreachable without acquiring.
pub struct SpinLock<T> {
    locked: AtomicBool,
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
    /// Creates a new unlocked `SpinLock`.
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Acquires the lock if it is free, without spinning.
    ///
    /// Exists for the page-fault path. A fault can interrupt code that already
    /// holds this lock, and a fault handler that then spins for it would hang
    /// the machine with no diagnostic. Returning `None` lets the handler say
    /// what happened instead — a clear report of an unserviceable fault beats
    /// a silent lock-up every time.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinLockGuard { lock: self })
    }

    /// Acquires the lock, spinning until it is free.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
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
        SpinLockGuard { lock: self }
    }
}

/// Grants access to the value protected by a [`SpinLock`], and releases it on
/// drop.
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
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
        let lock = SpinLock::new(41);
        *lock.lock() += 1;
        assert_eq!(*lock.lock(), 42);
    }

    #[test]
    fn lock_is_released_on_drop() {
        let lock = SpinLock::new(());
        drop(lock.lock());
        // Would spin forever if the guard had not released it.
        drop(lock.lock());
    }
}
