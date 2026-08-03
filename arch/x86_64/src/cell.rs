// SPDX-License-Identifier: Apache-2.0
//! Storage for values initialised once during boot.
//!
//! The descriptor tables, the TSS, and the interrupt stacks are all written
//! exactly once, on the bootstrap CPU, before interrupts are enabled and
//! before any other CPU exists. That is the only reason a plain static is
//! sound here, so the requirement is encoded in the type's safety contract
//! rather than left as a comment on each use.
//!
//! `arch` cannot use the kernel's `SpinLock`: the dependency direction is
//! `arch -> nothing` (`docs/architecture.md` §5). It does not need one either —
//! there is no concurrency at the point these are written.
//!
//! # Not a substitute for a lock
//!
//! When SMP bring-up lands in M4, per-CPU structures move to a proper per-CPU
//! area indexed by CPU id. This type is for the genuinely single-threaded boot
//! window, and it will be an error to introduce new uses after that point.

use core::cell::UnsafeCell;

/// A value written once during single-threaded boot, then read many times.
#[repr(transparent)]
pub struct BootCell<T>(UnsafeCell<T>);

// SAFETY: the type's whole contract is that mutation happens only during
// single-threaded boot. `get_mut` is `unsafe` and documents that obligation;
// every other access is a shared read of data that is immutable by then.
unsafe impl<T: Send> Sync for BootCell<T> {}

impl<T> BootCell<T> {
    /// Creates a cell holding `value`.
    pub const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    /// Returns a raw pointer to the contents.
    ///
    /// Prefer [`BootCell::get`] or [`BootCell::get_mut`]. This exists for the
    /// cases that need an address rather than a reference — loading the GDT
    /// register, for instance.
    pub const fn as_ptr(&self) -> *mut T {
        self.0.get()
    }

    /// Borrows the contents mutably.
    ///
    /// # Safety
    ///
    /// The caller must ensure this runs during single-threaded boot, that no
    /// other reference to the contents is live, and that this is called at
    /// most once for a given cell.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get_mut(&self) -> &mut T {
        // SAFETY: the caller guarantees exclusivity; see the method contract.
        unsafe { &mut *self.0.get() }
    }

    /// Borrows the contents immutably.
    ///
    /// # Safety
    ///
    /// The caller must ensure initialisation has completed and that no
    /// mutable borrow is live.
    pub unsafe fn get(&self) -> &T {
        // SAFETY: the caller guarantees no mutable borrow is outstanding.
        unsafe { &*self.0.get() }
    }
}
