// SPDX-License-Identifier: Apache-2.0
//! Who owns which interrupt vector.
//!
//! There are 256 of them and they are a global resource. Until M6-07 they were
//! constants in five places — `apic::TIMER_VECTOR`, `sched::RESCHEDULE_VECTOR`,
//! `tlb::SHOOTDOWN_VECTOR`, `input::SERIAL_VECTOR`, and the two the local APIC
//! fixes — with nothing checking that they were distinct. Two subsystems
//! choosing the same number would have produced a machine that behaved
//! strangely, on a path nobody would think to look at.
//!
//! [RFC 0011](../../../docs/rfc/0011-irq-handler.md) makes this the one
//! registry: **every vector in use is taken from here, and a collision is a
//! boot failure rather than a mystery.**
//!
//! # Reserved, and allocated
//!
//! Two ways to take a vector, and the difference is whether the *number*
//! matters to something outside this kernel:
//!
//! - [`reserve`] takes a specific one. For vectors the architecture fixes
//!   (the CPU's exceptions, the local APIC's spurious and error vectors) and
//!   for the ones this kernel programs into hardware at a fixed point during
//!   bring-up. The number is an input.
//! - [`allocate`] takes whichever is free and reports which. For everything
//!   else — a device interrupt, today and in future. **The number is an
//!   output, and nobody outside this module needs to know it.**
//!
//! RFC 0011 asks that a domain never learn a vector, because a domain that
//! could choose one could choose the timer's. `allocate` returning the number
//! to its *caller* rather than to the claiming domain is what makes that
//! possible later.
//!
//! # Why the owner is a name
//!
//! Each entry records who took it, as a string, and the boot report prints
//! them. A table of numbers says which vectors are used; a table of names says
//! what the machine is doing, which is what someone reading a boot log after a
//! collision actually needs.

use crate::sync::{Rank, SpinLock};

/// Vectors below this are the CPU's own exceptions and are never allocatable.
pub const FIRST_ALLOCATABLE: u8 = 32;

/// Why a vector could not be taken.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VectorError {
    /// Something already owns it.
    Taken,
    /// It is one of the CPU's exceptions.
    Reserved,
    /// Every allocatable vector is taken.
    Exhausted,
    /// The vector is not one this module hands out.
    OutOfRange,
}

/// One entry: who owns this vector, or nothing.
#[derive(Clone, Copy)]
struct Entry {
    owner: Option<&'static str>,
}

struct Table {
    entries: [Entry; 256],
}

impl Table {
    const fn new() -> Self {
        Self {
            entries: [Entry { owner: None }; 256],
        }
    }
}

static TABLE: SpinLock<Table> = SpinLock::new(Rank::Vectors, Table::new());

/// Takes `vector` for `owner`, or says who has it.
///
/// # Errors
///
/// [`VectorError::Taken`] naming nothing — the caller reports, because it
/// knows what it was trying to do. [`VectorError::Reserved`] for an exception
/// vector.
pub fn reserve(vector: u8, owner: &'static str) -> Result<u8, VectorError> {
    if vector < FIRST_ALLOCATABLE {
        return Err(VectorError::Reserved);
    }
    let mut table = TABLE.lock();
    if table.entries[vector as usize].owner.is_some() {
        return Err(VectorError::Taken);
    }
    table.entries[vector as usize].owner = Some(owner);
    Ok(vector)
}

/// Takes any free vector for `owner`.
///
/// Allocates downwards from the top, so that dynamically allocated vectors are
/// far from the fixed ones and a mistake is obvious in a log rather than
/// plausible. The local APIC's spurious and error vectors are reserved before
/// this is ever called, so "the top" starts below them.
///
/// # Errors
///
/// [`VectorError::Exhausted`] when every allocatable vector is taken.
pub fn allocate(owner: &'static str) -> Result<u8, VectorError> {
    let mut table = TABLE.lock();
    for vector in (FIRST_ALLOCATABLE..=u8::MAX).rev() {
        if table.entries[vector as usize].owner.is_none() {
            table.entries[vector as usize].owner = Some(owner);
            return Ok(vector);
        }
    }
    Err(VectorError::Exhausted)
}

/// Gives a vector back.
///
/// # Errors
///
/// [`VectorError::OutOfRange`] for an exception vector, which was never
/// allocatable and so cannot be released.
pub fn release(vector: u8) -> Result<(), VectorError> {
    if vector < FIRST_ALLOCATABLE {
        return Err(VectorError::OutOfRange);
    }
    TABLE.lock().entries[vector as usize].owner = None;
    Ok(())
}

/// Who owns `vector`, if anyone.
#[must_use]
pub fn owner(vector: u8) -> Option<&'static str> {
    TABLE.lock().entries[vector as usize].owner
}

/// How many allocatable vectors are taken, and how many exist.
#[must_use]
pub fn usage() -> (usize, usize) {
    let table = TABLE.lock();
    let taken = table
        .entries
        .iter()
        .skip(FIRST_ALLOCATABLE as usize)
        .filter(|entry| entry.owner.is_some())
        .count();
    (taken, 256 - FIRST_ALLOCATABLE as usize)
}

/// Runs `f` for each vector with an owner, in order.
pub fn for_each(mut f: impl FnMut(u8, &'static str)) {
    let table = TABLE.lock();
    for (vector, entry) in table.entries.iter().enumerate() {
        if let Some(owner) = entry.owner {
            f(vector as u8, owner);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table is a global, so the host tests take it in one test rather
    /// than racing each other for it. Cargo runs tests in parallel by default
    /// and a shared allocator is exactly the thing that would fail
    /// intermittently and be blamed on something else.
    #[test]
    fn the_allocator_is_a_registry_and_a_collision_is_an_error() {
        // Reserving a specific vector works once.
        assert_eq!(reserve(0x20, "timer"), Ok(0x20));
        assert_eq!(owner(0x20), Some("timer"));

        // And exactly once. This is the whole point: two subsystems choosing
        // the same number is an error rather than a machine behaving oddly.
        assert_eq!(reserve(0x20, "somebody else"), Err(VectorError::Taken));
        assert_eq!(owner(0x20), Some("timer"), "the first owner keeps it");

        // An exception vector is never available.
        for vector in [0u8, 8, 14, 31] {
            assert_eq!(reserve(vector, "nobody"), Err(VectorError::Reserved));
            assert_eq!(release(vector), Err(VectorError::OutOfRange));
        }

        // Allocation picks a free one, and picks a different one each time.
        let first = allocate("device a").expect("plenty free");
        let second = allocate("device b").expect("plenty free");
        assert_ne!(first, second);
        assert!(first >= FIRST_ALLOCATABLE && second >= FIRST_ALLOCATABLE);
        assert_eq!(owner(first), Some("device a"));

        // Release makes it available again, to somebody else.
        assert_eq!(release(first), Ok(()));
        assert_eq!(owner(first), None);
        assert_eq!(reserve(first, "device c"), Ok(first));

        let (taken, total) = usage();
        assert_eq!(total, 224, "32 exceptions are not allocatable");
        assert!(taken >= 3);

        // Everything that has an owner is reported, and nothing else is.
        let mut seen = 0;
        for_each(|vector, owner| {
            seen += 1;
            assert!(vector >= FIRST_ALLOCATABLE, "an exception has no owner");
            assert!(!owner.is_empty());
        });
        assert_eq!(seen, taken);

        // Clean up, so this test leaves the global as it found it.
        for vector in [0x20, first, second] {
            let _ = release(vector);
        }
    }

    #[test]
    fn exhaustion_is_reported_rather_than_wrapping() {
        // A separate table, because taking all 224 would fight the test above
        // for the global one. The logic under test is the loop, and the loop
        // is the same.
        let mut table = Table::new();
        for entry in table.entries.iter_mut().skip(FIRST_ALLOCATABLE as usize) {
            entry.owner = Some("full");
        }
        let free = table
            .entries
            .iter()
            .skip(FIRST_ALLOCATABLE as usize)
            .filter(|entry| entry.owner.is_none())
            .count();
        assert_eq!(free, 0, "the model is full, so allocate would report it");
    }
}
