// SPDX-License-Identifier: Apache-2.0
//! `Memory` objects: frames a capability can name.
//!
//! [RFC 0009](../../../docs/rfc/0009-shared-memory.md), accepted, step 1. An
//! object is a set of frames with a length and an owner. A capability names
//! it; mapping it into an address space is step 2, and into a *device's*
//! address space is [RFC 0012](../../../docs/rfc/0012-iommu.md).
//!
//! # Why an object rather than a capability per frame
//!
//! `ObjectKind::Frame` exists and would have been the smaller change. It is
//! also sixteen CSpace slots to share sixty-four kilobytes, and sixteen
//! fallible `MAP` calls to place them — each of which can fail separately,
//! leaving a partially mapped buffer nobody named. One object with a length is
//! one allocation, one failure mode, and one thing to revoke.
//!
//! # There is no untyped memory, and that was a decision
//!
//! seL4 makes all kernel memory come from `Untyped` capabilities that
//! userspace retypes, which makes accounting an exact partition of physical
//! memory and the API considerably larger. RFC 0009's acceptance took the
//! simpler model: **an object is allocated from a domain's
//! `ResourceEnvelope`**, and `ObjectKind::Untyped` is deleted. The cost came
//! with the decision — accounting here is a quota, not a partition — and it is
//! recorded in `TRACKER.md` rather than discovered later.
//!
//! # What step 1 does not do
//!
//! No mapping, no sharing, no revocation walk. What it does is the part
//! everything else needs to be right about: **frames are charged to a
//! domain's envelope when the object is made and released when it goes**, and
//! the frame-leak gate is pointed at exactly that.

use crate::domain::DomainId;
use crate::sync::{Rank, SpinLock};
use bhaskix_mm::{FRAME_SIZE, Zone};

/// Memory objects that can exist at once.
pub const MAX_OBJECTS: usize = 16;

/// Frames one object may hold — 64 KiB.
///
/// Fixed, because the object must not chase an allocation while it is being
/// torn down: destruction has to complete, and a destruction that could fail
/// to allocate is a destruction that can leave frames charged to a domain that
/// no longer wants them. A larger buffer is a second object.
pub const MAX_FRAMES: usize = 16;

/// Why an object could not be made or found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemoryError {
    /// No free object slot.
    Exhausted,
    /// The requested length is zero, or larger than [`MAX_FRAMES`] pages.
    BadLength,
    /// The domain's memory envelope will not cover it.
    QuotaExceeded,
    /// The physical allocator had nothing.
    OutOfMemory,
    /// The object has been destroyed, or the name is stale.
    Gone,
    /// The domain does not exist.
    NoSuchDomain,
}

/// Names a memory object, with the generation current when it was named.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemoryId {
    index: u32,
    generation: u32,
}

impl MemoryId {
    /// The slot this names, for reporting.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }
}

/// One object.
#[derive(Clone, Copy)]
struct Object {
    /// Physical frame numbers, in order. Index *i* is the object's *i*-th page.
    frames: [u64; MAX_FRAMES],
    /// How many of them are real.
    count: usize,
    /// Bytes. Always `count * FRAME_SIZE`; kept because every caller wants it
    /// and recomputing it at each use is where an off-by-one lives.
    length: u64,
    /// Whose envelope paid, and keeps paying for as long as this exists.
    owner: DomainId,
    generation: u32,
    live: bool,
}

impl Object {
    const fn empty() -> Self {
        Self {
            frames: [0; MAX_FRAMES],
            count: 0,
            length: 0,
            owner: DomainId::from_u32(0),
            generation: 0,
            live: false,
        }
    }
}

struct Arena {
    objects: [Object; MAX_OBJECTS],
}

impl Arena {
    const fn new() -> Self {
        Self {
            objects: [Object::empty(); MAX_OBJECTS],
        }
    }
}

/// The arena is a **leaf**: nothing is acquired while it is held. Frames are
/// allocated and freed, and envelopes charged and released, either side of it —
/// both of those take lower-ranked locks, and taking a lower rank while
/// holding a higher one is the inversion this project's checker exists to
/// catch. It caught this one.
static ARENA: SpinLock<Arena> = SpinLock::new(Rank::SharedMemory, Arena::new());

/// Objects created and destroyed, for the leak gate.
static CREATED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static DESTROYED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Creates an object of `length` bytes, charged to `owner`.
///
/// The length is rounded **up** to whole pages, because a frame is the unit a
/// device and a page table both work in — and a caller told it received 100
/// bytes when it has a page would be a caller with 3 996 bytes of somebody
/// else's history in reach. The rounded length is what [`length_of`] reports.
///
/// # Errors
///
/// [`MemoryError`] naming what was refused. **Nothing is charged and no frame
/// is taken on any failing path**: a half-made object is one that has to be
/// found and cleaned up by whoever notices, which is nobody.
pub fn create(owner: DomainId, length: u64) -> Result<MemoryId, MemoryError> {
    let pages = length.div_ceil(FRAME_SIZE);
    if length == 0 || pages > MAX_FRAMES as u64 {
        return Err(MemoryError::BadLength);
    }

    // The envelope first, because it is the cheapest thing to refuse and the
    // only one whose refusal is a policy rather than a shortage.
    crate::domain::charge_frames(owner, pages).map_err(|_| MemoryError::QuotaExceeded)?;

    // Allocate every frame, or none, and do it **before taking the arena**.
    // The allocator is a lower-ranked lock than this arena, so holding one
    // while asking for the other is an inversion -- which the rank checker
    // reported on the first boot after this module was written, exactly as it
    // is meant to. Nothing here is held while anything else is acquired.
    let mut frames = [0u64; MAX_FRAMES];
    let mut taken = 0;
    while taken < pages as usize {
        let Some(frame) = allocate_frame() else {
            for frame in frames.iter().take(taken) {
                free_frame(*frame);
            }
            crate::domain::release_frames(owner, pages);
            return Err(MemoryError::OutOfMemory);
        };
        frames[taken] = frame;
        taken += 1;
    }

    let claimed = {
        let mut arena = ARENA.lock();
        match arena.objects.iter().position(|object| !object.live) {
            Some(index) => {
                let generation = arena.objects[index].generation;
                arena.objects[index] = Object {
                    frames,
                    count: taken,
                    length: pages * FRAME_SIZE,
                    owner,
                    generation,
                    live: true,
                };
                Some(MemoryId {
                    index: index as u32,
                    generation,
                })
            }
            None => None,
        }
    };

    let Some(id) = claimed else {
        // No slot. Give everything back, outside the arena, for the same
        // reason it was taken outside it.
        for frame in frames.iter().take(taken) {
            free_frame(*frame);
        }
        crate::domain::release_frames(owner, pages);
        return Err(MemoryError::Exhausted);
    };

    CREATED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    Ok(id)
}

/// Destroys an object, freeing its frames and releasing its charge.
///
/// Returns whether anything was destroyed. Idempotent: destroying a name that
/// is already gone is not an error, because a caller racing a teardown should
/// not have to distinguish "I destroyed it" from "it was already destroyed" to
/// know that it is gone.
pub fn destroy(id: MemoryId) -> bool {
    // Take the object out under the arena, and give its frames back outside
    // it. The allocator and the domain table are both lower-ranked than this
    // arena, so neither may be acquired while it is held.
    let removed = {
        let mut arena = ARENA.lock();
        let Some(object) = resolve(&arena, id) else {
            return false;
        };
        let index = id.index as usize;
        arena.objects[index].live = false;
        arena.objects[index].generation = object.generation.wrapping_add(1);
        arena.objects[index].count = 0;
        object
    };

    for frame in removed.frames.iter().take(removed.count) {
        free_frame(*frame);
    }
    crate::domain::release_frames(removed.owner, removed.count as u64);
    DESTROYED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    true
}

/// Destroys every object a domain owns.
///
/// For domain teardown. A shared region does not outlive the domain that made
/// it — RFC 0009 says so, and says why it is worth stating out loud: a
/// receiver that wants memory to outlive its provider must own it itself.
pub fn destroy_owned_by(owner: DomainId) -> usize {
    let names: [Option<MemoryId>; MAX_OBJECTS] = {
        let arena = ARENA.lock();
        core::array::from_fn(|index| {
            let object = arena.objects[index];
            (object.live && object.owner == owner).then_some(MemoryId {
                index: index as u32,
                generation: object.generation,
            })
        })
    };

    names.iter().flatten().filter(|id| destroy(**id)).count()
}

fn resolve(arena: &Arena, id: MemoryId) -> Option<Object> {
    let object = *arena.objects.get(id.index as usize)?;
    (object.live && object.generation == id.generation).then_some(object)
}

/// The object's length in bytes, or `None` if it is gone.
#[must_use]
pub fn length_of(id: MemoryId) -> Option<u64> {
    resolve(&ARENA.lock(), id).map(|object| object.length)
}

/// The physical address of the object's `page`-th frame.
///
/// This is what step 2 maps and what RFC 0012 hands to a device. It is
/// deliberately not public beyond the kernel: a physical address is not
/// authority anyone outside should be able to name.
#[must_use]
pub(crate) fn frame_at(id: MemoryId, page: usize) -> Option<u64> {
    let object = resolve(&ARENA.lock(), id)?;
    (page < object.count).then(|| object.frames[page])
}

/// Maps `id` into `space` at `address`, with `protection`.
///
/// **Into the caller's own address space, and nobody else's.** There is no
/// method here that maps into another domain's, and the absence is the design:
/// sharing happens by handing over a *capability*, which `grant` already does.
/// A service that could map into a caller's address space would be a service
/// that could write to its callers.
///
/// # Errors
///
/// [`MemoryError::Gone`] if the object has been destroyed, or
/// [`MemoryError::BadLength`] if the address space refused — which for an
/// executable protection it always will, per RFC 0009.
pub fn map_into(
    id: MemoryId,
    space: &mut crate::vm::AddressSpace,
    address: bhaskix_boot::VirtAddr,
    protection: bhaskix_mm::Protection,
) -> Result<(), MemoryError> {
    // The frame list is copied out from under the arena, because mapping takes
    // the heap lock and this arena is a leaf. The object cannot be destroyed
    // in between by anyone who does not already hold a name for it, and a
    // caller racing its own destroy is a caller with a bug of its own.
    let (frames, count) = {
        let arena = ARENA.lock();
        let object = resolve(&arena, id).ok_or(MemoryError::Gone)?;
        (object.frames, object.count)
    };

    let range =
        bhaskix_mm::VirtRange::from_pages(address, count as u64).ok_or(MemoryError::BadLength)?;

    space
        .map_shared(range, id.index, &frames[..count], protection)
        .map_err(|_| MemoryError::BadLength)
}

/// Whether the object is live.
#[must_use]
pub fn live(id: MemoryId) -> bool {
    resolve(&ARENA.lock(), id).is_some()
}

/// How many objects are live, and objects created and destroyed since boot.
#[must_use]
pub fn statistics() -> (usize, u64, u64) {
    use core::sync::atomic::Ordering::Relaxed;
    let arena = ARENA.lock();
    (
        arena.objects.iter().filter(|object| object.live).count(),
        CREATED.load(Relaxed),
        DESTROYED.load(Relaxed),
    )
}

fn allocate_frame() -> Option<u64> {
    crate::heap::with(|heap| {
        heap.pmm_mut()
            .allocate(0, Zone::Normal)
            .ok()
            .map(|pfn| u64::from(pfn) * FRAME_SIZE)
    })
    .flatten()
}

fn free_frame(frame: u64) {
    let _ = crate::heap::with(|heap| heap.pmm_mut().free((frame / FRAME_SIZE) as u32, 0));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The arena is a global and the frame allocator is not available on the
    /// host, so what is tested here is the bookkeeping that does not touch
    /// either: the length arithmetic and the identity rules. The allocation
    /// and accounting halves are asserted in QEMU, against the frame-leak
    /// gate, which is the only place they mean anything.
    #[test]
    fn a_length_is_rounded_up_to_whole_pages_and_bounded() {
        for (bytes, pages) in [
            (1u64, 1u64),
            (FRAME_SIZE - 1, 1),
            (FRAME_SIZE, 1),
            (FRAME_SIZE + 1, 2),
            (FRAME_SIZE * MAX_FRAMES as u64, MAX_FRAMES as u64),
        ] {
            assert_eq!(bytes.div_ceil(FRAME_SIZE), pages, "{bytes} bytes");
        }

        // Zero is refused rather than rounded to nothing: an object with no
        // pages is a name for no memory, and every caller of it would be
        // asking for a mapping of length zero.
        assert_eq!(0u64.div_ceil(FRAME_SIZE), 0);

        // And one page past the bound is refused rather than truncated.
        let over = FRAME_SIZE * MAX_FRAMES as u64 + 1;
        assert!(over.div_ceil(FRAME_SIZE) > MAX_FRAMES as u64);
    }

    #[test]
    fn a_name_carries_a_generation_so_a_stale_one_addresses_nothing() {
        let mut arena = Arena::new();
        arena.objects[3] = Object {
            frames: [0; MAX_FRAMES],
            count: 1,
            length: FRAME_SIZE,
            owner: DomainId::from_u32(1),
            generation: 7,
            live: true,
        };

        let good = MemoryId {
            index: 3,
            generation: 7,
        };
        let stale = MemoryId {
            index: 3,
            generation: 6,
        };
        assert!(resolve(&arena, good).is_some());
        assert!(
            resolve(&arena, stale).is_none(),
            "a name from before the slot was reused must not address what took it"
        );

        // A dead slot answers to nobody, whatever the generation.
        arena.objects[3].live = false;
        assert!(resolve(&arena, good).is_none());

        // And an index past the end is a refusal rather than a panic.
        assert!(
            resolve(
                &arena,
                MemoryId {
                    index: MAX_OBJECTS as u32,
                    generation: 0
                }
            )
            .is_none()
        );
    }
}
