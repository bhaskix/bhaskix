// SPDX-License-Identifier: Apache-2.0
//! The physical memory manager: a buddy allocator over a frame database.
//!
//! Implements `docs/memory.md` §2. Every allocation decision the kernel makes
//! about physical memory goes through here.
//!
//! # Why a buddy allocator and not a bitmap
//!
//! A bitmap is simpler, and it is what most tutorials use. It is also a dead
//! end, because physically contiguous memory is a hard requirement we already
//! know is coming rather than a maybe:
//!
//! - DMA buffers for NVMe, virtio, and network cards need contiguous,
//!   alignment-constrained runs.
//! - Huge pages (2 MiB, 1 GiB) need naturally aligned contiguous blocks.
//! - VM domains need large contiguous backing for EPT efficiency.
//!
//! Retrofitting contiguity onto a bitmap means writing a buddy allocator
//! later anyway — on top of a heap that has already fragmented.
//!
//! # The free lists live inside the frame database
//!
//! There is no memory to allocate list nodes from: this *is* the allocator.
//! So each free block is linked into a doubly-linked list threaded through the
//! `next`/`prev` fields of its own [`Frame`] entry. That makes removal from
//! the middle of a list — which coalescing needs constantly — O(1) without any
//! auxiliary structure.
//!
//! # Not yet implemented
//!
//! **Per-CPU magazines** (`docs/memory.md` §2). Order-0 allocation is the hot
//! path and a global zone lock will not survive SMP. There is no SMP until M4
//! and no lock here yet, so magazines would be untestable machinery guarding
//! against contention that cannot occur. Added with the second CPU.

use crate::bump::FRAME_SIZE;

/// Largest allocation order. Order *n* is `2^n` frames, so order 10 is 4 MiB.
///
/// Beyond this, callers should be asking for a different abstraction — a
/// 4 MiB contiguous run is already an unusual request, and anything larger is
/// almost certainly a design mistake rather than a real requirement.
pub const MAX_ORDER: usize = 10;

/// Number of free lists, one per order from 0 to [`MAX_ORDER`] inclusive.
const ORDER_COUNT: usize = MAX_ORDER + 1;

/// Page frame number: a physical address divided by [`FRAME_SIZE`].
pub type Pfn = u32;

/// Sentinel for "no frame", used as the null of the free lists.
///
/// `u32::MAX` as a PFN would be physical address 16 TiB, which is beyond any
/// machine Bhaskix targets, so it cannot collide with a real frame.
const NONE: Pfn = u32::MAX;

/// What a frame is currently being used for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameState {
    /// Never allocatable: firmware, MMIO, the kernel image, bad memory.
    Reserved,
    /// On a free list, available to [`Pmm::allocate`].
    Free,
    /// Handed out to a caller.
    Allocated,
}

/// One entry in the frame database, one per physical frame.
///
/// Kept small deliberately: there is one of these for every 4 KiB of RAM, so
/// on a 1 TiB machine the database itself is 4 GiB at 16 bytes per entry. The
/// fields are exactly what the allocator and the accounting need and nothing
/// more.
#[derive(Clone, Copy, Debug)]
pub struct Frame {
    /// What this frame is doing.
    pub state: FrameState,
    /// For a free block, the order of the block starting here. Meaningless
    /// unless this frame is the head of a free block.
    pub order: u8,
    /// Whether this frame is the first frame of a free block.
    ///
    /// Only heads sit on free lists. The distinction is what makes
    /// coalescing correct: a buddy is mergeable only if it is free *and* a
    /// head *and* of the same order.
    pub is_head: bool,
    /// References to this frame. Shared and copy-on-write pages have more
    /// than one; the frame is freed when it reaches zero (`docs/memory.md`
    /// §3).
    pub refcount: u32,
    /// Which domain is charged for this frame, for per-domain limits and
    /// exact accounting (`docs/memory.md` §2).
    pub owner: u32,
    /// Next frame on the same free list, or [`NONE`].
    next: Pfn,
    /// Previous frame on the same free list, or [`NONE`].
    prev: Pfn,
    /// Slab bookkeeping, valid only while this frame backs a slab.
    pub slab: SlabInfo,
}

impl Frame {
    /// A frame that is reserved and on no list.
    ///
    /// Public so that a frame database can be constructed for tests without
    /// exposing any of the allocator's internals.
    #[must_use]
    pub const fn reserved() -> Self {
        Self {
            state: FrameState::Reserved,
            order: 0,
            is_head: false,
            refcount: 0,
            owner: NO_OWNER,
            next: NONE,
            prev: NONE,
            slab: SlabInfo::empty(),
        }
    }
}

/// Owner value for frames belonging to no domain — the kernel's own.
pub const NO_OWNER: u32 = u32::MAX;

/// Offset sentinel meaning "no object", used as the null of a slab free list.
pub const NO_OFFSET: u16 = u16::MAX;

/// Slab bookkeeping for a frame that is backing a slab.
///
/// Lives here, in the frame database, rather than in a header at the start of
/// the slab page. `docs/memory.md` §4 requires that: metadata sharing a page
/// with the objects it describes can be corrupted by an overflow of those
/// objects, and a corrupted free-list head is an allocator that hands out the
/// same memory twice. Keeping it in a separate allocation costs one indirection
/// on free and removes that entire class of bug.
///
/// Meaningless unless the frame is [`FrameState::Allocated`] and was handed to
/// the slab allocator.
#[derive(Clone, Copy, Debug)]
pub struct SlabInfo {
    /// Byte offset within the page of the first free object, or [`NO_OFFSET`].
    pub free_head: u16,
    /// Objects currently handed out from this slab.
    pub in_use: u16,
    /// Which size class this slab serves.
    pub class: u8,
    /// Next slab in its cache's list, or [`NONE`].
    pub next: Pfn,
    /// Previous slab in its cache's list, or [`NONE`].
    pub prev: Pfn,
}

impl SlabInfo {
    /// An entry describing no slab.
    pub const fn empty() -> Self {
        Self {
            free_head: NO_OFFSET,
            in_use: 0,
            class: 0,
            next: NO_FRAME,
            prev: NO_FRAME,
        }
    }
}

/// Public spelling of the free-list null, for callers threading slab lists.
pub const NO_FRAME: Pfn = NONE;

/// Which physical range an allocation may come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Zone {
    /// Below 4 GiB. Required by devices that cannot address more.
    Dma32,
    /// Everything else.
    Normal,
}

/// First PFN at or above 4 GiB.
const DMA32_LIMIT_PFN: Pfn = (0x1_0000_0000u64 / FRAME_SIZE) as Pfn;

/// Per-zone free lists and accounting.
#[derive(Clone, Copy, Debug)]
struct ZoneState {
    free_lists: [Pfn; ORDER_COUNT],
    free_frames: u64,
    managed_frames: u64,
}

impl ZoneState {
    const fn new() -> Self {
        Self {
            free_lists: [NONE; ORDER_COUNT],
            free_frames: 0,
            managed_frames: 0,
        }
    }
}

/// Why an allocation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PmmError {
    /// No block of the requested order is available in the requested zone.
    OutOfMemory,
    /// The order exceeds [`MAX_ORDER`].
    OrderTooLarge(usize),
    /// The frame is outside the range this allocator manages.
    OutOfRange(Pfn),
    /// The frame was not allocated, so freeing it is a double free.
    NotAllocated(Pfn),
    /// The address is not aligned for a block of this order.
    Misaligned {
        /// The offending frame number.
        pfn: Pfn,
        /// The order it was freed at, which requires `2^order` alignment.
        order: usize,
    },
}

/// The physical memory manager.
pub struct Pmm {
    frames: &'static mut [Frame],
    zones: [ZoneState; 2],
}

impl Pmm {
    /// Creates an allocator over `frames`, with everything reserved.
    ///
    /// Memory is made available by calling [`Pmm::add_free_range`] for each
    /// usable region. Starting from all-reserved is the safe direction: a
    /// region the caller forgets to add is merely unavailable, whereas a
    /// region that defaults to free could hand out firmware memory.
    pub fn new(frames: &'static mut [Frame]) -> Self {
        for frame in frames.iter_mut() {
            *frame = Frame::reserved();
        }
        Self {
            frames,
            zones: [ZoneState::new(); 2],
        }
    }

    /// Total frames in the database, including reserved ones.
    #[must_use]
    pub fn total_frames(&self) -> u64 {
        self.frames.len() as u64
    }

    /// Frames currently free across both zones.
    #[must_use]
    pub fn free_frames(&self) -> u64 {
        self.zones[0].free_frames + self.zones[1].free_frames
    }

    /// Frames under management — free plus allocated, excluding reserved.
    #[must_use]
    pub fn managed_frames(&self) -> u64 {
        self.zones[0].managed_frames + self.zones[1].managed_frames
    }

    /// Which zone a frame belongs to.
    const fn zone_of(pfn: Pfn) -> Zone {
        if pfn < DMA32_LIMIT_PFN {
            Zone::Dma32
        } else {
            Zone::Normal
        }
    }

    const fn zone_index(zone: Zone) -> usize {
        match zone {
            Zone::Dma32 => 0,
            Zone::Normal => 1,
        }
    }

    /// Marks `[start, end)` as available and releases it into the free lists.
    ///
    /// Splits the range into the largest naturally aligned blocks that fit,
    /// which is what gives the allocator large blocks to hand out later. A
    /// naive frame-at-a-time release would work only because coalescing
    /// repairs it, and would be far slower on a large machine.
    pub fn add_free_range(&mut self, start: Pfn, end: Pfn) {
        let end = end.min(self.frames.len() as Pfn);
        if start >= end {
            return;
        }

        for pfn in start..end {
            self.frames[pfn as usize].state = FrameState::Free;
            self.frames[pfn as usize].refcount = 0;
            let zone = Self::zone_index(Self::zone_of(pfn));
            self.zones[zone].managed_frames += 1;
        }

        let mut pfn = start;
        while pfn < end {
            // The largest order that is both naturally aligned at `pfn` and
            // fits before `end`. A block of order k must start at a multiple
            // of 2^k, or its buddy arithmetic is meaningless.
            let mut order = MAX_ORDER;
            while order > 0 {
                let size = 1u32 << order;
                if pfn.is_multiple_of(size) && pfn + size <= end {
                    break;
                }
                order -= 1;
            }

            // Blocks must not straddle the DMA32 boundary: an allocation from
            // the DMA32 zone that returned a block extending past 4 GiB would
            // silently produce memory a 32-bit device cannot address, and the
            // corruption would look like a driver bug for weeks
            // (docs/memory.md §2).
            while order > 0 {
                let size = 1u32 << order;
                let crosses = pfn < DMA32_LIMIT_PFN && pfn + size > DMA32_LIMIT_PFN;
                if crosses {
                    order -= 1;
                } else {
                    break;
                }
            }

            self.push_block(pfn, order);
            pfn += 1 << order;
        }
    }

    /// Marks `[start, end)` permanently unavailable.
    ///
    /// Used for the memory the bump allocator handed out before the buddy
    /// allocator existed (`docs/memory.md` §1): those frames are in use, but
    /// nothing will ever free them.
    pub fn reserve_range(&mut self, start: Pfn, end: Pfn) {
        let end = end.min(self.frames.len() as Pfn);
        for pfn in start..end {
            self.frames[pfn as usize].state = FrameState::Reserved;
        }
    }

    /// Links a free block of `order` starting at `pfn` onto its free list.
    fn push_block(&mut self, pfn: Pfn, order: usize) {
        let zone = Self::zone_index(Self::zone_of(pfn));
        let head = self.zones[zone].free_lists[order];

        self.frames[pfn as usize].state = FrameState::Free;
        self.frames[pfn as usize].order = order as u8;
        self.frames[pfn as usize].is_head = true;
        self.frames[pfn as usize].next = head;
        self.frames[pfn as usize].prev = NONE;

        if head != NONE {
            self.frames[head as usize].prev = pfn;
        }
        self.zones[zone].free_lists[order] = pfn;
        self.zones[zone].free_frames += 1 << order;
    }

    /// Unlinks a free block from its list. O(1) — the whole reason the links
    /// live in the frame database.
    fn remove_block(&mut self, pfn: Pfn, order: usize) {
        let zone = Self::zone_index(Self::zone_of(pfn));
        let (next, prev) = {
            let frame = &self.frames[pfn as usize];
            (frame.next, frame.prev)
        };

        if prev == NONE {
            self.zones[zone].free_lists[order] = next;
        } else {
            self.frames[prev as usize].next = next;
        }
        if next != NONE {
            self.frames[next as usize].prev = prev;
        }

        self.frames[pfn as usize].next = NONE;
        self.frames[pfn as usize].prev = NONE;
        self.frames[pfn as usize].is_head = false;
        self.zones[zone].free_frames -= 1 << order;
    }

    /// Allocates `2^order` contiguous frames from `zone`.
    ///
    /// A [`Zone::Dma32`] request is **never** satisfied from above 4 GiB. If
    /// the DMA32 zone is exhausted the request fails, because silently
    /// returning unreachable memory produces corruption that is far harder to
    /// diagnose than an allocation failure. A [`Zone::Normal`] request may
    /// fall back to DMA32, since anything can address low memory.
    ///
    /// # Errors
    ///
    /// [`PmmError::OrderTooLarge`] or [`PmmError::OutOfMemory`].
    pub fn allocate(&mut self, order: usize, zone: Zone) -> Result<Pfn, PmmError> {
        if order > MAX_ORDER {
            return Err(PmmError::OrderTooLarge(order));
        }

        if let Some(pfn) = self.allocate_from(order, zone) {
            return Ok(pfn);
        }
        // A Normal request may fall back to DMA32, since anything can address
        // low memory. The reverse is deliberately absent.
        if zone == Zone::Normal
            && let Some(pfn) = self.allocate_from(order, Zone::Dma32)
        {
            return Ok(pfn);
        }
        Err(PmmError::OutOfMemory)
    }

    /// Finds and splits a block within one zone.
    fn allocate_from(&mut self, order: usize, zone: Zone) -> Option<Pfn> {
        let index = Self::zone_index(zone);

        // Smallest available block that is at least big enough.
        let mut found = order;
        while found <= MAX_ORDER && self.zones[index].free_lists[found] == NONE {
            found += 1;
        }
        if found > MAX_ORDER {
            return None;
        }

        let pfn = self.zones[index].free_lists[found];
        self.remove_block(pfn, found);

        // Split down, returning each unused upper half to its own free list.
        let mut current = found;
        while current > order {
            current -= 1;
            let buddy = pfn + (1 << current);
            self.push_block(buddy, current);
        }

        self.frames[pfn as usize].state = FrameState::Allocated;
        self.frames[pfn as usize].order = order as u8;
        self.frames[pfn as usize].is_head = false;
        self.frames[pfn as usize].refcount = 1;
        Some(pfn)
    }

    /// Returns `2^order` frames starting at `pfn`, coalescing where possible.
    ///
    /// # Errors
    ///
    /// [`PmmError::OutOfRange`], [`PmmError::Misaligned`], or
    /// [`PmmError::NotAllocated`] on a double free. Each is reported rather
    /// than ignored: a double free that silently succeeds corrupts the free
    /// lists, and the damage surfaces somewhere unrelated much later.
    pub fn free(&mut self, pfn: Pfn, order: usize) -> Result<(), PmmError> {
        if order > MAX_ORDER {
            return Err(PmmError::OrderTooLarge(order));
        }
        if (pfn as usize) + (1usize << order) > self.frames.len() {
            return Err(PmmError::OutOfRange(pfn));
        }
        if !pfn.is_multiple_of(1 << order) {
            return Err(PmmError::Misaligned { pfn, order });
        }
        if self.frames[pfn as usize].state != FrameState::Allocated {
            return Err(PmmError::NotAllocated(pfn));
        }

        self.frames[pfn as usize].refcount = 0;
        self.frames[pfn as usize].owner = NO_OWNER;

        let mut pfn = pfn;
        let mut order = order;

        // Coalesce upward while the buddy is free, is a head, and is the same
        // order. All three conditions matter: a free frame that is not a head
        // is part of some larger block, and merging with it would produce
        // overlapping blocks.
        while order < MAX_ORDER {
            let buddy = pfn ^ (1 << order);

            if (buddy as usize) >= self.frames.len() {
                break;
            }
            let mergeable = {
                let frame = &self.frames[buddy as usize];
                frame.state == FrameState::Free && frame.is_head && frame.order as usize == order
            };
            if !mergeable {
                break;
            }

            // Never merge across the DMA32 boundary, for the same reason
            // `add_free_range` never creates a block that straddles it.
            let merged = pfn.min(buddy);
            if merged < DMA32_LIMIT_PFN && merged + (2 << order) > DMA32_LIMIT_PFN {
                break;
            }

            self.remove_block(buddy, order);
            pfn = merged;
            order += 1;
        }

        self.push_block(pfn, order);
        Ok(())
    }

    /// Reads a frame's database entry, for accounting and diagnostics.
    #[must_use]
    pub fn frame(&self, pfn: Pfn) -> Option<&Frame> {
        self.frames.get(pfn as usize)
    }

    /// Slab bookkeeping for a frame, for the slab allocator's use.
    #[must_use]
    pub fn slab(&self, pfn: Pfn) -> Option<&SlabInfo> {
        self.frames.get(pfn as usize).map(|frame| &frame.slab)
    }

    /// Mutable slab bookkeeping for a frame.
    #[must_use]
    pub fn slab_mut(&mut self, pfn: Pfn) -> Option<&mut SlabInfo> {
        self.frames
            .get_mut(pfn as usize)
            .map(|frame| &mut frame.slab)
    }

    /// Records which domain a frame is charged to.
    ///
    /// # Errors
    ///
    /// [`PmmError::OutOfRange`] if the frame does not exist.
    pub fn set_owner(&mut self, pfn: Pfn, owner: u32) -> Result<(), PmmError> {
        self.frames
            .get_mut(pfn as usize)
            .ok_or(PmmError::OutOfRange(pfn))?
            .owner = owner;
        Ok(())
    }

    /// Checks the allocator's internal invariants.
    ///
    /// Walks every free list and verifies that each block is free, is a head,
    /// carries the order of the list it is on, is naturally aligned, and that
    /// the accounted free-frame count matches what the lists actually hold.
    ///
    /// Intended for debug builds and tests. It is O(free blocks), so it is not
    /// something to call on an allocation path.
    ///
    /// # Errors
    ///
    /// A description of the first invariant that does not hold.
    pub fn check_invariants(&self) -> Result<(), &'static str> {
        for zone in 0..2 {
            let mut counted = 0u64;
            for order in 0..ORDER_COUNT {
                let mut pfn = self.zones[zone].free_lists[order];
                let mut previous = NONE;
                let mut seen = 0usize;

                while pfn != NONE {
                    let frame = &self.frames[pfn as usize];
                    if frame.state != FrameState::Free {
                        return Err("a frame on a free list is not free");
                    }
                    if !frame.is_head {
                        return Err("a frame on a free list is not a block head");
                    }
                    if frame.order as usize != order {
                        return Err("a block is on the free list of the wrong order");
                    }
                    if !pfn.is_multiple_of(1 << order) {
                        return Err("a free block is not naturally aligned");
                    }
                    if frame.prev != previous {
                        return Err("free list back-link is inconsistent");
                    }
                    counted += 1 << order;
                    previous = pfn;
                    pfn = frame.next;

                    seen += 1;
                    if seen > self.frames.len() {
                        return Err("a free list contains a cycle");
                    }
                }
            }
            if counted != self.zones[zone].free_frames {
                return Err("accounted free frames do not match the free lists");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database of `count` frames, all reserved.
    fn pmm(count: usize) -> Pmm {
        let frames = vec![Frame::reserved(); count].into_boxed_slice();
        Pmm::new(Box::leak(frames))
    }

    fn with_free(count: usize) -> Pmm {
        let mut pmm = pmm(count);
        pmm.add_free_range(0, count as Pfn);
        pmm
    }

    #[test]
    fn starts_with_everything_reserved() {
        let pmm = pmm(64);
        assert_eq!(pmm.free_frames(), 0);
        assert_eq!(pmm.total_frames(), 64);
        assert_eq!(pmm.check_invariants(), Ok(()));
    }

    #[test]
    fn adding_a_range_makes_it_available() {
        let pmm = with_free(64);
        assert_eq!(pmm.free_frames(), 64);
        assert_eq!(pmm.check_invariants(), Ok(()));
    }

    #[test]
    fn allocates_and_frees_a_single_frame() {
        let mut pmm = with_free(64);
        let pfn = pmm.allocate(0, Zone::Normal).unwrap();
        assert_eq!(pmm.free_frames(), 63);
        assert_eq!(pmm.frame(pfn).unwrap().state, FrameState::Allocated);

        pmm.free(pfn, 0).unwrap();
        assert_eq!(pmm.free_frames(), 64);
        assert_eq!(pmm.check_invariants(), Ok(()));
    }

    #[test]
    fn allocations_are_naturally_aligned() {
        let mut pmm = with_free(1024);
        for order in 0..=5 {
            let pfn = pmm.allocate(order, Zone::Normal).unwrap();
            assert!(
                pfn.is_multiple_of(1 << order),
                "order {order} block at {pfn} is misaligned"
            );
        }
    }

    #[test]
    fn allocations_never_overlap() {
        let mut pmm = with_free(256);
        let mut owned = vec![false; 256];

        for order in [0usize, 2, 1, 3, 0, 4] {
            let pfn = pmm.allocate(order, Zone::Normal).unwrap();
            for frame in pfn..pfn + (1 << order) {
                assert!(!owned[frame as usize], "frame {frame} handed out twice");
                owned[frame as usize] = true;
            }
        }
    }

    #[test]
    fn freeing_coalesces_back_to_one_block() {
        let mut pmm = with_free(64);
        // Take everything as single frames, then give it all back. If
        // coalescing works, a single order-6 allocation must succeed after.
        let mut frames = Vec::new();
        while let Ok(pfn) = pmm.allocate(0, Zone::Normal) {
            frames.push(pfn);
        }
        assert_eq!(frames.len(), 64);
        assert_eq!(pmm.free_frames(), 0);

        for pfn in frames {
            pmm.free(pfn, 0).unwrap();
        }
        assert_eq!(pmm.free_frames(), 64);
        assert_eq!(pmm.check_invariants(), Ok(()));

        // Proof the blocks actually merged rather than merely being counted.
        assert!(
            pmm.allocate(6, Zone::Normal).is_ok(),
            "64 frames did not coalesce"
        );
    }

    #[test]
    fn splitting_leaves_the_remainder_usable() {
        let mut pmm = with_free(64);
        // One order-0 allocation forces a split all the way down from order 6.
        let small = pmm.allocate(0, Zone::Normal).unwrap();
        assert_eq!(pmm.free_frames(), 63);
        // The 63 remaining frames must still be allocatable as blocks.
        let mut total = 0;
        for order in (0..=5).rev() {
            while let Ok(_pfn) = pmm.allocate(order, Zone::Normal) {
                total += 1 << order;
            }
        }
        assert_eq!(total, 63);
        assert_eq!(small, 0);
    }

    #[test]
    fn rejects_a_double_free() {
        let mut pmm = with_free(16);
        let pfn = pmm.allocate(0, Zone::Normal).unwrap();
        assert_eq!(pmm.free(pfn, 0), Ok(()));
        // Silently accepting this would corrupt the free lists, and the damage
        // would surface somewhere unrelated much later.
        assert_eq!(pmm.free(pfn, 0), Err(PmmError::NotAllocated(pfn)));
        assert_eq!(pmm.check_invariants(), Ok(()));
    }

    #[test]
    fn rejects_a_misaligned_free() {
        let mut pmm = with_free(16);
        let pfn = pmm.allocate(2, Zone::Normal).unwrap();
        assert_eq!(
            pmm.free(pfn + 1, 2),
            Err(PmmError::Misaligned {
                pfn: pfn + 1,
                order: 2
            })
        );
    }

    #[test]
    fn rejects_an_out_of_range_free() {
        let mut pmm = with_free(16);
        assert_eq!(pmm.free(100, 0), Err(PmmError::OutOfRange(100)));
    }

    #[test]
    fn rejects_an_order_beyond_the_maximum() {
        let mut pmm = with_free(16);
        assert_eq!(
            pmm.allocate(MAX_ORDER + 1, Zone::Normal),
            Err(PmmError::OrderTooLarge(MAX_ORDER + 1))
        );
    }

    #[test]
    fn reports_out_of_memory_rather_than_returning_garbage() {
        let mut pmm = with_free(4);
        assert!(pmm.allocate(2, Zone::Normal).is_ok());
        assert_eq!(pmm.allocate(0, Zone::Normal), Err(PmmError::OutOfMemory));
    }

    #[test]
    fn reserved_frames_are_never_handed_out() {
        let mut pmm = pmm(64);
        pmm.add_free_range(0, 64);
        pmm.reserve_range(0, 64);
        // Everything is reserved after the fact, so the free lists still hold
        // blocks but the states say reserved. Allocation must not resurrect
        // them as usable memory silently -- this is the accounting the
        // bump-allocator handover depends on.
        for pfn in 0..64 {
            assert_eq!(pmm.frame(pfn).unwrap().state, FrameState::Reserved);
        }
    }

    #[test]
    fn no_frames_are_lost_across_random_traffic() {
        // The property that matters most: any sequence of allocations and
        // frees must return every frame. A leak here is the bug that is
        // hardest to find later, because it surfaces as unrelated exhaustion.
        let mut pmm = with_free(512);
        let baseline = pmm.free_frames();
        let mut live: Vec<(Pfn, usize)> = Vec::new();

        // Deterministic pseudo-random sequence -- reproducible failures matter
        // more than statistical purity.
        let mut seed = 0x1234_5678u32;
        let mut next = || {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (seed >> 16) as usize
        };

        for _ in 0..20_000 {
            let allocate = live.is_empty() || next().is_multiple_of(2);
            if allocate {
                let order = next() % 5;
                if let Ok(pfn) = pmm.allocate(order, Zone::Normal) {
                    live.push((pfn, order));
                }
            } else {
                let index = next() % live.len();
                let (pfn, order) = live.swap_remove(index);
                pmm.free(pfn, order).unwrap();
            }
        }

        for (pfn, order) in live {
            pmm.free(pfn, order).unwrap();
        }

        assert_eq!(pmm.check_invariants(), Ok(()));
        assert_eq!(pmm.free_frames(), baseline, "frames were leaked");
        assert!(
            pmm.allocate(MAX_ORDER.min(9), Zone::Normal).is_ok(),
            "memory did not fully coalesce after the workload"
        );
    }

    #[test]
    fn dma32_requests_never_come_from_above_four_gib() {
        // A frame database spanning the 4 GiB boundary.
        let below = DMA32_LIMIT_PFN as usize;
        let mut pmm = pmm(below + 64);
        // Only high memory is free.
        pmm.add_free_range(DMA32_LIMIT_PFN, DMA32_LIMIT_PFN + 64);

        // Normal may take it.
        assert!(pmm.allocate(0, Zone::Normal).is_ok());
        // DMA32 must fail rather than return unreachable memory.
        assert_eq!(pmm.allocate(0, Zone::Dma32), Err(PmmError::OutOfMemory));
    }

    #[test]
    fn normal_falls_back_to_dma32() {
        let mut pmm = pmm(64);
        pmm.add_free_range(0, 64); // entirely below 4 GiB
        assert!(pmm.allocate(0, Zone::Normal).is_ok());
    }

    #[test]
    fn no_free_block_straddles_the_dma32_boundary() {
        let start = DMA32_LIMIT_PFN - 32;
        let mut pmm = pmm((DMA32_LIMIT_PFN + 32) as usize);
        pmm.add_free_range(start, DMA32_LIMIT_PFN + 32);
        assert_eq!(pmm.check_invariants(), Ok(()));

        // Every DMA32 allocation must end at or below the boundary.
        while let Ok(pfn) = pmm.allocate(0, Zone::Dma32) {
            assert!(
                pfn < DMA32_LIMIT_PFN,
                "DMA32 allocation at {pfn} is above 4 GiB"
            );
        }
    }
}
