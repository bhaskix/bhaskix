// SPDX-License-Identifier: Apache-2.0
//! The kernel heap: a slab allocator over the buddy allocator.
//!
//! Implements `docs/memory.md` §4. This is what makes `alloc` — `Box`, `Vec`,
//! `BTreeMap` — usable in the kernel.
//!
//! # Structure
//!
//! Each *slab* is one 4 KiB frame from the buddy allocator, divided evenly
//! into objects of one size class. Free objects are threaded onto a
//! singly-linked list whose links live **inside the free objects themselves**,
//! which costs nothing: the memory is unused by definition.
//!
//! Per-slab bookkeeping does *not* live in the page. It lives in the frame
//! database ([`SlabInfo`]), because metadata sharing a page with the objects it
//! describes can be corrupted by an overflow of those objects — and a
//! corrupted free-list head is an allocator that hands the same memory out
//! twice. Finding it costs one indirection on free: pointer → frame number →
//! frame entry.
//!
//! # Size classes
//!
//! Powers of two from 16 to 2048 bytes. Anything larger goes straight to the
//! buddy allocator as whole pages. Powers of two waste up to half a class on
//! awkward sizes, which is the accepted cost of making alignment automatic:
//! an object of size `2^n` placed at a multiple of `2^n` within a
//! 4 KiB-aligned page is aligned to `2^n` for free.
//!
//! # Not yet implemented
//!
//! - **Per-CPU caches** (`docs/memory.md` §4). Same reasoning as the buddy
//!   allocator's magazines: there is no second CPU to contend with until M4.
//! - **Red zones, poisoning, and quarantine** for debug builds. Worth having,
//!   and cheap, but they are debugging aids rather than correctness, and they
//!   need the `alloc` machinery working first to be worth testing.

use crate::bump::FRAME_SIZE;
use crate::pmm::{NO_FRAME, NO_OFFSET, Pfn, Pmm, PmmError, Zone};

/// Size classes, in bytes.
pub const CLASS_SIZES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];

/// Number of size classes.
pub const CLASS_COUNT: usize = CLASS_SIZES.len();

/// Largest allocation the slab allocator serves. Above this, whole pages.
pub const MAX_SLAB_SIZE: usize = 2048;

/// Why a heap allocation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapError {
    /// The physical allocator had nothing left.
    OutOfMemory,
    /// The requested alignment exceeds what this allocator can guarantee.
    UnsupportedAlignment(usize),
    /// The pointer being freed does not belong to any slab.
    NotAllocated,
    /// The allocation is larger than the largest supported buddy order.
    TooLarge(usize),
}

/// One size class's list of slabs that still have a free object.
///
/// Full slabs are unlinked entirely rather than kept on a second list. They
/// are re-linked the moment an object is freed back into them, and until then
/// there is nothing useful to do with them — walking past full slabs on every
/// allocation is exactly the cost this avoids.
#[derive(Clone, Copy, Debug)]
struct Cache {
    object_size: usize,
    partial: Pfn,
}

/// The kernel heap.
pub struct Heap {
    pmm: Pmm,
    /// Base of the higher-half direct map, for turning a frame number into a
    /// usable pointer and back.
    hhdm_base: u64,
    caches: [Cache; CLASS_COUNT],
    /// Live slab-backed objects, for leak detection.
    live_objects: u64,
    /// Frames currently held by slabs.
    slab_frames: u64,
}

/// Maps a size to its class index, or `None` if it belongs to the buddy path.
#[must_use]
pub fn class_for(size: usize) -> Option<usize> {
    if size > MAX_SLAB_SIZE {
        return None;
    }
    let mut index = 0;
    while index < CLASS_COUNT {
        if size <= CLASS_SIZES[index] {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// The buddy order needed to hold `bytes`.
#[must_use]
pub fn order_for(bytes: usize) -> usize {
    let frames = (bytes as u64).div_ceil(FRAME_SIZE);
    let mut order = 0;
    while (1u64 << order) < frames {
        order += 1;
    }
    order
}

impl Heap {
    /// Creates a heap over `pmm`.
    ///
    /// `hhdm_base` must be the higher-half direct map base: every frame the
    /// buddy allocator returns is reached at `hhdm_base + physical`.
    #[must_use]
    pub fn new(pmm: Pmm, hhdm_base: u64) -> Self {
        let mut caches = [Cache {
            object_size: 0,
            partial: NO_FRAME,
        }; CLASS_COUNT];
        let mut index = 0;
        while index < CLASS_COUNT {
            caches[index] = Cache {
                object_size: CLASS_SIZES[index],
                partial: NO_FRAME,
            };
            index += 1;
        }
        Self {
            pmm,
            hhdm_base,
            caches,
            live_objects: 0,
            slab_frames: 0,
        }
    }

    /// The physical allocator underneath.
    #[must_use]
    pub fn pmm(&self) -> &Pmm {
        &self.pmm
    }

    /// Mutable access to the physical allocator.
    pub fn pmm_mut(&mut self) -> &mut Pmm {
        &mut self.pmm
    }

    /// Objects currently handed out from slabs.
    #[must_use]
    pub const fn live_objects(&self) -> u64 {
        self.live_objects
    }

    /// Frames currently held by slabs.
    #[must_use]
    pub const fn slab_frames(&self) -> u64 {
        self.slab_frames
    }

    /// Virtual address of a frame, through the direct map.
    const fn page_address(&self, pfn: Pfn) -> u64 {
        self.hhdm_base + (pfn as u64) * FRAME_SIZE
    }

    /// Frame number containing a virtual address in the direct map.
    const fn pfn_of(&self, address: u64) -> Pfn {
        ((address - self.hhdm_base) / FRAME_SIZE) as Pfn
    }

    /// Allocates `size` bytes aligned to `align`.
    ///
    /// # Errors
    ///
    /// See [`HeapError`].
    ///
    /// # Safety
    ///
    /// The returned memory is uninitialised. The caller must not read it
    /// before writing, and must free it with the same size and alignment.
    pub unsafe fn allocate(&mut self, size: usize, align: usize) -> Result<u64, HeapError> {
        // An object of size 2^n at a multiple of 2^n inside a 4 KiB-aligned
        // page is aligned to 2^n. So any alignment up to the class size is
        // free, and anything larger has to come from whole pages, which are
        // 4 KiB aligned.
        if align > FRAME_SIZE as usize {
            return Err(HeapError::UnsupportedAlignment(align));
        }

        let effective = size.max(align).max(1);

        match class_for(effective) {
            // SAFETY: delegated; `allocate_from_slab` upholds the same contract.
            Some(class) => unsafe { self.allocate_from_slab(class) },
            None => self.allocate_pages(effective),
        }
    }

    /// Allocates whole pages for something too large for a slab.
    fn allocate_pages(&mut self, size: usize) -> Result<u64, HeapError> {
        let order = order_for(size);
        match self.pmm.allocate(order, Zone::Normal) {
            Ok(pfn) => Ok(self.page_address(pfn)),
            Err(PmmError::OrderTooLarge(_)) => Err(HeapError::TooLarge(size)),
            Err(_) => Err(HeapError::OutOfMemory),
        }
    }

    /// Takes one object from `class`, growing the cache if needed.
    ///
    /// # Safety
    ///
    /// Writes to the free-list link inside the object being returned, which
    /// requires that the slab page is mapped and owned by this allocator.
    unsafe fn allocate_from_slab(&mut self, class: usize) -> Result<u64, HeapError> {
        let pfn = if self.caches[class].partial == NO_FRAME {
            // SAFETY: `grow` initialises a freshly allocated page it owns.
            unsafe { self.grow(class)? }
        } else {
            self.caches[class].partial
        };

        let object_size = self.caches[class].object_size;

        let offset = {
            let slab = self.pmm.slab_mut(pfn).ok_or(HeapError::NotAllocated)?;
            let offset = slab.free_head;
            if offset == NO_OFFSET {
                // A slab on the partial list with no free object is a broken
                // invariant, not a recoverable condition.
                return Err(HeapError::NotAllocated);
            }
            slab.in_use += 1;
            offset
        };

        let address = self.page_address(pfn) + u64::from(offset);

        // Pop: the next free offset is stored in the first two bytes of the
        // object being handed out.
        // SAFETY: `address` is inside a slab page this allocator owns, and the
        // object is at least 16 bytes, so a `u16` at its start is in bounds.
        // The value was written by `free` or by `grow`.
        let next = unsafe { (address as *const u16).read() };
        if let Some(slab) = self.pmm.slab_mut(pfn) {
            slab.free_head = next;
        }

        // A slab with nothing left comes off the partial list; it is re-linked
        // the moment something is freed back into it.
        if next == NO_OFFSET {
            self.unlink_partial(class, pfn);
        }

        self.live_objects += 1;
        let _ = object_size;
        Ok(address)
    }

    /// Allocates a page and turns it into a slab for `class`.
    ///
    /// # Safety
    ///
    /// Writes the initial free list into the page, which requires that the
    /// page is mapped through the direct map and owned by this allocator.
    unsafe fn grow(&mut self, class: usize) -> Result<Pfn, HeapError> {
        let object_size = self.caches[class].object_size;
        let pfn = self
            .pmm
            .allocate(0, Zone::Normal)
            .map_err(|_| HeapError::OutOfMemory)?;

        let base = self.page_address(pfn);
        let count = FRAME_SIZE as usize / object_size;

        // Thread every object onto the free list, last one terminating it.
        // SAFETY: `base` is a freshly allocated 4 KiB page reached through the
        // direct map, and every offset written is below FRAME_SIZE. Nothing
        // else holds a reference: the buddy allocator just handed it over.
        unsafe {
            for index in 0..count {
                let offset = index * object_size;
                let next = if index + 1 == count {
                    NO_OFFSET
                } else {
                    (offset + object_size) as u16
                };
                ((base + offset as u64) as *mut u16).write(next);
            }
        }

        if let Some(slab) = self.pmm.slab_mut(pfn) {
            slab.free_head = 0;
            slab.in_use = 0;
            slab.class = class as u8;
            slab.next = NO_FRAME;
            slab.prev = NO_FRAME;
        }

        self.slab_frames += 1;
        self.link_partial(class, pfn);
        Ok(pfn)
    }

    /// Puts `pfn` at the head of `class`'s partial list.
    fn link_partial(&mut self, class: usize, pfn: Pfn) {
        let head = self.caches[class].partial;
        if let Some(slab) = self.pmm.slab_mut(pfn) {
            slab.next = head;
            slab.prev = NO_FRAME;
        }
        if head != NO_FRAME
            && let Some(old) = self.pmm.slab_mut(head)
        {
            old.prev = pfn;
        }
        self.caches[class].partial = pfn;
    }

    /// Removes `pfn` from `class`'s partial list.
    fn unlink_partial(&mut self, class: usize, pfn: Pfn) {
        let (next, prev) = match self.pmm.slab(pfn) {
            Some(slab) => (slab.next, slab.prev),
            None => return,
        };

        if prev == NO_FRAME {
            self.caches[class].partial = next;
        } else if let Some(slab) = self.pmm.slab_mut(prev) {
            slab.next = next;
        }
        if next != NO_FRAME
            && let Some(slab) = self.pmm.slab_mut(next)
        {
            slab.prev = prev;
        }

        if let Some(slab) = self.pmm.slab_mut(pfn) {
            slab.next = NO_FRAME;
            slab.prev = NO_FRAME;
        }
    }

    /// Returns memory obtained from [`Heap::allocate`].
    ///
    /// # Errors
    ///
    /// [`HeapError::NotAllocated`] if the pointer does not belong to a slab of
    /// the expected class.
    ///
    /// # Safety
    ///
    /// `address` must have come from [`Heap::allocate`] with the same `size`
    /// and `align`, and must not be used afterwards.
    pub unsafe fn free(
        &mut self,
        address: u64,
        size: usize,
        align: usize,
    ) -> Result<(), HeapError> {
        let effective = size.max(align).max(1);

        let Some(class) = class_for(effective) else {
            // Whole pages: return them to the buddy allocator directly.
            let order = order_for(effective);
            let pfn = self.pfn_of(address);
            return self
                .pmm
                .free(pfn, order)
                .map_err(|_| HeapError::NotAllocated);
        };

        let pfn = self.pfn_of(address);
        let object_size = self.caches[class].object_size;
        let page_base = self.page_address(pfn);
        let offset = (address - page_base) as u16;

        let (was_full, now_empty) = {
            let slab = self.pmm.slab_mut(pfn).ok_or(HeapError::NotAllocated)?;
            if slab.class as usize != class {
                // The pointer belongs to a different size class, which means
                // the caller's Layout does not match what was allocated.
                return Err(HeapError::NotAllocated);
            }
            let was_full = slab.free_head == NO_OFFSET;
            slab.in_use = slab.in_use.saturating_sub(1);
            (was_full, slab.in_use == 0)
        };

        // Push the object back onto the free list, storing the old head in it.
        let old_head = self.pmm.slab(pfn).map_or(NO_OFFSET, |slab| slab.free_head);
        // SAFETY: `address` is inside a slab page this allocator owns and the
        // object is at least 16 bytes, so a `u16` at its start is in bounds.
        unsafe { (address as *mut u16).write(old_head) };
        if let Some(slab) = self.pmm.slab_mut(pfn) {
            slab.free_head = offset;
        }

        if was_full {
            self.link_partial(class, pfn);
        }

        self.live_objects = self.live_objects.saturating_sub(1);

        // Return wholly unused slabs to the buddy allocator, so a burst of
        // allocations does not permanently retain memory in one size class.
        if now_empty {
            self.unlink_partial(class, pfn);
            if let Some(slab) = self.pmm.slab_mut(pfn) {
                *slab = crate::pmm::SlabInfo::empty();
            }
            self.slab_frames -= 1;
            self.pmm.free(pfn, 0).map_err(|_| HeapError::NotAllocated)?;
        }

        let _ = object_size;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pmm::{Frame, FrameState};

    /// A heap backed by a real page-aligned buffer, so the tests exercise the
    /// actual pointer arithmetic rather than a model of it. `hhdm_base` points
    /// at the buffer, which makes frame 0 the first page of it.
    struct TestHeap {
        heap: Heap,
        _backing: *mut u8,
        layout: core::alloc::Layout,
    }

    impl TestHeap {
        fn new(pages: usize) -> Self {
            let layout =
                core::alloc::Layout::from_size_align(pages * FRAME_SIZE as usize, 4096).unwrap();
            // SAFETY: non-zero size, valid power-of-two alignment.
            let backing = unsafe { std::alloc::alloc(layout) };
            assert!(!backing.is_null());

            let frames = vec![Frame::reserved(); pages].into_boxed_slice();
            let mut pmm = Pmm::new(Box::leak(frames));
            pmm.add_free_range(0, pages as Pfn);

            Self {
                heap: Heap::new(pmm, backing as u64),
                _backing: backing,
                layout,
            }
        }
    }

    impl Drop for TestHeap {
        fn drop(&mut self) {
            // SAFETY: allocated in `new` with this exact layout.
            unsafe { std::alloc::dealloc(self._backing, self.layout) };
        }
    }

    #[test]
    fn size_classes_round_up_to_the_next_power_of_two() {
        assert_eq!(class_for(1), Some(0));
        assert_eq!(class_for(16), Some(0));
        assert_eq!(class_for(17), Some(1));
        assert_eq!(class_for(2048), Some(7));
        assert_eq!(class_for(2049), None);
    }

    #[test]
    fn page_orders_cover_the_requested_size() {
        assert_eq!(order_for(1), 0);
        assert_eq!(order_for(4096), 0);
        assert_eq!(order_for(4097), 1);
        assert_eq!(order_for(8192), 1);
        assert_eq!(order_for(8193), 2);
    }

    #[test]
    fn allocations_are_correctly_aligned() {
        let mut t = TestHeap::new(64);
        for &size in &CLASS_SIZES {
            let address = unsafe { t.heap.allocate(size, size) }.unwrap();
            assert!(
                address.is_multiple_of(size as u64),
                "{size}-byte object at {address:#x} is not {size}-aligned"
            );
        }
    }

    #[test]
    fn allocations_never_overlap() {
        let mut t = TestHeap::new(16);
        let mut live = Vec::new();
        // Exhaust one slab's worth of 64-byte objects and then some.
        for _ in 0..200 {
            match unsafe { t.heap.allocate(64, 8) } {
                Ok(address) => live.push(address),
                Err(_) => break,
            }
        }
        assert!(live.len() >= 64, "expected at least one full slab");

        let mut sorted = live.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), live.len(), "an address was handed out twice");

        for pair in sorted.windows(2) {
            assert!(pair[1] - pair[0] >= 64, "objects at {pair:?} overlap");
        }
    }

    #[test]
    fn memory_is_writable_and_holds_its_contents() {
        // The free-list links live inside free objects, so a bug there shows
        // up as one allocation corrupting another's data.
        let mut t = TestHeap::new(16);
        let mut live = Vec::new();
        for index in 0..100u64 {
            let address = unsafe { t.heap.allocate(64, 8) }.unwrap();
            unsafe { (address as *mut u64).write(index) };
            live.push((address, index));
        }
        for (address, expected) in live {
            let actual = unsafe { (address as *const u64).read() };
            assert_eq!(actual, expected, "object at {address:#x} was corrupted");
        }
    }

    #[test]
    fn freeing_returns_memory_for_reuse() {
        let mut t = TestHeap::new(16);
        let first = unsafe { t.heap.allocate(64, 8) }.unwrap();
        unsafe { t.heap.free(first, 64, 8) }.unwrap();
        let second = unsafe { t.heap.allocate(64, 8) }.unwrap();
        assert_eq!(first, second, "a freed object was not reused");
    }

    #[test]
    fn empty_slabs_are_returned_to_the_buddy_allocator() {
        let mut t = TestHeap::new(16);
        let free_before = t.heap.pmm().free_frames();

        let mut live = Vec::new();
        for _ in 0..64 {
            live.push(unsafe { t.heap.allocate(64, 8) }.unwrap());
        }
        assert!(
            t.heap.pmm().free_frames() < free_before,
            "no page was taken"
        );

        for address in live {
            unsafe { t.heap.free(address, 64, 8) }.unwrap();
        }
        assert_eq!(
            t.heap.pmm().free_frames(),
            free_before,
            "an emptied slab was not returned to the buddy allocator"
        );
        assert_eq!(t.heap.slab_frames(), 0);
        assert_eq!(t.heap.live_objects(), 0);
    }

    #[test]
    fn large_allocations_bypass_the_slab() {
        let mut t = TestHeap::new(64);
        let free_before = t.heap.pmm().free_frames();

        let address = unsafe { t.heap.allocate(8192, 8) }.unwrap();
        assert!(
            address.is_multiple_of(4096),
            "page allocation is not page aligned"
        );
        // Two pages, so a whole order-1 block.
        assert_eq!(t.heap.pmm().free_frames(), free_before - 2);

        unsafe { t.heap.free(address, 8192, 8) }.unwrap();
        assert_eq!(t.heap.pmm().free_frames(), free_before);
    }

    #[test]
    fn rejects_alignment_larger_than_a_page() {
        let mut t = TestHeap::new(8);
        assert_eq!(
            unsafe { t.heap.allocate(16, 8192) },
            Err(HeapError::UnsupportedAlignment(8192))
        );
    }

    #[test]
    fn reports_out_of_memory_rather_than_returning_garbage() {
        let mut t = TestHeap::new(2);
        let mut count = 0;
        loop {
            match unsafe { t.heap.allocate(2048, 8) } {
                Ok(_) => count += 1,
                Err(error) => {
                    assert_eq!(error, HeapError::OutOfMemory);
                    break;
                }
            }
            assert!(count < 1000, "allocator never reported exhaustion");
        }
        assert!(count > 0);
    }

    #[test]
    fn nothing_leaks_across_mixed_traffic() {
        // The property that matters: any sequence of allocations and frees
        // must return every frame to the buddy allocator.
        let mut t = TestHeap::new(64);
        let baseline = t.heap.pmm().free_frames();
        let mut live: Vec<(u64, usize)> = Vec::new();

        let mut seed = 0x9E37_79B9u32;
        let mut next = || {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (seed >> 16) as usize
        };

        for _ in 0..20_000 {
            if live.is_empty() || next().is_multiple_of(2) {
                let size = CLASS_SIZES[next() % CLASS_COUNT];
                if let Ok(address) = unsafe { t.heap.allocate(size, 8) } {
                    // Write through the whole object, so any overlap between
                    // two live allocations corrupts one of them.
                    unsafe { core::ptr::write_bytes(address as *mut u8, 0xab, size) };
                    live.push((address, size));
                }
            } else {
                let index = next() % live.len();
                let (address, size) = live.swap_remove(index);
                unsafe { t.heap.free(address, size, 8) }.unwrap();
            }
        }

        for (address, size) in live {
            unsafe { t.heap.free(address, size, 8) }.unwrap();
        }

        assert_eq!(t.heap.live_objects(), 0);
        assert_eq!(t.heap.slab_frames(), 0, "slab pages were leaked");
        assert_eq!(t.heap.pmm().free_frames(), baseline, "frames were leaked");
        assert_eq!(t.heap.pmm().check_invariants(), Ok(()));
    }

    #[test]
    fn a_frame_backing_a_slab_is_marked_allocated() {
        let mut t = TestHeap::new(8);
        let address = unsafe { t.heap.allocate(64, 8) }.unwrap();
        let pfn = ((address - t._backing as u64) / FRAME_SIZE) as Pfn;
        assert_eq!(
            t.heap.pmm().frame(pfn).unwrap().state,
            FrameState::Allocated
        );
    }
}
