// SPDX-License-Identifier: Apache-2.0
//! Virtual memory regions and the map that owns them.
//!
//! Implements the portable half of `docs/memory.md` §3. The page table is a
//! *cache* of what this module says; the [`RangeMap`] is the source of truth.
//!
//! That inversion is the important design choice. On a page fault the kernel
//! consults the region map to decide whether the access is legal, and only
//! then populates the page table. It is what makes demand paging,
//! copy-on-write, and file-backed mappings one mechanism rather than three
//! special cases — and it means a missing page table entry is a normal
//! condition rather than a bug.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use bhaskix_boot::VirtAddr;

/// Size of a virtual page.
pub const PAGE_SIZE: u64 = 4096;

/// What a mapping permits.
///
/// **Write and execute cannot both be set.** There is no variant for it, no
/// flag to override it, and no boot parameter that relaxes it
/// (`docs/memory.md` §3). JIT workloads use two mappings of the same frames
/// with different protections, which is the standard modern approach and keeps
/// the invariant checkable by reading this enum rather than by auditing every
/// call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    /// Present but inaccessible — a guard page.
    ///
    /// Distinct from "not mapped": the region exists and is reserved, so a
    /// fault on it is a stack overflow or a deliberate probe rather than a
    /// wild pointer, and the fault handler can say which.
    None,
    /// Readable only.
    ReadOnly,
    /// Readable and writable. Not executable.
    ReadWrite,
    /// Readable and executable. Not writable.
    ReadExecute,
}

impl Protection {
    /// Whether reads are permitted.
    #[must_use]
    pub const fn readable(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Whether writes are permitted.
    #[must_use]
    pub const fn writable(self) -> bool {
        matches!(self, Self::ReadWrite)
    }

    /// Whether instruction fetches are permitted.
    #[must_use]
    pub const fn executable(self) -> bool {
        matches!(self, Self::ReadExecute)
    }

    /// Whether this mapping should be present in the page table at all.
    #[must_use]
    pub const fn present(self) -> bool {
        !matches!(self, Self::None)
    }
}

impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "---",
            Self::ReadOnly => "r--",
            Self::ReadWrite => "rw-",
            Self::ReadExecute => "r-x",
        })
    }
}

/// A half-open range of virtual addresses, `[start, end)`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VirtRange {
    /// First address in the range. Page aligned.
    pub start: VirtAddr,
    /// One past the last address. Page aligned.
    pub end: VirtAddr,
}

impl VirtRange {
    /// Creates a range, returning `None` unless it is page-aligned and
    /// non-empty.
    #[must_use]
    pub const fn new(start: VirtAddr, end: VirtAddr) -> Option<Self> {
        if start.as_u64() >= end.as_u64() {
            return None;
        }
        if !start.as_u64().is_multiple_of(PAGE_SIZE) || !end.as_u64().is_multiple_of(PAGE_SIZE) {
            return None;
        }
        Some(Self { start, end })
    }

    /// Creates a range of `pages` pages starting at `start`.
    #[must_use]
    pub const fn from_pages(start: VirtAddr, pages: u64) -> Option<Self> {
        Self::new(start, VirtAddr(start.as_u64() + pages * PAGE_SIZE))
    }

    /// Length in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end.as_u64() - self.start.as_u64()
    }

    /// Whether the range covers no bytes. Never true for a constructed range.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of pages spanned.
    #[must_use]
    pub const fn pages(&self) -> u64 {
        self.len() / PAGE_SIZE
    }

    /// Whether `address` falls inside.
    #[must_use]
    pub const fn contains(&self, address: VirtAddr) -> bool {
        address.as_u64() >= self.start.as_u64() && address.as_u64() < self.end.as_u64()
    }

    /// Whether two ranges share any address.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start.as_u64() < other.end.as_u64() && other.start.as_u64() < self.end.as_u64()
    }

    /// Iterates the page-aligned addresses in the range.
    pub fn pages_iter(&self) -> impl Iterator<Item = VirtAddr> + '_ {
        (0..self.pages()).map(|index| VirtAddr(self.start.as_u64() + index * PAGE_SIZE))
    }
}

impl fmt::Debug for VirtRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#018x}..{:#018x}",
            self.start.as_u64(),
            self.end.as_u64()
        )
    }
}

/// What backs a region's pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backing {
    /// Zero-filled on first touch.
    Anonymous,
    /// A fixed physical range — device registers, or the kernel image.
    Direct {
        /// Physical address the region starts at.
        physical: u64,
    },
    /// Reserved address space with nothing behind it. Guard pages.
    Reserved,
    /// Frames owned by a `Memory` object, not by this address space.
    ///
    /// [RFC 0009](../../docs/rfc/0009-shared-memory.md). The distinction is
    /// the whole point of the variant: **tearing down an address space must
    /// not free these frames**, because they belong to the object and may be
    /// mapped somewhere else as well. Every path that releases memory checks
    /// for [`Backing::Anonymous`] rather than for "not reserved", so a shared
    /// region is skipped by construction rather than by a branch somebody has
    /// to remember to add.
    Shared {
        /// Which object, as its arena index. An opaque number here: `mm` does
        /// not know what a `Memory` object is, and should not — it needs only
        /// to know that these frames are not its to free.
        object: u32,
    },
}

/// Additional properties of a region.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RegionFlags {
    /// Writes fault and copy the frame rather than modifying it.
    pub copy_on_write: bool,
    /// Never reclaimed or swapped.
    pub locked: bool,
    /// Mapped eagerly rather than on first fault.
    pub populate: bool,
}

/// One contiguous mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmRegion {
    /// The addresses covered.
    pub range: VirtRange,
    /// What access is permitted.
    pub protection: Protection,
    /// What the pages are backed by.
    pub backing: Backing,
    /// Additional properties.
    pub flags: RegionFlags,
}

impl VmRegion {
    /// A region with default flags.
    #[must_use]
    pub const fn new(range: VirtRange, protection: Protection, backing: Backing) -> Self {
        Self {
            range,
            protection,
            backing,
            flags: RegionFlags {
                copy_on_write: false,
                locked: false,
                populate: false,
            },
        }
    }
}

/// Why a region could not be inserted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeMapError {
    /// The range overlaps an existing region, at this index.
    Overlaps(usize),
    /// No region covers the requested range.
    NotFound,
    /// Out of memory while growing the map.
    OutOfMemory,
}

/// A sorted, non-overlapping set of regions.
///
/// A `Vec` with binary search rather than a balanced tree. Address spaces
/// hold tens of regions, not thousands, and at that size the flat array wins
/// on both cache behaviour and on being obviously correct — which matters more
/// here, since this structure decides whether a memory access is legal. If
/// profiling ever shows the linear insert cost mattering, the interface is
/// narrow enough to swap the implementation behind.
#[derive(Clone, Debug, Default)]
pub struct RangeMap {
    regions: Vec<VmRegion>,
}

impl RangeMap {
    /// An empty map.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    /// Gives `[start, start + pages)` a new protection, **splitting** the
    /// region it falls inside if it is only part of one.
    ///
    /// # Why this is here and not in `AddressSpace::protect`
    ///
    /// Splitting a live range is the part with the failure modes, and it is
    /// pure: it moves entries in a sorted array and touches no page table. Kept
    /// here it can be tested on a host without a machine, which is what the rest
    /// of `protect` cannot be. `MAP_AT`'s own comment called this *"a different
    /// piece of work with its own failure modes"* and deferred it; these are
    /// the failure modes, handled where they can be watched.
    ///
    /// # What it refuses
    ///
    /// A range that is not wholly inside **one** region. Spanning two is a
    /// different operation — the regions may differ in backing, and merging that
    /// question into this one is how a caller silently reprotects memory it did
    /// not name.
    ///
    /// # Why the reserve comes first
    ///
    /// A split turns one region into as many as three, so the array may need to
    /// grow twice. **Growing after the original is removed is the bug this
    /// ordering exists to prevent**: an allocation failure there would leave the
    /// map with a hole where a live mapping used to be, and the page tables
    /// still pointing at it — memory that is mapped and that the map says is
    /// free. So the space is reserved while the map is still whole, and a
    /// refusal happens before anything is disturbed.
    ///
    /// Answers the range whose pages the caller must now reprotect, which is
    /// the middle piece.
    ///
    /// # Errors
    ///
    /// [`RangeMapError::NotFound`] if no single region holds the whole range,
    /// [`RangeMapError::OutOfMemory`] if the array cannot make room.
    pub fn reprotect(
        &mut self,
        start: VirtAddr,
        pages: u64,
        protection: Protection,
    ) -> Result<VirtRange, RangeMapError> {
        let Some(wanted) = VirtRange::from_pages(start, pages) else {
            return Err(RangeMapError::NotFound);
        };
        let region = *self.find(start).ok_or(RangeMapError::NotFound)?;
        // Wholly inside, and `contains` is not enough on its own: a range that
        // starts inside and ends past the end is the spanning case above.
        if wanted.start.as_u64() < region.range.start.as_u64()
            || wanted.end.as_u64() > region.range.end.as_u64()
        {
            return Err(RangeMapError::NotFound);
        }

        let head = (wanted.start.as_u64() > region.range.start.as_u64())
            .then(|| {
                VirtRange::from_pages(
                    region.range.start,
                    (wanted.start.as_u64() - region.range.start.as_u64()) / crate::FRAME_SIZE,
                )
            })
            .flatten();
        let tail = (wanted.end.as_u64() < region.range.end.as_u64())
            .then(|| {
                VirtRange::from_pages(
                    wanted.end,
                    (region.range.end.as_u64() - wanted.end.as_u64()) / crate::FRAME_SIZE,
                )
            })
            .flatten();

        // Before anything is removed. See above.
        let extra = usize::from(head.is_some()) + usize::from(tail.is_some());
        self.regions
            .try_reserve(extra)
            .map_err(|_| RangeMapError::OutOfMemory)?;

        self.remove(region.range.start)?;
        // Every piece keeps the original's backing and flags; only the middle's
        // protection changes. A head or tail that lost its backing would be a
        // region the fault handler could not service.
        let mut middle = region;
        middle.range = wanted;
        middle.protection = protection;
        self.insert(middle)?;
        if let Some(head) = head {
            let mut piece = region;
            piece.range = head;
            self.insert(piece)?;
        }
        if let Some(tail) = tail {
            let mut piece = region;
            piece.range = tail;
            self.insert(piece)?;
        }
        Ok(wanted)
    }

    /// Number of regions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Whether the map holds no regions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// All regions, in ascending address order.
    pub fn iter(&self) -> impl Iterator<Item = &VmRegion> {
        self.regions.iter()
    }

    /// Index of the region containing `address`, if any.
    fn index_of(&self, address: VirtAddr) -> Option<usize> {
        // Binary search for the last region starting at or below `address`,
        // then check that it actually reaches far enough.
        let mut low = 0usize;
        let mut high = self.regions.len();
        while low < high {
            let mid = (low + high) / 2;
            if self.regions[mid].range.start.as_u64() <= address.as_u64() {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        if low == 0 {
            return None;
        }
        let candidate = low - 1;
        if self.regions[candidate].range.contains(address) {
            Some(candidate)
        } else {
            None
        }
    }

    /// The region containing `address`, if any.
    #[must_use]
    pub fn find(&self, address: VirtAddr) -> Option<&VmRegion> {
        self.index_of(address).map(|index| &self.regions[index])
    }

    /// Inserts `region`, keeping the map sorted.
    ///
    /// # Errors
    ///
    /// [`RangeMapError::Overlaps`] if it intersects an existing region.
    /// Overlap is rejected rather than resolved: silently replacing part of a
    /// mapping is how a region ends up with two owners.
    pub fn insert(&mut self, region: VmRegion) -> Result<(), RangeMapError> {
        let position = self.regions.partition_point(|existing| {
            existing.range.start.as_u64() < region.range.start.as_u64()
        });

        // Only the neighbours can overlap, because the map is sorted and
        // already non-overlapping.
        if position > 0 && self.regions[position - 1].range.overlaps(&region.range) {
            return Err(RangeMapError::Overlaps(position - 1));
        }
        if position < self.regions.len() && self.regions[position].range.overlaps(&region.range) {
            return Err(RangeMapError::Overlaps(position));
        }

        self.regions
            .try_reserve(1)
            .map_err(|_| RangeMapError::OutOfMemory)?;
        self.regions.insert(position, region);
        Ok(())
    }

    /// Removes the region starting exactly at `start`, returning it.
    ///
    /// # Errors
    ///
    /// [`RangeMapError::NotFound`] if no region starts there. Partial
    /// unmapping — splitting a region in two — is deliberately not supported
    /// yet: it needs the page-table teardown to split with it, and doing one
    /// without the other leaves the table describing memory the map says is
    /// gone.
    pub fn remove(&mut self, start: VirtAddr) -> Result<VmRegion, RangeMapError> {
        let index = self
            .regions
            .iter()
            .position(|region| region.range.start == start)
            .ok_or(RangeMapError::NotFound)?;
        Ok(self.regions.remove(index))
    }

    /// Removes and returns every region, leaving the map empty.
    ///
    /// Used when tearing an address space down, where every mapping has to be
    /// walked to release its frames.
    pub fn drain(&mut self) -> Vec<VmRegion> {
        core::mem::take(&mut self.regions)
    }

    /// Finds `pages` consecutive free pages within `[low, high)`.
    ///
    /// Returns the lowest such range, so allocation is deterministic and
    /// therefore reproducible in tests. Randomised placement belongs with
    /// ASLR, which is a policy layered on top rather than a property of this
    /// structure.
    #[must_use]
    pub fn find_free(&self, low: VirtAddr, high: VirtAddr, pages: u64) -> Option<VirtRange> {
        let needed = pages * PAGE_SIZE;
        let mut candidate = low.as_u64();

        for region in &self.regions {
            let start = region.range.start.as_u64();
            let end = region.range.end.as_u64();

            if end <= candidate {
                continue; // Entirely below the search cursor.
            }
            if start >= high.as_u64() {
                break; // Beyond the search window; the map is sorted.
            }
            if start.saturating_sub(candidate) >= needed {
                return VirtRange::from_pages(VirtAddr(candidate), pages);
            }
            candidate = candidate.max(end);
        }

        if high.as_u64().saturating_sub(candidate) >= needed {
            return VirtRange::from_pages(VirtAddr(candidate), pages);
        }
        None
    }

    /// Checks that the map is sorted and non-overlapping.
    ///
    /// # Errors
    ///
    /// A description of the first invariant that does not hold.
    pub fn check_invariants(&self) -> Result<(), &'static str> {
        for pair in self.regions.windows(2) {
            if pair[1].range.start.as_u64() < pair[0].range.end.as_u64() {
                return Err("regions overlap or are out of order");
            }
        }
        for region in &self.regions {
            if region.range.is_empty() {
                return Err("a region covers no pages");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: u64, pages: u64) -> VirtRange {
        VirtRange::from_pages(VirtAddr(start), pages).unwrap()
    }

    fn region(start: u64, pages: u64) -> VmRegion {
        VmRegion::new(
            range(start, pages),
            Protection::ReadWrite,
            Backing::Anonymous,
        )
    }

    const PAGE: u64 = crate::FRAME_SIZE;

    /// The middle of a region becomes its own, and the two ends survive.
    ///
    /// **This is what glibc's start-up needs.** A static-PIE binary re-protects
    /// its RELRO segment, which is a sub-range of a larger one it was loaded
    /// into; `protect` refused it because it required the range to be exactly a
    /// whole region, and BusyBox printed *"cannot apply additional memory
    /// protection after relocation"* and gave up.
    #[test]
    fn reprotecting_the_middle_splits_the_region_in_three() {
        let mut map = RangeMap::new();
        map.insert(region(0x1000, 8)).expect("room");

        let changed = map
            .reprotect(VirtAddr(0x1000 + 2 * PAGE), 3, Protection::ReadOnly)
            .expect("the middle is inside the region");
        assert_eq!(changed.start.as_u64(), 0x1000 + 2 * PAGE);
        assert_eq!(map.len(), 3, "head, middle and tail");

        let head = map.find(VirtAddr(0x1000)).expect("head");
        let middle = map.find(VirtAddr(0x1000 + 2 * PAGE)).expect("middle");
        let tail = map.find(VirtAddr(0x1000 + 5 * PAGE)).expect("tail");
        assert_eq!(
            head.protection,
            Protection::ReadWrite,
            "the head is untouched"
        );
        assert_eq!(
            middle.protection,
            Protection::ReadOnly,
            "the middle changed"
        );
        assert_eq!(
            tail.protection,
            Protection::ReadWrite,
            "the tail is untouched"
        );
        // Every piece keeps what the fault handler needs to service it. A head
        // that lost its backing is a region that faults and cannot be helped.
        assert_eq!(head.backing, Backing::Anonymous);
        assert_eq!(tail.backing, Backing::Anonymous);
        // And the three cover exactly what the one did, with no gap and no
        // overlap -- a gap here is memory that is mapped and that the map
        // believes is free.
        assert_eq!(head.range.end.as_u64(), middle.range.start.as_u64());
        assert_eq!(middle.range.end.as_u64(), tail.range.start.as_u64());
        assert_eq!(tail.range.end.as_u64(), 0x1000 + 8 * PAGE);
    }

    /// A range at either end splits in two, not three.
    #[test]
    fn reprotecting_an_edge_leaves_two_regions() {
        let mut map = RangeMap::new();
        map.insert(region(0x1000, 4)).expect("room");
        map.reprotect(VirtAddr(0x1000), 1, Protection::ReadOnly)
            .expect("the first page is inside");
        assert_eq!(map.len(), 2, "no empty head is inserted");

        let mut map = RangeMap::new();
        map.insert(region(0x1000, 4)).expect("room");
        map.reprotect(VirtAddr(0x1000 + 3 * PAGE), 1, Protection::ReadOnly)
            .expect("the last page is inside");
        assert_eq!(map.len(), 2, "no empty tail is inserted");
    }

    /// The whole region keeps the old behaviour and does not split.
    #[test]
    fn reprotecting_a_whole_region_changes_it_in_place() {
        let mut map = RangeMap::new();
        map.insert(region(0x1000, 4)).expect("room");
        map.reprotect(VirtAddr(0x1000), 4, Protection::ReadOnly)
            .expect("exactly the region");
        assert_eq!(map.len(), 1, "nothing to split");
        assert_eq!(
            map.find(VirtAddr(0x1000)).expect("region").protection,
            Protection::ReadOnly
        );
    }

    /// A range that leaves the region is refused, and **nothing moves**.
    ///
    /// Spanning two regions is a different operation: they may differ in
    /// backing, and answering it here is how a caller reprotects memory it did
    /// not name. The map must be exactly as it was.
    #[test]
    fn a_range_that_runs_past_the_region_is_refused_and_changes_nothing() {
        let mut map = RangeMap::new();
        map.insert(region(0x1000, 4)).expect("room");
        map.insert(region(0x1000 + 4 * PAGE, 4)).expect("room");

        let refused = map.reprotect(VirtAddr(0x1000 + 2 * PAGE), 4, Protection::ReadOnly);
        assert!(refused.is_err(), "it runs into the second region");
        assert_eq!(map.len(), 2, "and the map is untouched");
        assert_eq!(
            map.find(VirtAddr(0x1000)).expect("first").protection,
            Protection::ReadWrite
        );
        assert_eq!(
            map.find(VirtAddr(0x1000 + 4 * PAGE))
                .expect("second")
                .protection,
            Protection::ReadWrite
        );
    }

    /// A range in no region at all is refused.
    #[test]
    fn a_range_in_no_region_is_refused() {
        let mut map = RangeMap::new();
        map.insert(region(0x1000, 2)).expect("room");
        assert!(
            map.reprotect(VirtAddr(0x9000), 1, Protection::ReadOnly)
                .is_err()
        );
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn write_and_execute_cannot_both_be_permitted() {
        // The guarantee is structural: there is no variant that is both, so
        // this is checkable by reading the enum rather than by auditing calls.
        for protection in [
            Protection::None,
            Protection::ReadOnly,
            Protection::ReadWrite,
            Protection::ReadExecute,
        ] {
            assert!(
                !(protection.writable() && protection.executable()),
                "{protection:?} permits both writing and execution"
            );
        }
    }

    #[test]
    fn guard_pages_are_not_present() {
        assert!(!Protection::None.present());
        assert!(!Protection::None.readable());
        assert!(Protection::ReadOnly.present());
    }

    #[test]
    fn ranges_must_be_page_aligned_and_non_empty() {
        assert!(VirtRange::new(VirtAddr(0x1000), VirtAddr(0x2000)).is_some());
        assert!(VirtRange::new(VirtAddr(0x1001), VirtAddr(0x2000)).is_none());
        assert!(VirtRange::new(VirtAddr(0x1000), VirtAddr(0x2001)).is_none());
        assert!(VirtRange::new(VirtAddr(0x2000), VirtAddr(0x2000)).is_none());
        assert!(VirtRange::new(VirtAddr(0x3000), VirtAddr(0x2000)).is_none());
    }

    #[test]
    fn overlap_detection_is_exact_at_the_boundary() {
        let a = range(0x1000, 2); // 0x1000..0x3000
        let b = range(0x3000, 1); // abuts, does not overlap
        let c = range(0x2000, 1); // overlaps
        assert!(!a.overlaps(&b));
        assert!(a.overlaps(&c));
        assert!(c.overlaps(&a));
    }

    #[test]
    fn insert_keeps_the_map_sorted() {
        let mut map = RangeMap::new();
        map.insert(region(0x5000, 1)).unwrap();
        map.insert(region(0x1000, 1)).unwrap();
        map.insert(region(0x3000, 1)).unwrap();

        let starts: Vec<u64> = map.iter().map(|r| r.range.start.as_u64()).collect();
        assert_eq!(starts, vec![0x1000, 0x3000, 0x5000]);
        assert_eq!(map.check_invariants(), Ok(()));
    }

    #[test]
    fn insert_rejects_overlap_rather_than_resolving_it() {
        let mut map = RangeMap::new();
        map.insert(region(0x1000, 4)).unwrap(); // 0x1000..0x5000
        assert!(matches!(
            map.insert(region(0x2000, 1)),
            Err(RangeMapError::Overlaps(_))
        ));
        assert!(matches!(
            map.insert(region(0x1000, 8)),
            Err(RangeMapError::Overlaps(_))
        ));
        // Abutting is fine.
        assert_eq!(map.insert(region(0x5000, 1)), Ok(()));
        assert_eq!(map.check_invariants(), Ok(()));
    }

    #[test]
    fn find_locates_the_containing_region() {
        let mut map = RangeMap::new();
        map.insert(region(0x1000, 2)).unwrap(); // 0x1000..0x3000
        map.insert(region(0x8000, 1)).unwrap(); // 0x8000..0x9000

        assert!(map.find(VirtAddr(0x1000)).is_some());
        assert!(map.find(VirtAddr(0x2fff)).is_some());
        assert!(map.find(VirtAddr(0x3000)).is_none(), "end is exclusive");
        assert!(map.find(VirtAddr(0x7fff)).is_none());
        assert!(map.find(VirtAddr(0x8000)).is_some());
        assert!(map.find(VirtAddr(0x9000)).is_none());
        assert!(map.find(VirtAddr(0)).is_none());
    }

    #[test]
    fn find_agrees_with_a_linear_scan() {
        // The binary search is the part most likely to be subtly wrong, so it
        // is checked against the obvious implementation across every address
        // in a small space.
        let mut map = RangeMap::new();
        for start in [0x1000u64, 0x4000, 0x5000, 0x9000] {
            map.insert(region(start, 1)).unwrap();
        }
        for address in (0..0xc000u64).step_by(0x800) {
            let expected = map
                .iter()
                .find(|r| r.range.contains(VirtAddr(address)))
                .copied();
            let actual = map.find(VirtAddr(address)).copied();
            assert_eq!(actual, expected, "disagreement at {address:#x}");
        }
    }

    #[test]
    fn remove_returns_the_region_and_shrinks_the_map() {
        let mut map = RangeMap::new();
        map.insert(region(0x1000, 1)).unwrap();
        map.insert(region(0x2000, 1)).unwrap();

        let removed = map.remove(VirtAddr(0x1000)).unwrap();
        assert_eq!(removed.range.start.as_u64(), 0x1000);
        assert_eq!(map.len(), 1);
        assert_eq!(map.remove(VirtAddr(0x1000)), Err(RangeMapError::NotFound));
    }

    #[test]
    fn drain_empties_the_map_and_yields_everything() {
        let mut map = RangeMap::new();
        for start in [0x1000u64, 0x2000, 0x3000] {
            map.insert(region(start, 1)).unwrap();
        }
        let drained = map.drain();
        assert_eq!(drained.len(), 3);
        assert!(map.is_empty());
    }

    #[test]
    fn find_free_returns_the_lowest_gap_that_fits() {
        let mut map = RangeMap::new();
        map.insert(region(0x2000, 1)).unwrap(); // 0x2000..0x3000
        map.insert(region(0x5000, 1)).unwrap(); // 0x5000..0x6000

        // Below the first region.
        let found = map
            .find_free(VirtAddr(0x1000), VirtAddr(0x10000), 1)
            .unwrap();
        assert_eq!(found.start.as_u64(), 0x1000);

        // Two pages do not fit at 0x1000, so the gap at 0x3000 is used.
        let found = map
            .find_free(VirtAddr(0x1000), VirtAddr(0x10000), 2)
            .unwrap();
        assert_eq!(found.start.as_u64(), 0x3000);
    }

    #[test]
    fn find_free_never_returns_an_occupied_range() {
        let mut map = RangeMap::new();
        for start in [0x2000u64, 0x4000, 0x7000] {
            map.insert(region(start, 1)).unwrap();
        }
        for pages in 1..=3 {
            if let Some(found) = map.find_free(VirtAddr(0x1000), VirtAddr(0x10000), pages) {
                for existing in map.iter() {
                    assert!(
                        !found.overlaps(&existing.range),
                        "find_free returned {found:?}, which overlaps {:?}",
                        existing.range
                    );
                }
            }
        }
    }

    #[test]
    fn find_free_reports_failure_when_the_window_is_full() {
        let mut map = RangeMap::new();
        map.insert(region(0x1000, 1)).unwrap();
        assert!(
            map.find_free(VirtAddr(0x1000), VirtAddr(0x2000), 1)
                .is_none()
        );
    }

    #[test]
    fn a_freshly_found_range_can_always_be_inserted() {
        // The property that ties the two operations together: whatever
        // find_free suggests, insert must accept.
        let mut map = RangeMap::new();
        for _ in 0..50 {
            let Some(found) = map.find_free(VirtAddr(0x1000), VirtAddr(0x100000), 2) else {
                break;
            };
            let inserted = map.insert(VmRegion::new(
                found,
                Protection::ReadWrite,
                Backing::Anonymous,
            ));
            assert_eq!(
                inserted,
                Ok(()),
                "find_free suggested {found:?}, which insert rejected"
            );
        }
        assert_eq!(map.check_invariants(), Ok(()));
    }
}
