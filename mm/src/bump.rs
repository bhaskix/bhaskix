// SPDX-License-Identifier: Apache-2.0
//! The boot-time bump allocator.
//!
//! The first of the four allocation stages in `docs/memory.md` §1, and the
//! shortest-lived. It exists because the real allocator cannot bootstrap
//! itself: the buddy allocator needs a frame database, the frame database
//! needs memory, and nothing else can supply it yet.
//!
//! # It is throwaway by design
//!
//! There is **no `free`**, and adding one is a review rejection. That is not an
//! oversight — it is the reason this allocator can be trusted. A structure with
//! one operation, no ordering constraints, and no reuse cannot develop the
//! class of bug that allocators develop. Once M3's buddy allocator is up, every
//! frame handed out here is marked permanently unavailable and this type is
//! never used again.
//!
//! # What it will not touch
//!
//! Only regions the handoff marks [`MemoryKind::Usable`]. In particular *not*
//! [`MemoryKind::BootloaderReclaimable`], which still holds the handoff itself
//! at this point — allocating from it would hand out memory the kernel is
//! still reading (`docs/memory.md` §1).

use bhaskix_boot::{Handoff, MemoryKind, MemoryRegion, PhysAddr};

/// Size of a physical frame.
pub const FRAME_SIZE: u64 = 4096;

/// Most distinct physical ranges the allocator will record as consumed.
///
/// One entry per contiguous run it hands out; runs that abut are merged. A
/// handful of regions is all a real memory map offers, and exceeding this
/// would mean the boot path is allocating far more than it should.
const MAX_CONSUMED_RANGES: usize = 16;

/// Allocates frames by walking forward through usable memory, never reusing.
#[derive(Clone, Copy, Debug)]
pub struct BumpAllocator {
    regions: &'static [MemoryRegion],
    /// Index of the region currently being consumed.
    region: usize,
    /// Next physical address to hand out.
    next: u64,
    /// Frames handed out so far, for reporting.
    allocated: u64,
    /// Physical `[start, end)` ranges handed out, merged where adjacent.
    ///
    /// Recorded because the buddy allocator has to know precisely which
    /// frames are already in use before it takes over. Marking them reserved
    /// *after* adding them to the free lists corrupts the lists — a frame can
    /// be on a free list and reserved at the same time, which the invariant
    /// checker correctly rejects.
    consumed: [(u64, u64); MAX_CONSUMED_RANGES],
    consumed_count: usize,
}

/// Why an allocation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BumpError {
    /// No usable memory remains.
    OutOfMemory,
}

impl BumpAllocator {
    /// Creates an allocator over the handoff's usable regions.
    ///
    /// No exclusion list is needed for the kernel image: the bootloader
    /// reports it as its own region kind, not as usable memory.
    #[must_use]
    pub fn new(handoff: &Handoff) -> Self {
        Self {
            regions: handoff.memory_map,
            region: 0,
            next: 0,
            allocated: 0,
            consumed: [(0, 0); MAX_CONSUMED_RANGES],
            consumed_count: 0,
        }
    }

    /// Positions `next` at the first frame that is actually available,
    /// skipping regions that are not usable or are already exhausted.
    fn advance_to_usable(&mut self) {
        while self.region < self.regions.len() {
            let region = self.regions[self.region];

            if region.kind == MemoryKind::Usable {
                let start = align_up(region.base.as_u64(), FRAME_SIZE);
                if self.next < start {
                    self.next = start;
                }
                // A whole frame must fit: a partial frame at the end of a
                // region is not usable memory, it is a rounding error waiting
                // to be written past.
                if self.next + FRAME_SIZE <= region.end().as_u64() {
                    return;
                }
            }

            self.region += 1;
            self.next = 0;
        }
    }

    /// Allocates `count` physically contiguous frames.
    ///
    /// Needed because the frame database must be one unbroken array, and the
    /// first usable region on a PC is typically a ~300 KiB fragment below the
    /// legacy hole — far too small. Allocating frame-by-frame and hoping they
    /// stay adjacent silently produces a database split across a gap, which
    /// is a corruption that surfaces much later and nowhere near the cause.
    ///
    /// Skips whole regions that cannot satisfy the request rather than
    /// splitting it, and the skipped remainder is simply never handed out.
    /// Wasting a few hundred kilobytes once at boot is a fair price for an
    /// allocator that stays this simple.
    ///
    /// # Errors
    ///
    /// [`BumpError::OutOfMemory`] if no single usable region has room.
    pub fn allocate_contiguous(&mut self, count: u64) -> Result<PhysAddr, BumpError> {
        if count == 0 {
            return Err(BumpError::OutOfMemory);
        }
        let bytes = count * FRAME_SIZE;

        loop {
            self.advance_to_usable();
            if self.region >= self.regions.len() {
                return Err(BumpError::OutOfMemory);
            }

            let region = self.regions[self.region];
            if self.next + bytes <= region.end().as_u64() {
                let base = self.next;
                self.next += bytes;
                self.allocated += count;
                self.record_consumed(base, base + bytes);
                return Ok(PhysAddr(base));
            }

            // This region cannot hold the run. Move on; `advance_to_usable`
            // will position `next` in the following usable region. The index
            // strictly increases, so this terminates.
            self.region += 1;
            self.next = 0;
        }
    }

    /// Allocates one frame, returning its physical address.
    ///
    /// The frame is **not** zeroed. This crate is `forbid(unsafe_code)` and
    /// cannot write physical memory; zeroing is the caller's responsibility,
    /// and `docs/memory.md` §6 requires it on allocation rather than on free.
    ///
    /// # Errors
    ///
    /// [`BumpError::OutOfMemory`] when no usable memory remains.
    pub fn allocate_frame(&mut self) -> Result<PhysAddr, BumpError> {
        self.allocate_contiguous(1)
    }

    /// Notes that `[start, end)` has been handed out, merging with the
    /// previous range when they abut.
    fn record_consumed(&mut self, start: u64, end: u64) {
        if self.consumed_count > 0 {
            let last = &mut self.consumed[self.consumed_count - 1];
            if last.1 == start {
                last.1 = end;
                return;
            }
        }
        if self.consumed_count < MAX_CONSUMED_RANGES {
            self.consumed[self.consumed_count] = (start, end);
            self.consumed_count += 1;
        }
        // Silently dropping a range would understate what is in use and let
        // the buddy allocator hand out live memory, so overflow saturates
        // instead: the last range is stretched to cover the new one.
        else {
            self.consumed[MAX_CONSUMED_RANGES - 1].1 = end;
        }
    }

    /// The physical `[start, end)` ranges this allocator has handed out.
    ///
    /// Sorted ascending and non-overlapping. The buddy allocator must exclude
    /// every one of these before taking over.
    #[must_use]
    pub fn consumed_ranges(&self) -> &[(u64, u64)] {
        &self.consumed[..self.consumed_count]
    }

    /// Frames handed out so far.
    #[must_use]
    pub const fn allocated_frames(&self) -> u64 {
        self.allocated
    }

    /// Bytes handed out so far.
    #[must_use]
    pub const fn allocated_bytes(&self) -> u64 {
        self.allocated * FRAME_SIZE
    }
}

/// Rounds `value` up to a multiple of `alignment`, a power of two.
#[must_use]
pub const fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

/// Rounds `value` down to a multiple of `alignment`, a power of two.
#[must_use]
pub const fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bhaskix_boot::{HANDOFF_VERSION, VirtAddr};

    static MAP: [MemoryRegion; 4] = [
        // Deliberately not frame-aligned, to prove the allocator rounds up.
        MemoryRegion {
            base: PhysAddr(0x1500),
            length: 0x2b00,
            kind: MemoryKind::Usable,
        },
        MemoryRegion {
            base: PhysAddr(0xa_0000),
            length: 0x6_0000,
            kind: MemoryKind::Reserved,
        },
        // Must never be allocated from: the handoff still lives here.
        MemoryRegion {
            base: PhysAddr(0x10_0000),
            length: 0x1_0000,
            kind: MemoryKind::BootloaderReclaimable,
        },
        MemoryRegion {
            base: PhysAddr(0x20_0000),
            length: 0x2000,
            kind: MemoryKind::Usable,
        },
    ];

    fn handoff() -> Handoff {
        Handoff {
            version: HANDOFF_VERSION,
            memory_map: &MAP,
            hhdm_base: VirtAddr(0xffff_8000_0000_0000),
            kernel_phys_base: PhysAddr(0x10_0000),
            kernel_virt_base: VirtAddr(0xffff_ffff_8000_0000),
            framebuffer: None,
            rsdp: None,
            smbios: None,
            cmdline: "",
            loader: "test",
            regions_truncated: false,
        }
    }

    fn drain(allocator: &mut BumpAllocator) -> Vec<u64> {
        let mut frames = Vec::new();
        while let Ok(frame) = allocator.allocate_frame() {
            frames.push(frame.as_u64());
            assert!(frames.len() < 1000, "allocator did not terminate");
        }
        frames
    }

    #[test]
    fn aligns_the_first_frame_up() {
        let mut allocator = BumpAllocator::new(&handoff());
        assert_eq!(allocator.allocate_frame(), Ok(PhysAddr(0x2000)));
    }

    #[test]
    fn hands_out_consecutive_frames() {
        let mut allocator = BumpAllocator::new(&handoff());
        assert_eq!(allocator.allocate_frame(), Ok(PhysAddr(0x2000)));
        assert_eq!(allocator.allocate_frame(), Ok(PhysAddr(0x3000)));
    }

    #[test]
    fn crosses_into_the_next_usable_region() {
        let mut allocator = BumpAllocator::new(&handoff());
        // 0x1500..0x4000 yields 0x2000 and 0x3000 once aligned; the reserved
        // and reclaimable regions are skipped entirely; then 0x200000..0x202000.
        assert_eq!(
            drain(&mut allocator),
            vec![0x2000, 0x3000, 0x20_0000, 0x20_1000]
        );
    }

    #[test]
    fn never_allocates_from_reserved_or_reclaimable_regions() {
        // Guards the classic bring-up bug: handing out bootloader-reclaimable
        // memory while the handoff still lives in it.
        let mut allocator = BumpAllocator::new(&handoff());
        for frame in drain(&mut allocator) {
            let usable = MAP.iter().any(|r| {
                r.kind == MemoryKind::Usable
                    && frame >= r.base.as_u64()
                    && frame + FRAME_SIZE <= r.end().as_u64()
            });
            assert!(usable, "frame {frame:#x} came from a non-usable region");
        }
    }

    #[test]
    fn never_hands_out_a_partial_frame_at_a_region_end() {
        // The first region ends at 0x4000, so 0x3000 is the last whole frame.
        // A partial frame beyond it would be written past the region end.
        let mut allocator = BumpAllocator::new(&handoff());
        for frame in drain(&mut allocator) {
            let fits = MAP
                .iter()
                .any(|r| frame >= r.base.as_u64() && frame + FRAME_SIZE <= r.end().as_u64());
            assert!(fits, "frame {frame:#x} extends past its region");
        }
    }

    #[test]
    fn reports_out_of_memory_rather_than_wrapping() {
        let mut allocator = BumpAllocator::new(&handoff());
        let _ = drain(&mut allocator);
        assert_eq!(allocator.allocate_frame(), Err(BumpError::OutOfMemory));
        // And stays exhausted rather than recovering on a later call.
        assert_eq!(allocator.allocate_frame(), Err(BumpError::OutOfMemory));
    }

    #[test]
    fn accounts_for_what_it_handed_out() {
        let mut allocator = BumpAllocator::new(&handoff());
        let count = drain(&mut allocator).len() as u64;
        assert_eq!(allocator.allocated_frames(), count);
        assert_eq!(allocator.allocated_bytes(), count * FRAME_SIZE);
    }

    #[test]
    fn frames_are_unique() {
        // Reuse would be a correctness disaster and is trivially checkable.
        let mut allocator = BumpAllocator::new(&handoff());
        let mut frames = drain(&mut allocator);
        let total = frames.len();
        frames.sort_unstable();
        frames.dedup();
        assert_eq!(
            frames.len(),
            total,
            "the allocator handed out a frame twice"
        );
    }

    #[test]
    fn contiguous_runs_skip_regions_that_are_too_small() {
        // Mirrors the real PC layout that broke frame-database setup: a small
        // fragment below the legacy hole, then the main block of RAM. A run
        // that does not fit in the fragment must come from the main block
        // rather than straddling the gap.
        static SPLIT: [MemoryRegion; 2] = [
            // Two frames only.
            MemoryRegion {
                base: PhysAddr(0x5_3000),
                length: 0x2000,
                kind: MemoryKind::Usable,
            },
            // Sixteen frames.
            MemoryRegion {
                base: PhysAddr(0x10_0000),
                length: 0x1_0000,
                kind: MemoryKind::Usable,
            },
        ];
        let mut h = handoff();
        h.memory_map = &SPLIT;

        let mut allocator = BumpAllocator::new(&h);
        assert_eq!(allocator.allocate_contiguous(5), Ok(PhysAddr(0x10_0000)));
    }

    #[test]
    fn a_run_that_fits_the_first_region_stays_there() {
        static SPLIT: [MemoryRegion; 2] = [
            MemoryRegion {
                base: PhysAddr(0x5_3000),
                length: 0x2000,
                kind: MemoryKind::Usable,
            },
            MemoryRegion {
                base: PhysAddr(0x10_0000),
                length: 0x1_0000,
                kind: MemoryKind::Usable,
            },
        ];
        let mut h = handoff();
        h.memory_map = &SPLIT;

        let mut allocator = BumpAllocator::new(&h);
        assert_eq!(allocator.allocate_contiguous(2), Ok(PhysAddr(0x5_3000)));
    }

    #[test]
    fn contiguous_runs_lie_inside_a_single_region() {
        let mut allocator = BumpAllocator::new(&handoff());
        let base = allocator.allocate_contiguous(2).unwrap().as_u64();
        // Must lie wholly inside one usable region.
        let inside = MAP.iter().any(|r| {
            r.kind == MemoryKind::Usable
                && base >= r.base.as_u64()
                && base + 2 * FRAME_SIZE <= r.end().as_u64()
        });
        assert!(inside, "run at {base:#x} crosses a region boundary");
    }

    #[test]
    fn a_run_larger_than_any_region_fails() {
        let mut allocator = BumpAllocator::new(&handoff());
        assert_eq!(
            allocator.allocate_contiguous(1000),
            Err(BumpError::OutOfMemory)
        );
    }

    #[test]
    fn a_zero_length_run_is_rejected() {
        let mut allocator = BumpAllocator::new(&handoff());
        assert_eq!(
            allocator.allocate_contiguous(0),
            Err(BumpError::OutOfMemory)
        );
    }

    #[test]
    fn records_what_it_consumed() {
        let mut allocator = BumpAllocator::new(&handoff());
        allocator.allocate_frame().unwrap();
        allocator.allocate_frame().unwrap();
        // Two adjacent frames merge into one recorded range.
        assert_eq!(allocator.consumed_ranges(), &[(0x2000, 0x4000)]);
    }

    #[test]
    fn consumed_ranges_split_when_regions_are_skipped() {
        let mut allocator = BumpAllocator::new(&handoff());
        // Exhausts the first region (2 frames), then crosses to the next.
        let all = drain(&mut allocator);
        assert_eq!(all.len(), 4);
        assert_eq!(
            allocator.consumed_ranges(),
            &[(0x2000, 0x4000), (0x20_0000, 0x20_2000)]
        );
    }

    #[test]
    fn every_allocated_frame_lies_inside_a_consumed_range() {
        // The property the buddy handover depends on: nothing handed out may
        // escape the record, or it would later be treated as free.
        let mut allocator = BumpAllocator::new(&handoff());
        let frames = drain(&mut allocator);
        let ranges = allocator.consumed_ranges().to_vec();
        for frame in frames {
            let covered = ranges
                .iter()
                .any(|&(start, end)| frame >= start && frame + FRAME_SIZE <= end);
            assert!(covered, "frame {frame:#x} was handed out but not recorded");
        }
    }

    #[test]
    fn alignment_helpers_round_correctly() {
        assert_eq!(align_up(0, 4096), 0);
        assert_eq!(align_up(1, 4096), 4096);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
        assert_eq!(align_down(4097, 4096), 4096);
        assert_eq!(align_down(4095, 4096), 0);
    }
}
