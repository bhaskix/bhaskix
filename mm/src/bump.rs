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
        self.advance_to_usable();
        if self.region >= self.regions.len() {
            return Err(BumpError::OutOfMemory);
        }

        let frame = self.next;
        self.next += FRAME_SIZE;
        self.allocated += 1;
        Ok(PhysAddr(frame))
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
    fn alignment_helpers_round_correctly() {
        assert_eq!(align_up(0, 4096), 0);
        assert_eq!(align_up(1, 4096), 4096);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
        assert_eq!(align_down(4097, 4096), 4096);
        assert_eq!(align_down(4095, 4096), 0);
    }
}
