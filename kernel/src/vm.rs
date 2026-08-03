// SPDX-License-Identifier: Apache-2.0
//! Address spaces.
//!
//! Joins the two halves of `docs/memory.md` §3: the portable region map
//! (`bhaskix_mm::vm`), which is the source of truth about what is mapped and
//! why, and the x86 page tables (`bhaskix_arch::paging`), which are a cache of
//! that truth the hardware can read.
//!
//! # A deadlock this code has to avoid
//!
//! The physical allocator lives inside the heap, behind a spinlock that is not
//! reentrant. The region map is a `Vec`, so touching it allocates — through the
//! global allocator, which takes that same lock.
//!
//! So the rule here is: **never touch the region map while holding the heap
//! lock**. Region-map work happens first, outside the lock; the lock is then
//! taken for the page-table work, which allocates only through the frame
//! callback and never through the global allocator. Getting this backwards
//! deadlocks on the first mapping, and the stack trace points at the
//! allocator rather than at the mistake.

use bhaskix_arch::paging::{self, MapError, flags};
use bhaskix_boot::VirtAddr;
use bhaskix_mm::vm::{Backing, Protection, RangeMap, RangeMapError, VirtRange, VmRegion};
use bhaskix_mm::{FRAME_SIZE, Zone};

use crate::heap;

/// First address belonging to the kernel half.
const KERNEL_HALF: u64 = 0xffff_8000_0000_0000;

/// Why an address-space operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmError {
    /// The heap, and therefore the physical allocator, is not up yet.
    NoAllocator,
    /// Out of physical memory.
    OutOfMemory,
    /// The region map rejected the change.
    Region(RangeMapError),
    /// The page tables rejected the change.
    Paging(MapError),
}

impl From<RangeMapError> for VmError {
    fn from(error: RangeMapError) -> Self {
        Self::Region(error)
    }
}

impl From<MapError> for VmError {
    fn from(error: MapError) -> Self {
        Self::Paging(error)
    }
}

/// One address space: a page table plus the regions that explain it.
pub struct AddressSpace {
    /// Physical address of the PML4.
    root: u64,
    /// What is mapped, and why. The authority; the page table is its cache.
    regions: RangeMap,
    /// Direct map base, for reaching page tables and frames.
    hhdm_base: u64,
}

impl AddressSpace {
    /// Creates an address space sharing the kernel's higher half.
    ///
    /// # Errors
    ///
    /// [`VmError::NoAllocator`] or [`VmError::OutOfMemory`].
    pub fn new(hhdm_base: u64) -> Result<Self, VmError> {
        // The heap lock is held only for the frame work, and nothing inside
        // this closure allocates through the global allocator.
        let root = heap::with(|heap| {
            let pmm = heap.pmm_mut();
            // SAFETY: the currently loaded page table is by definition a valid
            // PML4 whose higher half maps the kernel, which is exactly the
            // template needed. Nothing else is modifying page tables: there is
            // one CPU and interrupts do not map memory.
            unsafe {
                let template = paging::active_page_table();
                paging::create_address_space(template, hhdm_base, &mut || {
                    pmm.allocate(0, Zone::Normal)
                        .ok()
                        .map(|pfn| u64::from(pfn) * FRAME_SIZE)
                })
            }
        })
        .ok_or(VmError::NoAllocator)??;

        Ok(Self {
            root,
            regions: RangeMap::new(),
            hhdm_base,
        })
    }

    /// Physical address of this space's top-level page table.
    #[must_use]
    pub const fn root(&self) -> u64 {
        self.root
    }

    /// The regions mapped here.
    #[must_use]
    pub const fn regions(&self) -> &RangeMap {
        &self.regions
    }

    /// Translates the page-table flags for a protection and address.
    fn entry_flags(protection: Protection, virtual_address: u64) -> u64 {
        let mut bits = flags::PRESENT;
        if protection.writable() {
            bits |= flags::WRITABLE;
        }
        if !protection.executable() {
            // W^X in the hardware, not merely in the type: anything that is
            // not explicitly executable is marked non-executable.
            bits |= flags::NO_EXECUTE;
        }
        if virtual_address < KERNEL_HALF {
            bits |= flags::USER;
        }
        bits
    }

    /// Maps `range` with anonymous, zero-filled memory.
    ///
    /// Eager rather than demand-paged: demand paging needs the page-fault
    /// handler to consult the region map, which is the next piece of M3.
    /// Mapping eagerly now keeps the region map authoritative and makes the
    /// teardown path — the part the frame-leak gate exercises — real.
    ///
    /// # Errors
    ///
    /// See [`VmError`]. On failure the address space is left unchanged.
    pub fn map_anonymous(
        &mut self,
        range: VirtRange,
        protection: Protection,
    ) -> Result<(), VmError> {
        // Region map first, outside the heap lock. If this fails, nothing has
        // been mapped and there is nothing to undo.
        let region = VmRegion::new(range, protection, Backing::Anonymous);
        self.regions.insert(region)?;

        if !protection.present() {
            // A guard page: reserved in the map, deliberately absent from the
            // page table, so touching it faults and the handler can say the
            // region exists but permits nothing.
            return Ok(());
        }

        let root = self.root;
        let hhdm = self.hhdm_base;

        let result = heap::with(|heap| {
            let pmm = heap.pmm_mut();
            // `index` is also the number of pages already mapped, which is
            // what the caller needs in order to undo a partial mapping.
            for (index, page) in range.pages_iter().enumerate() {
                let Ok(pfn) = pmm.allocate(0, Zone::Normal) else {
                    return Err((VmError::OutOfMemory, index as u64));
                };
                let physical = u64::from(pfn) * FRAME_SIZE;

                // Zero on allocation, never on free (`docs/memory.md` §6): the
                // receiving domain's correctness depends on it, and a
                // zero-on-free scheme can be skipped by a crash.
                // SAFETY: the frame was just allocated, so nothing else refers
                // to it, and it is reachable through the direct map.
                unsafe {
                    core::ptr::write_bytes((hhdm + physical) as *mut u8, 0, FRAME_SIZE as usize);
                }

                let entry = Self::entry_flags(protection, page.as_u64());
                // SAFETY: `root` is this space's PML4, `hhdm` the direct map
                // base, and there is one CPU with nothing else touching these
                // tables.
                let outcome = unsafe {
                    paging::map_page(root, page.as_u64(), physical, entry, hhdm, &mut || {
                        pmm.allocate(0, Zone::Normal)
                            .ok()
                            .map(|pfn| u64::from(pfn) * FRAME_SIZE)
                    })
                };
                if let Err(error) = outcome {
                    let _ = pmm.free(pfn, 0);
                    return Err((VmError::Paging(error), index as u64));
                }
            }
            Ok(())
        })
        .ok_or(VmError::NoAllocator)?;

        if let Err((error, mapped)) = result {
            // Undo the pages that did map, so a failed call leaves no trace.
            // A partial mapping is worse than a failure: it is memory the
            // region map does not know about.
            self.unmap_pages(range, mapped);
            self.regions.remove(range.start).ok();
            return Err(error);
        }

        Ok(())
    }

    /// Unmaps and frees the first `count` pages of `range`.
    fn unmap_pages(&mut self, range: VirtRange, count: u64) {
        let root = self.root;
        let hhdm = self.hhdm_base;

        heap::with(|heap| {
            let pmm = heap.pmm_mut();
            for page in range.pages_iter().take(count as usize) {
                // SAFETY: single CPU, and `root` is this space's PML4.
                if let Ok(physical) = unsafe { paging::unmap_page(root, page.as_u64(), hhdm) } {
                    let _ = pmm.free((physical / FRAME_SIZE) as u32, 0);
                }
            }
        });
    }

    /// Removes the region starting at `start`, freeing anything it owned.
    ///
    /// # Errors
    ///
    /// [`VmError::Region`] if no region starts there.
    pub fn unmap(&mut self, start: VirtAddr) -> Result<(), VmError> {
        let region = self.regions.remove(start)?;
        if region.backing == Backing::Anonymous && region.protection.present() {
            self.unmap_pages(region.range, region.range.pages());
        }
        Ok(())
    }

    /// Physical address backing `address`, if any.
    #[must_use]
    pub fn translate(&self, address: VirtAddr) -> Option<u64> {
        // SAFETY: `root` is this space's PML4 and only entries are read.
        unsafe { paging::translate(self.root, address.as_u64(), self.hhdm_base) }
    }

    /// Tears the address space down, returning every frame it owned.
    ///
    /// Consumes `self`, because using an address space after its page tables
    /// are gone is not a recoverable mistake.
    pub fn destroy(mut self) {
        // Region-map work first: `drain` allocates nothing but the regions are
        // read outside the heap lock regardless, to keep the rule in this
        // module's header simple to follow.
        let regions = self.regions.drain();

        let root = self.root;
        let hhdm = self.hhdm_base;

        heap::with(|heap| {
            let pmm = heap.pmm_mut();

            // Leaf frames first, and only the ones this space owns. Device
            // mappings and reserved ranges are not ours to free.
            for region in &regions {
                if region.backing != Backing::Anonymous || !region.protection.present() {
                    continue;
                }
                for page in region.range.pages_iter() {
                    // SAFETY: single CPU; `root` is this space's PML4, which is
                    // not loaded in CR3 -- the kernel runs in the address space
                    // the bootloader built.
                    if let Ok(physical) = unsafe { paging::unmap_page(root, page.as_u64(), hhdm) } {
                        let _ = pmm.free((physical / FRAME_SIZE) as u32, 0);
                    }
                }
            }

            // Then the page tables themselves, lower half only: the higher
            // half is shared with every other address space, and freeing it
            // would unmap the kernel out from under the machine.
            // SAFETY: as above, and nothing references `root` afterwards --
            // `self` is consumed.
            unsafe {
                paging::destroy_address_space(root, hhdm, &mut |frame| {
                    let _ = pmm.free((frame / FRAME_SIZE) as u32, 0);
                });
            }
        });
    }
}

/// Creates and destroys address spaces, asserting nothing leaks.
///
/// This is the frame-leak gate from `docs/memory.md` §7. It is the test that
/// decides whether the address-space code is trustworthy: leaks in a virtual
/// memory system surface as unrelated exhaustion, arbitrarily far from the
/// cause, and are close to impossible to attribute after the fact.
///
/// Returns whether the free-frame count returned to exactly its baseline.
pub fn self_test(hhdm_base: u64, iterations: u32) -> bool {
    let baseline = heap::free_frames();

    for index in 0..iterations {
        let Ok(mut space) = AddressSpace::new(hhdm_base) else {
            crate::println!("    address space  FAILED to create at iteration {index}");
            return false;
        };

        // A few regions at addresses far enough apart to force separate
        // page-table subtrees, so teardown has to walk more than one branch.
        let layout = [
            (0x0000_0000_4000_0000u64, 4, Protection::ReadWrite),
            (0x0000_0000_8000_0000u64, 2, Protection::ReadExecute),
            (0x0000_0100_0000_0000u64, 1, Protection::ReadOnly),
        ];

        for &(start, pages, protection) in &layout {
            let Some(range) = VirtRange::from_pages(VirtAddr(start), pages) else {
                return false;
            };
            if space.map_anonymous(range, protection).is_err() {
                crate::println!("    address space  FAILED to map at iteration {index}");
                space.destroy();
                return false;
            }
        }

        // The mapping must actually be readable through the page tables, or
        // the teardown below would be freeing something that was never linked.
        if space.translate(VirtAddr(0x0000_0000_4000_0000)).is_none() {
            crate::println!("    address space  mapping did not take effect");
            space.destroy();
            return false;
        }

        space.destroy();
    }

    let after = heap::free_frames();
    if after != baseline {
        crate::println!(
            "    address space  LEAK: {baseline} frames before, {after} after {iterations} cycles"
        );
        return false;
    }
    true
}
