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
use bhaskix_arch::uaccess;
use bhaskix_boot::VirtAddr;
use bhaskix_mm::vm::{
    Backing, PAGE_SIZE, Protection, RangeMap, RangeMapError, VirtRange, VmRegion,
};
use bhaskix_mm::{FRAME_SIZE, Zone};

use crate::frames;
use crate::heap;
use crate::sync::{Rank, SpinLock};

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
    /// The request describes something this kernel refuses to map.
    ///
    /// A shared region asking to be executable, or a frame list whose length
    /// does not match the range. Both are refusals rather than clamps: a
    /// mapping that is *nearly* what was asked for is one the caller will use
    /// as though it were exactly that.
    Refused,
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

    /// Whether this address space is currently loaded in `CR3`.
    ///
    /// Decides whether unmapping needs a TLB shootdown. A translation can only
    /// be cached by a CPU that has actually run in this address space, so a
    /// space no CPU has loaded needs no interruption at all — which is what
    /// keeps tearing down a thousand address spaces from costing a thousand
    /// rounds of IPIs.
    ///
    /// The check is against *this* CPU's `CR3` only, which is sufficient
    /// because secondary CPUs never load an address space: they idle in the
    /// one the bootloader built. That stops being true the moment threads run
    /// on more than one CPU, and this must become a per-space "loaded on"
    /// mask when it does.
    fn is_active(&self) -> bool {
        // SAFETY: reading CR3 at CPL 0 has no side effects.
        unsafe { paging::active_page_table() == self.root }
    }

    /// Unmaps and frees the first `count` pages of `range`.
    fn unmap_pages(&mut self, range: VirtRange, count: u64) {
        let root = self.root;
        let hhdm = self.hhdm_base;
        let active = self.is_active();

        heap::with(|heap| {
            let pmm = heap.pmm_mut();
            for page in range.pages_iter().take(count as usize) {
                // SAFETY: `root` is this space's PML4.
                if let Ok(physical) = unsafe { paging::unmap_page(root, page.as_u64(), hhdm) } {
                    // Shoot down *before* the frame is freed. Reversing this
                    // hands the frame to another allocation while a CPU may
                    // still be writing through the old translation, which is
                    // the exact corruption shootdown exists to prevent.
                    if active {
                        crate::tlb::shootdown(page.as_u64());
                    }
                    let _ = pmm.free((physical / FRAME_SIZE) as u32, 0);
                }
            }
        });
    }

    /// Removes the region starting at `start`, freeing anything it owned.
    ///
    /// # Errors
    ///
    /// Maps frames this address space does not own.
    ///
    /// The frames belong to a `Memory` object ([RFC 0009](../../../docs/rfc/0009-shared-memory.md));
    /// this address space borrows them. Two consequences, and both are the
    /// point rather than side effects:
    ///
    /// - **Teardown does not free them.** `unmap` and `destroy` release frames
    ///   only for [`Backing::Anonymous`], so a shared region is skipped
    ///   without a branch anyone has to remember.
    /// - **They are not zeroed.** An anonymous mapping is zeroed on allocation
    ///   because the receiving domain's correctness depends on it; these
    ///   already hold whatever the object's owner put there, which is the
    ///   entire reason for mapping them.
    ///
    /// `frames` gives the physical address of each page in order, and must
    /// yield exactly `range.pages()` of them.
    ///
    /// # Errors
    ///
    /// [`VmError::Refused`] if `protection` is executable — RFC 0009
    /// refuses that outright, because revocation unmaps while the other side
    /// is running, and a receiver whose *code* vanishes faults at an
    /// instruction that no longer exists. See [`VmError`] otherwise; on
    /// failure the address space is left unchanged.
    pub fn map_shared(
        &mut self,
        range: VirtRange,
        object: u32,
        frames: &[u64],
        protection: Protection,
    ) -> Result<(), VmError> {
        if protection.executable() {
            return Err(VmError::Refused);
        }
        if frames.len() as u64 != range.pages() {
            return Err(VmError::Refused);
        }

        let region = VmRegion::new(range, protection, Backing::Shared { object });
        self.regions.insert(region)?;

        let root = self.root;
        let hhdm = self.hhdm_base;

        let result = heap::with(|heap| {
            let pmm = heap.pmm_mut();
            for (index, page) in range.pages_iter().enumerate() {
                let physical = frames[index];
                let entry = Self::entry_flags(protection, page.as_u64());
                // SAFETY: `root` is this space's PML4, `hhdm` the direct map
                // base, and `physical` is a frame the object owns and keeps
                // owning -- this only builds a second name for it.
                let outcome = unsafe {
                    paging::map_page(root, page.as_u64(), physical, entry, hhdm, &mut || {
                        pmm.allocate(0, Zone::Normal)
                            .ok()
                            .map(|pfn| u64::from(pfn) * FRAME_SIZE)
                    })
                };
                if let Err(error) = outcome {
                    return Err((VmError::Paging(error), index as u64));
                }
            }
            Ok(())
        });

        match result {
            Some(Ok(())) => Ok(()),
            Some(Err((error, mapped))) => {
                // Undo the pages that were mapped, and the region, so a failed
                // map leaves nothing behind. The frames themselves are not
                // freed -- they were never this address space's.
                self.unmap_pages(range, mapped);
                let _ = self.regions.remove(range.start);
                Err(error)
            }
            None => {
                let _ = self.regions.remove(range.start);
                Err(VmError::OutOfMemory)
            }
        }
    }

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
                    // SAFETY: `root` is this space's PML4, which is not loaded
                    // in CR3 -- `destroy` consumes the space, and a space
                    // cannot be destroyed while it is running. No CPU can hold
                    // a cached translation for it, so no shootdown is needed.
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
    let baseline = heap::available_frames();

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

    let after = heap::available_frames();
    if after != baseline {
        crate::println!(
            "    address space  LEAK: {baseline} frames before, {after} after {iterations} cycles"
        );
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Demand paging and copy-on-write
// ---------------------------------------------------------------------------

/// How many user address spaces can exist at once.
///
/// Four: the shell and both services in their own domains, with one spare. It
/// was one until RFC 0013 step 4, which is not a number anybody chose — the
/// kernel simply kept a single installed space, because until there were two
/// programs to run at once nothing could tell. What told was two services in
/// domains landing on the same CPU and running in each other's page table.
pub const MAX_SPACES: usize = 4;

/// Every user address space the kernel has installed, found by its root.
///
/// The page-fault handler needs the region map to decide whether a fault is
/// legal, and it has no other way to find it. Keyed by the page-table root
/// rather than by thread or domain, because the root is what `CR3` holds: the
/// fault happened in whatever space is loaded, and asking the hardware which
/// one that is cannot disagree with the hardware.
static SPACES: SpinLock<[Option<AddressSpace>; MAX_SPACES]> =
    SpinLock::new(Rank::AddressSpace, [None, None, None, None]);

/// The page table to restore when the installed space is removed.
static PREVIOUS_ROOT: SpinLock<u64> = SpinLock::new(Rank::AddressSpacePrevious, 0);

/// How many user address spaces exist at once.
///
/// Printed at boot because it was one for the whole of M5 and M6 and nothing
/// said so: the kernel kept a single installed space, and with one user
/// program at a time that is indistinguishable from keeping the right one. A
/// number here is what makes "more than one program has its own memory" a
/// claim the machine states rather than one the design implies.
#[must_use]
pub fn installed() -> usize {
    SPACES.lock().iter().flatten().count()
}

/// Runs `f` against the address space currently loaded in `CR3`.
///
/// `None` if this CPU is not running in one the kernel installed.
fn with_active<T>(f: impl FnOnce(&mut AddressSpace) -> T) -> Option<T> {
    // SAFETY: reading CR3 at CPL 0 has no side effects and cannot fault.
    let root = unsafe { paging::active_page_table() };
    let mut spaces = SPACES.lock();
    let space = spaces
        .iter_mut()
        .flatten()
        .find(|space| space.root() == root)?;
    Some(f(space))
}

/// What the fault handler did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultOutcome {
    /// A mapping was created or upgraded; the faulting instruction can retry.
    Handled,
    /// No installed address space, or no region covers the address. The fault
    /// is genuinely a bug and belongs in the exception report.
    NotOurs,
    /// The region says the access is illegal — a write to a read-only mapping,
    /// or any access to a guard page.
    Refused(&'static str),
    /// The fault is legal but could not be serviced right now.
    Unserviceable(&'static str),
}

impl AddressSpace {
    /// Registers a region without mapping any of its pages.
    ///
    /// This is what makes the region map authoritative rather than decorative:
    /// afterwards the map says the address is valid while the page table says
    /// nothing is there, and the difference is resolved on first touch.
    ///
    /// # Errors
    ///
    /// [`VmError::Region`] if the range overlaps an existing region.
    pub fn map_anonymous_lazy(
        &mut self,
        range: VirtRange,
        protection: Protection,
    ) -> Result<(), VmError> {
        self.regions
            .insert(VmRegion::new(range, protection, Backing::Anonymous))?;
        Ok(())
    }

    /// Marks an already-mapped range copy-on-write.
    ///
    /// Drops write permission in the page table while leaving the region's
    /// declared protection alone. A later write faults, and the handler copies
    /// the frame rather than refusing — which is the whole trick.
    ///
    /// # Errors
    ///
    /// [`VmError::Region`] if no region starts at `start`.
    pub fn make_copy_on_write(&mut self, start: VirtAddr) -> Result<(), VmError> {
        let region = *self
            .regions
            .find(start)
            .ok_or(VmError::Region(RangeMapError::NotFound))?;

        let root = self.root;
        let hhdm = self.hhdm_base;
        let read_only = Self::entry_flags(Protection::ReadOnly, start.as_u64());

        for page in region.range.pages_iter() {
            // SAFETY: `root` is this space's PML4; single CPU.
            let _ = unsafe { paging::protect_page(root, page.as_u64(), read_only, hhdm) };
        }

        self.regions.remove(region.range.start)?;
        let mut updated = region;
        updated.flags.copy_on_write = true;
        self.regions.insert(updated)?;
        Ok(())
    }
}

/// Installs `space` as the active address space and loads its page table.
///
/// Returns the previous `CR3`, which [`uninstall`] restores.
///
/// # Safety
///
/// The space's higher half must already map the running code, the current
/// stack, and the descriptor tables — which holds for anything built by
/// [`AddressSpace::new`] *after* those mappings existed in the template, since
/// creation copies the higher half rather than sharing a live view of it.
pub unsafe fn install(space: AddressSpace) {
    let root = space.root();
    {
        let mut spaces = SPACES.lock();
        // Replace an entry with the same root before taking a new slot: a
        // space is identified by its root, and two entries claiming one root
        // would make which region map answers a fault depend on search order.
        let slot = spaces
            .iter()
            .position(|held| held.as_ref().is_some_and(|held| held.root() == root))
            .or_else(|| spaces.iter().position(Option::is_none));
        match slot {
            Some(slot) => spaces[slot] = Some(space),
            // Out of slots. The space is dropped, the switch below still
            // happens, and every fault in it will be unserviceable -- loud,
            // and better than evicting somebody else's mappings.
            None => {
                crate::println!("    address space  no free slot; faults in it will be refused")
            }
        }
    }
    // SAFETY: delegated to the caller's obligation above.
    let previous = unsafe { paging::switch_address_space(root) };
    *PREVIOUS_ROOT.lock() = previous;

    // The thread carries its root from here on, so that a context switch can
    // put it back. Without this a user thread resumes in whichever space ran
    // last on that CPU -- which, with one user program, is always its own.
    if let Some(me) = crate::sched::current_thread_id() {
        crate::sched::set_space_root(me, root);
    }
}

/// Restores the previous page table and returns the installed space.
///
/// # Safety
///
/// The previously recorded root must still be a valid page table.
pub unsafe fn uninstall() -> Option<AddressSpace> {
    // SAFETY: reading CR3 has no side effects.
    let root = unsafe { paging::active_page_table() };
    let previous = *PREVIOUS_ROOT.lock();
    if previous != 0 {
        // SAFETY: `previous` was read from CR3 by `install`, so it is the page
        // table the kernel was running in, which by construction maps
        // everything currently in use.
        unsafe { paging::switch_address_space(previous) };
    }
    let mut spaces = SPACES.lock();
    let slot = spaces
        .iter()
        .position(|held| held.as_ref().is_some_and(|held| held.root() == root))?;
    spaces[slot].take()
}

/// Services a page fault against the installed address space.
///
/// This is the point of the whole design in `docs/memory.md` §3: the region map
/// decides whether the access is legal, and only then is the page table
/// touched. Demand paging and copy-on-write are the same mechanism reading
/// different fields, not two special cases.
///
/// `write` comes from the architectural error code, not from any bookkeeping —
/// bookkeeping is exactly what may be wrong when a fault is being handled.
#[must_use]
pub fn handle_fault(address: u64, write: bool) -> FaultOutcome {
    // `try_lock` throughout. A fault can interrupt code already holding either
    // lock, and spinning here would hang the machine with no output. Reporting
    // an unserviceable fault is worse than servicing it and far better than a
    // silent lock-up.
    let Some(mut guard) = SPACES.try_lock() else {
        return FaultOutcome::Unserviceable("address space lock held");
    };
    // Whichever space is loaded *now*. Asked of the hardware rather than of
    // any bookkeeping, for the reason in this function's doc comment: the
    // bookkeeping is what may be wrong when a fault is being handled.
    //
    // SAFETY: reading CR3 at CPL 0 has no side effects and cannot fault.
    let root = unsafe { paging::active_page_table() };
    let Some(space) = guard
        .iter_mut()
        .flatten()
        .find(|space| space.root() == root)
    else {
        return FaultOutcome::NotOurs;
    };

    let page = VirtAddr(address & !(PAGE_SIZE - 1));
    let Some(region) = space.regions.find(page).copied() else {
        return FaultOutcome::NotOurs;
    };

    if !region.protection.present() {
        return FaultOutcome::Refused("access to a guard page");
    }
    if write && !region.protection.writable() && !region.flags.copy_on_write {
        return FaultOutcome::Refused("write to a read-only mapping");
    }

    // A shared region is mapped eagerly and never demand-paged, so a fault on
    // one means its pages have been taken away -- which is what revocation
    // does. Servicing it would hand the faulting code a *fresh* frame at the
    // address it was just revoked from: a revoked mapping silently replaced by
    // blank memory, which is worse than either keeping it or refusing it.
    //
    // Found by reading this function while writing the revocation walk, not by
    // a test. The region map outlives the mapping by design -- revocation
    // works on page tables, because page tables are what grant access -- so
    // this arm is what stops the stale entry becoming an accidental grant.
    if matches!(region.backing, Backing::Shared { .. }) {
        return FaultOutcome::Refused("a shared region was revoked, or never mapped");
    }

    let root = space.root;
    let hhdm = space.hhdm_base;

    // SAFETY: reads page table entries only.
    let existing = unsafe { paging::translate(root, page.as_u64(), hhdm) };

    // Frames come from this CPU's reserve, not from the allocator.
    //
    // The allocator's lock is the one thing a fault handler must never wait
    // for: a fault can interrupt code on this very CPU that already holds it,
    // and then neither can proceed. Taking the frame from a reserve that no
    // lock protects removes the question. `frames::take` falls back to nothing
    // -- if the reserve is dry the fault is refused, which is the same
    // outcome as before but now the rare case rather than the common one.
    let Some(fresh) = frames::take() else {
        return FaultOutcome::Unserviceable("no frame in this cpu's reserve");
    };

    // Page-table levels come from the same place, for the same reason.
    let mut reserve_frame = || frames::take();

    match existing {
        // Copy-on-write: the page is present but write-protected, and the
        // region says a write should copy rather than fail.
        Some(old) if write && region.flags.copy_on_write => {
            // SAFETY: both frames are reachable through the direct map;
            // `fresh` came from this CPU's reserve so nothing else refers to
            // it, and the ranges cannot overlap because they are distinct
            // frames. No zeroing first: every byte is about to be written.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (hhdm + (old & !(PAGE_SIZE - 1))) as *const u8,
                    (hhdm + fresh) as *mut u8,
                    PAGE_SIZE as usize,
                );
            }

            let entry = AddressSpace::entry_flags(Protection::ReadWrite, page.as_u64());
            // SAFETY: `root` is the installed space's PML4, and this CPU is
            // the one faulting on it.
            let replaced = unsafe {
                paging::unmap_page(root, page.as_u64(), hhdm).and_then(|_| {
                    paging::map_page(root, page.as_u64(), fresh, entry, hhdm, &mut reserve_frame)
                })
            };
            if replaced.is_err() {
                frames::give(fresh);
                return FaultOutcome::Unserviceable("could not remap the copied page");
            }

            // The frame that was shared is released only when nothing else
            // holds it. Refcounting arrives with fork in M5; until then a
            // COW region's original frame belongs to whoever mapped it, so
            // it is deliberately *not* freed here.
            FaultOutcome::Handled
        }

        // Present, and not a copy-on-write write. There is nothing to
        // create, so this handler cannot help -- and saying `Handled`
        // would retry the same faulting instruction forever.
        //
        // That loop is reachable: with SMAP on, a kernel access to a
        // *mapped* user page faults, and the mapping already being there
        // is exactly what makes it look serviceable.
        Some(_) => {
            frames::give(fresh);
            FaultOutcome::NotOurs
        }

        // Demand paging: the region says this address is valid and the
        // page table says nothing is there. Make it so.
        None => {
            // SAFETY: taken from this CPU's reserve and unaliased, reachable
            // through the direct map. Zeroing is required by
            // `docs/memory.md` §6 -- a frame must never reach a consumer
            // carrying another domain's data -- and unlike the copy above,
            // nothing here is about to overwrite it.
            unsafe {
                core::ptr::write_bytes((hhdm + fresh) as *mut u8, 0, PAGE_SIZE as usize);
            }

            let entry = AddressSpace::entry_flags(region.protection, page.as_u64());
            // SAFETY: as above.
            let mapped = unsafe {
                paging::map_page(root, page.as_u64(), fresh, entry, hhdm, &mut reserve_frame)
            };
            if mapped.is_err() {
                frames::give(fresh);
                return FaultOutcome::Unserviceable("could not map the demanded page");
            }
            FaultOutcome::Handled
        }
    }
}

/// Exercises demand paging and copy-on-write against a live address space.
///
/// Unlike every earlier test in M3, this one **switches `CR3`** — nothing
/// before it had ever run in an address space Bhaskix built, so the
/// higher-half copy that keeps the kernel mapped was untested in the only way
/// that matters.
///
/// Returns whether every property held.
pub fn demand_paging_self_test(hhdm_base: u64) -> bool {
    const LAZY: u64 = 0x0000_0000_2000_0000;
    const EAGER: u64 = 0x0000_0000_3000_0000;
    const UNDER_LOCK: u64 = 0x0000_0000_4000_0000;
    const PATTERN: u64 = 0xfeed_face_0bad_c0de;

    let baseline = heap::available_frames();

    let Ok(mut space) = AddressSpace::new(hhdm_base) else {
        crate::println!("    demand paging  FAILED to create an address space");
        return false;
    };

    let (Some(lazy), Some(eager), Some(under_lock)) = (
        VirtRange::from_pages(VirtAddr(LAZY), 2),
        VirtRange::from_pages(VirtAddr(EAGER), 1),
        VirtRange::from_pages(VirtAddr(UNDER_LOCK), 1),
    ) else {
        return false;
    };

    // Registered, deliberately unmapped. The region map now says this address
    // is valid while the page table says nothing is there.
    if space
        .map_anonymous_lazy(lazy, Protection::ReadWrite)
        .is_err()
        || space.map_anonymous(eager, Protection::ReadWrite).is_err()
        || space
            .map_anonymous_lazy(under_lock, Protection::ReadWrite)
            .is_err()
    {
        crate::println!("    demand paging  FAILED to register regions");
        space.destroy();
        return false;
    }

    // Nothing is mapped for the lazy range yet -- that is the premise.
    let unmapped_before = space.translate(VirtAddr(LAZY)).is_none();

    // Seed the eager page, then make it copy-on-write and remember the frame
    // so the copy can be proven to be a copy.
    let eager_frame_before = space.translate(VirtAddr(EAGER));

    // SAFETY: the space's higher half was copied from the running page table
    // after the kernel, its stack, and the descriptor tables were all mapped
    // there, so everything currently executing stays addressable.
    unsafe { install(space) };

    // --- demand paging -----------------------------------------------------
    // No mapping exists for this address. Touching it must fault, the handler
    // must consult the region map, and the instruction must then complete.
    // Through `uaccess`, not a raw volatile write. Two reasons: with SMAP on,
    // a direct kernel write to a user page faults regardless of the mapping;
    // and this exercises the path real kernel code will use.
    //
    // The first touch faults on an *unmapped* page, so this also proves demand
    // paging works underneath a user copy rather than only for direct access.
    let mut value = PATTERN;
    // SAFETY: `value` is a live local of the right size. The destination is
    // untrusted by contract -- that is the point of the routine.
    let wrote =
        unsafe { uaccess::copy_to_user(LAZY, (&raw const value).cast::<u8>(), size_of::<u64>()) };
    value = 0;
    // SAFETY: as above, in the other direction.
    let read =
        unsafe { uaccess::copy_from_user((&raw mut value).cast::<u8>(), LAZY, size_of::<u64>()) };
    let read_back = if wrote.is_ok() && read.is_ok() {
        value
    } else {
        0
    };

    // A second page in the same region, to prove the handler works per page
    // rather than per region.
    let mut second = PATTERN ^ 1;
    // SAFETY: as above.
    let wrote_second = unsafe {
        uaccess::copy_to_user(
            LAZY + PAGE_SIZE,
            (&raw const second).cast::<u8>(),
            size_of::<u64>(),
        )
    };
    second = 0;
    // SAFETY: as above.
    let read_second = unsafe {
        uaccess::copy_from_user(
            (&raw mut second).cast::<u8>(),
            LAZY + PAGE_SIZE,
            size_of::<u64>(),
        )
    };
    let read_back_second = if wrote_second.is_ok() && read_second.is_ok() {
        second
    } else {
        0
    };

    // --- copy-on-write -----------------------------------------------------
    let seed = PATTERN;
    // SAFETY: mapped eagerly above; `seed` is a live local.
    let _ =
        unsafe { uaccess::copy_to_user(EAGER, (&raw const seed).cast::<u8>(), size_of::<u64>()) };

    let cow_ready =
        with_active(|space| space.make_copy_on_write(VirtAddr(EAGER)).is_ok()).unwrap_or(false);

    // This write must fault -- the page is now read-only -- and the handler
    // must copy rather than refuse.
    let replacement = !PATTERN;
    // SAFETY: the region is marked copy-on-write, so the write is legal and
    // resolves by copying.
    let cow_wrote = unsafe {
        uaccess::copy_to_user(
            EAGER,
            (&raw const replacement).cast::<u8>(),
            size_of::<u64>(),
        )
    };
    let mut observed = 0u64;
    // SAFETY: as above.
    let cow_read = unsafe {
        uaccess::copy_from_user((&raw mut observed).cast::<u8>(), EAGER, size_of::<u64>())
    };
    let after_cow = if cow_wrote.is_ok() && cow_read.is_ok() {
        observed
    } else {
        0
    };

    let eager_frame_after = with_active(|space| space.translate(VirtAddr(EAGER))).flatten();

    // The original frame must still hold the old value: that is what makes it
    // a copy rather than an in-place write.
    let original_intact = match eager_frame_before {
        // SAFETY: the frame is still allocated -- COW does not free the shared
        // original -- and is reachable through the direct map.
        Some(physical) => unsafe {
            core::ptr::read_volatile((hhdm_base + (physical & !(PAGE_SIZE - 1))) as *const u64)
                == PATTERN
        },
        None => false,
    };

    // --- a fault serviced while the allocator lock is held -----------------
    //
    // The property M4-12 exists for, and the one the old fault path could not
    // provide. The closure below runs with the physical allocator's lock held
    // by *this* CPU; the write inside it touches a page that has never been
    // mapped, so it faults, and the handler must complete without going
    // anywhere near that lock. Before the per-CPU reserve this returned
    // "allocator lock held" and the write failed.
    //
    // Deliberately the real lock rather than a simulation: a mock would prove
    // the handler avoids a lock nobody was holding.
    let mut under_lock_value = PATTERN ^ 0x5555;
    let serviced_under_lock = heap::with(|_allocator| {
        // SAFETY: `under_lock_value` is a live local of the right size, and
        // the destination is untrusted by contract.
        unsafe {
            uaccess::copy_to_user(
                UNDER_LOCK,
                (&raw const under_lock_value).cast::<u8>(),
                size_of::<u64>(),
            )
        }
        .is_ok()
    })
    .unwrap_or(false);

    under_lock_value = 0;
    // SAFETY: as above, in the other direction, with the lock released.
    let read_under_lock = unsafe {
        uaccess::copy_from_user(
            (&raw mut under_lock_value).cast::<u8>(),
            UNDER_LOCK,
            size_of::<u64>(),
        )
    };
    let under_lock_read_back = if serviced_under_lock && read_under_lock.is_ok() {
        under_lock_value
    } else {
        0
    };

    // While a space is still installed, so the fault paths have somewhere real
    // to land.
    let user_access_ok = user_access_self_test();

    // SAFETY: restores the page table the kernel was running in.
    let recovered = unsafe { uninstall() };

    let Some(space) = recovered else {
        crate::println!("    demand paging  FAILED to recover the address space");
        return false;
    };
    space.destroy();

    let after = heap::available_frames();

    let checks = [
        ("no mapping existed beforehand", unmapped_before),
        ("demand-paged write read back", read_back == PATTERN),
        (
            "second page faulted separately",
            read_back_second == PATTERN ^ 1,
        ),
        (
            "fault serviced while the allocator lock was held",
            under_lock_read_back == PATTERN ^ 0x5555,
        ),
        ("region became copy-on-write", cow_ready),
        ("copy-on-write write took effect", after_cow == !PATTERN),
        (
            "the page moved to a new frame",
            eager_frame_after != eager_frame_before,
        ),
        ("the original frame is unchanged", original_intact),
        ("bad user pointers fault rather than panic", user_access_ok),
    ];

    let mut ok = true;
    for (what, passed) in checks {
        if !passed {
            crate::println!("    demand paging  FAILED: {what}");
            ok = false;
        }
    }

    // The COW original is deliberately not freed -- there is no refcounting
    // until fork in M5 -- so one frame per COW page is expected to remain.
    if after > baseline {
        crate::println!("    demand paging  frames went UP: {baseline} -> {after}");
        ok = false;
    }

    ok
}

/// Checks that a bad user pointer produces an error rather than a panic.
///
/// This is the property the exception table exists for: a hostile or simply
/// wrong pointer from user space is *expected input*, not a kernel defect, and
/// must not be able to take the machine down.
///
/// Run inside an installed address space so the "valid" cases have somewhere
/// real to land.
#[must_use]
pub fn user_access_self_test() -> bool {
    // Unmapped, but a legitimate user-half address: nothing in the region map
    // covers it, so the fault is not serviceable and the fixup must catch it.
    const UNMAPPED_USER: u64 = 0x0000_0000_7000_0000;
    // Kernel half. Must be refused before any access is attempted -- a user
    // pointer aimed at kernel memory that merely happens to be mapped would
    // otherwise succeed, which is the confused-deputy bug the range check
    // exists to prevent.
    const KERNEL_ADDRESS: u64 = 0xffff_ffff_8000_0000;

    let mut buffer = 0u64;

    // SAFETY: `buffer` is a live local of the right size; the source address
    // is untrusted by contract.
    let unmapped = unsafe {
        uaccess::copy_from_user(
            (&raw mut buffer).cast::<u8>(),
            UNMAPPED_USER,
            size_of::<u64>(),
        )
    };

    // SAFETY: as above.
    let kernel_source = unsafe {
        uaccess::copy_from_user(
            (&raw mut buffer).cast::<u8>(),
            KERNEL_ADDRESS,
            size_of::<u64>(),
        )
    };

    // SAFETY: `buffer` is a live local; the destination is untrusted.
    let kernel_destination = unsafe {
        uaccess::copy_to_user(
            KERNEL_ADDRESS,
            (&raw const buffer).cast::<u8>(),
            size_of::<u64>(),
        )
    };

    // A length that wraps the address space. Rejected by the overflow check
    // rather than by faulting, because a wrapped range would pass a naive
    // bounds test.
    // SAFETY: as above.
    let wrapping =
        unsafe { uaccess::copy_from_user((&raw mut buffer).cast::<u8>(), u64::MAX - 8, 64) };

    let checks = [
        (
            "unmapped user pointer returns a fault",
            unmapped == Err(uaccess::UserAccessError::Fault),
        ),
        (
            "kernel source is refused",
            kernel_source == Err(uaccess::UserAccessError::NotUserAddress),
        ),
        (
            "kernel destination is refused",
            kernel_destination == Err(uaccess::UserAccessError::NotUserAddress),
        ),
        (
            "a wrapping range is refused",
            wrapping == Err(uaccess::UserAccessError::NotUserAddress),
        ),
        (
            "the exception table is populated",
            uaccess::fixup_count() > 0,
        ),
    ];

    let mut ok = true;
    for (what, passed) in checks {
        if !passed {
            crate::println!("    user access    FAILED: {what}");
            ok = false;
        }
    }
    ok
}
