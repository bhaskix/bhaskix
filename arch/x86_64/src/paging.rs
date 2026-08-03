// SPDX-License-Identifier: Apache-2.0
//! Minimal page-table manipulation.
//!
//! **This is not the memory manager.** Address spaces, demand paging,
//! copy-on-write, and the `RangeMap` that will be the source of truth all
//! arrive in M3 (`docs/memory.md`). This module does exactly one thing: add a
//! single 4 KiB mapping to the page tables the bootloader already built.
//!
//! It exists because M2 needs it and cannot wait. The Local APIC is
//! memory-mapped at a physical address the bootloader's direct map does not
//! cover — it maps RAM, and the APIC is not RAM — so on any CPU without
//! x2APIC, the choice is to map one page or to have no timer at all.
//!
//! # Deliberate limitations
//!
//! - **4 KiB pages only.** No huge-page support and no huge-page splitting. If
//!   a mapping would land inside an existing huge page, this refuses rather
//!   than doing something clever. Splitting one correctly requires knowing
//!   what else lives inside it, which is bookkeeping the region map owns.
//! - **Single-CPU only.** Unmapping invalidates the local TLB and nothing
//!   else. On SMP that is a correctness bug, so M4 must add shootdown before
//!   the second CPU starts.
//! - **No accessed/dirty tracking.** Needed for reclaim, which is Phase 2.

/// Page table entry flags.
pub mod flags {
    /// The entry maps something.
    pub const PRESENT: u64 = 1 << 0;
    /// Writes are permitted.
    pub const WRITABLE: u64 = 1 << 1;
    /// Accessible from user mode.
    pub const USER: u64 = 1 << 2;
    /// Write-through rather than write-back caching.
    pub const WRITE_THROUGH: u64 = 1 << 3;
    /// Uncacheable. Required for memory-mapped device registers.
    pub const NO_CACHE: u64 = 1 << 4;
    /// This entry maps a large page rather than pointing at another table.
    pub const HUGE: u64 = 1 << 7;
    /// Not flushed from the TLB on an address-space switch.
    pub const GLOBAL: u64 = 1 << 8;
    /// Instruction fetches from this page fault.
    pub const NO_EXECUTE: u64 = 1 << 63;

    /// Flags for a device register mapping.
    ///
    /// Uncacheable because a cached read of a device register returns a stale
    /// value and a cached write may never reach the device. Non-executable
    /// because nothing should ever fetch instructions from a device
    /// (`docs/memory.md` §3, W^X).
    pub const DEVICE: u64 = PRESENT | WRITABLE | NO_CACHE | WRITE_THROUGH | NO_EXECUTE;
}

/// Mask selecting the physical address out of a page table entry.
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

/// Entries per page table at every level.
pub const ENTRIES: usize = 512;

/// First PML4 index belonging to the kernel half of the address space.
///
/// Entries 0-255 map the lower half and belong to whichever domain is running;
/// 256-511 map the higher half and are shared by every address space, so that
/// the kernel stays mapped across a context switch.
pub const KERNEL_PML4_START: usize = 256;

/// `IA32_EFER` bit 11: no-execute enable.
///
/// Without it the CPU treats bit 63 of a page table entry as reserved, so an
/// entry carrying [`flags::NO_EXECUTE`] faults with a reserved-bit error
/// instead of being non-executable. W^X therefore depends on this being set
/// before the first mapping is created (`docs/memory.md` §3).
const EFER_NXE: u64 = 1 << 11;

/// Enables no-execute page protection.
///
/// # Errors
///
/// Returns `false` if the CPU does not support NX, in which case W^X cannot be
/// enforced at all and the caller must treat that as fatal.
///
/// # Safety
///
/// Must run on the bootstrap CPU during init, before any mapping carrying
/// [`flags::NO_EXECUTE`] is created.
pub unsafe fn enable_no_execute() -> bool {
    if !crate::msr::features().nx {
        return false;
    }
    // SAFETY: `IA32_EFER` is architectural, and the caller guarantees this runs
    // during single-threaded init. Only the NXE bit is changed; long mode and
    // syscall enables in the same register are preserved.
    unsafe {
        let efer = crate::msr::read(crate::msr::IA32_EFER);
        crate::msr::write(crate::msr::IA32_EFER, efer | EFER_NXE);
    }
    true
}

/// Whether no-execute is currently enabled.
///
/// # Safety
///
/// Safe at CPL 0; unsafe only because it reads an MSR.
#[must_use]
pub unsafe fn no_execute_enabled() -> bool {
    // SAFETY: `IA32_EFER` is architectural on every x86-64 CPU.
    unsafe { crate::msr::read(crate::msr::IA32_EFER) & EFER_NXE != 0 }
}

/// Why a mapping could not be created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// The virtual or physical address was not 4 KiB aligned.
    Misaligned,
    /// A table on the path is a huge-page mapping, which this will not split.
    HugePageInTheWay,
    /// The address is already mapped, to a different frame.
    AlreadyMapped,
    /// The frame allocator had nothing left.
    OutOfMemory,
    /// Nothing is mapped at the address.
    NotMapped,
}

/// Reads `CR3`, the physical address of the active top-level page table.
///
/// # Safety
///
/// Safe to execute at CPL 0; marked unsafe because the returned value is only
/// meaningful to code that intends to walk the page tables.
#[must_use]
pub unsafe fn active_page_table() -> u64 {
    let cr3: u64;
    // SAFETY: reading CR3 at CPL 0 has no side effects and cannot fault.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3 & ADDRESS_MASK
}

/// Invalidates the TLB entry for one page.
///
/// # Safety
///
/// Safe at CPL 0. Must be called after changing a mapping, or the CPU may keep
/// using the old translation indefinitely.
pub unsafe fn invalidate(virtual_address: u64) {
    // SAFETY: `invlpg` at CPL 0 invalidates one TLB entry and cannot fault,
    // even for an address that is not mapped.
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) virtual_address,
            options(nostack, preserves_flags)
        );
    }
}

/// Splits a virtual address into its four page-table indices, top down.
const fn indices_of(virtual_address: u64) -> [usize; 4] {
    [
        ((virtual_address >> 39) & 0x1ff) as usize,
        ((virtual_address >> 30) & 0x1ff) as usize,
        ((virtual_address >> 21) & 0x1ff) as usize,
        ((virtual_address >> 12) & 0x1ff) as usize,
    ]
}

/// Maps one 4 KiB page into `root`.
///
/// `allocate_frame` supplies physical frames for any page tables that have to
/// be created. They are zeroed here, before being linked in — the allocator
/// cannot write physical memory, and a table full of whatever was there before
/// is a set of mappings to arbitrary memory that the CPU would honour the
/// instant the link is written.
///
/// # Errors
///
/// See [`MapError`]. An existing mapping to the *same* frame is success;
/// mapping to a different frame is [`MapError::AlreadyMapped`] rather than a
/// silent overwrite, because overwriting loses whoever owned the old frame.
///
/// # Safety
///
/// The caller must ensure:
/// - `root` is the physical address of a valid PML4.
/// - `hhdm_base` is the direct map base, so tables are reachable at
///   `hhdm_base + physical`.
/// - No other CPU is running and nothing else is modifying these tables:
///   there is no locking here and no TLB shootdown.
pub unsafe fn map_page(
    root: u64,
    virtual_address: u64,
    physical: u64,
    entry_flags: u64,
    hhdm_base: u64,
    allocate_frame: &mut dyn FnMut() -> Option<u64>,
) -> Result<(), MapError> {
    if !virtual_address.is_multiple_of(4096) || !physical.is_multiple_of(4096) {
        return Err(MapError::Misaligned);
    }

    let indices = indices_of(virtual_address);

    // SAFETY: the caller guarantees `root` is a PML4 and `hhdm_base` maps
    // physical memory, so every table reached below is a real page table.
    unsafe {
        let mut table = (hhdm_base + root) as *mut u64;

        for &index in &indices[..3] {
            let entry = table.add(index);
            let value = entry.read_volatile();

            let next = if value & flags::PRESENT == 0 {
                let frame = allocate_frame().ok_or(MapError::OutOfMemory)?;
                core::ptr::write_bytes((hhdm_base + frame) as *mut u8, 0, 4096);

                // Intermediate entries are permissive; the leaf decides the
                // real protection. x86 takes the AND of permissions down the
                // path, so restricting here would silently constrain unrelated
                // mappings that happen to share this table.
                //
                // USER is included for lower-half addresses for the same
                // reason: without it, no leaf below could ever be reachable
                // from user mode.
                let mut link = frame | flags::PRESENT | flags::WRITABLE;
                if entry_flags & flags::USER != 0 {
                    link |= flags::USER;
                }
                entry.write_volatile(link);
                frame
            } else if value & flags::HUGE != 0 {
                return Err(MapError::HugePageInTheWay);
            } else {
                // An existing intermediate entry may need widening to USER if
                // this is the first user mapping beneath it.
                if entry_flags & flags::USER != 0 && value & flags::USER == 0 {
                    entry.write_volatile(value | flags::USER);
                }
                value & ADDRESS_MASK
            };

            table = (hhdm_base + next) as *mut u64;
        }

        let entry = table.add(indices[3]);
        let existing = entry.read_volatile();
        if existing & flags::PRESENT != 0 {
            return if existing & ADDRESS_MASK == physical {
                Ok(())
            } else {
                Err(MapError::AlreadyMapped)
            };
        }

        entry.write_volatile(physical | entry_flags);
        invalidate(virtual_address);
    }

    Ok(())
}

/// Maps one 4 KiB page of device memory into the active address space.
///
/// # Errors
///
/// See [`MapError`].
///
/// # Safety
///
/// As [`map_page`], and `physical` must really be device memory.
pub unsafe fn map_device_page(
    virtual_address: u64,
    physical: u64,
    hhdm_base: u64,
    allocate_frame: &mut dyn FnMut() -> Option<u64>,
) -> Result<(), MapError> {
    // SAFETY: delegated to `map_page`; the active page table is by definition
    // a valid PML4.
    unsafe {
        let root = active_page_table();
        map_page(
            root,
            virtual_address,
            physical,
            flags::DEVICE,
            hhdm_base,
            allocate_frame,
        )
    }
}

/// Returns the physical address `virtual_address` maps to, if any.
///
/// # Safety
///
/// `root` must be a valid PML4 and `hhdm_base` the direct map base.
#[must_use]
pub unsafe fn translate(root: u64, virtual_address: u64, hhdm_base: u64) -> Option<u64> {
    let indices = indices_of(virtual_address);

    // SAFETY: the caller guarantees `root` is a PML4 reachable through the
    // direct map. Every read is of a table entry; nothing is written.
    unsafe {
        let mut table = (hhdm_base + root) as *mut u64;

        for &index in &indices[..3] {
            let value = table.add(index).read_volatile();
            if value & flags::PRESENT == 0 {
                return None;
            }
            if value & flags::HUGE != 0 {
                return None; // Not a 4 KiB mapping; out of scope here.
            }
            table = (hhdm_base + (value & ADDRESS_MASK)) as *mut u64;
        }

        let leaf = table.add(indices[3]).read_volatile();
        if leaf & flags::PRESENT == 0 {
            None
        } else {
            Some((leaf & ADDRESS_MASK) | (virtual_address & 0xfff))
        }
    }
}

/// Removes the mapping at `virtual_address`, returning the frame it pointed at.
///
/// The frame is *not* freed: ownership belongs to whoever mapped it, and this
/// module has no way to know whether it is anonymous memory, a device
/// register, or shared with another address space.
///
/// # Errors
///
/// [`MapError::NotMapped`] if nothing was mapped there.
///
/// # Safety
///
/// As [`map_page`]. In particular there is **no TLB shootdown**: on SMP, other
/// CPUs may keep using the stale translation, so this must not be called once
/// a second CPU is running until M4 adds shootdown.
pub unsafe fn unmap_page(root: u64, virtual_address: u64, hhdm_base: u64) -> Result<u64, MapError> {
    let indices = indices_of(virtual_address);

    // SAFETY: as `translate`, plus a single write to clear the leaf entry.
    unsafe {
        let mut table = (hhdm_base + root) as *mut u64;

        for &index in &indices[..3] {
            let value = table.add(index).read_volatile();
            if value & flags::PRESENT == 0 {
                return Err(MapError::NotMapped);
            }
            if value & flags::HUGE != 0 {
                return Err(MapError::HugePageInTheWay);
            }
            table = (hhdm_base + (value & ADDRESS_MASK)) as *mut u64;
        }

        let entry = table.add(indices[3]);
        let leaf = entry.read_volatile();
        if leaf & flags::PRESENT == 0 {
            return Err(MapError::NotMapped);
        }

        entry.write_volatile(0);
        invalidate(virtual_address);
        Ok(leaf & ADDRESS_MASK)
    }
}

/// Creates a fresh address space, sharing the kernel's higher half.
///
/// Returns the physical address of the new PML4. The lower half is empty; the
/// upper half is copied from `template`, so the kernel remains mapped after a
/// switch to this address space — without which the very next instruction
/// after loading `CR3` would fault.
///
/// # Errors
///
/// [`MapError::OutOfMemory`].
///
/// # Safety
///
/// `template` must be a valid PML4 whose higher half describes the kernel, and
/// `hhdm_base` the direct map base.
pub unsafe fn create_address_space(
    template: u64,
    hhdm_base: u64,
    allocate_frame: &mut dyn FnMut() -> Option<u64>,
) -> Result<u64, MapError> {
    let frame = allocate_frame().ok_or(MapError::OutOfMemory)?;

    // SAFETY: `frame` was just allocated and is reachable through the direct
    // map; `template` is a valid PML4 per the caller's obligation. The new
    // table is fully written before it is usable.
    unsafe {
        let new = (hhdm_base + frame) as *mut u64;
        let old = (hhdm_base + template) as *const u64;

        core::ptr::write_bytes(new.cast::<u8>(), 0, 4096);
        for index in KERNEL_PML4_START..ENTRIES {
            new.add(index)
                .write_volatile(old.add(index).read_volatile());
        }
    }

    Ok(frame)
}

/// Frees every page-table frame belonging to the lower half of `root`, then
/// `root` itself. Returns how many frames were freed.
///
/// Only the lower half: the higher half is shared with every other address
/// space, and freeing it would unmap the kernel out from under the machine.
///
/// Leaf-mapped frames are **not** freed. They belong to whoever mapped them,
/// and are released by the region map that owns them.
///
/// # Safety
///
/// `root` must be a valid PML4 that is not currently loaded in `CR3`, and
/// nothing may reference it afterwards.
pub unsafe fn destroy_address_space(
    root: u64,
    hhdm_base: u64,
    free_frame: &mut dyn FnMut(u64),
) -> u64 {
    let mut freed = 0u64;

    // SAFETY: the caller guarantees `root` is a valid, inactive PML4 reachable
    // through the direct map. Only table entries are read.
    unsafe {
        let pml4 = (hhdm_base + root) as *const u64;

        for pml4_index in 0..KERNEL_PML4_START {
            let pdpt_entry = pml4.add(pml4_index).read_volatile();
            if pdpt_entry & flags::PRESENT == 0 || pdpt_entry & flags::HUGE != 0 {
                continue;
            }
            let pdpt_frame = pdpt_entry & ADDRESS_MASK;
            let pdpt = (hhdm_base + pdpt_frame) as *const u64;

            for pdpt_index in 0..ENTRIES {
                let pd_entry = pdpt.add(pdpt_index).read_volatile();
                if pd_entry & flags::PRESENT == 0 || pd_entry & flags::HUGE != 0 {
                    continue;
                }
                let pd_frame = pd_entry & ADDRESS_MASK;
                let pd = (hhdm_base + pd_frame) as *const u64;

                for pd_index in 0..ENTRIES {
                    let pt_entry = pd.add(pd_index).read_volatile();
                    if pt_entry & flags::PRESENT == 0 || pt_entry & flags::HUGE != 0 {
                        continue;
                    }
                    free_frame(pt_entry & ADDRESS_MASK);
                    freed += 1;
                }

                free_frame(pd_frame);
                freed += 1;
            }

            free_frame(pdpt_frame);
            freed += 1;
        }
    }

    free_frame(root);
    freed + 1
}

/// Loads `root` into `CR3`, switching address spaces.
///
/// Returns the previous value, so a caller can switch back.
///
/// # Safety
///
/// Catastrophic if `root` does not map everything the current execution needs:
/// the very next instruction fetch, the stack, and the interrupt tables all
/// have to be present in the new space, or the CPU faults with no way to
/// report it. In Bhaskix that means the higher half must have been copied from
/// a template that already contained them — see [`create_address_space`].
///
/// Also invalidates the entire TLB except global entries, which is a real
/// cost; it is not something to do on a hot path.
pub unsafe fn switch_address_space(root: u64) -> u64 {
    // SAFETY: reading CR3 is side-effect free; writing it is the architectural
    // way to change address space, and the caller owns the obligation that the
    // new one maps the running code, its stack, and the descriptor tables.
    unsafe {
        let previous = active_page_table();
        core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
        previous
    }
}

/// Changes the flags on an existing mapping, keeping the frame.
///
/// Used by copy-on-write to drop write permission without unmapping, and to
/// restore it after the copy.
///
/// # Errors
///
/// [`MapError::NotMapped`] if nothing is mapped there.
///
/// # Safety
///
/// As [`map_page`].
pub unsafe fn protect_page(
    root: u64,
    virtual_address: u64,
    entry_flags: u64,
    hhdm_base: u64,
) -> Result<u64, MapError> {
    let indices = indices_of(virtual_address);

    // SAFETY: as `translate`, plus one write to the leaf entry.
    unsafe {
        let mut table = (hhdm_base + root) as *mut u64;
        for &index in &indices[..3] {
            let value = table.add(index).read_volatile();
            if value & flags::PRESENT == 0 {
                return Err(MapError::NotMapped);
            }
            if value & flags::HUGE != 0 {
                return Err(MapError::HugePageInTheWay);
            }
            table = (hhdm_base + (value & ADDRESS_MASK)) as *mut u64;
        }

        let entry = table.add(indices[3]);
        let leaf = entry.read_volatile();
        if leaf & flags::PRESENT == 0 {
            return Err(MapError::NotMapped);
        }
        let physical = leaf & ADDRESS_MASK;
        entry.write_volatile(physical | entry_flags);
        invalidate(virtual_address);
        Ok(physical)
    }
}
