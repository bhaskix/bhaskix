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
//!   than doing something clever. Splitting a huge page correctly requires
//!   knowing what else lives inside it, which needs the M3 bookkeeping.
//! - **No unmapping.** Nothing at M2 unmaps anything, and an unmap that does
//!   not shoot down the TLB on other CPUs would be a latent correctness bug
//!   waiting for M4.
//! - **Single-CPU only.** No TLB shootdown, because there is no second CPU.
//!
//! Each of those becomes wrong in M3 or M4, which is why this module is small
//! enough to delete outright when the real one lands.

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

/// Maps one 4 KiB page of device memory.
///
/// `allocate_frame` supplies zeroed-capable physical frames for any page
/// tables that have to be created; this function zeroes them itself, since the
/// allocator cannot write physical memory.
///
/// # Errors
///
/// See [`MapError`]. Notably, an existing mapping to the *same* frame is
/// treated as success — mapping the APIC twice is harmless — while a mapping
/// to a different frame is an error rather than a silent overwrite.
///
/// # Safety
///
/// The caller must ensure:
/// - `hhdm_base` is the higher-half direct map base, so page tables can be
///   reached at `hhdm_base + physical`.
/// - No other CPU is running, and no other code is modifying page tables.
///   There is no locking here and no TLB shootdown.
/// - `physical` really is device memory that is safe to map.
pub unsafe fn map_device_page(
    virtual_address: u64,
    physical: u64,
    hhdm_base: u64,
    allocate_frame: &mut dyn FnMut() -> Option<u64>,
) -> Result<(), MapError> {
    if virtual_address & 0xfff != 0 || physical & 0xfff != 0 {
        return Err(MapError::Misaligned);
    }

    // One index per paging level, from the top down.
    let indices = [
        ((virtual_address >> 39) & 0x1ff) as usize,
        ((virtual_address >> 30) & 0x1ff) as usize,
        ((virtual_address >> 21) & 0x1ff) as usize,
        ((virtual_address >> 12) & 0x1ff) as usize,
    ];

    // SAFETY: the caller guarantees `hhdm_base` maps physical memory and that
    // nothing else is touching the page tables concurrently.
    unsafe {
        let mut table = (hhdm_base + active_page_table()) as *mut u64;

        // Descend the three upper levels, creating tables where absent.
        for &index in &indices[..3] {
            let entry = table.add(index);
            let value = entry.read_volatile();

            let next_physical = if value & flags::PRESENT == 0 {
                let frame = allocate_frame().ok_or(MapError::OutOfMemory)?;

                // Zero it before linking it in. A page table full of whatever
                // was there before is a set of mappings to arbitrary memory,
                // and the CPU would honour them the moment the link is
                // written -- so the order here matters.
                core::ptr::write_bytes((hhdm_base + frame) as *mut u8, 0, 4096);

                // Intermediate entries are permissive; the leaf entry decides
                // the actual protection. This is how x86 paging works: the
                // effective permission is the AND down the path, so being
                // restrictive here would silently constrain unrelated
                // mappings that share this table.
                entry.write_volatile(frame | flags::PRESENT | flags::WRITABLE);
                frame
            } else if value & flags::HUGE != 0 {
                // Refuse rather than split. Splitting needs to know what else
                // lives inside the huge page, which is M3 bookkeeping.
                return Err(MapError::HugePageInTheWay);
            } else {
                value & ADDRESS_MASK
            };

            table = (hhdm_base + next_physical) as *mut u64;
        }

        // The leaf.
        let entry = table.add(indices[3]);
        let existing = entry.read_volatile();
        if existing & flags::PRESENT != 0 {
            return if existing & ADDRESS_MASK == physical {
                Ok(()) // Already mapped to exactly this frame.
            } else {
                Err(MapError::AlreadyMapped)
            };
        }

        entry.write_volatile(physical | flags::DEVICE);
        invalidate(virtual_address);
    }

    Ok(())
}
