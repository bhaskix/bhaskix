// SPDX-License-Identifier: Apache-2.0
//! Device interrupts: finding the I/O APIC and routing a line to a vector.
//!
//! The kernel could be interrupted by its own timer and by other CPUs since
//! M2. Nothing a *device* did could reach it, because the path a device
//! interrupt takes — pin, I/O APIC, vector, local APIC — was missing its
//! middle. This module is that middle, and M6-04's console input is its first
//! customer.
//!
//! # One chip, on the bootstrap CPU
//!
//! Everything here runs once, during boot, on the bootstrap CPU. The chip is
//! programmed through a non-atomic index/data pair (see
//! `bhaskix_arch::ioapic`), so concurrent programming would interleave; making
//! it single-threaded by construction is simpler and costs nothing, because
//! routing decisions are made at bring-up and not afterwards.
//!
//! The window address is kept in an atomic and the chip rebuilt around it per
//! call, rather than held in a lock. A lock would have to be ranked, and its
//! rank would be a claim about ordering against the scheduler that this
//! module — which programs hardware at boot and is never touched again — has
//! no reason to make.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use bhaskix_arch::acpi;
use bhaskix_arch::ioapic::IoApic;
use bhaskix_arch::paging;
use bhaskix_boot::{PhysAddr, VirtAddr};
use bhaskix_mm::FRAME_SIZE;

use crate::heap;

/// Makes `length` bytes at `physical` readable through the direct map.
///
/// ACPI tables are not always somewhere the bootloader mapped. The RSDP on a
/// BIOS machine sits in the legacy area below one megabyte, which the memory
/// map calls reserved — so the first version of this code faulted on it during
/// boot, at an address that looked entirely plausible.
///
/// Pages already present are left alone; the rest are mapped uncached and
/// non-executable. Uncached is not a performance decision: firmware tables are
/// read once, and a mapping that matches how the firmware itself describes the
/// region is one less thing that can differ between machines.
fn ensure_mapped(physical: u64, length: usize, hhdm: u64) -> bool {
    if length == 0 {
        return true;
    }
    let Some(last) = physical.checked_add(length as u64 - 1) else {
        return false;
    };
    let first_page = physical & !(FRAME_SIZE - 1);
    let last_page = last & !(FRAME_SIZE - 1);

    let mut page = first_page;
    loop {
        let virtual_address = hhdm + page;
        // SAFETY: reading the active page table's entries has no side effects.
        let present = unsafe {
            paging::translate(paging::active_page_table(), virtual_address, hhdm).is_some()
        };
        if !present {
            let mapped = heap::with(|heap| {
                let pmm = heap.pmm_mut();
                // SAFETY: bootstrap CPU during boot, mapping firmware memory
                // read-only into the direct map at its usual address.
                unsafe {
                    paging::map_device_page(virtual_address, page, hhdm, &mut || {
                        pmm.allocate(0, bhaskix_mm::Zone::Normal)
                            .ok()
                            .map(|pfn| u64::from(pfn) * FRAME_SIZE)
                    })
                }
            });
            match mapped {
                Some(Ok(())) => {}
                _ => return false,
            }
        }

        if page == last_page {
            return true;
        }
        page += FRAME_SIZE;
    }
}

/// Virtual address of the chip's register window, or zero.
static WINDOW: AtomicU64 = AtomicU64::new(0);
/// The first global interrupt the chip is responsible for.
static GSI_BASE: AtomicU32 = AtomicU32::new(0);
/// Inputs the chip reported.
static INPUTS: AtomicU32 = AtomicU32::new(0);

/// Why interrupt routing could not be brought up.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IrqError {
    /// The bootloader reported no ACPI tables.
    NoTables,
    /// The tables held no I/O APIC.
    NoIoApic,
    /// The register window could not be mapped.
    MapFailed,
    /// The heap was not available to allocate a page table from.
    NoHeap,
    /// The chip refused the redirection.
    NotRouted,
    /// Nothing has been brought up.
    NotPresent,
    /// The destination CPU's APIC id does not fit a physical destination.
    UnreachableCpu,
}

/// What bring-up found.
#[derive(Clone, Copy, Debug)]
pub struct Report {
    /// Physical address of the chip that was claimed.
    pub address: u32,
    /// How many inputs it has.
    pub inputs: u32,
    /// Interrupt source overrides the firmware declared.
    pub overrides: usize,
    /// I/O APICs the firmware declared, of which the first is used.
    pub chips: usize,
    /// Whether the firmware's table was longer than this kernel will read.
    pub truncated: bool,
}

/// Finds the I/O APIC and maps its registers.
///
/// # Errors
///
/// [`IrqError`] naming what was missing. Every one of them is survivable: the
/// kernel runs without device interrupts, it just cannot be typed at.
///
/// # Safety
///
/// Must be called once, on the bootstrap CPU, after the heap exists. `rsdp`
/// must be the address the bootloader reported and `hhdm` the direct map base.
pub unsafe fn init(rsdp: Option<PhysAddr>, hhdm: u64) -> Result<Report, IrqError> {
    let rsdp = rsdp.ok_or(IrqError::NoTables)?;

    // SAFETY: the caller guarantees these came from the handoff; the walk maps
    // every byte it reads through the closure before reading it.
    let madt = unsafe {
        acpi::madt(rsdp.as_u64(), hhdm, &mut |physical, length| {
            ensure_mapped(physical, length, hhdm)
        })
    }
    .ok_or(IrqError::NoTables)?;
    let entry = madt.io_apic().ok_or(IrqError::NoIoApic)?;

    let physical = u64::from(entry.address);
    let window = PhysAddr(physical).to_hhdm(VirtAddr(hhdm)).as_u64();

    // The direct map already covers this address as ordinary memory. Mapping
    // it again with device attributes is not redundant: a cached mapping of a
    // register window means a write can sit in a cache line and a read can be
    // answered from one, so a redirection entry would be programmed into the
    // cache and the chip would never see it.
    let mapped = heap::with(|heap| {
        let pmm = heap.pmm_mut();
        // SAFETY: bootstrap CPU during boot, mapping a firmware-reported
        // register page into the active address space.
        unsafe {
            paging::map_device_page(window, physical, hhdm, &mut || {
                pmm.allocate(0, bhaskix_mm::Zone::Normal)
                    .ok()
                    .map(|pfn| u64::from(pfn) * bhaskix_mm::FRAME_SIZE)
            })
        }
    })
    .ok_or(IrqError::NoHeap)?;
    mapped.map_err(|_| IrqError::MapFailed)?;

    // SAFETY: `window` is the mapping just made of this chip's registers, and
    // this is the only code that touches it.
    let chip = unsafe { IoApic::new(window as *mut u8, entry.gsi_base) };

    INPUTS.store(chip.inputs(), Ordering::Relaxed);
    GSI_BASE.store(chip.gsi_base(), Ordering::Relaxed);
    // Published last: a non-zero window is what every other function here
    // takes as "the chip is ready", so it must not be visible before the
    // values describing it are.
    WINDOW.store(window, Ordering::Release);

    Ok(Report {
        address: entry.address,
        inputs: chip.inputs(),
        overrides: madt.overrides(),
        chips: madt.io_apics_seen,
        truncated: madt.truncated,
    })
}

/// Rebuilds the chip, if there is one.
fn chip() -> Option<IoApic> {
    let window = WINDOW.load(Ordering::Acquire);
    if window == 0 {
        return None;
    }
    // SAFETY: `window` was mapped by `init` and is never unmapped; the gsi
    // base was published before the window. Rebuilding is sound because the
    // type holds no state beyond these -- it reads the chip for anything else.
    Some(unsafe { IoApic::new(window as *mut u8, GSI_BASE.load(Ordering::Relaxed)) })
}

/// Routes a legacy ISA interrupt to `vector` on the CPU with `apic_id`.
///
/// The interrupt number is translated through the firmware's overrides first.
/// Skipping that step is the classic way to program an input nothing is wired
/// to and then debug a device that "raises no interrupts".
///
/// # Errors
///
/// [`IrqError`] if there is no chip, the CPU cannot be a physical destination,
/// or the chip refused the input.
///
/// # Safety
///
/// There must be an IDT gate for `vector` whose handler acknowledges the local
/// APIC. From the moment this returns, interrupts arrive.
pub unsafe fn route_isa(
    rsdp: Option<PhysAddr>,
    hhdm: u64,
    irq: u8,
    vector: u8,
    apic_id: u32,
) -> Result<u32, IrqError> {
    let mut chip = chip().ok_or(IrqError::NotPresent)?;
    let rsdp = rsdp.ok_or(IrqError::NoTables)?;
    // SAFETY: as `init`; the tables were mapped there and are not unmapped.
    let madt = unsafe {
        acpi::madt(rsdp.as_u64(), hhdm, &mut |physical, length| {
            ensure_mapped(physical, length, hhdm)
        })
    }
    .ok_or(IrqError::NoTables)?;
    let routing = madt.route(irq);

    let destination = u8::try_from(apic_id).map_err(|_| IrqError::UnreachableCpu)?;

    // SAFETY: the caller guarantees a handler for `vector`; the chip is the
    // one `init` mapped, and this runs on the bootstrap CPU only.
    unsafe {
        chip.route(
            routing.gsi,
            vector,
            destination,
            routing.active_low,
            routing.level,
        )
    }
    .map_err(|_| IrqError::NotRouted)?;

    Ok(routing.gsi)
}

/// Reads back the redirection entry for `gsi`.
///
/// For the self-test: a write to a memory-mapped register that is never read
/// back is a write that may have gone anywhere.
#[must_use]
pub fn redirection(gsi: u32) -> Option<u32> {
    let chip = chip()?;
    // SAFETY: the chip `init` mapped; reading a redirection register has no
    // side effects.
    unsafe { chip.redirection(gsi) }
}

/// Whether a chip was found and mapped.
#[must_use]
pub fn present() -> bool {
    WINDOW.load(Ordering::Acquire) != 0
}

/// How many inputs the chip has.
#[must_use]
pub fn inputs() -> u32 {
    INPUTS.load(Ordering::Relaxed)
}
