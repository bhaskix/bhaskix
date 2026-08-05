// SPDX-License-Identifier: Apache-2.0
//! Finding the IOMMU, and saying honestly whether there is one.
//!
//! [RFC 0012](../../../docs/rfc/0012-iommu.md) step 1: **discovery and
//! reporting, with no translation enabled.** The units are found and described;
//! nothing is programmed, and every DMA-capable device still reaches all of
//! physical memory. What changes here is only that the machine says which of
//! those two worlds it is in, rather than asserting the worse one.
//!
//! # Why reporting is a step of its own
//!
//! `docs/memory.md` §5 commits the kernel to printing its degraded mode rather
//! than silently accepting a broken threat model. Until now that line was a
//! constant: it said "NO IOMMU" on every machine, including machines with three
//! of them. A warning that is always printed carries no information — it cannot
//! distinguish the dangerous case from the safe one, which is the entire job of
//! a warning. Discovery is what makes the sentence true rather than merely
//! cautious.
//!
//! # The table is not trusted
//!
//! `DMAR` is firmware input, parsed by `bhaskix_arch::acpi::parse_dmar` with
//! the same treatment as the MADT walk and a seeded mutation harness beside it.
//! Believing it wrongly is worse than believing the MADT wrongly: what gets
//! built from a `DMAR` is a register window that is then written to as if it
//! were an IOMMU.

use bhaskix_boot::PhysAddr;

use bhaskix_arch::vtd;

use crate::println;
use crate::sync::{Rank, SpinLock};

/// The one window, once it exists.
///
/// Global because revocation must reach it. RFC 0009's `revoke` walks an
/// object's mappings and removes them; step 5 makes a device window one of the
/// places an object can be mapped, so the revoke path needs the window without
/// having been handed it.
static WINDOW: SpinLock<Option<(Report, Window)>> = SpinLock::new(Rank::DmaWindow, None);

/// The unit's register window, mapped once.
///
/// Cached rather than mapped per use, and that is a locking decision rather
/// than a performance one: mapping MMIO reaches the heap, which is the
/// outermost lock here, and invalidating an IOTLB happens while holding the
/// innermost. Doing it per use would be an inversion on every unmap.
static UNIT_BASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// What discovery found, if anything.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Report {
    /// Remapping units the firmware described and this kernel recorded.
    pub units: usize,
    /// Units the firmware described, including any refused or unrecorded.
    pub units_seen: usize,
    /// Firmware-reserved regions recorded.
    pub regions: usize,
    /// Those regions, as inclusive `(base, limit)` pairs.
    ///
    /// Carried rather than counted, because step 3 has to identity-map them
    /// and check each against the kernel's own image before it does.
    pub region_list: [(u64, u64); bhaskix_arch::acpi::MAX_RESERVED],
    /// Physical address bits the hardware can generate.
    pub address_width: u8,
    /// Whether the platform declares interrupt remapping.
    pub interrupt_remapping: bool,
    /// Whether the table described more than was recorded, or held a structure
    /// that was refused.
    pub incomplete: bool,
    /// The first unit's register window, for the step that programs it.
    pub first_register_base: u64,
}

/// Finds the IOMMU units the firmware describes.
///
/// `None` means no `DMAR` table, or one that did not parse — RFC 0012 treats
/// those as the same thing deliberately, because a table that does not parse
/// describes hardware this kernel cannot program, and pretending otherwise is
/// how a half-working IOMMU happens.
///
/// # Safety
///
/// `rsdp` must be the address the bootloader reported and `hhdm` the direct map
/// base, and the caller must be able to map firmware tables — the same
/// obligation `irq::init` carries.
pub unsafe fn discover(rsdp: Option<PhysAddr>, hhdm: u64) -> Option<Report> {
    let rsdp = rsdp?;
    // SAFETY: the caller's obligation; the walk maps every byte it reads
    // through the closure before reading it, as the MADT walk does.
    let dmar = unsafe {
        bhaskix_arch::acpi::dmar(rsdp.as_u64(), hhdm, &mut |physical, length| {
            crate::mmio::map(physical, length as u64, hhdm).is_some()
        })
    }?;

    let mut region_list = [(0u64, 0u64); bhaskix_arch::acpi::MAX_RESERVED];
    for (slot, region) in region_list.iter_mut().zip(dmar.regions()) {
        *slot = (region.base, region.limit);
    }

    Some(Report {
        units: dmar.unit_count(),
        units_seen: dmar.units_seen,
        regions: dmar.region_count(),
        region_list,
        address_width: dmar.host_address_width,
        interrupt_remapping: dmar.interrupt_remapping,
        incomplete: dmar.truncated,
        first_register_base: dmar.units().next().map_or(0, |unit| unit.register_base),
    })
}

/// Prints what was found, or that nothing was.
///
/// Deliberately says "found, not enabled". A line that reported an IOMMU
/// without that qualifier would read, correctly and wrongly, as protection the
/// machine does not yet have: step 1 programs nothing, and every device still
/// reaches all of memory.
pub fn report(found: Option<Report>) {
    match found {
        Some(report) if report.units > 0 => {
            println!(
                "    iommu          {} unit{} found, not enabled; {}-bit addresses, \
                 {} reserved region{}, interrupt remapping {}",
                report.units,
                if report.units == 1 { "" } else { "s" },
                report.address_width,
                report.regions,
                if report.regions == 1 { "" } else { "s" },
                if report.interrupt_remapping {
                    "supported"
                } else {
                    "absent"
                },
            );
            if report.incomplete {
                // Not a detail. A unit that was refused or dropped is a set of
                // devices nobody is translating, and RFC 0012's rule is that a
                // device covered by no unit is treated as if there were no
                // IOMMU at all.
                println!(
                    "    iommu          WARNING: the firmware described {} unit{} and {} \
                     could be used",
                    report.units_seen,
                    if report.units_seen == 1 { "" } else { "s" },
                    report.units,
                );
            }
        }
        // A `DMAR` with no usable unit is the same machine as no `DMAR`, and
        // says so in the same words -- the difference matters to whoever reads
        // the firmware, not to a device that can reach the kernel either way.
        Some(_) | None => {}
    }
}

/// States what a device can reach, once it is settled.
///
/// Printed *after* the attempt to enable rather than before it, because the
/// answer is not known until then and a boot log that says one thing and then
/// does another is worse than one that waits. `docs/memory.md` §5 asks for the
/// degraded mode to be printed; what it is really asking for is that the
/// machine never leaves this unsaid.
pub fn report_dma(translating: bool) {
    if translating {
        println!(
            "    dma            translating: this device reaches only what it was given \
             (docs/memory.md §5)"
        );
    } else {
        println!(
            "    dma            NO IOMMU: this device can reach all of physical memory \
             (docs/memory.md §5)"
        );
    }
}

/// An address a *device* uses.
///
/// Not a [`PhysAddr`], and the compiler says so. They are both integers naming
/// memory and they are not interchangeable: handing a device a physical
/// address once translation is on is a fault, and handing the kernel a device
/// address is a read of whatever happens to live there. RFC 0012 makes the
/// distinction a type because the failure mode of confusing them is silent.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct DevAddr(u64);

impl DevAddr {
    /// The raw address, for programming a descriptor.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Rebuilds one from an address this module handed out.
    #[must_use]
    pub const fn from_u64(address: u64) -> Self {
        Self(address)
    }
}

/// Which addresses in a window are free.
///
/// A bump pointer with a small free list. Not a bitmap: a 39-bit window holds
/// 128 million pages, and a bitmap of them is 16 MiB of kernel memory per
/// device to track allocations that this driver model makes a handful of.
///
/// # Zero is never handed out
///
/// A device address of zero is what an uninitialised descriptor holds. Keeping
/// it permanently unmapped means a device that DMAs to an address nobody set
/// takes a fault naming the device, which is the whole point of the exercise —
/// rather than reading whatever was mapped at the bottom of its window.
#[derive(Clone, Copy, Debug)]
pub struct DevAddrSpace {
    /// Next address in the region below 4 GiB.
    low_next: u64,
    /// Next address in the region above it.
    high_next: u64,
    /// The end of the window, from its address width.
    limit: u64,
    /// Returned extents, for reuse. Fixed, because this allocates nothing.
    freed: [Option<(u64, u64)>; Self::FREE_SLOTS],
}

impl DevAddrSpace {
    /// Extents remembered for reuse before they are simply forgotten.
    ///
    /// Forgetting leaks address space, not memory — the page is unmapped
    /// either way, and the window is 512 GiB.
    const FREE_SLOTS: usize = 16;

    /// The boundary a 32-bit device cannot address past.
    pub const LOW_LIMIT: u64 = 1 << 32;

    /// A fresh window of `width` addressable bits.
    #[must_use]
    pub fn new(width: bhaskix_arch::vtd::AddressWidth) -> Self {
        Self {
            // Both regions start one page in, so zero is never allocated.
            low_next: bhaskix_arch::vtd::PAGE_SIZE,
            high_next: Self::LOW_LIMIT,
            limit: width.limit(),
            freed: [None; Self::FREE_SLOTS],
        }
    }

    /// Allocates `pages` contiguous pages.
    ///
    /// `below_4gib` is for a device whose descriptors hold 32-bit addresses.
    /// RFC 0012 chose this over a bounce buffer deliberately: the constraint is
    /// satisfied by *where* the address is allocated, so there is no copy and
    /// no second buffer whose lifetime has to be tracked.
    ///
    /// `None` when the window has no room, which the caller must report rather
    /// than work around — nothing is programmed on this path.
    pub fn allocate(&mut self, pages: u64, below_4gib: bool) -> Option<DevAddr> {
        if pages == 0 {
            return None;
        }
        let bytes = pages.checked_mul(bhaskix_arch::vtd::PAGE_SIZE)?;

        // An exact-fit extent that was returned earlier. Exact, because
        // splitting one leaves a remainder this fixed table cannot describe
        // and would quietly lose.
        for slot in &mut self.freed {
            if let Some((address, extent)) = *slot
                && extent == bytes
                && (!below_4gib || address + extent <= Self::LOW_LIMIT)
            {
                *slot = None;
                return Some(DevAddr(address));
            }
        }

        let next = if below_4gib {
            &mut self.low_next
        } else {
            &mut self.high_next
        };
        let ceiling = if below_4gib {
            Self::LOW_LIMIT
        } else {
            // Inclusive limit, so one past the last addressable byte.
            self.limit.checked_add(1)?
        };

        let address = *next;
        let end = address.checked_add(bytes)?;
        if end > ceiling {
            return None;
        }
        *next = end;
        Some(DevAddr(address))
    }

    /// Returns an extent for reuse.
    ///
    /// Remembering it is best effort; forgetting costs address space in a
    /// window that has 512 GiB of it, and never costs a page that stays mapped
    /// — the unmapping is the caller's, and it has already happened.
    pub fn free(&mut self, address: DevAddr, pages: u64) {
        let Some(bytes) = pages.checked_mul(bhaskix_arch::vtd::PAGE_SIZE) else {
            return;
        };
        if bytes == 0 {
            return;
        }
        for slot in &mut self.freed {
            if slot.is_none() {
                *slot = Some((address.as_u64(), bytes));
                return;
            }
        }
    }

    /// The highest address this window can translate.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }
}

/// The structures one device's translation walks, built and not enabled.
///
/// RFC 0012 step 2. Every field is a physical address of a page this kernel
/// allocated and wrote; nothing here has been shown to any hardware, and no
/// register has been touched. What it proves is that the tables can be built
/// on a real machine with the widths the firmware reported — the part the host
/// tests cannot check, because they have no frames.
#[derive(Clone, Copy, Debug)]
pub struct Window {
    /// Physical address of the root table, which is what the unit's register
    /// would be pointed at.
    pub root_table: u64,
    /// Physical address of the context table for this device's bus.
    pub context_table: u64,
    /// Physical address of the second-level page table's root.
    pub page_table: u64,
    /// How many address bits it translates.
    pub width: bhaskix_arch::vtd::AddressWidth,
    /// Which device it translates for.
    pub device: (u8, u8, u8),
    /// Which of that window's addresses are free.
    pub addresses: DevAddrSpace,
}

/// Allocates a zeroed frame, returning `(physical, virtual)`.
///
/// Zeroed because every entry this kernel does not write must read as absent.
/// A table built on a dirty frame is a device given whatever the last owner
/// of that page left behind, interpreted as page addresses.
fn zeroed_frame(hhdm: u64) -> Option<(u64, u64)> {
    let pfn = crate::heap::with(|heap| heap.pmm_mut().allocate(0, bhaskix_mm::Zone::Normal).ok())??;
    let physical = u64::from(pfn) * bhaskix_mm::FRAME_SIZE;
    // SAFETY: a frame that was just allocated, so nothing else refers to it,
    // reachable through the direct map.
    unsafe {
        core::ptr::write_bytes(
            (hhdm + physical) as *mut u8,
            0,
            bhaskix_mm::FRAME_SIZE as usize,
        );
    }
    Some((physical, hhdm + physical))
}

/// Builds the translation structures for one device, and enables nothing.
///
/// Default deny, as RFC 0012 requires: the page table is allocated and left
/// **empty**, so a device translated through it can reach nothing at all. That
/// is `driver-model.md` §5's "an unmatched device gets no capabilities" made
/// true by hardware rather than by the driver framework's politeness — and it
/// is why this cannot be enabled until step 3 identity-maps what firmware says
/// a device must keep reaching.
///
/// `None` if there are no frames, or if the hardware reported an address width
/// this kernel cannot describe. Both are refusals rather than defaults: a
/// window built to the wrong width is tables the hardware walks to the wrong
/// depth.
pub fn build_window(
    report: &Report,
    device: (u8, u8, u8),
    domain: u16,
    hhdm: u64,
) -> Option<Window> {
    use bhaskix_arch::vtd;

    let width = vtd::AddressWidth::fitting(report.address_width)?;

    let (root_table, root_virtual) = zeroed_frame(hhdm)?;
    let (context_table, context_virtual) = zeroed_frame(hhdm)?;
    let (page_table, _) = zeroed_frame(hhdm)?;

    let (bus, slot, function) = device;

    let root = vtd::RootEntry { context_table };
    let (root_low, root_high) = root.to_bits();
    let context = vtd::ContextEntry {
        page_table,
        width,
        domain,
    };
    let (context_low, context_high) = context.to_bits();

    // SAFETY: both frames were just allocated and zeroed by this function, and
    // the indices are bounded by construction -- a root index is a byte and a
    // context index is masked to eight bits, so neither can leave its page.
    // Written as two 64-bit words each, which is the layout the hardware
    // reads.
    unsafe {
        let root_entry = (root_virtual as *mut u64).add(vtd::root_index(bus) * 2);
        core::ptr::write_volatile(root_entry, root_low);
        core::ptr::write_volatile(root_entry.add(1), root_high);

        let context_entry =
            (context_virtual as *mut u64).add(vtd::context_index(slot, function) * 2);
        core::ptr::write_volatile(context_entry, context_low);
        core::ptr::write_volatile(context_entry.add(1), context_high);
    }

    Some(Window {
        root_table,
        context_table,
        page_table,
        width,
        device,
        addresses: DevAddrSpace::new(width),
    })
}

/// Reads a window's own entries back and checks they say what was written.
///
/// Not paranoia about the writes: it is the only check that the *indices* were
/// right. An entry written at the wrong offset is a device whose translation
/// silently uses another device's tables, and every value in it would still be
/// correct.
#[must_use]
pub fn verify_window(window: &Window, hhdm: u64) -> bool {
    use bhaskix_arch::vtd;

    let (bus, slot, function) = window.device;
    let expected_root = vtd::RootEntry {
        context_table: window.context_table,
    }
    .to_bits();
    let expected_context = vtd::ContextEntry {
        page_table: window.page_table,
        width: window.width,
        domain: 0,
    }
    .to_bits();

    // The offsets are recomputed here from the requester id rather than taken
    // from `vtd::root_index` and `vtd::context_index`, and the duplication is
    // deliberate. A check that locates an entry with the same function that
    // placed it cannot catch an error in that function: it would read back
    // whatever it wrote, at whatever offset, and agree. The first version of
    // this did exactly that, and passed a deliberately broken index.
    let root_slot = bus as usize;
    let context_slot = (((slot & 0x1f) as usize) << 3) | ((function & 0x07) as usize);

    // SAFETY: addresses this module allocated and wrote, through the direct
    // map. `root_slot` is a byte and `context_slot` is masked to eight bits,
    // so neither can leave its page.
    unsafe {
        let root_entry = ((hhdm + window.root_table) as *const u64).add(root_slot * 2);
        let context_entry = ((hhdm + window.context_table) as *const u64).add(context_slot * 2);

        if core::ptr::read_volatile(root_entry) != expected_root.0
            || core::ptr::read_volatile(root_entry.add(1)) != expected_root.1
            || core::ptr::read_volatile(context_entry) != expected_context.0
            || core::ptr::read_volatile(context_entry.add(1)) != expected_context.1
        {
            return false;
        }

        // And exactly one context entry is present. An entry written at the
        // wrong offset leaves the right one absent -- caught above -- and a
        // stray one behind, which is a second device this window would
        // translate for without anyone asking.
        let context = (hhdm + window.context_table) as *const u64;
        let mut present = 0;
        for index in 0..256 {
            if core::ptr::read_volatile(context.add(index * 2)) & 1 != 0 {
                present += 1;
            }
        }
        present == 1
    }
}

/// Maps one page into a window, building the levels it needs.
///
/// Returns false if a level could not be allocated, and leaves whatever it
/// built in place — the intermediate tables are empty and harmless, and
/// unwinding them would be a second failure path on the boot sequence that
/// enables translation. The caller's answer to false is to refuse to enable,
/// not to retry.
///
/// # Panics on nothing, and refuses on everything else
///
/// An address past what the window's width can translate is refused rather
/// than truncated: the hardware would fault on it, and building the entry
/// would put a mapping somewhere nobody asked for.
fn map_page(window: &Window, address: u64, physical: u64, rights: vtd::Rights, hhdm: u64) -> bool {
    if !rights.grants_anything() || address > window.addresses.limit() {
        return false;
    }

    let mut table = window.page_table;
    // Down from the root to the level above the page, allocating as needed.
    for level in (2..=window.width.levels()).rev() {
        let index = vtd::level_index(address, level);
        // SAFETY: `table` is a frame this module allocated and zeroed, reached
        // through the direct map; `index` is nine bits, so it cannot leave it.
        let entry = unsafe { core::ptr::read_volatile(((hhdm + table) as *const u64).add(index)) };

        table = match vtd::PageEntry::from_bits(entry) {
            Some(existing) => existing.address,
            None => {
                let Some((next, _)) = zeroed_frame(hhdm) else {
                    return false;
                };
                let bits = vtd::table_entry(next).to_bits();
                // SAFETY: as the read above.
                unsafe {
                    core::ptr::write_volatile(((hhdm + table) as *mut u64).add(index), bits);
                }
                next
            }
        };
    }

    let index = vtd::level_index(address, 1);
    let bits = vtd::PageEntry {
        address: physical,
        rights,
    }
    .to_bits();
    // SAFETY: as above -- a table this module allocated, at a nine-bit index.
    unsafe {
        core::ptr::write_volatile(((hhdm + table) as *mut u64).add(index), bits);
    }
    true
}

/// Identity-maps `frames` into a window: the device reaches them at their own
/// physical addresses.
///
/// The transitional mapping RFC 0012 step 3 needs. The driver still writes
/// physical addresses into its descriptors, so until step 4 converts it to
/// hand over a `DevAddr`, the window must translate those addresses to
/// themselves. Identity is not a weaker protection here: everything *not* in
/// this list is still refused, which is the whole difference from a machine
/// with no IOMMU.
#[must_use]
pub fn identity_map(window: &Window, frames: &[u64], hhdm: u64) -> usize {
    let mut mapped = 0;
    for frame in frames {
        if map_page(window, *frame, *frame, vtd::Rights::READ_WRITE, hhdm) {
            mapped += 1;
        }
    }
    mapped
}

/// Identity-maps the regions firmware says a device must keep reaching.
///
/// **Refuses any that overlap the kernel's own image**, and says so. An `RMRR`
/// is chosen by firmware, so a firmware that named the kernel's memory would
/// be asking for a device to be granted access to it — RFC 0012 requires the
/// check rather than the trust, and requires the refusal to be reported,
/// because a machine whose firmware asked for that is a machine worth knowing
/// about.
///
/// Returns `(mapped, refused)`.
pub fn map_reserved(
    window: &Window,
    report: &Report,
    kernel: (u64, u64),
    hhdm: u64,
) -> (usize, usize) {
    let (kernel_start, kernel_end) = kernel;
    let mut mapped = 0;
    let mut refused = 0;

    for region in report.region_list.iter().take(report.regions) {
        let (base, limit) = *region;
        // Overlap, computed on inclusive bounds because a limit is the last
        // byte rather than one past it.
        if overlaps_kernel((base, limit), (kernel_start, kernel_end)) {
            refused += 1;
            println!(
                "    iommu          REFUSED a reserved region {base:#x}..={limit:#x} \
                 overlapping the kernel"
            );
            continue;
        }
        let mut address = base & !(vtd::PAGE_SIZE - 1);
        while address <= limit {
            if map_page(window, address, address, vtd::Rights::READ_WRITE, hhdm) {
                mapped += 1;
            }
            let Some(next) = address.checked_add(vtd::PAGE_SIZE) else {
                break;
            };
            address = next;
        }
    }
    (mapped, refused)
}

/// Installs the window everything else will reach through.
///
/// Called once, at bring-up. Revocation needs the window without having been
/// handed it — an object's owner asks for it to be revoked, and what that has
/// to reach is whichever device was given the object.
pub fn install(report: Report, window: Window) {
    *WINDOW.lock() = Some((report, window));
}

/// Whether a window exists to map into.
#[must_use]
pub fn present() -> bool {
    WINDOW.lock().is_some()
}

/// Maps a `Memory` object into the device window, and records it.
///
/// RFC 0012 step 5, and RFC 0009's `Memory` on the other side of it: the same
/// frames a domain can share with another domain are what a device is given,
/// through the same object and the same revocation. Returns where the device
/// should look.
///
/// `None` if there is no window, the object is gone, or the window has no
/// room — all refusals, because a device that was told an address for a
/// mapping that did not happen reads whatever is there instead.
pub fn map_memory(
    id: crate::shared::MemoryId,
    rights: vtd::Rights,
    below_4gib: bool,
    hhdm: u64,
) -> Option<DevAddr> {
    let (frames, count) = crate::shared::frames_of(id)?;
    if count == 0 {
        return None;
    }

    let mut guard = WINDOW.lock();
    let (_, window) = guard.as_mut()?;

    // The object's frames need not be contiguous in physical memory, and the
    // device needs them contiguous in *its* address space -- which is most of
    // what an IOMMU is for. So the address is allocated once and each frame is
    // placed at its own offset within it.
    let address = window.addresses.allocate(count as u64, below_4gib)?;
    for (page, frame) in frames.iter().take(count).enumerate() {
        let at = address.as_u64() + (page as u64) * vtd::PAGE_SIZE;
        let physical = frame * bhaskix_mm::FRAME_SIZE;
        if !map_page(window, at, physical, rights, hhdm) {
            // Nothing half-mapped: the device would reach part of an object
            // and fault on the rest, which reads as a driver bug.
            for done in 0..page {
                let at = address.as_u64() + (done as u64) * vtd::PAGE_SIZE;
                let _ = clear_page(window, at, hhdm);
            }
            window.addresses.free(address, count as u64);
            return None;
        }
    }
    drop(guard);

    if !crate::shared::record_device_mapping(id, address.as_u64(), count as u64) {
        // Recorded or not mapped. An object whose device mapping is not
        // written down is one revocation cannot find, which is a page a device
        // keeps after the object naming it is destroyed.
        unmap_device(address.as_u64(), count as u64);
        return None;
    }
    Some(address)
}

/// Removes a device mapping recorded against a `Memory` object.
///
/// Called by RFC 0009's `revoke`. Invalidates before returning, for the same
/// reason `unmap` does: until the IOTLB is invalidated the device still
/// reaches the page that has just been taken away from it.
pub fn unmap_device(address: u64, pages: u64) -> bool {
    let mut guard = WINDOW.lock();
    let Some((_, window)) = guard.as_mut() else {
        return false;
    };
    let hhdm = crate::shared::hhdm();
    for page in 0..pages {
        let at = address + page * vtd::PAGE_SIZE;
        if !clear_page(window, at, hhdm) {
            return false;
        }
    }
    window.addresses.free(DevAddr::from_u64(address), pages);
    drop(guard);

    // SAFETY: the unit `enable` programmed and whose registers it cached.
    unsafe { invalidate() }
}

/// Whether a firmware-reserved region overlaps the kernel's own image.
///
/// Both bounds are inclusive: a limit is the last byte, not one past it, and
/// treating it as exclusive lets a region ending exactly at the kernel's first
/// byte through.
///
/// Pure, and tested on the host, because the machine this matters on is the
/// one that cannot be booted here: QEMU's `intel-iommu` declares **no**
/// reserved regions at all, so the refusal path has no natural test in the
/// emulator. A check that only runs on firmware nobody has is a check that
/// ships unexercised.
#[must_use]
pub const fn overlaps_kernel(region: (u64, u64), kernel: (u64, u64)) -> bool {
    let (base, limit) = region;
    let (start, end) = kernel;
    base <= end && start <= limit
}

/// The kernel's own physical extent, from the memory map.
///
/// Taken from the map rather than from a linker symbol because what must not
/// be handed to a device is every byte the loader placed, which is the kernel
/// *and its modules* — the ramdisk among them.
#[must_use]
pub fn kernel_extent(handoff: &bhaskix_boot::Handoff) -> (u64, u64) {
    let mut start = u64::MAX;
    let mut end = 0u64;
    for region in handoff.memory_map {
        if region.kind == bhaskix_boot::MemoryKind::KernelAndModules {
            let base = region.base.as_u64();
            start = start.min(base);
            end = end.max(base.saturating_add(region.length).saturating_sub(1));
        }
    }
    if start == u64::MAX {
        // No region said so. Refusing everything is the safe answer: a
        // reserved region that cannot be checked against the kernel is one
        // that must not be identity-mapped.
        (0, u64::MAX)
    } else {
        (start, end)
    }
}

/// Programs a unit with a window's root table and turns translation on.
///
/// From the moment this returns true, every DMA by every device the root table
/// covers is translated and anything unmapped is refused. There is no partial
/// state, which is why everything the machine needs must already be mapped —
/// RFC 0012's sequence is build, identity-map, *then* enable, and the order is
/// not a preference.
///
/// # Safety
///
/// `window` must be built and populated, and its tables must not be freed. The
/// unit walks them by physical address with no notice.
pub unsafe fn enable(report: &Report, window: &Window, hhdm: u64) -> Result<(), &'static str> {
    let base = crate::mmio::map(report.first_register_base, bhaskix_mm::FRAME_SIZE, hhdm)
        .ok_or("the unit's registers could not be mapped")?;

    // SAFETY: the window the `DMAR` named, just mapped, and nothing else in
    // this kernel programs a remapping unit.
    let mut unit = unsafe { vtd::Unit::new(base as *mut u8) };

    // SAFETY: a mapped register window, as above.
    unsafe {
        // A zero version register means the `DMAR` named an address that is
        // not a remapping unit. The parser's alignment check makes that
        // unlikely; this makes it visible rather than programming whatever is
        // there.
        if unit.version() == 0 {
            return Err("the register window is not a remapping unit");
        }
        // What the hardware can *generate* is not what it can be asked to
        // *walk*. Building tables to an unsupported width is a walk to the
        // wrong depth, and the tables are already built by now.
        if !unit.supports_width(window.width) {
            return Err("the unit does not support the width the tables were built to");
        }
        if !unit.set_root_table(window.root_table) {
            return Err("the unit did not accept the root table");
        }
        // Both caches, before enabling. A unit that had cached anything from a
        // previous kernel would translate through it.
        if !unit.invalidate_context() {
            return Err("the context cache did not invalidate");
        }
        if !unit.invalidate_iotlb() {
            return Err("the IOTLB did not invalidate");
        }
        if !unit.enable_translation() {
            return Err("the unit did not report translation enabled");
        }
    }
    UNIT_BASE.store(base, core::sync::atomic::Ordering::Release);
    Ok(())
}

/// Whether the unit has recorded a fault since translation was enabled.
///
/// A fault means a device attempted an access it was not granted — RFC 0012's
/// position is that this is the feature rather than an error path, because it
/// is either a driver bug or a hostile device and both are what the exercise
/// exists to make visible.
///
/// # Safety
///
/// As [`enable`], and the unit must already have been mapped by it.
#[must_use]
pub unsafe fn faulted(report: &Report, hhdm: u64) -> Option<bool> {
    let base = crate::mmio::map(report.first_register_base, bhaskix_mm::FRAME_SIZE, hhdm)?;
    // SAFETY: the same window `enable` mapped and programmed.
    unsafe {
        let unit = vtd::Unit::new(base as *mut u8);
        Some(unit.faulted())
    }
}

/// Maps `pages` physical pages into a window and returns where the device
/// should look for them.
///
/// This is RFC 0012's `MAP`. The address is allocated from the window rather
/// than chosen by the caller, which is what makes a `DevAddr` meaningful:
/// nothing outside what this returned is reachable, so a device that computes
/// an address rather than being given one gets a fault.
///
/// `below_4gib` for a device whose descriptors hold 32-bit addresses. The
/// constraint is satisfied by *where* the address comes from — no bounce
/// buffer, no copy, no second lifetime.
pub fn map(
    window: &mut Window,
    physical: u64,
    pages: u64,
    rights: vtd::Rights,
    below_4gib: bool,
    hhdm: u64,
) -> Option<DevAddr> {
    let address = window.addresses.allocate(pages, below_4gib)?;
    for page in 0..pages {
        let offset = page.checked_mul(vtd::PAGE_SIZE)?;
        if !map_page(
            window,
            address.as_u64().checked_add(offset)?,
            physical.checked_add(offset)?,
            rights,
            hhdm,
        ) {
            // Half a mapping is worse than none: the device would reach part
            // of a buffer and fault on the rest, which reads as a device bug.
            // The address is given back and nothing is programmed.
            window.addresses.free(address, pages);
            return None;
        }
    }
    Some(address)
}

/// Removes a mapping and invalidates before returning.
///
/// The invalidation is the reason this cannot be a table write and a return.
/// Until the IOTLB is invalidated the device may still be translating through
/// the entry that was just removed, so an `UNMAP` that returned early would
/// tell its caller a page is unreachable while the hardware still reaches it —
/// which is exactly the window RFC 0012 calls out as the difference between
/// strict and deferred invalidation. Strict, here, and the cost is measured
/// rather than assumed away.
pub fn unmap(window: &mut Window, address: DevAddr, pages: u64, hhdm: u64) -> bool {
    for page in 0..pages {
        let Some(offset) = page.checked_mul(vtd::PAGE_SIZE) else {
            return false;
        };
        let Some(at) = address.as_u64().checked_add(offset) else {
            return false;
        };
        if !clear_page(window, at, hhdm) {
            return false;
        }
    }
    window.addresses.free(address, pages);

    // SAFETY: the unit this window was programmed into, mapped by `enable`.
    unsafe { invalidate() }
}

/// Clears one page's entry, leaving the levels above it in place.
///
/// The intermediate tables are kept deliberately. Freeing one means proving no
/// other mapping needs it, which is a refcount per level on a path that must
/// not fail — and the cost of keeping it is one page per 2 MiB of address
/// space that was used once.
fn clear_page(window: &Window, address: u64, hhdm: u64) -> bool {
    if address > window.addresses.limit() {
        return false;
    }
    let mut table = window.page_table;
    for level in (2..=window.width.levels()).rev() {
        let index = vtd::level_index(address, level);
        // SAFETY: a table this module allocated, at a nine-bit index.
        let entry = unsafe { core::ptr::read_volatile(((hhdm + table) as *const u64).add(index)) };
        match vtd::PageEntry::from_bits(entry) {
            Some(existing) => table = existing.address,
            // Nothing below this level, so nothing to clear.
            None => return true,
        }
    }
    let index = vtd::level_index(address, 1);
    // SAFETY: as above. Zero is absent, which is what makes the page
    // unreachable rather than reachable-with-no-rights.
    unsafe {
        core::ptr::write_volatile(((hhdm + table) as *mut u64).add(index), 0);
    }
    true
}

/// Invalidates the unit's IOTLB.
///
/// # Safety
///
/// The unit must be the one this window is programmed into.
unsafe fn invalidate() -> bool {
    let base = UNIT_BASE.load(core::sync::atomic::Ordering::Acquire);
    if base == 0 {
        return false;
    }
    // SAFETY: the caller's obligation.
    unsafe {
        let unit = vtd::Unit::new(base as *mut u8);
        unit.invalidate_iotlb()
    }
}

/// What a unit recorded about a refused access.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    /// The requester id that attempted it, as `(bus, device, function)`.
    pub device: (u8, u8, u8),
    /// The address it asked for.
    pub address: u64,
    /// Whether it was a read. Writes are the other case.
    pub read: bool,
    /// The unit's reason code.
    pub reason: u8,
}

/// Reads the first recorded fault, if there is one, and clears it.
///
/// A count alone cannot answer the question a fault raises. "Something
/// faulted" is a number; "device 00:03.0 asked to read 0x4000 and was refused"
/// names the driver to go and look at, which is what makes this the feature
/// RFC 0012 says it is rather than an error path.
///
/// # Safety
///
/// As [`enable`], and the unit must already have been programmed by it.
pub unsafe fn take_fault(report: &Report, hhdm: u64) -> Option<Fault> {
    let base = crate::mmio::map(report.first_register_base, bhaskix_mm::FRAME_SIZE, hhdm)?;
    // SAFETY: the caller's obligation.
    unsafe {
        let unit = vtd::Unit::new(base as *mut u8);
        let (address, requester, read, reason) = unit.take_fault()?;
        Some(Fault {
            device: (
                (requester >> 8) as u8,
                ((requester >> 3) & 0x1f) as u8,
                (requester & 0x07) as u8,
            ),
            address,
            read,
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bhaskix_arch::vtd::{AddressWidth, PAGE_SIZE};

    #[test]
    fn a_reserved_region_overlapping_the_kernel_is_detected() {
        // The check QEMU cannot exercise: its `intel-iommu` declares no
        // reserved regions at all, so on the emulator this path is never
        // taken. A firmware that named the kernel's memory would be asking
        // for a device to be granted access to it, and RFC 0012 requires the
        // check rather than the trust.
        let kernel = (0x0010_0000, 0x0090_0000);

        // Entirely inside, straddling either end, and containing it whole.
        assert!(overlaps_kernel((0x0020_0000, 0x0030_0000), kernel));
        assert!(overlaps_kernel((0x0000_0000, 0x0020_0000), kernel));
        assert!(overlaps_kernel((0x0080_0000, 0x00a0_0000), kernel));
        assert!(overlaps_kernel((0x0000_0000, 0xffff_ffff), kernel));
    }

    #[test]
    fn a_reserved_region_beside_the_kernel_is_allowed() {
        let kernel = (0x0010_0000, 0x0090_0000);
        assert!(!overlaps_kernel((0x0009_0000, 0x0009_ffff), kernel));
        assert!(!overlaps_kernel((0x0090_0001, 0x00a0_0000), kernel));
    }

    #[test]
    fn the_bounds_are_inclusive_at_both_ends() {
        // A limit is the last byte, not one past it. Treating it as exclusive
        // lets a region ending exactly on the kernel's first byte through --
        // one byte of the kernel, handed to a device.
        let kernel = (0x0010_0000, 0x0090_0000);
        assert!(overlaps_kernel((0x0000_0000, 0x0010_0000), kernel));
        assert!(overlaps_kernel((0x0090_0000, 0x00ff_0000), kernel));
        // And one byte clear on either side is clear.
        assert!(!overlaps_kernel((0x0000_0000, 0x000f_ffff), kernel));
        assert!(!overlaps_kernel((0x0090_0001, 0x00ff_0000), kernel));
    }

    #[test]
    fn a_single_byte_region_is_handled_at_the_boundaries() {
        let kernel = (0x1000, 0x1fff);
        assert!(overlaps_kernel((0x1000, 0x1000), kernel));
        assert!(overlaps_kernel((0x1fff, 0x1fff), kernel));
        assert!(!overlaps_kernel((0x0fff, 0x0fff), kernel));
        assert!(!overlaps_kernel((0x2000, 0x2000), kernel));
    }

    #[test]
    fn zero_is_never_handed_out() {
        // An uninitialised descriptor holds zero. Keeping it unmapped means a
        // device that DMAs to an address nobody set faults with its own name
        // on the record, instead of reading the bottom of its window.
        let mut space = DevAddrSpace::new(AddressWidth::Bits39);
        for _ in 0..8 {
            let address = space.allocate(1, false).expect("room");
            assert_ne!(address.as_u64(), 0);
        }
        assert_ne!(space.allocate(1, true).expect("room").as_u64(), 0);
    }

    #[test]
    fn allocations_are_page_aligned_and_do_not_overlap() {
        let mut space = DevAddrSpace::new(AddressWidth::Bits39);
        let first = space.allocate(2, false).expect("room");
        let second = space.allocate(1, false).expect("room");

        assert_eq!(first.as_u64() % PAGE_SIZE, 0);
        assert_eq!(second.as_u64() % PAGE_SIZE, 0);
        assert!(second.as_u64() >= first.as_u64() + 2 * PAGE_SIZE);
    }

    #[test]
    fn a_32_bit_device_is_given_an_address_it_can_express() {
        // The RFC's answer to a 32-bit device is where the address comes from,
        // not a bounce buffer: no copy, and no second lifetime to track.
        let mut space = DevAddrSpace::new(AddressWidth::Bits39);
        let high = space.allocate(1, false).expect("room");
        let low = space.allocate(1, true).expect("room");

        assert!(low.as_u64() + PAGE_SIZE <= DevAddrSpace::LOW_LIMIT);
        assert!(high.as_u64() >= DevAddrSpace::LOW_LIMIT);
    }

    #[test]
    fn a_window_that_is_full_refuses_rather_than_wrapping() {
        let mut space = DevAddrSpace::new(AddressWidth::Bits30);
        let pages = (1u64 << 30) / PAGE_SIZE;

        // More than the whole window, in one request.
        assert_eq!(space.allocate(pages + 1, false), None);
        // And a request whose size overflows rather than one that is merely
        // large: an allocator that wrapped here would return a valid-looking
        // address for a mapping that runs off the end.
        assert_eq!(space.allocate(u64::MAX, false), None);
        assert_eq!(space.allocate(u64::MAX / PAGE_SIZE + 1, false), None);
        // Zero pages is not an address.
        assert_eq!(space.allocate(0, false), None);
    }

    #[test]
    fn the_low_region_is_exhausted_independently_of_the_window() {
        // A 39-bit window has 512 GiB, and a 32-bit device can reach 4 GiB of
        // it. Running out below the line must not be answered with an address
        // above it, which the device would truncate.
        let mut space = DevAddrSpace::new(AddressWidth::Bits39);
        let low_pages = DevAddrSpace::LOW_LIMIT / PAGE_SIZE;

        assert_eq!(
            space.allocate(low_pages, true),
            None,
            "one page is reserved"
        );
        let all_but_one = space.allocate(low_pages - 1, true).expect("the rest fits");
        assert_eq!(all_but_one.as_u64(), PAGE_SIZE);
        assert_eq!(space.allocate(1, true), None, "the low region is full");
        // The window itself still has room, and says so.
        assert!(space.allocate(1, false).is_some());
    }

    #[test]
    fn a_freed_extent_is_reused() {
        let mut space = DevAddrSpace::new(AddressWidth::Bits39);
        let first = space.allocate(4, false).expect("room");
        let _second = space.allocate(1, false).expect("room");

        space.free(first, 4);
        let again = space.allocate(4, false).expect("the freed extent");
        assert_eq!(again, first);
    }

    #[test]
    fn a_freed_extent_is_not_reused_for_a_request_that_does_not_fit_it() {
        // Splitting one leaves a remainder this fixed table cannot describe,
        // so an inexact match must come from the bump pointer instead of
        // silently handing back part of an extent and losing the rest.
        let mut space = DevAddrSpace::new(AddressWidth::Bits39);
        let first = space.allocate(4, false).expect("room");
        space.free(first, 4);

        let smaller = space.allocate(2, false).expect("room");
        assert_ne!(smaller, first);
        let larger = space.allocate(8, false).expect("room");
        assert_ne!(larger, first);
    }

    #[test]
    fn a_freed_high_extent_is_not_given_to_a_32_bit_device() {
        // The reuse path is the one that could hand a 39-bit address to a
        // device that can only express 32 of them.
        let mut space = DevAddrSpace::new(AddressWidth::Bits39);
        let high = space.allocate(1, false).expect("room");
        space.free(high, 1);

        let low = space.allocate(1, true).expect("room");
        assert_ne!(low, high);
        assert!(low.as_u64() + PAGE_SIZE <= DevAddrSpace::LOW_LIMIT);
    }

    #[test]
    fn forgetting_a_freed_extent_costs_address_space_and_nothing_else() {
        // The free list is fixed. Overflowing it must not corrupt anything or
        // hand the same address out twice -- it may only lose the reuse.
        let mut space = DevAddrSpace::new(AddressWidth::Bits39);
        let mut given = alloc::vec::Vec::new();
        for _ in 0..DevAddrSpace::FREE_SLOTS + 4 {
            given.push(space.allocate(1, false).expect("room"));
        }
        for address in &given {
            space.free(*address, 1);
        }

        let mut seen = alloc::vec::Vec::new();
        for _ in 0..DevAddrSpace::FREE_SLOTS + 8 {
            let address = space.allocate(1, false).expect("room");
            assert!(!seen.contains(&address), "{address:?} was handed out twice");
            seen.push(address);
        }
    }
}
