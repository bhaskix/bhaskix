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
use core::sync::atomic::AtomicBool;

use crate::sync::{Rank, SpinLock};

/// The one window, once it exists.
///
/// Global because revocation must reach it. RFC 0009's `revoke` walks an
/// object's mappings and removes them; step 5 makes a device window one of the
/// places an object can be mapped, so the revoke path needs the window without
/// having been handed it.
/// How many devices can have a translation of their own at once.
///
/// **Eight since 2026-08-23, and the paragraph above this line said "Two"
/// while the constant read four.** It had been raised twice without the
/// reasoning being brought along, which is how a bound stops recording the
/// decision that set it. What is true: every device doing DMA needs one, the
/// machine's `full` profile now fills four of them -- the kernel's disk, the
/// delegated disk, the network device and an xHCI controller (RFC 0041 step 3)
/// -- and a table with no free slot degrades by printing "no free slot" and
/// leaving a device untranslated. Eight is headroom for a second controller
/// and whatever the next driver is, at 32 bytes of static table per slot.
///
/// Sharing a window between devices was the tempting shortcut and would have
/// undone the thing RFC 0012 is for: two devices translating through one page
/// table can reach each other's buffers, so a driver in a domain would have
/// been contained from the kernel's memory and not from the kernel's *device*.
pub const MAX_WINDOWS: usize = 8;

/// Every device with a translation of its own, found by where it is on the bus.
///
/// Keyed by bus/device/function packed into a word, because that is what a
/// `DmaWindow` capability names: the authority is over one device's view of
/// memory, and a capability that named "the window" would name whichever one
/// happened to be first.
static WINDOWS: SpinLock<[Option<(u64, Report, Window)>; MAX_WINDOWS]> =
    SpinLock::new(Rank::DmaWindow, [const { None }; MAX_WINDOWS]);

/// Packs a device's bus address into the word a `DmaWindow` capability names.
#[must_use]
pub const fn device_key(device: (u8, u8, u8)) -> u64 {
    let (bus, slot, function) = device;
    ((bus as u64) << 16) | ((slot as u64) << 8) | (function as u64)
}

/// The unit's register window, mapped once.
///
/// Cached rather than mapped per use, and that is a locking decision rather
/// than a performance one: mapping MMIO reaches the heap, which is the
/// outermost lock here, and invalidating an IOTLB happens while holding the
/// innermost. Doing it per use would be an inversion on every unmap.
static UNIT_BASES: [core::sync::atomic::AtomicU64; bhaskix_arch::acpi::MAX_UNITS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; bhaskix_arch::acpi::MAX_UNITS];

/// How many of [`UNIT_BASES`] hold a unit this kernel programmed.
///
/// **This was one unit until RFC 0049.** The kernel programmed
/// `dmar.units().next()` and called it the IOMMU, which is right on a machine
/// that has one and silently wrong on a machine that has four: the devices
/// governed by every other unit were untranslated while being reported as
/// contained.
static UNITS_PROGRAMMED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// The register windows of every unit this kernel programmed.
///
/// Empty before [`enable`] runs, and after it fails.
fn programmed_units() -> impl Iterator<Item = u64> {
    let count = UNITS_PROGRAMMED.load(core::sync::atomic::Ordering::Acquire);
    UNIT_BASES
        .iter()
        .take(count)
        .map(|base| base.load(core::sync::atomic::Ordering::Acquire))
        .filter(|base| *base != 0)
}

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
    ///
    /// **The first, which is not necessarily the right one.** A platform may
    /// describe several units, each governing a different set of devices, and
    /// exactly one of them may carry `INCLUDE_PCI_ALL` for everything the
    /// others do not claim. This kernel programs `units[0]` and always has.
    /// On a machine with one unit — every emulator this has run on — that is
    /// correct by accident. See [`Report::unit_list`].
    pub first_register_base: u64,
    /// Every unit the firmware described: its register window, and whether it
    /// claims every device not claimed by another.
    ///
    /// Carried so the boot report can say how many units there are and which
    /// one is being programmed, rather than reporting a count and then
    /// silently acting on one of them.
    pub unit_list: [(u64, bool); bhaskix_arch::acpi::MAX_UNITS],
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

    let mut unit_list = [(0u64, false); bhaskix_arch::acpi::MAX_UNITS];
    for (slot, unit) in unit_list.iter_mut().zip(dmar.units()) {
        *slot = (unit.register_base, unit.covers_all);
    }

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
        unit_list,
    })
}

/// Prints what was found, or that nothing was.
///
/// Deliberately refuses to claim protection. A line that reported an IOMMU
/// without a qualifier would read, correctly and wrongly, as protection the
/// machine does not yet have: this runs before anything is programmed, and
/// every device still reaches all of memory.
///
/// # It used to say "not enabled", and that was a different wrong
///
/// The qualifier was right and the tense was not: printed once at discovery,
/// **it says "not enabled" on every machine including the ones where
/// translation is enabled four lines later.** On 2026-08-24 it was read off an
/// SR550 as the answer to *"did the units come up?"* — by the person who had
/// just changed the code to make them come up — and it is not that answer. It
/// is not any answer; it is a fixed string.
///
/// So it now points at the line that *is* the verdict. [`report_dma`] prints
/// exactly one of `translating:` or `NO IOMMU:` after bring-up has either
/// succeeded or returned, and that is the line to read.
pub fn report(found: Option<Report>) {
    match found {
        Some(report) if report.units > 0 => {
            println!(
                "    iommu          {} unit{} found, none programmed yet (the dma line below \
                 is the verdict); {}-bit addresses, {} reserved region{}, interrupt remapping {}",
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
            // **Every unit the firmware named.** A count alone reads as "the
            // IOMMU was found" and says nothing about how many units there
            // are or what each claims. This runs before anything is
            // programmed, so it deliberately does **not** say which are: that
            // is `enable`'s outcome to report, and a line here claiming it in
            // advance was wrong for exactly one commit.
            for (index, (base, covers_all)) in
                report.unit_list.iter().take(report.units).enumerate()
            {
                println!(
                    "    iommu unit {index}   registers at {base:#x}, {}",
                    if *covers_all {
                        "claims every device not claimed by another"
                    } else {
                        "claims only the devices its scope names"
                    },
                );
            }

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

        // A freed extent of exactly this size is reused, and the proof that
        // makes that safe is `iommu_reuse_self_test`: a device address is
        // mapped, written through, unmapped with an invalidation, handed out
        // again to a *different* object, and written through again — and the
        // first object's page is checked to be untouched. That last check is
        // the whole thing, because a stale translation writes to the old page
        // and reports nothing.
        //
        // Reuse was disabled from M6-13 until 2026-08-11 because that proof
        // was missing and the fault had been seen once. It is exact-size only:
        // splitting an extent means tracking remainders, and the window has
        // 512 GiB, so the addresses a partial match would recover are not
        // worth the bookkeeping.
        for slot in &mut self.freed {
            if let Some((address, extent)) = *slot
                && extent == bytes
                && (address < Self::LOW_LIMIT) == below_4gib
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
    /// The domain id in this device's context entry.
    ///
    /// Kept because the verifier has to expect the right one, and because two
    /// devices sharing a domain id are entitled to share IOTLB entries —
    /// which would make two separate page tables one cache, and undo the
    /// separation they exist for.
    pub domain: u16,
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
/// What a survey of the bus found: functions, and how many this kernel drives.
///
/// RFC 0043 step 2.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Survey {
    /// Functions seen at all.
    pub functions: usize,
    /// Of them, ones this kernel has a driver for and can give a window to.
    pub drivable: usize,
    /// Of them, endpoints this kernel cannot describe.
    ///
    /// **The number that decides whether translation may be turned on**, and
    /// the reason RFC 0043 exists: a device in here reaches all of memory today
    /// and would be refused outright the moment a unit is programmed without a
    /// window for it.
    pub unknown: usize,
    /// Of them, bridges — not endpoints, and not bus masters of their own.
    ///
    /// Counted apart because counting them as unknown overstates the problem:
    /// the first version of this did, and reported five undescribable bus
    /// masters on a QEMU machine whose bus masters are all describable.
    pub bridges: usize,
}

/// PCI class for a bridge: not an endpoint, and not a bus master of its own.
const CLASS_BRIDGE: u8 = 0x06;

/// Whether this kernel has a driver that would claim this function.
///
/// The list is short and that is the point: virtio block, virtio net, xHCI, and
/// — since RFC 0046 — a SATA controller presenting AHCI's registers. Everything
/// else on a real machine — SAS, NVMe, a management NIC, a graphics adapter —
/// is a bus master with no driver here and no window to give it.
///
/// **The programming interface is part of the answer, and it was not until
/// 2026-08-24.** This took an `Identity` alone and answered *yes* for any USB
/// controller, on the reasoning that "could this kernel contain it" was a
/// question the class settled. It is not: a UHCI or EHCI controller is a USB
/// controller this kernel has no driver for, and counting it as drivable
/// understated exactly the number RFC 0043's survey exists to report. No lane
/// in this tree has one, so no count printed here has ever been wrong — which
/// is why it survived, and is not a reason to leave it.
#[must_use]
fn drivable(identity: &bhaskix_arch::pci::Identity, prog_if: u8) -> bool {
    // Class 0x0c subclass 0x03 is USB; the programming interface separates xHCI
    // from its predecessors, and `xhci::discover` checks the same byte before
    // it will drive one.
    let usb = identity.class == 0x0c && identity.subclass == 0x03 && prog_if == 0x30;
    // And `ahci::classify` is the one that decides for storage, called here so
    // that the survey and the driver cannot disagree about which controller has
    // a driver -- a report whose two halves contradict each other is worse than
    // either half alone.
    let ahci = crate::ahci::classify(identity.class, identity.subclass, prog_if)
        == crate::ahci::Kind::Ahci;
    let virtio = identity.vendor == 0x1af4;
    usb || ahci || virtio
}

/// Devices this project intends to **contain**, whether or not it drives them.
///
/// **Deliberately wider than [`drivable`], and used only by the pass-through
/// decision.** `drivable` answers "is there a driver for this", which is what
/// [`survey`] must keep counting and what keeps the survey and the drivers from
/// disagreeing. This answers a different question: should the device be given a
/// translated domain rather than untranslated DMA.
///
/// Containing a device nobody drives is **strictly safer than passing it
/// through**. A translated domain with no mappings lets the device reach
/// nothing; pass-through lets it reach everything. The only reason to pass a
/// device through at all is that firmware may still be using it, and that
/// argument does not apply to a device this project is about to take.
///
/// RFC 0072 step 2 found this the hard way: the X722 was passed through because
/// no driver existed, so `present_for` answered no and the containment step
/// could not succeed before the driver step. The dependency ran backwards.
///
/// Named by exact identifier and not by family. `8086:37d1` is what the SR550
/// reports for all four of its ports, measured in step 1; the other i40e
/// identifiers are not something to write down from memory, and a wrong one here
/// would silently contain the wrong device or fail to contain the right one.
fn claimed(identity: &bhaskix_arch::pci::Identity) -> bool {
    identity.vendor == 0x8086 && identity.device == 0x37d1
}

/// Walks the bus and says what is on it.
///
/// **Reporting only — this changes nothing.** RFC 0043's question is whether
/// translation may be enabled on a machine holding devices this kernel cannot
/// contain, and that question could not even be *asked* before, because nothing
/// counted them. It is asked on every boot now, including every QEMU boot, so
/// the answer for a real machine is not a surprise the first time one is seen.
///
/// # Safety
///
/// Configuration access must work, as [`crate::xhci::discover`].
pub unsafe fn survey() -> Survey {
    let mut survey = Survey::default();
    let mut visit = |address: bhaskix_arch::pci::Address, identity: bhaskix_arch::pci::Identity| {
        survey.functions += 1;
        // SAFETY: one byte of configuration space, at a fixed offset, on a
        // function `for_each` has already found present.
        let prog_if =
            unsafe { bhaskix_arch::pci::read8(address, bhaskix_arch::pci::PROG_IF_OFFSET) };
        if drivable(&identity, prog_if) {
            survey.drivable += 1;
        } else if identity.class == CLASS_BRIDGE {
            survey.bridges += 1;
        } else {
            survey.unknown += 1;
            // **Named, not just counted.** RFC 0043's report has to say which
            // device would stop translation coming up; a number cannot, and
            // somebody reading it on a machine that will contain nothing needs
            // to know what to go and look at.
            crate::println!(
                "      dma unknown  {:02x}:{:02x}.{} {:04x}:{:04x} class {:02x}.{:02x} -- no \
                 driver here, so no window",
                address.bus,
                address.device,
                address.function,
                identity.vendor,
                identity.device,
                identity.class,
                identity.subclass
            );
        }
        true
    };
    // SAFETY: the caller's obligation; `for_each` reads configuration space
    // only.
    unsafe { bhaskix_arch::pci::for_each(&mut visit) };
    survey
}

/// A unit's own tables: the root table, and the context table for bus zero.
///
/// **The root table belongs to the machine, not to a device.** It was allocated
/// inside [`build_window`] until 2026-08-23, which made turning translation on
/// something that could only happen if a particular device existed — and on a
/// machine with no virtio device, nothing happened at all. RFC 0043 separates
/// the two: this is the unit's half, and [`attach_device`] is the device's.
///
/// Every context entry is absent until something is attached, which means every
/// device is **refused** if translation is enabled over these tables alone. That
/// is why building them is not the same as enabling, and why RFC 0043 spends
/// most of its length on when it is safe to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tables {
    /// Physical address of the root table.
    ///
    /// **One root table, and a context table per bus reached through it.** The
    /// root table has an entry per bus (VT-d rev 5.20 §9.1) and each points at
    /// that bus's own 256-entry context table; [`context_table_for`] allocates
    /// them as buses are first seen, so a machine with one bus pays for one.
    pub root_table: u64,
    /// How many address bits the unit translates.
    pub width: bhaskix_arch::vtd::AddressWidth,
}

/// Allocates a unit's root table, empty.
///
/// Context tables are **not** allocated here: there is one per bus and they are
/// built as buses are first seen. This held a single `context_table` until
/// 2026-08-24, which was correct only because every device on every machine
/// this had run on was on bus 0 -- see [`context_table_for`].
///
/// `None` if there are no frames, or if the hardware reported an address width
/// this kernel cannot describe. Both are refusals rather than defaults: tables
/// built to the wrong width are tables the hardware walks to the wrong depth.
#[must_use]
pub fn build_tables(report: &Report, hhdm: u64) -> Option<Tables> {
    // SAFETY: the unit the `DMAR` named; mapping it and reading one register.
    let width = unsafe { widest_supported(report, hhdm) }?;
    let (root_table, _) = zeroed_frame(hhdm)?;
    Some(Tables { root_table, width })
}

/// The widest translation width **the unit says it can walk**.
///
/// # Why this is not the `DMAR`'s host address width
///
/// It was, until 2026-08-24, and on an SR550 that was the difference between
/// containment and none. Two different numbers describe two different things:
///
/// - **MGAW / host address width**, from the `DMAR` table, is how many address
///   bits the *hardware can generate*.
/// - **`SAGAW`**, a bitmap in the unit's capability register, is which
///   page-table depths the unit *will walk*.
///
/// `AddressWidth::fitting` picked from the first. The SR550 reports **46-bit
/// addresses**, so it chose 39-bit — the widest encoding no wider than 46 — and
/// its units do not offer 39-bit at all. `enable` then refused, correctly, with
/// *"the unit does not support the width the tables were built to"*, and the
/// machine ran with four working remapping units and nothing programmed.
///
/// The specification is explicit about which of the two governs: *"The value
/// specified in this field must match an AGAW value supported by hardware (as
/// reported in the SAGAW field in the Capability Register)"* (VT-d rev 5.20
/// §9.3, of a context entry's `AW`). So the tables are built to a width the
/// unit offers, and `None` — a refusal — if it offers none this kernel can
/// describe.
///
/// QEMU's unit reports `SAGAW` `0b00010`: 39-bit only, which is what
/// `fitting(39)` also chose, which is why no emulator boot could have found
/// this.
///
/// # Safety
///
/// The `DMAR` must name a real remapping unit at `report.first_register_base`.
unsafe fn widest_supported(report: &Report, hhdm: u64) -> Option<bhaskix_arch::vtd::AddressWidth> {
    // **The narrowest of what every unit supports**, because RFC 0049 gives
    // them all the same root table and a unit asked to walk tables built to a
    // depth it does not support refuses -- and a refusal is a set of devices
    // nobody translates. Taking the first unit's answer would build tables
    // that unit alone can read.
    //
    // A unit whose registers will not map is skipped rather than treated as
    // supporting nothing: `enable` will refuse it by name, and letting it
    // narrow the tables here would degrade every other unit's translation on
    // account of a unit that is not going to be used.
    let mut narrowest: Option<bhaskix_arch::vtd::AddressWidth> = None;
    for (register_base, _) in report.unit_list.iter().take(report.units) {
        let Some(base) = crate::mmio::map(*register_base, bhaskix_mm::FRAME_SIZE, hhdm) else {
            continue;
        };
        // SAFETY: the caller's obligation; this reads one register and
        // programs nothing.
        let Some(width) = (unsafe {
            let unit = bhaskix_arch::vtd::Unit::new(base as *mut u8);
            unit.largest_width()
        }) else {
            continue;
        };
        narrowest = Some(match narrowest {
            Some(sofar) if sofar.levels() <= width.levels() => sofar,
            _ => width,
        });
    }
    narrowest
}

/// The context table for `bus`, allocating and installing one the first time
/// that bus is seen.
///
/// # Why this exists, and what it was before
///
/// **A context entry is selected by `(device << 3) | function` alone** -- eight
/// bits, unique within a bus and *not* across buses. The bus is selected one
/// level up, by the root entry. Until 2026-08-24 this kernel allocated **one**
/// context table and pointed every bus's root entry at it, so `00:11.5` and
/// `b1:11.5` would have indexed the same entry and the second written would
/// have replaced the first.
///
/// That was invisible because every device on every machine this had ever run
/// on was on bus 0. The SR550 has 115 functions across buses `00`, `b1`, `ae`
/// and more, and [RFC 0043] step 4 gives an entry to every endpoint it cannot
/// drive -- so the first multi-bus machine would have been the first collision,
/// and a collision that replaced a *translating* entry with a pass-through one
/// would have silently un-contained the device, with nothing to report it.
///
/// Found by reading before booting that machine rather than by booting it.
fn context_table_for(tables: &Tables, bus: u8, hhdm: u64) -> Option<u64> {
    use bhaskix_arch::vtd;

    // SAFETY: the root table this module allocated and never frees, reached
    // through the direct map; a root index is a byte, so it cannot leave the
    // page.
    let entry = unsafe { ((hhdm + tables.root_table) as *mut u64).add(vtd::root_index(bus) * 2) };
    // SAFETY: as above.
    let present = unsafe { core::ptr::read_volatile(entry) };
    if present & 1 != 0 {
        return Some(present & !(vtd::PAGE_SIZE - 1));
    }
    let (context_table, _) = zeroed_frame(hhdm)?;
    let (low, high) = vtd::RootEntry { context_table }.to_bits();
    // SAFETY: as above, and the table was just allocated and zeroed.
    unsafe {
        core::ptr::write_volatile(entry, low);
        core::ptr::write_volatile(entry.add(1), high);
    }
    Some(context_table)
}

/// Gives `device` a page table of its own, reached through `tables`.
///
/// The one place a context entry is written. Both [`build_window`] and
/// [`attach_device`] are this function with their tables found differently,
/// which is what makes "the first device" no longer a special case.
///
/// `domain` must differ from every other device's, or the hardware is entitled
/// to share IOTLB entries between them.
#[must_use]
pub fn attach_to(tables: &Tables, device: (u8, u8, u8), domain: u16, hhdm: u64) -> Option<Window> {
    use bhaskix_arch::vtd;

    let (page_table, _) = zeroed_frame(hhdm)?;
    let (bus, slot, function) = device;
    // This bus's own table, allocated and installed the first time the bus is
    // seen. The root entry is written there rather than here.
    let context_table = context_table_for(tables, bus, hhdm)?;

    let context = vtd::ContextEntry {
        translation: vtd::Translation::SecondStage { page_table },
        width: tables.width,
        domain,
    };
    let (context_low, context_high) = context.to_bits();

    // SAFETY: a table this module allocated and never frees, reached through
    // the direct map; a context index is masked to eight bits, so it cannot
    // leave its page. Written as two 64-bit words, the layout the hardware
    // reads.
    unsafe {
        let context_entry =
            ((hhdm + context_table) as *mut u64).add(vtd::context_index(slot, function) * 2);
        core::ptr::write_volatile(context_entry, context_low);
        core::ptr::write_volatile(context_entry.add(1), context_high);
    }

    Some(Window {
        root_table: tables.root_table,
        context_table,
        page_table,
        width: tables.width,
        domain,
        device,
        addresses: DevAddrSpace::new(tables.width),
    })
}

/// Passes every undrivable endpoint through, or says why it could not.
///
/// **Split out of [`enable`] so that its reasoning -- and its comments -- sit
/// in safe code.** The budget check counts every line inside an `unsafe` block,
/// and the argument below is thirty lines of prose that perform no unsafe
/// operation. Putting them there would have charged them to the number
/// `coding-style.md` §3 exists to keep meaningful.
///
/// Until 2026-08-24 an endpoint this kernel cannot drive had no context entry,
/// so the moment translation came on its DMA was refused. That survives on QEMU
/// because the endpoints there are idle -- a display adapter and an SMBus this
/// kernel never touches. On a real server the boot device is one of them and is
/// not idle, which is why translation has never been enabled on the SR550:
/// four working units, all off.
///
/// **This is not containment for those devices and is never reported as if it
/// were.** They reach all of memory, exactly as with no unit at all. What it
/// buys is that the unit can be *enabled*, so the devices that do have drivers
/// are contained -- on real hardware, the difference between some containment
/// and none.
fn pass_through_or_say_why(
    unit: (bool, Option<bhaskix_arch::vtd::AddressWidth>),
    window: &Window,
    hhdm: u64,
) {
    let tables = Tables {
        root_table: window.root_table,
        width: window.width,
    };
    match unit {
        (true, Some(widest)) => {
            // SAFETY: configuration access works by here, and these are this
            // kernel's tables with nothing else programming them. `enable` has
            // not yet turned translation on, which is this call's whole point.
            let passed = unsafe { pass_through_undrivable(&tables, widest, hhdm) };
            if passed.failed != 0 {
                crate::println!(
                    "\x1b[91m    dma untranslated FAILED: {} endpoint(s) could not be passed \
                     through\x1b[0m",
                    passed.failed
                );
            }
        }
        (supported, widest) => {
            // Said, rather than fallen back into silently. Absent entries are
            // this kernel's old behaviour: safe here, and fatal on a machine
            // that boots from a device it cannot drive.
            crate::println!(
                "\x1b[93m    dma untranslated the unit cannot pass devices through (ECAP.PT {}, \
                 widest {:?}); undrivable endpoints stay absent and their DMA is refused\x1b[0m",
                u8::from(supported),
                widest
            );
        }
    }
}

/// Says *which* widths disagreed when a unit refuses the tables' width.
///
/// **Both numbers, not just the verdict.** The refusal said only *"the unit
/// does not support the width the tables were built to"* until 2026-08-24, and
/// on a real server that is a sentence with no next step in it: the reader
/// cannot tell whether the tables are too wide, too narrow, or the unit claims
/// nothing at all. A refusal that cannot be acted on is one somebody re-runs
/// the boot to understand — and on a live cluster node that is a reboot per
/// question.
///
/// The widths come from `SAGAW`, which is the field the specification says the
/// tables' width must match: *"The value specified in this field must match an
/// AGAW value supported by hardware (as reported in the SAGAW field in the
/// Capability Register)."* `build_tables` chooses from the `DMAR`'s host
/// address width instead, which is a different number and is why this refusal
/// can fire at all.
fn report_width_refusal(
    built: bhaskix_arch::vtd::AddressWidth,
    sagaw: u64,
    widest: Option<bhaskix_arch::vtd::AddressWidth>,
) {
    crate::println!(
        "\x1b[91m    iommu enable   the tables are {}-bit; this unit's SAGAW is {:#07b}, widest \
         supported {:?}\x1b[0m",
        built.bits(),
        sagaw,
        widest
    );
}

/// Endpoints given a pass-through entry, **per bus**, for [`verify_window`].
///
/// One counter per bus rather than one for the machine, and the distinction is
/// not academic. `verify_window` counts the present entries in **one bus's**
/// context table; a machine-wide total is only equal to that when every device
/// is on one bus. QEMU is such a machine and the SR550 is not: it passed 105
/// endpoints through across seven buses, and the xHCI's window then failed to
/// verify because the expected count included pass-through entries living in
/// six other tables. The check was right and the arithmetic was wrong.
static PASSED_THROUGH: [core::sync::atomic::AtomicUsize; 256] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; 256];

/// The domain every passed-through device shares.
///
/// One rather than one each: VT-d rev 5.20 §9.3 requires context entries with
/// the same domain id to reference the same address translation, and
/// pass-through entries all reference *none*, so they agree trivially. Clear of
/// 0..=4, which the translating windows use, and non-zero because the
/// specification reserves domain id zero on any unit reporting Caching Mode.
pub const PASS_THROUGH_DOMAIN: u16 = 15;

/// What [`pass_through_undrivable`] did, for the report.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct PassedThrough {
    /// Endpoints given a pass-through entry.
    pub passed: usize,
    /// Endpoints that needed one and could not be written.
    pub failed: usize,
}

/// Gives every endpoint this kernel cannot drive a pass-through entry.
///
/// **RFC 0043 step 4, and the reason translation can be enabled on a real
/// machine at all.** Walks the bus with the *same* predicate the survey uses --
/// [`drivable`] and [`CLASS_BRIDGE`] -- so the count a boot reports and the set
/// of devices actually passed through cannot disagree. Bridges are skipped:
/// they are not endpoints, and requester-id rewriting behind one is RFC 0043's
/// unresolved question 2, which no machine here can yet exercise.
///
/// Must run **before** the unit is enabled. Afterwards is a device whose first
/// transaction faults, which on a boot device is the machine.
///
/// # Safety
///
/// Configuration access must work, and `tables` must be this kernel's, with
/// nothing else programming them.
pub unsafe fn pass_through_undrivable(
    tables: &Tables,
    widest: bhaskix_arch::vtd::AddressWidth,
    hhdm: u64,
) -> PassedThrough {
    let mut result = PassedThrough::default();
    let mut visit = |address: bhaskix_arch::pci::Address, identity: bhaskix_arch::pci::Identity| {
        // SAFETY: one byte of configuration space at a fixed offset, on a
        // function `for_each` has already found present.
        let prog_if =
            unsafe { bhaskix_arch::pci::read8(address, bhaskix_arch::pci::PROG_IF_OFFSET) };
        if drivable(&identity, prog_if) || claimed(&identity) || identity.class == CLASS_BRIDGE {
            return true;
        }
        let device = (address.bus, address.device, address.function);
        if pass_through_to(tables, device, PASS_THROUGH_DOMAIN, widest, hhdm) {
            result.passed += 1;
            PASSED_THROUGH[device.0 as usize].fetch_add(1, core::sync::atomic::Ordering::AcqRel);
            crate::println!(
                "    dma untranslated {:02x}:{:02x}.{} {:04x}:{:04x} passed through deliberately -- it reaches all of memory, and is not contained",
                device.0,
                device.1,
                device.2,
                identity.vendor,
                identity.device
            );
        } else {
            result.failed += 1;
        }
        true
    };
    // SAFETY: the caller's obligation.
    unsafe { bhaskix_arch::pci::for_each(&mut visit) };
    result
}

/// Writes a **pass-through** context entry: this device is not translated.
///
/// The one place an *untranslated* entry is written, as [`attach_to`] is the
/// one place a translating one is. [RFC 0043]'s answer to what an endpoint this
/// kernel has no driver for should get, chosen by the project lead on
/// 2026-08-24 over *absent* (which refuses its DMA, and on a real server's boot
/// device is a dead machine) and over *identity-mapped* (which reaches the same
/// memory and costs a page table over all of RAM -- 402 MB per device on the
/// SR550).
///
/// **This is not containment and must never be reported as containment.** The
/// device reaches all of memory, exactly as it would with no unit at all. What
/// it buys is that the unit can be *enabled*, so the devices that do have
/// drivers are contained -- which on real hardware is the difference between
/// some containment and none.
///
/// # Two obligations from the specification, both easy to miss
///
/// **No page table is allocated.** VT-d rev 5.20 §9.3: `SSPTPTR` is *"ignored
/// by hardware when Translation-Type (TT) field is 10b"*. Allocating one would
/// be a frame per undrivable device that nothing ever reads.
///
/// **`AW` is the unit's widest, not the tables' width**: *"When the
/// Translation-type (TT) field indicates pass-through processing (10b), this
/// field must be programmed to indicate the largest AGAW value supported by
/// hardware."* The caller passes it, from `Unit::largest_width`.
///
/// `None` if the root entry could not be written. The caller must have checked
/// `Unit::supports_pass_through` first: with `ECAP.PT` clear this encoding is
/// *reserved*, and a reserved context entry is not a device that works.
pub fn pass_through_to(
    tables: &Tables,
    device: (u8, u8, u8),
    domain: u16,
    widest: bhaskix_arch::vtd::AddressWidth,
    hhdm: u64,
) -> bool {
    use bhaskix_arch::vtd;

    let (bus, slot, function) = device;
    // This device's own bus's table -- **the reason this function is safe on a
    // machine with more than one bus.** Sharing one across buses would let two
    // devices with the same `(device, function)` index the same entry.
    let Some(context_table) = context_table_for(tables, bus, hhdm) else {
        return false;
    };
    let context = vtd::ContextEntry {
        translation: vtd::Translation::PassThrough,
        width: widest,
        domain,
    };
    let (context_low, context_high) = context.to_bits();

    // SAFETY: a table this module allocated and never frees, reached through
    // the direct map; a context index is masked to eight bits, so it cannot
    // leave its page.
    unsafe {
        let context_entry =
            ((hhdm + context_table) as *mut u64).add(vtd::context_index(slot, function) * 2);
        core::ptr::write_volatile(context_entry, context_low);
        core::ptr::write_volatile(context_entry.add(1), context_high);
    }
    true
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
    // **The unit's tables, then one device in them** -- which is all this ever
    // did, written as the two things it is since RFC 0043. The allocation order
    // is unchanged (root, context, page), so a machine that built a window
    // before this split builds the identical one after it.
    let tables = build_tables(report, hhdm)?;
    attach_to(&tables, device, domain, hhdm)
}

/// Gives a second device a translation of its own, under the same unit.
///
/// The unit has one root table, so a second device cannot have a second
/// `build_window`: enabling that would point the hardware at the new root and
/// the first device would stop translating. What it gets instead is its own
/// **page table**, reached through its own context entry in the tables that
/// already exist.
///
/// That is the difference between two devices being isolated and two devices
/// merely being translated: sharing a page table would let each reach whatever
/// the other had mapped, which is most of what RFC 0012 is for.
///
/// `domain` must differ from every other device's, or the hardware is entitled
/// to share IOTLB entries between them.
#[must_use]
pub fn attach_device(
    existing: &Window,
    device: (u8, u8, u8),
    domain: u16,
    hhdm: u64,
) -> Option<Window> {
    // The same tables the installed window is reached through. Writing the root
    // entry again with the same context table is harmless; writing it with a
    // *different* one would not be, which is why the tables come from the window
    // that is already installed rather than from a fresh allocation.
    attach_to(&existing.tables(), device, domain, hhdm)
}

impl Window {
    /// The unit's tables this window is reached through.
    ///
    /// A window is one device's page table plus the machine's root and context
    /// tables; this is the second half, which every other device on the same
    /// unit shares.
    #[must_use]
    pub const fn tables(&self) -> Tables {
        Tables {
            root_table: self.root_table,
            width: self.width,
        }
    }
}

/// Reads a window's own entries back and checks they say what was written.
///
/// Not paranoia about the writes: it is the only check that the *indices* were
/// right. An entry written at the wrong offset is a device whose translation
/// silently uses another device's tables, and every value in it would still be
/// correct.
#[must_use]
pub fn verify_window(window: &Window, devices: usize, hhdm: u64) -> bool {
    use bhaskix_arch::vtd;

    let (bus, slot, function) = window.device;
    let expected_root = vtd::RootEntry {
        context_table: window.context_table,
    }
    .to_bits();
    let expected_context = vtd::ContextEntry {
        translation: vtd::Translation::SecondStage {
            page_table: window.page_table,
        },
        width: window.width,
        // From the window rather than a constant. It was zero here, which was
        // true of the only window there was and became a false expectation the
        // moment a second device was given a domain of its own.
        domain: window.domain,
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

        // And exactly as many context entries are present as there are
        // devices attached to this table. An entry written at the wrong offset
        // leaves the right one absent -- caught above -- and a stray one
        // behind, which is a device this table would translate for without
        // anyone asking.
        //
        // The count was `== 1` while there was one device, which is the same
        // property and a different number. It stopped being true the moment a
        // second device was attached, and said so.
        let context = (hhdm + window.context_table) as *const u64;
        let mut present = 0;
        for index in 0..256 {
            if core::ptr::read_volatile(context.add(index * 2)) & 1 != 0 {
                present += 1;
            }
        }
        // `+ passed_through(bus)`: those entries are present and deliberate, and
        // the count is **this bus's** -- the table being counted holds only its
        // own bus's devices. The invariant is unweakened: a stray entry still
        // breaks it, because the pass-through count is tracked rather than
        // assumed.
        present == devices + passed_through(bus)
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
pub fn install(device: (u8, u8, u8), report: Report, window: Window) -> bool {
    let key = device_key(device);
    let mut windows = WINDOWS.lock();
    // Replace an entry for the same device before taking a free slot: two
    // entries for one device would make which page table answers a mapping
    // depend on search order.
    let slot = windows
        .iter()
        .position(|held| held.as_ref().is_some_and(|(held, ..)| *held == key))
        .or_else(|| windows.iter().position(Option::is_none));
    if let Some(slot) = slot {
        windows[slot] = Some((key, report, window));
        true
    } else {
        // Returned rather than only printed, and that is a correction. This
        // said so on the console and told its caller nothing, so a caller that
        // went on to announce the device was translating did exactly that with
        // the refusal one line above it — which is what a third device on a
        // two-slot table produced the first time one was added.
        crate::println!("    iommu window   no free slot; this device will not translate");
        false
    }
}

/// Whether a window exists to map into.
#[must_use]
pub fn present() -> bool {
    WINDOWS.lock().iter().flatten().count() > 0
}

/// Whether `device` has a translation of its own.
#[must_use]
pub fn present_for(device: (u8, u8, u8)) -> bool {
    let key = device_key(device);
    WINDOWS
        .lock()
        .iter()
        .flatten()
        .any(|(held, ..)| *held == key)
}

/// How many endpoints on `bus` were passed through -- present in that bus's
/// context table, and deliberately not translated.
///
/// [`verify_window`] needs this: its invariant is that the number of *present*
/// context entries equals the number of devices attached, which is what catches
/// an entry written at the wrong offset. A pass-through entry is present too,
/// so without this the check would read every one of them as a stray -- and it
/// did, the first time this was wired up, which is the check working.
#[must_use]
pub fn passed_through(bus: u8) -> usize {
    PASSED_THROUGH[bus as usize].load(core::sync::atomic::Ordering::Acquire)
}

/// How many devices are translating **on one bus**.
///
/// **[`verify_window`] needs this and was given the global count.** Its
/// invariant compares context entries *present in one bus's table* against the
/// devices attached to it, and `passed_through` is already per-bus for exactly
/// that reason -- but every caller passed `windows() + 1`, which counts every
/// bus. That was correct only because every device this project drove lived on
/// bus `00`, where the two numbers are equal.
///
/// RFC 0072 step 2 attached a NIC on bus `b1` and the check failed: one entry
/// present on that bus, against a global count that already included the AHCI
/// controller's window on bus `00`. The window was correct and the verification
/// was wrong, which is the worse way round -- a check that rejects good work
/// teaches people to remove the check.
#[must_use]
pub fn windows_on(bus: u8) -> usize {
    WINDOWS
        .lock()
        .iter()
        .flatten()
        .filter(|(held, ..)| (*held >> 16) as u8 == bus)
        .count()
}

/// How many devices are translating.
#[must_use]
pub fn windows() -> usize {
    WINDOWS.lock().iter().flatten().count()
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
    device: (u8, u8, u8),
    id: crate::shared::MemoryId,
    rights: vtd::Rights,
    below_4gib: bool,
    hhdm: u64,
    mapper: u32,
) -> Option<DevAddr> {
    let (frames, count) = crate::shared::frames_of(id)?;
    if count == 0 {
        return None;
    }

    let key = device_key(device);
    let mut guard = WINDOWS.lock();
    let (_, _, window) = guard.iter_mut().flatten().find(|(held, ..)| *held == key)?;

    // The object's frames need not be contiguous in physical memory, and the
    // device needs them contiguous in *its* address space -- which is most of
    // what an IOMMU is for. So the address is allocated once and each frame is
    // placed at its own offset within it.
    let address = window.addresses.allocate(count as u64, below_4gib)?;
    for (page, frame) in frames.iter().take(count).enumerate() {
        let at = address.as_u64() + (page as u64) * vtd::PAGE_SIZE;
        // `frames_of` yields physical *addresses*, not frame numbers --
        // `shared::allocate_frame` multiplies by the frame size before storing
        // them. Multiplying again produced entries pointing 4096 times too
        // high, which the hardware refused as reserved bits when the result
        // overflowed the window's width and silently dropped when it did not.
        let physical = *frame;
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

    MAPPED.fetch_add(count as u64, core::sync::atomic::Ordering::Relaxed);

    if !crate::shared::record_device_mapping(id, key, address.as_u64(), count as u64, mapper) {
        // Recorded or not mapped. An object whose device mapping is not
        // written down is one revocation cannot find, which is a page a device
        // keeps after the object naming it is destroyed.
        unmap_device(device, address.as_u64(), count as u64);
        return None;
    }
    Some(address)
}

/// Removes a device mapping recorded against a `Memory` object.
///
/// Called by RFC 0009's `revoke`. Invalidates before returning, for the same
/// reason `unmap` does: until the IOTLB is invalidated the device still
/// reaches the page that has just been taken away from it.
pub fn unmap_device(device: (u8, u8, u8), address: u64, pages: u64) -> bool {
    let key = device_key(device);
    let mut guard = WINDOWS.lock();
    let Some((_, _, window)) = guard.iter_mut().flatten().find(|(held, ..)| *held == key) else {
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
    MAPPED.fetch_sub(
        pages.min(MAPPED.load(core::sync::atomic::Ordering::Relaxed)),
        core::sync::atomic::Ordering::Relaxed,
    );
    drop(guard);

    // SAFETY: the unit `enable` programmed and whose registers it cached.
    //
    // Load-bearing, and measured: with this invalidation removed,
    // `iommu_reuse_self_test` fails exactly as M6-13 recorded the fault --
    // the new object's read never arrives, the *old* object's page is written
    // through an address it no longer owns, and no fault is raised.
    unsafe { invalidate() }
}

/// The interrupt remapping table, and how much of it has been issued.
///
/// One table for the machine, because there is one unit. Handles are issued in
/// order and never reused: a handle that was recycled would be a device
/// raising an interrupt that now belongs to something else, which is the exact
/// forgery this table exists to stop.
static IRT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static NEXT_HANDLE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static REMAPPING: AtomicBool = AtomicBool::new(false);

/// The invalidation queue, and the word the unit writes when it has drained.
///
/// Both physical, because both are reached by rebuilding a [`vtd::Unit`] around
/// [`UNIT_BASE`] wherever an invalidation is needed, and a rebuilt unit
/// remembers nothing. Zero means the queue was never enabled, which is the
/// ordinary case: it goes on only with interrupt remapping.
///
/// The status word costs a frame to hold four bytes. The queue is one page and
/// the format's smallest size fills it, so there is no room inside it for a
/// word the unit writes *after* the descriptors it is reporting on.
static IQ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static IQ_STATUS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Invalidates through the queue, if the unit is taking invalidations that way.
///
/// `None` when it is not, which leaves the caller to use the registers. The
/// split is the whole point: **once `QIE` is set the unit ignores the
/// invalidation registers and says nothing** — the command bit clears, the
/// poll succeeds, and the cache is untouched. A kernel that enabled the queue
/// for interrupt remapping and went on writing registers would believe it was
/// invalidating and would not be.
///
/// # Safety
///
/// The unit must be the one this kernel programmed.
unsafe fn queued(unit: &vtd::Unit, descriptors: &[[u64; 2]]) -> Option<bool> {
    // SAFETY: the caller's obligation.
    if !unsafe { unit.queued_invalidation_enabled() } {
        return None;
    }
    let queue = IQ.load(core::sync::atomic::Ordering::Acquire);
    let status = IQ_STATUS.load(core::sync::atomic::Ordering::Acquire);
    if queue == 0 || status == 0 {
        // The unit says the queue is on and this kernel does not know where it
        // is, so there is no way to invalidate anything. Reported as a failure
        // rather than falling back to registers the unit is ignoring.
        return Some(false);
    }

    let hhdm = crate::shared::hhdm();
    // SAFETY: frames this module allocated and zeroed for exactly this, mapped
    // through the direct map, and handed to the unit in `IQA`.
    Some(unsafe {
        unit.queued_invalidate(
            (hhdm + queue) as *mut u64,
            (hhdm + status) as *mut u32,
            status,
            descriptors,
        )
    })
}

/// Whether interrupts are being remapped.
///
/// Every interrupt this kernel programs asks first: in remappable format the
/// entry carries a handle instead of a vector and a CPU, so the two formats
/// are not interchangeable and writing the wrong one is a source that stops
/// being delivered.
#[must_use]
pub fn remapping() -> bool {
    REMAPPING.load(core::sync::atomic::Ordering::Acquire)
}

/// Builds the remapping table and turns remapping on.
///
/// Called before any interrupt is routed, so that everything programmed
/// afterwards is programmed in the one format the unit will accept. Blocking
/// compatibility format is the half that retires RFC 0011's residual risk —
/// remapping alone routes what a device sends through a table, and blocking
/// the old format is what stops it sending something else instead.
///
/// # Safety
///
/// The unit must already be programmed by [`enable`], and no interrupt source
/// may have been routed yet.
pub unsafe fn enable_interrupt_remapping(hhdm: u64) -> Result<(), &'static str> {
    // The first programmed unit, and **only** it. Interrupt remapping is per
    // unit like translation is, so on a multi-unit machine this leaves the
    // others unremapped. That is a narrower claim than this function's name
    // suggests and is left as it was rather than widened silently: RFC 0049
    // covers translation, which is what the evidence was about, and extending
    // it to remapping needs its own measurement on a machine that routes an
    // interrupt through a unit this does not program.
    let Some(base) = programmed_units().next() else {
        return Err("no unit");
    };
    let (table, _) = zeroed_frame(hhdm).ok_or("no frame for the remapping table")?;

    // SAFETY: the unit `enable` programmed, and a table this function just
    // allocated and zeroed -- so every entry reads as absent, which is what
    // makes an unissued handle unusable.
    unsafe {
        // `adopt`, not `new`: this unit is already translating, and every
        // command below writes the whole of `GCMD`. Built fresh, the first of
        // them would write a zero into the translation-enable bit and turn the
        // IOMMU's memory protection off while reporting remapping on -- which
        // is what it did, from M6-15 until 2026-08-11.
        let mut unit = vtd::Unit::adopt(base as *mut u8);
        if !unit.supports_interrupt_remapping() {
            return Err("the unit does not support interrupt remapping");
        }
        // The specification wants the invalidation queue on before remapping,
        // and register-based invalidation working without it is exactly why
        // that is easy to miss.
        let (queue, _) = zeroed_frame(hhdm).ok_or("no frame for the invalidation queue")?;
        let (status, _) = zeroed_frame(hhdm).ok_or("no frame for the invalidation status")?;
        if !unit.enable_queued_invalidation(queue) {
            return Err("the unit did not report queued invalidation enabled");
        }
        // Translation must still be on. Every command here rewrites the whole
        // register, so a shadow that lost a bit is a protection that silently
        // went away -- and the only place that is visible is right here.
        if !unit.translating() {
            return Err("enabling remapping turned translation off");
        }
        // Published before anything can invalidate, because from the line
        // above the registers stop working and this is the only route left.
        IQ.store(queue, core::sync::atomic::Ordering::Release);
        IQ_STATUS.store(status, core::sync::atomic::Ordering::Release);
        if !unit.set_interrupt_remap_table(table, vtd::IRT_ENTRIES) {
            return Err("the unit did not accept the remapping table");
        }
        if !unit.enable_interrupt_remapping() {
            return Err("the unit did not report interrupt remapping enabled");
        }
    }

    IRT.store(table, core::sync::atomic::Ordering::Release);
    REMAPPING.store(true, core::sync::atomic::Ordering::Release);
    Ok(())
}

/// Issues a handle for one interrupt source, and programs its entry.
///
/// `source` is the requester id allowed to present the handle, and `None` is
/// for a line the kernel routes on a chip's behalf — see `vtd::Irte`. Every
/// handle issued to a *device* carries one, which is what makes the guarantee
/// "this device may raise this interrupt, and no other".
///
/// `None` if remapping is off or the table is full. A caller that gets one
/// must not fall back to the old format: with compatibility format blocked it
/// would program a source that is never delivered.
pub fn remap_interrupt(source: Option<(u8, u8, u8)>, vector: u8, destination: u8) -> Option<u16> {
    let table = IRT.load(core::sync::atomic::Ordering::Acquire);
    if table == 0 || !remapping() {
        return None;
    }
    let handle = NEXT_HANDLE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if handle as usize >= vtd::IRT_ENTRIES {
        return None;
    }

    let (low, high) = vtd::Irte {
        vector,
        destination,
        source,
    }
    .to_bits();

    let hhdm = crate::shared::hhdm();
    // SAFETY: a table this module allocated and zeroed, at an index bounded by
    // the check above. The high half is written first: the low half carries
    // the present bit, so writing it first would publish an entry whose source
    // and destination are still zero.
    unsafe {
        let entry = ((hhdm + table) as *mut u64).add(handle as usize * 2);
        core::ptr::write_volatile(entry.add(1), high);
        core::ptr::write_volatile(entry, low);
    }

    // SAFETY: the unit that owns this table.
    unsafe {
        let _ = invalidate_interrupt_cache();
    }
    u16::try_from(handle).ok()
}

/// Invalidates the unit's cache of remapping entries.
///
/// # Safety
///
/// The unit must be the one holding this table.
unsafe fn invalidate_interrupt_cache() -> bool {
    // Global invalidation through the same register the IOTLB uses is not
    // available for interrupt entries on this path, and the entries here are
    // written before anything is routed through them -- so there is nothing
    // cached to invalidate yet. Kept as a named no-op rather than omitted, so
    // that the day an entry is *changed* rather than issued, the place that
    // has to grow an invalidation is obvious.
    true
}

/// Names the window with a capability, so it can be granted to a domain.
///
/// RFC 0012 step 7. Holding this is the authority to say what a *device* may
/// reach, which is strictly more than holding memory: a device writes with no
/// page table and asks nobody. Granting it is how a driver moves out of the
/// kernel, and it is the only way any of `MAP`, `UNMAP` or `INFO` can be
/// reached at all.
///
/// # Errors
///
/// [`crate::cap::CapError`] if the arena is full, or there is no window.
pub fn name(device: (u8, u8, u8)) -> Result<crate::cap::SlotRef, crate::cap::CapError> {
    if !present_for(device) {
        return Err(crate::cap::CapError::NotFound);
    }
    crate::cap::with_arena(|arena| {
        arena.insert_root(
            crate::cap::ObjectRef::new(crate::cap::ObjectKind::DmaWindow, device_key(device)),
            crate::cap::Rights::ALL,
            0,
        )
    })
}

/// Unpacks the device a `DmaWindow` capability names.
#[must_use]
pub const fn device_of(key: u64) -> (u8, u8, u8) {
    (
        ((key >> 16) & 0xff) as u8,
        ((key >> 8) & 0xff) as u8,
        (key & 0xff) as u8,
    )
}

/// Any fault the unit has recorded, from whichever report is installed.
///
/// For asking *after* something has run, rather than during bring-up. A device
/// that reached for something nobody granted it leaves a record, and the
/// difference between "the device was refused" and "the device never asked" is
/// the difference between a wrong mapping and a driver that never kicked —
/// which look identical from the outside and take a long time to tell apart by
/// any other means.
#[must_use]
pub fn fault(hhdm: u64) -> Option<Fault> {
    let report = {
        let windows = WINDOWS.lock();
        let (_, report, _) = windows.iter().flatten().next()?;
        *report
    };
    // SAFETY: a report this module discovered and whose unit it programmed.
    unsafe { take_fault(&report, hhdm) }
}

/// How many pages this window has mapped, for `INFO`.
#[must_use]
pub fn mapped_pages() -> u64 {
    MAPPED.load(core::sync::atomic::Ordering::Relaxed)
}

/// Pages currently mapped into the window.
static MAPPED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Reads back the leaf entry for `address`.
///
/// For a self-test that needs to distinguish "the mapping is wrong" from "the
/// device did not ask" — which cost a long detour to tell apart, because a
/// translation to an address that does not exist is dropped silently rather
/// than refused.
#[must_use]
pub fn entry_at(device: (u8, u8, u8), address: u64, hhdm: u64) -> Option<u64> {
    let key = device_key(device);
    let guard = WINDOWS.lock();
    let (_, _, window) = guard.iter().flatten().find(|(held, ..)| *held == key)?;
    let mut table = window.page_table;
    for level in (2..=window.width.levels()).rev() {
        let index = vtd::level_index(address, level);
        // SAFETY: a table this module allocated, at a nine-bit index.
        let entry = unsafe { core::ptr::read_volatile(((hhdm + table) as *const u64).add(index)) };
        table = vtd::PageEntry::from_bits(entry)?.address;
    }
    let index = vtd::level_index(address, 1);
    // SAFETY: as above.
    Some(unsafe { core::ptr::read_volatile(((hhdm + table) as *const u64).add(index)) })
}

/// Maps one physical frame into the window and returns where the device looks.
///
/// The only way a driver gets a `DevAddr`, and it goes through the **one**
/// window rather than a copy of it. `Window` is `Copy`, and for a while two
/// copies existed: the driver mapped its rings through one and every later
/// mapping was allocated from the other, which still believed those addresses
/// were free. The second mapping landed on top of the first -- same page
/// tables, different idea of what was taken -- and the device read a
/// descriptor ring that was no longer there.
pub fn map_frame(device: (u8, u8, u8), physical: u64, hhdm: u64) -> Option<DevAddr> {
    let key = device_key(device);
    let mut guard = WINDOWS.lock();
    let (_, _, window) = guard.iter_mut().flatten().find(|(held, ..)| *held == key)?;
    let address = window.addresses.allocate(1, false)?;
    if !map_page(
        window,
        address.as_u64(),
        physical,
        vtd::Rights::READ_WRITE,
        hhdm,
    ) {
        window.addresses.free(address, 1);
        return None;
    }
    MAPPED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    Some(address)
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
    // **Every unit the firmware named, not the first of them.** RFC 0049. A
    // device is governed by whichever unit claims it, and a unit that is not
    // programmed does not translate: its devices use the addresses they are
    // handed as physical addresses and reach whatever lives there. Sharing one
    // root table across every unit makes "which unit governs this device" stop
    // mattering for correctness, because they all walk the same tables.
    let mut programmed = 0usize;
    let mut first_failure: Option<&'static str> = None;

    for (index, (register_base, covers_all)) in
        report.unit_list.iter().take(report.units).enumerate()
    {
        let Some(base) = crate::mmio::map(*register_base, bhaskix_mm::FRAME_SIZE, hhdm) else {
            report_unit_refusal(index, *covers_all, "its registers could not be mapped");
            first_failure = first_failure.or(Some("a unit's registers could not be mapped"));
            continue;
        };

        // SAFETY: the window the `DMAR` named, just mapped, and nothing else
        // in this kernel programs a remapping unit.
        let mut unit = unsafe { vtd::Unit::new(base as *mut u8) };

        // SAFETY: a mapped register window, as above.
        let outcome = unsafe { program_unit(&mut unit, window, hhdm, index == 0) };
        match outcome {
            Ok(()) => {
                UNIT_BASES[programmed].store(base, core::sync::atomic::Ordering::Release);
                programmed += 1;
                // Published as they are programmed rather than at the end, so
                // an invalidation issued partway through reaches the units
                // that are already live.
                UNITS_PROGRAMMED.store(programmed, core::sync::atomic::Ordering::Release);
            }
            Err(why) => {
                report_unit_refusal(index, *covers_all, why);
                first_failure = first_failure.or(Some(why));
            }
        }
    }

    // A unit that refused is a set of devices nobody is translating. RFC 0012's
    // rule is that such a device is to be treated as if there were no IOMMU at
    // all, so the count is reported rather than rounded up to "translating".
    if programmed != report.units {
        crate::println!(
            "\x1b[91m    iommu          {programmed} of {} units programmed -- devices governed \
             by the rest are NOT translated\x1b[0m",
            report.units,
        );
    } else {
        // Printed on every machine, including the one-unit case. A line that
        // appears only when there is more than one unit is a line whose
        // absence means two different things.
        crate::println!(
            "    iommu          all {programmed} unit{} programmed",
            if programmed == 1 { "" } else { "s" }
        );
    }

    if programmed == 0 {
        return Err(first_failure.unwrap_or("no unit could be programmed"));
    }
    Ok(())
}

/// Says which unit refused and why, in the same shape for every reason.
fn report_unit_refusal(index: usize, covers_all: bool, why: &str) {
    crate::println!(
        "\x1b[91m    iommu unit {index}   REFUSED: {why}{}\x1b[0m",
        if covers_all {
            " -- and this is the unit claiming every device not claimed by another"
        } else {
            ""
        },
    );
}

/// Programs one unit with the shared root table.
///
/// `pass_through` asks for RFC 0043's pass-through entries to be written, which
/// is a property of the *tables* and so is done once rather than per unit.
///
/// # Safety
///
/// `unit` must be a mapped register window of a real remapping unit, and
/// `window` must be built and populated.
unsafe fn program_unit(
    unit: &mut vtd::Unit,
    window: &Window,
    hhdm: u64,
    pass_through: bool,
) -> Result<(), &'static str> {
    // SAFETY: the caller's obligation.
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
            let sagaw = (unit.capabilities() >> 8) & 0x1f;
            let widest = unit.largest_width();
            report_width_refusal(window.width, sagaw, widest);
            return Err("the unit does not support the width the tables were built to");
        }

        // RFC 0043 step 4. The reasoning is on `pass_through_undrivable`; what
        // matters here is the ordering, which is why this is inside `enable`
        // and not in a caller that could get it wrong silently.
        //
        // Written once, against the shared tables, rather than once per unit:
        // a second pass would find every entry already present and report a
        // second set of pass-through lines for the same devices.
        if pass_through {
            let pass = (unit.supports_pass_through(), unit.largest_width());
            pass_through_or_say_why(pass, window, hhdm);
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
    Ok(())
}

/// Prints every fault the unit has recorded, and says so when there are none.
///
/// **This is the line that was missing.** [`faulted`] below has existed since
/// RFC 0012 and was never called from anywhere, so a device refused by the
/// IOMMU produced exactly the same boot report as a device that worked: the
/// kernel held a bit saying "something faulted" and never read it, and held no
/// way at all to learn *which device*, *what address*, or *why*.
///
/// Only the unit this kernel programs is read, which on a machine with several
/// is not all of them. That is stated in the line rather than left implied.
///
/// # Safety
///
/// As [`enable`], and the unit must already have been mapped by it.
pub unsafe fn report_faults_since(_report: &Report, _hhdm: u64, when: &str) {
    let mut records = [vtd::FaultRecord {
        source: 0,
        address: 0,
        reason: 0,
        read: false,
    }; MAX_FAULTS_REPORTED];

    let mut units = 0usize;
    let mut total = 0usize;
    for (index, base) in programmed_units().enumerate() {
        units += 1;
        // SAFETY: a window `enable` mapped and programmed.
        let found = unsafe {
            let unit = vtd::Unit::new(base as *mut u8);
            unit.fault_records(&mut records)
        };
        total += found;
        for record in &records[..found] {
            let (bus, device, function) = record.bus_device_function();
            crate::println!(
                "\x1b[91m    iommu fault    [{when}] unit {index}: {:02x}:{:02x}.{} was refused \
                 a {} of {:#x}: {} (reason {:#x})\x1b[0m",
                bus,
                device,
                function,
                if record.read { "read" } else { "write" },
                record.address,
                vtd::describe_fault(record.reason),
                record.reason,
            );
        }
        if found == MAX_FAULTS_REPORTED {
            crate::println!(
                "    iommu fault    [{when}] unit {index}: {found} is as many as this report \
                 holds; there may be more"
            );
        }
    }

    if units == 0 {
        crate::println!(
            "    iommu faults   [{when}] no unit is programmed, so nothing could be asked"
        );
    } else if total == 0 {
        // Said out loud. A silent report cannot be told apart from one that did
        // not run, and the absence of a fault is often the most useful fact
        // available about a device that is not working.
        crate::println!(
            "    iommu faults   [{when}] none recorded by {}",
            if units == 1 {
                "the one programmed unit"
            } else {
                "any programmed unit"
            }
        );
    }
}

/// How many fault records one boot report will print.
///
/// A unit may hold up to 256. A boot that faults that many times has one bug
/// repeated, not 256 findings, and a report that scrolls the first one off the
/// screen has hidden the only line that mattered.
const MAX_FAULTS_REPORTED: usize = 8;

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

/// Invalidates the unit's cached context entries.
///
/// A unit caches the context entry it used for a device, so a device added to
/// a unit that is already translating is a device the hardware still believes
/// has no context. Nothing had ever added one to a live unit before — the
/// kernel's device was attached before translation was enabled — so nothing
/// had ever needed this, and the entry was correct in memory while the
/// hardware went on using what it had cached.
///
/// # Safety
///
/// The unit must be the one the windows are programmed into.
pub unsafe fn invalidate_contexts() -> bool {
    // **Every programmed unit.** They share the root table, so a context entry
    // written after translation is live is stale in all of their caches, not
    // just the first one's.
    let mut any = false;
    let mut all = true;
    for base in programmed_units() {
        any = true;
        // SAFETY: the caller's obligation.
        all &= unsafe { invalidate_contexts_of(base) };
    }
    any && all
}

/// Invalidates one unit's context cache and IOTLB, in that order.
///
/// # Safety
///
/// `base` must be a mapped register window of a unit [`enable`] programmed.
unsafe fn invalidate_contexts_of(base: u64) -> bool {
    // SAFETY: the caller's obligation. Invalidating a cache cannot make a
    // translation wrong; it can only make a stale one stop being used.
    unsafe {
        let unit = vtd::Unit::new(base as *mut u8);
        // The IOTLB after the context cache, in that order: entries cached
        // through the old context must go too, and invalidating them first
        // would leave a window in which the old context could fill them again.
        // One submission keeps that order without a second round trip.
        match queued(
            &unit,
            &[vtd::context_invalidation(), vtd::iotlb_invalidation()],
        ) {
            Some(done) => done,
            None => unit.invalidate_context() && unit.invalidate_iotlb(),
        }
    }
}

/// Invalidates the unit's IOTLB.
///
/// # Safety
///
/// The unit must be the one this window is programmed into.
unsafe fn invalidate() -> bool {
    let mut any = false;
    let mut all = true;
    for base in programmed_units() {
        any = true;
        // SAFETY: the caller's obligation.
        all &= unsafe { invalidate_one(base) };
    }
    any && all
}

/// Invalidates one unit's IOTLB.
///
/// # Safety
///
/// `base` must be a mapped register window of a unit [`enable`] programmed.
unsafe fn invalidate_one(base: u64) -> bool {
    // SAFETY: the caller's obligation.
    unsafe {
        let unit = vtd::Unit::new(base as *mut u8);
        match queued(&unit, &[vtd::iotlb_invalidation()]) {
            Some(done) => done,
            None => unit.invalidate_iotlb(),
        }
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
pub unsafe fn take_fault(_report: &Report, _hhdm: u64) -> Option<Fault> {
    // **Across every programmed unit**, not the first. A device's fault is
    // recorded by the unit that governs it, and on a multi-unit machine that
    // is usually not unit zero -- so a self-test that deliberately causes one
    // and then read only the first unit would find nothing and call it a pass.
    for base in programmed_units() {
        // SAFETY: the caller's obligation.
        if let Some(fault) = unsafe { take_fault_of(base) } {
            return Some(fault);
        }
    }
    None
}

/// Takes one fault from one unit.
///
/// # Safety
///
/// `base` must be a mapped register window of a unit [`enable`] programmed.
unsafe fn take_fault_of(base: u64) -> Option<Fault> {
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
    fn a_freed_extent_is_reused_only_at_its_own_size() {
        // This asserted the opposite until 2026-08-11, when reuse was enabled:
        // an address that may still be translated must not name new memory,
        // and the proof that it cannot is `iommu_reuse_self_test` rather than
        // a rule in this allocator. What the allocator still owes is that a
        // reused extent is the size it was freed at -- handing back four pages
        // of a sixteen-page extent would leave twelve nobody is tracking.
        let mut space = DevAddrSpace::new(AddressWidth::Bits39);
        let big = space.allocate(16, false).expect("room");
        space.free(big, 16);

        let small = space.allocate(4, false).expect("room");
        assert_ne!(small, big, "a smaller request took a larger freed extent");

        let exact = space.allocate(16, false).expect("room");
        assert_eq!(exact, big, "the extent is reused by a request of its size");
    }

    #[test]
    fn a_freed_low_extent_is_not_handed_to_a_request_above_4_gib() {
        // The two regions are separate address spaces to the device that has
        // to fit an address in 32 bits, and a freed extent carries no note of
        // which it came from beyond its own value.
        let mut space = DevAddrSpace::new(AddressWidth::Bits39);
        let low = space.allocate(1, true).expect("room below 4 GiB");
        space.free(low, 1);

        let high = space.allocate(1, false).expect("room above it");
        assert_ne!(high, low, "a low extent was handed to a high request");
        assert!(high >= DevAddr::from_u64(DevAddrSpace::LOW_LIMIT));
    }

    #[test]
    fn an_inexact_request_also_comes_from_fresh_space() {
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
