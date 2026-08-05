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

use crate::println;

/// What discovery found, if anything.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Report {
    /// Remapping units the firmware described and this kernel recorded.
    pub units: usize,
    /// Units the firmware described, including any refused or unrecorded.
    pub units_seen: usize,
    /// Firmware-reserved regions recorded.
    pub regions: usize,
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

    Some(Report {
        units: dmar.unit_count(),
        units_seen: dmar.units_seen,
        regions: dmar.region_count(),
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
            println!(
                "    dma            no translation yet: this device can reach all of \
                 physical memory (docs/memory.md §5)"
            );
        }
        // A `DMAR` with no usable unit is the same machine as no `DMAR`, and
        // says so in the same words -- the difference matters to whoever reads
        // the firmware, not to a device that can reach the kernel either way.
        Some(_) | None => {
            println!(
                "    dma            NO IOMMU: this device can reach all of physical memory \
                 (docs/memory.md §5)"
            );
        }
    }
}
