// SPDX-License-Identifier: Apache-2.0
//! Assembling the `Handoff` — RFC 0028 step 5.
//!
//! The native boot protocol *is* `bhaskix_boot::Handoff`, so this module's
//! whole job is filling the kernel's own struct honestly: the firmware's
//! memory map translated into the handoff's vocabulary and sorted, the
//! shape findings carried over, and every reference pointing into one
//! page-aligned block the loader allocated as `LoaderData` — which the
//! translation reports as `BootloaderReclaimable`, exactly the lifetime
//! the contract promises: the kernel's, until it has copied what it needs.

use bhaskix_boot::{
    Framebuffer, HANDOFF_VERSION, Handoff, MemoryKind, MemoryRegion, PhysAddr, PixelFormat,
    VirtAddr,
};

use crate::efi::MemoryMap;
use crate::paging::HHDM_BASE;

/// Pages in the handoff block: the struct, the region array, the command
/// line, and the kernel's first stack, each at a fixed page offset.
pub const BLOCK_PAGES: usize = 32;

/// Offsets within the block.
const REGIONS_AT: u64 = 0x1000;
const CMDLINE_AT: u64 = 0x4000;
const STACK_TOP: u64 = 0x2_0000;

/// The most regions the block's array holds. A firmware map larger than
/// this is refused loudly by the caller, not truncated quietly — the shim's
/// rule, kept.
pub const MAX_REGIONS: usize = 128;

/// One UEFI memory type, in the handoff's vocabulary.
///
/// The discriminating trick is the loader's own allocation discipline: the
/// kernel image and the initrd were allocated as `LoaderCode`, the
/// scaffolding as `LoaderData` — so the firmware's own labels tell the
/// translation which is which. The loader's `.efi` image is `LoaderCode`
/// too and is therefore over-labelled `KernelAndModules`; a few hundred
/// kilobytes kept, stated here rather than discovered.
const fn kind_of(uefi_type: u32) -> MemoryKind {
    match uefi_type {
        7 => MemoryKind::Usable,
        1 => MemoryKind::KernelAndModules,
        2..=4 => MemoryKind::BootloaderReclaimable,
        8 => MemoryKind::BadMemory,
        9 => MemoryKind::AcpiReclaimable,
        10 => MemoryKind::AcpiNvs,
        _ => MemoryKind::Reserved,
    }
}

/// Everything the assembly needs handed in one visible bundle, so the call
/// site reads as the handoff it produces.
pub struct Findings<'boot> {
    /// The map taken at the exit.
    pub map: &'boot MemoryMap,
    /// Where the kernel's segments were placed.
    pub kernel_phys: u64,
    /// The image's linked base.
    pub kernel_virt: u64,
    /// The framebuffer, as `(width, height, stride pixels, base, bgr)`.
    pub framebuffer: Option<(u32, u32, u32, u64, bool)>,
    /// The ACPI root, if the configuration tables named one.
    pub rsdp: Option<u64>,
    /// The SMBIOS entry, likewise.
    pub smbios: Option<u64>,
    /// The command line read from the boot volume.
    pub cmdline: &'boot str,
    /// The initrd's placement and size.
    pub initrd: (u64, usize),
    /// The bootstrap CPU's local APIC id, read by `cpuid`.
    pub bsp_lapic_id: u32,
}

/// Assembles the handoff in `block` (physical, identity-mapped, page
/// aligned, [`BLOCK_PAGES`] long) and returns it with the stack top the
/// kernel is entered on.
///
/// # Errors
///
/// The region count when the firmware's map outgrows [`MAX_REGIONS`] — a
/// refusal, never a truncation — or when the command line outgrows its
/// page.
pub fn assemble(block: u64, findings: &Findings<'_>) -> Result<(&'static Handoff, u64), usize> {
    // The regions, translated, then insertion-sorted by base: the handoff
    // contract demands sorted and the specification does not promise it.
    let mut regions = [MemoryRegion {
        base: PhysAddr(0),
        length: 0,
        kind: MemoryKind::Reserved,
    }; MAX_REGIONS];
    let mut count = 0usize;
    let mut overflowed = false;
    findings.map.regions(|uefi_type, base, bytes| {
        if bytes == 0 {
            return;
        }
        if count == MAX_REGIONS {
            overflowed = true;
            return;
        }
        regions[count] = MemoryRegion {
            base: PhysAddr(base),
            length: bytes,
            kind: kind_of(uefi_type),
        };
        count += 1;
    });
    if overflowed {
        return Err(findings.map.len());
    }
    let mut index = 1;
    while index < count {
        let mut at = index;
        while at > 0 && regions[at - 1].base.0 > regions[at].base.0 {
            regions.swap(at - 1, at);
            at -= 1;
        }
        index += 1;
    }

    // The block's contents, written through the identity map the loader
    // still runs under. Regions first, then the command line, then the
    // struct that points at both.
    let regions_at = block + REGIONS_AT;
    for (slot, region) in regions.iter().enumerate().take(count) {
        // SAFETY: inside the block the loader allocated, at a fixed page
        // offset, bounded by MAX_REGIONS; MemoryRegion is plain data.
        unsafe {
            core::ptr::write_volatile(
                (regions_at as usize + slot * core::mem::size_of::<MemoryRegion>())
                    as *mut MemoryRegion,
                *region,
            );
        }
    }

    if findings.cmdline.len() >= 0x1000 {
        return Err(findings.cmdline.len());
    }
    let cmdline_at = block + CMDLINE_AT;
    for (offset, byte) in findings.cmdline.bytes().enumerate() {
        // SAFETY: inside the block's command-line page, bounds-checked
        // above.
        unsafe { core::ptr::write_volatile((cmdline_at + offset as u64) as *mut u8, byte) };
    }

    let framebuffer = findings
        .framebuffer
        .map(|(width, height, stride, base, bgr)| Framebuffer {
            address: VirtAddr(HHDM_BASE + base),
            width: u64::from(width),
            height: u64::from(height),
            pitch: u64::from(stride) * 4,
            bpp: 32,
            format: if bgr {
                PixelFormat {
                    red_shift: 16,
                    red_size: 8,
                    green_shift: 8,
                    green_size: 8,
                    blue_shift: 0,
                    blue_size: 8,
                }
            } else {
                PixelFormat {
                    red_shift: 0,
                    red_size: 8,
                    green_shift: 8,
                    green_size: 8,
                    blue_shift: 16,
                    blue_size: 8,
                }
            },
        });

    // The references, fabricated from the block: sound because the block is
    // BootloaderReclaimable — the kernel's to read until it says otherwise
    // — and the loader never touches it again.
    // SAFETY: the regions were written just above, at this address, with
    // this count; the block outlives the loader by the contract stated in
    // the module header.
    let memory_map =
        unsafe { core::slice::from_raw_parts(regions_at as *const MemoryRegion, count) };
    // SAFETY: as above, for the command line's bytes, which came from a
    // `&str` and are therefore valid UTF-8 unchanged.
    let cmdline = unsafe {
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(
            cmdline_at as *const u8,
            findings.cmdline.len(),
        ))
    };
    // SAFETY: the initrd's pages were allocated `LoaderCode` and filled
    // from the boot volume; they translate as KernelAndModules and are
    // never reclaimed.
    let initrd =
        unsafe { core::slice::from_raw_parts(findings.initrd.0 as *const u8, findings.initrd.1) };

    let handoff = Handoff {
        version: HANDOFF_VERSION,
        memory_map,
        hhdm_base: VirtAddr(HHDM_BASE),
        kernel_phys_base: PhysAddr(findings.kernel_phys),
        kernel_virt_base: VirtAddr(findings.kernel_virt),
        framebuffer,
        rsdp: findings.rsdp.map(PhysAddr),
        smbios: findings.smbios.map(PhysAddr),
        cmdline,
        loader: "bhaskixboot 0.0.0",
        cpu_count: 1,
        bsp_lapic_id: findings.bsp_lapic_id,
        start_secondaries: None,
        regions_truncated: false,
        initrd: Some(initrd),
    };
    // SAFETY: the block's first page, aligned far beyond the struct's
    // needs, written once and read by the kernel alone after the jump.
    unsafe { core::ptr::write_volatile(block as *mut Handoff, handoff) };

    // SAFETY: written just above; the reference lives as long as the block,
    // which is for ever by the reclamation contract.
    let handoff = unsafe { &*(block as *const Handoff) };
    Ok((handoff, block + STACK_TOP))
}
