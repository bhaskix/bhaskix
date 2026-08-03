// SPDX-License-Identifier: Apache-2.0
//! The Bhaskix boot handoff contract.
//!
//! This crate defines [`Handoff`], the structure the kernel receives at entry.
//! It is **owned by Bhaskix** and deliberately independent of any bootloader:
//! nothing here names, imports, or resembles a particular boot protocol.
//!
//! Why this exists (see `docs/architecture.md` §1): the kernel is currently
//! started by Limine, but must not be coupled to it. A shim translates
//! whatever the bootloader provided into this structure, so that replacing the
//! bootloader — with `bhaskixboot.efi` in Phase 2, or with a BIOS, coreboot, or
//! U-Boot path later — is a rewrite of roughly 200 lines rather than a rewrite
//! of the kernel.
//!
//! The second benefit is testability: a synthetic [`Handoff`] can be built on
//! the host, so memory-management code is unit-testable with no firmware and
//! no emulator.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// Tests are exempt from the `unwrap`/`expect`/`panic` bans, as
// docs/coding-style.md §4 specifies: those exist to stop a fallible operation
// from taking down the nucleus, and a test that cannot panic cannot fail.
// The workspace lint table cannot express a cfg-conditional allow, so it is
// stated here.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use core::fmt;

/// Version of the handoff contract this build speaks.
///
/// The shim writes it into [`Handoff::version`] and the kernel checks it. Bump
/// this on any change to the layout or meaning of the structures below.
pub const HANDOFF_VERSION: u32 = 1;

/// A physical address.
///
/// Distinct from [`VirtAddr`] on purpose. Both are 64-bit integers, and
/// confusing them is a class of bug that costs days; the compiler checks it so
/// a reviewer does not have to (`docs/coding-style.md` §5).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(pub u64);

/// A virtual address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(pub u64);

impl PhysAddr {
    /// The raw value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Translates this physical address through the higher-half direct map.
    ///
    /// Every byte of usable physical memory is mapped at `hhdm_base + pa`, so
    /// this is how kernel code reaches physical memory before it has built any
    /// mappings of its own.
    #[must_use]
    pub const fn to_hhdm(self, hhdm_base: VirtAddr) -> VirtAddr {
        VirtAddr(hhdm_base.0 + self.0)
    }
}

impl VirtAddr {
    /// The raw value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#018x})", self.0)
    }
}

impl fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VirtAddr({:#018x})", self.0)
    }
}

/// What a region of physical memory is for.
///
/// The kernel's handling of each kind is specified in `docs/memory.md` §1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryKind {
    /// Free for the physical memory manager to take.
    Usable,
    /// Firmware- or hardware-reserved. Never touched.
    Reserved,
    /// ACPI tables. Reclaimable once the tables have been parsed and copied.
    AcpiReclaimable,
    /// ACPI non-volatile storage. Never touched.
    AcpiNvs,
    /// Memory the firmware reported as faulty.
    BadMemory,
    /// Bootloader structures.
    ///
    /// Reclaimable, but **only after** the kernel has copied everything it
    /// needs out of the handoff. Reclaiming this while a `&'static` slice still
    /// points into it is the classic bring-up bug; see `docs/memory.md` §1.
    BootloaderReclaimable,
    /// The kernel image and any boot modules. Already mapped.
    KernelAndModules,
    /// Framebuffer memory. Mapped write-combining.
    Framebuffer,
}

impl MemoryKind {
    /// Whether the physical memory manager may allocate from this region at
    /// the point the handoff is consumed.
    ///
    /// Note that [`MemoryKind::BootloaderReclaimable`] is *not* usable yet: it
    /// becomes usable only after the handoff has been fully consumed.
    #[must_use]
    pub const fn is_usable_now(self) -> bool {
        matches!(self, Self::Usable)
    }

    /// A short label for diagnostics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Usable => "usable",
            Self::Reserved => "reserved",
            Self::AcpiReclaimable => "acpi-reclaim",
            Self::AcpiNvs => "acpi-nvs",
            Self::BadMemory => "bad",
            Self::BootloaderReclaimable => "boot-reclaim",
            Self::KernelAndModules => "kernel",
            Self::Framebuffer => "framebuffer",
        }
    }
}

/// One contiguous region of physical memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    /// Base physical address. Page-aligned.
    pub base: PhysAddr,
    /// Length in bytes. A multiple of the page size.
    pub length: u64,
    /// What the region is for.
    pub kind: MemoryKind,
}

impl MemoryRegion {
    /// One past the last byte of this region.
    #[must_use]
    pub const fn end(&self) -> PhysAddr {
        PhysAddr(self.base.0 + self.length)
    }
}

/// How pixels are laid out in framebuffer memory.
///
/// Stored as shift/size pairs rather than as a named format enum because
/// firmware reports it this way and because it is what the blitter needs; an
/// enum would have to be decoded back into exactly these numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PixelFormat {
    /// Bit position of the least significant red bit.
    pub red_shift: u8,
    /// Number of red bits.
    pub red_size: u8,
    /// Bit position of the least significant green bit.
    pub green_shift: u8,
    /// Number of green bits.
    pub green_size: u8,
    /// Bit position of the least significant blue bit.
    pub blue_shift: u8,
    /// Number of blue bits.
    pub blue_size: u8,
}

impl PixelFormat {
    /// Packs an 8-bit-per-channel colour into this format.
    ///
    /// Channels narrower than 8 bits are truncated from the top, which is the
    /// standard approximation and is imperceptible at 5-6 bits.
    #[must_use]
    pub const fn encode(&self, r: u8, g: u8, b: u8) -> u32 {
        let r = (r as u32 >> (8 - self.red_size)) << self.red_shift;
        let g = (g as u32 >> (8 - self.green_size)) << self.green_shift;
        let b = (b as u32 >> (8 - self.blue_size)) << self.blue_shift;
        r | g | b
    }
}

/// A linear framebuffer the firmware or bootloader has already configured.
#[derive(Clone, Copy, Debug)]
pub struct Framebuffer {
    /// Virtual address of the first pixel. Already mapped by the bootloader.
    pub address: VirtAddr,
    /// Width in pixels.
    pub width: u64,
    /// Height in pixels.
    pub height: u64,
    /// Bytes per scanline. May exceed `width * bytes_per_pixel`.
    pub pitch: u64,
    /// Bits per pixel. Only 32 and 24 are supported by the console.
    pub bpp: u16,
    /// Channel layout.
    pub format: PixelFormat,
}

impl Framebuffer {
    /// Bytes occupied by one pixel.
    #[must_use]
    pub const fn bytes_per_pixel(&self) -> usize {
        (self.bpp as usize).div_ceil(8)
    }

    /// Byte offset of the pixel at `(x, y)` from [`Framebuffer::address`].
    ///
    /// Returns `None` if the coordinate is outside the visible area, so that
    /// the caller cannot write past the end of the mapping.
    #[must_use]
    pub const fn offset_of(&self, x: u64, y: u64) -> Option<usize> {
        if x >= self.width || y >= self.height {
            return None;
        }
        Some((y * self.pitch + x * self.bytes_per_pixel() as u64) as usize)
    }
}

/// Everything the kernel is given at entry.
///
/// Constructed by the boot shim and consumed exactly once, by
/// `kernel::init`. The kernel copies out what it needs to keep, so that
/// [`MemoryKind::BootloaderReclaimable`] memory can be released safely.
#[derive(Clone, Copy, Debug)]
pub struct Handoff {
    /// Contract version. Must equal [`HANDOFF_VERSION`].
    pub version: u32,
    /// Physical memory map, sorted by base address, non-overlapping.
    pub memory_map: &'static [MemoryRegion],
    /// Base of the higher-half direct map of all physical memory.
    pub hhdm_base: VirtAddr,
    /// Physical load address of the kernel image.
    pub kernel_phys_base: PhysAddr,
    /// Virtual load address of the kernel image.
    pub kernel_virt_base: VirtAddr,
    /// The framebuffer, if the firmware provided one.
    pub framebuffer: Option<Framebuffer>,
    /// Physical address of the ACPI RSDP, if present.
    pub rsdp: Option<PhysAddr>,
    /// Physical address of the 64-bit SMBIOS entry point, if present.
    pub smbios: Option<PhysAddr>,
    /// Kernel command line. Empty if none was given.
    pub cmdline: &'static str,
    /// Name and version of whatever loaded us, for diagnostics only.
    pub loader: &'static str,
    /// Whether the shim had to drop memory regions it could not represent.
    ///
    /// Must be reported, never ignored. A memory map that is quietly short is
    /// how a kernel comes to allocate from memory a device already owns.
    pub regions_truncated: bool,
}

impl Handoff {
    /// Whether this handoff speaks a version the kernel understands.
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        self.version == HANDOFF_VERSION
    }

    /// Total bytes across regions that are usable right now.
    #[must_use]
    pub fn usable_bytes(&self) -> u64 {
        let mut total = 0;
        let mut i = 0;
        while i < self.memory_map.len() {
            let region = self.memory_map[i];
            if region.kind.is_usable_now() {
                total += region.length;
            }
            i += 1;
        }
        total
    }

    /// Highest physical address covered by any region in the map.
    #[must_use]
    pub fn highest_address(&self) -> PhysAddr {
        let mut highest = PhysAddr(0);
        let mut i = 0;
        while i < self.memory_map.len() {
            let end = self.memory_map[i].end();
            if end.0 > highest.0 {
                highest = end;
            }
            i += 1;
        }
        highest
    }

    /// Checks the invariants the kernel relies on.
    ///
    /// Called once at entry. A handoff that fails this is a bootloader or shim
    /// bug, and continuing would corrupt memory in a way that is very hard to
    /// diagnose later — so the kernel reports and halts instead.
    ///
    /// # Errors
    ///
    /// Returns the first invariant that does not hold.
    pub fn validate(&self) -> Result<(), HandoffError> {
        if !self.is_supported() {
            return Err(HandoffError::UnsupportedVersion(self.version));
        }
        if self.memory_map.is_empty() {
            return Err(HandoffError::EmptyMemoryMap);
        }
        if self.hhdm_base.0 == 0 {
            return Err(HandoffError::MissingHhdm);
        }

        // Two separate checks, because firmware guarantees two different
        // things. The map is sorted by base address, but only the *usable*
        // regions are guaranteed not to overlap — reserved and ACPI regions
        // routinely overlap each other on real hardware, and rejecting that
        // would refuse to boot perfectly good machines.
        let mut previous_base = 0u64;
        let mut previous_usable_end = 0u64;
        let mut i = 0;
        while i < self.memory_map.len() {
            let region = self.memory_map[i];

            if region.base.0 < previous_base {
                return Err(HandoffError::Unsorted(i));
            }
            previous_base = region.base.0;

            if region.kind.is_usable_now() {
                if region.base.0 < previous_usable_end {
                    return Err(HandoffError::OverlappingUsable(i));
                }
                previous_usable_end = region.end().0;
            }

            i += 1;
        }

        if self.usable_bytes() == 0 {
            return Err(HandoffError::NoUsableMemory);
        }
        Ok(())
    }
}

/// Why a [`Handoff`] was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoffError {
    /// The shim speaks a contract version this kernel does not.
    UnsupportedVersion(u32),
    /// The memory map has no entries.
    EmptyMemoryMap,
    /// No higher-half direct map was provided.
    MissingHhdm,
    /// The region at this index starts before its predecessor.
    Unsorted(usize),
    /// The usable region at this index overlaps an earlier usable region.
    OverlappingUsable(usize),
    /// The map contains no usable memory at all.
    NoUsableMemory,
}

impl fmt::Display for HandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => {
                write!(
                    f,
                    "handoff version {v} is not supported (expected {HANDOFF_VERSION})"
                )
            }
            Self::EmptyMemoryMap => f.write_str("memory map is empty"),
            Self::MissingHhdm => f.write_str("no higher-half direct map was provided"),
            Self::Unsorted(i) => write!(f, "memory region {i} starts before its predecessor"),
            Self::OverlappingUsable(i) => {
                write!(
                    f,
                    "usable memory region {i} overlaps an earlier usable region"
                )
            }
            Self::NoUsableMemory => f.write_str("memory map contains no usable memory"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FMT: PixelFormat = PixelFormat {
        red_shift: 16,
        red_size: 8,
        green_shift: 8,
        green_size: 8,
        blue_shift: 0,
        blue_size: 8,
    };

    static GOOD_MAP: [MemoryRegion; 3] = [
        MemoryRegion {
            base: PhysAddr(0x1000),
            length: 0x9_f000,
            kind: MemoryKind::Usable,
        },
        MemoryRegion {
            base: PhysAddr(0xa_0000),
            length: 0x6_0000,
            kind: MemoryKind::Reserved,
        },
        MemoryRegion {
            base: PhysAddr(0x10_0000),
            length: 0x3f00_0000,
            kind: MemoryKind::Usable,
        },
    ];

    fn handoff(map: &'static [MemoryRegion]) -> Handoff {
        Handoff {
            version: HANDOFF_VERSION,
            memory_map: map,
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

    #[test]
    fn validates_a_well_formed_handoff() {
        assert_eq!(handoff(&GOOD_MAP).validate(), Ok(()));
    }

    #[test]
    fn sums_only_currently_usable_regions() {
        // Reserved and bootloader-reclaimable must not be counted.
        assert_eq!(handoff(&GOOD_MAP).usable_bytes(), 0x9_f000 + 0x3f00_0000);
    }

    #[test]
    fn reports_the_highest_address() {
        assert_eq!(
            handoff(&GOOD_MAP).highest_address(),
            PhysAddr(0x10_0000 + 0x3f00_0000)
        );
    }

    #[test]
    fn rejects_an_unsupported_version() {
        let mut h = handoff(&GOOD_MAP);
        h.version = HANDOFF_VERSION + 1;
        assert_eq!(
            h.validate(),
            Err(HandoffError::UnsupportedVersion(HANDOFF_VERSION + 1))
        );
    }

    #[test]
    fn rejects_an_empty_map() {
        static EMPTY: [MemoryRegion; 0] = [];
        assert_eq!(
            handoff(&EMPTY).validate(),
            Err(HandoffError::EmptyMemoryMap)
        );
    }

    #[test]
    fn rejects_a_missing_hhdm() {
        let mut h = handoff(&GOOD_MAP);
        h.hhdm_base = VirtAddr(0);
        assert_eq!(h.validate(), Err(HandoffError::MissingHhdm));
    }

    #[test]
    fn rejects_overlapping_usable_regions() {
        static OVERLAP: [MemoryRegion; 2] = [
            MemoryRegion {
                base: PhysAddr(0x1000),
                length: 0x2000,
                kind: MemoryKind::Usable,
            },
            // Starts before the previous usable region ends.
            MemoryRegion {
                base: PhysAddr(0x2000),
                length: 0x1000,
                kind: MemoryKind::Usable,
            },
        ];
        assert_eq!(
            handoff(&OVERLAP).validate(),
            Err(HandoffError::OverlappingUsable(1))
        );
    }

    #[test]
    fn accepts_overlapping_reserved_regions() {
        // Real firmware routinely reports overlapping reserved and ACPI
        // regions. Rejecting them would refuse to boot good machines, so only
        // usable regions are held to the non-overlap rule.
        static OVERLAP: [MemoryRegion; 3] = [
            MemoryRegion {
                base: PhysAddr(0x1000),
                length: 0x1000,
                kind: MemoryKind::Usable,
            },
            MemoryRegion {
                base: PhysAddr(0xe000_0000),
                length: 0x2000,
                kind: MemoryKind::Reserved,
            },
            MemoryRegion {
                base: PhysAddr(0xe000_1000),
                length: 0x2000,
                kind: MemoryKind::AcpiNvs,
            },
        ];
        assert_eq!(handoff(&OVERLAP).validate(), Ok(()));
    }

    #[test]
    fn rejects_an_unsorted_map() {
        static UNSORTED: [MemoryRegion; 2] = [
            MemoryRegion {
                base: PhysAddr(0x10_0000),
                length: 0x1000,
                kind: MemoryKind::Usable,
            },
            MemoryRegion {
                base: PhysAddr(0x1000),
                length: 0x1000,
                kind: MemoryKind::Usable,
            },
        ];
        assert_eq!(
            handoff(&UNSORTED).validate(),
            Err(HandoffError::Unsorted(1))
        );
    }

    #[test]
    fn rejects_a_map_with_no_usable_memory() {
        static NONE: [MemoryRegion; 1] = [MemoryRegion {
            base: PhysAddr(0),
            length: 0x1000,
            kind: MemoryKind::Reserved,
        }];
        assert_eq!(handoff(&NONE).validate(), Err(HandoffError::NoUsableMemory));
    }

    #[test]
    fn bootloader_reclaimable_is_not_usable_yet() {
        // Guards the invariant in docs/memory.md §1: reclaiming this memory
        // before the handoff is consumed is the classic bring-up bug.
        assert!(!MemoryKind::BootloaderReclaimable.is_usable_now());
        assert!(MemoryKind::Usable.is_usable_now());
    }

    #[test]
    fn hhdm_translation_is_a_simple_offset() {
        let base = VirtAddr(0xffff_8000_0000_0000);
        assert_eq!(
            PhysAddr(0x1234).to_hhdm(base),
            VirtAddr(0xffff_8000_0000_1234)
        );
    }

    #[test]
    fn encodes_pixels_for_a_32bpp_layout() {
        assert_eq!(FMT.encode(0xff, 0x00, 0x00), 0x00ff_0000);
        assert_eq!(FMT.encode(0x00, 0xff, 0x00), 0x0000_ff00);
        assert_eq!(FMT.encode(0x00, 0x00, 0xff), 0x0000_00ff);
        assert_eq!(FMT.encode(0x12, 0x34, 0x56), 0x0012_3456);
    }

    #[test]
    fn encodes_pixels_for_a_16bpp_565_layout() {
        let f = PixelFormat {
            red_shift: 11,
            red_size: 5,
            green_shift: 5,
            green_size: 6,
            blue_shift: 0,
            blue_size: 5,
        };
        assert_eq!(f.encode(0xff, 0xff, 0xff), 0xffff);
        assert_eq!(f.encode(0xff, 0x00, 0x00), 0xf800);
    }

    #[test]
    fn framebuffer_rejects_out_of_bounds_coordinates() {
        let fb = Framebuffer {
            address: VirtAddr(0xffff_8000_fd00_0000),
            width: 1024,
            height: 768,
            pitch: 4096,
            bpp: 32,
            format: FMT,
        };
        assert_eq!(fb.offset_of(0, 0), Some(0));
        assert_eq!(fb.offset_of(1023, 0), Some(1023 * 4));
        assert_eq!(fb.offset_of(0, 1), Some(4096));
        // The pitch is wider than the visible area; writing at x >= width
        // would land in padding, and at y >= height past the mapping.
        assert_eq!(fb.offset_of(1024, 0), None);
        assert_eq!(fb.offset_of(0, 768), None);
    }
}
