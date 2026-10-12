// SPDX-License-Identifier: Apache-2.0
//! Memory types: the PAT this kernel programs, and the MTRRs the firmware left.
//!
//! **Why any of this exists** (2026-10-12): the SR550's framebuffer is the
//! BMC's video memory across PCIe, and the native loader maps it as plain
//! direct-map memory -- PAT entry 0, write-back -- so its effective type is
//! whatever the firmware's MTRRs say, which on a server is uncached. Every
//! glyph the console draws is then an uncached write: about 30 ms a scroll.
//! A write-combining window over it needs a PAT entry that says WC, and the
//! MTRRs read first, because aliasing WC with a *cacheable* mapping of the
//! same memory is something the processor does not support.
//!
//! The encodings are Linux's, read from its headers on 2026-10-12 rather than
//! recalled: the memory-type codes (`X86_MEMTYPE_*`, `msr-index.h`), the MSR
//! numbers (`MSR_IA32_CR_PAT` 0x277, `MSR_MTRRcap` 0xFE, `MSR_MTRRdefType`
//! 0x2FF, `MTRRphysBase_MSR(n)` 0x200 + 2n), the `MTRRdefType` and
//! `MTRRphysMask` bits (`asm/mtrr.h`), the PTE bits (`_PAGE_BIT_PWT` 3,
//! `_PAGE_BIT_PCD` 4, `_PAGE_BIT_PAT` 7 on a 4 KiB page), and how overlapping
//! variable ranges combine (`get_effective_type`, `mtrr/generic.c`).

use crate::msr;

/// Memory-type codes, as the PAT and the MTRRs both write them.
pub mod kind {
    /// Uncacheable.
    pub const UC: u8 = 0;
    /// Write-combining.
    pub const WC: u8 = 1;
    /// Write-through.
    pub const WT: u8 = 4;
    /// Write-protected.
    pub const WP: u8 = 5;
    /// Write-back.
    pub const WB: u8 = 6;
    /// Uncacheable, weakly: an MTRR of WC may still combine (PAT only).
    pub const UC_MINUS: u8 = 7;
}

/// The name of a memory-type code, for the boot report.
#[must_use]
pub const fn name(code: u8) -> &'static str {
    match code {
        kind::UC => "UC",
        kind::WC => "WC",
        kind::WT => "WT",
        kind::WP => "WP",
        kind::WB => "WB",
        kind::UC_MINUS => "UC-",
        _ => "an undefined type",
    }
}

/// `IA32_PAT`.
pub const IA32_PAT: u32 = 0x277;
/// `IA32_MTRRCAP`: how many variable ranges there are, in its low byte.
pub const IA32_MTRRCAP: u32 = 0xFE;
/// `IA32_MTRR_DEF_TYPE`: the default type and the enable bits.
pub const IA32_MTRR_DEF_TYPE: u32 = 0x2FF;
/// `IA32_MTRR_PHYSBASE0`; range `n`'s base is `0x200 + 2n`, its mask one past.
pub const IA32_MTRR_PHYSBASE0: u32 = 0x200;

/// **The PAT layout the shim's loader already sets up** (its boot protocol;
/// see `boot/shim`), adopted on both loaders so there is one: WB, WT, UC-, UC,
/// WP, WC, and -- where that protocol leaves them unspecified -- UC- and UC,
/// the reset values. Entries 0 to 3 are the reset values too, so every mapping
/// made before this is programmed means what it meant.
pub const PAT_LAYOUT: [u8; 8] = [
    kind::WB,
    kind::WT,
    kind::UC_MINUS,
    kind::UC,
    kind::WP,
    kind::WC,
    kind::UC_MINUS,
    kind::UC,
];

/// The entry of [`PAT_LAYOUT`] that is write-combining.
pub const WC_INDEX: u8 = 5;

/// The `IA32_PAT` value for `entries`, entry 0 in the low byte.
#[must_use]
pub const fn pat_value(entries: [u8; 8]) -> u64 {
    let mut value = 0u64;
    let mut index = 0;
    while index < 8 {
        value |= (entries[index] as u64) << (index * 8);
        index += 1;
    }
    value
}

/// The PTE bits that select PAT entry `index` on a 4 KiB page: PWT for bit
/// 0, PCD for bit 1, and the PAT bit (7) for bit 2.
#[must_use]
pub const fn pte_bits_4k(index: u8) -> u64 {
    ((index as u64 & 1) << 3) | (((index as u64 >> 1) & 1) << 4) | (((index as u64 >> 2) & 1) << 7)
}

/// Writes [`PAT_LAYOUT`] to this CPU's `IA32_PAT`.
///
/// # Safety
///
/// The CPU must have a PAT, and every mapping in use must keep meaning what
/// it meant: true when nothing maps through entries 4 to 7 yet, or when the
/// entries a mapping uses are already these values (the shim loader's).
pub unsafe fn program_pat() {
    // SAFETY: the caller's contract; `IA32_PAT` exists on a CPU with a PAT.
    unsafe { msr::write(IA32_PAT, pat_value(PAT_LAYOUT)) };
}

/// One variable MTRR: its `PHYSBASE` and `PHYSMASK` registers, as read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VariableRange {
    /// `IA32_MTRR_PHYSBASEn`: the base in bits 12 and up, the type in 0-7.
    pub base: u64,
    /// `IA32_MTRR_PHYSMASKn`: the mask in bits 12 and up, valid in bit 11.
    pub mask: u64,
}

impl VariableRange {
    const VALID: u64 = 1 << 11;
    const ADDRESS: u64 = !0xFFF;

    fn covers(self, address: u64) -> bool {
        self.mask & Self::VALID != 0
            && address & self.mask & Self::ADDRESS == self.base & self.mask & Self::ADDRESS
    }

    const fn kind(self) -> u8 {
        (self.base & 0xFF) as u8
    }
}

/// What the firmware's MTRRs say about memory: the default type, whether the
/// MTRRs are on at all, and the variable ranges.
#[derive(Clone, Copy, Debug)]
pub struct Mtrrs {
    /// `MTRR_DEF_TYPE`'s type.
    pub default: u8,
    /// `MTRR_DEF_TYPE`'s enable bit (11). Off, every address is UC.
    pub enabled: bool,
    /// The variable ranges, the first `count` of them meaningful.
    pub ranges: [VariableRange; 32],
    /// How many there are.
    pub count: usize,
}

impl Mtrrs {
    /// The type the MTRRs give `address`: UC when they are off; otherwise
    /// the default where no variable range covers it, and where several do,
    /// combined as Linux combines them -- UC wins, WB with WT is WT, and any
    /// other disagreement is UC. Fixed ranges cover only the first megabyte
    /// and are not read.
    #[must_use]
    pub fn type_at(&self, address: u64) -> u8 {
        if !self.enabled {
            return kind::UC;
        }
        let mut found: Option<u8> = None;
        for range in self.ranges.iter().take(self.count) {
            if !range.covers(address) {
                continue;
            }
            let this = range.kind();
            found = Some(match found {
                None => this,
                Some(kind::UC) => kind::UC,
                Some(_) if this == kind::UC => kind::UC,
                Some(kind::WB) if this == kind::WT => kind::WT,
                Some(kind::WT) if this == kind::WB => kind::WT,
                Some(earlier) if earlier == this => this,
                Some(_) => kind::UC,
            });
        }
        found.unwrap_or(self.default)
    }

    /// The one type the MTRRs give every 4 KiB page of `[start, start +
    /// length)`, or `None` when the pages disagree.
    #[must_use]
    pub fn type_of(&self, start: u64, length: u64) -> Option<u8> {
        let first = start & !0xFFF;
        let end = start.checked_add(length)?;
        let kind = self.type_at(first);
        let mut page = first;
        while page < end {
            if self.type_at(page) != kind {
                return None;
            }
            page = page.checked_add(0x1000)?;
        }
        Some(kind)
    }
}

/// Reads the firmware's MTRRs.
///
/// # Safety
///
/// The CPU must have MTRRs (CPUID.1:EDX bit 12), so these MSRs exist.
#[must_use]
pub unsafe fn read_mtrrs() -> Mtrrs {
    // SAFETY: the caller's contract -- these MSRs exist on a CPU with MTRRs --
    // and every register read below is the capability, the default type, or
    // a variable range below the count the capability reports.
    let read = |register: u32| unsafe { msr::read(register) };
    let capability = read(IA32_MTRRCAP);
    let default = read(IA32_MTRR_DEF_TYPE);
    let count = ((capability & 0xFF) as usize).min(32);
    let mut ranges = [VariableRange::default(); 32];
    for (index, range) in ranges.iter_mut().enumerate().take(count) {
        let base = IA32_MTRR_PHYSBASE0 + 2 * index as u32;
        *range = VariableRange {
            base: read(base),
            mask: read(base + 1),
        };
    }
    Mtrrs {
        default: (default & 0xFF) as u8,
        enabled: default & (1 << 11) != 0,
        ranges,
        count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared layout, in the register's own order -- entry 0 lowest.
    #[test]
    fn the_layout_is_limines_and_entry_5_is_write_combining() {
        // Bytes, entry 0 first: 06 04 07 00 05 01 07 00.
        assert_eq!(pat_value(PAT_LAYOUT), 0x0007_0105_0007_0406);
        assert_eq!(PAT_LAYOUT[usize::from(WC_INDEX)], kind::WC);
        // Entries 0 to 3 are the reset values, so nothing mapped before this
        // changes its meaning.
        assert_eq!(
            &PAT_LAYOUT[..4],
            &[kind::WB, kind::WT, kind::UC_MINUS, kind::UC]
        );
    }

    /// Entry 5 on a 4 KiB page is PWT and the PAT bit, and not PCD.
    #[test]
    fn a_pat_index_becomes_its_pte_bits() {
        assert_eq!(pte_bits_4k(0), 0);
        assert_eq!(pte_bits_4k(3), (1 << 3) | (1 << 4));
        assert_eq!(pte_bits_4k(5), (1 << 3) | (1 << 7));
        assert_eq!(pte_bits_4k(7), (1 << 3) | (1 << 4) | (1 << 7));
    }

    fn range(base: u64, size: u64, kind: u8) -> VariableRange {
        VariableRange {
            base: base | u64::from(kind),
            mask: (!(size - 1) & 0x000F_FFFF_FFFF_F000) | (1 << 11),
        }
    }

    fn mtrrs(default: u8, ranges: &[VariableRange]) -> Mtrrs {
        let mut all = [VariableRange::default(); 32];
        all[..ranges.len()].copy_from_slice(ranges);
        Mtrrs {
            default,
            enabled: true,
            ranges: all,
            count: ranges.len(),
        }
    }

    /// A server's shape: RAM write-back by default, the PCI hole uncached.
    #[test]
    fn a_range_takes_its_type_and_the_rest_the_default() {
        let m = mtrrs(kind::WB, &[range(0xC000_0000, 0x4000_0000, kind::UC)]);
        assert_eq!(m.type_at(0xE000_0000), kind::UC);
        assert_eq!(m.type_at(0x1000_0000), kind::WB);
        assert_eq!(m.type_of(0xE000_0000, 3 << 20), Some(kind::UC));
    }

    /// Overlaps combine as Linux combines them.
    #[test]
    fn overlapping_ranges_combine_with_uc_winning() {
        let uc_over_wb = mtrrs(
            kind::WB,
            &[
                range(0, 0x1_0000_0000, kind::WB),
                range(0xE000_0000, 0x1000_0000, kind::UC),
            ],
        );
        assert_eq!(uc_over_wb.type_at(0xE100_0000), kind::UC);
        let wt_over_wb = mtrrs(
            kind::UC,
            &[
                range(0, 0x1000_0000, kind::WB),
                range(0, 0x1000_0000, kind::WT),
            ],
        );
        assert_eq!(wt_over_wb.type_at(0x10_0000), kind::WT);
        let wc_over_wb = mtrrs(
            kind::UC,
            &[
                range(0, 0x1000_0000, kind::WB),
                range(0, 0x1000_0000, kind::WC),
            ],
        );
        assert_eq!(wc_over_wb.type_at(0x10_0000), kind::UC);
    }

    /// A range whose valid bit is clear is not there; MTRRs switched off make
    /// everything UC; a span crossing a boundary has no one type.
    #[test]
    fn invalid_ranges_disabled_mtrrs_and_mixed_spans() {
        let mut off = range(0xE000_0000, 0x1000_0000, kind::UC);
        off.mask &= !(1 << 11);
        let m = mtrrs(kind::WB, &[off]);
        assert_eq!(m.type_at(0xE000_0000), kind::WB);
        let mut disabled = mtrrs(kind::WB, &[]);
        disabled.enabled = false;
        assert_eq!(disabled.type_at(0x1000), kind::UC);
        let edge = mtrrs(kind::WB, &[range(0xE000_0000, 0x10_0000, kind::UC)]);
        assert_eq!(edge.type_of(0xE00F_F000, 0x2000), None);
    }
}
