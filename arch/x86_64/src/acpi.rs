// SPDX-License-Identifier: Apache-2.0
//! Just enough ACPI to find the I/O APIC.
//!
//! The kernel needs one fact out of the firmware's tables: where the I/O APIC
//! is, and which of its inputs a legacy ISA interrupt arrives on. Without that
//! there is no way to receive an interrupt from a device — the local APIC
//! handles the timer and messages between CPUs, and everything else in a PC
//! arrives through an I/O APIC.
//!
//! # This is firmware input, and it is parsed as such
//!
//! ACPI tables are written by firmware, which is neither trusted nor
//! especially careful. A table can name a length longer than the table, an
//! entry length of zero (which is an infinite loop in a naive walker), or a
//! signature that does not match what it claims to be. Every one of those is
//! refused here rather than believed, and the refusals are tested — the
//! parsing half is a pure function over a byte slice for exactly that reason.
//!
//! Checksums are verified and **not trusted as authentication**: anyone who
//! can write a table can compute one. What they catch is a truncated or
//! misaligned table, where continuing would read something that is not a
//! table at all.
//!
//! # What this is not
//!
//! - **Not an ACPI implementation.** No AML, no interpreter, no power
//!   management, no `_PRT`. Those are large, and none of them is needed to
//!   deliver a serial interrupt.
//! - **Not a device enumerator.** PCIe enumeration is Phase 2's driver
//!   framework; this finds one fixed piece of the interrupt path.
//! - **Not multi-I/O-APIC aware.** The first is used and the rest are counted
//!   and reported. A machine with several would route high GSIs to the others,
//!   and nothing here does that yet — it is recorded rather than silently
//!   mishandled.

/// Interrupt source overrides one table may declare.
///
/// Bounded because the walk must not allocate. Sixteen covers every ISA
/// interrupt; a table declaring more is truncated, and says so.
pub const MAX_OVERRIDES: usize = 16;

/// Largest table this will read.
///
/// A header claiming more is refused rather than believed. Real tables are a
/// few kilobytes; the bound exists so that a corrupt length cannot turn into a
/// gigabyte-long slice of whatever follows in memory.
const MAX_TABLE_LENGTH: usize = 1 << 20;

/// Bytes in a system description table header.
const HEADER_LENGTH: usize = 36;

/// Where an I/O APIC is, as the firmware describes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IoApicEntry {
    /// The APIC ID the firmware assigned it.
    pub id: u8,
    /// Physical address of its register window.
    pub address: u32,
    /// The global interrupt number its first input corresponds to.
    pub gsi_base: u32,
}

/// A legacy interrupt that does not arrive where its number suggests.
///
/// On nearly every PC the timer is one of these: ISA IRQ 0 arrives on global
/// interrupt 2. A kernel that assumed `gsi == irq` would program the wrong
/// input and receive nothing, with no error anywhere.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SourceOverride {
    /// The ISA interrupt number.
    pub source: u8,
    /// The global interrupt it actually arrives on.
    pub gsi: u32,
    /// Polarity and trigger mode, in the MADT's encoding.
    pub flags: u16,
}

/// How an interrupt should be programmed into an I/O APIC.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Routing {
    /// The I/O APIC input to program.
    pub gsi: u32,
    /// Whether the line is asserted low.
    pub active_low: bool,
    /// Whether the line is level-triggered rather than edge-triggered.
    pub level: bool,
}

/// What the Multiple APIC Description Table said.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Madt {
    io_apic: Option<IoApicEntry>,
    overrides: [Option<SourceOverride>; MAX_OVERRIDES],
    count: usize,
    /// I/O APICs the table declared, including ones not used.
    pub io_apics_seen: usize,
    /// Whether entries were dropped for want of room.
    pub truncated: bool,
}

impl Madt {
    /// The I/O APIC to program, if the table named one.
    #[must_use]
    pub const fn io_apic(&self) -> Option<IoApicEntry> {
        self.io_apic
    }

    /// How many overrides were recorded.
    #[must_use]
    pub const fn overrides(&self) -> usize {
        self.count
    }

    /// How to program `isa_irq`, applying any override the firmware declared.
    ///
    /// Absent an override, the ISA defaults apply: edge-triggered, active
    /// high, arriving on the input with the same number. Those defaults are
    /// the specification's, not a guess — but the override is what makes them
    /// correct on a real machine, which is why looking one up is not optional.
    #[must_use]
    pub fn route(&self, isa_irq: u8) -> Routing {
        for entry in self.overrides.iter().flatten() {
            if entry.source == isa_irq {
                // Bits 0-1 polarity, bits 2-3 trigger mode. `0` in either
                // field means "whatever the bus says", and for ISA that is
                // active high and edge triggered.
                let polarity = entry.flags & 0b11;
                let trigger = (entry.flags >> 2) & 0b11;
                return Routing {
                    gsi: entry.gsi,
                    active_low: polarity == 0b11,
                    level: trigger == 0b11,
                };
            }
        }
        Routing {
            gsi: u32::from(isa_irq),
            active_low: false,
            level: false,
        }
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset.checked_add(8)?)?;
    let mut value = [0u8; 8];
    value.copy_from_slice(slice);
    Some(u64::from_le_bytes(value))
}

/// Whether every byte of `bytes` sums to zero, modulo 256.
fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) == 0
}

/// Remapping units a `DMAR` table may declare before this parser stops
/// recording them.
///
/// Fixed, because this runs before the heap on a path that programs hardware.
/// A machine with more is reported as truncated rather than silently served by
/// the first eight — a unit that was dropped is a set of devices nobody is
/// translating, which is exactly the state RFC 0012 refuses to be in quietly.
pub const MAX_UNITS: usize = 8;

/// Firmware-reserved regions recorded, for the same reason.
pub const MAX_RESERVED: usize = 8;

/// How many ECAM regions this parser will keep.
///
/// Four. One segment is what a PC has; a machine with more is a machine with
/// more root complexes, and refusing to look at the fifth is better than
/// silently using the first for a device that is not under it.
pub const MAX_ECAM: usize = 4;

/// One memory-mapped configuration region, from `MCFG`.
///
/// With this, a function's configuration space is 4 KiB of ordinary memory at
/// a computable address — which is what makes it something a capability could
/// name, and why RFC 0014 asks how much of it a domain may hold.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ecam {
    /// Physical address of the region's base.
    pub base: u64,
    /// PCI segment group this region covers.
    pub segment: u16,
    /// First bus number in it.
    pub start_bus: u8,
    /// Last bus number in it, inclusive.
    pub end_bus: u8,
}

impl Ecam {
    /// Where a function's configuration space starts, physically.
    ///
    /// `None` if the bus is not in this region — which is the check that stops
    /// a machine with several regions reading the wrong one, and the reason
    /// this is a method rather than a formula written at each call site.
    pub const fn address(&self, bus: u8, device: u8, function: u8) -> Option<u64> {
        if bus < self.start_bus || bus > self.end_bus {
            return None;
        }
        let bus_offset = (bus - self.start_bus) as u64;
        Some(
            self.base
                + (bus_offset << 20)
                + (((device & 0x1f) as u64) << 15)
                + (((function & 0x07) as u64) << 12),
        )
    }

    /// How many bytes this region spans.
    #[must_use]
    pub const fn length(&self) -> u64 {
        ((self.end_bus as u64 - self.start_bus as u64) + 1) << 20
    }
}

/// What `MCFG` said, if anything did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mcfg {
    regions: [Option<Ecam>; MAX_ECAM],
    count: usize,
}

impl Mcfg {
    /// The regions, in the order the firmware listed them.
    pub fn regions(&self) -> impl Iterator<Item = Ecam> + '_ {
        self.regions.iter().take(self.count).flatten().copied()
    }

    /// How many there are.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }
}

/// Reads `MCFG`: where configuration space is, as memory.
///
/// Returns `None` for a table that is not `MCFG`, fails its checksum, or lists
/// no regions — a table that says nothing is the same as no table, and a
/// machine with neither uses the port pair instead.
#[must_use]
pub fn parse_mcfg(bytes: &[u8]) -> Option<Mcfg> {
    if bytes.get(0..4)? != b"MCFG" || !checksum_ok(bytes) {
        return None;
    }

    // Header, then eight reserved bytes, then sixteen bytes per region.
    let mut offset = HEADER_LENGTH + 8;
    let mut regions = [None; MAX_ECAM];
    let mut count = 0;

    while offset + 16 <= bytes.len() && count < MAX_ECAM {
        let base = u64_at(bytes, offset)?;
        let segment = u16_at(bytes, offset + 8)?;
        let start_bus = *bytes.get(offset + 10)?;
        let end_bus = *bytes.get(offset + 11)?;
        offset += 16;

        // A region whose buses run backwards describes nothing, and a base of
        // zero is firmware that filled in a template. Both are skipped rather
        // than believed: an entry believed here becomes an address read later.
        if end_bus < start_bus || base == 0 {
            continue;
        }
        regions[count] = Some(Ecam {
            base,
            segment,
            start_bus,
            end_bus,
        });
        count += 1;
    }

    (count > 0).then_some(Mcfg { regions, count })
}

/// One DMA remapping hardware unit — an IOMMU, and where its registers are.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Unit {
    /// PCI segment this unit covers.
    pub segment: u16,
    /// Physical address of its register window.
    pub register_base: u64,
    /// Whether it covers every device on its segment not claimed by another.
    pub covers_all: bool,
}

/// A region firmware says a device may always reach.
///
/// Named by firmware, and therefore an attack surface by design: a firmware
/// that named the kernel's memory would be asking for a device to be given
/// access to it. RFC 0012 requires the kernel to check these against its own
/// image before identity-mapping any of them. This parser reports what was
/// claimed and vouches for none of it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reserved {
    /// PCI segment.
    pub segment: u16,
    /// First byte.
    pub base: u64,
    /// Last byte, inclusive.
    pub limit: u64,
}

/// What the DMA Remapping table said.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Dmar {
    units: [Option<Unit>; MAX_UNITS],
    unit_count: usize,
    regions: [Option<Reserved>; MAX_RESERVED],
    region_count: usize,
    /// Physical address bits the hardware can generate.
    pub host_address_width: u8,
    /// Whether the platform declares interrupt remapping.
    pub interrupt_remapping: bool,
    /// Units the table declared, including any there was no room for.
    pub units_seen: usize,
    /// Reserved regions declared, likewise.
    pub regions_seen: usize,
    /// Whether anything was dropped for want of room, or refused as malformed.
    ///
    /// Reported rather than folded into the counts, because "there are three
    /// units and two were understood" is a different machine from "there are
    /// two units", and only one of them is safe to enable translation on.
    pub truncated: bool,
}

impl Dmar {
    /// The remapping units recorded.
    pub fn units(&self) -> impl Iterator<Item = Unit> + '_ {
        self.units.iter().take(self.unit_count).flatten().copied()
    }

    /// How many units were recorded.
    #[must_use]
    pub const fn unit_count(&self) -> usize {
        self.unit_count
    }

    /// The firmware-reserved regions recorded.
    pub fn regions(&self) -> impl Iterator<Item = Reserved> + '_ {
        self.regions
            .iter()
            .take(self.region_count)
            .flatten()
            .copied()
    }

    /// How many reserved regions were recorded.
    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.region_count
    }
}

/// Reads a `DMAR` table out of `bytes`.
///
/// Another untrusted parser of the same kind as the MADT walk, and with a
/// worse failure mode: believing this one wrongly means programming a register
/// window that is not an IOMMU. Nothing here is trusted to be sensible. Every
/// length is checked against what is left, **a structure length of zero is
/// refused rather than looped on** — it is the loop increment, so believing it
/// is a hang rather than a crash — and a unit whose register base is not a
/// plausible page-aligned address is dropped rather than recorded.
///
/// Returns `None` only when the buffer is not a `DMAR` table at all.
#[must_use]
pub fn parse_dmar(bytes: &[u8]) -> Option<Dmar> {
    /// Header, plus the host address width byte, the flags byte, and ten
    /// reserved bytes.
    const DMAR_HEADER: usize = HEADER_LENGTH + 12;
    const TYPE_DRHD: u16 = 0;
    const TYPE_RMRR: u16 = 1;
    /// DRHD: type, length, flags, reserved, segment, register base.
    const DRHD_LENGTH: usize = 16;
    /// RMRR: type, length, reserved, segment, base, limit.
    const RMRR_LENGTH: usize = 24;
    /// Fewer address bits than a page offset describes hardware that cannot
    /// address a page, which is not a machine.
    const MIN_ADDRESS_WIDTH: u8 = 12;

    if bytes.len() < DMAR_HEADER || bytes.get(0..4)? != b"DMAR" {
        return None;
    }
    let length = u32_at(bytes, 4)? as usize;
    if length < DMAR_HEADER || length > bytes.len() {
        return None;
    }
    let bytes = bytes.get(..length)?;
    if !checksum_ok(bytes) {
        return None;
    }

    // Stored as width-minus-one, so a byte can describe a 64-bit machine.
    let width = (*bytes.get(HEADER_LENGTH)?).saturating_add(1);
    let flags = *bytes.get(HEADER_LENGTH + 1)?;

    let mut dmar = Dmar {
        units: [None; MAX_UNITS],
        unit_count: 0,
        regions: [None; MAX_RESERVED],
        region_count: 0,
        host_address_width: width,
        interrupt_remapping: flags & 1 != 0,
        units_seen: 0,
        regions_seen: 0,
        truncated: width < MIN_ADDRESS_WIDTH,
    };

    let mut offset = DMAR_HEADER;
    while offset + 4 <= bytes.len() {
        let kind = u16_at(bytes, offset)?;
        let structure = u16_at(bytes, offset + 2)? as usize;

        // Anything that does not fit what is left ends the walk: the rest of
        // the table cannot be trusted to start where this structure claims to
        // end.
        if structure < 4 || offset + structure > bytes.len() {
            dmar.truncated = true;
            break;
        }
        let entry = bytes.get(offset..offset + structure)?;
        offset += structure;

        match kind {
            TYPE_DRHD if structure >= DRHD_LENGTH => {
                dmar.units_seen += 1;
                let base = u64_at(entry, 8)?;
                // Non-zero and page-aligned, or it is not a register window.
                // This address is dereferenced as hardware, so a wrong one is
                // not a wrong answer, it is a write to whatever was there.
                if base == 0 || base % 4096 != 0 {
                    dmar.truncated = true;
                } else if dmar.unit_count < MAX_UNITS {
                    dmar.units[dmar.unit_count] = Some(Unit {
                        segment: u16_at(entry, 6)?,
                        register_base: base,
                        covers_all: entry.get(4)? & 1 != 0,
                    });
                    dmar.unit_count += 1;
                } else {
                    dmar.truncated = true;
                }
            }
            TYPE_RMRR if structure >= RMRR_LENGTH => {
                dmar.regions_seen += 1;
                let base = u64_at(entry, 8)?;
                let limit = u64_at(entry, 16)?;
                if base > limit {
                    dmar.truncated = true;
                } else if dmar.region_count < MAX_RESERVED {
                    dmar.regions[dmar.region_count] = Some(Reserved {
                        segment: u16_at(entry, 6)?,
                        base,
                        limit,
                    });
                    dmar.region_count += 1;
                } else {
                    dmar.truncated = true;
                }
            }
            // A DRHD or RMRR too short to be what it says it is.
            TYPE_DRHD | TYPE_RMRR => dmar.truncated = true,
            // A structure this parser does not read, skipped by its own
            // length — which is what lets an older kernel read a newer table.
            _ => {}
        }
    }

    Some(dmar)
}

/// Reads a MADT out of `bytes`.
///
/// Pure, and the reason the walk below is thin: every refusal this makes can
/// be tested against a byte array, with no firmware, no physical memory and no
/// machine. A parser reachable only through a pointer is a parser tested only
/// by booting.
///
/// Returns `None` if the table is not a MADT, is too short, or fails its
/// checksum.
#[must_use]
pub fn parse_madt(bytes: &[u8]) -> Option<Madt> {
    if bytes.len() < 44 || bytes.get(0..4)? != b"APIC" {
        return None;
    }

    // The header's own length field decides how much of the buffer is the
    // table. A larger value than the buffer means the caller was handed less
    // than the table claims to be, which is a truncated read, not a table.
    let length = u32_at(bytes, 4)? as usize;
    if length < 44 || length > bytes.len() {
        return None;
    }
    let bytes = bytes.get(..length)?;
    if !checksum_ok(bytes) {
        return None;
    }

    let mut madt = Madt {
        io_apic: None,
        overrides: [None; MAX_OVERRIDES],
        count: 0,
        io_apics_seen: 0,
        truncated: false,
    };

    // Entries start after the fixed part: header, local APIC address, flags.
    let mut offset = 44;
    while offset + 2 <= bytes.len() {
        let kind = bytes[offset];
        let entry_length = bytes[offset + 1] as usize;

        // A length of zero is the interesting case: a walker that trusted it
        // would advance nowhere and loop for ever, and this runs during boot
        // with interrupts disabled, so the machine would simply stop. A length
        // that runs past the table is the same class of mistake.
        if entry_length < 2 || offset + entry_length > bytes.len() {
            madt.truncated = true;
            break;
        }
        let entry = &bytes[offset..offset + entry_length];

        match kind {
            // I/O APIC.
            1 if entry_length >= 12 => {
                madt.io_apics_seen += 1;
                if madt.io_apic.is_none() {
                    madt.io_apic = Some(IoApicEntry {
                        id: entry[2],
                        address: u32_at(entry, 4)?,
                        gsi_base: u32_at(entry, 8)?,
                    });
                }
            }
            // Interrupt source override.
            2 if entry_length >= 10 => {
                if madt.count < MAX_OVERRIDES {
                    madt.overrides[madt.count] = Some(SourceOverride {
                        source: entry[3],
                        gsi: u32_at(entry, 4)?,
                        flags: u16_at(entry, 8)?,
                    });
                    madt.count += 1;
                } else {
                    madt.truncated = true;
                }
            }
            // Everything else -- local APICs, NMI sources, x2APIC entries --
            // is skipped by length. Skipping by length is safe here precisely
            // because the length was checked above; skipping by a guessed size
            // per type is how a walker desynchronises from the table.
            _ => {}
        }

        offset += entry_length;
    }

    Some(madt)
}

/// Makes a physical range readable through the direct map.
///
/// ACPI tables are not always in memory the direct map already covers. The
/// RSDP in particular often sits in the legacy BIOS area below one megabyte,
/// which the firmware's memory map calls *reserved* and a bootloader has no
/// reason to map. Dereferencing it because "the direct map covers physical
/// memory" is a page fault during boot with a plausible-looking address, and
/// it is what the first version of this module did.
///
/// So the caller supplies the mapping. `arch` cannot do it itself — the
/// allocator that a new page table comes from lives above this layer — and
/// making it an argument keeps the walk honest: every dereference below is
/// preceded by a request for exactly the bytes about to be read.
pub type EnsureMapped<'a> = &'a mut dyn FnMut(u64, usize) -> bool;

/// Borrows a table at a physical address, if it is one.
///
/// # Safety
///
/// `hhdm` must be the direct map's base, and `ensure` must genuinely map what
/// it says it mapped. The returned slice borrows firmware-owned memory, which
/// the kernel never reclaims — ACPI-reclaimable memory is deliberately left
/// alone (`docs/memory.md`).
unsafe fn table_at(physical: u64, hhdm: u64, ensure: EnsureMapped<'_>) -> Option<&'static [u8]> {
    let address = hhdm.checked_add(physical)?;
    if physical == 0 {
        return None;
    }
    // No alignment requirement, deliberately. Firmware places tables where it
    // likes -- the machine this was written on reports its RSDT at an address
    // two bytes off a word boundary -- and every field here is read a byte at
    // a time out of a slice, so alignment is not a correctness question. An
    // alignment check looks defensive and rejects real firmware.

    // The header first, so the length is read before anything is borrowed at
    // that length. Reading the length out of a slice built *from* the length
    // would be circular.
    if !ensure(physical, HEADER_LENGTH) {
        return None;
    }
    // SAFETY: `ensure` has just made these bytes readable at `address`.
    let header = unsafe { core::slice::from_raw_parts(address as *const u8, HEADER_LENGTH) };
    let length = u32_at(header, 4)? as usize;
    if !(HEADER_LENGTH..=MAX_TABLE_LENGTH).contains(&length) {
        return None;
    }
    if !ensure(physical, length) {
        return None;
    }

    // SAFETY: as above, now for the length the header declares, which was
    // bounded to something a table can plausibly be.
    Some(unsafe { core::slice::from_raw_parts(address as *const u8, length) })
}

/// Walks the ACPI tables, returning the first that `read` accepts.
///
/// Every table the firmware lists is offered to `read`, which returns `None`
/// for one it does not recognise. That is what lets one walk serve the MADT
/// and the `DMAR` without either knowing about the other, and it keeps the
/// pointer-chasing — the part that cannot be tested without a machine — in one
/// place with the parsers pure beside it.
///
/// # Safety
///
/// `rsdp` must be the physical address the bootloader reported, and `hhdm` the
/// direct map base. Both come from the handoff; nothing else may pass an
/// address here. `ensure` must map what it claims to map.
#[must_use]
unsafe fn tables<T>(
    rsdp: u64,
    hhdm: u64,
    ensure: EnsureMapped<'_>,
    read: impl Fn(&'static [u8]) -> Option<T>,
) -> Option<T> {
    let address = hhdm.checked_add(rsdp)?;
    // 36 bytes rather than 20, so a version 2 pointer's extended fields are in
    // the same borrow as the rest.
    if !ensure(rsdp, 36) {
        return None;
    }
    // SAFETY: `ensure` has just made these bytes readable at `address`.
    let rsdp_bytes = unsafe { core::slice::from_raw_parts(address as *const u8, 36) };

    if rsdp_bytes.get(0..8)? != b"RSD PTR " || !checksum_ok(rsdp_bytes.get(..20)?) {
        return None;
    }

    let revision = *rsdp_bytes.get(15)?;
    let (root, entry_size) = if revision >= 2 {
        // Version 2 adds its own checksum over the longer structure. A machine
        // whose XSDT checksum fails falls back to the 32-bit RSDT rather than
        // failing outright: the fallback is what the specification intends and
        // costs one branch.
        let length = u32_at(rsdp_bytes, 20)? as usize;
        match rsdp_bytes.get(..length.min(36)) {
            Some(extended) if length >= 33 && checksum_ok(extended) => {
                (u64_at(rsdp_bytes, 24)?, 8usize)
            }
            _ => (u64::from(u32_at(rsdp_bytes, 16)?), 4usize),
        }
    } else {
        (u64::from(u32_at(rsdp_bytes, 16)?), 4usize)
    };

    // SAFETY: an address taken from a checksummed RSDP, mapped on demand.
    let root = unsafe { table_at(root, hhdm, ensure) }?;
    let signature = if entry_size == 8 { b"XSDT" } else { b"RSDT" };
    if root.get(0..4)? != signature || !checksum_ok(root) {
        return None;
    }

    let mut offset = HEADER_LENGTH;
    while offset + entry_size <= root.len() {
        let physical = if entry_size == 8 {
            u64_at(root, offset)?
        } else {
            u64::from(u32_at(root, offset)?)
        };
        offset += entry_size;

        // SAFETY: an address from the root table, which was checksummed, and
        // mapped on demand by the caller's closure.
        if let Some(table) = unsafe { table_at(physical, hhdm, ensure) }
            && let Some(parsed) = read(table)
        {
            return Some(parsed);
        }
    }
    None
}

/// Finds and parses the MADT.
///
/// # Safety
///
/// As [`tables`].
pub unsafe fn madt(rsdp: u64, hhdm: u64, ensure: EnsureMapped<'_>) -> Option<Madt> {
    // SAFETY: the caller's obligation, unchanged.
    unsafe { tables(rsdp, hhdm, ensure, parse_madt) }
}

/// Finds and parses the `DMAR` table, if the firmware provided one.
///
/// `None` means no IOMMU is described — which RFC 0012 treats as a *reported*
/// degraded mode rather than a detail, because it is the difference between a
/// device that can reach the memory it was given and one that can reach all of
/// it.
///
/// # Safety
///
/// As [`tables`].
pub unsafe fn dmar(rsdp: u64, hhdm: u64, ensure: EnsureMapped<'_>) -> Option<Dmar> {
    // SAFETY: the caller's obligation, unchanged.
    unsafe { tables(rsdp, hhdm, ensure, parse_dmar) }
}

/// Finds `MCFG` and reads it.
///
/// # Safety
///
/// As [`tables`].
pub unsafe fn mcfg(rsdp: u64, hhdm: u64, ensure: EnsureMapped<'_>) -> Option<Mcfg> {
    // SAFETY: the caller's obligation, unchanged.
    unsafe { tables(rsdp, hhdm, ensure, parse_mcfg) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `std` rather than `alloc`: this crate is `no_std` only when it is not
    // being tested, and the test build has the whole library.
    use std::vec::Vec;

    /// Builds a MADT with the entries given, and a correct checksum.
    fn madt_bytes(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"APIC");
        bytes.extend_from_slice(&0u32.to_le_bytes()); // length, filled in below
        bytes.push(1); // revision
        bytes.push(0); // checksum, filled in below
        bytes.extend_from_slice(b"BHASKXBHASKIX  "); // oem id + table id
        bytes.resize(36, 0);
        bytes.extend_from_slice(&0xfee0_0000u32.to_le_bytes()); // local apic
        bytes.extend_from_slice(&1u32.to_le_bytes()); // flags
        for entry in entries {
            bytes.extend_from_slice(entry);
        }

        let length = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        let sum = bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        bytes[9] = sum.wrapping_neg();
        bytes
    }

    fn io_apic(id: u8, address: u32, gsi_base: u32) -> Vec<u8> {
        let mut entry = vec![1u8, 12, id, 0];
        entry.extend_from_slice(&address.to_le_bytes());
        entry.extend_from_slice(&gsi_base.to_le_bytes());
        entry
    }

    fn source_override(source: u8, gsi: u32, flags: u16) -> Vec<u8> {
        let mut entry = vec![2u8, 10, 0, source];
        entry.extend_from_slice(&gsi.to_le_bytes());
        entry.extend_from_slice(&flags.to_le_bytes());
        entry
    }

    /// A local APIC entry: skipped, and there to be skipped correctly.
    fn local_apic(id: u8) -> Vec<u8> {
        vec![0u8, 8, id, id, 1, 0, 0, 0]
    }

    #[test]
    fn a_well_formed_table_yields_the_io_apic_and_its_overrides() {
        let bytes = madt_bytes(&[
            local_apic(0),
            io_apic(2, 0xfec0_0000, 0),
            source_override(0, 2, 0),
            local_apic(1),
            source_override(9, 9, 0b1101),
        ]);
        let madt = parse_madt(&bytes).expect("valid");

        assert_eq!(
            madt.io_apic(),
            Some(IoApicEntry {
                id: 2,
                address: 0xfec0_0000,
                gsi_base: 0
            })
        );
        assert_eq!(madt.overrides(), 2);
        assert!(!madt.truncated);
    }

    #[test]
    fn an_override_moves_an_interrupt_to_a_different_input() {
        // The case that makes overrides non-optional: on nearly every PC the
        // timer's ISA IRQ 0 arrives on global interrupt 2, and a kernel that
        // assumed otherwise would program an input nothing is wired to and
        // receive silence.
        let bytes = madt_bytes(&[io_apic(0, 0xfec0_0000, 0), source_override(0, 2, 0)]);
        let madt = parse_madt(&bytes).expect("valid");

        assert_eq!(
            madt.route(0),
            Routing {
                gsi: 2,
                active_low: false,
                level: false
            }
        );
        // Unmentioned interrupts keep the ISA defaults.
        assert_eq!(
            madt.route(4),
            Routing {
                gsi: 4,
                active_low: false,
                level: false
            }
        );
    }

    #[test]
    fn polarity_and_trigger_come_from_the_flags() {
        let bytes = madt_bytes(&[
            io_apic(0, 0xfec0_0000, 0),
            source_override(9, 9, 0b1111), // active low, level triggered
        ]);
        let madt = parse_madt(&bytes).expect("valid");
        assert_eq!(
            madt.route(9),
            Routing {
                gsi: 9,
                active_low: true,
                level: true
            }
        );
    }

    #[test]
    fn an_entry_length_of_zero_ends_the_walk_rather_than_looping_for_ever() {
        // The one that matters most. A walker that trusted this length would
        // advance nowhere, with interrupts disabled, during boot -- so the
        // machine would stop with no output and no fault to look at.
        let mut bytes = madt_bytes(&[io_apic(0, 0xfec0_0000, 0), source_override(0, 2, 0)]);
        bytes[44 + 12 + 1] = 0;
        let sum = bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        bytes[9] = bytes[9].wrapping_sub(sum);

        let madt = parse_madt(&bytes).expect("valid");
        assert!(madt.truncated, "the walk must report that it stopped early");
        assert_eq!(madt.overrides(), 0);
    }

    #[test]
    fn an_entry_running_past_the_table_is_refused() {
        let mut bytes = madt_bytes(&[io_apic(0, 0xfec0_0000, 0)]);
        bytes[44 + 1] = 200;
        let sum = bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        bytes[9] = bytes[9].wrapping_sub(sum);

        let madt = parse_madt(&bytes).expect("valid");
        assert!(madt.truncated);
        assert_eq!(madt.io_apic(), None);
    }

    #[test]
    fn a_length_longer_than_the_buffer_is_refused() {
        // The caller was handed less than the table claims to be, which is a
        // truncated read rather than a table.
        let mut bytes = madt_bytes(&[io_apic(0, 0xfec0_0000, 0)]);
        let length = (bytes.len() + 64) as u32;
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        assert_eq!(parse_madt(&bytes), None);
    }

    #[test]
    fn a_bad_signature_or_checksum_is_refused() {
        let mut bytes = madt_bytes(&[io_apic(0, 0xfec0_0000, 0)]);
        bytes[0] = b'X';
        assert_eq!(parse_madt(&bytes), None);

        let mut bytes = madt_bytes(&[io_apic(0, 0xfec0_0000, 0)]);
        bytes[9] = bytes[9].wrapping_add(1);
        assert_eq!(parse_madt(&bytes), None);
    }

    #[test]
    fn more_overrides_than_there_is_room_for_are_reported_not_dropped_silently() {
        let mut entries = vec![io_apic(0, 0xfec0_0000, 0)];
        for index in 0..MAX_OVERRIDES + 4 {
            entries.push(source_override(index as u8, index as u32, 0));
        }
        let madt = parse_madt(&madt_bytes(&entries)).expect("valid");
        assert_eq!(madt.overrides(), MAX_OVERRIDES);
        assert!(madt.truncated);
    }

    #[test]
    fn a_truncated_table_is_refused_at_every_length() {
        let bytes = madt_bytes(&[io_apic(0, 0xfec0_0000, 0), source_override(0, 2, 0)]);
        for length in 0..bytes.len() {
            // What it returns does not matter; that it returns does.
            let _ = parse_madt(&bytes[..length]);
        }
    }

    /// The generator the `ustar` and `elf` harnesses use.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn below(&mut self, bound: usize) -> usize {
            if bound == 0 {
                0
            } else {
                (self.next() % bound as u64) as usize
            }
        }
    }

    #[test]
    fn a_mutation_harness_never_makes_the_parser_hang_or_panic() {
        // Firmware tables are input the kernel does not control, so
        // `docs/coding-style.md` §8 applies to this parser as much as to the
        // ones reading a disk. The failure mode here is not only a panic: an
        // entry-length field is a loop increment, so a mutated table is one of
        // the few inputs that can hang a parser rather than crash it. A test
        // that hangs still fails, loudly, by timing out.
        let iterations: usize = std::env::var("BHASKIX_FUZZ_ITERATIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(20_000);

        let base = madt_bytes(&[
            local_apic(0),
            io_apic(2, 0xfec0_0000, 0),
            source_override(0, 2, 0),
            source_override(9, 9, 0b1101),
        ]);

        for seed in 0..iterations as u64 {
            let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d).wrapping_add(11));
            let mut bytes = base.clone();

            for _ in 0..1 + rng.below(6) {
                match rng.below(3) {
                    0 if !bytes.is_empty() => {
                        let index = rng.below(bytes.len());
                        bytes[index] = rng.next() as u8;
                    }
                    // Lengths, specifically: the header's and the entries'.
                    // Uniform byte flips reach these eventually; aiming at
                    // them reaches the interesting cases in the first hundred
                    // seeds rather than the last thousand.
                    1 if bytes.len() > 45 => {
                        let index = 44 + rng.below(bytes.len() - 44);
                        bytes[index] = [0u8, 1, 2, 255, 128][rng.below(5)];
                    }
                    _ => {
                        let length = rng.below(bytes.len().max(1));
                        bytes.truncate(length);
                    }
                }
            }

            if let Some(madt) = parse_madt(&bytes) {
                // Anything accepted must be usable without further checking:
                // the caller programs hardware from it.
                assert!(madt.overrides() <= MAX_OVERRIDES, "seed {seed}");
                // `route` must answer for any interrupt without panicking --
                // including one whose override the mutation made nonsense. The
                // number it returns is range-checked against the hardware by
                // whoever programs it; a GSI this parser cannot vouch for is a
                // refused redirection, not a wild write.
                let _ = madt.route(4);
            }
        }
    }

    /// Builds a `DMAR` with the structures given, and a correct checksum.
    fn dmar_bytes(width: u8, flags: u8, entries: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"DMAR");
        bytes.extend_from_slice(&0u32.to_le_bytes()); // length, filled in below
        bytes.push(1); // revision
        bytes.push(0); // checksum, filled in below
        bytes.extend_from_slice(b"BHASKXBHASKIX  ");
        bytes.resize(36, 0);
        bytes.push(width.saturating_sub(1)); // host address width, minus one
        bytes.push(flags);
        bytes.resize(48, 0); // ten reserved bytes
        for entry in entries {
            bytes.extend_from_slice(entry);
        }

        let length = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        let sum = bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        bytes[9] = sum.wrapping_neg();
        bytes
    }

    /// Builds an `MCFG` with the given regions, correctly checksummed.
    fn mcfg_bytes(regions: &[(u64, u16, u8, u8)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"MCFG");
        bytes.extend_from_slice(&0u32.to_le_bytes()); // length, filled in below
        bytes.push(1); // revision
        bytes.push(0); // checksum, filled in below
        bytes.extend_from_slice(b"BHASKXBHASKIX  ");
        bytes.resize(36, 0);
        bytes.resize(44, 0); // eight reserved bytes
        for (base, segment, start, end) in regions {
            bytes.extend_from_slice(&base.to_le_bytes());
            bytes.extend_from_slice(&segment.to_le_bytes());
            bytes.push(*start);
            bytes.push(*end);
            bytes.extend_from_slice(&0u32.to_le_bytes()); // reserved
        }

        let length = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        let sum = bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        bytes[9] = sum.wrapping_neg();
        bytes
    }

    #[test]
    fn an_mcfg_says_where_configuration_space_is() {
        let bytes = mcfg_bytes(&[(0xb000_0000, 0, 0, 255)]);
        let mcfg = parse_mcfg(&bytes).expect("a well-formed MCFG");
        assert_eq!(mcfg.count(), 1);

        let region = mcfg.regions().next().expect("one region");
        assert_eq!(region.base, 0xb000_0000);
        assert_eq!(region.length(), 256 << 20);

        // The address of a function is the base plus bus, device and function
        // in their own fields. Written out here rather than recomputed with
        // the same expression the parser uses, because a check that repeats
        // the formula cannot catch an error in it.
        assert_eq!(region.address(0, 0, 0), Some(0xb000_0000));
        assert_eq!(region.address(0, 3, 0), Some(0xb000_0000 + 3 * 0x8000));
        assert_eq!(region.address(1, 0, 0), Some(0xb000_0000 + 0x10_0000));
        assert_eq!(region.address(0, 0, 7), Some(0xb000_0000 + 7 * 0x1000));
    }

    #[test]
    fn a_bus_outside_the_region_has_no_address_in_it() {
        let bytes = mcfg_bytes(&[(0xb000_0000, 0, 16, 31)]);
        let mcfg = parse_mcfg(&bytes).expect("a well-formed MCFG");
        let region = mcfg.regions().next().expect("one region");

        assert_eq!(region.address(15, 0, 0), None, "below the range");
        assert_eq!(region.address(32, 0, 0), None, "above the range");
        // And the first bus in the region is at the base, not at bus 16's
        // worth of offset -- the offset is from the region's start.
        assert_eq!(region.address(16, 0, 0), Some(0xb000_0000));
    }

    #[test]
    fn an_mcfg_that_is_wrong_about_itself_is_refused() {
        let good = mcfg_bytes(&[(0xb000_0000, 0, 0, 255)]);

        let mut wrong_signature = good.clone();
        wrong_signature[0] = b'X';
        assert!(parse_mcfg(&wrong_signature).is_none(), "signature");

        let mut wrong_checksum = good.clone();
        wrong_checksum[9] = wrong_checksum[9].wrapping_add(1);
        assert!(parse_mcfg(&wrong_checksum).is_none(), "checksum");

        // Regions that describe nothing are skipped rather than believed: an
        // entry believed here becomes an address read later.
        assert!(
            parse_mcfg(&mcfg_bytes(&[(0xb000_0000, 0, 200, 100)])).is_none(),
            "buses running backwards"
        );
        assert!(
            parse_mcfg(&mcfg_bytes(&[(0, 0, 0, 255)])).is_none(),
            "a base of zero is firmware that filled in a template"
        );
        assert!(parse_mcfg(&mcfg_bytes(&[])).is_none(), "no regions at all");
    }

    fn drhd(segment: u16, base: u64, covers_all: bool) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(&0u16.to_le_bytes()); // type
        entry.extend_from_slice(&16u16.to_le_bytes()); // length
        entry.push(u8::from(covers_all)); // flags
        entry.push(0); // reserved
        entry.extend_from_slice(&segment.to_le_bytes());
        entry.extend_from_slice(&base.to_le_bytes());
        entry
    }

    fn rmrr(segment: u16, base: u64, limit: u64) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(&1u16.to_le_bytes()); // type
        entry.extend_from_slice(&24u16.to_le_bytes()); // length
        entry.extend_from_slice(&0u16.to_le_bytes()); // reserved
        entry.extend_from_slice(&segment.to_le_bytes());
        entry.extend_from_slice(&base.to_le_bytes());
        entry.extend_from_slice(&limit.to_le_bytes());
        entry
    }

    #[test]
    fn a_well_formed_dmar_reports_its_units_and_reserved_regions() {
        let bytes = dmar_bytes(
            39,
            1,
            &[
                drhd(0, 0xfed9_0000, false),
                rmrr(0, 0x0009_0000, 0x0009_ffff),
                drhd(0, 0xfed9_1000, true),
            ],
        );
        let dmar = parse_dmar(&bytes).expect("a well-formed table parses");

        assert_eq!(dmar.host_address_width, 39);
        assert!(dmar.interrupt_remapping);
        assert!(!dmar.truncated);
        assert_eq!(dmar.unit_count(), 2);
        assert_eq!(dmar.region_count(), 1);

        let units: Vec<_> = dmar.units().collect();
        assert_eq!(units[0].register_base, 0xfed9_0000);
        assert!(!units[0].covers_all);
        assert!(units[1].covers_all);

        let regions: Vec<_> = dmar.regions().collect();
        assert_eq!(regions[0].base, 0x0009_0000);
        assert_eq!(regions[0].limit, 0x0009_ffff);
    }

    #[test]
    fn a_structure_claiming_no_length_ends_the_walk() {
        // The length is the loop increment. Believing a zero is not a wrong
        // answer, it is a kernel that never finishes booting -- and a hang in
        // firmware parsing is a hang with no output to explain it.
        let mut entry = drhd(0, 0xfed9_0000, false);
        entry[2..4].copy_from_slice(&0u16.to_le_bytes());
        let bytes = dmar_bytes(39, 0, &[entry]);

        let dmar = parse_dmar(&bytes).expect("the table itself is still valid");
        assert!(
            dmar.truncated,
            "a zero length must be reported, not looped on"
        );
        assert_eq!(dmar.unit_count(), 0);
    }

    #[test]
    fn a_register_base_that_is_not_a_register_window_is_refused() {
        // This address is dereferenced as hardware. Recording a misaligned or
        // zero one is not a wrong number, it is a write to whatever is there.
        for base in [0u64, 0xfed9_0001, 0x0000_0fff] {
            let bytes = dmar_bytes(39, 0, &[drhd(0, base, false)]);
            let dmar = parse_dmar(&bytes).expect("the table parses");
            assert_eq!(dmar.unit_count(), 0, "base {base:#x} was recorded");
            assert!(dmar.truncated, "base {base:#x} was refused silently");
            assert_eq!(dmar.units_seen, 1, "base {base:#x} was not even counted");
        }
    }

    #[test]
    fn a_reserved_region_that_ends_before_it_starts_is_refused() {
        let bytes = dmar_bytes(39, 0, &[rmrr(0, 0x2000, 0x1000)]);
        let dmar = parse_dmar(&bytes).expect("the table parses");
        assert_eq!(dmar.region_count(), 0);
        assert!(dmar.truncated);
    }

    #[test]
    fn more_units_than_there_is_room_for_are_reported_rather_than_dropped() {
        // A unit nobody recorded is a set of devices nobody is translating.
        // Reporting nine as eight would be a kernel that believes memory is
        // protected while a whole unit's devices reach all of it.
        let entries: Vec<_> = (0..MAX_UNITS + 1)
            .map(|index| drhd(0, 0xfed9_0000 + (index as u64) * 0x1000, false))
            .collect();
        let bytes = dmar_bytes(39, 0, &entries);
        let dmar = parse_dmar(&bytes).expect("the table parses");

        assert_eq!(dmar.unit_count(), MAX_UNITS);
        assert_eq!(dmar.units_seen, MAX_UNITS + 1);
        assert!(dmar.truncated);
    }

    #[test]
    fn a_table_that_is_not_a_dmar_is_not_read_as_one() {
        let mut bytes = dmar_bytes(39, 0, &[drhd(0, 0xfed9_0000, false)]);
        assert!(parse_dmar(&bytes).is_some());

        // Wrong signature.
        let mut wrong = bytes.clone();
        wrong[0..4].copy_from_slice(b"APIC");
        assert!(parse_dmar(&wrong).is_none());

        // Broken checksum.
        let mut broken = bytes.clone();
        broken[9] = broken[9].wrapping_add(1);
        assert!(parse_dmar(&broken).is_none());

        // A length longer than the buffer is a truncated read, not a table.
        let over = (bytes.len() as u32) + 64;
        bytes[4..8].copy_from_slice(&over.to_le_bytes());
        assert!(parse_dmar(&bytes).is_none());
    }

    #[test]
    fn a_mutation_harness_never_makes_the_dmar_parser_hang_or_panic() {
        // The fuzz target RFC 0012 adds. The MADT's harness explains why this
        // shape of parser needs one; this one matters more, because what is
        // built from a believed `DMAR` is a register window that gets written
        // to as if it were an IOMMU.
        let iterations: usize = std::env::var("BHASKIX_FUZZ_ITERATIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(20_000);

        let base = dmar_bytes(
            39,
            1,
            &[
                drhd(0, 0xfed9_0000, false),
                rmrr(0, 0x0009_0000, 0x0009_ffff),
                drhd(0, 0xfed9_1000, true),
            ],
        );

        for seed in 0..iterations as u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(7));
            let mut bytes = base.clone();

            for _ in 0..1 + rng.below(6) {
                match rng.below(3) {
                    0 if !bytes.is_empty() => {
                        let index = rng.below(bytes.len());
                        bytes[index] = rng.next() as u8;
                    }
                    // The structure lengths, which are the loop increment and
                    // therefore the only field that can hang this parser
                    // rather than crash it. Aimed at deliberately: uniform
                    // flips reach them, eventually, and M6-03 measured what
                    // "eventually" costs.
                    1 if bytes.len() > 49 => {
                        let index = 48 + rng.below(bytes.len() - 48);
                        bytes[index] = [0u8, 1, 2, 4, 255, 128][rng.below(6)];
                    }
                    _ => {
                        let length = rng.below(bytes.len().max(1));
                        bytes.truncate(length);
                    }
                }
            }

            if let Some(dmar) = parse_dmar(&bytes) {
                // Anything accepted must be usable without further checking:
                // the caller maps and programs what this reports.
                assert!(dmar.unit_count() <= MAX_UNITS, "seed {seed}");
                assert!(dmar.region_count() <= MAX_RESERVED, "seed {seed}");
                for unit in dmar.units() {
                    assert!(unit.register_base != 0, "seed {seed}");
                    assert!(unit.register_base % 4096 == 0, "seed {seed}");
                }
                for region in dmar.regions() {
                    assert!(region.base <= region.limit, "seed {seed}");
                }
            }
        }
    }
}
