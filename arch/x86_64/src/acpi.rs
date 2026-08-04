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

/// Finds the MADT by walking the RSDP and the table it points at.
///
/// # Safety
///
/// `rsdp` must be the physical address the bootloader reported, and `hhdm` the
/// direct map base. Both come from the handoff; nothing else may pass an
/// address here. `ensure` must map what it claims to map.
#[must_use]
pub unsafe fn madt(rsdp: u64, hhdm: u64, ensure: EnsureMapped<'_>) -> Option<Madt> {
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
            && let Some(madt) = parse_madt(table)
        {
            return Some(madt);
        }
    }
    None
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
}
