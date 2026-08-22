// SPDX-License-Identifier: Apache-2.0
// Adapted from the `xhci` crate, Copyright (c) 2021 Hiroki Tokunaga.
// Upstream: https://github.com/rust-osdev/xhci, version 0.9.2, MIT OR Apache-2.0.
//! Host Controller Capability Registers.
//!
//! Read-only, and the first thing a driver touches: they say how big the
//! machine is — how many slots, how many ports, how many interrupters — and
//! where the other two register banks begin. Nothing else can be found until
//! these are read.

use crate::{bit32, bits32};

/// Byte offsets from the start of the controller's MMIO window.
///
/// The window's base comes from the device's BAR 0. These are the only fixed
/// offsets in the whole controller: everything else is found relative to
/// [`CAPLENGTH`], [`DBOFF`] and [`RTSOFF`].
pub mod offset {
    /// `CAPLENGTH` — how long this bank is, and so where operational begins.
    pub const CAPLENGTH: usize = 0x00;
    /// `HCIVERSION` — BCD interface version.
    pub const HCIVERSION: usize = 0x02;
    /// `HCSPARAMS1` — slots, interrupters, ports.
    pub const HCSPARAMS1: usize = 0x04;
    /// `HCSPARAMS2` — scratchpad and event-ring sizing.
    pub const HCSPARAMS2: usize = 0x08;
    /// `HCSPARAMS3` — exit latencies.
    pub const HCSPARAMS3: usize = 0x0c;
    /// `HCCPARAMS1` — what this controller can do.
    pub const HCCPARAMS1: usize = 0x10;
    /// `DBOFF` — doorbell array, relative to the window base.
    pub const DBOFF: usize = 0x14;
    /// `RTSOFF` — runtime registers, relative to the window base.
    pub const RTSOFF: usize = 0x18;
    /// `HCCPARAMS2` — further capabilities.
    pub const HCCPARAMS2: usize = 0x1c;
}

/// `HCSPARAMS1`: how many of each thing this controller has.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StructuralParameters1(pub u32);

impl StructuralParameters1 {
    /// Device slots the controller supports. Bits 7:0.
    ///
    /// **A driver must not enable more than this**, and the number also sizes
    /// the device context base address array — one entry per slot, plus the
    /// entry at index zero that is the scratchpad pointer rather than a slot.
    #[must_use]
    pub const fn number_of_device_slots(self) -> u8 {
        bits32(self.0, 0, 7) as u8
    }

    /// Interrupters the controller supports. Bits 18:8.
    ///
    /// Eleven bits, not eight: the field crosses a byte boundary, which is the
    /// kind of thing a table transcribed carelessly gets wrong and a test
    /// catches.
    #[must_use]
    pub const fn number_of_interrupters(self) -> u16 {
        bits32(self.0, 8, 18) as u16
    }

    /// Root hub ports. Bits 31:24.
    #[must_use]
    pub const fn number_of_ports(self) -> u8 {
        bits32(self.0, 24, 31) as u8
    }
}

/// `HCSPARAMS2`: scratchpad sizing and event-ring limits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StructuralParameters2(pub u32);

impl StructuralParameters2 {
    /// Scratchpad buffers the controller wants. Bits 31:27 are the high five,
    /// bits 25:21 the low five.
    ///
    /// **Split across two ranges, high part first**, which is the single most
    /// error-prone field in this bank: read it as one contiguous range and a
    /// controller asking for 32 buffers is given 0, which fails later and
    /// somewhere else. The controller will not work without the buffers it
    /// asked for.
    #[must_use]
    pub const fn max_scratchpad_buffers(self) -> u32 {
        let high = bits32(self.0, 21, 25);
        let low = bits32(self.0, 27, 31);
        (high << 5) | low
    }

    /// Whether the scratchpad must survive a save/restore. Bit 26.
    #[must_use]
    pub const fn scratchpad_restore(self) -> bool {
        bit32(self.0, 26)
    }

    /// Event ring segment table maximum, as a power of two. Bits 7:4.
    #[must_use]
    pub const fn event_ring_segment_table_max(self) -> u32 {
        bits32(self.0, 4, 7)
    }
}

/// `HCCPARAMS1`: what this controller is capable of.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CapabilityParameters1(pub u32);

impl CapabilityParameters1 {
    /// Whether the controller can address 64 bits. Bit 0.
    ///
    /// If this is clear, every address handed to the controller — contexts,
    /// rings, buffers — must be below 4 GiB, which is an allocation constraint
    /// and not a detail to discover later.
    #[must_use]
    pub const fn addressing_capability_64(self) -> bool {
        bit32(self.0, 0)
    }

    /// Context size: `true` means 64-byte contexts, `false` 32-byte. Bit 2.
    ///
    /// **This multiplies every context offset in the whole driver.** Reading it
    /// wrong does not fail at boot; it puts each field at half or double its
    /// address, and the controller follows the pointers it finds there.
    #[must_use]
    pub const fn context_size_64(self) -> bool {
        bit32(self.0, 2)
    }

    /// Whether the controller supports port power control. Bit 3.
    #[must_use]
    pub const fn port_power_control(self) -> bool {
        bit32(self.0, 3)
    }

    /// Whether the controller supports a light reset. Bit 5.
    #[must_use]
    pub const fn light_hc_reset_capability(self) -> bool {
        bit32(self.0, 5)
    }

    /// Maximum primary stream array size, as an exponent. Bits 7:4 of the
    /// upper half — bits 15:12 of the register.
    #[must_use]
    pub const fn max_primary_stream_array_size(self) -> u32 {
        bits32(self.0, 12, 15)
    }

    /// Offset of the extended capability list, in **dwords** from the window
    /// base. Bits 31:16.
    ///
    /// Dwords, not bytes. Multiply by four before using it as an offset; this
    /// accessor deliberately does not, so that the unit is visible at the call
    /// site rather than hidden here.
    #[must_use]
    pub const fn extended_capabilities_pointer_dwords(self) -> u32 {
        bits32(self.0, 16, 31)
    }
}

/// The interface version, as binary-coded decimal.
///
/// `0x0110` is xHCI 1.1.0. Kept as the raw value rather than parsed, because a
/// driver compares it and does not display it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct InterfaceVersion(pub u16);

#[cfg(test)]
mod tests {
    use super::*;

    /// **The transcription test, and it is why this module has tests at all.**
    ///
    /// The offsets are asserted as literals here, written a second time. That
    /// is deliberate duplication: a constant compared against itself proves
    /// nothing, and the failure this guards is a digit slipped while copying a
    /// table. Two independent transcriptions disagreeing is the only signal
    /// available without hardware.
    #[test]
    fn every_capability_register_is_where_the_specification_puts_it() {
        assert_eq!(offset::CAPLENGTH, 0x00);
        assert_eq!(offset::HCIVERSION, 0x02);
        assert_eq!(offset::HCSPARAMS1, 0x04);
        assert_eq!(offset::HCSPARAMS2, 0x08);
        assert_eq!(offset::HCSPARAMS3, 0x0c);
        assert_eq!(offset::HCCPARAMS1, 0x10);
        assert_eq!(offset::DBOFF, 0x14);
        assert_eq!(offset::RTSOFF, 0x18);
        assert_eq!(offset::HCCPARAMS2, 0x1c);
    }

    #[test]
    fn the_offsets_are_ordered_and_do_not_overlap() {
        // Every register in this bank is four bytes except CAPLENGTH and
        // HCIVERSION, which share the first dword. A table that had two
        // registers at one offset would pass the literal test above if both
        // literals were wrong the same way; this one would not.
        let dwords = [
            offset::HCSPARAMS1,
            offset::HCSPARAMS2,
            offset::HCSPARAMS3,
            offset::HCCPARAMS1,
            offset::DBOFF,
            offset::RTSOFF,
            offset::HCCPARAMS2,
        ];
        for pair in dwords.windows(2) {
            assert_eq!(pair[1] - pair[0], 4, "gap between {pair:?}");
        }
        // The first dword is shared by CAPLENGTH and HCIVERSION; their order
        // is pinned by the literal test above, and asserting it again here
        // would only be two constants agreeing with each other.
    }

    #[test]
    fn structural_parameters_1_splits_into_three_fields() {
        // 32 slots, 8 interrupters, 4 ports.
        let raw = 32 | (8 << 8) | (4 << 24);
        let p = StructuralParameters1(raw);
        assert_eq!(p.number_of_device_slots(), 32);
        assert_eq!(p.number_of_interrupters(), 8);
        assert_eq!(p.number_of_ports(), 4);
    }

    #[test]
    fn the_interrupter_count_uses_all_eleven_of_its_bits() {
        // 1024 needs bit 18. A field transcribed as 8 bits wide would read 0
        // here, and a controller with more than 255 interrupters is not
        // hypothetical on server parts.
        let p = StructuralParameters1(1024 << 8);
        assert_eq!(p.number_of_interrupters(), 1024);
    }

    #[test]
    fn the_scratchpad_count_is_assembled_from_two_ranges() {
        // High five bits at 21..=25, low five at 27..=31. 33 is 0b100001:
        // high = 1, low = 1.
        let raw = (1 << 21) | (1 << 27);
        assert_eq!(StructuralParameters2(raw).max_scratchpad_buffers(), 33);

        // And the maximum: both halves all ones is 1023.
        let raw = (0b11111 << 21) | (0b11111 << 27);
        assert_eq!(StructuralParameters2(raw).max_scratchpad_buffers(), 1023);
    }

    #[test]
    fn the_scratchpad_count_does_not_swallow_the_restore_bit() {
        // Bit 26 sits *between* the two halves. A range read as 21..=31 would
        // fold it into the count.
        let raw = 1 << 26;
        assert_eq!(StructuralParameters2(raw).max_scratchpad_buffers(), 0);
        assert!(StructuralParameters2(raw).scratchpad_restore());
    }

    #[test]
    fn capability_parameters_1_reads_the_bits_a_driver_acts_on() {
        let p = CapabilityParameters1(0b101);
        assert!(p.addressing_capability_64());
        assert!(p.context_size_64());
        assert!(!p.port_power_control());

        let p = CapabilityParameters1(0xabcd_0000);
        assert_eq!(p.extended_capabilities_pointer_dwords(), 0xabcd);
    }

    #[test]
    fn context_size_is_bit_two_and_not_bit_one() {
        // Bit 1 is BW negotiation. Confusing the two changes every context
        // offset in the driver, and does it silently.
        assert!(!CapabilityParameters1(0b010).context_size_64());
        assert!(CapabilityParameters1(0b100).context_size_64());
    }
}
