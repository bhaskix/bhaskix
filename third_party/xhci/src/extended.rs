// SPDX-License-Identifier: Apache-2.0
//! xHCI Extended Capabilities, and the one that matters before anything else.
//!
//! A controller's capability bank ends with a pointer to a linked list of
//! optional capabilities (specification §7, Table 7-1). This driver walks it
//! for exactly one of them: **USB Legacy Support** (§7.1), the register pair
//! through which firmware hands the controller to an operating system.
//!
//! That handoff is not optional on a server. Firmware drives the xHC to offer a
//! USB keyboard and a virtual CD, and it does so from System Management Mode,
//! having asked the controller to raise an SMI on the events it cares about. A
//! driver that starts the controller without taking ownership does not race
//! firmware for a device — it wakes firmware's SMI handler on a controller
//! firmware no longer understands. The specification is blunt about the
//! consequence (§4.22.1):
//!
//! > Failure to do so will result in two software agents believing they each
//! > have exclusive ownership of the xHC and attempt to use the controller
//! > concurrently.
//!
//! Everything here is arithmetic on register values, so all of it is tested on
//! the host. The MMIO belongs to the caller.

use crate::{bit32, bits32};

/// Capability ID of USB Legacy Support (Table 7-2).
pub const LEGACY_SUPPORT: u32 = 1;

/// Byte offset of `USBLEGCTLSTS` from the start of `USBLEGSUP` (§7.1.1):
/// *"this register is located at offset xECP+04h"*.
pub const CONTROL_OFFSET: usize = 0x04;

/// How many list entries to walk before deciding the list is malformed.
///
/// A next-pointer of zero ends the list, so a well-formed list terminates. A
/// controller that returns garbage — or all-ones, which a window read past the
/// end of a device produces — describes a list that never does. This is the
/// bound that turns that into a refusal instead of a hang.
pub const MAX_CAPABILITIES: usize = 64;

/// The dword every extended capability starts with (Table 7-1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CapabilityHeader(pub u32);

impl CapabilityHeader {
    /// Which capability this is. Bits 7:0.
    #[must_use]
    pub const fn id(self) -> u32 {
        bits32(self.0, 0, 7)
    }

    /// Distance to the next capability, **in dwords from this one**. Bits 15:8.
    ///
    /// Dwords relative to *here*, not to the window base: the specification's
    /// own worked example is `350h + (068h << 2) -> 4F0h`. Zero ends the list.
    #[must_use]
    pub const fn next_dwords(self) -> u32 {
        bits32(self.0, 8, 15)
    }
}

/// `USBLEGSUP` — the ownership semaphores (Table 7-4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LegacySupport(pub u32);

impl LegacySupport {
    /// Whether firmware claims the controller. Bit 16.
    #[must_use]
    pub const fn bios_owned(self) -> bool {
        bit32(self.0, 16)
    }

    /// Whether this driver has claimed the controller. Bit 24.
    #[must_use]
    pub const fn os_owned(self) -> bool {
        bit32(self.0, 24)
    }

    /// The same register with this driver's claim staked.
    ///
    /// Sets one bit and preserves the rest, because the other semaphore belongs
    /// to firmware and may change underneath this read-modify-write. The
    /// specification puts the two in adjacent bytes precisely so that neither
    /// agent has to overwrite the other's.
    #[must_use]
    pub const fn requesting(self) -> Self {
        Self(self.0 | (1 << 24))
    }

    /// Whether ownership is *held*, which takes both bits (§7.1.1):
    /// *"Ownership is obtained when this bit reads as '1' and the HC BIOS Owned
    /// Semaphore bit reads as '0'."*
    ///
    /// Asking for it is not having it. The wait between the two is what the
    /// whole protocol is.
    #[must_use]
    pub const fn owned_by_us(self) -> bool {
        self.os_owned() && !self.bios_owned()
    }
}

/// `USBLEGCTLSTS` — which xHC events firmware asked to be told about (Table 7-5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LegacyControlStatus(pub u32);

impl LegacyControlStatus {
    /// The reserved-preserve fields: bits 3:1, 12:5 and 19:17.
    ///
    /// `RsvdP` means read them, write them back unchanged. Everything outside
    /// this mask is either an SMI enable this driver is turning off, a
    /// read-only shadow of `USBSTS` that ignores writes, or `RsvdZ` at 28:21,
    /// which is written zero.
    const RESERVED_PRESERVE: u32 = (0x7 << 1) | (0xff << 5) | (0x7 << 17);

    /// The write-one-to-clear status bits: 31:29 — SMI on OS Ownership Change,
    /// on PCI Command, and on BAR.
    const WRITE_ONE_TO_CLEAR: u32 = 0x7 << 29;

    /// Whether firmware has *any* SMI source enabled here.
    ///
    /// Bits 0, 4, 13, 14 and 15 are the five enables in Table 7-5. Reported
    /// rather than merely acted on: a machine where this reads non-zero is one
    /// where skipping the handoff would have been fatal, and that is worth
    /// saying out loud in a boot report rather than silently fixing.
    #[must_use]
    pub const fn smi_enabled(self) -> bool {
        self.0 & ((1 << 0) | (1 << 4) | (1 << 13) | (1 << 14) | (1 << 15)) != 0
    }

    /// The value to write back: every SMI enable off, every latched status
    /// acknowledged, every reserved-preserve field carried through.
    ///
    /// Taking the semaphore is not enough on its own. Firmware may have asked
    /// for an SMI on *event interrupt* — which is to say, on the controller
    /// doing anything at all — and that request outlives the handoff because it
    /// lives in the controller, not in firmware.
    #[must_use]
    pub const fn quietened(self) -> Self {
        Self((self.0 & Self::RESERVED_PRESERVE) | Self::WRITE_ONE_TO_CLEAR)
    }
}

/// Where the next capability begins, given where this one is and its header.
///
/// `None` ends the list — either because the pointer is zero, or because
/// following it would leave `window`, which a truthful controller never asks
/// for and a broken one asks for constantly.
#[must_use]
pub const fn next_capability(
    here: usize,
    header: CapabilityHeader,
    window: usize,
) -> Option<usize> {
    let next = header.next_dwords() as usize;
    if next == 0 {
        return None;
    }
    let there = here + (next << 2);
    // The header itself must be readable, or there is nothing there to walk.
    if there + 4 > window {
        return None;
    }
    Some(there)
}

/// Where the capability list starts, given `HCCPARAMS1`'s pointer in dwords.
///
/// `None` means the controller declares no extended capabilities at all —
/// which is what an emulator typically says, and is why this whole path can be
/// dead on a virtual machine and load-bearing on a real one.
#[must_use]
pub const fn first_capability(pointer_dwords: u32, window: usize) -> Option<usize> {
    if pointer_dwords == 0 {
        return None;
    }
    let at = (pointer_dwords as usize) << 2;
    if at + 4 > window {
        return None;
    }
    Some(at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_splits_id_from_the_next_pointer() {
        let header = CapabilityHeader(0x0000_6801);
        assert_eq!(header.id(), LEGACY_SUPPORT);
        assert_eq!(header.next_dwords(), 0x68);
    }

    #[test]
    fn the_next_pointer_is_dwords_from_here_not_from_the_base() {
        // The specification's own worked example, §7 Table 7-1: an effective
        // address of 350h and a pointer of 068h gives 4F0h. Reading the
        // pointer as bytes, or as relative to the window base, both give
        // something else -- and both find a capability that is not there.
        let header = CapabilityHeader(0x0000_6800);
        assert_eq!(next_capability(0x350, header, 0x1000), Some(0x4f0));
    }

    #[test]
    fn a_zero_next_pointer_ends_the_list() {
        assert_eq!(
            next_capability(0x350, CapabilityHeader(0x0000_0001), 0x1000),
            None
        );
    }

    #[test]
    fn a_capability_past_the_window_is_not_followed() {
        // All-ones is what a read off the end of a device's window returns.
        // Followed literally it walks 1020 bytes at a time through whatever is
        // mapped next.
        let header = CapabilityHeader(0xffff_ffff);
        assert_eq!(next_capability(0xf00, header, 0x1000), None);
    }

    #[test]
    fn the_first_capability_is_dwords_from_the_window_base() {
        assert_eq!(first_capability(0x100, 0x1000), Some(0x400));
        assert_eq!(
            first_capability(0, 0x1000),
            None,
            "no extended capabilities"
        );
        assert_eq!(first_capability(0x800, 0x1000), None, "outside the window");
    }

    #[test]
    fn ownership_needs_both_semaphores_not_one() {
        // Asking is not having: this is the state the driver sits in while it
        // waits, and treating it as ownership is the bug the wait exists to
        // prevent.
        let asked = LegacySupport(1 << 24 | 1 << 16);
        assert!(asked.os_owned());
        assert!(asked.bios_owned());
        assert!(!asked.owned_by_us());

        let granted = LegacySupport(1 << 24);
        assert!(granted.owned_by_us());

        // Firmware gone but never asked: also not ours.
        assert!(!LegacySupport(0).owned_by_us());
    }

    #[test]
    fn requesting_sets_only_our_semaphore() {
        // Bit 16 is firmware's and must survive the read-modify-write, along
        // with the capability header in the low half.
        let before = LegacySupport(0x0001_6801);
        let after = before.requesting();
        assert!(after.os_owned());
        assert!(after.bios_owned(), "firmware's semaphore was cleared");
        assert_eq!(after.0 & 0xffff, 0x6801, "the header was damaged");
    }

    #[test]
    fn quietening_clears_every_enable_and_acknowledges_every_latch() {
        // Every SMI enable in Table 7-5 set, and a reserved-preserve bit in
        // each of the three ranges.
        let firmware = LegacyControlStatus(
            (1 << 0)
                | (1 << 4)
                | (1 << 13)
                | (1 << 14)
                | (1 << 15)
                | (1 << 2)
                | (1 << 7)
                | (1 << 18),
        );
        assert!(firmware.smi_enabled());

        let ours = firmware.quietened();
        assert_eq!(ours.0 & (1 << 0), 0, "USB SMI Enable");
        assert_eq!(ours.0 & (1 << 4), 0, "SMI on Host System Error Enable");
        assert_eq!(ours.0 & (1 << 13), 0, "SMI on OS Ownership Enable");
        assert_eq!(ours.0 & (1 << 14), 0, "SMI on PCI Command Enable");
        assert_eq!(ours.0 & (1 << 15), 0, "SMI on BAR Enable");
        assert!(!ours.smi_enabled());

        assert_eq!(ours.0 & (1 << 2), 1 << 2, "RsvdP 3:1 not preserved");
        assert_eq!(ours.0 & (1 << 7), 1 << 7, "RsvdP 12:5 not preserved");
        assert_eq!(ours.0 & (1 << 18), 1 << 18, "RsvdP 19:17 not preserved");

        assert_eq!(
            ours.0 >> 29,
            0b111,
            "the RW1C latches were not acknowledged"
        );
    }

    #[test]
    fn quietening_writes_zero_to_the_rsvdz_range() {
        // 28:21 is RsvdZ, not RsvdP: written zero, not carried through.
        let ours = LegacyControlStatus(0xff << 21).quietened();
        assert_eq!(ours.0 & (0xff << 21), 0);
    }

    #[test]
    fn every_enable_in_table_7_5_counts_on_its_own() {
        // One at a time, because a test that sets all five at once still
        // passes when the check has lost three of them -- which is exactly
        // what the first version of this file did.
        for (bit, name) in [
            (0, "USB SMI Enable"),
            (4, "SMI on Host System Error Enable"),
            (13, "SMI on OS Ownership Enable"),
            (14, "SMI on PCI Command Enable"),
            (15, "SMI on BAR Enable"),
        ] {
            assert!(
                LegacyControlStatus(1 << bit).smi_enabled(),
                "{name} (bit {bit}) is not counted as an SMI source"
            );
        }
    }

    #[test]
    fn a_controller_with_no_smi_enables_is_reported_as_such() {
        // The emulator's case, and the reason this whole path went untested
        // for as long as it did.
        assert!(!LegacyControlStatus(0).smi_enabled());
    }
}
