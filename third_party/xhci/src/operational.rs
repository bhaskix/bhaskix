// SPDX-License-Identifier: Apache-2.0
// Adapted from the `xhci` crate, Copyright (c) 2021 Hiroki Tokunaga.
// Upstream: https://github.com/rust-osdev/xhci, version 0.9.2, MIT OR Apache-2.0.
//! Host Controller Operational Registers, and the port register sets.
//!
//! These are how a driver starts, stops and steers the controller. They begin
//! at `CAPLENGTH` bytes past the window base — the capability bank's own length
//! is the only way to find them.

use crate::{bit32, bits32, bits64};

/// Byte offsets from the **start of the operational bank**, which is the window
/// base plus `CAPLENGTH`.
pub mod offset {
    /// `USBCMD` — run/stop, reset, interrupt enable.
    pub const USBCMD: usize = 0x00;
    /// `USBSTS` — halted, not-ready, errors, and the change bits.
    pub const USBSTS: usize = 0x04;
    /// `PAGESIZE` — the page size the controller uses, as a bitmap.
    pub const PAGESIZE: usize = 0x08;
    /// `DNCTRL` — device notification control.
    pub const DNCTRL: usize = 0x14;
    /// `CRCR` — command ring control. 64-bit.
    pub const CRCR: usize = 0x18;
    /// `DCBAAP` — device context base address array pointer. 64-bit.
    pub const DCBAAP: usize = 0x30;
    /// `CONFIG` — how many slots are enabled.
    pub const CONFIG: usize = 0x38;
    /// Where the per-port register sets begin, relative to this bank.
    pub const PORT_REGISTERS: usize = 0x400;
    /// Bytes per port register set: `PORTSC`, `PORTPMSC`, `PORTLI`, `PORTHLPMC`.
    pub const PORT_REGISTER_STRIDE: usize = 0x10;
}

/// Offset of port `number`'s `PORTSC`, relative to the operational bank.
///
/// **Ports are numbered from one**, as the specification numbers them, and this
/// function takes that numbering. Passing a zero-based index reads the register
/// set *before* the array — inside `CONFIG`'s neighbourhood — which is why this
/// exists rather than leaving the arithmetic at each call site.
///
/// Answers `None` for port zero, which does not exist.
#[must_use]
pub const fn port_status_control(number: u8) -> Option<usize> {
    if number == 0 {
        return None;
    }
    Some(offset::PORT_REGISTERS + offset::PORT_REGISTER_STRIDE * (number as usize - 1))
}

/// `USBCMD`: what the controller should be doing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UsbCommand(pub u32);

impl UsbCommand {
    /// Bit 0. Set to run, clear to stop.
    #[must_use]
    pub const fn run_stop(self) -> bool {
        bit32(self.0, 0)
    }

    /// Bit 1. Writing one resets the controller; it self-clears when done.
    #[must_use]
    pub const fn host_controller_reset(self) -> bool {
        bit32(self.0, 1)
    }

    /// Bit 2. The controller raises interrupts only while this is set.
    #[must_use]
    pub const fn interrupter_enable(self) -> bool {
        bit32(self.0, 2)
    }

    /// Bit 3. Report host system errors.
    #[must_use]
    pub const fn host_system_error_enable(self) -> bool {
        bit32(self.0, 3)
    }

    /// With [`run_stop`](Self::run_stop) set or cleared.
    #[must_use]
    pub const fn with_run_stop(self, run: bool) -> Self {
        Self(if run { self.0 | 1 } else { self.0 & !1 })
    }

    /// With the reset bit set.
    #[must_use]
    pub const fn with_host_controller_reset(self) -> Self {
        Self(self.0 | (1 << 1))
    }

    /// With interrupts enabled or disabled.
    #[must_use]
    pub const fn with_interrupter_enable(self, enable: bool) -> Self {
        Self(if enable {
            self.0 | (1 << 2)
        } else {
            self.0 & !(1 << 2)
        })
    }
}

/// `USBSTS`: what the controller is doing, and what has happened.
///
/// **Bits 2, 3, 4 and 10 are write-one-to-clear.** See
/// [`UsbStatus::acknowledging`], which exists because the obvious way to clear
/// one of them clears the others too.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UsbStatus(pub u32);

impl UsbStatus {
    /// Bit 0, read-only. The controller has stopped.
    #[must_use]
    pub const fn hc_halted(self) -> bool {
        bit32(self.0, 0)
    }

    /// Bit 2, write-one-to-clear. A host system error occurred.
    #[must_use]
    pub const fn host_system_error(self) -> bool {
        bit32(self.0, 2)
    }

    /// Bit 3, write-one-to-clear. An interrupt is pending.
    #[must_use]
    pub const fn event_interrupt(self) -> bool {
        bit32(self.0, 3)
    }

    /// Bit 4, write-one-to-clear. A port changed state.
    #[must_use]
    pub const fn port_change_detect(self) -> bool {
        bit32(self.0, 4)
    }

    /// Bit 10, write-one-to-clear. Save or restore failed.
    #[must_use]
    pub const fn save_restore_error(self) -> bool {
        bit32(self.0, 10)
    }

    /// Bit 11, read-only. **The controller is not ready to be touched.**
    ///
    /// Set after a reset and cleared when the controller is willing to answer.
    /// Writing any operational register while this is set is undefined, and the
    /// specification says so — so a driver waits on this bit rather than on a
    /// delay.
    #[must_use]
    pub const fn controller_not_ready(self) -> bool {
        bit32(self.0, 11)
    }

    /// Bit 12, read-only. The controller has failed internally.
    #[must_use]
    pub const fn host_controller_error(self) -> bool {
        bit32(self.0, 12)
    }

    /// Every write-one-to-clear bit in this register.
    pub const WRITE_ONE_TO_CLEAR: u32 = (1 << 2) | (1 << 3) | (1 << 4) | (1 << 10);

    /// The value to write to acknowledge exactly `bits` and nothing else.
    ///
    /// **This is the whole reason this type is not a bare `u32`.** The obvious
    /// way to clear one status bit is to read the register, set the bit and
    /// write it back — and that clears *every* write-one-to-clear bit that
    /// happened to be set, including events that arrived between the read and
    /// the write. The events do not come back. What it looks like afterwards is
    /// a controller that intermittently stops reporting port changes, which is
    /// a hard bug to find from the symptom.
    ///
    /// So an acknowledgement is built from nothing rather than from the value
    /// read: only the requested bits, and every non-clearing bit left at zero
    /// where it has no effect.
    #[must_use]
    pub const fn acknowledging(bits: u32) -> u32 {
        bits & Self::WRITE_ONE_TO_CLEAR
    }
}

/// `CRCR`: where the command ring is, and what to do with it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CommandRingControl(pub u64);

impl CommandRingControl {
    /// Bit 0. The cycle state the controller expects next.
    #[must_use]
    pub const fn ring_cycle_state(self) -> bool {
        self.0 & 1 != 0
    }

    /// Bit 3, read-only. The command ring is running.
    #[must_use]
    pub const fn command_ring_running(self) -> bool {
        self.0 & (1 << 3) != 0
    }

    /// Bits 63:6 — the ring's physical address, which is 64-byte aligned.
    ///
    /// The low six bits are flags, not address, so the pointer is returned
    /// already shifted back into place rather than as a field.
    #[must_use]
    pub const fn pointer(self) -> u64 {
        bits64(self.0, 6, 63) << 6
    }

    /// A `CRCR` value pointing at `address` with the given cycle state.
    ///
    /// # Errors
    ///
    /// `None` if `address` is not 64-byte aligned. **A misaligned ring pointer
    /// is not rejected by the controller** — the low bits are read as flags, so
    /// the address is silently truncated and the flags silently set. Refusing
    /// here is the only place it can be caught.
    #[must_use]
    pub const fn with_pointer(address: u64, cycle: bool) -> Option<Self> {
        if address & 0x3f != 0 {
            return None;
        }
        Some(Self(address | if cycle { 1 } else { 0 }))
    }
}

/// `DCBAAP`: where the device context base address array is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceContextBaseAddressArrayPointer(pub u64);

impl DeviceContextBaseAddressArrayPointer {
    /// Bits 63:6 — the array's physical address, 64-byte aligned.
    #[must_use]
    pub const fn pointer(self) -> u64 {
        bits64(self.0, 6, 63) << 6
    }

    /// A pointer value for `address`.
    ///
    /// # Errors
    ///
    /// `None` if `address` is not 64-byte aligned, for the same reason as
    /// [`CommandRingControl::with_pointer`].
    #[must_use]
    pub const fn with_pointer(address: u64) -> Option<Self> {
        if address & 0x3f != 0 {
            return None;
        }
        Some(Self(address))
    }
}

/// `CONFIG`: how many device slots the driver is asking for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Configure(pub u32);

impl Configure {
    /// Bits 7:0 — slots enabled.
    #[must_use]
    pub const fn max_device_slots_enabled(self) -> u8 {
        bits32(self.0, 0, 7) as u8
    }

    /// With `slots` enabled.
    ///
    /// **The caller must have checked this against `HCSPARAMS1`.** Asking for
    /// more slots than the controller has is not refused by the hardware; it
    /// sizes the device context array the driver then allocates, and a driver
    /// that asks for more than it allocates hands the controller an array it
    /// will index past.
    #[must_use]
    pub const fn with_max_device_slots_enabled(self, slots: u8) -> Self {
        Self((self.0 & !0xff) | slots as u32)
    }
}

/// `PORTSC`: one root hub port's state.
///
/// **Six of these bits are write-one-to-clear**, and this register is the one
/// where getting that wrong actually loses events, because port changes are how
/// a device announces itself. See [`PortStatusControl::preserving`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PortStatusControl(pub u32);

impl PortStatusControl {
    /// Bit 0, read-only. Something is plugged in.
    #[must_use]
    pub const fn current_connect_status(self) -> bool {
        bit32(self.0, 0)
    }

    /// Bit 1. The port is enabled.
    #[must_use]
    pub const fn port_enabled(self) -> bool {
        bit32(self.0, 1)
    }

    /// Bit 3, read-only. The port is drawing too much current.
    #[must_use]
    pub const fn over_current_active(self) -> bool {
        bit32(self.0, 3)
    }

    /// Bit 4. Writing one resets the port.
    #[must_use]
    pub const fn port_reset(self) -> bool {
        bit32(self.0, 4)
    }

    /// Bits 8:5 — the link state.
    #[must_use]
    pub const fn port_link_state(self) -> u32 {
        bits32(self.0, 5, 8)
    }

    /// Bit 9. Port power.
    #[must_use]
    pub const fn port_power(self) -> bool {
        bit32(self.0, 9)
    }

    /// Bits 13:10, read-only — the negotiated speed.
    ///
    /// Zero means undefined, which a driver must treat as "not ready" rather
    /// than as a speed.
    #[must_use]
    pub const fn port_speed(self) -> u32 {
        bits32(self.0, 10, 13)
    }

    /// Bit 17, write-one-to-clear. The connect status changed.
    #[must_use]
    pub const fn connect_status_change(self) -> bool {
        bit32(self.0, 17)
    }

    /// Bit 21, write-one-to-clear. A reset finished.
    #[must_use]
    pub const fn port_reset_change(self) -> bool {
        bit32(self.0, 21)
    }

    /// Bit 22, write-one-to-clear. The link state changed.
    #[must_use]
    pub const fn port_link_state_change(self) -> bool {
        bit32(self.0, 22)
    }

    /// Every write-one-to-clear bit in `PORTSC`.
    ///
    /// Connect status, port enable, warm reset, over-current, reset, link
    /// state and config error changes — bits 17 through 23 — plus bit 1, which
    /// is write-one-to-*disable* and is just as destructive to write back.
    pub const WRITE_ONE_TO_CLEAR: u32 = (1 << 1)
        | (1 << 17)
        | (1 << 18)
        | (1 << 19)
        | (1 << 20)
        | (1 << 21)
        | (1 << 22)
        | (1 << 23);

    /// This value with every write-one-to-clear bit masked off.
    ///
    /// **Use this for every read-modify-write of `PORTSC`.** Writing back a
    /// value read from the register clears every change bit that was set and
    /// disables the port into the bargain, because bit 1 is write-one-to-clear
    /// too. The symptom is a port that works once and then never reports
    /// another device.
    #[must_use]
    pub const fn preserving(self) -> Self {
        Self(self.0 & !Self::WRITE_ONE_TO_CLEAR)
    }

    /// This value with the change bits in `bits` acknowledged and nothing else
    /// disturbed.
    #[must_use]
    pub const fn acknowledging(self, bits: u32) -> Self {
        Self(self.preserving().0 | (bits & Self::WRITE_ONE_TO_CLEAR))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The transcription test, as in `capability`: the offsets written a second
    /// time, so a slipped digit disagrees with itself.
    #[test]
    fn every_operational_register_is_where_the_specification_puts_it() {
        assert_eq!(offset::USBCMD, 0x00);
        assert_eq!(offset::USBSTS, 0x04);
        assert_eq!(offset::PAGESIZE, 0x08);
        assert_eq!(offset::DNCTRL, 0x14);
        assert_eq!(offset::CRCR, 0x18);
        assert_eq!(offset::DCBAAP, 0x30);
        assert_eq!(offset::CONFIG, 0x38);
        assert_eq!(offset::PORT_REGISTERS, 0x400);
        assert_eq!(offset::PORT_REGISTER_STRIDE, 0x10);
    }

    #[test]
    fn ports_are_numbered_from_one() {
        // Port 1 is the first set, not the second.
        assert_eq!(port_status_control(1), Some(0x400));
        assert_eq!(port_status_control(2), Some(0x410));
        assert_eq!(port_status_control(255), Some(0x400 + 0x10 * 254));
        // And port zero does not exist. A zero-based caller reading
        // `0x400 - 0x10` would land on other registers entirely.
        assert_eq!(port_status_control(0), None);
    }

    #[test]
    fn usb_command_bits_round_trip() {
        let c = UsbCommand(0)
            .with_run_stop(true)
            .with_interrupter_enable(true);
        assert!(c.run_stop());
        assert!(c.interrupter_enable());
        assert!(!c.host_controller_reset());
        assert!(!c.with_run_stop(false).run_stop());
    }

    #[test]
    fn controller_not_ready_is_bit_eleven() {
        // Waited on after every reset. Reading the wrong bit here means
        // touching a controller that is not ready, which is undefined rather
        // than merely early.
        assert!(UsbStatus(1 << 11).controller_not_ready());
        assert!(!UsbStatus(!(1 << 11)).controller_not_ready());
    }

    /// **The write-one-to-clear test for `USBSTS`.**
    #[test]
    fn acknowledging_a_status_bit_does_not_acknowledge_the_others() {
        // Every clearable bit set, as a busy controller would show.
        let busy = (1 << 2) | (1 << 3) | (1 << 4) | (1 << 10);
        // Acknowledge only the event interrupt.
        let write = UsbStatus::acknowledging(1 << 3);
        assert_eq!(write, 1 << 3);
        // The others are not in the written value, so they survive.
        assert_eq!(write & busy & !(1 << 3), 0);
    }

    #[test]
    fn acknowledging_cannot_write_a_bit_that_is_not_clearable() {
        // A caller passing the whole register back must not set read-only or
        // control bits. Only the four clearable ones survive -- named as
        // literals rather than as the constant, for the reason the PORTSC test
        // below gives at length.
        assert_eq!(
            UsbStatus::acknowledging(!0),
            (1 << 2) | (1 << 3) | (1 << 4) | (1 << 10)
        );
    }

    #[test]
    fn a_ring_pointer_must_be_sixty_four_byte_aligned() {
        assert!(CommandRingControl::with_pointer(0x1_0000, true).is_some());
        // 32-byte aligned is not enough: the low six bits are flags, so this
        // address would be truncated and two flags silently set.
        assert!(CommandRingControl::with_pointer(0x1_0020, false).is_none());
        assert!(DeviceContextBaseAddressArrayPointer::with_pointer(0x1_0008).is_none());
    }

    #[test]
    fn a_ring_pointer_reads_back_as_the_address_it_was_given() {
        let c = CommandRingControl::with_pointer(0xdead_be00, true).expect("aligned");
        assert_eq!(c.pointer(), 0xdead_be00);
        assert!(c.ring_cycle_state());
    }

    /// **The one that would have cost a port.**
    #[test]
    fn preserving_portsc_does_not_clear_change_bits_or_disable_the_port() {
        // A port with a device attached, enabled, and three changes pending.
        let raw = 1 | (1 << 1) | (1 << 17) | (1 << 21) | (1 << 22);
        let read = PortStatusControl(raw);
        assert!(read.current_connect_status());
        assert!(read.port_enabled());
        assert!(read.connect_status_change());

        // Written back naively, this would clear all three changes *and*
        // disable the port, because bit 1 is write-one-to-clear.
        let safe = read.preserving();

        // **Asserted against literal bit positions, not against
        // `WRITE_ONE_TO_CLEAR`.** The first version of this test masked with
        // that constant, which meant the constant was compared against itself:
        // deleting bit 1 from it made `preserving` stop protecting the port
        // *and* made the test stop checking, and the suite stayed green. A
        // constant is not evidence about itself.
        assert_eq!(safe.0 & (1 << 1), 0, "the port would have been disabled");
        assert_eq!(safe.0 & (1 << 17), 0, "connect change would have been lost");
        assert_eq!(safe.0 & (1 << 18), 0);
        assert_eq!(safe.0 & (1 << 19), 0);
        assert_eq!(safe.0 & (1 << 20), 0);
        assert_eq!(safe.0 & (1 << 21), 0, "reset change would have been lost");
        assert_eq!(safe.0 & (1 << 22), 0, "link change would have been lost");
        assert_eq!(safe.0 & (1 << 23), 0);
        // What is not clearable survives untouched.
        assert!(safe.current_connect_status());
    }

    #[test]
    fn acknowledging_portsc_clears_exactly_what_was_asked_for() {
        let raw = 1 | (1 << 17) | (1 << 21);
        let write = PortStatusControl(raw).acknowledging(1 << 17);
        // The requested change is written...
        assert!(write.connect_status_change());
        // ...and the other one is not, so it is still pending afterwards.
        assert!(!write.port_reset_change());
        // Read-only state is carried through so the write does not disturb it.
        assert!(write.current_connect_status());
    }

    #[test]
    fn slots_enabled_replaces_rather_than_accumulates() {
        let c = Configure(0xff).with_max_device_slots_enabled(4);
        assert_eq!(c.max_device_slots_enabled(), 4);
    }
}
