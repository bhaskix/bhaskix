// SPDX-License-Identifier: Apache-2.0
//! The eight bytes that begin a control transfer.
//!
//! [RFC 0041](../../docs/rfc/0041-a-usb-keyboard.md). Everything a driver asks
//! a device before it can read reports — what are you, how are you configured,
//! speak the boot protocol — is one of these, and each is eight bytes of
//! little-endian fields with a bitmap on the front.
//!
//! They are built here, away from the driver, for the same reason the
//! descriptors are parsed here: a wrong field in a setup packet does not fail
//! loudly, it asks the device a different question and gets a plausible answer
//! to it. That is a mistake worth having tests for, and tests are cheaper here.

/// Bytes in a setup packet.
pub const BYTES: usize = 8;

/// `bmRequestType` bit 7: the data stage goes device-to-host.
const DEVICE_TO_HOST: u8 = 0x80;
/// `bmRequestType` bits 6:5 = 1: a class request rather than a standard one.
const CLASS: u8 = 0x20;
/// `bmRequestType` bits 4:0 = 1: addressed to an interface, not the device.
const INTERFACE: u8 = 0x01;

/// Standard request codes this crate uses.
pub mod request {
    /// Ask for a descriptor.
    pub const GET_DESCRIPTOR: u8 = 6;
    /// Select a configuration.
    pub const SET_CONFIGURATION: u8 = 9;
    /// HID: how often to resend unchanged reports.
    pub const SET_IDLE: u8 = 0x0a;
    /// HID: report protocol, or boot protocol.
    pub const SET_PROTOCOL: u8 = 0x0b;
}

/// The HID protocol values.
pub mod protocol {
    /// **Boot protocol is zero**, which is the unintuitive half: the richer,
    /// report-descriptor-driven mode is 1, and the simple fixed-layout mode a
    /// firmware can drive is 0. A driver that sends 1 meaning "the simple one"
    /// gets a keyboard whose reports it cannot parse.
    pub const BOOT: u16 = 0;
    /// Report protocol: the device's own layout, described by a report
    /// descriptor this kernel does not parse.
    pub const REPORT: u16 = 1;
}

/// A setup packet, as the eight bytes that go on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Setup(pub [u8; BYTES]);

impl Setup {
    const fn new(request_type: u8, request: u8, value: u16, index: u16, length: u16) -> Self {
        Self([
            request_type,
            request,
            value as u8,
            (value >> 8) as u8,
            index as u8,
            (index >> 8) as u8,
            length as u8,
            (length >> 8) as u8,
        ])
    }

    /// Whether the data stage flows device-to-host.
    ///
    /// The driver needs this to build the transfer's data stage the right way
    /// round, and getting it wrong means asking the device to read a buffer the
    /// driver meant it to write.
    #[must_use]
    pub const fn is_device_to_host(&self) -> bool {
        self.0[0] & DEVICE_TO_HOST != 0
    }

    /// `wLength` — how many bytes the data stage carries.
    #[must_use]
    pub const fn length(&self) -> u16 {
        self.0[6] as u16 | ((self.0[7] as u16) << 8)
    }

    /// Ask for a descriptor.
    ///
    /// **The type goes in the high byte of `wValue` and the index in the low
    /// one**, which is the field most easily written back to front — and a
    /// swapped pair asks for descriptor index 1 of type 0 rather than index 0
    /// of type 1, which some devices answer rather than refuse.
    #[must_use]
    pub const fn get_descriptor(kind: u8, index: u8, length: u16) -> Self {
        Self::new(
            DEVICE_TO_HOST,
            request::GET_DESCRIPTOR,
            ((kind as u16) << 8) | index as u16,
            0,
            length,
        )
    }

    /// Select a configuration, by its `bConfigurationValue`.
    ///
    /// **Not its index.** The value comes from the configuration descriptor's
    /// own field, and a device is entitled to number its configurations
    /// however it likes — passing the position in the list works on most
    /// devices and fails on the ones that do not start at one.
    #[must_use]
    pub const fn set_configuration(value: u8) -> Self {
        Self::new(0, request::SET_CONFIGURATION, value as u16, 0, 0)
    }

    /// Tell a HID interface to speak the boot protocol.
    ///
    /// A class request addressed to the **interface**, not the device: a
    /// composite device has one HID interface among several, and addressing the
    /// device would be asking the wrong thing.
    #[must_use]
    pub const fn set_boot_protocol(interface: u16) -> Self {
        Self::new(
            CLASS | INTERFACE,
            request::SET_PROTOCOL,
            protocol::BOOT,
            interface,
            0,
        )
    }

    /// Set the idle rate for a HID interface.
    ///
    /// `duration` is in four-millisecond units, and **zero means "only when
    /// something changes"** — which is what a keyboard should do. Left at the
    /// device's default, some keyboards resend the same report indefinitely,
    /// and a driver that treats each report as a keystroke then types for ever.
    /// This kernel's driver does not, but the interrupts are still waste.
    ///
    /// The report id goes in the low byte of `wValue`; zero means all reports.
    #[must_use]
    pub const fn set_idle(interface: u16, duration: u8, report: u8) -> Self {
        Self::new(
            CLASS | INTERFACE,
            request::SET_IDLE,
            ((duration as u16) << 8) | report as u16,
            interface,
            0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kind;

    #[test]
    fn a_setup_packet_is_eight_little_endian_bytes() {
        let s = Setup::new(0x80, 6, 0x0102, 0x0304, 0x0506);
        assert_eq!(s.0, [0x80, 6, 0x02, 0x01, 0x04, 0x03, 0x06, 0x05]);
        assert_eq!(s.length(), 0x0506);
    }

    /// **The field most easily written back to front.**
    #[test]
    fn get_descriptor_puts_the_type_high_and_the_index_low() {
        let s = Setup::get_descriptor(kind::DEVICE, 0, 18);
        // wValue is bytes 2 and 3, little-endian: low = index, high = type.
        assert_eq!(s.0[2], 0, "index belongs in the low byte");
        assert_eq!(s.0[3], kind::DEVICE, "type belongs in the high byte");
        assert_eq!(s.length(), 18);
        assert!(s.is_device_to_host());

        // And a configuration descriptor, index 0.
        let s = Setup::get_descriptor(kind::CONFIGURATION, 0, 9);
        assert_eq!(s.0[3], kind::CONFIGURATION);
    }

    #[test]
    fn a_get_is_device_to_host_and_a_set_is_not() {
        assert!(Setup::get_descriptor(kind::DEVICE, 0, 18).is_device_to_host());
        assert!(!Setup::set_configuration(1).is_device_to_host());
        assert!(!Setup::set_boot_protocol(0).is_device_to_host());
        assert!(!Setup::set_idle(0, 0, 0).is_device_to_host());
    }

    /// **Boot protocol is zero**, and this test exists because the intuition
    /// runs the other way.
    #[test]
    fn boot_protocol_is_zero_and_report_protocol_is_one() {
        assert_eq!(protocol::BOOT, 0);
        assert_eq!(protocol::REPORT, 1);
        let s = Setup::set_boot_protocol(0);
        assert_eq!(s.0[2], 0, "wValue low byte is the protocol");
        assert_eq!(s.0[3], 0);
    }

    #[test]
    fn the_hid_requests_are_addressed_to_the_interface_not_the_device() {
        // A composite device has one HID interface among several; addressing
        // the device asks the wrong thing.
        for s in [Setup::set_boot_protocol(2), Setup::set_idle(2, 0, 0)] {
            assert_eq!(s.0[0] & 0b1_1111, 1, "recipient must be interface");
            assert_eq!((s.0[0] >> 5) & 0b11, 1, "type must be class");
            // wIndex carries the interface number.
            assert_eq!(s.0[4], 2);
        }
    }

    #[test]
    fn set_idle_puts_the_duration_high_and_the_report_low() {
        let s = Setup::set_idle(0, 0x7f, 3);
        assert_eq!(s.0[2], 3, "report id low");
        assert_eq!(s.0[3], 0x7f, "duration high");
        // Zero duration means "only on change", which is what a keyboard wants.
        let s = Setup::set_idle(0, 0, 0);
        assert_eq!(s.0[2], 0);
        assert_eq!(s.0[3], 0);
    }

    #[test]
    fn the_request_codes_are_the_ones_the_specification_gives() {
        assert_eq!(request::GET_DESCRIPTOR, 6);
        assert_eq!(request::SET_CONFIGURATION, 9);
        assert_eq!(request::SET_IDLE, 0x0a);
        assert_eq!(request::SET_PROTOCOL, 0x0b);
    }

    #[test]
    fn a_set_request_carries_no_data_stage() {
        // wLength zero: the status stage is the whole of the answer, and a
        // driver that built a data stage for one would wait for bytes that
        // never come.
        assert_eq!(Setup::set_configuration(1).length(), 0);
        assert_eq!(Setup::set_boot_protocol(0).length(), 0);
        assert_eq!(Setup::set_idle(0, 0, 0).length(), 0);
    }
}
