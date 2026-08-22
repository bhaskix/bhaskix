// SPDX-License-Identifier: Apache-2.0
//! USB descriptors, and the one report a keyboard sends.
//!
//! [RFC 0041](../../docs/rfc/0041-a-usb-keyboard.md) step 1. A leaf crate
//! beside `elf`, `net`, `fs` and `ustar`: `no_std`, depending on nothing,
//! host-testable, and **fuzzed**, for the reason this module exists at all.
//!
//! # Everything here is written by whatever is plugged in
//!
//! Descriptors are length-prefixed, self-describing and nested — the shape that
//! produces parser bugs — and they arrive from a device the host does not
//! control. On a hostile USB stick they arrive from an attacker.
//!
//! So this crate is separated from the driver deliberately: a parser that needs
//! a controller to run is a parser nobody fuzzes. Here it is a pure function
//! from bytes to values, and RFC 0038's fifth rule — *every descriptor is
//! untrusted input* — is a thing that can be tested rather than promised.
//!
//! The rules the parsing obeys, each with a test that fails without it:
//!
//! - **A length is checked against the buffer, never believed.** A descriptor
//!   claiming to be longer than what remains is refused.
//! - **A zero length terminates rather than repeats.** It is the one value that
//!   turns a walk into an infinite loop, and a device can send it.
//! - **A total length is a claim.** `wTotalLength` bounds the walk only after
//!   the buffer bounds it first.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod hid;
pub mod setup;

/// Every descriptor begins with its length and its type.
pub const HEADER: usize = 2;

/// Descriptor types this crate names.
pub mod kind {
    /// The device itself.
    pub const DEVICE: u8 = 1;
    /// A configuration, and the header of the blob that follows it.
    pub const CONFIGURATION: u8 = 2;
    /// A string.
    pub const STRING: u8 = 3;
    /// An interface within a configuration.
    pub const INTERFACE: u8 = 4;
    /// An endpoint within an interface.
    pub const ENDPOINT: u8 = 5;
    /// A HID class descriptor.
    pub const HID: u8 = 0x21;
}

/// The USB class, subclass and protocol that mean "boot keyboard".
pub mod class {
    /// Human interface device.
    pub const HID: u8 = 3;
    /// The boot subclass: a device that a firmware can drive without parsing
    /// a report descriptor.
    pub const BOOT: u8 = 1;
    /// The keyboard protocol within the boot subclass.
    pub const KEYBOARD: u8 = 1;
}

/// One descriptor found in a blob: its type, and its bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Descriptor<'a> {
    /// `bDescriptorType`.
    pub kind: u8,
    /// The whole descriptor, header included.
    pub bytes: &'a [u8],
}

impl<'a> Descriptor<'a> {
    /// A byte at `offset` within the descriptor, if it is that long.
    ///
    /// **Every field access goes through this.** A descriptor may be shorter
    /// than its type implies — a device can send a five-byte endpoint
    /// descriptor — and indexing it directly would panic in a driver.
    #[must_use]
    pub fn byte(&self, offset: usize) -> Option<u8> {
        self.bytes.get(offset).copied()
    }

    /// A little-endian `u16` at `offset`, if the descriptor is that long.
    #[must_use]
    pub fn word(&self, offset: usize) -> Option<u16> {
        let low = self.byte(offset)?;
        let high = self.byte(offset + 1)?;
        Some(u16::from(low) | (u16::from(high) << 8))
    }
}

/// Walks the descriptors in a configuration blob.
///
/// Stops at the first thing it cannot trust, which is the whole point: a device
/// that lies about a length ends the walk rather than steering it.
#[derive(Clone, Copy, Debug)]
pub struct Descriptors<'a> {
    rest: &'a [u8],
}

impl<'a> Descriptors<'a> {
    /// Walks `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }
}

impl<'a> Iterator for Descriptors<'a> {
    type Item = Descriptor<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.len() < HEADER {
            return None;
        }
        let length = self.rest[0] as usize;

        // **Zero is the value that turns this into an infinite loop**, and a
        // device can send it. Ending the walk is the only safe reading: a
        // descriptor with no length describes nothing, and skipping it would
        // require guessing how far.
        if length < HEADER || length > self.rest.len() {
            return None;
        }

        let (descriptor, rest) = self.rest.split_at(length);
        self.rest = rest;
        Some(Descriptor {
            kind: descriptor[1],
            bytes: descriptor,
        })
    }
}

/// A device descriptor, as far as a driver reads it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Device {
    /// `bMaxPacketSize0` — the control endpoint's packet size.
    pub max_packet_size_0: u8,
    /// `idVendor`.
    pub vendor: u16,
    /// `idProduct`.
    pub product: u16,
    /// `bNumConfigurations`.
    pub configurations: u8,
}

impl Device {
    /// The length a device descriptor is defined to have.
    pub const LENGTH: usize = 18;

    /// Parses one, or answers `None` if it is not one or is too short.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::LENGTH || bytes[1] != kind::DEVICE {
            return None;
        }
        Some(Self {
            max_packet_size_0: bytes[7],
            vendor: u16::from(bytes[8]) | (u16::from(bytes[9]) << 8),
            product: u16::from(bytes[10]) | (u16::from(bytes[11]) << 8),
            configurations: bytes[17],
        })
    }
}

/// A configuration descriptor's header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Configuration {
    /// `wTotalLength` — how long the whole blob claims to be.
    ///
    /// **A claim, not a fact.** The driver asks for this many bytes and must
    /// then walk only as far as it actually received.
    pub total_length: u16,
    /// `bNumInterfaces`.
    pub interfaces: u8,
    /// `bConfigurationValue` — what a Set Configuration names.
    pub value: u8,
}

impl Configuration {
    /// The length a configuration descriptor's header is defined to have.
    pub const LENGTH: usize = 9;

    /// Parses one, or answers `None`.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::LENGTH || bytes[1] != kind::CONFIGURATION {
            return None;
        }
        Some(Self {
            total_length: u16::from(bytes[2]) | (u16::from(bytes[3]) << 8),
            interfaces: bytes[4],
            value: bytes[5],
        })
    }
}

/// An interface descriptor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Interface {
    /// `bInterfaceNumber`.
    pub number: u8,
    /// `bAlternateSetting`.
    pub alternate: u8,
    /// `bNumEndpoints`.
    pub endpoints: u8,
    /// `bInterfaceClass`.
    pub class: u8,
    /// `bInterfaceSubClass`.
    pub subclass: u8,
    /// `bInterfaceProtocol`.
    pub protocol: u8,
}

impl Interface {
    /// The length an interface descriptor is defined to have.
    pub const LENGTH: usize = 9;

    /// Parses one, or answers `None`.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::LENGTH || bytes[1] != kind::INTERFACE {
            return None;
        }
        Some(Self {
            number: bytes[2],
            alternate: bytes[3],
            endpoints: bytes[4],
            class: bytes[5],
            subclass: bytes[6],
            protocol: bytes[7],
        })
    }

    /// Whether this interface is a keyboard a driver can read without parsing
    /// a report descriptor.
    #[must_use]
    pub const fn is_boot_keyboard(&self) -> bool {
        self.class == class::HID && self.subclass == class::BOOT && self.protocol == class::KEYBOARD
    }
}

/// What an endpoint carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransferType {
    /// Control.
    Control,
    /// Isochronous.
    Isochronous,
    /// Bulk.
    Bulk,
    /// Interrupt — what a keyboard reports on.
    Interrupt,
}

/// An endpoint descriptor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Endpoint {
    /// `bEndpointAddress`, whole.
    pub address: u8,
    /// `bmAttributes`, whole.
    pub attributes: u8,
    /// `wMaxPacketSize`.
    ///
    /// **Bounded before it sizes anything.** This is a number the device chose,
    /// and it ends up in an endpoint context telling a bus master how much to
    /// write into a buffer the driver allocated.
    pub max_packet_size: u16,
    /// `bInterval` — the polling interval, in the units the speed defines.
    pub interval: u8,
}

impl Endpoint {
    /// The length an endpoint descriptor is defined to have.
    pub const LENGTH: usize = 7;

    /// Parses one, or answers `None`.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::LENGTH || bytes[1] != kind::ENDPOINT {
            return None;
        }
        Some(Self {
            address: bytes[2],
            attributes: bytes[3],
            max_packet_size: u16::from(bytes[4]) | (u16::from(bytes[5]) << 8),
            interval: bytes[6],
        })
    }

    /// The endpoint number: the low four bits of the address.
    #[must_use]
    pub const fn number(&self) -> u8 {
        self.address & 0x0f
    }

    /// Whether data flows device-to-host: the address's top bit.
    #[must_use]
    pub const fn is_input(&self) -> bool {
        self.address & 0x80 != 0
    }

    /// What this endpoint carries: the low two bits of the attributes.
    #[must_use]
    pub const fn transfer_type(&self) -> TransferType {
        match self.attributes & 0b11 {
            0 => TransferType::Control,
            1 => TransferType::Isochronous,
            2 => TransferType::Bulk,
            _ => TransferType::Interrupt,
        }
    }
}

/// Finds the interrupt IN endpoint of the first boot-keyboard interface.
///
/// Answers the interface and the endpoint together, because a driver needs both
/// — the interface to select and the endpoint to configure — and finding them in
/// two passes invites them to come from different interfaces.
#[must_use]
pub fn boot_keyboard(blob: &[u8]) -> Option<(Interface, Endpoint)> {
    let mut current: Option<Interface> = None;
    for descriptor in Descriptors::new(blob) {
        match descriptor.kind {
            kind::INTERFACE => {
                current = Interface::parse(descriptor.bytes).filter(Interface::is_boot_keyboard);
            }
            kind::ENDPOINT => {
                // Only while inside a boot-keyboard interface: an endpoint
                // belongs to the interface that precedes it, and taking one
                // from a different interface is how a driver ends up polling
                // a mouse for keystrokes.
                if let Some(interface) = current
                    && let Some(endpoint) = Endpoint::parse(descriptor.bytes)
                    && endpoint.is_input()
                    && endpoint.transfer_type() == TransferType::Interrupt
                {
                    return Some((interface, endpoint));
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal configuration blob: configuration, interface, HID, endpoint.
    fn keyboard_blob() -> [u8; 34] {
        [
            // Configuration: length 9, type 2, total 34, 1 interface, value 1
            9, 2, 34, 0, 1, 1, 0, 0xa0, 50,
            // Interface: length 9, type 4, number 0, alt 0, 1 endpoint,
            // class 3, subclass 1, protocol 1
            9, 4, 0, 0, 1, 3, 1, 1, 0, // HID: length 9, type 0x21
            9, 0x21, 0x11, 1, 0, 1, 0x22, 65, 0,
            // Endpoint: length 7, type 5, address 0x81, attributes 3,
            // max packet 8, interval 10
            7, 5, 0x81, 3, 8, 0, 10,
        ]
    }

    #[test]
    fn the_walk_finds_every_descriptor_in_order() {
        let blob = keyboard_blob();
        let mut kinds = [0u8; 8];
        let mut found = 0;
        for descriptor in Descriptors::new(&blob) {
            kinds[found] = descriptor.kind;
            found += 1;
        }
        assert_eq!(&kinds[..found], &[2, 4, 0x21, 5]);
    }

    /// **The one that stops an infinite loop.**
    #[test]
    fn a_zero_length_descriptor_ends_the_walk_rather_than_repeating() {
        // A device can send this, and a walk that advanced by `bLength` would
        // advance by nothing and go round for ever.
        let blob = [0u8, 4, 0, 0];
        assert_eq!(Descriptors::new(&blob).count(), 0);
        // And a length below the header is the same case.
        let blob = [1u8, 4, 0, 0];
        assert_eq!(Descriptors::new(&blob).count(), 0);
    }

    #[test]
    fn a_length_longer_than_the_buffer_is_refused_not_believed() {
        // Nine bytes claimed, four present.
        let blob = [9u8, 4, 0, 0];
        assert_eq!(Descriptors::new(&blob).count(), 0);
    }

    #[test]
    fn a_truncated_blob_yields_what_is_whole_and_stops() {
        let full = keyboard_blob();
        // Cut the endpoint descriptor in half.
        let blob = &full[..full.len() - 4];
        let mut kinds = [0u8; 8];
        let mut found = 0;
        for descriptor in Descriptors::new(blob) {
            kinds[found] = descriptor.kind;
            found += 1;
        }
        assert_eq!(&kinds[..found], &[2, 4, 0x21]);
    }

    #[test]
    fn a_field_past_the_end_of_a_short_descriptor_is_none_not_a_panic() {
        // A five-byte endpoint descriptor: legal to receive, not legal to
        // index into as though it were seven.
        let short = [5u8, 5, 0x81, 3, 8];
        let d = Descriptors::new(&short).next().expect("one descriptor");
        assert_eq!(d.byte(2), Some(0x81));
        assert_eq!(d.byte(6), None);
        assert_eq!(d.word(4), None);
        // And parsing refuses it rather than reading rubbish.
        assert_eq!(Endpoint::parse(d.bytes), None);
    }

    #[test]
    fn the_keyboard_is_found_with_its_interface_and_endpoint_together() {
        let blob = keyboard_blob();
        let (interface, endpoint) = boot_keyboard(&blob).expect("a keyboard");
        assert!(interface.is_boot_keyboard());
        assert_eq!(interface.number, 0);
        assert_eq!(endpoint.number(), 1);
        assert!(endpoint.is_input());
        assert_eq!(endpoint.transfer_type(), TransferType::Interrupt);
        assert_eq!(endpoint.max_packet_size, 8);
        assert_eq!(endpoint.interval, 10);
    }

    /// **An endpoint belongs to the interface before it**, and this is the test
    /// that stops a driver polling a mouse for keystrokes.
    #[test]
    fn an_endpoint_of_another_interface_is_not_taken_for_the_keyboards() {
        let blob = [
            // Configuration
            9, 2, 25, 0, 1, 1, 0, 0xa0, 50,
            // Interface: class 3, subclass 1, protocol 2 -- a boot *mouse*
            9, 4, 0, 0, 1, 3, 1, 2, 0, // Its interrupt IN endpoint
            7, 5, 0x81, 3, 8, 0, 10,
        ];
        assert_eq!(boot_keyboard(&blob), None);
    }

    #[test]
    fn an_out_endpoint_is_not_mistaken_for_an_in_one() {
        let mut blob = keyboard_blob();
        // Clear the direction bit on the endpoint address.
        let at = blob.len() - 5;
        blob[at] = 0x01;
        assert_eq!(boot_keyboard(&blob), None);
    }

    #[test]
    fn a_bulk_endpoint_is_not_mistaken_for_an_interrupt_one() {
        let mut blob = keyboard_blob();
        let at = blob.len() - 4;
        blob[at] = 2; // bulk
        assert_eq!(boot_keyboard(&blob), None);
    }

    #[test]
    fn device_and_configuration_headers_parse_their_fields() {
        let device = [
            18u8, 1, 0, 2, 0, 0, 0, 64, 0x6d, 0x04, 0x2d, 0xc0, 0, 1, 1, 2, 3, 1,
        ];
        let d = Device::parse(&device).expect("a device");
        assert_eq!(d.max_packet_size_0, 64);
        assert_eq!(d.vendor, 0x046d);
        assert_eq!(d.product, 0xc02d);
        assert_eq!(d.configurations, 1);

        let blob = keyboard_blob();
        let c = Configuration::parse(&blob).expect("a configuration");
        assert_eq!(c.total_length, 34);
        assert_eq!(c.interfaces, 1);
        assert_eq!(c.value, 1);
    }

    #[test]
    fn a_descriptor_of_the_wrong_type_is_refused() {
        let blob = keyboard_blob();
        // The configuration header is not a device descriptor.
        assert_eq!(Device::parse(&blob), None);
        assert_eq!(Endpoint::parse(&blob), None);
    }

    #[test]
    fn every_prefix_of_a_real_blob_parses_without_panicking() {
        // The cheap stand-in for a fuzzer, run on every build: a device that
        // stops talking mid-descriptor must not take the parser with it.
        let full = keyboard_blob();
        for end in 0..=full.len() {
            let _ = boot_keyboard(&full[..end]);
            let _ = Descriptors::new(&full[..end]).count();
        }
    }
}
