// SPDX-License-Identifier: Apache-2.0
//! Descriptors and reports, from a device that is not to be trusted.
//!
//! [RFC 0041](../../docs/rfc/0041-a-usb-keyboard.md) rule 5, made executable.
//! Everything this target feeds the parser is what a USB device sends the host,
//! and on a hostile stick that is whatever an attacker chose. The parser is a
//! leaf crate with no dependencies precisely so this target can drive it without
//! a controller.
//!
//! Nothing here asserts a *result*. The property is that no input, however
//! malformed, makes the parser panic, index past a buffer, or fail to
//! terminate — the walk in particular, which a zero length would turn into an
//! infinite loop if the guard for it were ever removed.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The walk: every descriptor, every field read through the bounds-checked
    // accessors, on a blob whose lengths may lie.
    for descriptor in bhaskix_usb::Descriptors::new(data) {
        let _ = descriptor.byte(0);
        let _ = descriptor.byte(descriptor.bytes.len());
        let _ = descriptor.word(descriptor.bytes.len().saturating_sub(1));
        let _ = bhaskix_usb::Device::parse(descriptor.bytes);
        let _ = bhaskix_usb::Configuration::parse(descriptor.bytes);
        let _ = bhaskix_usb::Interface::parse(descriptor.bytes);
        let _ = bhaskix_usb::Endpoint::parse(descriptor.bytes);
    }

    // The search a driver actually performs on a configuration blob.
    let _ = bhaskix_usb::boot_keyboard(data);

    // And the reports, fed as a stream: a keyboard sends state, so the
    // interesting inputs are sequences rather than single packets.
    let mut keyboard = bhaskix_usb::hid::Keyboard::new();
    for chunk in data.chunks(bhaskix_usb::hid::REPORT_BYTES) {
        let _ = keyboard.feed(chunk);
    }
});
