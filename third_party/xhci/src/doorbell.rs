// SPDX-License-Identifier: Apache-2.0
// Adapted from the `xhci` crate, Copyright (c) 2021 Hiroki Tokunaga.
// Upstream: https://github.com/rust-osdev/xhci, version 0.9.2, MIT OR Apache-2.0.
//! Doorbell registers: how the driver tells the controller to go and look.
//!
//! An array of 32-bit registers beginning at `DBOFF` past the window base, one
//! per device slot plus one at index zero for the command ring. Writing one is
//! the only way the driver ever asks the controller to do anything — everything
//! else is preparing memory for it to read.

use crate::bits32;

/// Bytes per doorbell.
pub const STRIDE: usize = 4;

/// Doorbells the architecture allows: the command ring, plus 255 device slots.
///
/// `HCSPARAMS1`'s slot count is eight bits, so 255 is the most slots any
/// controller can report, and index zero is the command ring rather than a
/// slot. As with the interrupters, this is a ceiling and not a licence: a
/// driver must bound its index by the slots it actually enabled.
pub const MAX_DOORBELLS: usize = 256;

/// Offset of doorbell `index`, relative to the doorbell array's base.
///
/// **Bounded for the same reason as the interrupters**: the index reaches
/// directly into an offset, so an unchecked one is an MMIO write outside the
/// window. A write, specifically — doorbells are write-only in practice — which
/// makes an out-of-range index worse than a stray read.
#[must_use]
pub const fn doorbell_at(index: usize) -> Option<usize> {
    if index >= MAX_DOORBELLS {
        return None;
    }
    Some(index * STRIDE)
}

/// The doorbell index for the command ring.
pub const COMMAND_RING: usize = 0;

/// The doorbell index for device `slot`.
///
/// Slots are numbered from one, and slot *n* rings doorbell *n* — the command
/// ring takes index zero. Answers `None` for slot zero, which is not a slot.
#[must_use]
pub const fn for_slot(slot: u8) -> Option<usize> {
    if slot == 0 {
        return None;
    }
    Some(slot as usize)
}

/// A doorbell value: which endpoint, and which stream.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Doorbell(pub u32);

impl Doorbell {
    /// Bits 7:0 — the target.
    ///
    /// For a slot doorbell this is the endpoint's Device Context Index: 1 is
    /// the default control endpoint, and thereafter `2 * n` for OUT and
    /// `2 * n + 1` for IN. For the command ring doorbell it must be zero.
    #[must_use]
    pub const fn target(self) -> u8 {
        bits32(self.0, 0, 7) as u8
    }

    /// Bits 31:16 — the stream, for endpoints that use streams.
    #[must_use]
    pub const fn stream_id(self) -> u16 {
        bits32(self.0, 16, 31) as u16
    }

    /// The value that rings the command ring's doorbell.
    ///
    /// Zero, in both fields. The command ring has no endpoints and no streams,
    /// and a non-zero target here is undefined rather than ignored.
    #[must_use]
    pub const fn command() -> Self {
        Self(0)
    }

    /// The value that rings `endpoint` on a slot's doorbell.
    #[must_use]
    pub const fn endpoint(target: u8) -> Self {
        Self(target as u32)
    }

    /// The same, naming a stream.
    #[must_use]
    pub const fn endpoint_stream(target: u8, stream: u16) -> Self {
        Self(target as u32 | ((stream as u32) << 16))
    }
}

/// The Device Context Index for the default control endpoint.
pub const CONTROL_ENDPOINT: u8 = 1;

/// The Device Context Index of endpoint `number`, in the given direction.
///
/// **This numbering is not the USB endpoint number**, and conflating the two is
/// a standing trap: USB endpoint 1 IN is Device Context Index 3, not 1. The
/// mapping is `2 * number` for OUT and `2 * number + 1` for IN, with the
/// control endpoint occupying index 1 alone.
///
/// Answers `None` for endpoint numbers past 15, which USB does not have.
#[must_use]
pub const fn device_context_index(number: u8, input: bool) -> Option<u8> {
    if number > 15 {
        return None;
    }
    if number == 0 {
        // Endpoint zero is the bidirectional control endpoint and has one
        // index regardless of direction.
        return Some(CONTROL_ENDPOINT);
    }
    Some(number * 2 + if input { 1 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doorbells_are_four_bytes_apart_from_index_zero() {
        assert_eq!(doorbell_at(0), Some(0));
        assert_eq!(doorbell_at(1), Some(4));
        assert_eq!(doorbell_at(255), Some(1020));
    }

    #[test]
    fn an_index_past_the_array_is_refused() {
        // 256 doorbells exist at most. The 257th would be a write four bytes
        // past the array, into whatever the controller maps next.
        assert_eq!(doorbell_at(256), None);
        assert_eq!(doorbell_at(usize::MAX), None);
    }

    #[test]
    fn the_command_ring_is_index_zero_and_slots_start_at_one() {
        assert_eq!(COMMAND_RING, 0);
        assert_eq!(for_slot(1), Some(1));
        assert_eq!(for_slot(255), Some(255));
        // Slot zero does not exist; a caller passing it would ring the command
        // ring instead, which is a different thing entirely.
        assert_eq!(for_slot(0), None);
    }

    #[test]
    fn the_command_doorbell_is_zero_in_both_fields() {
        let d = Doorbell::command();
        assert_eq!(d.target(), 0);
        assert_eq!(d.stream_id(), 0);
        assert_eq!(d.0, 0);
    }

    #[test]
    fn a_doorbell_carries_target_and_stream_without_overlapping() {
        let d = Doorbell::endpoint_stream(3, 0xbeef);
        assert_eq!(d.target(), 3);
        assert_eq!(d.stream_id(), 0xbeef);
        // Bits 15:8 are reserved and must stay clear: a stream written eight
        // bits low would land in them and the target would read wrong.
        assert_eq!(d.0 & 0xff00, 0);
    }

    /// **The endpoint-numbering test, and it guards a standing confusion.**
    #[test]
    fn device_context_indices_are_not_usb_endpoint_numbers() {
        // The control endpoint is index 1 whichever way it is asked for.
        assert_eq!(device_context_index(0, false), Some(1));
        assert_eq!(device_context_index(0, true), Some(1));
        // Endpoint 1 OUT is 2, endpoint 1 IN is 3 -- not 1.
        assert_eq!(device_context_index(1, false), Some(2));
        assert_eq!(device_context_index(1, true), Some(3));
        // The interrupt IN endpoint a HID keyboard uses is typically 1 IN,
        // which is index 3. Ringing index 1 instead rings the control
        // endpoint, and the keyboard simply never reports.
        assert_eq!(device_context_index(2, true), Some(5));
        assert_eq!(device_context_index(15, true), Some(31));
    }

    #[test]
    fn an_endpoint_number_usb_does_not_have_is_refused() {
        // Four bits in the descriptor, so 15 is the maximum. 16 would compute
        // index 33, past the 31 a device context holds.
        assert_eq!(device_context_index(16, false), None);
        assert_eq!(device_context_index(255, true), None);
    }

    #[test]
    fn no_endpoint_index_exceeds_what_a_device_context_holds() {
        // A device context has 31 endpoint contexts plus the slot context. An
        // index past 31 would be read from beyond the structure -- by the
        // controller, by DMA.
        for number in 0..=15u8 {
            for input in [false, true] {
                let index = device_context_index(number, input).expect("valid");
                assert!(index <= 31, "endpoint {number} gave index {index}");
                assert!(index >= 1);
            }
        }
    }
}
