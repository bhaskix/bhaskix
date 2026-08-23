// SPDX-License-Identifier: Apache-2.0
// Adapted from the `xhci` crate, Copyright (c) 2021 Hiroki Tokunaga.
// Upstream: https://github.com/rust-osdev/xhci, version 0.9.2, MIT OR Apache-2.0.
//! Device, endpoint and input contexts: the structures the controller reads.
//!
//! [RFC 0038](../../docs/rfc/0038-vendoring-the-xhci-definitions.md) step 4.
//!
//! # These are read by the device, not by us
//!
//! Everything in this module describes memory the **controller** walks, by DMA,
//! on its own initiative. A field at the wrong offset is not a wrong number on
//! a screen: it is a pointer the hardware follows. That is why the offsets here
//! are asserted against literals written a second time, and why RFC 0038's
//! first rule is that no driver built on these may run untranslated.

use crate::{bits32, bits64};

/// Dwords of *fields* in every context, whichever size the controller uses.
///
/// **The field layout does not change with the context size**, and reading that
/// wrongly is the single easiest mistake here: `HCCPARAMS1`'s context-size bit
/// selects 32-byte or 64-byte contexts, and what the extra 32 bytes buy is
/// *padding*, not different offsets. Dword 3 is dword 3 either way. What the
/// bit changes is the **stride** from one context to the next — see
/// [`stride_bytes`].
pub const DWORDS: usize = 8;

/// Bytes from one context to the next.
///
/// Taken from `HCCPARAMS1` bit 2, which the caller must have read: passing the
/// wrong one does not misplace a field within a context, it misplaces every
/// context after the first, by a factor of two.
#[must_use]
pub const fn stride_bytes(context_size_64: bool) -> usize {
    if context_size_64 { 64 } else { 32 }
}

/// Byte offset of the context at `index` inside a **device** context.
///
/// A device context is `[slot][endpoint 1][endpoint 2]…`, so the slot context
/// is index 0 and the endpoint with Device Context Index *n* is at `n`.
///
/// Answers `None` past index 31, which is the last endpoint a device context
/// holds.
#[must_use]
pub const fn device_context_offset(index: u8, context_size_64: bool) -> Option<usize> {
    if index > 31 {
        return None;
    }
    Some(index as usize * stride_bytes(context_size_64))
}

/// Byte offset of the context at `index` inside an **input** context.
///
/// **One context further along than in a device context, and this asymmetry is
/// the trap.** An input context is `[input control][slot][endpoint 1]…`, so the
/// slot context is at one stride rather than zero and the endpoint with Device
/// Context Index *n* is at `n + 1`. A driver that uses the device-context
/// arithmetic to fill an input context writes every field one context early —
/// the slot context lands on the input control context's add and drop flags,
/// which is a configure command that changes the wrong endpoints.
///
/// `index` is the Device Context Index, as in [`device_context_offset`]; the
/// input control context is [`INPUT_CONTROL_OFFSET`] and is not an index.
#[must_use]
pub const fn input_context_offset(index: u8, context_size_64: bool) -> Option<usize> {
    if index > 31 {
        return None;
    }
    Some((index as usize + 1) * stride_bytes(context_size_64))
}

/// The input control context is always first in an input context.
pub const INPUT_CONTROL_OFFSET: usize = 0;

/// Bytes a device context base address array needs for `slots` slots.
///
/// One 64-bit entry per slot **plus one at index zero**, which is not a slot:
/// it is the scratchpad buffer array pointer. Sizing this by the slot count
/// alone leaves the controller reading one entry past the allocation, by DMA.
#[must_use]
pub const fn device_context_base_array_bytes(slots: u8) -> usize {
    (slots as usize + 1) * 8
}

/// Bytes an input context needs, for a device using up to `last_index`.
#[must_use]
pub const fn input_context_bytes(last_index: u8, context_size_64: bool) -> Option<usize> {
    if last_index > 31 {
        return None;
    }
    Some((last_index as usize + 2) * stride_bytes(context_size_64))
}

/// What the controller thinks a slot is doing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotState {
    /// Disabled, or enabled and not addressed.
    DisabledEnabled,
    /// Default: addressed to zero.
    Default,
    /// A device address has been assigned.
    Addressed,
    /// Endpoints beyond the control endpoint are configured.
    Configured,
    /// A value the specification does not define.
    Reserved(u8),
}

impl SlotState {
    /// The state a raw field value names.
    #[must_use]
    pub const fn from_raw(value: u8) -> Self {
        match value {
            0 => Self::DisabledEnabled,
            1 => Self::Default,
            2 => Self::Addressed,
            3 => Self::Configured,
            other => Self::Reserved(other),
        }
    }
}

/// What kind of endpoint a context describes.
///
/// **The direction is part of the type**, which is why there are seven kinds
/// and not four: an isochronous OUT endpoint and an isochronous IN endpoint are
/// different values, and the Device Context Index already encodes the same
/// direction separately. The two must agree.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EndpointType {
    /// Not a valid endpoint — the reset value, and a refusal if configured.
    NotValid,
    /// Isochronous, host to device.
    IsochOut,
    /// Bulk, host to device.
    BulkOut,
    /// Interrupt, host to device.
    InterruptOut,
    /// Control. Bidirectional, and the only kind that is.
    Control,
    /// Isochronous, device to host.
    IsochIn,
    /// Bulk, device to host.
    BulkIn,
    /// Interrupt, device to host — what a HID keyboard reports on.
    InterruptIn,
}

impl EndpointType {
    /// The value written into the endpoint context's type field.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        match self {
            Self::NotValid => 0,
            Self::IsochOut => 1,
            Self::BulkOut => 2,
            Self::InterruptOut => 3,
            Self::Control => 4,
            Self::IsochIn => 5,
            Self::BulkIn => 6,
            Self::InterruptIn => 7,
        }
    }

    /// The kind a raw field value names.
    #[must_use]
    pub const fn from_raw(value: u32) -> Self {
        match value & 0b111 {
            1 => Self::IsochOut,
            2 => Self::BulkOut,
            3 => Self::InterruptOut,
            4 => Self::Control,
            5 => Self::IsochIn,
            6 => Self::BulkIn,
            7 => Self::InterruptIn,
            _ => Self::NotValid,
        }
    }
}

/// A slot context: what the controller knows about the device itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Slot(pub [u32; DWORDS]);

impl Slot {
    /// An all-zero slot context.
    #[must_use]
    pub const fn new() -> Self {
        Self([0; DWORDS])
    }

    /// Dword 0, bits 19:0 — the route string through any intervening hubs.
    #[must_use]
    pub const fn route_string(self) -> u32 {
        bits32(self.0[0], 0, 19)
    }

    /// Dword 0, bits 23:20 — the device's speed.
    #[must_use]
    pub const fn speed(self) -> u8 {
        bits32(self.0[0], 20, 23) as u8
    }

    /// Dword 0, bits 31:27 — the highest Device Context Index in use.
    ///
    /// **This is an index, not a count**, and the controller reads exactly this
    /// many endpoint contexts. Setting it higher than the contexts actually
    /// initialised is the controller reading uninitialised memory as endpoint
    /// state, by DMA.
    #[must_use]
    pub const fn context_entries(self) -> u8 {
        bits32(self.0[0], 27, 31) as u8
    }

    /// With the context-entries field set.
    #[must_use]
    pub const fn with_context_entries(mut self, entries: u8) -> Self {
        self.0[0] = (self.0[0] & !(0b11111 << 27)) | (((entries & 0b11111) as u32) << 27);
        self
    }

    /// With the route string and speed set.
    #[must_use]
    pub const fn with_route_and_speed(mut self, route: u32, speed: u8) -> Self {
        self.0[0] =
            (self.0[0] & !0x00ff_ffff) | (route & 0x000f_ffff) | (((speed & 0b1111) as u32) << 20);
        self
    }

    /// Dword 1, bits 23:16 — the root hub port this device is on.
    ///
    /// **Ports are numbered from one**, as everywhere else in xHCI.
    ///
    /// # Corrected 2026-08-23 — this was bits 31:24, and that is Number of Ports
    ///
    /// Both this accessor and [`Slot::with_root_hub_port_number`] used bits
    /// 31:24, agreed with each other, and were pinned by a round-trip test that
    /// read the value back through the very accessor that had written it. A
    /// test shaped like that verifies the *pair*; it cannot see the layout, and
    /// it passed for as long as the two were wrong together.
    ///
    /// **Caught by a controller, not by a reading.** RFC 0041 step 5's Address
    /// Device command was refused with `CC_TRB_ERROR` while every other field
    /// of the input context probed correct. Written at bits 31:24 the slot
    /// context read `0x05000000`; moved to 23:16 it read `0x00050000` and the
    /// same command succeeded, the device reaching slot state `Addressed` with
    /// USB address 1. That is evidence from this machine rather than from
    /// recall, which is the only kind available here — see PROVENANCE.md, which
    /// says the specification wins and which nobody can consult from this tree.
    ///
    /// Dword 1 is `[max exit latency 15:0][root hub port 23:16][number of
    /// ports 31:24]`, and the field this used to occupy belongs to a hub's port
    /// count. The test below now asserts the raw dword as well as the round
    /// trip, which is the only form that can fail when both accessors move
    /// together.
    #[must_use]
    pub const fn root_hub_port_number(self) -> u8 {
        bits32(self.0[1], 16, 23) as u8
    }

    /// With the root hub port number set.
    #[must_use]
    pub const fn with_root_hub_port_number(mut self, port: u8) -> Self {
        self.0[1] = (self.0[1] & !(0xff << 16)) | ((port as u32) << 16);
        self
    }

    /// Dword 2, bits 31:22 — which interrupter this device's events go to.
    #[must_use]
    pub const fn interrupter_target(self) -> u16 {
        bits32(self.0[2], 22, 31) as u16
    }

    /// Dword 3, bits 7:0 — the USB address the controller assigned.
    ///
    /// Read-only in practice: the controller writes it, the driver does not.
    #[must_use]
    pub const fn usb_device_address(self) -> u8 {
        bits32(self.0[3], 0, 7) as u8
    }

    /// Dword 3, bits 31:27 — what the controller thinks this slot is doing.
    #[must_use]
    pub const fn slot_state(self) -> SlotState {
        SlotState::from_raw(bits32(self.0[3], 27, 31) as u8)
    }
}

/// An endpoint context: one endpoint's state and its transfer ring.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Endpoint(pub [u32; DWORDS]);

impl Endpoint {
    /// An all-zero endpoint context.
    #[must_use]
    pub const fn new() -> Self {
        Self([0; DWORDS])
    }

    /// Dword 0, bits 2:0 — the endpoint's state.
    #[must_use]
    pub const fn endpoint_state(self) -> u32 {
        bits32(self.0[0], 0, 2)
    }

    /// Dword 0, bits 23:16 — the polling interval, as a power of two.
    ///
    /// An exponent, not a count of milliseconds: the period is
    /// `2^interval` × 125 µs. A HID keyboard's descriptor states its interval
    /// in frames, and converting that to this field is arithmetic a driver must
    /// do rather than a value it may copy.
    #[must_use]
    pub const fn interval(self) -> u8 {
        bits32(self.0[0], 16, 23) as u8
    }

    /// With the interval exponent set.
    #[must_use]
    pub const fn with_interval(mut self, interval: u8) -> Self {
        self.0[0] = (self.0[0] & !(0xff << 16)) | ((interval as u32) << 16);
        self
    }

    /// Dword 1, bits 2:1 — how many times a transfer is retried.
    ///
    /// **Zero means retry for ever**, which is not the harmless default it
    /// looks like: an endpoint that never gives up can wedge its ring against a
    /// device that has stopped answering. Three is what the specification
    /// suggests for anything that is not isochronous.
    #[must_use]
    pub const fn error_count(self) -> u8 {
        bits32(self.0[1], 1, 2) as u8
    }

    /// With the error count set.
    #[must_use]
    pub const fn with_error_count(mut self, count: u8) -> Self {
        self.0[1] = (self.0[1] & !(0b11 << 1)) | (((count & 0b11) as u32) << 1);
        self
    }

    /// Dword 1, bits 5:3 — what kind of endpoint this is.
    #[must_use]
    pub const fn endpoint_type(self) -> EndpointType {
        EndpointType::from_raw(bits32(self.0[1], 3, 5))
    }

    /// With the endpoint type set.
    #[must_use]
    pub const fn with_endpoint_type(mut self, kind: EndpointType) -> Self {
        self.0[1] = (self.0[1] & !(0b111 << 3)) | (kind.as_raw() << 3);
        self
    }

    /// Dword 1, bits 31:16 — the largest packet this endpoint accepts.
    #[must_use]
    pub const fn max_packet_size(self) -> u16 {
        bits32(self.0[1], 16, 31) as u16
    }

    /// With the maximum packet size set.
    ///
    /// **Must be the value from the device's own endpoint descriptor.** Larger,
    /// and the controller writes more into the driver's buffer than the buffer
    /// was sized for — which is a DMA write past an allocation and the reason
    /// RFC 0038's rule 5 treats every descriptor field as untrusted until it is
    /// bounded.
    #[must_use]
    pub const fn with_max_packet_size(mut self, size: u16) -> Self {
        self.0[1] = (self.0[1] & 0x0000_ffff) | ((size as u32) << 16);
        self
    }

    /// Dword 2 bit 0 — the cycle state the transfer ring starts at.
    #[must_use]
    pub const fn dequeue_cycle_state(self) -> bool {
        self.0[2] & 1 != 0
    }

    /// Dwords 3:2 — where this endpoint's transfer ring is.
    ///
    /// The low four bits are flags rather than address, so this is returned
    /// already masked.
    #[must_use]
    pub const fn transfer_ring_pointer(self) -> u64 {
        let low = self.0[2] as u64;
        let high = self.0[3] as u64;
        ((high << 32) | low) & !0b1111
    }

    /// With the transfer ring pointer and starting cycle state set.
    ///
    /// # Errors
    ///
    /// `None` unless `address` is 16-byte aligned. A misaligned pointer is not
    /// refused by the controller: its low bits are read as the cycle state and
    /// reserved flags, so the ring is silently placed elsewhere and started in
    /// the wrong phase.
    #[must_use]
    pub const fn with_transfer_ring(mut self, address: u64, cycle: bool) -> Option<Self> {
        if address & 0b1111 != 0 {
            return None;
        }
        let value = address | if cycle { 1 } else { 0 };
        self.0[2] = value as u32;
        self.0[3] = (value >> 32) as u32;
        Some(self)
    }

    /// Dword 4, bits 15:0 — the average transfer length, for scheduling.
    #[must_use]
    pub const fn average_trb_length(self) -> u16 {
        bits32(self.0[4], 0, 15) as u16
    }

    /// With the average TRB length set.
    #[must_use]
    pub const fn with_average_trb_length(mut self, length: u16) -> Self {
        self.0[4] = (self.0[4] & !0xffff) | length as u32;
        self
    }
}

/// An input control context: which contexts a configure command touches.
///
/// **Two bitmaps, and they are not symmetric.** Bit *n* of the add flags means
/// "evaluate the context at Device Context Index *n*"; bit *n* of the drop
/// flags means "tear it down". Bits 1:0 of the drop flags are reserved, because
/// the slot context and the control endpoint cannot be dropped — only
/// re-evaluated.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct InputControl(pub [u32; DWORDS]);

impl InputControl {
    /// An all-zero input control context: nothing added, nothing dropped.
    #[must_use]
    pub const fn new() -> Self {
        Self([0; DWORDS])
    }

    /// Dword 0 — the drop-context flags.
    #[must_use]
    pub const fn drop_flags(self) -> u32 {
        self.0[0]
    }

    /// Dword 1 — the add-context flags.
    #[must_use]
    pub const fn add_flags(self) -> u32 {
        self.0[1]
    }

    /// With the context at `index` marked for evaluation.
    ///
    /// # Errors
    ///
    /// `None` past index 31.
    #[must_use]
    pub const fn adding(mut self, index: u8) -> Option<Self> {
        if index > 31 {
            return None;
        }
        self.0[1] |= 1 << index;
        Some(self)
    }

    /// With the context at `index` marked for teardown.
    ///
    /// # Errors
    ///
    /// `None` past index 31, and `None` for indices 0 and 1 — the slot context
    /// and the control endpoint, whose drop bits are reserved. Refusing here
    /// rather than writing a reserved bit is the difference between a command
    /// the controller rejects and one whose behaviour is undefined.
    #[must_use]
    pub const fn dropping(mut self, index: u8) -> Option<Self> {
        if index > 31 || index < 2 {
            return None;
        }
        self.0[0] |= 1 << index;
        Some(self)
    }

    /// Dword 7, bits 7:0 — the configuration value being selected.
    #[must_use]
    pub const fn configuration_value(self) -> u8 {
        bits32(self.0[7], 0, 7) as u8
    }

    /// Dword 7, bits 15:8 — the interface number.
    #[must_use]
    pub const fn interface_number(self) -> u8 {
        bits32(self.0[7], 8, 15) as u8
    }

    /// Dword 7, bits 23:16 — the alternate setting.
    #[must_use]
    pub const fn alternate_setting(self) -> u8 {
        bits32(self.0[7], 16, 23) as u8
    }

    /// With the configuration, interface and alternate setting named.
    #[must_use]
    pub const fn with_configuration(mut self, value: u8, interface: u8, alternate: u8) -> Self {
        self.0[7] = (self.0[7] & !0x00ff_ffff)
            | value as u32
            | ((interface as u32) << 8)
            | ((alternate as u32) << 16);
        self
    }
}

/// Reads a 64-bit device context base array entry.
///
/// The array the controller walks to find each device's context. Entry zero is
/// the scratchpad pointer; entry *n* is slot *n*.
#[must_use]
pub const fn base_array_entry(raw: u64) -> u64 {
    bits64(raw, 6, 63) << 6
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_context_holds_eight_dwords_of_fields_at_either_size() {
        // The field layout does not change with the context size. Only the
        // stride does, and this is the test that keeps the two ideas apart.
        assert_eq!(DWORDS, 8);
        assert_eq!(stride_bytes(false), 32);
        assert_eq!(stride_bytes(true), 64);
    }

    /// **The asymmetry test, and it guards the worst mistake in this module.**
    #[test]
    fn an_endpoint_sits_one_context_later_in_an_input_context() {
        // Device context: [slot][ep1][ep2]...
        assert_eq!(device_context_offset(0, false), Some(0));
        assert_eq!(device_context_offset(1, false), Some(32));
        assert_eq!(device_context_offset(3, false), Some(96));
        // Input context: [control][slot][ep1]...
        assert_eq!(input_context_offset(0, false), Some(32));
        assert_eq!(input_context_offset(1, false), Some(64));
        assert_eq!(input_context_offset(3, false), Some(128));
        // Every index differs by exactly one stride between the two.
        for index in 0..=31u8 {
            let device = device_context_offset(index, true).expect("valid");
            let input = input_context_offset(index, true).expect("valid");
            assert_eq!(input - device, 64, "index {index}");
        }
    }

    #[test]
    fn an_index_past_the_last_endpoint_is_refused() {
        // A device context holds 31 endpoint contexts plus the slot context.
        assert!(device_context_offset(31, false).is_some());
        assert_eq!(device_context_offset(32, false), None);
        assert_eq!(input_context_offset(32, true), None);
    }

    #[test]
    fn the_base_array_has_an_entry_that_is_not_a_slot() {
        // One entry per slot plus entry zero, the scratchpad pointer. Sizing
        // by the slot count alone leaves the controller reading past the end.
        assert_eq!(device_context_base_array_bytes(0), 8);
        assert_eq!(device_context_base_array_bytes(1), 16);
        assert_eq!(device_context_base_array_bytes(255), 256 * 8);
    }

    #[test]
    fn slot_fields_do_not_overlap_each_other() {
        let slot = Slot::new()
            .with_route_and_speed(0xabcde, 3)
            .with_context_entries(31)
            .with_root_hub_port_number(7);
        assert_eq!(slot.route_string(), 0xabcde);
        assert_eq!(slot.speed(), 3);
        assert_eq!(slot.context_entries(), 31);
        assert_eq!(slot.root_hub_port_number(), 7);
    }

    /// **The raw encoding, written a second time — and this is why.**
    ///
    /// The test above round-trips every field through the accessor that wrote
    /// it, which pins the getter and setter *to each other* and says nothing
    /// about where the field actually is. `root_hub_port_number` and
    /// `with_root_hub_port_number` both used bits 31:24 until 2026-08-23, both
    /// agreed, and that test passed the whole time. A controller found it:
    /// Address Device was refused until the field moved to 23:16.
    ///
    /// So the layout is asserted against literals here, the same second
    /// transcription the offset tests use. This is the only form of this test
    /// that can fail when both accessors are wrong together.
    #[test]
    fn slot_fields_are_where_the_dword_layout_puts_them() {
        // Dword 0: route string 19:0, speed 23:20, context entries 31:27.
        let dword0 = Slot::new().with_route_and_speed(0xabcde, 3).0[0];
        assert_eq!(dword0 & 0xf_ffff, 0xabcde, "route string is bits 19:0");
        assert_eq!((dword0 >> 20) & 0xf, 3, "speed is bits 23:20");
        assert_eq!(
            Slot::new().with_context_entries(31).0[0] >> 27,
            31,
            "context entries is bits 31:27"
        );

        // Dword 1: max exit latency 15:0, root hub port 23:16, number of
        // ports 31:24. Bits 31:24 are *not* the port -- that is a hub's port
        // count, and writing a port number there is what produced
        // CC_TRB_ERROR from a real controller.
        let dword1 = Slot::new().with_root_hub_port_number(7).0[1];
        assert_eq!(dword1, 7 << 16, "root hub port is bits 23:16, and alone");
        assert_eq!(
            dword1 >> 24,
            0,
            "nothing may land in the number-of-ports field"
        );
    }

    #[test]
    fn context_entries_is_five_bits_and_saturates_there() {
        // 31 is the maximum Device Context Index, and the field is exactly
        // wide enough for it. A wider write would run into the reserved bits
        // above dword 0.
        let slot = Slot::new().with_context_entries(31);
        assert_eq!(slot.context_entries(), 31);
        assert_eq!(slot.0[0] >> 27, 31);
        // And a value that does not fit is masked rather than spilling.
        assert_eq!(Slot::new().with_context_entries(0xff).context_entries(), 31);
    }

    #[test]
    fn slot_state_names_what_the_controller_reports() {
        let mut slot = Slot::new();
        slot.0[3] = 2 << 27;
        assert_eq!(slot.slot_state(), SlotState::Addressed);
        slot.0[3] = 3 << 27;
        assert_eq!(slot.slot_state(), SlotState::Configured);
        // A value the specification does not define is carried, not guessed.
        slot.0[3] = 9 << 27;
        assert_eq!(slot.slot_state(), SlotState::Reserved(9));
    }

    #[test]
    fn endpoint_type_round_trips_and_direction_is_part_of_it() {
        for kind in [
            EndpointType::Control,
            EndpointType::InterruptIn,
            EndpointType::InterruptOut,
            EndpointType::BulkIn,
            EndpointType::BulkOut,
            EndpointType::IsochIn,
            EndpointType::IsochOut,
        ] {
            let ep = Endpoint::new().with_endpoint_type(kind);
            assert_eq!(ep.endpoint_type(), kind);
        }
        // IN and OUT of the same kind are different values, not a flag.
        assert_ne!(
            EndpointType::InterruptIn.as_raw(),
            EndpointType::InterruptOut.as_raw()
        );
        // A HID keyboard reports on interrupt IN, which is 7.
        assert_eq!(EndpointType::InterruptIn.as_raw(), 7);
    }

    #[test]
    fn endpoint_fields_do_not_overlap_each_other() {
        let ep = Endpoint::new()
            .with_endpoint_type(EndpointType::InterruptIn)
            .with_max_packet_size(8)
            .with_error_count(3)
            .with_interval(7)
            .with_average_trb_length(8);
        assert_eq!(ep.endpoint_type(), EndpointType::InterruptIn);
        assert_eq!(ep.max_packet_size(), 8);
        assert_eq!(ep.error_count(), 3);
        assert_eq!(ep.interval(), 7);
        assert_eq!(ep.average_trb_length(), 8);
    }

    #[test]
    fn a_transfer_ring_pointer_must_be_sixteen_byte_aligned() {
        assert!(Endpoint::new().with_transfer_ring(0x1_0000, true).is_some());
        // Eight-byte aligned is not enough: the low four bits are flags.
        assert!(
            Endpoint::new()
                .with_transfer_ring(0x1_0008, false)
                .is_none()
        );
    }

    #[test]
    fn a_transfer_ring_pointer_survives_the_dword_split() {
        // The pointer straddles dwords 2 and 3, which is where a 32-bit
        // truncation would silently drop the top half.
        let ep = Endpoint::new()
            .with_transfer_ring(0x0000_00ff_dead_b000, true)
            .expect("aligned");
        assert_eq!(ep.transfer_ring_pointer(), 0x0000_00ff_dead_b000);
        assert!(ep.dequeue_cycle_state());
    }

    #[test]
    fn the_slot_context_and_control_endpoint_cannot_be_dropped() {
        // Their drop bits are reserved. Refusing is better than writing a
        // reserved bit and finding out what the controller does with it.
        assert!(InputControl::new().dropping(0).is_none());
        assert!(InputControl::new().dropping(1).is_none());
        assert!(InputControl::new().dropping(2).is_some());
        assert!(InputControl::new().dropping(31).is_some());
        assert!(InputControl::new().dropping(32).is_none());
    }

    #[test]
    fn add_and_drop_flags_are_separate_words() {
        let control = InputControl::new()
            .adding(0)
            .expect("valid")
            .adding(1)
            .expect("valid")
            .dropping(3)
            .expect("valid");
        assert_eq!(control.add_flags(), 0b11);
        assert_eq!(control.drop_flags(), 0b1000);
        // Adding must not have disturbed the drop word, or a configure command
        // would tear down endpoints nobody asked it to.
        assert_eq!(control.drop_flags() & control.add_flags(), 0);
    }

    #[test]
    fn the_configuration_triple_shares_one_dword_without_overlapping() {
        let control = InputControl::new().with_configuration(1, 2, 3);
        assert_eq!(control.configuration_value(), 1);
        assert_eq!(control.interface_number(), 2);
        assert_eq!(control.alternate_setting(), 3);
    }

    #[test]
    fn an_input_context_is_sized_for_the_control_context_as_well() {
        // [control][slot] alone is two contexts even for a device using only
        // the control endpoint, whose Device Context Index is 1.
        assert_eq!(input_context_bytes(1, false), Some(3 * 32));
        assert_eq!(input_context_bytes(31, true), Some(33 * 64));
        assert_eq!(input_context_bytes(32, false), None);
    }
}
