// SPDX-License-Identifier: Apache-2.0
// Adapted from the `xhci` crate, Copyright (c) 2021 Hiroki Tokunaga.
// Upstream: https://github.com/rust-osdev/xhci, version 0.9.2, MIT OR Apache-2.0.
//! Transfer Request Blocks, and the rings they sit in.
//!
//! [RFC 0038](../../docs/rfc/0038-vendoring-the-xhci-definitions.md) step 5.
//!
//! A TRB is sixteen bytes — four dwords — and everything the driver ever asks
//! the controller to do is one. Commands go on the command ring, data on a
//! transfer ring per endpoint, and answers come back on an event ring the
//! controller writes and the driver reads.
//!
//! # The cycle bit, which is the whole protocol
//!
//! There is no head or tail pointer shared between the two sides. A ring is a
//! fixed array of TRBs, and **ownership is encoded in one bit per entry**.
//!
//! Each side keeps a *cycle state*. A TRB belongs to the consumer when its
//! cycle bit equals the consumer's cycle state, and to the producer otherwise.
//! The producer writes an entry with its own cycle state — **last**, after
//! every other field — and moves on. The consumer reads entries while their
//! cycle bit matches, and stops at the first one that does not, because that
//! entry has not been written yet.
//!
//! Both sides wrap at the end of the array and **flip their cycle state as they
//! wrap**, which is what stops a stale entry from a previous lap being mistaken
//! for a fresh one. Without the flip, every entry would still carry last lap's
//! bit and the consumer would read the whole ring again.
//!
//! On a command or transfer ring the wrap is a [`Trb::link`] whose *toggle
//! cycle* bit tells the controller to flip; on the event ring the driver flips
//! its own state when it reaches the end of a segment. Getting this wrong does
//! not produce an error — it produces a ring that silently replays or silently
//! stalls, which is why [`owned_by_consumer`] is a named function with tests
//! rather than a comparison written out at each call site.

use crate::{bit32, bits32, bits64};

/// Bytes in one TRB.
pub const BYTES: usize = 16;

/// Dwords in one TRB.
pub const DWORDS: usize = 4;

/// What a TRB is.
///
/// The numbers are the wire encoding, in dword 3 bits 15:10.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Kind {
    /// Data on a transfer ring.
    Normal = 1,
    /// The setup packet of a control transfer.
    SetupStage = 2,
    /// The data phase of a control transfer.
    DataStage = 3,
    /// The status phase of a control transfer.
    StatusStage = 4,
    /// Isochronous data.
    Isoch = 5,
    /// The wrap at the end of a ring segment.
    Link = 6,
    /// An event the driver asked to be generated.
    EventData = 7,
    /// A transfer that does nothing.
    NoopTransfer = 8,
    /// Command: give me a device slot.
    EnableSlot = 9,
    /// Command: take this slot back.
    DisableSlot = 10,
    /// Command: assign this device an address.
    AddressDevice = 11,
    /// Command: configure these endpoints.
    ConfigureEndpoint = 12,
    /// Command: re-read this context.
    EvaluateContext = 13,
    /// Command: recover a halted endpoint.
    ResetEndpoint = 14,
    /// Command: stop an endpoint's ring.
    StopEndpoint = 15,
    /// Command: move an endpoint's dequeue pointer.
    SetTrDequeuePointer = 16,
    /// Command: reset a device.
    ResetDevice = 17,
    /// Command: a command that does nothing, for testing the ring.
    NoopCommand = 23,
    /// Event: a transfer finished, or failed.
    TransferEvent = 32,
    /// Event: a command finished.
    CommandCompletion = 33,
    /// Event: a root hub port changed state.
    PortStatusChange = 34,
    /// Event: the controller has a problem.
    HostController = 37,
    /// A type this crate does not name.
    Other(u32),
}

impl Kind {
    /// The wire encoding.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        match self {
            Self::Normal => 1,
            Self::SetupStage => 2,
            Self::DataStage => 3,
            Self::StatusStage => 4,
            Self::Isoch => 5,
            Self::Link => 6,
            Self::EventData => 7,
            Self::NoopTransfer => 8,
            Self::EnableSlot => 9,
            Self::DisableSlot => 10,
            Self::AddressDevice => 11,
            Self::ConfigureEndpoint => 12,
            Self::EvaluateContext => 13,
            Self::ResetEndpoint => 14,
            Self::StopEndpoint => 15,
            Self::SetTrDequeuePointer => 16,
            Self::ResetDevice => 17,
            Self::NoopCommand => 23,
            Self::TransferEvent => 32,
            Self::CommandCompletion => 33,
            Self::PortStatusChange => 34,
            Self::HostController => 37,
            Self::Other(raw) => raw,
        }
    }

    /// What a wire encoding names.
    ///
    /// Unknown types are carried as [`Kind::Other`] rather than refused: the
    /// controller may legitimately produce an event this crate has no name for,
    /// and a driver must be able to skip it and advance its ring. Refusing
    /// would leave the event ring stuck on an entry nobody can consume.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        match raw {
            1 => Self::Normal,
            2 => Self::SetupStage,
            3 => Self::DataStage,
            4 => Self::StatusStage,
            5 => Self::Isoch,
            6 => Self::Link,
            7 => Self::EventData,
            8 => Self::NoopTransfer,
            9 => Self::EnableSlot,
            10 => Self::DisableSlot,
            11 => Self::AddressDevice,
            12 => Self::ConfigureEndpoint,
            13 => Self::EvaluateContext,
            14 => Self::ResetEndpoint,
            15 => Self::StopEndpoint,
            16 => Self::SetTrDequeuePointer,
            17 => Self::ResetDevice,
            23 => Self::NoopCommand,
            32 => Self::TransferEvent,
            33 => Self::CommandCompletion,
            34 => Self::PortStatusChange,
            37 => Self::HostController,
            other => Self::Other(other),
        }
    }
}

/// How a transfer or command turned out.
///
/// Dword 2, bits 31:24 of an event.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CompletionCode {
    /// **The producer has not written this yet.** Zero is not a failure code;
    /// it is the reset value, and reading it means the driver looked at an
    /// entry it does not own.
    Invalid,
    /// It worked.
    Success,
    /// The controller could not keep up with the data.
    DataBufferError,
    /// The device sent more than it was asked for.
    BabbleDetectedError,
    /// A transaction failed on the wire.
    UsbTransactionError,
    /// The TRB itself was malformed.
    TrbError,
    /// The endpoint halted.
    StallError,
    /// The controller is out of resources.
    ResourceError,
    /// No slots left.
    NoSlotsAvailableError,
    /// The slot is not enabled.
    SlotNotEnabledError,
    /// The endpoint is not enabled.
    EndpointNotEnabledError,
    /// **Fewer bytes than asked for, and not an error.** A device answering a
    /// request with less data than the buffer allows is normal; treating this
    /// as a failure is how a driver rejects perfectly good descriptors.
    ShortPacket,
    /// A parameter in the command was wrong.
    ParameterError,
    /// The slot or endpoint was in the wrong state for the command.
    ContextStateError,
    /// A code this crate does not name.
    Other(u8),
}

impl CompletionCode {
    /// What a wire encoding names.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Invalid,
            1 => Self::Success,
            2 => Self::DataBufferError,
            3 => Self::BabbleDetectedError,
            4 => Self::UsbTransactionError,
            5 => Self::TrbError,
            6 => Self::StallError,
            7 => Self::ResourceError,
            9 => Self::NoSlotsAvailableError,
            11 => Self::SlotNotEnabledError,
            12 => Self::EndpointNotEnabledError,
            13 => Self::ShortPacket,
            17 => Self::ParameterError,
            19 => Self::ContextStateError,
            other => Self::Other(other),
        }
    }

    /// The wire value, whether or not this code has a name here.
    ///
    /// **A code without a name still has a number**, and the number is what a
    /// reader looks up. A report that says only "an unnamed completion code"
    /// has told them the driver does not recognise it and nothing they can act
    /// on -- which cost a reboot of a server on 2026-08-25 to learn what an
    /// Address Device command had actually answered.
    #[must_use]
    pub const fn raw(self) -> u8 {
        match self {
            Self::Invalid => 0,
            Self::Success => 1,
            Self::DataBufferError => 2,
            Self::BabbleDetectedError => 3,
            Self::UsbTransactionError => 4,
            Self::TrbError => 5,
            Self::StallError => 6,
            Self::ResourceError => 7,
            Self::NoSlotsAvailableError => 9,
            Self::SlotNotEnabledError => 11,
            Self::EndpointNotEnabledError => 12,
            Self::ShortPacket => 13,
            Self::ParameterError => 17,
            Self::ContextStateError => 19,
            Self::Other(raw) => raw,
        }
    }

    /// What this code means, in words a boot report can print.
    ///
    /// Codes this enum does not name are described by what the specification's
    /// table calls them where that is known, and as unnamed otherwise -- but
    /// [`CompletionCode::raw`] always has the number.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Invalid => "no completion was written",
            Self::Success => "success",
            Self::DataBufferError => "data buffer error",
            Self::BabbleDetectedError => "the device babbled",
            Self::UsbTransactionError => "usb transaction error -- the device did not answer",
            Self::TrbError => "trb error: the command itself was malformed",
            Self::StallError => "the endpoint stalled",
            Self::ResourceError => "the controller is out of resources",
            Self::NoSlotsAvailableError => "no device slots left",
            Self::SlotNotEnabledError => "that slot is not enabled",
            Self::EndpointNotEnabledError => "that endpoint is not enabled",
            Self::ShortPacket => "short packet",
            Self::ParameterError => "parameter error: a field of the input context is wrong",
            Self::ContextStateError => "context state error: the slot was in the wrong state",
            // Codes the specification defines that this enum has no variant
            // for. Named here rather than left to the number alone, because
            // these are the ones a bring-up actually meets.
            Self::Other(8) => "bandwidth error",
            Self::Other(10) => "the stream id is invalid",
            Self::Other(14) => "ring underrun",
            Self::Other(15) => "ring overrun",
            Self::Other(16) => "vf event ring full",
            Self::Other(18) => "bandwidth overrun",
            Self::Other(20) => "no ping response",
            Self::Other(21) => "the event ring is full",
            Self::Other(22) => "the device was disconnected",
            Self::Other(23) => "missed service error",
            Self::Other(24) => "command ring stopped",
            Self::Other(25) => "the command was aborted",
            Self::Other(26) => "stopped",
            Self::Other(27) => "stopped -- length invalid",
            Self::Other(29) => "max exit latency too large",
            Self::Other(31) => "isoch buffer overrun",
            Self::Other(32) => "the event was lost",
            Self::Other(33) => "an undefined error",
            Self::Other(34) => "the stream id is invalid",
            Self::Other(35) => "secondary bandwidth error",
            Self::Other(36) => "split transaction error",
            Self::Other(_) => "an unnamed completion code",
        }
    }

    /// Whether this code means the operation did what was asked.
    ///
    /// **`ShortPacket` counts as success**, which is the point of asking
    /// through a function rather than comparing against `Success`. A control
    /// transfer that returns fewer bytes than the buffer allowed has succeeded;
    /// a driver that treats it as a failure rejects descriptors that are
    /// perfectly well formed, and USB devices return short packets routinely.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success | Self::ShortPacket)
    }
}

/// Whether a control transfer has a data stage, and which way it goes.
///
/// **The numbers are the wire encoding and one of them is missing on purpose**:
/// dword 3 bits 17:16 encode 0, 2 and 3, and the value 1 is reserved. A
/// contiguous enum would put `Out` at 1 and every control write would be a
/// reserved transfer type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransferType {
    /// No data stage: the request is the whole transfer.
    NoData,
    /// The host sends data.
    Out,
    /// The device sends data.
    In,
}

impl TransferType {
    /// The wire encoding.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        match self {
            Self::NoData => 0,
            Self::Out => 2,
            Self::In => 3,
        }
    }
}

/// Which way data moves on a stage that has a direction bit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    /// Host to device.
    Out,
    /// Device to host.
    In,
}

impl Direction {
    /// Whether this is the device-to-host direction, which is the bit's value.
    #[must_use]
    pub const fn is_in(self) -> bool {
        matches!(self, Self::In)
    }

    /// The direction that acknowledges a transfer moving `self`.
    ///
    /// A control read is acknowledged by writing nothing and a control write by
    /// reading nothing, so a status stage always points the other way. Written
    /// here so that no caller has to remember to invert it.
    #[must_use]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Out => Self::In,
            Self::In => Self::Out,
        }
    }
}

/// One Transfer Request Block.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Trb(pub [u32; DWORDS]);

impl Trb {
    /// An all-zero TRB.
    #[must_use]
    pub const fn new() -> Self {
        Self([0; DWORDS])
    }

    /// Dword 3, bit 0 — who owns this entry.
    #[must_use]
    pub const fn cycle_bit(self) -> bool {
        self.0[3] & 1 != 0
    }

    /// With the cycle bit set to `cycle`.
    ///
    /// **Written last.** Every other field of a TRB must be in memory before
    /// this bit is, because this bit is what hands the entry to the other side.
    /// Setting it first publishes an entry the consumer may read before the
    /// rest of it exists — and on the transfer rings that is a pointer the
    /// controller follows.
    #[must_use]
    pub const fn with_cycle_bit(mut self, cycle: bool) -> Self {
        self.0[3] = (self.0[3] & !1) | if cycle { 1 } else { 0 };
        self
    }

    /// Dword 3, bits 15:10 — what kind of TRB this is.
    #[must_use]
    pub const fn kind(self) -> Kind {
        Kind::from_raw(bits32(self.0[3], 10, 15))
    }

    /// With the type field set.
    #[must_use]
    pub const fn with_kind(mut self, kind: Kind) -> Self {
        self.0[3] = (self.0[3] & !(0b11_1111 << 10)) | ((kind.as_raw() & 0b11_1111) << 10);
        self
    }

    /// Dwords 1:0 — the parameter, which is usually an address.
    #[must_use]
    pub const fn parameter(self) -> u64 {
        ((self.0[1] as u64) << 32) | self.0[0] as u64
    }

    /// With the parameter set.
    #[must_use]
    pub const fn with_parameter(mut self, value: u64) -> Self {
        self.0[0] = value as u32;
        self.0[1] = (value >> 32) as u32;
        self
    }

    /// Dword 2 — the status word.
    #[must_use]
    pub const fn status(self) -> u32 {
        self.0[2]
    }

    /// A Link TRB pointing at `address`, wrapping a ring.
    ///
    /// `toggle` sets the Toggle Cycle bit, which tells the controller to flip
    /// its cycle state here. **Exactly one Link TRB in a ring should toggle**:
    /// the one that closes the loop. A ring whose link does not toggle replays
    /// the previous lap's entries, because they all still carry the old bit; a
    /// ring where every link toggles flips more often than the driver does and
    /// the two sides disagree about who owns what.
    ///
    /// # Errors
    ///
    /// `None` unless `address` is 16-byte aligned — a TRB's own size, and the
    /// alignment every ring must have.
    #[must_use]
    pub const fn link(address: u64, toggle: bool, cycle: bool) -> Option<Self> {
        if address & 0b1111 != 0 {
            return None;
        }
        let mut trb = Self::new().with_parameter(address).with_kind(Kind::Link);
        if toggle {
            trb.0[3] |= 1 << 1;
        }
        Some(trb.with_cycle_bit(cycle))
    }

    /// Whether this Link TRB toggles the cycle state. Dword 3, bit 1.
    #[must_use]
    pub const fn toggle_cycle(self) -> bool {
        self.0[3] & (1 << 1) != 0
    }

    /// An Enable Slot command.
    #[must_use]
    pub const fn enable_slot(cycle: bool) -> Self {
        Self::new()
            .with_kind(Kind::EnableSlot)
            .with_cycle_bit(cycle)
    }

    /// A No-Op command, which is how a driver proves its command ring works.
    #[must_use]
    pub const fn no_op_command(cycle: bool) -> Self {
        Self::new()
            .with_kind(Kind::NoopCommand)
            .with_cycle_bit(cycle)
    }

    /// An Address Device command for `slot`, using the input context at
    /// `input_context`.
    ///
    /// # Errors
    ///
    /// `None` unless `input_context` is 16-byte aligned, or if `slot` is zero —
    /// slot zero is not a slot.
    #[must_use]
    pub const fn address_device(input_context: u64, slot: u8, cycle: bool) -> Option<Self> {
        if input_context & 0b1111 != 0 || slot == 0 {
            return None;
        }
        let mut trb = Self::new()
            .with_parameter(input_context)
            .with_kind(Kind::AddressDevice);
        trb.0[3] |= (slot as u32) << 24;
        Some(trb.with_cycle_bit(cycle))
    }

    /// A Configure Endpoint command for `slot`.
    ///
    /// # Errors
    ///
    /// As [`Trb::address_device`].
    #[must_use]
    pub const fn configure_endpoint(input_context: u64, slot: u8, cycle: bool) -> Option<Self> {
        if input_context & 0b1111 != 0 || slot == 0 {
            return None;
        }
        let mut trb = Self::new()
            .with_parameter(input_context)
            .with_kind(Kind::ConfigureEndpoint);
        trb.0[3] |= (slot as u32) << 24;
        Some(trb.with_cycle_bit(cycle))
    }

    /// A Normal TRB: `length` bytes at `buffer`.
    ///
    /// # Errors
    ///
    /// `None` if `length` does not fit the 17-bit transfer-length field. The
    /// field is not wide enough for an arbitrary buffer, and truncating it
    /// would tell the controller to move a different amount of data than the
    /// caller allocated for.
    #[must_use]
    pub const fn normal(buffer: u64, length: u32, cycle: bool) -> Option<Self> {
        if length > 0x1_ffff {
            return None;
        }
        let mut trb = Self::new().with_parameter(buffer).with_kind(Kind::Normal);
        trb.0[2] = length;
        Some(trb.with_cycle_bit(cycle))
    }

    /// With Interrupt On Completion set. Dword 3, bit 5.
    ///
    /// **The last TRB of a transfer descriptor needs this or nothing is ever
    /// reported.** The controller executes the whole descriptor and posts a
    /// Transfer Event only where it is asked to — so a control transfer whose
    /// Status Stage does not carry it completes, correctly and silently, and
    /// the driver waits for ever.
    #[must_use]
    pub const fn with_interrupt_on_completion(mut self, interrupt: bool) -> Self {
        if interrupt {
            self.0[3] |= 1 << 5;
        } else {
            self.0[3] &= !(1 << 5);
        }
        self
    }

    /// Whether Interrupt On Completion is set.
    #[must_use]
    pub const fn interrupt_on_completion(self) -> bool {
        bit32(self.0[3], 5)
    }

    /// A Setup Stage TRB carrying the eight bytes of a control request.
    ///
    /// **The setup packet is immediate data, not a pointer.** Dwords 0 and 1
    /// *are* the eight bytes, and dword 3's Immediate Data bit says so — which
    /// this sets, because a Setup Stage without it points the controller at
    /// whatever address those eight bytes happen to spell.
    ///
    /// The transfer length is fixed at eight for the same reason: it is the
    /// size of the packet, not of the data the request will move.
    #[must_use]
    pub const fn setup_stage(setup: [u8; 8], transfer: TransferType, cycle: bool) -> Self {
        let low = u32::from_le_bytes([setup[0], setup[1], setup[2], setup[3]]);
        let high = u32::from_le_bytes([setup[4], setup[5], setup[6], setup[7]]);
        let mut trb = Self::new().with_kind(Kind::SetupStage);
        trb.0[0] = low;
        trb.0[1] = high;
        // Bits 16:0. The packet is always eight bytes.
        trb.0[2] = 8;
        // Bit 6, Immediate Data.
        trb.0[3] |= 1 << 6;
        // Bits 17:16, Transfer Type.
        trb.0[3] |= transfer.as_raw() << 16;
        trb.with_cycle_bit(cycle)
    }

    /// A Data Stage TRB: `length` bytes at `buffer`, in `direction`.
    ///
    /// # Errors
    ///
    /// `None` if `length` does not fit the 17-bit transfer-length field, as
    /// [`Trb::normal`].
    #[must_use]
    pub const fn data_stage(
        buffer: u64,
        length: u32,
        direction: Direction,
        cycle: bool,
    ) -> Option<Self> {
        if length > 0x1_ffff {
            return None;
        }
        let mut trb = Self::new()
            .with_parameter(buffer)
            .with_kind(Kind::DataStage);
        trb.0[2] = length;
        if direction.is_in() {
            // Bit 16, Direction.
            trb.0[3] |= 1 << 16;
        }
        Some(trb.with_cycle_bit(cycle))
    }

    /// A Status Stage TRB, which ends a control transfer.
    ///
    /// **Its direction is the opposite of the data stage's**, and that is not a
    /// convention this function can enforce — a control read is acknowledged by
    /// writing nothing, and a control write by reading nothing. A status stage
    /// pointing the same way as its data stage is a transfer the device never
    /// completes.
    #[must_use]
    pub const fn status_stage(direction: Direction, cycle: bool) -> Self {
        let mut trb = Self::new().with_kind(Kind::StatusStage);
        if direction.is_in() {
            trb.0[3] |= 1 << 16;
        }
        trb.with_cycle_bit(cycle)
    }

    /// Event: dword 3, bits 31:24 — which slot this concerns.
    #[must_use]
    pub const fn slot_id(self) -> u8 {
        bits32(self.0[3], 24, 31) as u8
    }

    /// Event: dword 3, bits 20:16 — which endpoint, as a Device Context Index.
    #[must_use]
    pub const fn endpoint_id(self) -> u8 {
        bits32(self.0[3], 16, 20) as u8
    }

    /// Event: dword 2, bits 31:24 — how it turned out.
    #[must_use]
    pub const fn completion_code(self) -> CompletionCode {
        CompletionCode::from_raw(bits32(self.0[2], 24, 31) as u8)
    }

    /// Transfer event: dword 2, bits 23:0 — bytes **not** transferred.
    ///
    /// **A residue, not a count.** The field is what was left over, so a
    /// complete transfer reports zero here. Reading it as "bytes moved" inverts
    /// every length a driver computes.
    #[must_use]
    pub const fn transfer_length_remaining(self) -> u32 {
        bits32(self.0[2], 0, 23)
    }

    /// Command completion event: dwords 1:0 — which command finished.
    ///
    /// The address of the command TRB on the command ring, which is how a
    /// driver matches an answer to a question it asked.
    #[must_use]
    pub const fn command_trb_pointer(self) -> u64 {
        bits64(self.parameter(), 4, 63) << 4
    }

    /// Port status change event: dword 0, bits 31:24 — which port changed.
    #[must_use]
    pub const fn port_id(self) -> u8 {
        bits32(self.0[0], 24, 31) as u8
    }
}

/// Whether the consumer owns the entry, given both cycle states.
///
/// The entire ownership protocol, in one comparison, named so it can be tested
/// and so no call site writes it out and gets it backwards. A TRB belongs to
/// the consumer when its cycle bit **equals** the consumer's cycle state.
#[must_use]
pub const fn owned_by_consumer(trb_cycle: bool, consumer_cycle: bool) -> bool {
    trb_cycle == consumer_cycle
}

/// Bytes a ring of `entries` TRBs occupies.
#[must_use]
pub const fn ring_bytes(entries: usize) -> usize {
    entries * BYTES
}

/// How many TRBs of a `entries`-entry command or transfer ring carry work.
///
/// **One fewer than the ring holds**, because the last entry must be the Link
/// TRB that wraps it. A driver that fills all of them overwrites its own link,
/// and the controller then runs off the end of the segment into whatever
/// follows it in memory — by DMA.
///
/// Answers `None` for a ring too small to hold a link and anything else.
#[must_use]
pub const fn usable_entries(entries: usize) -> Option<usize> {
    if entries < 2 {
        return None;
    }
    Some(entries - 1)
}

/// An Event Ring Segment Table entry: where a segment is and how big.
///
/// Sixteen bytes, like a TRB, but it is not one: it has no cycle bit and no
/// type, and the controller reads it once when the driver points `ERSTBA` at
/// the table.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SegmentTableEntry(pub [u32; DWORDS]);

impl SegmentTableEntry {
    /// An entry describing `entries` TRBs at `address`.
    ///
    /// # Errors
    ///
    /// `None` unless `address` is **64-byte** aligned — note this is stricter
    /// than a ring's own 16-byte alignment — or unless the size is between 16
    /// and 4096, which is what the specification allows for a segment.
    #[must_use]
    pub const fn new(address: u64, entries: u16) -> Option<Self> {
        if address & 0x3f != 0 || entries < 16 || entries > 4096 {
            return None;
        }
        let mut raw = [0u32; DWORDS];
        raw[0] = address as u32;
        raw[1] = (address >> 32) as u32;
        raw[2] = entries as u32;
        Some(Self(raw))
    }

    /// Where the segment is.
    #[must_use]
    pub const fn address(self) -> u64 {
        (((self.0[1] as u64) << 32) | self.0[0] as u64) & !0x3f
    }

    /// How many TRBs the segment holds.
    #[must_use]
    pub const fn entries(self) -> u16 {
        bits32(self.0[2], 0, 15) as u16
    }
}

#[cfg(test)]
mod control_transfer_tests {
    use super::*;

    /// **Raw encodings against literals, not round trips.** On 2026-08-23 a
    /// getter and setter pair in `context` were both wrong about a bit range,
    /// agreed with each other, and were pinned by a test that read the value
    /// back through the accessor that wrote it — which passed the whole time.
    /// These assert the dwords.
    #[test]
    fn a_setup_stage_carries_its_packet_as_immediate_data() {
        // A GET_DESCRIPTOR(DEVICE, 0, 18): 0x80 0x06 0x00 0x01 0x00 0x00 0x12 0x00.
        let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
        let trb = Trb::setup_stage(setup, TransferType::In, true);

        assert_eq!(
            trb.0[0], 0x0100_0680,
            "dwords 0 and 1 *are* the eight bytes"
        );
        // Dword 1 is wIndex[15:0] then wLength[31:16]. This assertion was
        // first written as 0x0000_0012 -- the two halves the wrong way round --
        // and the test caught its own author.
        assert_eq!(trb.0[1], 0x0012_0000);
        assert_eq!(trb.0[1] & 0xffff, 0, "wIndex is the low half");
        assert_eq!(
            trb.0[1] >> 16,
            18,
            "wLength is the high half: 18 bytes asked for"
        );
        assert_eq!(
            trb.0[2], 8,
            "the transfer length is the size of the packet, not of the data \
             the request will move"
        );
        assert_eq!(trb.kind(), Kind::SetupStage);
        assert!(trb.cycle_bit());
        assert!(
            trb.0[3] & (1 << 6) != 0,
            "Immediate Data: without it the controller reads those eight bytes \
             as an address"
        );
        assert_eq!((trb.0[3] >> 16) & 0b11, 3, "Transfer Type In is 3");
    }

    #[test]
    fn the_reserved_transfer_type_is_not_reachable() {
        // Bits 17:16 encode 0, 2 and 3. One is reserved, so a contiguous enum
        // would make every control write a reserved transfer type.
        assert_eq!(TransferType::NoData.as_raw(), 0);
        assert_eq!(TransferType::Out.as_raw(), 2);
        assert_eq!(TransferType::In.as_raw(), 3);
        for kind in [TransferType::NoData, TransferType::Out, TransferType::In] {
            assert_ne!(kind.as_raw(), 1, "1 is reserved");
        }
    }

    #[test]
    fn a_data_stage_points_at_its_buffer_and_names_its_direction() {
        let trb =
            Trb::data_stage(0x1_0000_4000, 18, Direction::In, true).expect("a length that fits");
        assert_eq!(trb.parameter(), 0x1_0000_4000);
        assert_eq!(trb.0[2] & 0x1_ffff, 18);
        assert_eq!(trb.kind(), Kind::DataStage);
        assert!(trb.0[3] & (1 << 16) != 0, "Direction In is bit 16 set");

        let out = Trb::data_stage(0x1_0000_4000, 18, Direction::Out, true).expect("fits");
        assert_eq!(out.0[3] & (1 << 16), 0, "Direction Out is bit 16 clear");
    }

    #[test]
    fn a_transfer_length_that_does_not_fit_is_refused_rather_than_truncated() {
        assert!(Trb::data_stage(0x1000, 0x1_ffff, Direction::In, true).is_some());
        assert!(
            Trb::data_stage(0x1000, 0x2_0000, Direction::In, true).is_none(),
            "truncating would tell the controller to move a different amount \
             of data than the caller allocated for"
        );
    }

    #[test]
    fn a_status_stage_carries_no_data_at_all() {
        let trb = Trb::status_stage(Direction::Out, true);
        assert_eq!(trb.0[0], 0, "dwords 0 and 1 are reserved on a status stage");
        assert_eq!(trb.0[1], 0);
        assert_eq!(trb.0[2], 0);
        assert_eq!(trb.kind(), Kind::StatusStage);
    }

    #[test]
    fn a_status_stage_points_the_opposite_way_to_its_data_stage() {
        // A control read is acknowledged by writing nothing and a control write
        // by reading nothing. A status stage pointing the same way as its data
        // stage is a transfer the device never completes.
        assert_eq!(Direction::In.opposite(), Direction::Out);
        assert_eq!(Direction::Out.opposite(), Direction::In);
        let status = Trb::status_stage(Direction::In.opposite(), true);
        assert_eq!(status.0[3] & (1 << 16), 0);
    }

    #[test]
    fn interrupt_on_completion_is_bit_five_and_nothing_reports_without_it() {
        let quiet = Trb::status_stage(Direction::Out, true);
        assert!(!quiet.interrupt_on_completion());
        let loud = quiet.with_interrupt_on_completion(true);
        assert!(loud.interrupt_on_completion());
        assert_eq!(loud.0[3] & (1 << 5), 1 << 5);
        assert_eq!(
            loud.with_interrupt_on_completion(false).0[3],
            quiet.0[3],
            "clearing it must put the dword back exactly"
        );
    }

    #[test]
    fn every_stage_publishes_on_the_cycle_it_was_given() {
        // The cycle bit is the whole protocol: a stage published with the wrong
        // one is a stage the controller reads as not yet written.
        for cycle in [false, true] {
            assert_eq!(
                Trb::setup_stage([0; 8], TransferType::NoData, cycle).cycle_bit(),
                cycle
            );
            assert_eq!(
                Trb::data_stage(0x1000, 1, Direction::In, cycle)
                    .expect("fits")
                    .cycle_bit(),
                cycle
            );
            assert_eq!(Trb::status_stage(Direction::Out, cycle).cycle_bit(), cycle);
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn every_named_completion_code_round_trips_through_its_number() {
        // `raw` and `from_raw` are two hand-written tables of the same
        // mapping. A variant added to one and not the other reports a code
        // that decodes back to something else.
        for raw in 0u8..=255 {
            let code = CompletionCode::from_raw(raw);
            assert_eq!(code.raw(), raw, "code {raw} does not round trip");
        }
    }

    #[test]
    fn an_unnamed_code_still_carries_its_number() {
        // The property the boot report depends on: a code this enum has no
        // variant for must still print as a number a reader can look up.
        let code = CompletionCode::from_raw(200);
        assert_eq!(code.raw(), 200);
        assert_eq!(code.describe(), "an unnamed completion code");
    }

    #[test]
    fn codes_the_enum_does_not_name_are_still_described() {
        // 22 is "the device was disconnected" -- the kind of answer a
        // bring-up on real hardware actually gets, and one this enum has no
        // variant for.
        assert_eq!(
            CompletionCode::from_raw(22).describe(),
            "the device was disconnected"
        );
        assert_eq!(
            CompletionCode::from_raw(4).describe(),
            "usb transaction error -- the device did not answer"
        );
    }

    use super::*;

    #[test]
    fn a_trb_is_sixteen_bytes_of_four_dwords() {
        assert_eq!(BYTES, 16);
        assert_eq!(DWORDS, 4);
        assert_eq!(ring_bytes(256), 4096);
    }

    /// **The ownership rule, and it is the protocol.**
    #[test]
    fn a_trb_belongs_to_the_consumer_when_the_bits_match() {
        assert!(owned_by_consumer(true, true));
        assert!(owned_by_consumer(false, false));
        // A mismatch means the producer has not written it yet. Reading it
        // anyway is reading uninitialised memory as a command.
        assert!(!owned_by_consumer(true, false));
        assert!(!owned_by_consumer(false, true));
    }

    #[test]
    fn a_ring_keeps_one_entry_back_for_its_link() {
        // Fill all of them and the link is overwritten, after which the
        // controller runs off the end of the segment.
        assert_eq!(usable_entries(256), Some(255));
        assert_eq!(usable_entries(2), Some(1));
        // A ring of one could hold only the link and no work at all.
        assert_eq!(usable_entries(1), None);
        assert_eq!(usable_entries(0), None);
    }

    #[test]
    fn the_type_field_round_trips_through_the_wire_encoding() {
        for kind in [
            Kind::Normal,
            Kind::Link,
            Kind::EnableSlot,
            Kind::AddressDevice,
            Kind::ConfigureEndpoint,
            Kind::NoopCommand,
            Kind::TransferEvent,
            Kind::CommandCompletion,
            Kind::PortStatusChange,
        ] {
            let trb = Trb::new().with_kind(kind);
            assert_eq!(trb.kind(), kind, "{kind:?}");
        }
    }

    #[test]
    fn an_unknown_type_is_carried_rather_than_refused() {
        // The controller may produce an event this crate has no name for, and
        // a driver must skip it and advance. Refusing would wedge the ring on
        // an entry nobody can consume.
        let trb = Trb::new().with_kind(Kind::Other(41));
        assert_eq!(trb.kind(), Kind::Other(41));
    }

    #[test]
    fn the_type_field_does_not_disturb_the_cycle_bit() {
        // They share dword 3, and the cycle bit is the one that publishes the
        // entry -- a type write that cleared it would un-publish a TRB.
        let trb = Trb::new().with_cycle_bit(true).with_kind(Kind::EnableSlot);
        assert!(trb.cycle_bit());
        assert_eq!(trb.kind(), Kind::EnableSlot);
        let trb = Trb::new().with_kind(Kind::EnableSlot).with_cycle_bit(true);
        assert!(trb.cycle_bit());
        assert_eq!(trb.kind(), Kind::EnableSlot);
    }

    #[test]
    fn a_link_trb_carries_its_pointer_and_its_toggle_separately() {
        let link = Trb::link(0xdead_b000, true, true).expect("aligned");
        assert_eq!(link.kind(), Kind::Link);
        assert_eq!(link.parameter(), 0xdead_b000);
        assert!(link.toggle_cycle());
        assert!(link.cycle_bit());

        // Toggle and cycle are different bits and must not be confused: a link
        // that toggles when it should not makes both sides disagree about who
        // owns the ring.
        let link = Trb::link(0xdead_b000, false, true).expect("aligned");
        assert!(!link.toggle_cycle());
        assert!(link.cycle_bit());
    }

    #[test]
    fn a_ring_pointer_must_be_sixteen_byte_aligned() {
        assert!(Trb::link(0x1_0000, true, false).is_some());
        assert!(Trb::link(0x1_0008, true, false).is_none());
    }

    #[test]
    fn slot_zero_is_not_a_slot() {
        assert!(Trb::address_device(0x1000, 1, true).is_some());
        assert!(Trb::address_device(0x1000, 0, true).is_none());
        assert!(Trb::configure_endpoint(0x1000, 0, true).is_none());
    }

    #[test]
    fn a_command_carries_its_slot_without_disturbing_its_type() {
        let trb = Trb::address_device(0x1_0000, 7, true).expect("valid");
        assert_eq!(trb.kind(), Kind::AddressDevice);
        assert_eq!(trb.slot_id(), 7);
        assert_eq!(trb.parameter(), 0x1_0000);
        assert!(trb.cycle_bit());
    }

    #[test]
    fn a_transfer_length_that_does_not_fit_is_refused() {
        // Seventeen bits. Truncating would tell the controller to move a
        // different amount of data than the caller allocated for.
        assert!(Trb::normal(0x1000, 0x1_ffff, true).is_some());
        assert!(Trb::normal(0x1000, 0x2_0000, true).is_none());
    }

    #[test]
    fn short_packet_counts_as_success() {
        // The reason `is_success` exists rather than `== Success`. USB devices
        // return short packets routinely, and rejecting them rejects perfectly
        // well-formed descriptors.
        assert!(CompletionCode::Success.is_success());
        assert!(CompletionCode::ShortPacket.is_success());
        assert!(!CompletionCode::StallError.is_success());
        // And zero is not a failure code -- it means nobody wrote this yet.
        assert!(!CompletionCode::Invalid.is_success());
        assert_eq!(CompletionCode::from_raw(0), CompletionCode::Invalid);
        assert_eq!(CompletionCode::from_raw(13), CompletionCode::ShortPacket);
        assert_eq!(CompletionCode::from_raw(200), CompletionCode::Other(200));
    }

    #[test]
    fn event_fields_read_from_the_dwords_that_hold_them() {
        let mut event = Trb::new().with_kind(Kind::TransferEvent);
        event.0[2] = (1 << 24) | 0x1234; // Success, 0x1234 bytes left over
        event.0[3] |= (9 << 24) | (3 << 16); // slot 9, endpoint index 3
        assert_eq!(event.completion_code(), CompletionCode::Success);
        assert_eq!(event.transfer_length_remaining(), 0x1234);
        assert_eq!(event.slot_id(), 9);
        assert_eq!(event.endpoint_id(), 3);
    }

    #[test]
    fn the_transfer_length_is_a_residue_and_not_a_count() {
        // A complete transfer reports zero left over. This test exists because
        // reading it the other way inverts every length a driver computes.
        let mut event = Trb::new();
        event.0[2] = 1 << 24;
        assert_eq!(event.transfer_length_remaining(), 0);
    }

    #[test]
    fn a_command_completion_names_the_command_it_answers() {
        let mut event = Trb::new().with_kind(Kind::CommandCompletion);
        event = event.with_parameter(0xdead_b000);
        assert_eq!(event.command_trb_pointer(), 0xdead_b000);
    }

    #[test]
    fn a_segment_table_entry_is_stricter_than_the_ring_it_points_at() {
        // 64-byte alignment here, against 16 for a ring itself.
        assert!(SegmentTableEntry::new(0x1_0000, 256).is_some());
        assert!(SegmentTableEntry::new(0x1_0010, 256).is_none());
        // And the size has a floor and a ceiling.
        assert!(SegmentTableEntry::new(0x1_0000, 15).is_none());
        assert!(SegmentTableEntry::new(0x1_0000, 16).is_some());
        assert!(SegmentTableEntry::new(0x1_0000, 4096).is_some());
        assert!(SegmentTableEntry::new(0x1_0000, 4097).is_none());
    }

    #[test]
    fn a_segment_table_entry_reads_back_what_it_was_given() {
        let entry = SegmentTableEntry::new(0x0000_00ff_dead_b000, 256).expect("valid");
        assert_eq!(entry.address(), 0x0000_00ff_dead_b000);
        assert_eq!(entry.entries(), 256);
    }
}
