// SPDX-License-Identifier: Apache-2.0
//! The telemetry plane's arithmetic — RFC 0026 step 1.
//!
//! Three things live here, and nothing else does:
//!
//! - **The event**: a 64-byte record — timestamp, CPU, domain, class, schema,
//!   forty bytes of payload — with its wire format defined by [`Event::to_bytes`]
//!   and [`Event::from_bytes`] rather than by a `repr` attribute, so the
//!   contract is bytes, not a compiler's layout choice.
//! - **The schema registry** ([`schema`]): the build-time table of payload
//!   formats and the hash over it that lets a reader refuse a registry it was
//!   not built against, instead of misdecoding structurally.
//! - **The ring protocol** ([`ring`]): every decision the producer and
//!   consumer make — admit or drop, clamp a hostile tail claim, how much is
//!   readable, where a sequence number lands in the region — as pure
//!   functions. The kernel performs the stores; `bin/traced` performs the
//!   loads; this crate decides, and a host test drives both sides of the
//!   same arithmetic in one process.
//!
//! What is deliberately *not* here: atomics, volatile accesses, and any
//! notion of shared memory. Those are the kernel's (RFC 0026 step 2) and the
//! reader's (step 4), against the offsets and decisions defined here. That
//! split is what makes the whole protocol host-testable, and it is why the
//! crate can forbid `unsafe` outright.

// Nothing that ships sees `std`: the crate is `no_std` in every build that
// is not the test harness, which needs it for the harness itself and the
// iteration-count environment variable.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod ring;
pub mod schema;

/// Bytes in one event record, on the wire and in a ring slot.
pub const EVENT_BYTES: usize = 64;

/// Bytes of schema-typed payload one event carries. Fixed on purpose: a
/// variable-length record needs a walk to index, can tear across a boundary,
/// and invites the payload to become a buffer. Forty is what is left of the
/// slot once the header fields have said when, where, and what shape.
pub const PAYLOAD_BYTES: usize = 40;

/// The event classes, exactly [ai-native.md](../docs/ai-native.md) §2's set.
///
/// A class is a *filter dimension* — the enable mask and a consumer's
/// interest are expressed in classes — and is deliberately independent of
/// the schema: the schema says how to read the payload, the class says which
/// subsystem's story it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EventClass {
    /// Scheduler: dispatches, wakes, migrations.
    Sched = 0,
    /// Memory: allocation, reclaim, faults serviced.
    Memory = 1,
    /// Block and device I/O.
    Io = 2,
    /// The network path.
    Net = 3,
    /// System call entry and exit, IPC rendezvous.
    Syscall = 4,
    /// Capability grants, derivations, revocations.
    Cap = 5,
    /// Exceptions and faults.
    Fault = 6,
    /// Audit. **Reserved and refused in Phase 2**: `security.md` §8 requires
    /// audit events to apply backpressure rather than drop, and a
    /// best-effort audit event is false assurance. The class exists so the
    /// numbering is settled; emitting it is counted and dropped until the
    /// audit RFC builds its ring.
    Audit = 7,
}

impl EventClass {
    /// How many classes exist. The enable mask is one bit per class.
    pub const COUNT: usize = 8;

    /// This class's bit in the enable mask.
    #[must_use]
    pub const fn bit(self) -> u32 {
        1 << (self as u32)
    }

    /// The class a wire value names, or `None` — a decoder never trusts the
    /// bytes to be one of ours.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Sched),
            1 => Some(Self::Memory),
            2 => Some(Self::Io),
            3 => Some(Self::Net),
            4 => Some(Self::Syscall),
            5 => Some(Self::Cap),
            6 => Some(Self::Fault),
            7 => Some(Self::Audit),
            _ => None,
        }
    }
}

/// Whether `class` is enabled in `mask`. The emit path's first and usually
/// only step: one load, one test, one predicted-not-taken branch.
#[must_use]
pub const fn enabled(mask: u32, class: EventClass) -> bool {
    mask & class.bit() != 0
}

/// One telemetry event.
///
/// The wire format is the field order below, each integer little-endian,
/// payload verbatim — 64 bytes exactly, defined by [`Event::to_bytes`] and
/// not by this struct's memory layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    /// The raw TSC at emit. Raw on purpose: converting to nanoseconds at
    /// emit time puts a multiply and a divide in every producer; the reader
    /// converts once per batch with the rate the kernel reports.
    pub timestamp: u64,
    /// The CPU that emitted. Always the producer's own — there is no
    /// cross-CPU emit path.
    pub cpu: u32,
    /// The `DomainId` of the domain running when the event was emitted —
    /// the id without the generation, a stated narrowness of RFC 0026: a
    /// tracing consumer correlates over windows where slot reuse is rare
    /// and visible, and a schema that needs the generation carries it in
    /// its own payload.
    pub domain: u32,
    /// The event's class, as [`EventClass::from_u32`] reads it. Stored raw
    /// so an `Event` can round-trip bytes it would refuse to decode.
    pub class: u32,
    /// The payload's schema id, resolved against [`schema::SCHEMAS`].
    pub schema: u32,
    /// The schema-typed payload. Bytes past the schema's declared size are
    /// zero on emit and ignored on decode.
    pub payload: [u8; PAYLOAD_BYTES],
}

impl Event {
    /// The wire form: 64 bytes, the contract both sides are built against.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; EVENT_BYTES] {
        let mut bytes = [0u8; EVENT_BYTES];
        bytes[0..8].copy_from_slice(&self.timestamp.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.cpu.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.domain.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.class.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.schema.to_le_bytes());
        bytes[24..64].copy_from_slice(&self.payload);
        bytes
    }

    /// Reads the wire form back. Total: any 64 bytes are *an* event, which
    /// is the point — refusing malformed ones is [`decode`]'s job, and a
    /// reader that cannot even represent bad bytes cannot count them.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; EVENT_BYTES]) -> Self {
        let word64 = |at: usize| {
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[at..at + 8]);
            u64::from_le_bytes(word)
        };
        let word32 = |at: usize| {
            let mut word = [0u8; 4];
            word.copy_from_slice(&bytes[at..at + 4]);
            u32::from_le_bytes(word)
        };
        let mut payload = [0u8; PAYLOAD_BYTES];
        payload.copy_from_slice(&bytes[24..64]);
        Self {
            timestamp: word64(0),
            cpu: word32(8),
            domain: word32(12),
            class: word32(16),
            schema: word32(20),
            payload,
        }
    }
}

/// Why a decode was refused. Counted by consumers, never fatal: an unknown
/// event in the stream is skipped and said, not indexed blindly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The class field names no class this build knows.
    UnknownClass(u32),
    /// The schema field names no entry in [`schema::SCHEMAS`].
    UnknownSchema(u32),
}

/// Decodes one slot's bytes into a validated event: the class must be one of
/// ours and the schema must be registered. This is the only door a consumer
/// reads events through.
///
/// # Errors
///
/// [`Refusal`] names the field that failed; the caller counts and skips.
pub fn decode(bytes: &[u8; EVENT_BYTES]) -> Result<(Event, &'static schema::Schema), Refusal> {
    let event = Event::from_bytes(bytes);
    if EventClass::from_u32(event.class).is_none() {
        return Err(Refusal::UnknownClass(event.class));
    }
    let Some(found) = schema::find(event.schema) else {
        return Err(Refusal::UnknownSchema(event.schema));
    };
    Ok((event, found))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_event_round_trips_through_its_wire_form() {
        let mut payload = [0u8; PAYLOAD_BYTES];
        payload[0] = 0xAB;
        payload[PAYLOAD_BYTES - 1] = 0xCD;
        let event = Event {
            timestamp: 0x0123_4567_89AB_CDEF,
            cpu: 3,
            domain: 17,
            class: EventClass::Net as u32,
            schema: schema::PROBE.id,
            payload,
        };
        assert_eq!(Event::from_bytes(&event.to_bytes()), event);
    }

    #[test]
    fn every_class_survives_its_own_wire_value_and_nothing_else_does() {
        for value in 0..EventClass::COUNT as u32 {
            let class = EventClass::from_u32(value);
            assert_eq!(class.map(|class| class as u32), Some(value));
        }
        assert_eq!(EventClass::from_u32(8), None);
        assert_eq!(EventClass::from_u32(u32::MAX), None);
    }

    #[test]
    fn the_mask_enables_exactly_the_classes_whose_bits_are_set() {
        let mask = EventClass::Sched.bit() | EventClass::Audit.bit();
        assert!(enabled(mask, EventClass::Sched));
        assert!(enabled(mask, EventClass::Audit));
        assert!(!enabled(mask, EventClass::Net));
        assert!(!enabled(0, EventClass::Sched));
    }

    #[test]
    fn decode_refuses_an_unknown_class_and_an_unknown_schema_by_name() {
        let good = Event {
            timestamp: 1,
            cpu: 0,
            domain: 0,
            class: EventClass::Sched as u32,
            schema: schema::PROBE.id,
            payload: [0; PAYLOAD_BYTES],
        };
        assert!(decode(&good.to_bytes()).is_ok());

        let mut bad_class = good;
        bad_class.class = 200;
        assert_eq!(
            decode(&bad_class.to_bytes()),
            Err(Refusal::UnknownClass(200))
        );

        let mut bad_schema = good;
        bad_schema.schema = 0xDEAD;
        assert_eq!(
            decode(&bad_schema.to_bytes()),
            Err(Refusal::UnknownSchema(0xDEAD))
        );
    }
}
