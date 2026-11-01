// SPDX-License-Identifier: Apache-2.0
//! The audit ring's arithmetic -- RFC 0101 step 1.
//!
//! RFC 0026 reserved the `Audit` class and refused it, because a
//! best-effort audit event is false assurance with a checksum. This is the
//! ring it was waiting for, and it differs from the telemetry plane's in the
//! three ways that sentence demands:
//!
//! - **Nothing is dropped.** An operation that can be refused reserves its
//!   slot *before* it changes anything, and is refused when the ring is
//!   full. One that must not be refused -- taking authority away -- draws
//!   on headroom the refusable ones may not touch, and if even that is gone
//!   it proceeds and is counted as a **gap**, which the next record that
//!   fits states. A record is never silently absent.
//! - **One ring, in one order.** A chain needs a total order, so the
//!   producers share one ring under the kernel's lock, rather than one ring
//!   per CPU merged afterwards.
//! - **Names that survive reuse.** A domain is named with its generation and
//!   a capability by a serial the kernel never reuses in a boot.
//!
//! As with [`crate::ring`], nothing here touches shared memory: [`Ledger`]
//! decides what is written where, and the kernel performs the stores.

use crate::ring;

/// Bytes in one audit record: a telemetry slot's size, so the same layout
/// arithmetic places it.
pub const RECORD_BYTES: usize = crate::EVENT_BYTES;

/// `b"BHXAUD01"`, little-endian: written last at bring-up, as the plane's
/// marker is, so a reader that maps an unwritten ring refuses it.
pub const MARKER: u64 = u64::from_le_bytes(*b"BHXAUD01");

/// Header offset of [`MARKER`].
pub const MARKER_OFFSET: usize = 0;
/// Header offset of the slot count.
pub const SLOTS_OFFSET: usize = 8;
/// Header offset of the count of refused operations.
pub const REFUSED_OFFSET: usize = 16;
/// Header offset of the count of operations that proceeded unrecorded.
pub const GAPS_OFFSET: usize = 24;
/// Header offset of `head`, alone on its cache line, published with a
/// release store after the records below it are whole.
pub const HEAD_OFFSET: usize = 64;

/// What a record says happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// The reader attached. The first record of a boot's chain: it carries
    /// the boot's identity, and how many operations happened before it.
    Attach = 1,
    /// Operations that happened while the ring had no room, and were not
    /// recorded. `count` says how many.
    Gap = 2,
    /// A capability was given to another domain.
    Grant = 3,
    /// A capability was derived into the caller's own CSpace.
    Derive = 4,
    /// A capability and everything derived from it were destroyed.
    Revoke = 5,
    /// A domain was created.
    DomainCreated = 6,
    /// A domain ended, for the reason in `object_kind`.
    DomainEnded = 7,
}

impl Kind {
    /// One more than the largest kind, for tables indexed by kind.
    pub const LIMIT: usize = 8;

    /// The kind a wire value names, or `None`.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Attach),
            2 => Some(Self::Gap),
            3 => Some(Self::Grant),
            4 => Some(Self::Derive),
            5 => Some(Self::Revoke),
            6 => Some(Self::DomainCreated),
            7 => Some(Self::DomainEnded),
            _ => None,
        }
    }
}

/// A domain, named so that the name cannot come to mean another one: the
/// slot is reused, the generation is not reused with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Name {
    /// The domain's slot.
    pub domain: u32,
    /// Which incarnation of that slot.
    pub generation: u32,
}

impl Name {
    /// The kernel acting on its own behalf, or no domain at all.
    pub const KERNEL: Self = Self {
        domain: u32::MAX,
        generation: 0,
    };
}

/// One audit record.
///
/// The wire form is the field order of [`Record::to_bytes`], each integer
/// little-endian:
///
/// | bytes | field |
/// |---|---|
/// | 0..8 | `sequence` |
/// | 8..16 | `timestamp` |
/// | 16 | `kind` |
/// | 17 | `object_kind` |
/// | 18 | `rights` |
/// | 19 | zero |
/// | 20..28 | `actor` |
/// | 28..36 | `target` |
/// | 36..40 | `count` |
/// | 40..48 | `subject` |
/// | 48..56 | `source` |
/// | 56..64 | `object` |
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Record {
    /// Its place in the boot's order, stamped by [`Ledger::commit`]. The
    /// chain covers it, so a record moved is a record changed.
    pub sequence: u64,
    /// The raw TSC when it was committed.
    pub timestamp: u64,
    /// What happened, as [`Kind::from_u8`] reads it. Raw, so any 64 bytes
    /// are a record.
    pub kind: u8,
    /// The object's kind, or for [`Kind::DomainEnded`] the reason.
    pub object_kind: u8,
    /// The rights the capability carries.
    pub rights: u8,
    /// Who did it.
    pub actor: Name,
    /// Whom it was done to: the recipient of a grant, the domain created or
    /// ended.
    pub target: Name,
    /// Capabilities destroyed by a revocation; operations in a gap; at
    /// attach, operations before it.
    pub count: u32,
    /// The capability's serial. At attach, the first half of the boot's
    /// identity.
    pub subject: u64,
    /// The serial it was derived from. At attach, the second half.
    pub source: u64,
    /// The object's identity within its kind.
    pub object: u64,
}

impl Record {
    /// The wire form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0u8; RECORD_BYTES];
        bytes[0..8].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.timestamp.to_le_bytes());
        bytes[16] = self.kind;
        bytes[17] = self.object_kind;
        bytes[18] = self.rights;
        bytes[20..24].copy_from_slice(&self.actor.domain.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.actor.generation.to_le_bytes());
        bytes[28..32].copy_from_slice(&self.target.domain.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.target.generation.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.count.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.subject.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.source.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.object.to_le_bytes());
        bytes
    }

    /// Reads the wire form back. Total, as [`crate::Event::from_bytes`] is:
    /// any 64 bytes are a record, and refusing a bad one is a reader's job.
    /// Byte 19 is not kept, so a record that round-trips with it set was
    /// changed there -- which the chain, covering the bytes, still sees.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; RECORD_BYTES]) -> Self {
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
        Self {
            sequence: word64(0),
            timestamp: word64(8),
            kind: bytes[16],
            object_kind: bytes[17],
            rights: bytes[18],
            actor: Name {
                domain: word32(20),
                generation: word32(24),
            },
            target: Name {
                domain: word32(28),
                generation: word32(32),
            },
            count: word32(36),
            subject: word64(40),
            source: word64(48),
            object: word64(56),
        }
    }
}

/// Whether an operation may be refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// It gives authority: a grant, a derive, a domain created. Refused
    /// when it would leave less than the headroom free.
    Refusable,
    /// It takes authority away: a revocation, a domain's end. Never
    /// refused, because refusing it would leave the authority in place.
    Unrefusable,
}

/// What the ledger decided for one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Recorded: one slot, or two when a gap is written first.
    Record {
        /// Whether a gap record goes first.
        gap_first: bool,
    },
    /// Refused: the operation must not happen.
    Refuse,
    /// Proceeds unrecorded, counted for the next gap record.
    Gap,
}

/// The decision, as a function of the ring's state.
///
/// `used` is everything not free: records the reader has not consumed, and
/// slots reserved by operations still in flight. A refusable operation
/// needs its slots *and* the headroom; an unrefusable one needs only its
/// slots, and without them is a gap rather than a refusal.
#[must_use]
pub const fn verdict(
    admission: Admission,
    used: u64,
    slots: u64,
    headroom: u64,
    gap_pending: bool,
) -> Verdict {
    let free = slots.saturating_sub(used);
    let need: u64 = if gap_pending { 2 } else { 1 };
    match admission {
        Admission::Refusable => {
            if free >= need.saturating_add(headroom) {
                Verdict::Record {
                    gap_first: gap_pending,
                }
            } else {
                Verdict::Refuse
            }
        }
        Admission::Unrefusable => {
            if free >= need {
                Verdict::Record {
                    gap_first: gap_pending,
                }
            } else {
                Verdict::Gap
            }
        }
    }
}

/// What an operation holds between its reservation and its commit.
///
/// Deliberately not `Clone`: a ticket is spent once, by
/// [`Ledger::commit`] or [`Ledger::cancel`].
#[derive(Debug, PartialEq, Eq)]
pub enum Ticket {
    /// The reader has not attached: counted, not recorded.
    Inactive,
    /// Slots reserved, and the gap this reservation took over to state
    /// first (0 for none).
    Slots {
        /// Unrecorded operations the gap record will state.
        gap: u64,
    },
    /// No room: the operation proceeds and is counted as a gap.
    Gap,
}

/// The operation was refused because the audit ring has no room for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused;

/// The records a commit or an attach produced, in order, each stamped with
/// its sequence. The kernel writes each at
/// [`slot_offset`](crate::ring::Layout::slot_offset) of its sequence, then
/// publishes [`Ledger::head`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Writes {
    /// At most a gap record and the record itself.
    pub records: [Option<Record>; 2],
}

/// The audit ring's state, and every decision about it.
#[derive(Debug)]
pub struct Ledger {
    slots: u64,
    headroom: u64,
    active: bool,
    head: u64,
    reserved: u64,
    pending_gaps: u64,
    gaps: u64,
    refused: u64,
    before: [u64; Kind::LIMIT],
}

impl Ledger {
    /// A ledger for a ring of `slots` records, keeping `headroom` of them
    /// for operations that may not be refused. Inactive until
    /// [`Ledger::attach`].
    #[must_use]
    pub const fn new(slots: u64, headroom: u64) -> Self {
        Self {
            slots,
            headroom,
            active: false,
            head: 0,
            reserved: 0,
            pending_gaps: 0,
            gaps: 0,
            refused: 0,
            before: [0; Kind::LIMIT],
        }
    }

    /// Reserves room for one operation of `admission`, given the reader's
    /// claimed tail -- untrusted, and clamped first, as the plane's is.
    ///
    /// # Errors
    ///
    /// [`Refused`] for a refusable operation the ring has no room for. It
    /// is counted, and the operation must not happen.
    pub fn reserve(&mut self, admission: Admission, tail_claim: u64) -> Result<Ticket, Refused> {
        if !self.active {
            return Ok(Ticket::Inactive);
        }
        let tail = ring::clamp_tail(self.head, tail_claim, self.slots);
        let used = (self.head - tail).saturating_add(self.reserved);
        match verdict(
            admission,
            used,
            self.slots,
            self.headroom,
            self.pending_gaps > 0,
        ) {
            Verdict::Record { gap_first } => {
                let gap = if gap_first {
                    core::mem::take(&mut self.pending_gaps)
                } else {
                    0
                };
                self.reserved += if gap_first { 2 } else { 1 };
                Ok(Ticket::Slots { gap })
            }
            Verdict::Refuse => {
                self.refused += 1;
                Err(Refused)
            }
            Verdict::Gap => Ok(Ticket::Gap),
        }
    }

    /// The operation happened: its record is stamped and placed, after the
    /// gap record its reservation took over, if any.
    pub fn commit(&mut self, ticket: Ticket, record: Record) -> Writes {
        match ticket {
            Ticket::Inactive => {
                if let Some(count) = self.before.get_mut(usize::from(record.kind)) {
                    *count += 1;
                }
                Writes::default()
            }
            Ticket::Gap => {
                self.pending_gaps += 1;
                self.gaps += 1;
                Writes::default()
            }
            Ticket::Slots { gap } => {
                let mut writes = Writes::default();
                if gap > 0 {
                    self.reserved = self.reserved.saturating_sub(1);
                    writes.records[0] = Some(Record {
                        sequence: self.head,
                        timestamp: record.timestamp,
                        kind: Kind::Gap as u8,
                        count: u32::try_from(gap).unwrap_or(u32::MAX),
                        ..Record::default()
                    });
                    self.head += 1;
                }
                self.reserved = self.reserved.saturating_sub(1);
                writes.records[1] = Some(Record {
                    sequence: self.head,
                    ..record
                });
                self.head += 1;
                writes
            }
        }
    }

    /// The operation did not happen: its slots are given back, and a gap
    /// it took over to state goes back to waiting.
    pub fn cancel(&mut self, ticket: Ticket) {
        if let Ticket::Slots { gap } = ticket {
            self.reserved = self.reserved.saturating_sub(if gap > 0 { 2 } else { 1 });
            self.pending_gaps += gap;
        }
    }

    /// The reader attached: auditing begins, and its first record names the
    /// boot and says how many operations came before it.
    ///
    /// `None` if already active -- a second reader does not restart a
    /// chain -- or if the ring has no slot at all.
    pub fn attach(&mut self, boot: [u64; 2], timestamp: u64) -> Option<Writes> {
        if self.active || self.slots == 0 {
            return None;
        }
        self.active = true;
        let before: u64 = self.before.iter().sum();
        let record = Record {
            sequence: self.head,
            timestamp,
            kind: Kind::Attach as u8,
            count: u32::try_from(before).unwrap_or(u32::MAX),
            subject: boot[0],
            source: boot[1],
            ..Record::default()
        };
        self.head += 1;
        Some(Writes {
            records: [None, Some(record)],
        })
    }

    /// The sequence the next record will carry; what the kernel publishes.
    #[must_use]
    pub const fn head(&self) -> u64 {
        self.head
    }

    /// Whether the reader has attached.
    #[must_use]
    pub const fn active(&self) -> bool {
        self.active
    }

    /// Operations refused for want of room.
    #[must_use]
    pub const fn refused(&self) -> u64 {
        self.refused
    }

    /// Operations that proceeded unrecorded.
    #[must_use]
    pub const fn gaps(&self) -> u64 {
        self.gaps
    }

    /// Operations of `kind` counted before the reader attached.
    #[must_use]
    pub fn before(&self, kind: Kind) -> u64 {
        self.before[kind as usize]
    }

    /// Slots in the ring.
    #[must_use]
    pub const fn slots(&self) -> u64 {
        self.slots
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values that break arithmetic (coding-style.md §8).
    const EDGES: [u64; 8] = [
        0,
        1,
        u64::MAX,
        u64::MAX - 1,
        1 << 63,
        (1 << 63) - 1,
        1 << 47,
        4096,
    ];

    fn record(kind: Kind) -> Record {
        Record {
            timestamp: 7,
            kind: kind as u8,
            actor: Name {
                domain: 3,
                generation: 9,
            },
            ..Record::default()
        }
    }

    #[test]
    fn a_record_round_trips_through_its_wire_form_with_every_field_in_place() {
        let record = Record {
            sequence: 0x0102_0304_0506_0708,
            timestamp: 0x1112_1314_1516_1718,
            kind: Kind::Grant as u8,
            object_kind: 5,
            rights: 0b10_1001,
            actor: Name {
                domain: 0x2122_2324,
                generation: 0x2526_2728,
            },
            target: Name {
                domain: 0x3132_3334,
                generation: 0x3536_3738,
            },
            count: 0x4142_4344,
            subject: 0x5152_5354_5556_5758,
            source: 0x6162_6364_6566_6768,
            object: 0x7172_7374_7576_7778,
        };
        let bytes = record.to_bytes();
        assert_eq!(Record::from_bytes(&bytes), record);
        // Placed where the table says, so a reader built from the table
        // and not from this code reads the same record.
        assert_eq!(bytes[0], 0x08);
        assert_eq!(bytes[8], 0x18);
        assert_eq!(&bytes[16..20], &[Kind::Grant as u8, 5, 0b10_1001, 0]);
        assert_eq!(bytes[20], 0x24);
        assert_eq!(bytes[24], 0x28);
        assert_eq!(bytes[28], 0x34);
        assert_eq!(bytes[32], 0x38);
        assert_eq!(bytes[36], 0x44);
        assert_eq!(bytes[40], 0x58);
        assert_eq!(bytes[48], 0x68);
        assert_eq!(bytes[56], 0x78);
        assert_eq!(bytes[63], 0x71);
    }

    #[test]
    fn any_bytes_read_as_some_record_and_only_known_kinds_decode() {
        for edge in EDGES {
            let mut bytes = [0u8; RECORD_BYTES];
            for (index, chunk) in bytes.chunks_mut(8).enumerate() {
                chunk.copy_from_slice(&edge.rotate_left(index as u32).to_le_bytes());
            }
            let _ = Record::from_bytes(&bytes);
        }
        for value in 0..=u8::MAX {
            let kind = Kind::from_u8(value);
            assert_eq!(kind.map(|kind| kind as u8), kind.map(|_| value));
            assert_eq!(kind.is_some(), (1..Kind::LIMIT as u8).contains(&value));
        }
    }

    #[test]
    fn a_refusable_operation_needs_its_slot_and_the_headroom() {
        // Eight slots, two kept back.
        assert_eq!(
            verdict(Admission::Refusable, 5, 8, 2, false),
            Verdict::Record { gap_first: false }
        );
        assert_eq!(
            verdict(Admission::Refusable, 6, 8, 2, false),
            Verdict::Refuse
        );
        // A pending gap costs a slot of its own.
        assert_eq!(
            verdict(Admission::Refusable, 5, 8, 2, true),
            Verdict::Refuse
        );
        assert_eq!(
            verdict(Admission::Refusable, 4, 8, 2, true),
            Verdict::Record { gap_first: true }
        );
    }

    #[test]
    fn an_unrefusable_operation_uses_the_headroom_and_is_never_refused() {
        for used in 0..=10 {
            for gap in [false, true] {
                let verdict = verdict(Admission::Unrefusable, used, 8, 2, gap);
                assert_ne!(verdict, Verdict::Refuse, "used {used}, gap {gap}");
            }
        }
        assert_eq!(
            verdict(Admission::Unrefusable, 7, 8, 2, false),
            Verdict::Record { gap_first: false }
        );
        assert_eq!(
            verdict(Admission::Unrefusable, 8, 8, 2, false),
            Verdict::Gap
        );
        assert_eq!(verdict(Admission::Unrefusable, 7, 8, 2, true), Verdict::Gap);
    }

    #[test]
    fn the_verdict_never_overflows_at_the_edges() {
        for used in EDGES {
            for slots in EDGES {
                for headroom in EDGES {
                    for admission in [Admission::Refusable, Admission::Unrefusable] {
                        for gap in [false, true] {
                            let _ = verdict(admission, used, slots, headroom, gap);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn before_the_reader_attaches_everything_is_counted_by_kind_and_nothing_is_written() {
        let mut ledger = Ledger::new(8, 2);
        for kind in [Kind::Grant, Kind::Grant, Kind::Revoke, Kind::DomainEnded] {
            let ticket = ledger
                .reserve(Admission::Refusable, 0)
                .expect("never refused");
            assert_eq!(ticket, Ticket::Inactive);
            assert_eq!(ledger.commit(ticket, record(kind)), Writes::default());
        }
        assert_eq!(ledger.before(Kind::Grant), 2);
        assert_eq!(ledger.before(Kind::Revoke), 1);
        assert_eq!(ledger.before(Kind::DomainEnded), 1);
        assert_eq!(ledger.before(Kind::Derive), 0);
        assert_eq!(ledger.head(), 0);
    }

    #[test]
    fn the_first_record_names_the_boot_and_counts_what_came_before() {
        let mut ledger = Ledger::new(8, 2);
        for _ in 0..3 {
            let ticket = ledger.reserve(Admission::Unrefusable, 0).unwrap();
            ledger.commit(ticket, record(Kind::DomainCreated));
        }
        let writes = ledger.attach([0xAAAA, 0xBBBB], 99).expect("attaches once");
        let first = writes.records[1].expect("the attach record");
        assert_eq!(first.sequence, 0);
        assert_eq!(first.kind, Kind::Attach as u8);
        assert_eq!(first.count, 3);
        assert_eq!((first.subject, first.source), (0xAAAA, 0xBBBB));
        assert!(ledger.active());
        assert_eq!(ledger.attach([1, 2], 100), None, "a chain is not restarted");
    }

    #[test]
    fn records_take_consecutive_sequences_in_commit_order() {
        let mut ledger = Ledger::new(8, 2);
        ledger.attach([1, 2], 0).unwrap();
        let first = ledger.reserve(Admission::Refusable, 0).unwrap();
        let second = ledger.reserve(Admission::Refusable, 0).unwrap();
        // Committed out of reservation order: the sequence is the commit's.
        let b = ledger.commit(second, record(Kind::Derive)).records[1].unwrap();
        let a = ledger.commit(first, record(Kind::Grant)).records[1].unwrap();
        assert_eq!((b.sequence, a.sequence), (1, 2));
        assert_eq!(ledger.head(), 3);
    }

    #[test]
    fn a_full_ring_refuses_grants_keeps_room_for_revocations_and_then_counts_gaps() {
        // Four slots, one kept back. The reader never moves its tail.
        let mut ledger = Ledger::new(4, 1);
        ledger.attach([1, 2], 0).unwrap(); // slot 0
        for _ in 0..2 {
            let ticket = ledger.reserve(Admission::Refusable, 0).unwrap();
            ledger.commit(ticket, record(Kind::Grant)); // slots 1 and 2
        }
        assert_eq!(
            ledger.reserve(Admission::Refusable, 0),
            Err(Refused),
            "the last slot is headroom"
        );
        assert_eq!(ledger.refused(), 1);
        let revoke = ledger.reserve(Admission::Unrefusable, 0).unwrap();
        assert_eq!(revoke, Ticket::Slots { gap: 0 }, "the headroom is for this");
        ledger.commit(revoke, record(Kind::Revoke)); // slot 3: full
        let end = ledger.reserve(Admission::Unrefusable, 0).unwrap();
        assert_eq!(end, Ticket::Gap, "proceeds, unrecorded");
        assert_eq!(
            ledger.commit(end, record(Kind::DomainEnded)),
            Writes::default()
        );
        assert_eq!(ledger.gaps(), 1);

        // The reader catches up: the next record states the gap first.
        let ticket = ledger.reserve(Admission::Refusable, 4).unwrap();
        assert_eq!(ticket, Ticket::Slots { gap: 1 });
        let writes = ledger.commit(ticket, record(Kind::Grant));
        let gap = writes.records[0].expect("the gap, first");
        assert_eq!((gap.kind, gap.count, gap.sequence), (Kind::Gap as u8, 1, 4));
        assert_eq!(writes.records[1].unwrap().sequence, 5);
    }

    #[test]
    fn a_cancelled_reservation_gives_back_its_slots_and_its_gap() {
        let mut ledger = Ledger::new(4, 0);
        ledger.attach([1, 2], 0).unwrap();
        for _ in 0..3 {
            let ticket = ledger.reserve(Admission::Unrefusable, 0).unwrap();
            ledger.commit(ticket, record(Kind::Revoke));
        }
        let lost = ledger.reserve(Admission::Unrefusable, 0).unwrap();
        ledger.commit(lost, record(Kind::Revoke)); // a gap
        let ticket = ledger.reserve(Admission::Refusable, 4).unwrap();
        assert_eq!(ticket, Ticket::Slots { gap: 1 });
        ledger.cancel(ticket);
        // The gap waits for the next record, and the slots are free again:
        // four free, so a gap and a record fit with nothing kept back.
        let again = ledger.reserve(Admission::Refusable, 4).unwrap();
        assert_eq!(again, Ticket::Slots { gap: 1 });
        let writes = ledger.commit(again, record(Kind::Grant));
        assert_eq!(writes.records[0].map(|gap| gap.count), Some(1));
    }

    #[test]
    fn a_hostile_tail_cannot_make_room_that_does_not_exist() {
        // A tail claiming the future reads as "everything consumed", which
        // frees only what was really written -- reservations still count.
        let mut ledger = Ledger::new(4, 0);
        ledger.attach([1, 2], 0).unwrap();
        let held = [
            ledger.reserve(Admission::Refusable, u64::MAX).unwrap(),
            ledger.reserve(Admission::Refusable, u64::MAX).unwrap(),
            ledger.reserve(Admission::Refusable, u64::MAX).unwrap(),
            ledger.reserve(Admission::Refusable, u64::MAX).unwrap(),
        ];
        assert_eq!(ledger.reserve(Admission::Refusable, u64::MAX), Err(Refused));
        for ticket in held {
            ledger.cancel(ticket);
        }
        // And a tail lagging further than the ring is clamped, not trusted.
        for edge in EDGES {
            let ticket = ledger.reserve(Admission::Unrefusable, edge);
            if let Ok(ticket) = ticket {
                ledger.cancel(ticket);
            }
        }
    }
}
