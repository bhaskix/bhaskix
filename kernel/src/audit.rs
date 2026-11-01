// SPDX-License-Identifier: Apache-2.0
//! The audit log's kernel half -- RFC 0101 steps 1 and 2.
//!
//! Every path that moves authority -- a capability derived, granted or
//! revoked, a domain created or ended -- asks this module first and tells it
//! after. Asking is a [`Reservation`]: for an operation that gives authority
//! it can be **refused**, and the operation then does not happen; for one
//! that takes authority away it never is. Telling is
//! [`Reservation::commit`], made only when the operation happened; a
//! reservation dropped uncommitted gives its room back.
//!
//! Every decision is `bhaskix_telemetry::audit::Ledger`'s host-tested
//! arithmetic. This module holds the ledger under the innermost lock,
//! [`Rank::Audit`], so it may be asked under any lock an emitting path holds,
//! and it performs the stores the ledger decides: records into one ring in
//! frames a keeper domain owns, `head` published behind a release fence, the
//! way the telemetry plane publishes.
//!
//! **Auditing begins when `bin/auditd` attaches** -- the lead's decision of
//! 2026-11-01. The boot's own self-tests make and end domains long before any
//! ring-3 service could drain a ring, and a ring nobody drains would refuse
//! them. Until [`attach`], each operation is counted by kind, and the first
//! record says how many there were.
//!
//! **The reader's tail is hostile**, as the plane's is: it lives in a page
//! `bin/auditd` maps read-write, and the ledger clamps it before believing
//! it. A lying tail can only make the ring look fuller -- refusing grants on
//! this machine, which a compromised `auditd` could do anyway by stopping.

use bhaskix_arch::tsc;
use bhaskix_telemetry::audit::{
    self as wire, Admission, Kind, Ledger, Name, RECORD_BYTES, Record, Refused, Ticket, Writes,
};
use bhaskix_telemetry::ring;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::shared;
use crate::sync::{Rank, SpinLock};

/// Pages the ring spans: a 128-byte header and 512 records, as the plane's
/// per-CPU rings.
const RING_PAGES: usize = 9;

/// Bytes the ring region spans.
const RING_BYTES: u64 = RING_PAGES as u64 * bhaskix_mm::FRAME_SIZE;

/// Records in the ring.
const SLOTS: u64 = match ring::Layout::for_region(RING_BYTES as usize) {
    Some(layout) => layout.slots(),
    None => 0,
};

/// Slots only an operation that takes authority away may use. A domain's
/// end can revoke many capabilities but is one record, so this is a
/// margin for many operations in flight at once, not for one large one.
const HEADROOM: u64 = 64;

static LEDGER: SpinLock<Ledger> = SpinLock::new(Rank::Audit, Ledger::new(SLOTS, HEADROOM));

/// The direct-map base, stashed by [`init`].
static HHDM: AtomicU64 = AtomicU64::new(0);

/// The ring's frames, physical, in region order. Zero until [`init`].
static RING_FRAMES: [AtomicU64; RING_PAGES] = [const { AtomicU64::new(0) }; RING_PAGES];

/// The tail page, physical: one word the reader writes. Zero until [`init`].
static TAIL_FRAME: AtomicU64 = AtomicU64::new(0);

/// The ring object's identity, for the grant. `u64::MAX` = none.
static RING_ID: AtomicU64 = AtomicU64::new(u64::MAX);

/// The tail object's identity, for the grant. `u64::MAX` = none.
static TAIL_ID: AtomicU64 = AtomicU64::new(u64::MAX);

/// An operation's claim on the log, held from before it changes anything
/// until after. Dropped uncommitted -- the operation failed for some other
/// reason -- it gives its room back.
#[must_use = "an operation that happened must commit its record"]
pub struct Reservation {
    ticket: Option<Ticket>,
}

impl Reservation {
    /// The operation happened: record it.
    pub fn commit(mut self, record: Record) {
        if let Some(ticket) = self.ticket.take() {
            let record = Record {
                timestamp: tsc::read(),
                ..record
            };
            let mut ledger = LEDGER.lock();
            let writes = ledger.commit(ticket, record);
            store(&ledger, &writes);
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            LEDGER.lock().cancel(ticket);
        }
    }
}

/// Asks for room for an operation that gives authority.
///
/// # Errors
///
/// [`Refused`] when the log has no room: the caller must not perform the
/// operation, and answers [`crate::syscall::Status::AuditFull`].
pub fn reserve() -> Result<Reservation, Refused> {
    let mut ledger = LEDGER.lock();
    let ticket = ledger.reserve(Admission::Refusable, tail_claim());
    if ticket.is_err() {
        set_header_word(wire::REFUSED_OFFSET, ledger.refused());
    }
    Ok(Reservation {
        ticket: Some(ticket?),
    })
}

/// Room for an operation that takes authority away. Never refused: without
/// room it proceeds and is counted as a gap.
pub fn must() -> Reservation {
    let ticket = LEDGER
        .lock()
        .reserve(Admission::Unrefusable, tail_claim())
        .unwrap_or(Ticket::Gap);
    Reservation {
        ticket: Some(ticket),
    }
}

/// A domain as the log names it.
#[must_use]
pub const fn name(domain: u32, generation: u32) -> Name {
    Name { domain, generation }
}

/// Where `offset` within the ring region lives in the direct map. Records
/// are 64 bytes and frames 4,096, so no record straddles a frame.
fn ring_address(offset: usize) -> u64 {
    let frame = RING_FRAMES[offset >> 12].load(Ordering::Relaxed);
    HHDM.load(Ordering::Relaxed) + frame + (offset & 0xFFF) as u64
}

/// Writes a header word, if the ring exists.
fn set_header_word(offset: usize, value: u64) {
    if RING_FRAMES[0].load(Ordering::Relaxed) == 0 {
        return;
    }
    // SAFETY: a frame the ring object owns, through the direct map, at a
    // header offset below `ring::HEADER_BYTES`; one aligned word. Only this
    // module writes the ring.
    unsafe { core::ptr::write_volatile(ring_address(offset) as *mut u64, value) };
}

/// The reader's claimed tail: untrusted, and clamped by the ledger.
fn tail_claim() -> u64 {
    let frame = TAIL_FRAME.load(Ordering::Relaxed);
    if frame == 0 {
        return 0;
    }
    // SAFETY: the tail frame, through the direct map, one aligned word; its
    // value is whatever the reader wrote, and only clamped arithmetic sees it.
    unsafe { core::ptr::read_volatile((HHDM.load(Ordering::Relaxed) + frame) as *const u64) }
}

/// Performs the ledger's writes: each record into its slot, then `head`,
/// behind a release fence, so a reader that acquires `head` never sees half
/// a record. Called with the ledger locked, which is what orders two commits'
/// publications.
fn store(ledger: &Ledger, writes: &Writes) {
    if RING_FRAMES[0].load(Ordering::Relaxed) == 0 {
        return;
    }
    let Some(layout) = ring::Layout::for_region(RING_BYTES as usize) else {
        return;
    };
    let mut wrote = false;
    for record in writes.records.iter().flatten() {
        let slot = layout.slot_offset(record.sequence);
        for (index, chunk) in record.to_bytes().as_chunks::<8>().0.iter().enumerate() {
            // SAFETY: a slot inside the ring region, whole within one frame,
            // and at a sequence at or above the published `head`, so no reader
            // may look at it yet -- the ledger admitted it only with the
            // reader's tail past its last use.
            unsafe {
                core::ptr::write_volatile(
                    ring_address(slot + index * 8) as *mut u64,
                    u64::from_le_bytes(*chunk),
                );
            }
        }
        wrote = true;
    }
    if wrote {
        core::sync::atomic::fence(Ordering::Release);
        set_header_word(wire::HEAD_OFFSET, ledger.head());
    }
    set_header_word(wire::GAPS_OFFSET, ledger.gaps());
}

/// Creates the ring and its tail page. The marker is written last, behind a
/// release fence, so a reader mapping it early refuses it.
///
/// # Errors
///
/// What would not be created.
pub fn init(hhdm: u64) -> Result<(), &'static str> {
    let keeper = crate::domain::create("audit-keeper", crate::domain::ResourceEnvelope::new())
        .map_err(|_| "the audit keeper domain would not be created")?;
    HHDM.store(hhdm, Ordering::Relaxed);

    let tail = shared::create(keeper, bhaskix_mm::FRAME_SIZE)
        .map_err(|_| "the audit tail page would not be created")?;
    let Some((tail_frames, tail_count)) = shared::frames_of(tail) else {
        return Err("the audit tail page has no frames");
    };
    if tail_count == 0 {
        return Err("the audit tail page is empty");
    }
    // SAFETY: the tail frame, freshly allocated, through the direct map;
    // zeroed before anything reads it as a tail.
    unsafe { core::ptr::write_volatile((hhdm + tail_frames[0]) as *mut u64, 0) };

    let object =
        shared::create(keeper, RING_BYTES).map_err(|_| "the audit ring would not be created")?;
    let Some((frames, count)) = shared::frames_of(object) else {
        return Err("the audit ring has no frames");
    };
    if count < RING_PAGES {
        return Err("the audit ring is short of frames");
    }
    for (page, frame) in frames.iter().enumerate().take(RING_PAGES) {
        RING_FRAMES[page].store(*frame, Ordering::Relaxed);
    }
    set_header_word(wire::SLOTS_OFFSET, SLOTS);
    set_header_word(wire::REFUSED_OFFSET, 0);
    set_header_word(wire::GAPS_OFFSET, 0);
    set_header_word(wire::HEAD_OFFSET, 0);
    core::sync::atomic::fence(Ordering::Release);
    set_header_word(wire::MARKER_OFFSET, wire::MARKER);
    TAIL_FRAME.store(tail_frames[0], Ordering::Relaxed);
    RING_ID.store(object.as_u64(), Ordering::Relaxed);
    TAIL_ID.store(tail.as_u64(), Ordering::Relaxed);
    Ok(())
}

/// The reader has its grants: auditing begins. The first record names the
/// boot and counts what came before. `false` if there is no ring, or a
/// reader attached already.
pub fn attach(boot: [u64; 2]) -> bool {
    if RING_ID.load(Ordering::Relaxed) == u64::MAX {
        return false;
    }
    let mut ledger = LEDGER.lock();
    let Some(writes) = ledger.attach(boot, tsc::read()) else {
        return false;
    };
    store(&ledger, &writes);
    true
}

/// The ring object's identity, for `bin/auditd`'s read-only grant.
#[must_use]
pub fn ring_identity() -> Option<u64> {
    match RING_ID.load(Ordering::Relaxed) {
        u64::MAX => None,
        identity => Some(identity),
    }
}

/// The tail object's identity, for `bin/auditd`'s read-write grant.
#[must_use]
pub fn tail_identity() -> Option<u64> {
    match TAIL_ID.load(Ordering::Relaxed) {
        u64::MAX => None,
        identity => Some(identity),
    }
}

/// What the ledger holds, for the boot report.
#[derive(Clone, Copy, Debug)]
pub struct State {
    /// Whether a reader attached.
    pub active: bool,
    /// The next sequence: records written so far.
    pub head: u64,
    /// Refused for want of room.
    pub refused: u64,
    /// Proceeded unrecorded.
    pub gaps: u64,
    /// Counted before the reader attached, by kind: grants, derives,
    /// revocations, domains created, domains ended.
    pub before: [u64; 5],
}

/// The ledger, read once.
#[must_use]
pub fn state() -> State {
    let ledger = LEDGER.lock();
    State {
        active: ledger.active(),
        head: ledger.head(),
        refused: ledger.refused(),
        gaps: ledger.gaps(),
        before: [
            ledger.before(Kind::Grant),
            ledger.before(Kind::Derive),
            ledger.before(Kind::Revoke),
            ledger.before(Kind::DomainCreated),
            ledger.before(Kind::DomainEnded),
        ],
    }
}

/// The bytes of one record a test reads back out of the ring, for the
/// self-test that checks names survive reuse.
#[must_use]
pub fn record_at(sequence: u64) -> Option<Record> {
    if RING_FRAMES[0].load(Ordering::Relaxed) == 0 {
        return None;
    }
    let layout = ring::Layout::for_region(RING_BYTES as usize)?;
    let slot = layout.slot_offset(sequence);
    let mut bytes = [0u8; RECORD_BYTES];
    for (index, chunk) in bytes.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        // SAFETY: a slot inside the ring region, whole within one frame,
        // through the direct map; read only.
        *chunk = unsafe { core::ptr::read_volatile(ring_address(slot + index * 8) as *const u64) }
            .to_le_bytes();
    }
    let record = Record::from_bytes(&bytes);
    (record.sequence == sequence).then_some(record)
}
