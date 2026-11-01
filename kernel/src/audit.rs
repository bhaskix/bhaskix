// SPDX-License-Identifier: Apache-2.0
//! The audit log's kernel half -- RFC 0101 step 1.
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
//! [`Rank::Audit`], so it may be asked under any lock an emitting path holds.
//!
//! **Step 1 counts and does not record.** Auditing begins when `bin/auditd`
//! attaches (step 2); until then each operation is counted by kind, and the
//! boot report prints the counts. That is the lead's decision of 2026-11-01:
//! the boot's own self-tests make and end domains long before any ring-3
//! service could drain a ring, and a ring nobody drains would refuse them.

use bhaskix_arch::tsc;
use bhaskix_telemetry::audit::{Admission, Kind, Ledger, Name, Record, Refused, Ticket};

use crate::sync::{Rank, SpinLock};

/// Records in the ring: a 128-byte header and 512 slots fit the nine pages
/// the telemetry plane's rings use.
const SLOTS: u64 = 512;

/// Slots only an operation that takes authority away may use. A domain's
/// end can revoke many capabilities but is one record, so this is a
/// margin for many operations in flight at once, not for one large one.
const HEADROOM: u64 = 64;

static LEDGER: SpinLock<Ledger> = SpinLock::new(Rank::Audit, Ledger::new(SLOTS, HEADROOM));

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
            // Nothing is written until a reader has attached, which step 2
            // builds; until then a commit is a count, and the ledger returns
            // no writes.
            let _ = LEDGER.lock().commit(ticket, record);
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
    let ticket = LEDGER.lock().reserve(Admission::Refusable, tail_claim())?;
    Ok(Reservation {
        ticket: Some(ticket),
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

/// The reader's tail. Nothing reads the ring before step 2, so nothing has
/// moved it.
fn tail_claim() -> u64 {
    0
}

/// A domain as the log names it.
#[must_use]
pub const fn name(domain: u32, generation: u32) -> Name {
    Name { domain, generation }
}

/// The boot report's line.
pub fn report() {
    let (active, refused, gaps, counts) = {
        let ledger = LEDGER.lock();
        (
            ledger.active(),
            ledger.refused(),
            ledger.gaps(),
            [
                ledger.before(Kind::Grant),
                ledger.before(Kind::Derive),
                ledger.before(Kind::Revoke),
                ledger.before(Kind::DomainCreated),
                ledger.before(Kind::DomainEnded),
            ],
        )
    };
    if active {
        crate::println!("    audit          recording; {refused} refused, {gaps} unrecorded");
        return;
    }
    let [grants, derives, revokes, created, ended] = counts;
    crate::println!(
        "    audit          inactive until auditd attaches: {grants} grant(s), {derives} \
         derive(s), {revokes} revocation(s), {created} domain(s) created, {ended} ended -- \
         counted, not recorded; {refused} refused"
    );
}
