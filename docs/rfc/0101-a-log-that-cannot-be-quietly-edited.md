# RFC 0101: A log that cannot be quietly edited

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-10-31 — ~~nothing built~~ ~~step 1 built 2026-11-01~~ all three steps built 2026-11-01**, for the lead to accept: every authority change through a system call reserved before and recorded after, a grant refused when the log is full, the chain kept on the disk and checked by a host verifier. ~~Questions for the lead~~ All four decided by the lead the same day, each as proposed, and three more on 2026-11-01 (§*Implementation plan*). Drafted at the lead's request, as Phase 3's third row. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (telemetry), userspace (an audit service), tpm |
| **Milestone** | Phase 3, *audit framework* ([roadmap.md](../roadmap.md)): threat T8 |
| **Depends on** | [RFC 0026](0026-telemetry-plane.md) (the plane, and the `Audit` class it reserved), [RFC 0089](0089-a-boot-the-tpm-records.md) (the TPM, read-only), [RFC 0095](0095-a-disk-that-keeps-what-was-written.md) (a disk that keeps what was written) |

---

## Summary

[`security.md` §8](../security.md) requires an audit log whose records are **hash-chained**, each
committing to its predecessor. Audit events **may not drop**: they apply backpressure. A verifier
can ask for a **TPM-signed quote** over the boot PCRs and the chain's head.

RFC 0026 built the telemetry plane and **reserved the `Audit` class and refused it**: "a
best-effort audit event is worse than none -- it is false assurance with a checksum". It named
three things this RFC owes: **the backpressure ring, the hash chain, and audit-grade naming**. This
RFC proposes all three, which events come first, and where the log is kept. Remote attestation is
proposed to wait for its own RFC. **Nothing is built until the lead answers its questions.**

## Motivation

**T8 is "partial"** (`security.md` §1). The plane exists; the tamper-evident log and attestation do
not. Today an `Audit` event is dropped and counted (`kernel/src/telemetry.rs`), and a boot gate
holds that count at 0 until this RFC.

**What exists to build on:**
- The plane: per-CPU rings of 64-byte events, written only by their CPU, drop-newest, read by
  `bin/traced` through two `Memory` capabilities (RFC 0026).
- `bhaskix-sha256`: `no_std`, no `unsafe`, already used in ring 3 (`bin/tpmd`).
- A kept disk (RFC 0095).

**What does not exist:**
- **any event about capabilities.** No `Cap`-class producer is emitted anywhere, and §8 says the
  log "records capability grants and revocations";
- **an identity that survives reuse.** RFC 0026's naming, (domain, slot, kind), is "insufficient
  for audit".

## Design

1. **A ring of its own, with backpressure.** Audit events go to a ring debug telemetry cannot
   evict. *Proposed*: when it is full, **the audited action fails closed**. The operation is
   refused with an error its caller sees, and is never allowed to happen unrecorded. The rest of
   the plane keeps drop-newest.
2. **The chain in ring 3.** A `bin/auditd`, holding the audit ring's capabilities and the disk
   capability for the log, drains it and writes records.
   - Each record carries the SHA-256 of its predecessor, so a record changed, removed or
     reordered breaks every later link.
   - *Proposed* there and not in the kernel, which stays hash-free; `auditd` is then trusted for
     what it appends, which the anchor in item 4 bounds.
3. **Audit-grade naming.** A domain is named with its generation, and a capability with a serial
   number the kernel never reuses in a boot. A record then names one thing even after the slot or
   domain is reused. A boot is named by its measured-boot event log's digest, so records from two
   boots cannot be spliced.
4. **Anchoring and attestation.** A chain alone shows a record was edited. It does not show the
   whole log was replaced by another valid chain. *Proposed*:
   - **the chain now**;
   - **anchoring its head in a TPM PCR, and a TPM Quote for a remote verifier, in a later RFC.**
     Extending a PCR reopens RFC 0089's rule that nothing reachable may extend, and the attestation
     format is `security.md` §10's open question.
5. **The first events:**
   - capability grant, derive and revoke;
   - domain create and end;
   - the loader's boot-signature verdict, which RFC 0091 measures.

   *Proposed* in that order, with the `Cap` class's first emitter.
6. **Where it is kept:** the kept disk (RFC 0095), appended by `auditd`, a file per boot. A disk
   that is full is a full ring, and item 1 holds.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Drop audit events under load, as telemetry does | §8: "may not"; a dropped audit event is false assurance. | Never. |
| Block the audited action until the ring drains | A thread blocked in a capability grant can deadlock the service `auditd` itself needs. | A measured case where failing closed refuses something that must not fail. |
| Hash in the kernel | Puts SHA-256 in the nucleus, on the paths that grant capabilities. | `auditd` is shown to be the weak link the anchor cannot bound. |

## Security implications

- **New authority:** `auditd` holds the audit ring and the log's disk. A compromise of it can
  withhold or invent records from the moment it is compromised, which is why item 4's anchor
  matters, and why it is named here rather than discovered.
- **Failing closed** gives a full ring the power to refuse capability operations: a denial of
  service by audit load, which is §8's chosen trade.
- **T8 moves from partial towards mitigated.** Attestation keeps it from mitigated until the
  later RFC.

## Testing plan

Each step's gate is in the implementation plan above. At least:
- a record edited, removed or reordered breaks the chain at that record;
- a full ring refuses the audited operation, and the gate holding `0 audit-refused` changes to
  what that means;
- the first events appear with names that survive reuse;
- each armed.

## Unresolved questions

**All four decided by the lead on 2026-10-31, each as proposed:**
- fail closed;
- the chain in `bin/auditd`;
- the chain now, with the anchor and attestation in a later RFC;
- capability and domain events first, kept on the disk.

1. **Backpressure:** the audited action fails closed (*proposed*), or blocks until the ring
   drains.
2. **Where the chain is computed:** in `bin/auditd` (*proposed*), or in the kernel.
3. **Anchor and attestation:** the chain now and both in a later RFC (*proposed*), or a PCR
   anchor now.
4. **The first events and where they are kept:** capability grant, derive and revoke plus domain
   create and end, kept on the disk (*proposed*); or memory only, first.

## Implementation plan

Written 2026-11-01, with three more decisions the lead made that day, each as recommended:
- **a revocation or a domain's end always proceeds.** Refusing one would leave authority in place,
  the opposite of failing safe. They draw on headroom a grant may not use, and if even that is
  gone, the operation happens and a **gap** is counted, which the next record that fits states;
- **auditing begins when `auditd` attaches.** Before that, the boot's self-tests create and end
  many domains, and no ring-3 service exists to drain anything. Those operations are counted by
  kind, not recorded, and the first record says how many there were;
- **with no kept disk, the chain is kept in memory**, and the boot report says it is not
  persisted.

**Step 1 -- naming, the record, the ring, the events (kernel and `telemetry`).**
- **A capability serial.** Every arena node carries a `u64` assigned from a per-boot counter when
  it is made, root or derived, and never reused within a boot. A node's index and generation
  already name it uniquely, until the generation wraps; the counter cannot.
- **The record, `telemetry::audit::Record`**: 64 bytes, its wire form defined by its encoder,
  host-tested. A sequence number, the TSC, a kind (attach, gap, grant, derive, revoke, domain
  created, domain ended), the actor and the target each as **domain and generation**, the
  capability's serial and the serial it came from, the object's kind and identity, the rights, and
  a count.
- **The ledger, `telemetry::audit::Ledger`**: every decision as arithmetic, host-tested, the way
  RFC 0026's ring is. It decides:
  - **reserve before act.** A grant, a derive or a domain creation reserves its slot before it
    changes anything, and is **refused** when that would leave less than the headroom free;
  - **commit after.** The record is stamped with its sequence when the operation succeeded, and
    a reservation the operation did not use is given back;
  - the headroom and the gap, as above.
- **The ledger in the kernel, `kernel/src/audit.rs`**:
  - sized for a ring of 512 records, 64 of them headroom;
  - under its own lock, **rank 18**, inside even the console's: nothing is taken while holding
    it, so it may be taken under any lock an emitting path holds.

  ~~One global ring of 512 records in a `Memory` object, and a tail page~~ -- **moved to step 2
  while building step 1**: before a reader can attach the ring is never written, so its memory
  would have been code nothing could reach.
- **The events**: the system call paths that move authority.
  - `DERIVE` and `REVOKE`;
  - `GRANT` and the three other ways a capability reaches another domain: a grant to a domain, a
    `HAND`, and a gift at a rendezvous;
  - every domain created and every domain ended, by whatever path.

  **Not recorded**: capabilities the kernel itself mints, and its own revocations. A domain's
  end is its revocation, and is recorded as that.
- **A refusal has its own status**, `AUDIT_FULL` (15), so a caller can tell "the log is full" from
  "you may not".
- **The gate**: the boot report's `audit` line, and before `auditd` exists, the operations counted
  by kind.

  **Built 2026-11-01.** A boot reads `audit  inactive until auditd attaches: 16 grant(s), 17
  derive(s), 1 revocation(s), 94 domain(s) created, 85 ended -- counted, not recorded; 0
  refused`; the gate requires every kind nonzero and nothing refused, and went red with the
  revocation site's commit removed (`0 revocation(s)`). Host tests: the record's wire form at every
  offset; the ledger refusing a grant at the headroom, granting a revocation from it, counting a
  gap and stating it first in the next record, giving back a cancelled reservation, and clamping a
  hostile tail -- red with the headroom ignored (2 tests) and with a revocation refused like a
  grant (3); a capability's serial never drawn twice, red with the serial taken from the reused
  index.

  **Found building it, recorded and not fixed**: a gift delivered at a rendezvous whose install
  fails leaves its derived capability in the arena, installed nowhere and never revoked (TRACKER
  §3). Such a node is reachable by nobody, and is not recorded.

**Step 2 -- `bin/auditd` and the chain.**
- **The ring's memory**: one global ring of 512 records in a `Memory` object a keeper domain
  owns, and a tail page. The kernel performs the ledger's stores and publishes `head` behind a
  release fence, as the telemetry plane does.
- **Attaching.** `auditd` holds the ring read-only and its tail read-write. At attach the kernel
  writes the first record: a 128-bit boot identity it draws, and the counts from before.
- **The chain.** Each record is chained, `sha256(previous ‖ record)`, by `bhaskix-sha256`.
- **Where it is kept.** On the kept disk, a file per boot in an `audit/` directory `bin/fsd`
  makes and reports, appended a block per write; with no kept disk, in memory.
- **The boot report** prints the records, the chain's head, and whether it is persisted.

  **Built 2026-11-01.** An `iommu` boot: `audit before  53 grant(s), 17 derive(s), 7
  revocation(s), 114 domain(s) created, 95 ended before bin/auditd attached -- counted, and the
  first record says 286 of 286`, then `audit  recording: 789 records chained by bin/auditd, head
  ee923ba2572b5725..., kept in /audit/9e711f83bc884fa3 (100992 bytes); 0 out of order, 0
  unrecorded, 0 refused`. A boot with no kept disk says `in memory, not persisted (no kept disk)`.
  **Names that survive reuse**, gated: two probe domains derive and revoke through the system
  call's own path and end, and their records are found by name -- `domain 42 generation 3, then
  domain 42 generation 4, the same slot; capability serials 1041 and 1044`. **Its arm found the
  test weak**: with every record's generation dropped it still passed, because it named both sides
  with the same function. It now builds the expected name from the domain table, and the same arm
  turns it red (no record found by name).
  - The ring is 512 records in nine pages, 64 of them headroom, read-only to `auditd`.
  - The boot's file is named by the first half of its 128-bit identity, in hex.
  - A kept entry is 128 bytes: the record, the link before it, its own link, where a link is
    `sha256("BHXAUDIT" ‖ previous ‖ record)`. 32 entries fill a block, and a partial block is
    rewritten until it fills, so a file is always whole entries.
  - `bin/fsd` makes `/audit` beside `/pkg` and reports its handle as a twelfth word.

**Step 3 -- shown to fail closed, and checked by something other than the writer.**
- **A fault, `bhaskix.fault=audit-stall`**: `auditd` stops draining. A grant is then refused
  once the ring passes its headroom, while a revocation and a domain's end still happen, and the
  gap is recorded.
- **A host verifier, `tools/audit-verify`**: it reads the kept disk image and recomputes the
  chain, naming the first record that breaks it.
- **Armed:**
  - a byte of a kept record flipped;
  - the headroom removed, so a stalled ring grants anyway;
  - a revocation refused like a grant.

  **Built 2026-11-01.**
  - `make test-audit-stall`: `a derive was refused with AUDIT_FULL after 180 were recorded; a
    revocation and a domain's end still happened after it`, and past the headroom a revocation
    proceeded and was counted as a gap.
  - `make test-disk-keeps` now runs `audit-verify` over the disk it booted on: four whole logs,
    one per boot -- the `iommu` lane it runs as its second boot boots twice -- with boots 1 and 3
    each found by the file name their own report printed.
  - **The tamper check is part of the lane**: one bit of the second entry of a kept log, changed
    in a copy, is named -- `BROKEN at entry 1: its record and its link disagree`.
  - Armed, one at a time, each red and restored:
    - refusals turned into gaps: `refused false`;
    - a revocation reserved like a grant: `revoked after false`;
    - the verifier's previous-link check removed: the host test of a removed record.
  - **Not built, and said so**:
    - the loader's boot-signature verdict as a record (design item 5's third event);
    - any rotation: a kept disk gains a file per boot and nothing removes them;
    - an anchor for the chain's head, so a log replaced whole by another valid chain is not
      detected (design item 4, a later RFC).
