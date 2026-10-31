# RFC 0101: A log that cannot be quietly edited

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-10-31 — nothing built.** ~~Questions for the lead~~ All four decided by the lead the same day, each as proposed (§*Unresolved questions*). Drafted at the lead's request, as Phase 3's third row. |
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

To be written once the questions are answered. At least:
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

Written once the questions are answered.
