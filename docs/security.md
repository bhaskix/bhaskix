# Bhaskix — Security Architecture

*Status: draft for review. Prerequisite reading: [architecture.md](architecture.md).*

"Security by design, not by addition" is the second core principle in [vision.md](vision.md). This
document says what that means mechanically, what we defend against, and — equally important — what
we do **not** defend against. A threat model that claims to cover everything covers nothing.

---

## 1. Threat model

### In scope — we intend to defend against these

| # | Threat | Primary mitigation |
|---|---|---|
| T1 | A compromised userspace process attempts to gain kernel privilege | Capability system; no ambient authority; no setuid; W^X; SMEP/SMAP |
| T2 | A compromised process attempts to access another domain's data | Address-space isolation; capabilities; no shared namespace by default |
| T3 | A compromised or malicious **device driver** | IOMMU-enforced DMA windows; per-device capabilities; relocatable-service isolation |
| T4 | A malicious peripheral performing DMA (evil maid, malicious PCIe/Thunderbolt device) | IOMMU on by default; devices default-denied until enumerated and granted |
| T5 | A guest VM escaping to the host | Domain isolation is the same mechanism as containers; EPT/NPT; no shared hypervisor codebase to diverge |
| T6 | Persistence across reboot (bootkit, tampered kernel or initrd) | UEFI Secure Boot chain; measured boot into TPM PCRs; signed, immutable system image |
| T7 | Tampering with an update in transit or at rest | Signed A/B images; rollback protection via monotonic counter; verified before switch |
| T8 | Undetected compromise | Tamper-evident audit log; remote attestation; the telemetry plane is the audit source |
| T9 | Memory-safety bugs in kernel code | Rust; `unsafe` budget tracked per crate; every `unsafe` block justified and reviewed |
| T10 | Resource exhaustion by one domain denying service to others | `ResourceEnvelope` enforced at allocation and scheduling time, not by best effort |

### Out of scope — stated honestly

We will not pretend to cover these. Each has a note on whether it becomes in-scope later.

| Threat | Why out of scope | Future |
|---|---|---|
| Physical attacker with unlimited time and equipment (bus probing, chip decapping, cold boot) | No software-only mitigation is credible | Memory encryption (SME/TME) — Phase 3, mitigation not solution |
| Compromised firmware / SMM / Management Engine | Below our privilege level, by construction | Attestation *detects* some cases; it cannot prevent them |
| Microarchitectural side channels (Spectre-class, MDS, port contention) | Requires per-CPU-generation mitigation work we cannot sustain yet | Phase 3: core scheduling, IBRS/STIBP, cache partitioning. Documented gap until then. |
| Supply-chain compromise of the Rust toolchain or crates.io dependencies | Real, and not solved by us | Vendored + hash-pinned dependencies; minimal dependency count; reproducible builds — Phase 2 |
| Denial of service by an authorised administrator | Authorisation is the boundary; we do not defend against correctly-authorised destruction | Audit log makes it *attributable*, not impossible |
| Traffic analysis, timing, and power side channels on network paths | Out of scope for an OS kernel | — |

**If you find that a mitigation listed as "in scope" does not actually work, that is a security bug
and we want the report.** See §9.

---

## 2. Capabilities: the foundation

Restated from [architecture.md](architecture.md) §3 because it is the load-bearing security
mechanism.

There is no `root`. There is no user ID in the nucleus. There is no ambient authority — a domain
cannot name a resource it was not given.

```
Capability { object: ObjectRef, rights: Rights, badge: u64 }
```

### Why this eliminates whole bug classes

Most privilege-escalation bugs in conventional kernels have the same shape: code holds *latent*
authority (it runs as root, or in kernel mode with access to everything) and a logic bug lets an
attacker direct that authority at the wrong object. Confused-deputy attacks, TOCTOU on path
resolution, and `setuid` exploitation are all instances.

If authority must be presented rather than possessed, the deputy has nothing to be confused about.
There is no path-name-to-authority lookup to race against: you hold a capability to the object or
you do not.

> **Demonstrated end to end as of M5-05b.** A program in ring 3 invokes a service through a
> capability it holds at index 0 of its own CSpace, and the service identifies it by a badge the
> program cannot read or set. Removing the capability, or the domain, leaves the program making the
> same system calls and reaching nothing — which is the claim above stated as a test rather than as
> a design intention.
>
> Still missing: there is no syscall to **grant, derive or revoke**, so a domain's authority is
> fixed when it is created. The mechanism exists in the arena and is unreachable from user mode.

### Rules the implementation must uphold

1. **Unforgeable.** A capability is an index into a kernel-owned CSpace. Userspace holds an integer
   that means nothing outside its own CSpace. Guessing gains nothing.
2. **Monotone derivation.** `derive(cap, rights)` requires `rights ⊆ cap.rights`. Enforced in one
   function, tested exhaustively.
3. **Immediate transitive revocation.** `revoke(cap)` invalidates every capability derived from it,
   transitively, *before returning*. Deferred revocation is a vulnerability with a delay fuse.
4. **Granter-set badges.** The holder cannot read or alter its badge. This is what lets a userspace
   service authenticate its callers without trusting them — and therefore what lets RBAC live in
   userspace.

### RBAC is policy, built on this mechanism

Phase 3's role-based security is a userspace service (`bhaskixd-authz`) that holds capabilities and
hands out derived, badged, rights-reduced capabilities according to a role policy. The nucleus knows
nothing about roles, users, or organisations. This means:

- The RBAC service can be replaced without touching the kernel.
- A bug in RBAC cannot grant authority the service did not itself hold.
- Different editions (desktop, server, hypervisor) can ship different policy services against the
  same kernel.

---

## 3. Boot integrity

```
UEFI firmware (Secure Boot)
   │  verifies signature  ─────────────────────────► PCR 0-7  (firmware, config)
   ▼
Limine (signed, shim-loaded)
   │  measures kernel + initrd before jumping ─────► PCR 8-9
   ▼
Bhaskix kernel (signed)
   │  measures the service set and boot policy ────► PCR 10-11
   ▼
Domain 0 / init (measured)
```

- **Secure Boot** gives us a verified chain: nothing unsigned executes.
- **Measured boot** gives us an *attestable* chain: the TPM PCRs record what actually ran, and a
  remote verifier can check it. Verification prevents; measurement detects. We do both, because
  Secure Boot alone cannot tell you *which* signed thing ran.
- The TPM event log is passed through `Handoff.tpm_event_log` so the kernel can extend it.
- **Sealing:** disk encryption keys are sealed to a PCR policy. A tampered boot chain cannot unseal
  them. The failure mode is "the disk does not decrypt", not "the disk decrypts for an attacker".

Our own signing keys, key rotation policy, and how community builds are signed differently from
release builds are governance questions — see [../GOVERNANCE.md](../GOVERNANCE.md). **Nobody ships a
release-signing key in a git repository.**

---

## 4. Hardware-assisted protections

Enabled at boot, verified present, and **refused-to-boot-without** where the guarantee is
load-bearing:

| Feature | Purpose | If absent |
|---|---|---|
| NX / `EFER.NXE` | Non-executable data pages | **Refuse to boot** — W^X is unenforceable without it |
| SMEP | Kernel cannot execute user pages | **Refuse to boot** on CPUs that have it disabled by firmware; warn on CPUs predating it |
| SMAP | Kernel cannot read/write user pages except via `copy_*_user` (which brackets with `STAC`/`CLAC`) | Warn loudly; degraded mode noted in attestation |
| UMIP | User mode cannot read descriptor-table registers | Warn |
| CET (shadow stack, IBT) | Control-flow integrity | Enable when present; not required |
| IOMMU (VT-d / AMD-Vi) | DMA containment | **Boot in degraded mode, printed at boot and recorded in attestation.** T3 and T4 are not mitigated without it. |
| KASLR | Randomise kernel image and heap base | Always on; `nokaslr` is a debug-build-only option |

The "refuse to boot" entries are deliberate. Booting with a silently broken guarantee is worse than
not booting, because the operator believes they have protection they do not have.

---

## 5. Memory safety and the `unsafe` budget

Rust removes memory-safety bugs from safe code. It does not remove them from `unsafe` code, and a
kernel needs `unsafe`. So we manage it as a measured quantity:

- Every crate declares `#![forbid(unsafe_op_in_unsafe_fn)]`. An `unsafe fn` body is not
  automatically an `unsafe` block.
- **Every `unsafe` block carries a `// SAFETY:` comment** stating the invariants that make it sound
  and why they hold here. CI rejects an `unsafe` block without one. A comment that says "this is
  fine" is a review rejection.
- **Per-crate `unsafe` budgets**, declared in `Cargo.toml` metadata and checked in CI. Raising a
  budget requires the PR description to say why. The number is reported on every PR so growth is
  visible rather than gradual.
- `unsafe` is **confined to designated modules**: `arch::*`, each driver's `hal` submodule, and the
  allocator internals. Business logic in `fs`, `net`, `sched`, and service code contains none, and
  CI enforces that with a `#![forbid(unsafe_code)]` at those crate roots.
- `unwrap()`, `expect()`, and panicking indexing are denied outside tests and one-time init paths.
  A panic in the nucleus is a denial of service.

Additionally: `miri` on host-testable crates, `cargo-fuzz` targets on every parser (ELF, filesystem
metadata, network packets, IPC messages), and UBSan/ASan-equivalent debug features in the allocator.

**Parsers are where kernels get exploited.** Every parser that touches untrusted input gets a fuzz
target before it gets merged, not after.

---

## 6. Isolation between domains

| Boundary | Mechanism |
|---|---|
| Memory | Separate page tables; no shared mappings without an explicit shared-memory capability |
| CPU | `ResourceEnvelope` enforced by the scheduler ([scheduler.md](scheduler.md) §3) |
| Physical memory | Per-frame `owner: DomainId`, enforced at allocation ([memory.md](memory.md) §2) |
| Devices | Per-device IOMMU domain; a device is reachable only via capability |
| IPC | Endpoints are capabilities; there is no global name service to enumerate |
| Time | Coarse time is free; fine-grained timers are rate-limited per domain (side-channel hygiene) |

**Frames are zeroed on allocation, not on free.** Zero-on-free is a common choice and it is the
wrong one: it puts the cost on the freeing path (often latency-sensitive teardown) and it can be
skipped by a crash. Zero-on-allocation cannot be skipped, because the receiving domain's correctness
depends on it. A frame never reaches a domain carrying another domain's data.

---

## 7. Secure update (Phase 3, specified now)

- **Immutable root.** The system image is read-only and integrity-verified at runtime (dm-verity
  equivalent). Configuration and state live in separate, writable, non-executable volumes.
- **A/B slots.** An update writes the inactive slot, verifies its signature and hash, then switches
  the boot pointer atomically. A failed boot rolls back automatically after N attempts.
- **Rollback protection.** A monotonic version counter in TPM NVRAM prevents an attacker from
  installing a genuinely-signed *old* image with a known vulnerability. Signed-but-outdated is a real
  attack and signature checking alone does not stop it.
- **Atomic or nothing.** There is no partially-updated state. This is a correctness property as much
  as a security one — an OS that can be interrupted mid-update during a power failure is not an
  enterprise OS.

---

## 8. Audit and attestation

The audit framework is **not a separate subsystem**. It is a consumer of the typed telemetry plane
described in [ai-native.md](ai-native.md) §2. This is deliberate: one event pipeline, one schema,
one place to get the semantics right.

Audit-specific requirements on top of the telemetry plane:

- **Tamper-evident.** Records are hash-chained; each entry commits to its predecessor. Removing or
  altering an entry breaks the chain and is detectable.
- **Guaranteed capture for audit-class events.** Telemetry may drop events under pressure (it is
  best-effort by design). Audit-class events may not: they apply backpressure instead. The classes
  are separated so that a flood of debug telemetry cannot evict a security record.
- **Remote attestation.** A verifier can request a TPM-signed quote over the boot PCRs plus the
  audit chain head, and thereby check both what booted and that the log has not been truncated.
- **The audit log records capability grants and revocations**, which is the security-relevant event
  set in a capability system — not `open()` calls on paths.

---

## 9. Reporting a vulnerability

Do not open a public issue for a security bug.

Report privately to the maintainers. Contact details and the current state of the reporting
channel are in [SECURITY.md](../SECURITY.md), which also records what is *not* a vulnerability yet —
this project documents its unfinished work in the open, and a report of a protection that is
tracked as unimplemented costs the reporter time for nothing.

We commit to:

- Acknowledgement within 72 hours.
- A coordinated disclosure window of 90 days by default, negotiable for severe or complex issues.
- Public credit to the reporter unless they prefer otherwise.
- A published post-mortem for every issue rated high or critical, including what in our design or
  process allowed it — because "security by design" means treating a vulnerability as a design
  question, not just a patch.

---

## 10. Open questions

- **KPTI-style page-table isolation:** always on, opt-in, or CPU-dependent? Cost is real; so is
  Meltdown-class exposure on older CPUs.
- **Core scheduling** (never co-schedule threads from different domains on SMT siblings): correct
  mitigation for cross-domain SMT side channels, meaningful throughput cost. Default on or off?
- **Attestation format:** align with an existing standard (TCG DICE, IETF RATS/EAT) or define our
  own? Strong lean toward an existing standard — see the open-standards principle.
- **Signing and key custody** for release builds. A governance decision with technical consequences.
- Do we allow unsigned kernels in developer mode, and how is that state made unmistakable to the
  user and to a remote verifier?
