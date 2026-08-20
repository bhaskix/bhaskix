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
| T11 | A hostile or compromised **Linux application inside a compatibility domain**, attacking through malformed system-call arguments or through Linux privilege (`root`) | The Linux personality translates and never manufactures authority; a hosted process holds no capabilities and has no way to name one; a compatibility domain reaches only what it was granted; and **the translator itself runs in a service domain** as of 2026-08-20 — the nucleus interprets no Linux syscall number, gated on every boot ([RFC 0005](rfc/0005-linux-abi-compatibility.md), [RFC 0031](rfc/0031-linux-compatibility-as-an-adapter.md), [RFC 0032](rfc/0032-a-supervisor-interface.md)) |

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

> **T3 and T4 are delivered as of 2026-08-11, on a machine that has an IOMMU.**
> [RFC 0012](rfc/0012-iommu.md) was accepted on 2026-08-04 and all seven of its steps are
> implemented. Every device the kernel drives translates through **its own** page table under its own
> domain id, a device reaches only the frames it was given, revoking a mapping is enforced against
> the hardware, and interrupt remapping is **on by default** — so a device cannot raise an interrupt
> it was never programmed to raise, which is what retires [RFC 0011](rfc/0011-irq-handler.md)'s
> residual risk. The boot says which world the machine is in:
>
> ```
>     iommu window   00:03.0 39-bit, 3 levels, 0 reserved pages mapped, 0 refused
>     iommu irq      remapping interrupts; compatibility format blocked, every message is a handle
>                    this kernel issued
> ```
>
> **Three conditions, and a reader should know all of them.** On a machine with **no** IOMMU nothing
> above is true and the boot says so, in the words this note used to quote — a domain-hosted driver
> is refused outright, because a domain that could aim a device with physical addresses could aim it
> at the kernel. `iommu=off` produces the same state deliberately, for a machine where the unit is
> what is wrong. And **nothing has ever booted on physical hardware** (M1-17), so every word here is
> QEMU — real firmware declares reserved regions that QEMU never has, and that path has host tests
> and no more.
>
> Gated either way: a boot test asserts interrupts *are* remapped, so a machine that quietly fell
> back to the old risk is a red build rather than a table that became true-looking.
>
> This note said it would come out when the code landed. It is kept, rewritten, because the useful
> version is not "delivered" but *under what conditions* — **a mitigation column is a claim, and a
> claim whose limits are not written down is believed further than it should be.**

> **T11 is in scope and is mitigated, as of 2026-08-20 — and this note stays because how it
> got there, and what it now costs, are worth more than the tick.**
> [RFC 0005](rfc/0005-linux-abi-compatibility.md) §"Where it lives" requires the Linux personality
> to run in a **service domain**, precisely so that a bug in the largest untrusted-input parser in
> the project is a compromise of that domain and not of the kernel. On 2026-08-19 the
> implementation was in the nucleus: `kernel/src/syscall.rs` held the foreign-call path and
> eighteen interpreted Linux call numbers, and `kernel/src/signal.rs` built and restored Linux
> signal frames — on the order of 700 lines of Linux ABI in ring 0. (Past tense throughout this
> paragraph: it describes the tree on that day, and is kept because the correction is worth more
> than a tidy document.)
>
> **As of 2026-08-20 that is no longer where it lives.** `kernel/src/signal.rs` is deleted, the
> foreign-call handlers are deleted, and the count of Linux numbers the nucleus interprets —
> printed on every boot that ran a hosted program, and gated — reads **0**. `bin/linuxd` answers
> every foreign call from ring 3. Every parser, every signal frame, every `mmap` decision, every
> descriptor and the futex table itself are outside the kernel.
>
> **So both halves of the mitigation column hold.** A hosted process holds no capabilities and
> cannot name one, and its domain reaches only what it was granted — structural, and unchanged. A
> bug in the *translator* is now a bug in a ring 3 program that holds: one endpoint, three pages,
> a **write-only** console capability (it can print; it cannot read what somebody typed at the
> shell), sixteen notifications it may signal and may not wait on, and a supervisor handle to each
> domain it hosts. That is authority over hosted processes and over nothing else. It is not
> nothing — an adapter compromise is a compromise of every hosted process — and this note says so
> rather than rounding it to "contained".
>
> [RFC 0031](rfc/0031-linux-compatibility-as-an-adapter.md) §5 records how the drift happened, and
> set the correction's trigger — before Tier 1's file surface, because that is when the adapter
> starts holding per-process state and moving it gets dear. The trigger was met with room to
> spare.
>
> **The mechanism was [RFC 0032](rfc/0032-a-supervisor-interface.md)**, accepted 2026-08-20: seven
> methods on a `Domain` capability and two reply shapes, so that holding a program is an authority
> a program can be *given* rather than something only the kernel can be. The trade it stated —
> **the nucleus grows a supervisor interface so the personality can leave entirely** — is now a
> measured one: the kernel's `unsafe` budget *fell* across the move, 1,514 → 1,506.
>
> **What this row does not claim:** that the adapter is correct. It claims that a bug in it is
> contained, which is a statement about placement and is now true.
>
> **And half of what that note predicted has happened, on the same day it was written.**
> [RFC 0033](rfc/0033-what-a-hosted-process-is.md) step 5 gave the adapter **`DomainControl`**, so
> that a hosted `execve` can build the domain its successor runs in — a hosted process cannot exec
> in place, because `START` refuses a domain that has threads and the thread asking is one. So the
> list above grows by one entry, and the sentence that goes with it is: **a compromised adapter can
> create domains, up to the sixteen its own envelope allows, and can do to them everything a
> supervisor can do — map their memory, write it, start threads in it.**
>
> What it still cannot do is name a capability it was not given. A domain it creates starts *empty*:
> every authority that domain will ever hold is one the adapter passes from what it already holds,
> which is one endpoint, three pages, a write-only console, sixteen notifications and a handle per
> hosted domain. There is no ambient root, no device, no memory outside its own objects.
>
> **And the other half happened too, later the same day.** RFC 0033 step 6 gave the adapter a
> **directory capability** — one directory of the filesystem, `READ` and `DERIVE` and no `WRITE` —
> so that a hosted process can open a file. So the sentence that note said would have to be written
> is written here: **a compromised adapter can read every file inside that directory, and every file
> any hosted process has open.** It cannot write one, cannot reach anything above that directory,
> and cannot name a directory it was not given — a hosted process's `/` *is* that capability, which
> is `chroot` by construction rather than by check.
>
> The list, in full, as of 2026-08-20: one endpoint, three pages, a write-only console, sixteen
> notifications, `DomainControl` within a sixteen-domain envelope, one directory, and a supervisor
> handle per hosted domain. **Every increase on that list is a decision, and each one is recorded in
> the step that made it** — which is the only way a row like this stays true.
>
> Written here rather than only in the RFC because [RFC 0005](rfc/0005-linux-abi-compatibility.md)'s
> own impact table asked for this row on the day it was drafted — *"The threat model gains an
> in-scope adversary: a hostile process inside a Linux-personality domain… This is new and must be
> written down, not assumed covered"* — and it was not written until now, while five of that RFC's
> steps shipped.

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
> **Delegation demonstrated from user mode as of M5-07.** The same program derives a second,
> differently badged capability to the endpoint, calls through it, revokes the parent, and finds the
> derived copy dead — all by `Invoke` methods on capabilities it holds, with no new system call. A
> domain can therefore only ever delegate what it was itself given.
>
> Still missing: `GRANT` *between* domains is implemented and has no test, so the cross-domain half
> of delegation is written rather than shown.

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

Since [RFC 0008](rfc/0008-syscall-and-ipc-shape.md) was accepted and M5 implemented it, these are
statements about named functions with named tests rather than aspirations:

| Rule | Enforced by | Checked by |
|---|---|---|
| 1 — unforgeable | `cap::CSpace`; a domain holds a slot index, never a pointer | A ring 3 program is refused a slot it was not given, before any service is reached (M6-05) |
| 2 — monotone derivation | `cap::Arena::derive`, one function | Exhaustive over all 64×64 rights pairs, on the host |
| 3 — immediate transitive revocation | `cap::Arena::destroy_subtree`, a fixed-point sweep | A derivation tree is revoked at an interior node and every descendant is dead *before the call returns* — and ring 3 revokes its own derived capability and finds the next call refused (M5-07) |
| 4 — granter-set badges | The badge is copied from the capability by the kernel and is never read from the caller's frame | Taking the badge from the frame instead makes a service unable to tell its callers apart, which fails the gate (M5-05) |

**Each of those checks has been shown to fail** when the rule it guards is deliberately broken. A
gate that has never failed is a gate nobody has tested.

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

> **None of this is built.** There is no TPM code, no PCR extension, no attestation and no
> signature verification anywhere in the tree — `grep -riE '\bpcr\b|attest|secure ?boot'` over
> `*.rs` returns nothing on this subject. What follows is the intended chain, and it is written in
> the present tense throughout, which is how one of its bullets came to describe a handoff field
> that has never existed. Read it as a design.

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
- The TPM event log has **no path into the kernel**. This document said until 2026-08-12 that it
  "is passed through `Handoff.tpm_event_log`"; no such field has ever existed, and carrying one
  will mean a new handoff field and a `HANDOFF_VERSION` bump.
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
| KASLR | Randomise the kernel image | Always on; `nokaslr` is a debug-build-only option |
| `RDRAND` | The machine's only source of unpredictability ([RFC 0021](rfc/0021-unpredictability.md)) | **Boot, warn loudly, and let the caller refuse.** A machine with no `RDRAND` still has a filesystem, a shell and a supervisor, none of which need to be unpredictable — but `bin/tcpd` does not start, because a guessable TCP sequence number is an off-path injection nobody can see. Reported in the `features` line every boot. |

The "refuse to boot" entries are deliberate. Booting with a silently broken guarantee is worse than
not booting, because the operator believes they have protection they do not have.

> **Correction, 2026-08-14.** The KASLR row read *"Randomise kernel image and heap base"* until
> [RFC 0021](rfc/0021-unpredictability.md) went looking for the randomness that would do it. **The
> heap base is not randomised at all**: the heap lives in the direct map, and this machine reports
> `hhdm base 0xffff800000000000` on every boot. The kernel image *is* slid — by **Limine**, not by
> us; `kernel/src/lib.rs` computes the slide it was handed rather than choosing one. Half that row
> was a claim about work nothing performed, and it was unperformable, because until RFC 0021 this
> system had no source of unpredictability to perform it with. Randomising the heap base is a
> separate change with its own risk to the direct map, and it is RFC 0021's open question 2.

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
| A domain that holds another | A supervisor reaches into a domain **only** through a `Domain` capability carrying `WRITE`, and only into domains it was given one for — [RFC 0032](rfc/0032-a-supervisor-interface.md). Revoking that capability ends the reach before the call returns. The reach is one-directional: the held domain gains nothing, and its CSpace stays empty |
| IPC | Endpoints are capabilities; there is no global name service to enumerate |
| Time | Coarse time is free; fine-grained timers are rate-limited per domain (side-channel hygiene) |

**Frames are zeroed on allocation, not on free.** Zero-on-free is a common choice and it is the
wrong one: it puts the cost on the freeing path (often latency-sensitive teardown) and it can be
skipped by a crash. Zero-on-allocation cannot be skipped, because the receiving domain's correctness
depends on it. A frame never reaches a domain carrying another domain's data.

### A Linux compatibility domain is a domain, and nothing in this table changes for it

Every boundary above applies to a hosted Linux workload unchanged, and it is worth saying why
rather than assuming a reader will infer it. **Linux privilege does not appear in this table**,
because there is nothing for it to appear as: authority here is a capability a domain holds, and
`root` inside a compatibility domain is a number in that domain's own process table. It buys the
files, ports and processes the domain was already granted, and nothing else, because there is no
mechanism by which being UID 0 could add a capability.

```text
Linux UID 0                   ≠  Bhaskix unrestricted authority
Linux application compromise  ≠  Bhaskix system compromise
```

Both lines are properties a test may attempt to violate rather than assurances — see
[RFC 0031](rfc/0031-linux-compatibility-as-an-adapter.md) §6, which specifies four of them.
**Two of the four are largely funded by gates that already run** (driver containment and
capability revocation); the Linux-facing two are not written yet, and the row above says so.

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

The plane exists as of [RFC 0026](rfc/0026-telemetry-plane.md) (accepted 2026-08-17), and the
`Audit` class is **reserved and refused** in it: emitting the class is counted and dropped,
because a best-effort audit event is false assurance with a checksum. The backpressure ring, the
hash chain and audit-grade naming are a future RFC on that foundation, and this section is its
requirements list.

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
