# Bhaskix — Security Architecture

*Status: draft for review. Prerequisite reading: [architecture.md](architecture.md).*

"Security by design, not by addition" is the second core principle in [vision.md](vision.md). This
document says what that means mechanically, what we defend against, and — equally important — what
we do **not** defend against. A threat model that claims to cover everything covers nothing.

---

## 1. Threat model

> ### Before any row below: what this evidence is worth
>
> **Nothing in this document has ever been observed on physical hardware** (M1-17). Every mitigation
> marked built below is built and gated *in QEMU*, and QEMU is not a machine: its VT-d is a model of
> an IOMMU, it has no SMM, no Management Engine, no firmware with its own opinions, and no device
> that misbehaves in the way real devices do. That is not a reason to distrust the rows — the gates
> are real and have each been watched go red — but it is a ceiling on how far any of them should be
> believed, and it applies to all of them at once.
>
> The second ceiling is narrower and sharper: **the kernel image is loaded without any authenticity
> check.** `bhaskixboot.efi` refuses a kernel that fails the *ELF parser* — the negative arm in
> `tests/qemu/native-boot-test.sh` corrupts the magic and asserts the refusal — and that is
> integrity against corruption, not authenticity against an attacker. Anyone who can write the ESP
> replaces the kernel and owns ring 0 from the next boot. T6 and T7 below are that gap, and their
> status column now says so.
>
> **The status column is new, 2026-08-20, and it exists because of a sentence already in this
> document**: *a mitigation column is a claim, and a claim whose limits are not written down is
> believed further than it should be.* **Three rows described mitigations that do not exist** (T5,
> T6, T7) **and a fourth described one that is half-built** (T8), all in the present tense, and a
> reader could not tell which. That is the failure mode this project exists to refuse, found in the
> project's own security document.

### In scope — we intend to defend against these

**Status** is what is true in the tree today, not what the design intends: **built** means
implemented and held by a gate that has been watched fail; **partial** means some of the mitigation
exists and the row says which part; **planned** means the mitigation column describes a design and
nothing in the tree implements it yet.

| # | Threat | Primary mitigation | Status |
|---|---|---|---|
| T1 | A compromised userspace process attempts to gain kernel privilege | Capability system; no ambient authority; no setuid; W^X; SMEP/SMAP | ✅ **built** — capability system, no ambient authority, SMEP/SMAP and the exception table gated on every boot. **One weakness named**: there is no ASLR for user programs; only the kernel image is slid |
| T2 | A compromised process attempts to access another domain's data | Address-space isolation; capabilities; no shared namespace by default | ✅ **built** — address-space isolation and immediate transitive revocation, both gated |
| T3 | A compromised or malicious **device driver** | IOMMU-enforced DMA windows; per-device capabilities; relocatable-service isolation | ✅ **built**, under the three conditions the note below states — and on a machine with no IOMMU a domain-hosted driver is refused outright rather than run unprotected |
| T4 | A malicious peripheral performing DMA (evil maid, malicious PCIe/Thunderbolt device) | IOMMU on by default; devices default-denied until enumerated and granted | ✅ **built**, same three conditions; interrupt remapping is on by default and gated |
| T5 | A guest VM escaping to the host | Domain isolation is the same mechanism as containers; EPT/NPT; no shared hypervisor codebase to diverge | ⬜ **planned** — domains exist and are the mechanism; **VMX/SVM and EPT/NPT do not**. There are no guests yet, so nothing has escaped and nothing has been prevented. Phase 3 |
| T6 | Persistence across reboot (bootkit, tampered kernel or initrd) | UEFI Secure Boot chain; measured boot into TPM PCRs; signed, immutable system image | ⬜ **planned, not built** — no Secure Boot chain, no TPM measurement, no signed image. The loader refuses a kernel that fails the ELF *parser*, which is corruption-detection, not authenticity. **Whoever can write the ESP owns ring 0.** Phase 3 |
| T7 | Tampering with an update in transit or at rest | Signed A/B images; rollback protection via monotonic counter; verified before switch | ⬜ **planned, not built** — no signing, no A/B slots, no rollback counter. There is no update mechanism at all yet, which is why nothing has been tampered with. Specified in §7; Phase 3 |
| T8 | Undetected compromise | Tamper-evident audit log; remote attestation; the telemetry plane is the audit source | 🔨 **partial** — the telemetry plane is built ([RFC 0026](rfc/0026-telemetry-plane.md)); the `Audit` class in it is **reserved and refused**, not served — emitting it is counted and dropped, because a best-effort audit event is false assurance with a checksum (§8). The backpressure ring, the hash chain, and remote attestation are a future RFC and are Phase 3. **This cell claimed backpressure when it was first written, on 2026-08-20, and §8 four sections below already said otherwise** — an error introduced by the same edit that added this column to stop exactly that |
| T9 | Memory-safety bugs in kernel code | Rust; `unsafe` budget tracked per crate; every `unsafe` block justified and reviewed | 🔨 **partial, and permanently so** — Rust, `forbid(unsafe_op_in_unsafe_fn)`, `deny(undocumented_unsafe_blocks)`, and a per-crate budget enforced by the build. 4,170 lines of `unsafe` in tree, **2,740 of them (66%) in ring 0**. The discipline is built; the exposure is structural and does not go to zero |
| T10 | Resource exhaustion by one domain denying service to others | `ResourceEnvelope` enforced at allocation and scheduling time, not by best effort | ✅ **built** — `ResourceEnvelope` enforced at allocation and scheduling time, gated ("envelope enforced, CPU share independent of thread count") |
| T11 | A hostile or compromised **Linux application inside a compatibility domain**, attacking through malformed system-call arguments or through Linux privilege (`root`) | The Linux personality translates and never manufactures authority; a hosted process holds no capabilities and has no way to name one; a compatibility domain reaches only what it was granted; and **the translator itself runs in a service domain** as of 2026-08-20 — the nucleus interprets no Linux syscall number, gated on every boot ([RFC 0005](rfc/0005-linux-abi-compatibility.md), [RFC 0031](rfc/0031-linux-compatibility-as-an-adapter.md), [RFC 0032](rfc/0032-a-supervisor-interface.md)) | 🔨 **mitigated 2026-08-20**, with the price written out in the note below rather than rounded to "contained" — the translator is in ring 3 and the nucleus interprets **0** Linux syscall numbers, gated; what a compromise of the adapter still reaches is enumerated |

### Out of scope — stated honestly

We will not pretend to cover these. Each has a note on whether it becomes in-scope later.

| Threat | Why out of scope | Future |
|---|---|---|
| Physical attacker with unlimited time and equipment (bus probing, chip decapping, cold boot) | No software-only mitigation is credible | Memory encryption (SME/TME) — Phase 3, mitigation not solution |
| Compromised firmware / SMM / Management Engine | Below our privilege level, by construction | Attestation *detects* some cases; it cannot prevent them |
| Microarchitectural side channels (Spectre-class, MDS, port contention) | Requires per-CPU-generation mitigation work we cannot sustain yet | Phase 3: core scheduling, IBRS/STIBP, cache partitioning. Documented gap until then. |
| Supply-chain compromise of the Rust **toolchain** | Real, and not solved by us | Reproducible builds, and the boot image is already a deterministic function of its package set, byte-compared twice per build ([RFC 0030](rfc/0030-packages.md)) |
| ~~Supply-chain compromise of crates.io dependencies~~ | **Corrected 2026-08-20: the shipped workspace has none.** `Cargo.lock` holds twenty packages and every one is `bhaskix-*`. This row previously promised "vendored + hash-pinned dependencies" as Phase 2 future work, which under-claimed what was already true — **there is nothing to vendor**, and an unearned understatement is as wrong as an unearned claim | Held by a gate, not by habit: `tools/check-deps.py`, run by `make gates` in CI, reads every manifest and rejects any external crate not in its `ALLOWED_EXTERNAL` set. That set holds exactly one name — `libfuzzer-sys`, reached only by `fuzz/`, **which is its own workspace on purpose and is never shipped** (its lockfile pulls ten transitive crates; none of them reach a booting machine) |
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

### Gaps found by the reassessment of 2026-08-20

Neither a threat nor a mitigation: **work that is missing, ranked by what it would actually cost an
attacker to exploit**, recorded here so the order survives the week it was decided in.

> **This ranking is by attacker cost. It is not a schedule, and the two orders differ on purpose.**
> [roadmap.md](roadmap.md) orders by *dependency* — it says so in its own first lines — and gap 1
> depends on a TPM driver, a `HANDOFF_VERSION` bump and a key-custody decision the project has not
> made, while gap 5 depends on nothing at all. So the roadmap's Phase 3 was reordered on 2026-08-20
> to put the rows that fund this section first *within that phase*, and **nothing was moved into
> Phase 2**; gaps 5 and 6 are merge-gate debts under §5 rather than phase items, and gaps 2 and 4
> are tracked as tasks. Reading this list as a delivery order would be reading it wrong. Each was
found by reading the tree rather than the documents, and each names what is true today.

| | Gap | Why it ranks here |
|---|---|---|
| 1 | **The kernel image has no authenticity check** | The whole of T6. It became *this project's* problem when `bhaskixboot.efi` replaced a shipped loader, and it is the only gap on this list that hands an attacker ring 0 outright |
| 2 | **`bin/linuxd` is the concentration point, and it is growing fastest** | It holds `DomainControl`, a directory capability and every hosted process's descriptors, it parses attacker-controlled arguments, and its `unsafe` went 42 → 85 in one day with L1 barely begun. On the evidence of the last week this is where the next real bug is |
| 3 | **No ASLR for user programs** | Only the kernel image is slid. Bhaskix's own services are Rust, so this costs little today — but the code arriving under L1–L4 is C, and a hosted process at a fixed image base with a fixed stack turns any bug in BusyBox or `curl` into a reliable exploit. The domain still contains it; containment is the claim being sold, and cheap exploitation of the contained thing weakens it |
| 4 | **The kernel's user-pointer copy path has one missing invariant** | Three bugs of the same shape landed on 2026-08-20, all of them "a supervisor's write to a lazily-mapped page". Three occurrences of one shape is a class, not three bugs, and it sits exactly where SMAP, the exception table and attacker-chosen addresses meet. It deserves a pass, not a fourth patch |
| 5 | ~~A hostile disk image is not fuzzed~~ **— paid 2026-08-21** | `fuzz/fuzz_targets/fs_image.rs`: four arms, **123,501 executions clean**, no crash and no hang. The fourth arm exists because the first three were *measured and found not to reach the walkers* — inodes carry a checksum as well as the superblock, so a probe that panicked inside `Filesystem::list` ran **16,132 executions without ever yielding a directory entry**. Arm D re-encodes an inode after taking its fields from the fuzzer, putting attacker-chosen block pointers behind a valid checksum, which is the bug class that matters. Five paths — the walkers, `journal::home`, a directory entry, a followed block pointer, the free bitmap — are each proven reachable by a deliberate panic rather than by a coverage number |
| 6 | ~~IPv6 and NDP have the mutation harness but no coverage-guided target~~ **— paid 2026-08-21** | `fuzz/fuzz_targets/ipv6_ndp.rs`, four arms, **12,906,117 executions clean**. All five probe points reach from an **empty** corpus, including the checksum-verified echo — which settles the question this gap raised: ICMPv6's mandatory 16-bit checksum over a pseudo-header is **not** a wall to a coverage-guided fuzzer, exactly as `udp_parse` and `icmp_parse` had already shown. A repaired arm is kept anyway, because recomputing the sum is what an attacker does and the fields behind it are the ones worth attacking |
| 7 | **One entropy source, no pool** | `RDRAND` only — no `RDSEED`, no mixing, no pool. Every unpredictable number in the system, including the KASLR slide and the TCP ISN key, traces to one instruction from one vendor. The design **fails closed** where most systems fail silently, which is why this is seventh and not first |

**And the strongest fact in this document, which it had been under-claiming**: twenty packages in
`Cargo.lock`, all of them `bhaskix-*`. **The shipped workspace has zero external dependencies**, and
`tools/check-deps.py` fails the build if one appears — a **manifest**-level check, not a lockfile one, which is equivalent here only because there is no external *direct* dependency for a transitive to arrive under. The out-of-scope table above is corrected
accordingly.

> **A correction inside the correction, made the same day, because it is exactly the mistake this
> document exists to catch.** The first version of the row above said the keeping-check *did not
> exist* — "the build should fail on a non-`bhaskix` package entering the lockfile, and does not
> yet". **That was wrong.** `tools/check-deps.py` has been enforcing it, in `make gates`, in CI, for
> longer than this reassessment took: it rejects any external crate not explicitly allowed and
> prints the allowed set. It was asserted absent without being looked for, which is the same failure
> as asserting a mitigation present without checking — the direction differs and the discipline does
> not. What is true: the gate exists, its allow-list holds one name, and that name is reachable only
> from `fuzz/`, a separate workspace that never ships.

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
- **Whole crates refuse `unsafe` outright**, and that is the strongest form of confinement here
  because the compiler enforces it rather than a reviewer: `bhaskix-boot`, `bhaskix-elf`,
  `bhaskix-net` (twice — the crate root and `siphash`), `bhaskix-personality`, `bhaskix-pkg`,
  `bhaskix-telemetry`, `bhaskix-ustar` and — since 2026-08-21 — **`bhaskix-fs`** carry
  `#![forbid(unsafe_code)]`; `bhaskix-mm` denies at its root and forbids in `bump`.
- **`forbid`, not `deny`, wherever the choice is free.** `deny` can be switched off by an `allow`
  anywhere inside the crate, which makes it a default; `forbid` makes the `allow` itself a compile
  error — *"allow(unsafe_code) incompatible with previous forbid"*. For a parser whose entire input
  is bytes somebody else wrote, the guarantee worth having is the one a future edit cannot quietly
  opt out of. `bhaskix-mm` is the deliberate exception: it needs `unsafe` in named places, so it
  denies at the root and forbids in the module that must stay clean.
- Everywhere else, **the budget is the confinement**. There is no module allow-list, and a number
  in a manifest is what a reviewer can actually check.
- `unwrap()`, `expect()`, and panicking indexing are denied outside tests and one-time init paths.
  A panic in the nucleus is a denial of service.

Additionally: `miri` on host-testable crates, `cargo-fuzz` targets on every parser (ELF, filesystem
metadata, network packets, IPC messages), and UBSan/ASan-equivalent debug features in the allocator.

> **Correction, 2026-08-20. The two bullets above replace one that was wrong in three ways**, and it
> had been wrong for long enough that it was quoted rather than checked. It read: *"`unsafe` is
> confined to designated modules: `arch::*`, each driver's `hal` submodule, and the allocator
> internals. Business logic in `fs`, `net`, `sched`, and service code contains none, and CI enforces
> that with a `#![forbid(unsafe_code)]` at those crate roots."*
>
> 1. **There is no module allow-list, and there never was one to enforce.** `unsafe` lives in 25
>    files in `kernel/` and 21 in `arch/`, plus 24 other crates. The kernel's own manifest carried
>    the same sentence — *confined to `sync`, `framebuffer`, `trap` and `faultinject`; no other
>    module may contain `unsafe`* — directly above a dated growth log that records it spreading into
>    `memory`, `vm`, `stack` and per-CPU bring-up. **The header was refuted by the history printed
>    underneath it**, and both are in one file that reviewers read.
> 2. **There is no `hal` submodule anywhere in the tree.** [RFC 0014](rfc/0014-driver-framework.md)
>    chose `register_block!` and `Mmio<T>` instead, which is a better answer — the sentence just
>    outlived the design it described.
> 3. **`sched` — named in that sentence as containing none — has 36 lines.** And this is the part
>    worth keeping: **almost all of them are calls into `arch`**, not dangerous work.
>    `cpu::disable_interrupts()`, `fx_save`/`fx_restore`, `bhaskix_context_switch` — `arch` exposes
>    them as `unsafe fn`, so calling one needs a block, and the metric counts that block's line the
>    same as it counts a raw pointer dereference. **A module's number does not distinguish doing
>    something dangerous from asking `arch` to**, and a reader who does not know that will read
>    every number on the table as worse than it is.
>
> What is true is what the bullets now say, and it is not a weaker claim: **eight crates forbid
> `unsafe` at their root** — `boot`, `elf`, `net`, `personality`, `pkg`, `telemetry`, `ustar` and,
> since 2026-08-21, `fs` — and `mm` denies at its root while forbidding in `bump`, so nine refuse it
> at compile time in whole or in part; every other crate declares a budget the build enforces, and every block
> carries a `// SAFETY:` comment CI requires. **The confinement was real. The description of it was
> written once, at M1, and never checked again** — which is the same failure this document found in
> `architecture.md` §7 the same day, and the reason both now name what enforces them.

**Parsers are where kernels get exploited.** Every parser that touches untrusted input gets a fuzz
target before it gets merged, not after.

> **And a target is not the same as coverage, which was measured on 2026-08-21 rather than assumed.**
> Every one of the fourteen targets was instrumented with probe points and run from an **empty**
> corpus — what a fresh clone has, since `fuzz/corpus/` is gitignored. Most were healthy. Three were
> not: `pkg_manifest` reached **none** of its five points in 1,523,042 executions, `pkg_package`
> none of five in 5,384,466, and `ustar_parse` one of five in four million — though five of five
> with its corpus, which meant its assurance lived in an untracked directory rather than in the
> repository.
>
> **All three were seeded on 2026-08-21** and re-measured from empty corpora: each now reaches what
> it never reached, in tens of thousands of executions rather than millions of futile ones. The
> technique is `fs_image.rs`'s — build the valid structure inside the target and let the fuzzer
> mutate within it, re-deriving whatever integrity value the structure requires. **Recomputing a
> checksum is the threat model, not a cheat**: it defends against corruption, not against somebody
> who can write the file.
>
> Two further findings, both worse than a coverage hole. `arp_parse` and `tcp_parse` **had not
> compiled since 2026-08-18**, when RFC 0029's renames landed: they ran zero executions for three
> days while this section went on claiming a target on every parser. `tools/check-fuzz-targets.sh`
> now runs in `make gates` so that cannot recur. And the analyses that predicted which walls would
> hold were **wrong in the reassuring direction**: a 16-bit checksum is not a wall to a
> coverage-guided fuzzer; a 32-bit one and a 48-bit address are.

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
