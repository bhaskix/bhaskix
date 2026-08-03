# RFC 0007: Live patching the nucleus

| | |
|---|---|
| **Status** | **Draft — for discussion** |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel, tools; new subsystem `livepatch` |
| **Milestone** | Decision now; earliest delivery Phase 3, after M5 and M6 |
| **Depends on** | M5 (capabilities, domains), M6 (ELF loader), [RFC 0004](0004-ot-security-gateway.md), Phase 3 secure boot and attestation |

---

## Summary

**Live patching** replaces the implementation of a running kernel function
without rebooting, so that a security fix can be applied to a system whose
maintenance window is measured in hours per year.

This RFC scopes it for Bhaskix, and its main conclusion is a narrowing rather
than an expansion:

- **Most of what people want live patching for, this architecture solves
  differently and better.** Bhaskix is a nucleus with relocatable services, so
  the overwhelming majority of code — drivers, filesystems, network, storage —
  runs in service domains that can be *restarted*. Restarting a domain is
  ordinary, testable, and reversible; patching running code is none of those.
- What remains is the **nucleus**, which is small by design and is the only
  thing worth building this machinery for.
- Even then, the honest competitor is a **fast A/B reboot**, already on the
  Phase 3 roadmap. Live patching is for the cases where seconds of downtime are
  genuinely unacceptable, and those are fewer than the demand for the feature
  suggests.

The recommendation is to **specify it now and build it late**, because the
decisions it forces — how functions are entered, how threads are made
quiescent, what attestation covers — are cheap to honour early and expensive to
retrofit.

---

## Motivation

### Where the requirement actually comes from

[RFC 0004](0004-ot-security-gateway.md) commits to operational technology as the
first deployment target, and says of that environment:

| Constraint | Consequence |
|---|---|
| Availability 99.99%+, maintenance windows of hours per year | Reboot-to-patch is not available |
| Vendor certified *that exact build* | A known-vulnerable system is the *compliant* configuration |

That is the requirement, and it is not hypothetical: it is the reason the OT
positioning is credible at all. A security gateway that must be taken down to
patch itself is a security gateway that does not get patched.

The same constraint appears in [RFC 0006](0006-kosh-distributed-storage.md) — a
storage node holding the only current replica cannot simply be restarted — and
in any mission-critical deployment.

### Why this is not the usual argument

The usual argument for live patching is that rebooting is slow. On this
architecture that argument is weak, and saying so is more useful than repeating
it:

> **The best live patch is a small nucleus.**

[architecture.md](../architecture.md) §2 puts drivers, filesystems, the network
stack and storage in relocatable service domains. A bug in any of them is fixed
by restarting that domain — which is a supported operation with a defined
recovery path, not a surgical modification of code that is currently executing.
A monolithic kernel needs live patching for its network stack because its
network stack *is* the kernel. Bhaskix does not.

So this RFC covers the nucleus and nothing else, and the nucleus is deliberately
the smallest part of the system.

---

## The competitor, stated fairly

Before any design: **A/B atomic update with a fast reboot** is already on the
Phase 3 roadmap and solves a large share of the same problem.

| | Live patch | A/B reboot |
|---|---|---|
| Downtime | None | Seconds |
| State preserved | Everything | Nothing — every domain restarts |
| Scope of fix | Function bodies only | Anything, including data layout and the boot path |
| Confidence | Patch runs against a system state no test reproduced | Runs the same image the test suite ran |
| Rollback | Unpatch, itself risky | Boot the other slot |
| Attestation | Measured state changes after boot | Measured state is the image |

The row that matters is the fourth. **A live patch executes in a process state
no test ever produced**, because the machine has been running for months and its
heap, its locks and its threads are in a configuration no test rig reproduces. A
rebooted image runs exactly what was tested. That is a real reduction in
assurance, and for a system aiming at certification it has to be weighed
explicitly rather than assumed away.

**Position:** A/B reboot is the default answer. Live patching is the exception,
justified only where seconds of downtime are genuinely unacceptable, and it is
scoped small enough to be reviewable.

---

## Design

### What can be patched, and what cannot

The single most important table in this document, because almost every live
patching disaster is on the right-hand side.

| Patchable | Not patchable |
|---|---|
| A function body: a bounds check, a wrong comparison, a missing validation | Anything that changes a **data structure's layout** |
| Adding a check that returns an error earlier | Anything that changes **lock ordering** or introduces a new lock |
| Changing a constant that is read, not cached | Anything that changes the **meaning of persistent state** |
| A leaf function with few callers | Anything **inlined** into its callers |
| | Anything on the **boot path**, which has already run |
| | The **patching machinery itself** |

**Shadow data — carrying a new field alongside an old structure — is refused.**
It is how Linux patches layout changes, and it roughly doubles the complexity of
every patch while making the patched and unpatched states genuinely different
programs. A layout change means a reboot.

### The inlining problem, which Rust makes worse

Live patching redirects a *call*. If the compiler inlined the function, there is
no call to redirect, and the buggy code exists in a dozen copies with no name.

This is a problem in C and a bigger one here: Bhaskix builds with LTO and an
optimising compiler that inlines aggressively across crate boundaries, and it
should keep doing so — the alternative is a slower kernel for the benefit of a
feature used rarely, which is the wrong trade for the other 99.9% of the time.

Three consequences, and none of them are comfortable:

1. **Not every function is patchable, and which ones are is a property of the
   build.** The tooling must be able to answer "is this function patchable in
   *this* image", and answer it from the image rather than from the source.
2. **A patch must be built against the exact image it patches.** Same compiler,
   same flags, same source revision. A patch is not portable between builds,
   and this must be enforced by a build identifier the patch carries and the
   kernel checks.
3. **A fix may require patching the callers instead**, which widens the blast
   radius. The tooling must compute that set, not the author.

### Redirection

Two mechanisms, and the choice is not settled:

**(a) Entry padding.** Reserve a few `nop` bytes at every function entry and
overwrite them with a jump when patching. This is what Linux does, via
`-fpatchable-function-entry`. Rust's equivalent, `-Z patchable-function-entry`,
is **nightly**, and [coding-style.md](../coding-style.md) §1 commits to stable
Rust with every nightly feature justified in
[nightly-features.md](../nightly-features.md). Adopting it means opening that
file for the first time, which is a real cost and should be a conscious one.

**(b) An indirection table.** Route patchable calls through a table of function
pointers that patching rewrites. No nightly feature, no code modification at
runtime, and trivially atomic — a single aligned pointer store. The cost is an
indirect call on every patchable path, which is a branch predictor miss the
hardware cannot always hide, and it is paid always rather than only when
patched.

**Leaning towards (b)**, applied to a *declared* set of functions rather than
all of them. Most of the nucleus never needs to be patchable, and a mechanism
that costs nothing where it is not used is easier to justify than one that taxes
every call. It also keeps the kernel free of self-modifying code, which is worth
something on its own to a reviewer who has to certify this.

### Consistency: the actual hard part

Replacing a function is easy. Knowing it is *safe* to replace is not.

If a thread is currently executing inside the old function — or will return into
it — then swapping the implementation means one thread runs half of the old
version and half of the new. If the two versions disagree about anything, that
thread is in a state neither version anticipated.

Three models, in increasing order of capability and cost:

**1. Stop-the-world quiescence (proposed first).** Park every CPU, verify that
no thread's stack contains a return address inside any function being patched,
apply, resume. Simple to reason about and simple to certify. Its weakness is
that it can *fail*: a thread blocked for a long time inside a patched function
means the patch cannot be applied, and the answer is "try again later", which
for a rarely-idle function is "never".

**2. Per-thread consistency** (Linux's model, from kGraft and kpatch). Each
thread is migrated to the patched version at a point where its stack is clear;
threads run mixed versions for a while. Much more capable, and it requires
**stack unwinding** — which Bhaskix does not have, and which is a project of its
own with its own correctness burden.

**3. Quiescence at a known-safe point.** Patch only at points where every thread
is known to hold no state related to the patched code — for a nucleus, the
syscall boundary is the natural one. Cheaper than unwinding and less capable
than (2).

**Proposed: (1) now, (3) later, (2) only if a real workload forces it.** Model
(1) is honest about failing, and a patch that refuses to apply is far better
than one that applies unsafely — the entire point of this feature is systems
where a wrong answer is expensive.

### Security

This is the most privileged operation the system will ever offer: it injects
code into the nucleus at runtime. Treating it as an administrative convenience
would be a serious mistake.

- **A distinct capability**, not derivable from general administration, and
  never held by a service domain. Applying a patch is a different authority from
  running the system, and [security.md](../security.md) §2's model can express
  that where a permission bit could not.
- **Signature verification before anything is mapped**, chaining to the same
  root as secure boot. An unsigned patch is not a degraded mode, it is refused.
- **Attestation must cover applied patches.** [security.md](../security.md) §8
  specifies a hash-chained audit log and remote attestation; a live patch
  changes the running kernel *after* boot measurement, so an attestation that
  reports only the boot image would be **actively misleading** — reporting a
  known-good state for a machine running modified code. The measured state must
  be the boot image *plus* the ordered list of applied patches, or live patching
  silently breaks the property it shares a roadmap with.
- **The patch is a parser target.** It is an ELF object with relocations,
  supplied to the most privileged code in the system. Mandatory fuzz target,
  per [coding-style.md](../coding-style.md) §8, before it can ever be enabled.
- **Rollback is a security requirement, not a convenience.** A bad patch must be
  removable without a reboot, or the feature makes availability worse.

---

## What is refused

| Item | Status | Why |
|---|---|---|
| **Shadow data / layout changes** | **Refused** | Roughly doubles patch complexity and makes patched and unpatched genuinely different programs. Layout changes mean a reboot. |
| **Patching service domains** | **Refused** | They restart. That is the architecture working, and a patched service is strictly worse than a restarted one. |
| **Patching the boot path** | **Refused** | It has already run. Patching it changes nothing until a reboot, at which point the A/B image is the answer. |
| **Patching the livepatch machinery** | **Refused** | Cannot be made safe, and the failure mode is unbounded. |
| **Unsigned patches, even in development** | **Refused** | A development-only bypass is a production bypass that nobody removed. Use a development key. |
| **Automatic patch application** | **Refused** | An operator decides when a machine changes underneath a running workload. |
| **Per-thread consistency (unwinding)** | Deferred | Needs an unwinder. Revisit only if stop-the-world proves inadequate against a real workload. |
| **Patching inlined functions** | Not possible | Stated so the tooling reports it rather than producing a patch that silently misses copies. |

---

## Sequencing

Nothing here can start before M5 and M6. It is deliberately late, and the useful
work meanwhile is the **prerequisites**, which are cheap now and expensive to
retrofit.

| Stage | Deliverable | Prerequisite |
|---|---|---|
| **P0** | *Prerequisites only.* A stable build identifier in the image; the indirection table declared for a small set of nucleus functions; attestation shaped so applied patches can extend it. No patching. | Now — these are design constraints, not features |
| **L1** | Load and verify a signed patch object; reject on build mismatch or bad signature. Apply nothing. | M6 ELF loader, Phase 3 secure boot |
| **L2** | Stop-the-world quiescence: park CPUs, verify no thread is inside a patched function, redirect, resume. One function, one patch. | L1, M4 SMP (done) |
| **L3** | Rollback; patch stacking with an ordered list; attestation extension. | L2 |
| **L4** | Tooling that determines patchability from the image and computes the caller set when a target was inlined. | L3 |
| **L5** | Quiescence at the syscall boundary, if L2 proves too restrictive in practice. | L4, M5 syscalls |

**P0 is the part that matters today**, and it is the reason this RFC is worth
writing before the feature is wanted. A build identifier and an attestation
format that can express "image plus patches" cost almost nothing now and are
painful to add to a shipped, certified system.

---

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **A/B reboot only** | Solves most of it, and is the default recommendation here. Rejected as the *whole* answer because RFC 0004's target explicitly cannot take the downtime. | If OT customers turn out to tolerate a 2-second reboot, this RFC should be withdrawn rather than delivered. That is a question for customers, not for engineering. |
| **Adopt Linux's model wholesale** | It is built on unwinding, `ftrace` entry padding and shadow data, none of which exist here and two of which are refused above. Copying it means adopting its complexity to patch a nucleus a fraction of the size. | Never wholesale; the per-thread consistency model specifically, if stop-the-world proves inadequate. |
| **Nightly `-Z patchable-function-entry`** | Opens `nightly-features.md` for the first time and puts self-modifying code in the nucleus, for a feature used rarely. | If the indirection table's cost on hot paths is measured and proves unacceptable. Measure first. |
| **Make every function patchable** | Taxes every call in the kernel for a capability needed on a handful of functions. | Never. Declared patchability is also a review surface, which is a benefit rather than a cost. |
| **Restart the whole nucleus, preserving domains** | Superficially attractive and the state is the problem: domains hold capabilities *into* the nucleus, and reconstructing them is harder than patching. | If domain state ever becomes fully serialisable — which is a much larger and more interesting project. |

---

## Impact on existing design documents

| Document | What changes |
|---|---|
| [security.md](../security.md) §8 | Attestation currently measures the boot image. It must become the boot image *plus* applied patches, or a patched machine attests as a known-good one it no longer is. This is the single most important consequence in this RFC. |
| [security.md](../security.md) §1 | The threat model gains an adversary who can supply a patch object — the highest-value attack surface in the system. |
| [architecture.md](../architecture.md) §2 | The relocatable-services claim becomes load-bearing for availability, not just for isolation: it is *why* the patching surface is small. Worth stating there. |
| [roadmap.md](../roadmap.md) Phase 3 | "Secure update — immutable root, A/B slots, rollback protection" is the competitor to this and should reference it, so the two are chosen between rather than both assumed. |
| [nightly-features.md](../nightly-features.md) | Only if redirection mechanism (a) is chosen. Currently empty, and keeping it empty is worth something. |

---

## Testing plan

- **Host**: the patch object parser and its relocation processing, as pure
  functions over byte buffers; the build-identifier check; the patchability
  analysis over a fixed ELF fixture. Mandatory fuzz target on the parser.
- **QEMU**: the gate is a patch that changes an observable answer. A function
  returning 1 is patched to return 2; the kernel is asked before and after, and
  must give both answers, in order, without a reboot. Negative-tested by
  corrupting the signature, by mismatching the build identifier, and by patching
  a function a parked thread is sitting inside — all three must be *refused*,
  and refusal is the assertion.
- **The property most likely to be got wrong**, and therefore an explicit gate:
  after applying and then rolling back, the attested measurement must return to
  its pre-patch value — and must *differ* while the patch is applied. A patch
  that leaves attestation unchanged is worse than no patch at all.
- **Real hardware**: not required for correctness; required before any
  availability claim, because the value proposition is uptime.

---

## Unresolved questions

1. **Indirection table or entry padding?** Decide by measuring the indirect-call
   cost on the syscall and fault paths, not by argument. *Blocks L2.*
2. **Which functions are declared patchable?** A list that is too small makes the
   feature useless and too large makes it a tax. Probably: the syscall dispatch
   surface, capability checks, and anything that has ever had a CVE-shaped bug.
   No good answer exists before there is a history.
3. **What happens to a patch across a reboot?** Reapplied automatically from a
   store, or dropped so the machine returns to its attested image? Dropping is
   safer and surprises operators. Leaning towards dropping, loudly.
4. **Does a patch need to survive kexec?** Only if kexec happens, which is
   itself undecided.
5. **Who signs?** The same root as secure boot, or a separate patch-signing key
   that can be rotated without re-signing the image? Separate is better
   operationally and adds a key to manage.
