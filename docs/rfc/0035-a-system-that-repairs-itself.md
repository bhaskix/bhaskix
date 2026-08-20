# RFC 0035: A system that repairs itself — supervision, reconciliation, and bounded autonomy

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-08-20** — a **direction recorded, and nothing built**. It was asked for as a question ("is this worth thinking about?") rather than proposed as work, and it is written down in that spirit: the purpose of this document is to fix the vocabulary and the bounds *now*, while the answer costs a document, rather than in Phase 3 when it would cost a rewrite. Stage 1 is buildable today and is deliberately **not** scheduled — see §8 |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | userspace (the supervisor and reconciler), docs. **The nucleus gains nothing.** That is a design claim in §3 and a test in §9 |
| **Milestone** | Phase 3 — the roadmap's "autonomous system management" row made mechanical. Stage 1 could be finished in Phase 2; §8 says why it should not be |
| **Depends on** | [RFC 0017](0017-process-management.md) (create, grant, start, kill, reap — every action here is one of these), [RFC 0030](0030-packages.md) (the manifest that already declares a program's authority and will declare its supervision), [RFC 0026](0026-telemetry-plane.md) (the observations, and the `Audit` ring the ledger lives in), [RFC 0032](0032-a-supervisor-interface.md) (`DomainControl`, and the precedent that supervision is a ring 3 capability), [RFC 0013](0013-service-framework.md) (the services being supervised), [ai-native.md](../ai-native.md) (§3's policy contract, which stage 3 reuses without amendment) |

---

## Summary

**A Bhaskix system should be able to notice that one of its own parts has failed, put it back, and
say what it did — without a human, and without the nucleus learning anything.** This RFC proposes
the plane that does that, in three stages that are deliberately separated because they have
different risks and only the third involves a model at all:

| Stage | Name | What it does | Model involved |
|---|---|---|---|
| **S1** | **Self-healing** | A service dies; a supervisor restarts it in a *fresh* domain with the grants its manifest declares, within a restart budget, and reports | **None** |
| **S2** | **Self-correcting** | The running system is compared against a declared desired state; drift is closed by the same capability calls an operator would make | **None** |
| **S3** | **Self-maturing** | When more than one legal remedy exists, an advisor in a killable domain **ranks** them. It cannot add one, cannot authorise one, and cannot act | Advisory only |

One invariant governs all three, and everything else in this document is a consequence of it:

```text
The system may do to itself only what an operator holding the same capabilities
could have done by hand — and every such action records the observation that
triggered it and the rule that authorised it.
```

The second half of that sentence is the load-bearing half. An automated action without a recorded
cause is indistinguishable from a bug, and a system that cannot tell you *why* it restarted your
database has not healed itself; it has hidden a fault.

## Motivation

### The problem this solves

Every operating system in production is *passive*. It fails in exactly the way it was built to fail
and then waits. A driver wedges and the machine is rebooted; a service leaks and someone is paged at
3 a.m.; a configuration drifts and nobody knows until an incident. The recovery intelligence lives
entirely in humans and in the tooling wrapped *around* the OS — Kubernetes, systemd units, runbooks,
monitoring — none of which can see inside the kernel, and all of which are reasoning about a machine
they cannot actually observe.

Bhaskix is in an unusual position to do better, and the reason is structural rather than clever:

- **A crashed driver is not a crashed kernel.** `bin/blkd` holds a device; if it dies, the domain
  dies and the machine does not. On Linux a block driver *is* the kernel, so "restart the driver" is
  not a sentence that can be said. Bhaskix can say it — and today, cannot yet do it.
- **Authority is already declarative.** RFC 0030 made a package's grants a reviewable manifest, and
  `pkg run` starts a program with exactly what the manifest asked for. A restarted service does not
  need its old authority *restored* from somewhere; it is re-derived from a file a human read.
- **The observations already exist and are typed.** RFC 0026's rings carry causal events, not text
  scraped from a log. A supervisor built on them is reading what the kernel decided, not guessing
  from a metric.
- **The pattern is already demonstrated.** `bin/sup` starts a program, notices it end, and starts it
  again — twelve times, then reports and stops. It adds nothing to the kernel; every call it makes
  existed before it did. It was written as RFC 0017's own test, and it is, in miniature, stage 1.

### What happens if we do nothing

Two things, and the second is worse than the first.

1. **The capability model's best argument goes undemonstrated.** "Drivers are isolated" is a claim a
   reviewer must take on trust. "Kill the block driver mid-workload; the shell still lists files"
   is a claim a reviewer can watch. Bhaskix has spent a year earning the right to run that
   demonstration and has not run it.
2. **The words get used before the mechanism exists.** "Self-healing", "self-learning" and
   "AI-native" are the most abused phrases in systems marketing. This project's entire method is
   that a claim is not believed until a gate has been watched go red. If those words enter the
   project's documents ahead of the mechanism, then the documents are doing the thing the project
   was built to refuse, and everything else they say gets discounted with them.

### Who has this problem, and the honest counterweight

Asked by the project lead on 2026-08-20, as a direction rather than a decision: whether a base OS
that can self-heal, self-correct, self-resolve and self-mature is worth building toward.

The answer this RFC gives is **yes, and in that order, and not yet** — because there is a fact that
must sit next to it: **nothing has ever booted on physical hardware** (M1-17), there is no libc, and
the system does not self-host. A self-healing operating system that has never met a real fault on a
real machine is a slogan. Stage 1's value is largely that it makes real faults survivable, and real
faults are mostly on the hardware this project has not reached yet.

So this document's own recommendation is that it be **accepted as a direction and implemented after
Phase 2's exit criteria**, and §8 states the trigger.

## Design

### The vocabulary, defined so it cannot be used loosely

Four words were asked about. They mean four different things and only one of them is hard.

| Word | What it means here | What it must never mean |
|---|---|---|
| **Self-healing** | Restore a **declared** invariant after a fault: the service named in a manifest is running, holding the grants that manifest requested | Retrying until something works. A restart that is not restoring a written invariant is a guess |
| **Self-correcting** | Notice that observed state has drifted from declared state, and close the gap by legal actions | Editing its own declaration to match reality. A reconciler that rewrites the goal has no goal |
| **Self-resolving** | Choose among **several legal** remedies when more than one exists | Inventing a remedy. The legal set is computed from the declaration, never proposed |
| **Self-maturing** | Change the **ranking** of legal remedies based on what has happened before, as a persisted, inspectable, revertible artifact | Changing the legal set, the bounds, or its own authority. A system that learns its way to more privilege is a vulnerability with a roadmap |

Read down the right-hand column: every one of those failure modes is what the phrase usually means
in practice. Naming them is most of the work.

### S1 — self-healing

**The keeper.** One ring 3 program, `bin/keeperd`, generalising `bin/sup`. It holds
`DomainControl` (RFC 0032) over the services it supervises and a telemetry-read capability
(RFC 0026), and nothing else — in particular it holds **no filesystem, no device, and no console
beyond a write-only report**, exactly as `bin/sup` does not today.

**A restart is a re-derivation, not a resurrection.** This is the sentence that makes supervision in
a capability system different from supervision anywhere else. When `bin/blkd` dies, the keeper does
not restore a saved domain: it creates a *new* domain and grants it what the manifest declares,
which is the same path `pkg run` takes. Consequences worth stating:

- A healed service **cannot come back with more authority than it started with**, and cannot come
  back with authority it accumulated at runtime, because there is no mechanism to carry it over.
- A service compromised at runtime is **cleaned by its own restart** — the residue is in the dead
  domain, and the dead domain is gone.
- The keeper never needs to hold the authority it hands out... except that it does hold the ability
  to *grant* it, which is priced honestly in §6 rather than glossed.

**Health is a declaration, not an inference.** A supervised service declares, in its manifest:

```text
service   blkd
liveness  notification every 2s          # the service arms it; a missed deadline is a fault
restart   on-fault, on-exit-nonzero      # not on a clean exit: that program did what it was asked
budget    5 restarts in 60s              # then stop, mark degraded, report — and do not try again
depends   none                           # started before, and stopped after, anything that needs it
```

Every field is a decision a human wrote in a file a human reviewed. Nothing here is discovered,
sampled or guessed. RFC 0030's manifest already carries the authority half; this is the same file
gaining the supervision half, which is the right place for it because **a reader of one paragraph
should be able to see both what a service may do and what happens when it dies**.

**A crash loop is a report, not a service.** The budget is the whole safety argument for S1. Without
it, a supervisor converts one deterministic fault into an unbounded stream of domain creations —
a denial of service the system performs on itself, delivered enthusiastically. `bin/sup`'s twelve
already encodes the principle, and it says why in its own comment: a policy that never finishes
cannot be asserted by a boot test.

**Degrade to doing nothing.** If the keeper dies, services already running keep running; the system
loses the ability to heal, not the ability to work. That mirrors [ai-native.md](../ai-native.md)'s
rule 2 and is checkable: kill the keeper, run the suite, everything passes.

### S2 — self-correcting

A file states what should be true — which services run, what envelope each holds, which packages are
installed at which version. A loop compares that against what *is* true and closes the gap using
calls that already exist. This is a control loop, not an intelligence: Kubernetes does it for
clusters and nothing does it for the inside of one machine.

Three rules keep it from becoming the thing it is easy to become:

1. **The reconciler never edits the declaration.** Drift is closed in one direction only.
2. **Every action is idempotent, and its own no-op is the common case.** A reconciler that does
   something on every pass is a reconciler with a bug.
3. **A gap it has no legal action for is a report, not an attempt.** Unrepairable drift must be
   loudly visible; the failure mode to avoid is a loop that keeps trying and keeps looking busy.

The decision function — *given declared state and observed state, what is the legal action set?* — is
pure arithmetic over two structures, which means it is **host-testable in full**, and that is why it
is specified separately from the code that executes it.

### S3 — self-maturing, and the only place a model appears

`ai-native.md` §3 already specifies the contract for a policy that influences a kernel decision, and
this RFC **adds nothing to it and weakens none of it**. The keeper computes the legal remedy set; an
advisor in an ordinary killable domain may order that set; the keeper acts. Restated in this plane's
terms:

- The advisor **cannot add a remedy** — the set comes from the manifests.
- The advisor **cannot authorise** — `ai-native.md` §7: a probabilistic system does not get a vote
  on a security decision. Capabilities authorise. That is the whole architecture.
- The advisor **cannot act** — it holds no `DomainControl`. It emits a ranking; the keeper reads it.
- The advisor **can be killed at any moment**, whereupon ranking reverts to the manifest's declared
  order and the system keeps healing exactly as well as S1 did.
- What "maturing" persists is a **ranking table**: small, inspectable, diffable, revertible, and — per
  `ai-native.md` §8's open question on model provenance — measured into the boot chain if it is
  allowed to influence anything.

**What the advisor is actually good at**, and it is worth being concrete rather than aspirational:
choosing *which* of three restart orders converges fastest for a dependency graph this machine has
seen fail before; predicting that a service which has faulted four times in an hour will fault again,
so that draining it is preferable to restarting it; correlating a fault with the causally preceding
events across subsystems — which is `ai-native.md` §1's thesis, and needs typed causal telemetry
that only a kernel can produce. None of that is an LLM in a fault path. An LLM belongs in the
operator assistant, off the critical path entirely, at second-scale latency, and `ai-native.md` §5
already says so.

### The ledger

Every action any stage takes emits an `Audit`-class telemetry event carrying four fields:

```text
observation   the event(s) that triggered it, by timestamp and id
rule          the manifest line or declaration that authorised it
action        the capability invocation made
result        what happened
```

**The `Audit` class is reserved and refused today** — RFC 0026 counts an emission and drops it,
because a best-effort audit event is false assurance with a checksum, and the backpressure ring is
owed to a future RFC ([security.md](../security.md) §8). That is a **hard prerequisite for S1**, not
a detail: an autonomous action whose record was dropped under load is an autonomous action nobody
can audit, so the audit RFC lands before a keeper is allowed to act. This paragraph claimed the
backpressure already existed when this RFC was first drafted; it does not.
`ai-native.md` §7's sentence is the acceptance criterion — *"the model decided" is not an audit
record* — and it applies to stages 1 and 2 as much as to 3, where there is no model to blame.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Do nothing; operator scripts and runbooks** | It is where every other OS is, and it discards the one advantage this architecture actually has. A driver restart is not scriptable on a monolithic kernel; here it is a capability call | Never for S1. If S2 turns out to duplicate what a package tool already does, S2 alone could fold into RFC 0030 |
| **Supervision in the nucleus — a kernel watchdog that restarts domains** | It is the mistake RFC 0032 spent ten steps undoing. Restart policy is *policy*: budgets, dependency order, what counts as healthy. Every one of those is Linux-shaped state's cousin, and none of it needs ring 0 | A measurement shows ring 3 supervision cannot meet a real latency target — and the number, the target and the workload are written down first |
| **One privileged supervisor that owns everything** (the systemd shape) | RFC 0031 §"three failure modes" names this exactly: a single process holding every service's authority is a monolithic kernel with an extra address space. The keeper must hold the ability to *start* services, not the union of their grants | It cannot be made to work otherwise — and the fix would be several keepers, not one bigger one |
| **Per-service supervisors, no central declaration** (the pure Erlang shape) | Supervision trees are the right *structure*, but with no single reviewable file there is no answer to "what is this machine supposed to be running?", which is exactly the question S2 exists to answer | The manifest set turns out to be the wrong place, in which case the declaration moves — it does not disappear |
| **Checkpoint and restore instead of restart** (the CRIU shape) | Restoring the state that crashed you is how you crash again, and it is an enormous surface. The journalled filesystem already shows the right kind of state recovery: recover the *data* by design, discard the *process* | A stateful service demonstrates that restart cost is unacceptable — with the measurement, not the intuition |
| **Machine learning from stage 1** | There is nothing to learn from: no fault corpus, no hardware, no production. And a non-deterministic component introduced before the deterministic one means neither can be tested — a failure to heal could be the model or the mechanism, and nothing distinguishes them | Never in this order. S3 after S1 and S2 have a fault corpus worth learning from |
| **Call the whole thing "AI" now** | The project's credibility rests on gates that have been watched go red. Stages 1 and 2 contain no model; naming them AI would be the first unearned claim in the documents, and it would retroactively discount the earned ones | S3 ships, at which point the word is accurate and small |

## Impact on existing design documents

If accepted, updating these is part of the implementation, not a follow-up:

- **[ai-native.md](../ai-native.md) §6** — the row *"Autonomous system management: closed-loop actions
  … executed only within pre-declared, operator-authored bounds"* is the one-line version of this
  entire RFC. It becomes a pointer here, and the sentence *"Autonomy is a bounded authority grant,
  not an ambition"* is promoted, because it is the correct summary.
- **[roadmap.md](../roadmap.md) Phase 3** — gains S1/S2 rows. S3 stays in Phase 4 with the rest of
  the model work.
- **[security.md](../security.md) §1** — gains **T12** and **T13** (§6 below). This is the first
  threat model change since T11, and both new rows are in scope from the day S1 ships.
- **[RFC 0030](0030-packages.md)** — the manifest grammar gains a supervision block. Question 1 of
  that RFC (*does the kernel's own bring-up read these manifests?*) is adjacent and stays open.
- **[RFC 0017](0017-process-management.md)** — its second unresolved question, *what restarts a
  service that died*, is answered in full rather than by demonstration. `bin/sup` stays as the
  minimal proof it was written to be.

## Security implications

Reference [security.md](../security.md) §1. This RFC introduces authority, and the honest accounting
matters more than the feature.

**New authority: the keeper.** It holds `DomainControl` over every service it supervises and the
ability to start programs with manifest-derived grants. That is not the same as holding the union of
those grants — it cannot read the filesystem because `bin/fsd` can — but it **is** the ability to
stop every service in the system, and to start a program with any authority any manifest declares.
Priced exactly as T11 was priced for the Linux adapter, in the step that creates it, not afterwards.

**T12 — a compromised or subverted supervisor.** Mitigations proposed: the keeper holds no
filesystem, device or network capability and cannot obtain one; it can only start programs from
manifests already installed and measured; every action is in the `Audit` ring, which it cannot write
selectively; and the budget bounds how much it can do per unit time even when it is doing it wrong.
**Several keepers, each over a subset, is the structural mitigation** and is left open in §7 rather
than assumed.

**T13 — automation as an amplifier, and policy poisoning.** Two shapes, one row:

- **Amplification.** A fault an attacker can *cause* becomes a fault the system *repeats*: crash the
  service, the keeper restarts it, crash it again. The restart budget is the mitigation and is
  therefore a security control, not a convenience — which is why it must have a boot gate of its
  own rather than being a constant somebody can raise.
- **Poisoning (S3 only, and out of scope until S3 exists).** If a policy learns from workload
  behaviour, then a hostile workload *teaches* it. This is a genuinely new threat class for this
  project — not a variant of T1–T11 — and it is the strongest argument for the rule that a learned
  artifact may change ranking and never the legal set: a poisoned ranking makes the system slower
  or dumber; it cannot make it insecure, because it never held the authority to.

**No new parser of untrusted input** at S1 and S2 — the manifest parser already exists and is
RFC 0030's. S3's persisted ranking table would be a new parsed artifact, and would need a fuzz
target named at the step that introduces it.

## Performance implications

The cost paid forever is the **idle** cost, not the healing cost, and it is the one to measure first:
a system that never faults still pays for liveness notifications and reconciliation passes.

| What | Claim to test | How |
|---|---|---|
| Liveness | One notification per service per interval is invisible next to the boot's existing crossings | The telemetry plane already prices crossings; compare a boot with supervision on and off |
| Reconciliation | A pass that finds nothing must cost approximately nothing | Time the no-drift pass; it is the common case by design |
| **Mean time to heal** | The number that actually matters: fault → service usable again | Measure it. A self-healing claim without this number is a hypothesis |
| S3 advice | Ranking is off the fault path; if the advisor is slow, the keeper proceeds with the declared order | `ai-native.md` §3 rule 4: a hard time budget, and exceeding it disables the policy |

## Testing plan

**Host.** The restart-budget arithmetic (N in T, including the boundary where the window slides) and
the reconciler's decision function (declared × observed → legal actions) are pure and belong in
`personality`-style crate tests with no QEMU anywhere near them. Dependency-order computation is a
topological sort and is host-testable including its cycle refusal.

**QEMU — and this is the demonstration the whole RFC exists for:**

> Kill `bin/blkd` in the middle of a filesystem workload. The keeper notices, restarts it in a fresh
> domain with the grants its manifest declares, and the shell lists files afterwards.

Negative-armed the way every gate in this project is armed: **withhold the keeper's `DomainControl`
and watch it fail closed**, and separately, run the same kill with supervision disabled and watch the
workload stay broken. A gate that has only been seen green has not been seen.

Two more: the budget gate (fault a service in a loop; assert it stops at the declared count and
reports degraded rather than restarting for ever), and `ai-native.md` §4's existing test shape
(kill the advisor; the suite still passes).

**Real hardware.** Most of this is testable in QEMU, which is the point — but the faults worth
healing are disproportionately hardware faults, and M1-17 is unmet. That is a reason to sequence
this after Phase 2, not a reason to weaken the gates.

## Unresolved questions

1. **Who supervises the supervisor?** The tree needs a root, and a root that can crash-loop is worse
   than no root. The honest position: the keeper is started by the boot path and its death is
   reported and not repaired at S1, which is a limitation stated openly rather than an oversight.
   Whether `bin/procd` supervises the keeper while the keeper supervises everything else — a
   two-level tree with a deliberately tiny apex — is the leading answer and is not decided here.
2. **Health: notification or poll?** A service arming a deadline proves the service is scheduled;
   it does not prove the service is *working*. A readiness check that exercises the actual path
   costs more and means more. Probably both, declared separately.
3. **How many keepers?** One is simplest and is a concentration of authority. Several, each over a
   subset, is the structural mitigation for T12 and costs coordination. Same question RFC 0033 left
   open about how many Linux adapters a machine should have, and it should probably be answered once
   for both.
4. **Does a hosted Linux process get any of this?** `bin/linuxd` is a service like any other and can
   be supervised; whether a *hosted process* inside it is supervised is a different question with a
   Linux-shaped answer, and belongs to RFC 0031's frame rather than here.
5. **What does "drain" mean for a device domain?** Restarting a stateless service is easy; a driver
   holding a device mid-transaction is not. The IOMMU makes it *containable*; it does not make it
   *quiescent*.
6. **Does the learned artifact persist across boots, and is it measured?** `ai-native.md` §8 leans
   yes on provenance. Persisting it also makes it an attack surface that survives a reboot, which is
   a property nothing else in this system currently has.

## Implementation plan

Not a schedule. **The trigger for starting is Phase 2's exit criteria and M1-17 — the first boot on physical
hardware.** Those are two triggers, not one: M1-17 is **M1's** criterion, in Phase 1, owed since
Phase 1 closed, and this document said "Phase 2's exit criteria, M1-17 in particular" until
2026-08-20, which put a Phase 1 criterion inside a Phase 2 clause. Until then this document is the deliverable.

**S1 — self-healing**

1. The manifest gains a supervision block; parsed, refused when malformed, host-tested. No behaviour.
2. `bin/keeperd`: `bin/sup` generalised to a manifest-declared service set, one service, no budget.
3. Liveness: a declared notification with a deadline; a missed deadline is a fault, gated.
4. The restart budget, with the boundary host-tested and a boot gate of its own (it is a security
   control — §6).
5. Dependency order: start before, stop after; cycles refused at parse time.
6. **The demonstration**: kill `bin/blkd` under load, and the shell still lists files. Negative-armed
   two ways.

**S2 — self-correcting**

7. The declaration: what this machine should be running. One file, reviewable, versioned.
8. The decision function, host-tested exhaustively before anything executes anything.
9. The reconciler, executing only actions RFC 0017 and RFC 0030 already provide, with the ledger.
10. Unrepairable drift reported, gated — the loud-failure path tested before the quiet-success one.

**S3 — self-maturing** — Phase 4, with `ai-native.md`'s model work, and not before there is a fault
corpus worth learning from. The first step is not a model: it is the ranking artifact's format, its
provenance, and the proof that discarding it entirely changes nothing but speed.
