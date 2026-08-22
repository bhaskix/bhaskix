# RFC 0034: The adoption case, and the claims it would commit us to

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-08-20** — a strategy relayed for consideration, recorded as a **ledger** rather than adopted as a direction. Nothing here is settled, nothing is built, and no existing claim in this project changes because of it. Its value is not the argument, which is largely [RFC 0031](0031-linux-compatibility-as-an-adapter.md)'s argument restated; it is the **audit** of that argument against the tree, which found three things nobody had written down — §3 P4, §4 D2, and §6 |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | docs |
| **Milestone** | Phase 2 → Phase 5. Like RFC 0031 this spans phases on purpose: the claims are testable at different milestones and the point is to say which |
| **Depends on** | [RFC 0031](0031-linux-compatibility-as-an-adapter.md) (the adapter frame this restates and audits), [RFC 0005](0005-linux-abi-compatibility.md) (the translation), [RFC 0030](0030-packages.md) (authority made reviewable — the "understandable" claim's only evidence), [RFC 0033](0033-what-a-hosted-process-is.md) (the draft L1 is blocked on), [vision.md](../vision.md) (which §6 says this contradicts), [GOVERNANCE.md](../../GOVERNANCE.md) §2 (who decides) |

---

## Summary

**A strategy for who adopts Bhaskix and why, recorded as a table of claims that can each be
checked.** The strategy in one line: *keep Linux software compatibility, replace the underlying
architecture* — so that a Linux user is never asked to choose between the ecosystem they have and
the security architecture they do not. Around it: five properties a system must hold to be loved
(Compatible, Secure, Understandable, Performant, Independent), five audiences, and a set of rules
about how the project should describe itself.

**This RFC does not ask for that strategy to be adopted.** It asks for it to be *recorded in a form
that can be checked*, because the failure mode of a positioning claim is that nobody can grep it,
and this project's entire documentary discipline exists to prevent exactly that. So §2–§5 are a
ledger: every claim gets a status, the line in this tree that proves or disproves it, and what would
make it true.

**Provenance, because it changes how much this document is allowed to settle.** The material arrived
2026-08-20 as an analysis the project lead relayed for consideration, *not* as a decision taken —
the same footing [RFC 0031](0031-linux-compatibility-as-an-adapter.md) recorded for its own framing
on 2026-08-19, and for the same reason. `Draft` is what that means here.

**What the audit found, which is the part worth reading:**

1. **"Performant" is not a tracked property of this project at all** (§3, P4). Individual boundaries
   are priced carefully, and there is exactly one performance gate in CI. The claim as stated has
   nothing behind it, and `vision.md` refuses the premise on purpose.
2. **The proposed demonstration is stronger than the one we have specified** (§4, D2). RFC 0031's
   Test 1 is a synthetic probe asking for things and being refused. A real application, really
   exploited, with the boundary holding and its neighbour still serving, is a different and better
   test — and it is nowhere in this tree.
3. **`vision.md` contradicts the whole thesis** (§6), has done since RFC 0031 was drafted, and is an
   *adopted* document whose own header says changes require a governance decision.

## Motivation

### The problem this solves

RFC 0031 fixed the *architecture* of Linux compatibility. It did not answer **who this is for and
what we are promising them**, and that question has started answering itself in prose — in the
README's opening, in the roadmap's demonstration line, in conversation. Prose accumulates claims
the way code accumulates behaviour, and this project's rule is that a claim nobody can check is a
claim believed further than it should be (`security.md` §1's T3/T4 note says exactly this about a
mitigation column).

There is a specific hazard here that is not hypothetical. The relayed material is *persuasive and
mostly correct*, and roughly two thirds of it describes things this tree genuinely does. That is
the dangerous ratio: a document where most rows are true is one where the false rows travel
unchallenged. Splitting them apart is the whole deliverable.

### What happens if we do nothing

The adoption story stays oral. Its true parts get repeated accurately, its untrue parts get
repeated with equal confidence, and the first time someone outside the project checks — a reviewer,
a journalist, the two independent document reviewers R6 has been waiting for — they find claims
with nothing under them, in a project whose entire credibility rests on the opposite habit.

### Who has this problem

The project lead, who is being asked to choose a direction; and every future contributor who
inherits a positioning they cannot audit.

---

## 1. The strategy, compressed

Recorded so the ledger has something to point at. This is the relayed argument, not a decision.

```text
                    BHASKIX
                       │
        ┌──────────────┴──────────────┐
   Linux applications           Native apps
   nginx / MariaDB / Python           │
   PostgreSQL / gcc / ssh             │
        │                             │
   Linux ABI adapter                  │
        └──────────────┬──────────────┘
                Bhaskix services
                       │
             Capabilities + domains
                       │
                Bhaskix nucleus
                       │
                    Hardware
```

- **The offer:** run the software you already have; get a different security foundation under it.
  Compatibility and a new architecture stop being a trade.
- **The message ordering:** *"you don't have to leave Linux software to use Bhaskix"* — never
  *"replace Linux"*, which buys resistance for nothing.
- **The five properties:** Compatible, Secure, Understandable, Performant, Independent.
- **The demonstration:** a real application is exploited, the blast radius stops at its domain, its
  neighbour keeps serving, the kernel is untouched.
- **The framing:** an operating-system architecture for the compromise-assumed era, *with* Linux
  compatibility. Origin — designed and developed in India — as provenance, not as the technical
  argument.

The diagram above is the same shape as RFC 0031 §1's, drawn for a different reader. Where the two
disagree about anything load-bearing, **RFC 0031 wins**: it is the architecture, this is a pitch.

---

## 2. Ledger, group A — what a Linux user would be promised

Status vocabulary is this tree's: ✅ true today · 🔨 partly true, with the limit stated ·
⬜ not started · ❌ refused, permanently or for now.

| # | Claim | Status | The line that decides it | What would make it true |
|---|---|---|---|---|
| **C1** | nginx, MariaDB, Python, gcc, rustc, ssh, curl, git "work as expected" | ⬜ | `roadmap.md` §"Linux compatibility — L1 to L4": **all four rows read `not started`**. What runs today is one static Go binary that loads, prints and stops in its own allocator after **212 traced calls**. Capacity is no longer the near ceiling it was: RFC 0033 step 3 raised four limits on 2026-08-20, so the machine holds **twenty-five** concurrent hosted processes where it held five — `MAX_SPACES` 32 with 7 used, gated at "at least eight free" because eight is a shell pipeline's worth | L1 → L2 → L3, in order, each gated. **L1 cannot start until [RFC 0033](0033-what-a-hosted-process-is.md) is accepted** — it is a draft |
| **C2** | "You don't have to choose between compatibility and security" | 🔨 | The security half is real and gated: `security.md` §1 **T11 is mitigated**, and the count of Linux syscall numbers the nucleus interprets reads **0**, printed and gated on every boot that ran a hosted program. The compatibility half is C1 | C1. Note the asymmetry honestly — **the trade cannot be said to be avoided while only one side of it exists** |
| **C3** | "You don't have to leave Linux software" as the *opening* message | ⬜ | `README.md`'s second line today is "Bhaskix is not a Linux distribution", and `vision.md` line 82 lists binary compatibility as an anti-goal | A governance decision — **§6, item G1** |

> **A number found stale while writing this row, recorded rather than quietly used.** C1 was drafted
> citing **five** concurrent hosted processes, which is what [RFC 0033](0033-what-a-hosted-process-is.md)'s
> Summary, `roadmap.md`'s L1 row and `TRACKER.md`'s **HP1** row all still say. RFC 0033 **step 3**
> raised the four limits behind that figure on 2026-08-20 — `MAX_SPACES` 12 → 32, `MAX_DOMAINS`
> 32 → 64, `CSPACE_SLOTS` 64 → 128, `MAX_CAPABILITIES` 1,024 → 4,096 — and `abi/src/lib.rs` reads 64
> today. The true figure is **twenty-five**. Step 3 recorded itself in its own section of RFC 0033
> and in this tracker's changelog, and did not update the three places carrying the old number,
> which is the drift working rule 1 exists to catch. **Not fixed here** — it belongs to step 3's
> change, not to a document that merely noticed it — and it is named so it is fixed rather than
> found again by whoever quotes "five" next.

---

## 3. Ledger, group B — the five properties

| # | Property | Status | The line that decides it | What would make it true |
|---|---|---|---|---|
| **P1** | **Compatible** — my applications work | ⬜ | = C1 | = C1 |
| **P2** | **Secure** — a compromised application does not compromise the system | 🔨 | Structural, and gated *at the boundary*. `packages/linuxd.manifest.in` is the whole of the adapter's authority: one endpoint, three pages, a **write-only** console, sixteen notifications it may signal and may not wait on, and one supervisor handle per hosted domain. RFC 0031 **Test 1's first arm shipped** and is negative-armed — a hosted program asking for all five native syscall kinds by number, refused five times, *including surviving the one that is `Exit` natively* | Test 1's **missing arms**: the memory arm (needs a second domain to read at), the device arm (needs a device it was not given), and the grant-set-unchanged assertion afterwards. **Test 3 — Linux `root` — is unfunded: there is no UID in this system at all.** And D2 |
| **P3** | **Understandable** — I can see what authority each component has | 🔨 | Real, and its limit is already recorded against itself. RFC 0030 makes a package's grants a reviewable list, and the shell's `caps` reports authority by *trying* each slot. But `packages/linuxd.manifest.in` **cannot express two of its own three grants**: the grammar has no way to say *write-only* about a console and no way to say *sixteen* notifications, so it describes them in prose and **deliberately over-claims** — "the safe direction for a reviewer to be wrong in" | `cap console write` and `cap notification count=N`, whose trigger is already written: the first package **installed** rather than started by the kernel that needs either. **This also answers RFC 0031's unresolved question 4 in the negative** — reuse was "the default until something cannot be said", and something cannot be said |
| **P4** | **Performant** — security does not destroy performance | ⬜ | **Not a tracked property of this project.** `TRACKER.md` §6 lists exactly one performance gate: rt latency p99.9 < 50 µs. Boundaries are priced individually and well — the personality relocation was floored at 4,916 cycles before it was done, telemetry emit at ~1101 cycles — but `architecture.md` line 562's rule **"Native software never pays"** has *no gate*, and `vision.md` line 86 says "**Not** a benchmark-first project" | Either a cross-cutting benchmark with a written regression bound, or **withdraw the claim**. Recommended: withdraw it from the pitch and keep pricing boundaries, which is the honest version of the same thing and is what this project already does well |
| **P5** | **Independent** | ✅ | **True, and stronger than the material claims it.** `Cargo.lock` holds **20 packages and all 20 are `bhaskix-*`** — this workspace has zero external dependencies, which is a supply-chain position almost nothing else in this class holds. Apache-2.0 with an explicit patent grant; the machine boots on its own loader (`bhaskixboot.efi`) through a struct the project owns | Already true. **Its limits belong beside it**: one author and no independent reviewers (**R6 unmet**), and Limine remains in-tree as the BIOS path — contained to `boot/` by a gate, but present |

---

## 4. Ledger, groups C and D — the audiences, and what is missing

| # | Claim | Status | The line that decides it |
|---|---|---|---|
| **A1** | Developers see their application's authority explicitly | 🔨 | = P3. And the vocabulary is narrower than the pitch: today's nouns are `console`, `endpoint <service>`, `memory pages=N`, `notification`, `timer`, `device-registers`. There is no `network`, `gpu`, `camera` or `database` — the pitch's example list is aspirational in every noun it uses |
| **A2** | Admins get containment after an RCE | ⬜ | Nothing to exploit. Depends entirely on L3, which depends on L2, L1 and RFC 0033. The *mechanism* is P2; the *story* is D2 |
| **A3** | Security engineers get causal visibility — "this domain attempted authority it did not possess" | 🔨 | The telemetry plane is built and gated (RFC 0026): typed, per-CPU, lock-free, with `Cap` and `Fault` classes and `bin/traced` draining for the life of the boot. **But `EventClass::Audit` is "Reserved and refused in Phase 2"** — deliberately, because `security.md` §8 requires audit events to apply backpressure rather than drop and "a best-effort audit event is false assurance". So the sentence in this claim is **a debugging record today and not an audit record** |
| **A4** | Cloud and multi-tenant workloads | ⬜ | Phase 3. RFC 0026 deferred per-domain telemetry filtering with the trigger written down: "the multi-tenant consumer that needs it arrives with the audit work" |
| **A5** | Hardware vendors — the driver leaves the trusted computing base | ✅ | True, with its conditions stated, which is how `security.md` §1 already writes it. RFC 0012 complete: per-device page tables under per-device domain ids, interrupt remapping **on by default**, revocation enforced against the hardware. Conditions: with **no** IOMMU a domain-hosted driver is refused outright and the boot says `NO IOMMU`; `iommu=off` reproduces that deliberately; and **nothing has ever booted on physical hardware**, where real firmware declares reserved regions QEMU never has |

**Group D — things the material proposes that this project does not have.**

| # | Proposal | Status | Note |
|---|---|---|---|
| **D1** | An installer showing a compatibility matrix, and `pkg install nginx` | ⬜ | No installer exists. The standing user-friendliness directive already asks for a configuration TUI and says it should arrive via RFC when the need appears; this is that need, not yet urgent |
| **D2** | **The demonstration: a real application exploited, contained, its neighbour still serving** | ⬜ | **The most valuable item in the relayed material, and it is new.** RFC 0031 §6 Test 1 is a *synthetic probe* — it asks for things it should not get and is refused. That proves the boundary is *shaped* right. It does not show a blast radius, because nothing is exploded. A real CVE in a real service, contained, with MariaDB still answering and the kernel untouched, is a different claim and a much harder one. **Recommendation: adopt as L3's demonstration criterion**, beside the one `roadmap.md` already names ("Bhaskix boots → a compatibility domain → nginx + MariaDB + OpenSSH → network clients connect"). Its prerequisite is L3, so it costs nothing to write down now and cannot be faked early |
| **D3** | "SecSphere receives causal security telemetry" | ❌ | **`SecSphere` names nothing in this project.** Checked as `git grep -i secsphere HEAD`, which returns **0** — the reproducible form, because a working-tree grep now finds this row and would read as a hit. Either it is a separate effort Bhaskix should not name until it exists, or it needs its own introduction. Recorded so the name does not enter these documents by assumption, and phrased against `HEAD` so the check stays runnable after this RFC lands |

**Group E — the communication rules**, recorded and not acted on. **E1** "do not lead with Rust"
(today `README.md` carries Rust as a headline bullet). **E2** the compromise-assumed framing with
origin as provenance rather than argument. **E3** "do not tell Linux users to switch". Each is a
decision for the project lead; each conflicts with a line that exists today; none is changed by this
RFC.

---

## 5. What this ledger is worth, stated plainly

Counting the sixteen statused rows of groups A–D: **two ✅, five 🔨, eight ⬜, one ❌.** Group E is
not counted — communication rules are decisions, not claims, and giving them a status would imply
they had been checked against something.

The honest reading is not flattering to the pitch and is quite flattering to the tree. **The
security architecture the material sells is largely real, gated, and better-evidenced than the
material knew** — P5 especially, which the pitch understates. **The compatibility half is entirely
future**, and every audience story except A5 rests on it. A pitch built on this ledger today would
be a pitch about architecture and discipline, delivered to kernel and security people, with the
Linux ecosystem named as a destination and marked unmet — which is roughly what `README.md` already
does.

That is the answer to "are we really doing this now, or in future": **the foundation now, the
promise later, and the boundary between them is this table.**

---

## 6. Governance item G1 — `vision.md` contradicts the thesis

**Stated as its own section because it is the one thing in this document that requires a decision
rather than a note.**

`docs/vision.md` is marked *adopted*, and its header says: "Changes to this document require a
governance decision." Its "What Success Does Not Mean" section, line 82, reads:

> - **Not** binary compatibility with Linux. We may add a translation layer in userspace much later;
>   it will never be a nucleus concern.

**The second clause is satisfied and gated** — better than satisfied: the count of Linux syscall
numbers the nucleus interprets reads 0, checked on every boot as an equality that may not move.

**The first clause is contradicted**, and not only by this RFC. RFC 0031 states the goal as running
the Linux software ecosystem through an adapter. `roadmap.md`'s L1–L4 table names nginx, MariaDB,
PostgreSQL, Python and OpenSSH as targets. RFC 0005 is a binary-compatibility RFC. The contradiction
has been live since **2026-08-19** and was not noticed when RFC 0031 was drafted; it is recorded here
rather than left for a reader to find.

Three ways out, and the choice is the project lead's per `GOVERNANCE.md` §2 ("Architecture direction
— Project lead, after RFC"):

| Option | What it means | Cost |
|---|---|---|
| **Amend `vision.md`** | Binary compatibility becomes a stated goal, scoped to "through an adapter, never in the nucleus" — which is what the tree already builds | A governance decision on an adopted document. Honest, and makes four other documents stop contradicting one |
| **Amend RFC 0031 and the roadmap** | Compatibility is demoted back to "may, much later", L1–L4 become speculative | Contradicts eleven steps of work already shipped and gated. Not recommended |
| **Leave it** | The contradiction stands, recorded | Cheapest today, and it is exactly the kind of quiet drift RFC 0031 §5 exists to prevent. Not recommended |

**Nothing in `vision.md` is edited by this RFC.**

---

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Record nothing — treat it as conversation | The material is persuasive and mostly true, which is precisely why its untrue parts travel. An unrecorded pitch cannot be audited, and this project's credibility is built on the opposite habit | Never for direction-setting material. A passing remark does not need an RFC |
| Write it as a strategy document that *adopts* the positioning | It arrived as material for consideration, not a decision, and adopting it would settle **G1** by side effect — an adopted document amended by a document that never mentioned amending it. That is the drift shape RFC 0031 §5 was written about | The project lead decides the direction explicitly, in which case this RFC's status changes and §6 is resolved first |
| Put the claims in `TRACKER.md` §4 as rows | `TRACKER.md` owns *status*, RFCs own *rationale* — the division that stops the two drifting. A claims ledger with no argument above it is unreadable in six months | Never; the tracker gets one decision-log row pointing here, which is the convention |
| Rewrite `README.md` to the new message ordering now | Commits to the positioning before it is decided, and would put a compatibility promise at the top of a project where L1–L4 all read `not started` — the exact thing `roadmap.md` forbids in writing | **G1** resolved in favour of amending `vision.md`, after which the README follows deliberately |

## Impact on existing design documents

- **[vision.md](../vision.md) line 82** — quoted in §6. **Contradicted, not changed here.** If G1 is
  resolved by amendment, that edit is part of *that* decision's implementation.
- **[vision.md](../vision.md) line 86** — "Not a benchmark-first project" is the reason P4 has no
  evidence. Not a defect; the pitch's claim is the thing out of step, not the document.
- **[RFC 0031](0031-linux-compatibility-as-an-adapter.md)** — gains two pointers, no changes:
  unresolved question 4 is answered in the negative by P3, and §6 Test 1 gains D2 as the stronger
  demonstration it does not currently specify. RFC 0031 is a draft, so this is legal.
- **[roadmap.md](../roadmap.md)** — unchanged. If D2 is adopted, its L3 row gains the criterion.
- **[README.md](../../README.md)** — unchanged, and one defect noted in passing for a separate fix:
  line 48 still says "No IPv6, and no sockets API beyond UDP and TCP's own", stale since RFC 0029
  was accepted on 2026-08-18.

## Security implications

**None.** This RFC adds no code, no interface, no authority, and no parser. It moves nothing between
in-scope and out-of-scope in `security.md` §1.

Two rows it *reports on* without changing: **T11** is mitigated and P2 restates its limits rather
than rounding them up; and RFC 0031's Test 3 (Linux `root` confined) is recorded here as **unfunded**
in the same words `security.md` uses, because a pitch that leans on the admin story is leaning on a
test nothing pays for yet.

## Performance implications

**None**, and P4 is the finding that this project has no cross-cutting performance claim to make.
Recorded rather than fixed: manufacturing a benchmark suite to back a pitch would be the wrong order
of operations, and `vision.md` line 86 already says so.

## Testing plan

A ledger's test is that its citations still resolve. Each row above names a file or a printed line;
if one goes stale the row is wrong, which is the same rule every other document here lives under.

- **Host / repository:** every evidence citation is a `grep` — the lockfile's 20 `bhaskix-*`
  packages, `EventClass::Audit`'s "Reserved and refused in Phase 2", `architecture.md`'s "Native
  software never pays", the four `not started` rows in `roadmap.md`, and `git grep -i secsphere HEAD`
  returning 0 — against `HEAD` rather than the working tree, for the reason D3 gives.
- **QEMU:** nothing new. The rows that cite boot output (the ratchet reading 0, `NO IOMMU`,
  Test 1's five refusals) are already gates and already run.
- **No new gate is proposed.** A ledger of unmet claims should not be enforced by CI; enforcing it
  would only prove the claims are still unmet, which is what the table says in plain text.

## Unresolved questions

1. **G1** — the `vision.md` contradiction. Project lead, per `GOVERNANCE.md` §2. §6 recommends
   amendment.
2. **Is D2 adopted as L3's demonstration criterion?** Recommended. Costs nothing now, cannot be
   faked early, and is the demonstration the adoption case actually rests on.
3. **Is P4 withdrawn or funded?** Recommended: withdrawn from the pitch, boundaries kept priced.
4. **Does `SecSphere` exist as a Bhaskix concern at all?** Until answered, the name stays out of
   this project's documents.
5. **The communication rules E1–E3** — each conflicts with a line shipped today. Decided together
   with G1 or not at all; deciding them piecemeal produces a README that argues with itself.

## Implementation plan

**Deliberately empty.** This RFC's whole content is a record; there is nothing to build, and the
next action is a decision rather than a PR.

What follows *if* the decisions in §"Unresolved questions" go the recommended way, in order and each
its own change:

1. **G1** — amend `vision.md` line 82 to state binary compatibility as a goal scoped to the adapter,
   with the contradiction's history recorded rather than deleted, per this project's correction rule.
2. **D2** — add the exploit-contained demonstration to `roadmap.md`'s L3 row and to RFC 0031 §6 as
   Test 1's endpoint.
3. **P4** — either a benchmark RFC with a written regression bound, or nothing, and the pitch drops
   the word.
4. **E1–E3** — the README and its bullet order, once, after G1 and not before.
