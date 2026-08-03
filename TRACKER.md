# Bhaskix — Project Tracker

**This file is the single source of truth for project status.** If any other document, issue, or
conversation disagrees with this file about *what is done* or *what is next*, this file wins.

| | |
|---|---|
| **Last updated** | 2026-08-03 |
| **Phase** | Phase 1 — Foundation |
| **Active milestone** | **M4 — Threads and scheduling** |
| **Overall progress** | M1 17/18 (hardware blocked) · M2 MET · M3 COMPLETE · M4 threads preempt, CPUs online · CI green |

### Division of responsibility between documents

Keeping these separate is what stops them drifting into contradiction.

| Document | Owns | Changes |
|---|---|---|
| **TRACKER.md** (this file) | *Status.* What is done, in progress, blocked, next. Decision log. Changelog. | Every working session |
| [docs/roadmap.md](docs/roadmap.md) | *Scope.* Milestone definitions and exit criteria. | Rarely — a change here is a scope change |
| [docs/rfc/](docs/rfc/) | *Rationale.* Why a design decision was made, and what was rejected. | Per accepted decision, then immutable |
| [docs/*.md](docs/) | *Design.* How subsystems work and their invariants. | With the code that changes them, in the same PR |

---

## 1. Working rules

These are the process rules for this project. They are binding.

1. **Update this file in the same change that changes reality.** A task moves to `DONE` in the PR
   that makes it done — never in a separate "update the tracker" commit. A tracker updated
   retroactively is fiction.
2. **`DONE` requires the exit criterion to pass**, not the code to exist. Criteria are in the task
   table and are things a stranger can run.
3. **Every task has a verifiable exit criterion.** If you cannot write one, the task is not
   understood well enough to start.
4. **Blocked means blocked.** Record what it is blocked on and who can unblock it. A task sitting in
   `IN PROGRESS` for weeks is a lie; move it to `BLOCKED` and say why.
5. **Design decisions go in the decision log below**, with an RFC number. "We discussed it" is not a
   record.
6. **Every bug fix adds a regression test** ([docs/coding-style.md](docs/coding-style.md) §8).
7. **No task is `DONE` with a failing or skipped CI gate.** Gates are listed in §6.
8. **Scope changes go to [docs/roadmap.md](docs/roadmap.md) first**, then here. Adding work to a
   milestone without updating its definition is how milestones stop meaning anything.

### Status legend

| | |
|---|---|
| `TODO` | Defined, not started |
| `WIP` | Actively being worked on |
| `REVIEW` | Code complete, in review or awaiting verification |
| `BLOCKED` | Cannot proceed — blocker recorded |
| `DONE` | Exit criterion verified passing |
| `DEFERRED` | Consciously moved to a later milestone, with a reason |

---

## 2. Decision log

Architecture decisions. Once `Accepted`, a decision is not revisited without a superseding RFC.

| ID | Decision | Status | Resolution | Record |
|---|---|---|---|---|
| **N1** | **Project name** | ✅ **Accepted** 2026-08-02 | **Bhaskix**, superseding the working name *VyomOS*. From *bhāskara* (भास्कर, "light-maker"/the sun) and the mathematician-astronomers Bhāskara I and II; `-ix` for the Unix lineage. Coined, therefore ownable — unlike a dictionary word. | [RFC 0002](docs/rfc/0002-project-name.md) |
| **A1** | **License** | ✅ **Accepted** 2026-08-02 | **Apache-2.0.** Permissive for maximal enterprise and government adoption; explicit patent grant, which MIT lacks and which matters for a project inviting corporate contribution. | [RFC 0001](docs/rfc/0001-license-apache-2.0.md) |
| **D1** | Implementation language | ✅ Accepted 2026-08-02 | **Rust** (`no_std`, edition 2024) + minimal asm. Chosen over C, Zig, C/Rust hybrid. Memory safety must be structural to satisfy the security principle. | [docs/architecture.md](docs/architecture.md) |
| **D2** | Boot mechanism | ✅ Accepted 2026-08-02 | **Limine protocol**, isolated behind project-owned `bhaskix_boot::Handoff`. Native `bhaskixboot.efi` scheduled for Phase 2. | [docs/architecture.md](docs/architecture.md) §1 |
| **D3** | Kernel model | ✅ Accepted 2026-08-02 | Capability-based **nucleus with relocatable services**. Not a pure microkernel, not a monolith. | [docs/architecture.md](docs/architecture.md) §2 |
| **D4** | Isolation primitive | ✅ Accepted 2026-08-02 | **Domains** — containers and VMs are the same primitive. | [docs/architecture.md](docs/architecture.md) §4 |
| **S1** | Storage architecture | ⬜ Draft | Capability-scoped Merkle-checksummed object store; POSIX as one personality. | [RFC 0003](docs/rfc/0003-storage-architecture.md) |
| **P1** | First deployment target | ⬜ Draft | Operational technology — a hypervisor beneath the customer's existing, uncertifiable OT stack. Reorders the roadmap: virtualization earlier, desktop later, IEC 62443 as the certification path. | [RFC 0004](docs/rfc/0004-ot-security-gateway.md) |
| **K1** | Storage implementation | ⬜ Draft | **Kosh** — RFC 0003's layers made concrete, plus distribution. Elastic from one node, RF=1…n, block/file/object/key-value, asynchronous geo. Commits to the row RFC 0003 marked *not committed*, and is explicit that the first years are single-node. | [RFC 0006](docs/rfc/0006-kosh-distributed-storage.md) |
| **C1** | Binary compatibility | ⬜ Draft | Linux `x86_64` ABI as a **domain personality**, not the native interface. First target deliberately narrow: statically linked Go binaries. Answers **A4** by refusing its premise — own ABI natively *and* Linux compatibility as something offered. | [RFC 0005](docs/rfc/0005-linux-abi-compatibility.md) |
| **A2** | Syscall ABI shape | ⬜ Open | Capability-invocation only vs a numbered syscall table. | *Blocks M5* |
| **A3** | IPC style | ⬜ Open | Synchronous rendezvous vs async buffered channels. Which is primitive? | *Blocks M5* |
| **A4** | Userspace ABI | ⬜ Open | Own ABI vs POSIX-shaped. [RFC 0005](docs/rfc/0005-linux-abi-compatibility.md) argues this is a false choice: capability-shaped natively, Linux-shaped through a personality that holds no authority its domain lacks. Still needs a decision on the *native* shape. | *Blocks M5* |
| **A5** | 5-level paging (LA57) | ⬜ Open | Support from day one, or assume 4-level and parameterise? | *Blocks M3* |

> **Correction to an earlier note:** A2–A5 were previously recorded in `roadmap.md` as blocking M1
> exit. They do not — M1 is boot and output, which none of them touch. The real gates are as shown
> above. A1 blocked *accepting external contributions*, and is now resolved.

---

## 3. Active milestone — M4: Threads and scheduling

**Threads exist and the timer preempts them.** The exit criterion is not met and will not be until
SMP lands — it requires N threads across M CPUs, and there is one CPU.

**Milestone exit criterion** ([docs/roadmap.md](docs/roadmap.md) M4): N threads across M CPUs,
10⁷ ping-pong iterations, no lost wakeups, no stranded threads, lock-rank assertions clean;
fairness within 2% for two equal-weight workloads.

| ID | Task | Status | Verified by |
|---|---|---|---|
| M4-01 | `Context` and `bhaskix_context_switch` | ✅ `DONE` | Threads run and resume correctly |
| M4-02 | Per-thread guarded kernel stacks | ✅ `DONE` | Each thread gets its own slot with a guard page |
| M4-03 | Round-robin runqueue | ✅ `DONE` | 7/7/7 runs across three workers |
| M4-04 | Timer-driven preemption | ✅ `DONE` | **Negative-tested**: removing the `preempt` call zeroes every worker counter |
| M4-05 | SMP bring-up, per-CPU areas | ✅ `DONE` | 1, 2, 4 and 8 CPUs all come online; boot test asserts N-of-N. Secondaries schedule as of M4-06. |
| M4-05b | Per-CPU GDT and TSS | ✅ `DONE` | Each CPU builds its own, with its own IST stacks; secondaries now idle with interrupts *enabled* |
| M4-06 | Per-CPU runqueues | ✅ `DONE` | One lock-per-CPU queue; threads are *owned* by a CPU. **Negative-tested**: forcing every thread onto CPU 0 fails the gate. |
| M4-06b | Work stealing and migration | ✅ `DONE` | Idle pull plus load-aware placement. **Negative-tested**: each of the three steal rules and the imbalance threshold has a unit test that fails when that rule alone is removed. |
| M4-06c | Topology-aware balancing, periodic push | ⬜ `TODO` | No ACPI topology, so every CPU is equidistant; balancing is pull-only. `docs/scheduler.md` §5.1 and §5.3. |
| M4-07 | Fair class (virtual deadline), RT class | ✅ `DONE` | Strict class priority, weighted fairness (3:1 measured 2.7–3.1x), FIFO/RR, admission control at 95%. **Negative-tested**: 13 unit tests over the pure pick, each failing when its rule alone is removed. |
| M4-07b | Priority inheritance, domain-level fairness, EEVDF lag | ⬜ `TODO` | PI needs a sleeping lock with an owner; domain fairness needs M5. A crude lead bound stands in for lag. |
| M4-08 | Lock ranking | ✅ `DONE` | Rank given at construction, so a lock cannot be added without one. ~7,400 acquisitions checked per boot, 0 violations. **Negative-tested**: mis-ranking a real lock produces violations; disabling the detector fails the "detector verified" claim. Deviates from "panic" — see `docs/coding-style.md` §7. |
| M4-09 | Sleeping, wait queues, blocking | ✅ `DONE` | `Blocked` state, `WaitQueue`, cross-CPU wake. Ring self-test over 4 CPUs. **Negative-tested**: disabling `wake` gives laps `[1,1,1,0]`, 0 wakeups. |
| M4-09b | Reschedule IPI on wake | ⬜ `TODO` | A cross-CPU wake waits for the target's next tick — up to 10 ms against the §4 target of 50 µs. |
| M4-10 | Tickless idle, timer wheel | ⬜ `TODO` | Timer is a fixed 100 Hz tick |
| M4-11 | TLB shootdown | ✅ `DONE` | IPI to all-but-self, sender waits for every acknowledgement. **Negative-tested**: disabling the receiving handler turns 8 completions into 8 timeouts. |
| M4-12 | Per-CPU frame reserve for the fault path | ⬜ `TODO` | Would let a fault be serviced while the allocator lock is held |

### Bugs found and fixed during M4

1. **New threads started with interrupts disabled, and the machine simply stopped.** A thread that
   has run before resumes through `iretq`, which restores `RFLAGS` and with it the interrupt flag.
   A brand-new thread has no such frame — it is entered by a `ret` from inside the timer's interrupt
   gate, which cleared `IF` on entry. So the first thread scheduled ran with interrupts off forever,
   the timer never fired again, and there was no crash to look at: no exception, no triple fault,
   just a halt. Diagnosed from QEMU's interrupt trace ending at a timer vector with nothing after.
   Fixed with an `sti` in the thread trampoline.
2. **Loading the GDT silently wiped the per-CPU `GS` base.** Secondaries set their `GS` base and
   *then* built their descriptor tables — but loading any selector into `GS`, including the null
   selector a GDT reload writes, resets the base to zero. Every later `gs:`-relative read therefore
   dereferenced address zero, and it surfaced as three page faults at `CR2 = 0` deep inside
   unrelated code, plus two "address space lock held" reports from a fault handler that could not
   service them. Found by resolving the faulting RIP through the KASLR slide back to a symbol and
   disassembling it: the faulting instruction was `mov %gs:0x0,%rcx`, and the GDT load sat between
   it and the `wrmsr` that was supposed to have made it valid. Fixed by splitting per-CPU setup into
   `install` (claim the identity, which the GDT build needs) and `activate` (point `GS` at it), so
   the two halves *bracket* the GDT load instead of preceding it. Negative-tested: putting
   `activate` back before the load reproduces all three faults.
3. **My own trampoline design was internally inconsistent** — it expected the entry point in `rax`,
   which the context switch does not restore. Caught while writing it; entry point and argument now
   travel in `r12` and `rbx`, which are callee-saved and therefore actually preserved.

### Honest notes on what is *not* proven

- **Balancing is pull-only, topology-blind and uncharged.** A CPU steals when it would otherwise
  run only the thread already on it; nothing pushes work, nothing runs periodically, and there is
  no ACPI topology, so a steal is as likely to cross a socket as to stay on one. Migration cost is
  not measured, so `docs/scheduler.md` §5's rule that a move must pay for itself is not enforced —
  the only brake is the imbalance threshold.
- **Convergence rests on one constant.** `STEAL_IMBALANCE = 2` is what stops a thread migrating
  back and forth forever. It is unit-tested and argued for in `docs/scheduler.md` §5, but it has
  never been tested against a workload that changes shape while it runs.
- **Shootdown is one address per IPI round trip, and one shootdown at a time.** Tearing down a range
  costs a round trip per page, which is the wrong shape for address-space teardown; batching is the
  obvious next step and deliberately untaken until there is a workload to measure. Teardown avoids
  the cost entirely today by skipping shootdown for address spaces no CPU has loaded.
- **`is_active` checks only this CPU's `CR3`.** Sufficient because secondaries never load an address
  space, and wrong the moment they do — it must become a per-space "loaded on" mask.
- **The locking is barely contended.** Each runqueue lock is taken by exactly one CPU plus its own
  timer interrupt, which is by design — but it means the only genuinely multi-CPU lock traffic is
  the console and the shootdown path. Nothing has stress-tested any of it.

- **This is round-robin, not the scheduler `docs/scheduler.md` specifies.** No priorities, no
  fairness weighting, no virtual deadlines, no RT class, no admission control. The fairness figure
  printed at boot is reported rather than asserted, because a tight bound on round-robin would be
  measuring timer jitter rather than any property worth defending.
- **Lock ranking does not stop a thread being preempted while holding a spinlock.** It makes the
  *order* safe; it does not make holding a spinlock across a context switch safe. A thread
  preempted while holding the heap leaves every other thread spinning for it until it is scheduled
  again — progress, but by luck of the timer rather than by design. Linux disables preemption
  inside `spin_lock` for exactly this reason and Bhaskix does not, which is a real gap that ranking
  made visible without addressing.
- **The `switching` handshake has not been observed doing its job.** It is the rule that stops a
  thief taking a thread whose registers are not yet saved, and it is the one hazard here that
  corrupts state rather than merely stranding it. Removing it fails a unit test, which proves the
  policy encodes the rule — not that the race it guards against was ever reached.
- **Real-time wakeup latency is 120–500 µs against a 50 µs budget.** Measured and printed at every
  boot rather than omitted. Part of the gap is that this is QEMU's TCG interpreter on a shared build
  machine and not a latency measurement of anything real; part is the missing reschedule IPI. It is
  a regression baseline, not a claim to have met `docs/scheduler.md` §4.
- **Priority inheritance does not exist**, which by §4's own words makes the RT latency bound a lie
  under contention. It needs a lock with an owner that can sleep; the spinlocks here have neither.
- **Fairness is between threads, not domains.** A domain that spawns more threads gets more CPU,
  which is exactly what §3's two-level runqueue exists to prevent. It needs domains, so M5.
- **A cross-CPU wake is not prompt.** It marks the thread `Ready` and stops; nothing interrupts the
  target CPU, so the woken thread waits for its next timer tick — up to 10 ms at 100 Hz, against
  `docs/scheduler.md` §4's 50 µs target. This is why the ring self-test measures dozens of laps per
  second rather than thousands. The fix is a reschedule IPI, using the mechanism shootdown already
  has.
- **One safety property is structural because it could not be tested.** Enqueueing a waiter and
  marking it blocked must happen together; separating them is a real lost-wakeup bug, and it was
  written deliberately and the ring test *did not catch it* — the window is a few instructions and
  116 sleeps never landed in it. The two steps are now fused in one function rather than left
  adjacent under a shared lock. The gate still cannot see that class of bug; the code makes it
  unwritable instead.
- **Excluding `Blocked` from scheduling is not covered by a gate.** Making blocked threads
  schedulable again still passes the ring test at 61 laps: they get scheduled, immediately re-block,
  and the ring works while burning CPU. It is a sleep-actually-saves-CPU property, and the boot test
  has no way to measure idle time.
- **Thread capacity is fixed at 8 per CPU** and stacks are never reclaimed. `exit` marks a thread finished
  but its stack stays mapped, so thread creation is effectively one-way.
- **No lock ranking**, which `docs/coding-style.md` §7 requires and which becomes load-bearing the
  moment there are enough locks to order.

### Blockers

| Task | Blocked on | Owner |
|---|---|---|
| M1-17 | Physical UEFI machine with serial. QEMU cannot substitute. | Tarun Kumar Kushwaha |
| Repo metadata | GitHub description and topics are unset, and `main` has no branch protection — `GOVERNANCE.md` §2 requires review for non-trivial changes and nothing enforces it. Deploy keys have no API scope, so these need the web UI. | Tarun Kumar Kushwaha |
| CI log access | Reading Actions logs needs authentication; unauthenticated API gives 60 requests/hour and only pass/fail. A fine-grained token with `Actions: read` would remove both limits. | Tarun Kumar Kushwaha |

## 4. Upcoming milestones

Scope and exit criteria are in [docs/roadmap.md](docs/roadmap.md). Not started; listed so the
dependency order is visible.

| Milestone | Scope | Status | Gated on |
|---|---|---|---|
| M2 | GDT, TSS, IDT, exceptions, APIC, bump allocator | `TODO` | M1 |
| M3 | Buddy PMM, paging, slab heap, COW, demand paging, KASLR | `TODO` | M2, **A5** |
| M4 | Threads, context switch, runqueues, SMP, timers | `TODO` | M3 |
| M5 | Capabilities, domains, syscalls, user mode, IPC | `TODO` | M4, **A2, A3, A4** |
| M6 | VFS, ELF loader, shell, virtio-blk | `TODO` | M5 |

---

## 5. Phase 0 — complete

| Item | Status |
|---|---|
| Vision, architecture, memory, scheduler, security, driver-model, ai-native, coding-style, roadmap docs | ✅ DONE |
| Repository structure and layout doc | ✅ DONE |
| Governance, contributing, authors, RFC template | ✅ DONE |
| License decision (A1) and `LICENSE` / `NOTICE` files | ✅ DONE |
| `tools/setup-dev.sh` | ✅ DONE |
| Design-document review by two people who did not write them | ⬜ **OUTSTANDING** |

> Phase 0's review criterion is genuinely not met — the documents have one author and no independent
> reviewers. This is recorded rather than quietly marked complete. It does not block M1 code, but it
> should be closed before the architecture calcifies.

---

## 6. CI gates

A task cannot be `DONE` with any of these failing. Each becomes active at the milestone shown.

| Gate | Active from | Enforces |
|---|---|---|
| `cargo fmt --check` | M1 | coding-style.md §2 |
| `cargo clippy -D warnings` | M1 | coding-style.md §2 |
| Host unit tests | M1 | coding-style.md §8 |
| QEMU boot test | M1 | Milestone exit criteria |
| `unsafe` budget | M1 | coding-style.md §3 |
| Limine containment (only `boot/` may name it) | M1 | architecture.md §1 |
| Dependency direction / no cycles | M1 | architecture.md §5 |
| No vendor strings in published files | M1 | Project policy |
| Frame-leak test (1000 address spaces, zero drift) | M3 | memory.md §7 |
| RT latency p99.9 < 50 µs | M4 | scheduler.md §4 |
| Fuzz targets on every untrusted parser | M6 | coding-style.md §8 |
| Both service placements build | Phase 2 | architecture.md §2 |
| AI-degradation test (kill `bhaskixd-ai`, suite still passes) | Phase 4 | ai-native.md §4 |

---

## 7. Changelog

Newest first. One entry per meaningful change of project state.

### 2026-08-04 (M4-07, scheduling classes — and four bugs it exposed)

- **Real-time and fair classes, in strict priority.** Fixed priorities 0–99 with `FIFO` and `RR`,
  weighted proportional share with virtual deadlines beneath them, and an idle class below that. The
  whole policy is one pure function over the runqueue, so all thirteen class rules are unit-tested on
  the host and each fails when its own rule is removed.
- **The deadline earns its place.** A thread asking for a *shorter* slice gets an earlier deadline and
  so runs sooner and more often for the same total share — how a latency-sensitive thread declares
  itself rather than being guessed at from its sleep pattern. Measured weight ratio at 3:1 is 2.7–3.1x.
- **Admission control refuses rather than degrades**, and real-time threads are excluded from work
  stealing: the budget is per-CPU, so migrating one invalidates it at both ends.
- **Accounting moved to the TSC**, because a 100 Hz tick cannot distinguish 200 µs from 9 ms and
  proportional fairness measured in ticks is not proportional fairness.

Four defects surfaced, three of them pre-existing and serious:

1. **The interrupt-enable flag was not part of a thread's context.** A thread yielding voluntarily,
   with interrupts on, could be resumed from inside an interrupt handler with them off — and then
   run on with the timer masked. That does not delay one thread, it stops the clock for the whole
   machine, and every other thread waits on a tick that never comes.
2. **Voluntary preemption was not atomic against the timer.** A tick landing between choosing the
   next thread and performing the switch re-entered the scheduler on the same thread; both calls
   then switched from their own stale view. It surfaced as a #GP on `iretq` from a corrupted
   interrupt frame — as far from the cause as a symptom gets. Both paths now mask for the duration
   of the decision and the switch.
3. **Nothing stopped a thread being preempted while holding a spinlock** — recorded as an open gap
   at M4-08 and now closed using that milestone's own rank mask, which already tracks what the CPU
   holds. On one processor this was a deadlock: the holder cannot release until it runs, and the
   spinner holds nothing, so the scheduler saw nothing wrong and kept choosing the spinner.
4. **`make iso` did not depend on `CMDLINE`.** Every fault-injection case after the first booted the
   *previous* case's image, so different subsets failed on different runs and it read as flakiness.
   This had been quietly weakening the fault gate, and it also explains the unreproducible hang
   recorded at M4-06.

- **Accounting had to move before the decision, not after.** `preempt` returns early when the running
  thread is still the right choice, so charging afterwards meant a thread that won one comparison was
  never charged again: its deadline froze at the winning value and it owned the CPU for ever.
- **An unbounded virtual-time lead starves.** A thread that once ran alone is far ahead in virtual
  time, and a group of threads that each run for microseconds before blocking accrue so slowly that
  it never runs again. Bounded at eight slices — deliberately generous, so it never fires under
  ordinary contention.
- **A test assertion was removed for measuring timing rather than policy.** Load-aware placement races
  with stealing by design, so asserting *which* CPU it chose failed about one run in three. It is
  reported now; the policy belongs in a unit test, not a live race.
- **The QEMU harness now polls instead of always waiting out the timeout.** The kernel halts rather
  than exiting, so every run cost the full timeout — which made the timeout impossible to tune, since
  long enough for a loaded machine also meant minutes of dead waiting. `make test` went from over ten
  minutes to 51 seconds, and the timeout went back to being an upper bound.
- **Toolchain moved to Rust 1.97.1** from 1.90.0, at the user's prompting. Two new lints found real
  sloppiness: casting a function item straight to an integer, and a hand-rolled checked division.

### 2026-08-03 (RFC 0006 drafted, Kosh storage)

- **RFC 0006 drafted**: `Kosh` (कोष, treasury) names the storage system and scopes the distributed
  tier — elastic from a single node, RF=1…n per volume, block/file/object/key-value over one
  substrate, heterogeneous geo-replication. Draft, awaiting a decision.
- **It commits to the row RFC 0003 marked "not committed"**, and does not withdraw that RFC's
  estimate: Ceph-scale distribution is a decade-scale programme. The document is therefore
  structured so the first two stages are independently useful and form a clean stopping point — a
  Merkle-checksummed, copy-on-write, capability-scoped store on one machine, which is what RFC 0003
  argued an evaluator actually needs.
- **The claims that cannot be made truthfully are stated first, not last.** RF=1 is not durable and
  must be reported as `Unprotected`; RF=2 on two nodes cannot survive a partition without a witness
  or a declared primary; cross-site replication is asynchronous because of the speed of light, so it
  has a non-zero RPO that must be measured and published rather than implied away; and "universal"
  describes the interface, not performance on all three workloads at once.
- **`n = 1` is not a special case** is called out as the hardest constraint. A separate single-node
  mode is two products with a migration between them, and the migration is the part users discover
  is risky.
- **Cluster membership ships before replication, deliberately.** Building both together means the
  first cluster test cannot distinguish a placement bug from a replication bug.
- **Automatic cross-site failover and synchronous geo-replication are refused outright**, not
  deferred, along with Ceph/S3 wire compatibility — which would mean inheriting the semantics RFC
  0003 exists to avoid.
- **Data locality is a scheduler decision, not a storage one.** Reads are served from the nearest
  healthy replica; writes cannot be local, because a synchronous write at RF=n is only durable when
  every replica has it. The interesting lever is moving the *compute* — Bhaskix schedules VMs and
  containers as domains and Kosh knows which nodes hold which extents, so "start this VM where its
  disk already is" is a decision the system can make. It is expressed as a weight the scheduler may
  trade off, never a constraint: locality and load balancing conflict directly, and a hard
  constraint turns a busy node into a queue.
- **Disaster recovery is separated from high availability, with the numbers named.** HA is
  within-site, synchronous, RPO zero, automatic. DR is cross-site, asynchronous, RPO non-zero and
  measured, RTO minutes, operator-initiated. Automatic cross-site failover is refused. Rehearsal is
  a first-class operation, because a failover procedure that has never been run is the thing that
  fails in the incident; and failback resynchronises by Merkle difference, because a full re-copy
  after every failover is how sites quietly stop failing back.
- **Replication is not backup**, and the RFC says so where a reader cannot miss it: replication
  copies destructive writes faithfully, so RF=3 across three sites is three copies of the ransomware.
  Snapshots are the answer, and an immutable snapshot means the capability that shortens retention
  is separate from the one that writes — expressible under the capability model in a way a
  permission bit is not.
- **The deepest open question is a capability question, not a storage one**: how authority survives
  a hop, so that a node holding a replica can serve it without holding authority over everything.
  It blocks the replication stage.

### 2026-08-03 (M4-09, sleeping and wait queues)

- **Threads can sleep.** A `Blocked` state, a `WaitQueue` with a bounded intrusive-free waiter list,
  and a cross-CPU `wake`. Until now the only way to wait was to spin, which cost a processor per
  waiter and — more to the point — made "no lost wakeups" not merely unproven but *inexpressible*,
  because nothing ever slept.
- **Waking stays inside M4-06's ownership rule.** It is the one place a CPU touches a thread in
  another CPU's queue, and it changes a `state` field under that queue's lock and never reads or
  writes a context. The woken thread is still scheduled by its own CPU, on its own stack.
- **The safety property was made structural because the test could not see it.** Enqueueing a
  waiter and marking it blocked must be one step: a waker only wakes threads already `Blocked`, so
  an entry belonging to a still-`Ready` thread is worse than no entry — the waker removes it, wakes
  nothing, and the thread sleeps forever. That bug was written on purpose and **the ring test passed
  anyway**, 52 laps, because the window is a handful of instructions. The two steps are now fused
  into one function so they cannot drift apart. A property a test cannot see should not be left to
  a convention.
- **A documented mechanism turned out to be documented wrongly.** The recheck in `block_self` was
  described as what closes the lost-wakeup race. It is not: by then the waker has already written
  `Ready`, and a `Ready` thread is picked up by round-robin regardless. What it actually provides is
  the loop's *exit* — deleting it hangs the kernel, because a thread woken in the gap with nothing
  else runnable on its CPU spins in the block path forever. Establishing that took deleting it and
  watching the kernel stop.
- **The gate requires three things at once**, because each hides a different way of passing without
  working: laps (a lost wakeup stops the ring dead rather than slowing it), non-zero sleeps (a ring
  that spun instead of sleeping proves nothing), and non-zero wakeups (threads woken rather than
  merely preempted onto). Negative-tested by disabling `wake`: laps `[1,1,1,0]`, zero wakeups.
- **A lost wakeup caused by migration, found by the thread table.** The waiter list originally
  recorded *which CPU* held each sleeper, so a wake could go straight to the right runqueue. That is
  wrong in a way that only shows up once work stealing exists: a thread is immune to migration only
  while it is `Blocked`, and a thread sleeping in a loop is `Ready` in between. Stolen in that gap,
  its recorded CPU goes stale and the next wake searches a queue that no longer holds it. The ring
  stalled at `[1,1,1,1]` with one station `Blocked` and marked `(migrated)` — which is the only
  reason it was diagnosable, and an argument for printing provenance in diagnostics. Waiters are now
  keyed by thread identifier, which is globally unique and cannot go stale; `wake` searches. The
  earlier claim that recording the CPU was migration-safe was true only *within* a single wait, and
  is corrected in the source.
- **A threshold tuned to the fastest configuration failed on the slowest.** The ring gate first
  required five laps, which BIOS cleared easily and UEFI did not — the framebuffer console is slow
  enough to turn the ring several times slower. It now asserts *shape* rather than speed: every
  station went round more than once, and no station is more than one lap ahead of another, which is
  what a ring guarantees when healthy and what a lost wakeup breaks.
- **A self-inflicted lock-order violation, caught by the previous milestone's gate.** `block_self`
  first took the runqueue lock with `lock()` rather than `try_lock()`, so the rank joined the held
  set and was then captured as the outgoing thread's — which carried a lock it did not hold to
  wherever it next ran. Twelve reports per boot, from the checker added the day before.

### 2026-08-03 (M4-08, lock ranking)

- **Every lock now declares its rank at construction.** `SpinLock::new` takes a `Rank`, so a lock
  cannot be added without saying where it sits — which is the rule `docs/coding-style.md` §7 asked
  for, expressed as a type signature rather than as a convention.
- **The declared order was recovered from the code, not invented, and two entries are not where
  intuition puts them.** `heap::HEAP` ranks *outside* `tlb::SENDER`, because unmapping frees frames
  inside `heap::with` and must shoot down before the frame is reused. And `sched::QUEUES` ranks
  *inside* the heap: a thread can be preempted while holding the heap, and the switch path then
  blocks on a runqueue. `sched::spawn_on` had already arrived at the same constraint independently
  by allocating outside the runqueue lock.
- **`try_lock` is exempt, and that is the load-bearing part.** A deadlock is a cycle in which every
  edge is a blocking wait, so a non-blocking acquisition can never be one. It matters because
  interrupt handlers acquire locks where the hardware chooses: a timer can land while any lock is
  held, so every lock taken in interrupt context is out of rank with respect to something.
- **The boot line reports what was checked, not just what was found.** Zero violations is exactly
  what a checker that never ran also reports, so the kernel states the number of acquisitions it
  checked (~7,400) and then proves the detector fires by provoking a deliberate inversion on a pair
  of locks created for that purpose.
- **Held ranks belong to the thread, not the CPU.** A thread preempted while holding the heap
  carries its held set with it; without that, the next thread to run on that CPU would inherit an
  ordering constraint it had no part in.
- **Deviation from the documented rule, recorded rather than quiet.** §7 said debug builds should
  panic; this reports and continues, as `lockdep` does. Halting on the first report discards the
  rest of the boot's coverage, and a rank violation is a latent risk rather than present
  corruption. `docs/coding-style.md` §7 and `docs/architecture.md` §6 now say so.
- **A bug I introduced and then caught the slow way.** The violation predicate had the mask
  direction backwards, so the checker was inert: it reported nothing on any input. The unit tests
  written alongside it encode the correct direction and would have failed immediately — I had not
  run them before booting. Running the host tests before the emulator would have found it in
  seconds instead of a boot cycle.
- **One unexplained hang, not carried forward as fixed.** A single `-smp 4` boot stopped after the
  TLB line while the checker was inert. Six consecutive runs afterwards were clean, and the
  evidence points to a partially built ISO rather than the kernel. It is recorded here because
  "could not reproduce" is the honest status, not "fixed".

### 2026-08-03 (RFC 0005 drafted, Linux ABI compatibility)

- **RFC 0005 drafted**: the Linux `x86_64` system-call ABI as a **domain
  personality** — a translation layer running in a service domain, implementing Linux calls on top
  of capabilities its domain already holds. Draft, awaiting a decision.
- **The narrow first target is the proposal, not a caveat.** Statically linked Go binaries with
  `CGO_ENABLED=0` remove the dynamic linker, `libc`, NSS and locale from the problem in one move,
  and Go issues raw syscalls, so the surface is the kernel ABI alone. "Enough Linux ABI for static
  Go" is a far smaller target than "enough for Docker", and choosing the smaller one deliberately
  is what makes it finishable.
- **It has to reconcile with RFC 0003, which argues POSIX is the wrong primitive.** The resolution
  is that the Linux ABI is a *personality*, exactly as POSIX is one row of RFC 0003's Layer 2 table
  — "paid only by callers who ask". Three rules make that real: no Linux concept enters the
  nucleus, the personality is never a source of authority, and native software does not link it.
  The RFC states that if those are ever relaxed for convenience it should be reverted rather than
  patched.
- **Docker and Kubernetes are answered by separating two questions.** Running OCI *images* needs
  no Docker daemon and is already on the Phase 3 roadmap; running `dockerd` would need namespaces,
  cgroups, overlayfs and seccomp-bpf, and would replace the domain model with Linux's. Position:
  OCI images yes, Docker daemon never. Kubernetes is named only so nothing forecloses it.
- **Recorded as decision C1**, and it reframes open decision **A4** (userspace ABI) rather than
  answering it: the own-ABI-versus-POSIX choice is a false one, but the native shape still needs
  deciding before M5.

### 2026-08-03 (M4-06b, work stealing and migration)

- **A CPU that would otherwise idle takes work from a busier one.** `docs/scheduler.md` §5 calls
  this the idle pull and expects most balancing to happen here, because it is free: the CPU had
  nothing to do. Creation also places a thread on the least-loaded CPU, which is cheaper than
  moving it afterwards.
- **Stealing moves ownership, which is what keeps the previous milestone's soundness argument.**
  A thread leaves the victim's queue and enters the thief's, under one lock at a time, and is
  afterwards owned by the thief exactly as if it had been created there. At no point do two CPUs
  hold pointers to the same context.
- **Three rules make that true, and every one of them is invisible when broken.** Only `Ready`
  threads move; never from a CPU partway through a switch; never the thread a CPU booted on. The
  middle one is the subtle one: a thread is marked `Ready` *before* the switch that saves its
  registers, and the runqueue lock is released in between — it has to be, since the incoming thread
  takes it — so `Ready` alone admits a thread whose context is not yet written.
- **The policy is unit-tested, not boot-tested, and that was a deliberate correction.** The first
  attempt at a negative test removed the pinned-thread rule and the boot test still passed: the
  hazard is a race that a single boot cannot be relied on to provoke. Extracting the decision into
  one pure function made each rule fail a specific test when removed, which is the difference
  between a rule that is enforced and a rule that is merely written down.
- **`STEAL_IMBALANCE = 2`, not 1.** At one, a thief with a single thread takes from a CPU with two,
  leaving two and one — and the victim, now lighter, takes it straight back. The thread migrates
  forever instead of running.
- **A bug in the test, found by a consistency check in the test.** The steal counter and the
  per-thread migration counters are written together under one lock and cannot legitimately
  disagree; asserting that caught the load-placement thread writing into migrant 0's record,
  because both were passed the same index. Without that check the phase would have reported success
  on two runs out of three.
- **Latent stack misalignment in the thread trampoline, fixed in passing.** It called the entry
  point with RSP 0 modulo 16, where the ABI promises 8. Nothing had noticed because the target
  disables SSE, and nothing would have until the first aligned vector access.

### 2026-08-03 (M4-06, per-CPU runqueues)

- **One runqueue per CPU, each with its own lock.** The throughput argument for this is real and is
  not why it landed now. The single-queue scheduler was *unsound* on more than one processor: it
  took raw pointers into a shared thread table and switched to them after releasing the lock, which
  is correct only if exactly one CPU is ever inside it. Making the queues per-CPU removes the
  sharing rather than protecting it — a CPU touches only its own threads' contexts, so there is
  nothing to race against.
- **Secondaries are now full scheduling CPUs.** Each registers its own queue with its current
  execution as the first thread, starts its own APIC timer, and idles interruptibly. Threads created
  on a secondary are preempted by that secondary's own timer, out of its own queue, with no lock
  shared with any other processor.
- **The boot test asserts the property, not the mechanism.** A global runqueue would still preempt;
  what distinguishes this is *where* threads run. The test spawns one worker per online CPU and
  requires worker *i* to observe itself on CPU *i*. Verified by breaking it: forcing every spawn
  onto CPU 0 produces three failures, and the gate goes red.
- **A page fault at `CR2 = 0` traced to segment-load semantics** — see M4 bug 2. The general lesson
  is that establishing per-CPU state is not one step: the identity is needed *before* the
  descriptor tables are built, and the `GS` base can only be set *after*, because building them
  destroys it.
- **`unsafe` budget for `bhaskix-kernel` raised 400 → 430**, with the reason recorded in
  `kernel/Cargo.toml` as the gate requires: an ordering-critical bring-up sequence where one
  `unsafe` block per step is what makes each ordering constraint documentable at the point it
  applies, plus the switch path's raw context pointers.

### 2026-08-03 (M4-05b and M4-11, per-CPU tables and shootdown)

- **Every CPU builds its own GDT, TSS and IST stacks.** Sharing them was not merely unwise, it does
  not work: `ltr` marks a TSS descriptor *busy*, so a second CPU claiming the same one faults. And a
  shared IST means two processors double-faulting at once land on the same stack and destroy each
  other's report — at exactly the moment the machine is least able to explain itself.
- **Secondaries now idle with interrupts enabled**, which is what makes them reachable at all.
  Halting with interrupts disabled — what they did before they had their own TSS — makes a CPU
  unable to answer anything, and any shootdown wait for it would spin until it gave up.
- **TLB shootdown works.** An IPI to all-but-self, with the sender waiting for every acknowledgement
  before returning, because the caller's next act is usually to free the frame. Negative-tested:
  disabling the receiving handler turns 8 completions into 8 timeouts.
- **Shootdown is skipped for address spaces no CPU has loaded**, which is a correctness observation
  before it is an optimisation: a translation can only be cached by a CPU that has run in that
  space. It is also what stops tearing down a thousand address spaces from costing a thousand
  rounds of IPIs.
- **A self-inflicted test bug worth recording.** `"timed out"` was added as a failure marker, and it
  matches the *success* message `"none timed out"` — so every passing run failed. Substring markers
  need to be checked against the strings they will actually see.

### 2026-08-03 (M4-05, CPUs online)

- **Secondary CPUs come online.** 1, 2, 4 and 8 all work; each claims a per-CPU area through an
  atomic and installs it as its `GS` base, so `gs:[0]` reaches different state on every processor
  with no lock and no lookup. The boot tests now run with four CPUs and assert N-of-N came online —
  asserting "more than one" would read as success on a machine that happens to be smaller.
- **The bootloader starts them.** Doing it by hand means a real-mode trampoline and an INIT/SIPI
  sequence with its own timing requirements; worth owning eventually, not before the kernel can use
  a second CPU for anything. The mechanism stays in `boot/shim` — the kernel receives a callback and
  never learns how a CPU is started.
- **They park, deliberately, and the tracker says why.** Shared GDT/TSS means shared IST stacks, the
  TLB shootdown gap is now a live bug rather than a theoretical one, and the scheduler assumes one
  CPU. Bringing CPUs up while being explicit that they idle is more honest than scheduling on them
  and finding all three in production.

### 2026-08-03 (M4, threads preempt)

- **Threads exist and the timer preempts them.** Real kernel threads, each on its own guarded stack,
  switched by `bhaskix_context_switch`. Three workers that never yield all made progress, which only
  the timer can have caused — negative-tested by removing the `preempt` call, which zeroes every
  counter.
- **One bug worth the whole exercise.** New threads started with interrupts disabled: a thread that
  has run before resumes through `iretq` and gets `RFLAGS` back, but a brand-new one is entered by a
  `ret` from inside an interrupt gate that cleared `IF`. The first thread scheduled therefore ran
  with interrupts off forever and the machine stopped — no exception, no triple fault, nothing to
  read. Found in QEMU's interrupt trace, which simply ended.
- **This is round-robin, not the fair scheduler**, and the tracker says so rather than letting the
  milestone name imply otherwise.

### 2026-08-03 (M3-13, KASLR — M3 complete)

- **KASLR works.** The kernel is now built as a position-independent executable, so the bootloader
  slides the image and fixes up its 403 relative relocations. Verified across boots: the base moved
  every time, and the boot test asserts a non-zero slide — losing KASLR otherwise looks identical to
  having it.
- **Two things had to change for it.** The exception table now stores self-relative offsets rather
  than absolute addresses, because an absolute address in a read-only section needs a dynamic
  relocation the linker refuses to emit there; Linux's table is built the same way for the same
  reason. And the link script gained an explicit `PT_DYNAMIC` segment — declaring PHDRS by hand
  means nothing is created implicitly, and the loader rejected the image with "ET_DYN, but
  PT_DYNAMIC segment missing" until it was added. A precise error message from Limine turned what
  could have been a long debugging session into a five-minute fix.
- **A fourth silently-failed patch.** The KASLR reporting edit matched nothing because rustfmt had
  rewrapped the surrounding `println!` — the same failure mode as three previous occasions. Caught
  by grepping for the new string rather than trusting the build.

### 2026-08-03 (M3-12, user access)

- **`copy_from_user` and `copy_to_user` land, with an exception table.** A fault at the copy
  instruction resumes at a recovery path and returns an error, so a hostile or simply wrong user
  pointer is ordinary input rather than a kernel defect. Negative-tested: disabling the table
  produces an unhandled page fault at exactly the address the test passes in.
- **SMEP and SMAP are enabled.** SMAP means a kernel access to a user page faults *even when the
  page is mapped*, so the copy routines bracket their access with `stac`/`clac` inside the assembly
  — the window is a few instructions wide and cannot be left open by an early return.
- **A range check, not just a fault check.** A user pointer aimed at kernel memory would otherwise
  succeed whenever that memory happens to be mapped, which is the confused-deputy bug the check
  exists to prevent; the fault handler cannot tell a kernel address the caller meant from one an
  attacker supplied.
- **Fixed a fault loop I had introduced.** The handler returned `Handled` for an already-present
  page, which retries the faulting instruction forever. SMAP makes that reachable, since a kernel
  access to a *mapped* user page faults and the mapping being there is what made it look
  serviceable.
- **The demand-paging test now goes through `uaccess`** rather than raw volatile writes, which is
  both required by SMAP and a better test — it proves demand paging works underneath a user copy.

### 2026-08-03 (M3 exit criterion met)

- **Demand paging and copy-on-write work**, which makes the region map authoritative in fact rather
  than only in structure: a fault consults the map, and demand paging and COW are the same mechanism
  reading different fields. Negative-tested by breaking the demand-paging arm, which produces an
  unhandled page fault instead of a quiet pass.
- **The kernel ran in an address space it built**, loading `CR3` for the first time. That closes the
  gap recorded when address spaces landed — until now the higher-half copy that keeps the kernel
  mapped had never been exercised.
- **The fault path uses `try_lock` throughout.** A fault can interrupt code already holding the
  allocator lock, and spinning there would hang the machine with no output; it reports an
  unserviceable fault instead. A limitation made visible rather than solved.
- **CI is green**, all nine jobs including every firmware/CPU combination. The OVMF pairing fix was
  correct.

### 2026-08-03 (published, CI live)

- **Pushed to `github.com/bhaskix/bhaskix`.** 9 commits, 93 files. Verified before publishing that
  no tooling files were tracked, that no vendor string appears anywhere in history rather than
  merely in the working tree, and that every commit is authored and DCO-signed by
  `tarunsoft1@gmail.com`.
- **`SECURITY.md` added**, because `docs/security.md` §9 promised a reporting channel that went
  public with no way to act on it. Written to be honest about the stage — it opens by stating the
  project has never been audited and must not be deployed — and includes a section on what is *not*
  a vulnerability yet, since this project documents its unfinished work openly and a report of a
  protection already tracked as unimplemented costs the reporter their time for nothing.
- **CI ran for the first time and found two real defects.** Details in §3.

### 2026-08-03 (M3, guarded stacks)

- **The M2 gap is closed.** The kernel switches off the bootloader's unguarded stack onto a 64 KiB
  stack with an unmapped guard page below it, and the `df` fault test now overflows it with real
  recursion rather than an artificial trigger. The report shows `rsp` at exactly the stack bottom
  and `cr2` 8 bytes into the guard page — the page fault cannot be delivered on the exhausted
  stack, so it escalates to a double fault, which IST1 catches and reports.
- **The guard is verified, not assumed**: boot asserts the guard page is genuinely unmapped and the
  stack genuinely mapped. If the address had happened to be mapped already, the "guard" would be an
  ordinary writable page and the mechanism would be a no-op that still printed success.
- **A patch silently failed to apply again** — the stack-switch block never landed because rustfmt
  had rewrapped the surrounding `println!`. The result booted and page-faulted with `cr2 = cr3 +
  0xa00`, because the handoff copy the switch was supposed to populate stayed zeroed. Second
  occurrence of this failure mode; the lesson stands that a clean build proves nothing about
  whether the code runs.
- **A test failed on its own wording**: the boot check matched `M1 complete` and broke when the
  banner said `M3`. Now milestone-agnostic.

### 2026-08-03 (M3, address spaces)

- **The M3 frame-leak gate passes**: 1000 address spaces created, mapped, translated through, and
  destroyed with the free-frame count returning to exactly its baseline. Negative-tested by removing
  the page-table teardown, which leaks 9 frames per cycle and fails the gate.
- **`Protection` makes W+X unrepresentable** — there is no variant for it, so the invariant is
  checkable by reading the enum rather than by auditing call sites. `EFER.NXE` is enabled before the
  first mapping and asserted at boot.
- **`RangeMap` is the source of truth**, with the page table as its cache, per `docs/memory.md` §3.
  14 host tests, including one checking the binary search against a linear scan across every address
  in a small space, and one asserting that whatever `find_free` suggests, `insert` accepts.
- **A deadlock avoided by design, and documented**: the region map is a `Vec`, so touching it
  allocates through the global allocator, which takes the heap lock the physical allocator lives
  behind. Region-map work therefore happens strictly outside that lock.

### 2026-08-03 (M3, kernel heap)

- **`alloc` works in the kernel.** Slab allocator over the buddy allocator, wired to
  `#[global_allocator]`; `Box` and `Vec` verified on real hardware paths in QEMU under both BIOS and
  UEFI, with a boot assertion that no frames leak.
- **Slab metadata lives in the frame database, not in the slab page**, as `docs/memory.md` §4
  requires: metadata sharing a page with the objects it describes can be corrupted by an overflow of
  those objects, and a corrupted free-list head hands the same memory out twice.
- **12 more host tests**, over a real page-aligned buffer so the pointer arithmetic is exercised
  rather than modelled — including a 20,000-operation mixed-traffic test that writes through every
  allocation to catch overlap, and asserts every slab page returns to the buddy allocator.
- **The `unsafe` budget now excludes test code**, which was distorting the number it exists to
  produce: the auditable surface of the kernel *as deployed*. `docs/coding-style.md` §3 updated, and
  the checker re-negative-tested to confirm it still catches unjustified blocks in shipped code.

### 2026-08-03 (M3, physical memory)

- **Buddy allocator and frame database landed.** Orders 0–10, DMA32 and Normal zones, free lists
  threaded through the frame database so coalescing is O(1) with no auxiliary allocation. 34 host
  tests in `mm`, including a 20,000-operation randomised property test asserting zero frame leakage
  and full coalescing.
- **Boot-time frame-leak self test** runs on every boot: 252 MiB managed on a 256 MiB machine, and
  the allocator returns to exactly its starting free count.
- **Two real bugs caught by the invariant checker and by reading the boot log** rather than by the
  compiler — the handover corruption and the split frame database. Both recorded in §3.
- **The `unsafe` checker was itself wrong** and is now negative-tested.

### 2026-08-03 (M2-08)

- **Interrupts are live.** Legacy PIC remapped and masked, Local APIC enabled, timer calibrated
  against PIT channel 2 and running at 100 Hz. Boot tests now assert *observed ticks* and `hlt`
  wakeup rather than merely that the enable code ran, on both BIOS and UEFI.
- **Both APIC paths implemented** — x2APIC via MSRs (no mapping needed, and required for >255 CPUs
  in M4) and xAPIC via MMIO. QEMU 4.2 forced the xAPIC path; see §3.
- **Bump allocator (M2-11) and a minimal page mapper (M2-13) landed early**, pulled forward because
  mapping the xAPIC register page was the only way to get a timer under this emulator. 9 host tests.
- **CPU feature reporting added** — the boot log now states which of the guarantees in
  `security.md` §4 the machine can actually provide, rather than assuming.
- **RFC 0004 drafted**: operational technology as the first deployment target.

### 2026-08-03 (later)

- **M2 exit criterion met.** GDT with IST stacks, IDT across all 256 vectors, uniform `TrapFrame`,
  and a decoding exception reporter. `tests/qemu/fault-test.sh` injects six fault types (#DE, #UD,
  #BP, #GP, #PF, #DF) and asserts each is reported with correct decoded detail and that QEMU logged
  no triple fault.
- **Three subtle bugs found and fixed** — `lateout` register aliasing, segment-limit encoding
  polluting the descriptor base, and Rust's overflow checks pre-empting the hardware #DE. Details
  in §3.
- **The panic handler is no longer unverified** — the first `de` test run reached it through Rust's
  divide-by-zero check and it printed correctly. That closes the M1-07 gap recorded yesterday.
- **RFC 0003 (storage architecture) drafted** — proposes a capability-scoped, Merkle-checksummed
  object store as the primitive, with POSIX as one personality among several, and a phased plan
  whose Phase 3 is the certifiable set rather than a distributed filesystem.

### 2026-08-03

- **M1 substantially complete: the kernel boots.** BIOS and UEFI, on Limine 8.7.0 base revision 3.
  Serial and framebuffer console both working; handoff validated; `make test` green end to end in
  ~80 s (fmt, clippy ×2, 17 host tests, 3 project gates, 2 boot tests).
- **Gates caught real defects on first run**, which is the point of having them: two `unsafe`
  blocks in `limine.rs` with no `// SAFETY:` justification, a missing SPDX header, and a
  self-referential flaw in the vendor-string checker.
- **Fixed a stale-image bug in the Makefile** found by negative-testing the boot test: `make iso`
  could rebuild the kernel without regenerating the ISO, so the boot test could pass against an old
  image. The ISO now depends on the phony build target and is always regenerated.
- **Boot test negative-tested** — deliberately broke the banner and confirmed the harness fails,
  then restored and confirmed it passes. A test that cannot fail is worse than no test.
- **`arch` unsafe budget set from measurement** (88 lines used, budget 95) rather than guessed.
- **Toolchain is stable Rust only** — no `#![feature]` anywhere; `docs/nightly-features.md` records
  the policy and the anticipated pressure points.

### 2026-08-02

- **Renamed VyomOS → Bhaskix** (N1, RFC 0002). 36 files, zero residual occurrences. Crate prefix is
  now `bhaskix-`/`bhaskix_`. Done at Phase 0 deliberately: no users, no contributors, nothing
  published — the same change after Phase 1 would have touched every fork and article.
  **Outstanding:** GitHub org handle and domain are not yet claimed, and no trademark search has
  been done. Both must happen before the first public push.
- **Toolchain verified working** — Rust 1.90.0 with `x86_64-unknown-none`, QEMU 4.2.1, xorriso,
  OVMF, and Limine v8.7.0 all installed and building.
- **A1 resolved: Apache-2.0.** `LICENSE` and `NOTICE` added; workspace manifest updated. External
  contributions can now be accepted. (RFC 0001)
- **M1 started.** Task breakdown M1-01 … M1-18 defined with exit criteria.
- **TRACKER.md created** as the single source of truth for project status.
- **Phase 0 design documents complete** — vision, architecture, memory, scheduler, security,
  driver-model, ai-native, coding-style, roadmap, repo-layout, RFC template.
- **Governance established** — benevolent-dictator model with written dissolution conditions at five
  maintainers. DCO, no CLA.
- **Repository initialised**; project structure created.
- **Founding decisions recorded** — D1 Rust, D2 Limine-behind-Handoff, D3 nucleus with relocatable
  services, D4 domains unify containers and VMs.
