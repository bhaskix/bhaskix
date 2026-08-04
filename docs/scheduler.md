# Bhaskix — Scheduler

*Status: draft for review. Prerequisite reading: [architecture.md](architecture.md).*

The scheduler decides which thread runs on which CPU, and for how long. It is designed for a machine
that is simultaneously running latency-sensitive services, batch compute, containers, and virtual
machine vCPUs — because in our design ([architecture.md](architecture.md) §4) those are all just
threads in domains.

---

## 1. Requirements, in priority order

1. **Correctness under SMP.** No lost wakeups, no runnable thread stranded off a runqueue, no
   priority inversion that can deadlock the system.
2. **Bounded latency for the RT class.** A real-time thread's wakeup-to-run latency must be bounded
   and measurable, or the hypervisor and edge editions are not viable.
3. **Fair sharing between domains**, not just between threads. A domain with 100 threads must not
   out-schedule a domain with 1.
4. **Predictable, explainable decisions.** Every scheduling decision must be attributable — this is
   what makes [ai-native.md](ai-native.md) possible and what makes debugging possible.
5. **Throughput.** Last, deliberately. Throughput work follows measurement.

---

## 2. Structure

### Per-CPU runqueues with work stealing

```rust
pub struct Cpu {
    id: CpuId,
    rt:       RtRunqueue,        // fixed priority, 0..=99
    fair:     FairRunqueue,      // virtual-deadline tree
    batch:    BatchRunqueue,     // FIFO, only runs when nothing else can
    idle:     Thread,
    current:  *mut Thread,
    lock:     SpinLock<()>,      // rank: Rank::SchedRunqueue
    load:     AtomicU64,         // published for the balancer, read without the lock
}
```

A single global runqueue is simpler and does not scale past about four CPUs. Per-CPU queues with
stealing is the design that works; we start there rather than migrating later.

> **Implemented, in part, as of M4-06.** `kernel/src/sched.rs` has one lock-per-CPU runqueue, and a
> thread is *owned* by the CPU whose queue holds it. That ownership is what makes the switch path
> sound on more than one processor: a CPU takes raw pointers to contexts in its own queue only, so
> there is no cross-CPU sharing to race against rather than a race that is prevented. What exists is
> the RT and Fair classes in strict priority with an Idle class beneath them, as of M4-07 — but no
> Batch class, and Fair is a linear scan over a fixed array rather than an augmented tree, because
> at eight threads per CPU an `O(n)` scan beats an `O(log n)` structure that would have to allocate.
> Idle pull (§5.2) landed at M4-06b; the rest of §5 is unbuilt. Threads block and wake as of M4-09.
> A wake on the *waking* CPU hands over immediately; a wake to another CPU sends no IPI, so it waits
> for that CPU's next tick — up to 10 ms, against the §4 target of 50 µs.

### Strict class priority

```
RT        ── runs if any RT thread is runnable. Always.
  ↓
Fair      ── the default class. Virtual-deadline ordering.
  ↓
Batch     ── runs only when Fair is empty.
  ↓
Idle      ── halts the CPU (MWAIT / HLT), enters the tickless path.
```

Strict priority between classes, not weighted. An RT thread starving a Fair thread is *the intended
behaviour*; the mitigation is admission control on RT (a bounded RT utilisation budget per CPU),
not softening the priority rule.

---

## 3. The Fair class

Virtual-deadline scheduling (EEVDF-family), not round-robin and not plain vruntime.

Each runnable thread has:

- `vruntime` — service received, scaled by weight (from nice / domain share).
- `deadline` — `vruntime + slice/weight`. The thread with the earliest deadline runs.
- `lag` — how much service the thread is owed relative to its fair share.

Why this rather than CFS-style pure vruntime: a virtual deadline lets a thread declare that it needs
*small* slices *soon* (interactive) versus *large* slices *eventually* (compute), without the
scheduler having to guess from behaviour. `latency_nice` is a first-class per-thread property rather
than a heuristic inferred from sleep patterns. Inferred interactivity heuristics are exactly the kind
of thing that works on the developer's machine and fails in production.

Ordering structure: an augmented red-black tree keyed by deadline, with min-lag tracking. `O(log n)`
pick, `O(log n)` insert.

> **Implemented, in part, as of M4-07.** `vruntime` and `deadline` exist and behave as described:
> service is scaled by weight, the earliest deadline runs, and a thread asking for a *shorter* slice
> earns an earlier deadline and so runs sooner and more often for the same total share — which is
> the property that distinguishes this from picking the smallest `vruntime`, and it is unit-tested.
> Measured weight ratio at 3:1 is 2.7x–3.1x on an emulated four-CPU machine.
>
> **`lag` is not implemented, and eligibility with it.** In its place is a cruder bound: a thread may
> not get more than eight slices of virtual time ahead of its runqueue's clock. That bound is not
> tidiness — proportional share alone has no limit on the lead, and a thread that once ran alone can
> be so far ahead that a group of threads which each run for microseconds before blocking never lets
> it run again. It presented as a hung machine.
>
> **No red-black tree, deliberately.** With `MAX_THREADS_PER_CPU = 8` a linear scan is faster than a
> tree and allocates nothing, which the switch path requires. The tree becomes right when the queue
> becomes heap-backed; until then it would be cost with no benefit.
>
> **No domain level.** §3's two-level runqueue needs domains, which arrive in M5. Fairness today is
> between threads only, so a domain that spawns more threads still gets more CPU — exactly what the
> two-level structure exists to prevent.

### Domain-level fairness

Threads do not compete directly across domain boundaries. The runqueue is **two-level**:

```
CPU
 └─ domain entities, ordered by domain weight and domain vruntime
     └─ threads within a domain, ordered by thread deadline
```

Picking a thread means picking a domain entity, then picking within it. A domain's CPU share is set
by its `ResourceEnvelope` and is honoured regardless of how many threads it spawns. This is cgroup
CPU control, present from the first version rather than grafted on — because containers are a
first-class concept, not an add-on.

---

## 4. The RT class

- Fixed priorities 0–99, higher wins.
- `FIFO` (runs until it blocks or yields) and `RR` (runs until it blocks, yields, or exhausts its
  quantum) policies.
- **Priority inheritance on kernel locks.** A low-priority thread holding a lock an RT thread wants
  temporarily inherits the RT priority. Without this, unbounded priority inversion makes the latency
  bound a lie.
- **Admission control:** total RT utilisation per CPU is capped (default 95%). Exceeding it fails the
  scheduling-parameter syscall rather than hanging the machine. The remaining 5% guarantees that
  Fair-class threads — including the ones that would let an operator log in and fix things — still
  run.

**Latency budget, to be measured and enforced by a test, not asserted:** wakeup-to-run for the
highest-priority RT thread on an otherwise busy machine, target < 50 µs at the 99.9th percentile.
The QEMU test suite measures this on every PR and fails on regression. A number nobody measures is
a number nobody meets.

> **Implemented, and over budget, as of M4-07.** Fixed priorities, `FIFO` and `RR`, and admission
> control at 95% are all in and unit-tested; a request that would exceed the cap is refused rather
> than accepted and then missed. Real-time threads are also excluded from work stealing, because
> admission control is per-CPU and migrating one invalidates the budget at both ends.
>
> **Measured worst-case wakeup-to-run is 120–500 µs**, against the 50 µs target — reported at every
> boot rather than quietly omitted. Two known reasons, in order of size: this is QEMU's TCG
> interpreter on a shared build machine, which is not a latency measurement of anything real; and a
> wake to a *different* CPU still waits for that CPU's tick because there is no reschedule IPI
> (M4-09b). The figure is recorded as a regression baseline, not as a claim to have met the budget.
>
> **Priority inheritance is not implemented**, so the §4 statement that its absence makes the
> latency bound a lie currently applies. It needs a lock that has an owner and can sleep; the
> spinlocks here have neither.

---

## 5. Load balancing

Runs periodically and on wakeup, cheapest option first:

1. **Wakeup placement.** Prefer the CPU where the thread last ran (cache-warm), unless it is busy and
   an idle sibling shares the LLC. Topology comes from ACPI/CPUID: SMT sibling → same LLC → same NUMA
   node → other node, in that order of preference.
2. **Idle pull.** A CPU entering idle steals from the busiest CPU in its domain before halting. This
   is where most balancing should happen — it is free, since the CPU had nothing to do.
3. **Periodic push.** A timer-driven pass that corrects imbalance the above missed, at a coarse
   interval (default 100 ms per scheduling domain level). Deliberately infrequent: aggressive
   periodic balancing destroys cache locality and burns CPU proving it is busy.

Migration cost is charged: a thread is not migrated unless the estimated imbalance improvement
exceeds its measured migration cost. NUMA migrations are charged much more than LLC-local ones.

> **Implemented, in part, as of M4-06b.** Idle pull (2) exists: a CPU whose queue holds nothing but
> the thread already on it takes one from a CPU with at least two more, and creation places a thread
> on the least-loaded CPU, which is a crude stand-in for (1). Nothing pushes, nothing runs
> periodically, and nothing knows the topology — there is no ACPI parsing yet, so every CPU is
> equidistant and a steal is as likely to cross a socket as to stay on one. Migration cost is not
> measured and therefore not charged; the only brake is the imbalance threshold below.
>
> **Why the threshold is two and not one.** At one, a CPU with a single thread would take from a CPU
> with two, leaving two and one — and the victim, now the lighter of the pair, would take it back on
> its next tick. The thread would spend its life migrating instead of running. Requiring a gap of
> two means a move leaves the pair no more unbalanced than it found them. This is the whole of the
> convergence argument today, which is why it is unit-tested rather than left to a comment.
>
> **What makes a steal safe.** Moving a thread is moving *ownership*: it leaves the victim's queue
> and enters the thief's, under one lock at a time, and afterwards is owned by the thief exactly as
> if created there. Three rules keep that true, and each is unit-tested by removing it — only
> `Ready` threads move (a `Running` thread's context is the stack the victim is standing on); never
> from a CPU partway through a switch (a thread is marked `Ready` *before* its registers are saved,
> and the lock is released in between); and never the thread a CPU booted on. The victim's lock is
> taken with `try_lock`, so two CPUs that pick each other both fail rather than deadlock.

---

## 6. Context switching

The switch itself is assembly (`arch/x86_64/asm/switch.S`). It:

1. Saves callee-saved registers and RSP into the outgoing `Context`.
2. Switches the kernel stack.
3. Switches `CR3` if the address space differs (with PCID, without a full flush).
4. Restores callee-saved registers and RSP from the incoming `Context`.
5. Returns into the new thread.

Deliberate design points:

- **Caller-saved registers are not saved.** The compiler already spilled anything live across the
  call. Saving them is wasted work — a mistake many hand-written switchers make.
- **FPU/SSE/AVX state is switched lazily** via `CR0.TS` / `XSAVE`, not eagerly. AVX-512 state is
  2.5 KiB; switching it on every context switch for threads that never touch it is a large,
  invisible cost.
- **The switch path allocates nothing and can take no locks that may sleep.** Enforced by type.
- **Kernel stacks have guard pages.** Stack overflow in the kernel becomes a clean panic with a
  backtrace instead of silent corruption of whatever was allocated below.

---

## 7. Timers and ticklessness

- Per-CPU deadline timers via the local APIC in TSC-deadline mode where available.
- **Tickless when a single thread is runnable** and no timer is pending: no periodic interrupt at
  all. This matters for VM domains (a ticking guest wastes host CPU across every idle VM) and for
  edge/battery devices.
- A hierarchical timer wheel for the many-short-timers case; a per-CPU binary heap for the
  few-precise-timers case. Both, because network stacks and RT threads have opposite profiles.
- `CLOCK_MONOTONIC` from TSC with invariant-TSC detection, falling back to HPET. TSC
  synchronisation across sockets is verified at boot and the fallback is taken if it fails, rather
  than assumed.

> **Implemented, in part, as of M4-10.** The APIC timer is **one-shot**, re-armed after every
> interrupt for exactly as long as the next thing that needs attention — the slice of the running
> thread, or the soonest pending timer, whichever is sooner. Ticklessness is not layered on top of
> that; it is what a one-shot timer does when asked for nothing. Measured: **0 timer interrupts over
> 400 ms** with the machine idle, against 320–483 with every CPU busy.
>
> **A tickless CPU can only be woken by an interrupt**, so this required the reschedule IPI first —
> and then a second fix, because *spawning* a thread on an idle CPU also has to poke it. Missing
> that presented as three worker threads that never ran. The rule is now explicit: every operation
> that makes a thread runnable on another processor must say so.
>
> **An idle CPU is still armed once a second.** Strictly it needs no interrupt at all, but that
> assumes every present and future path that makes a thread runnable remembers the IPI. The backstop
> costs nothing and turns the worst failure this design has — a silently lost thread — into "that
> thread ran late".
>
> **No hierarchical timer wheel**, because there is no network stack to give it a shape. What exists
> is §7's few-precise-timers case: a small per-CPU array, scanned linearly, allocating nothing. **No
> TSC-deadline mode**, **no HPET fallback**, and **no cross-socket TSC verification** — every reading
> is compared only against another from the same CPU, and that assumption must be revisited before
> any timestamp crosses a CPU boundary.
>
> **The tick is no longer a clock.** It counts timer interrupts delivered, which stopped being
> proportional to elapsed time. Anything measuring duration now reads the TSC.

---

## 8. The policy hook

This is the scheduler's contribution to [ai-native.md](ai-native.md), and the boundary is strict.

```rust
pub trait SchedPolicy: Send + Sync {
    /// Called with the set of candidate CPUs the scheduler has already
    /// determined to be LEGAL for this thread. May reorder. May not extend.
    fn rank_placement(&self, t: &ThreadSummary, candidates: &mut [CpuId]);

    /// Suggest a time slice within [min, max] the scheduler already computed.
    /// Values outside the range are clamped, not honoured.
    fn suggest_slice(&self, t: &ThreadSummary, bounds: SliceBounds) -> Duration;

    /// Predict how long this thread will run before blocking. Advisory only —
    /// used to improve placement, never to preempt early or late.
    fn predict_runtime(&self, t: &ThreadSummary) -> Option<Duration>;
}
```

The rules, which are the whole point:

- The policy **never sees a candidate the scheduler did not already approve.** It cannot place a
  thread on a CPU excluded by affinity, isolation, or a domain's envelope.
- Every returned value is **clamped to bounds the scheduler computed**. A malicious or broken policy
  can make the system slow. It cannot make the system incorrect or unfair beyond the envelope.
- The policy **runs in the calling context with a hard time budget** (default 2 µs). Exceeding it
  disables the policy, logs the event, and reverts to the default heuristic — permanently, until an
  operator re-enables it.
- **The default policy is a real, complete heuristic**, not a stub. The AI policy is an optimisation
  over a system that already works. If the AI subsystem never ships, the scheduler is still good.

---

## 9. What we are explicitly not doing (yet)

- Gang scheduling for vCPUs. Needed eventually for VM domains (lock-holder preemption is a real
  problem); deferred to Phase 3 with the rest of virtualization.
- Energy-aware scheduling / big.LITTLE. Needed for the edge and embedded editions on AArch64. The
  scheduling-domain hierarchy is designed to accommodate it; no code yet.
- Deadline (EDF) class for hard real-time. The RT class covers soft real-time. EDF is additive.

---

## 10. Testing strategy

| Property | Test |
|---|---|
| No lost wakeups | **Implemented at M4-09**, though not yet at this scale. Four threads pass a token round a ring spanning every CPU, sleeping on a wait queue for their turn; a single lost wakeup stops the ring dead rather than slowing it. The gate requires every station to have run, and requires non-zero sleep *and* wake counts, so a ring that spun instead of sleeping fails. Negative-tested: disabling `wake` gives laps `[1,1,1,0]` and zero wakeups. The 10⁷-iteration IPC version waits on IPC. |
| No stranded threads | Invariant checker in debug builds: every non-running runnable thread is on exactly one runqueue. |
| Fairness | Two domains with a 3:1 weight ratio, each CPU-saturating; assert measured CPU time is 3:1 ± 2%. |
| Domain fairness vs thread count | Domain A with 1 thread vs domain B with 64, equal weight; assert 1:1 split. |
| RT latency | Cyclictest-equivalent under load; assert p99.9 < 50 µs. |
| Priority inversion | RT thread blocks on a lock held by a Fair thread while a mid-priority thread spins; assert bounded latency. |
| Policy containment | A deliberately hostile `SchedPolicy` (returns garbage, sleeps, panics); assert the system stays correct and the policy is disabled. |
| Lock ordering | **Implemented at M4-08.** Ranks declared at construction, checked on every blocking acquisition; the boot test requires zero violations across ~7,400 checked acquisitions, and the check itself is verified by provoking a deliberate inversion. The runqueue lock ranks *inside* the heap — see `kernel/src/sync.rs`. |

The fairness and latency tests produce numbers that are recorded per-commit. Regressions are a
failing build, not a discussion.

Of that table, **none** is running yet: every row needs blocking, IPC, or a scheduling class, and
none of those exist. What the boot test does check, at `-smp 4`, is the one property this milestone
actually claims — that each worker thread ran on the CPU it was created on, and that the timer
preempted it there. The test was verified by breaking it: forcing every thread onto CPU 0 makes it
fail, which is what distinguishes a per-CPU runqueue from a global one that happens to work.

A second boot assertion covers balancing, and deliberately requires the opposite: every thread is
created on CPU 0, and at least one must end up elsewhere. The two are not in tension — the first
runs one thread per CPU, where there is no imbalance to correct. A kernel that pinned threads
forever passes the first and fails the second; one that scattered them at random does the reverse.

The steal *policy* is unit-tested rather than boot-tested, because every rule in it is invisible
when broken: dropping the pinned check does not fail a boot, it strands a CPU minutes later when its
queue happens to drain. Each rule has a test that fails when that rule alone is removed.
