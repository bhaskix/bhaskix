# RFC 0062: a thread may not run with a TLS base it did not set

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-09-01 — steps 1–4 built as of 2026-09-03.** The mechanism is proven end to end; the race it closes was **not** reproduced, so the fix is reasoned rather than demonstrated. Step 4's counters now make this RFC's own two readings separable, and the first thing they measured is that the handler loses the queue lock about 4% of the times it runs — see "What step 4 measured" |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel / scheduler |
| **Milestone** | Phase 2 — core operating system |
| **Depends on** | [RFC 0032](0032-a-supervisor-interface.md), [RFC 0033](0033-what-a-hosted-process-is.md) |

---

## Summary

`arch_prctl(ARCH_SET_FS, base)` can return successfully and leave the calling
thread running with a TLS base of **zero**. Its next `%fs:`-relative read then
faults at a small absolute address, and the program dies.

`sched::set_fs_base` already documents this window and counts it. This closes
it, with the IPI that comment names and defers.

## The window

The register is one per CPU. When the target thread is the **current** thread of
*another* CPU, this code may not write that CPU's `IA32_FS_BASE`, so it records
the base and lets it reach the register at that CPU's next switch. Between those
two points the thread runs in user mode with its old base — which, for a thread
that never had one, is zero:

```rust
BaseReach::FollowsAtNextSwitch => {
    FS_BASE_SET_ELSEWHERE.fetch_add(1, Ordering::Relaxed);
}
```

The comment beside it is explicit that this is deferred rather than solved:
*"Counting, not fixing: closing it means making the other CPU load the register,
which is an IPI and a design decision, not an edit."*

## The evidence

Seen first at `rip 0x500000a6` — `mov %fs:0x0,%rax`, four instructions after
`arch_prctl` — "once or twice in three hundred boots".

**And it is more expensive than that estimate.** On 2026-09-01 it was found to
be the whole of the `BusyBox's sh did not run -- the L1 corpus is absent or
refused` intermittent, which took **2 of 4 full `make test` runs** the previous
day. Two boots of the same lane, byte-identical for eight syscalls and then
diverging:

```
passing:  busybox  29 calls: 107 102 108 104 158 12 12 158 | 63 89 12 12 1 ...
failing:  busybox   8 calls: 107 102 108 104 158 12 12 158 | (nothing)
```

Call eight is `arch_prctl` (158). The failing boot alone logs `a hosted program
faulted at 0x48 (rip 0x404c96)` — `%fs:0x48` through a zero base — and alone
carries `linux tls  1 FS base(s) set for a thread running on another cpu`.

So the gate's message named the corpus and the corpus was never the problem.
**A harness that reports the wrong subsystem is how a scheduler race spent a
week filed under BusyBox.**

## What this changes

**Step 1 — the sender asks.** `set_fs_base`, on `FollowsAtNextSwitch`, sends
`RESCHEDULE_VECTOR` to the CPU running the target, using `notify`, which exists
and is already used to wake an idle CPU. The counter stays: it now measures how
often the IPI was needed rather than how often the window opened unattended.

**Step 2 — the receiver loads it, and this is the half that matters.** The
`RESCHEDULE_VECTOR` handler calls `preempt`, and `preempt` loads a base only
when it actually *switches*. A thread that is re-selected — the common case for
the only runnable thread on a CPU — would return to user mode with the stale
base and the window would be exactly as open as before. So the handler refreshes
the **current** thread's base from its record before scheduling.

**Step 3 — `try_lock`, and what a miss means.** The handler runs in interrupt
context on a CPU that may have been interrupted holding its own runqueue lock,
so it takes the queue with `try_lock`, as everything reachable from an interrupt
in this module does. A miss falls back to the old behaviour — the base arrives
at the next switch — which is strictly no worse than today.

**What was verified, and what was not — because the difference matters here.** With the branch forced and the load made unconditional, a boot reports `3 FS base(s) set for a thread running on another cpu; 1 loaded there by RFC 0062's IPI`. That proves the whole path: the IPI is delivered, the handler runs **on the target CPU**, it reads the current thread's recorded base, it loads it, and the counter moves. **What it does not prove is the fix**, because forcing the branch does not force the *condition*: with it forced, `notify` goes to a CPU whose current thread is not the target, so the handler correctly finds nothing to do. The real race — the target *is* the current thread there — did not occur in six unforced boots, which is consistent with "once or twice in three hundred". So this closes the window by construction and the demonstration is owed. The two counters are how it arrives: `elsewhere > 0` with `by_ipi > 0` is the fix working; `elsewhere > 0` with `by_ipi` still zero would mean the IPI is not arriving or the handler is losing the queue lock, and either is a bug in this RFC rather than a mystery.

**Step 4 — the gate.** A host test drives `base_reach` for the three cases;
the boot report gains the count of bases loaded by IPI, and `FS_BASE_SET_ELSEWHERE`
must stop being the last word on the window.

## What this does not do

- It does not make `arch_prctl` synchronous. The base is in the register before
  the thread next runs in user mode, which is what correctness needs; it is not
  necessarily there when the syscall returns to the *caller*, which is a
  different thread.
- It does not touch `LoadedHere` or `NotRunning`, which were already correct.
- It adds an IPI to a path that runs once or twice per hosted process start.
  That is the price, and it is paid only when the target is running elsewhere.


---

## What step 4 measured (2026-09-03)

Step 4 asked for the boot report to gain the count of bases loaded by IPI, and for
`FS_BASE_SET_ELSEWHERE` to "stop being the last word on the window". It had one number, and this
RFC's own text names two readings behind it:

> `elsewhere > 0` with `by_ipi` still zero would mean the IPI is not arriving or the handler is
> losing the queue lock, and either is a bug in this RFC rather than a mystery.

Nothing distinguished them, so that sentence could not be acted on. Two counters now do:
`contended` when `refresh_fs_base_here` cannot take this CPU's runqueue lock, and `idle` when it
runs with no base to load — the ordinary case, because `RESCHEDULE_VECTOR` is shared and the
handler runs for every reschedule. `by_ipi == 0` therefore reads three ways: `contended` up means
the handler arrives and loses the lock; `idle` up with `contended` zero means it arrives and finds
another thread current; both zero means the IPI never reached the CPU.

**The measurement.** On an unforced boot the line does not print at all — `elsewhere` is zero, so
the window never opened, which is consistent with "once or twice in three hundred boots". Forcing
every `set_fs_base` to take the `FollowsAtNextSwitch` path, as this RFC's earlier verification did,
gives:

```
linux tls      3 FS base(s) set for a thread running on another cpu; 0 loaded there by RFC 0062's
               IPI rather than waiting for a switch (177 lost the queue lock, 4410 had nothing to
               load)
```

**177 losses in 4,587 handler runs — about 3.9%.** That is the second reading, measured for the
first time.

**What follows, and what does not.** Step 3 says a miss "falls back to the old behaviour — the
base arrives at the next switch — which is strictly no worse than today", and that remains true:
this is not a regression, and the fix is still an improvement on every attempt that lands. What is
now known is that it is **not airtight** — roughly one attempt in twenty-five is expected to be
dropped by `try_lock`, so the window this RFC closes "by construction" is closed about 96% of the
time rather than always.

Two limits on that number, stated rather than left for a reader to find. It was taken with the
branch forced, so the three `set_fs_base` calls are not themselves the population; and the handler
runs on every reschedule, so 4,587 is dominated by ordinary IPI traffic rather than by base-carrying
ones. The 3.9% is therefore the handler's general lock-loss rate, and applying it to a base-carrying
IPI is an inference from that rate, not a direct measurement of one.

**The next step this suggests, unimplemented.** Making the load not depend on winning a lock — a
per-CPU pending-base slot the interrupt-return path can consume without taking the runqueue — would
close the remaining 4%. That is a design change rather than a constant, and it is named here so it
is a known cost rather than a surprise.
