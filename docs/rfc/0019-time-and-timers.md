# RFC 0019: Time, and a deadline a program can be woken by

| | |
|---|---|
| **Status** | ✅ **Accepted 2026-08-14**, with all four steps implemented: the deadline table, `ARM`/`DISARM` and expiry, `bin/dhcp` waiting on a duration instead of a loop count, and the measurement. **Its open question 2 was answered against it and then closed by fixing it.** The measurement found that the deadline had no effect on the wake instant at all — nothing re-programmed the timer when one was armed — and `ARM` now does, which took a 20 ms deadline from 150–193 ms to 20.3 ms. Both the finding and the fix are recorded under question 2 rather than edited into a document that always knew. Questions 1 and 3 stay open, and 1 is sharper for this. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (`notify`, `time`, `syscall`) |
| **Milestone** | Phase 2 — required before TCP (RFC 0020), and before any service that must give up waiting |
| **Depends on** | [RFC 0008](0008-syscall-and-ipc-shape.md), [RFC 0010](0010-notifications.md) (both halves of it, as of 2026-08-13) |

---

## Summary

A program can arm a **deadline on a notification it holds**, and be woken when the deadline passes.
No new object, no new blocking primitive, no new syscall kind: `Invoke(notification, ARM, deadline)`
asks the kernel to signal that notification later, and the program is woken through the machinery
RFC 0010 already built — a bound notification and a blocking `Recv` that returns `NOTIFIED`.

## Motivation

**Nothing in this system can wait for a length of time.** There is no sleep, no timed receive, no
deadline, and no timer object. A program can block for ever on an endpoint, or spin. That is the
whole list.

This has already cost real work, three times, and each cost is in `TRACKER.md` rather than
hypothetical:

- **`bin/dhcp` cannot wait for a reply.** It polls with a yield between looks, and its patience is a
  loop count tuned by experiment — 400 was too few, a million was too many and made the shell test
  time out. A client waiting for a server it cannot hurry is the plainest possible use of a timer.
- **`bin/ipd` cannot give up.** RFC 0018's step 5 asks what a socket does when nothing answers, and
  the answer today is that the *caller* counts loop iterations.
- **A service that hangs cannot be told from one that is waiting.** RFC 0018's open question 4 says
  this in full and calls it "the worst subsystem to have it in", because a stack is the first thing
  with a legitimate reason to be slow. Every proposal for a fix begins with a deadline.

**And TCP cannot be written at all.** Retransmission needs a measured timeout, a close needs
`TIME_WAIT`, an acknowledgement may be delayed and a zero window must be probed. Four timers before
any argument about congestion control. That is what makes this RFC first and TCP second, rather than
a section inside it.

**`M4-10b` is waiting for the same thing from the other side.** The hierarchical timer wheel is
`TODO` with the reason *"a wheel needs a many-short-timers workload to have a shape; there is no
network stack"*. This RFC creates the workload. It does not build the wheel.

## Design

### Reading time is already ambient, and that is not a decision this RFC gets to make

`rdtsc` is readable at every privilege level unless `CR4.TSD` is set. This kernel does not set it —
`CR4` is `0x300020`: PAE, SMEP, SMAP, and no TSD — and `arch/x86_64/src/tsc.rs` says so where the
instruction is used.

So **a program can already read a monotonic counter without holding anything.** Designing a `Clock`
capability would be ceremony around an instruction any program can execute, and would read as
authority the system does not actually control. It is stated here so that a later reader does not
mistake its absence for an oversight.

What a program *cannot* do is be **woken**. That is the scarce thing, because it costs the kernel a
timer and a wake, and it is what this RFC hands out.

### A deadline is a property of a notification, not a new kind of object

```
Invoke(notification, ARM,    deadline)   ← signal this notification at that time
Invoke(notification, DISARM, 0)          ← never mind
```

`deadline` is an absolute value on the same monotonic scale `rdtsc` reads, so a program computes it
from a clock it already has and there is no unit to disagree about. Relative durations are a
convenience the caller can compute; absolute deadlines are what survives being descheduled between
reading the clock and arming.

**No new object kind**, and that is the same finding RFC 0018 step 5 made about sockets: the thing
being asked for is a *property of a capability the program already holds*, not a new type. A
notification is already "something that can be signalled and waited on"; this adds "…and the kernel
will signal it for you at a time you name".

**The bits are the badge**, exactly as `SIGNAL`. A receiver waiting on one notification can tell a
timer firing from a frame arriving because they carry different bits, which is RFC 0010's
badge-as-bitmask used for its purpose a second time.

**Rights: `WRITE`**, the same right `SIGNAL` needs, and for the same reason — arming causes a signal.
A capability with only `READ` may wait on a notification and cannot arm it, so a service can hand a
client something that can be woken without handing it the ability to schedule wakes.

### One deadline per notification

A second `ARM` **replaces** the first. This is the opposite of the second-waiter rule and the
difference is deliberate: two waiters want two wakes and only one can have it, whereas re-arming is
how every timer user in practice expresses "not then, this instead".

A service needing many timers — TCP will need one per connection, at least — keeps its own ordered
list and arms the **nearest** deadline. That is what a timer wheel does internally, and doing it in
the service first is what gives `M4-10b` a shape to be designed against rather than guessed at.

### How a program actually waits

Nothing new. The thread binds the notification (RFC 0010's question 1, answered 2026-08-13) and
blocks in `Recv` on its endpoint. The kernel signals the notification when the deadline passes;
`Recv` returns `NOTIFIED` with the badge word. A service therefore handles callers, arriving frames
and expiring timers **in one loop, with one blocking call** — which is the shape the whole of
RFC 0010 was arguing towards.

### In the kernel

`kernel/src/time.rs` already has what is needed: `now()`, `now_nanos()`, `wake_at(deadline)`,
`cancel_wake()` and a tickless per-CPU deadline. What does not exist is the association between a
deadline and a *notification*, and the pass that signals expired ones.

- A fixed table of armed deadlines, sized like every other table this system exposes to something it
  does not control. Full is a refusal, not an allocation.
- Checked where the timer interrupt already runs. The signal path is `notify::signal`, which is
  lock-free and safe from interrupt context — the property RFC 0010 built it for and the reason this
  RFC needs no new wake machinery.
- Cleared when the notification is destroyed or its owning domain ends, alongside the existing
  `unbind_thread`.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **A `Timer` object kind** | A new object, a new arena, new revocation rules, and a second thing to hold — to express a property a notification can carry. RFC 0018 step 5 made exactly this mistake about sockets and the kernel gained nothing when it was undone. | A timer needed authority a notification does not have — for example if arming ever had to name a *different* notification than the caller holds. |
| **A timed `Recv`** | Puts a duration in the blocking primitive every service depends on, so every caller pays for a concept most do not use, and the timeout is then per-call rather than per-purpose. It also cannot express a timer that fires while the thread is doing something else. | Measurement showed the arm/disarm pair costs more than a deadline argument in the common case. |
| **A `sleep` syscall** | Blocks the thread and nothing else, so a service cannot sleep and serve. That is the two-thread answer RFC 0010's question 1 already rejected for want of a second thread. | Never, for services. It would be defensible for a program that only sleeps. |
| **Relative durations rather than absolute deadlines** | A duration read before being descheduled becomes a lie. Absolute deadlines are what survive preemption between reading the clock and arming. | The clock were not readable from ring 3, which today it is. |
| **A `Clock` capability for reading time** | `rdtsc` is unprivileged on this machine; the capability would guard nothing. | `CR4.TSD` were set, which would be a separate decision with its own costs. |

## Impact on existing design documents

- **[rfc/0010-notifications.md](0010-notifications.md)** — its notification gains a third operation.
  Its "Unresolved questions" gain nothing: this is additive, and its question 1 is what makes the
  waiting side work.
- **[docs/scheduler.md](../scheduler.md)** — gains a user-visible source of wakes. `M4-10b`'s entry
  in `TRACKER.md` says a timer wheel wants a many-short-timers workload; this RFC is where that
  workload comes from, and the entry should say so rather than continuing to say none exists.
- **[roadmap.md](../roadmap.md)** — no bullet changes. This is machinery under the networking bullet
  rather than a bullet of its own.

## Security implications

**New authority: the ability to be woken later.** It is narrow — a holder can schedule a wake for a
notification it already holds and nothing else — and it is `WRITE`-gated, so a read-only holder
cannot arm.

**A new denial of service, and it is the honest risk here.** A program that arms a deadline one tick
away, repeatedly, is a spin with the kernel's timer in the loop. It cannot reach another domain's
notification, so the damage is bounded to the processor it is on — which is the same bound a plain
spin already has, and this system has shipped two of those by accident. The refusal to design is
stated in the open questions rather than pretended away.

**No new parser, and no new reachable-without-a-capability surface.** A deadline is a number the
caller supplies and the kernel compares; there is nothing to parse and no fuzz target.

## Performance implications

The kernel is already tickless and already arms a per-CPU deadline. The cost is one more reason to
arm one, and a scan of a small fixed table where the timer interrupt already runs.

**What to measure**: the delay between a deadline and the wake, at a few durations, reported as a
distribution rather than a mean — `report_service_cost` in `kernel/src/lib.rs` records why a mean is
the weaker statistic for anything a scheduler can preempt.

**Measured at step 4**; the numbers and what they mean are under unresolved question 2, because they
answer it. One warning belongs here, for whoever measures this next. A measuring loop that arms its
next deadline the moment the last one fires is arming *inside the expiring tick's own handler*,
before that handler reaches `rearm` — which then finds a deadline waiting and programs the hardware
for it exactly. The first version of this measurement did that and reported a median lateness of
0.1 ms on a machine ticking every 100 ms, which is not a number that can happen: fourteen samples in
sixteen cannot each land in a 0.2 ms window by chance. It was measuring the loop, not the timer. The
measurement now waits a growing interval before each arm, so the arrivals are spread over the phase
of the machine's own timers instead of locking to one point in it.

## Testing plan

- **Host**: the deadline table — arming, replacing, disarming, expiry ordering, and a full table
  refusing rather than allocating. No kernel needed.
- **QEMU**: a program arms a deadline, blocks in `Recv`, and is woken **after** it and not before.
  Both halves matter: a timer that fires early is a bug that looks like success.
- **Watched failing**: disarm and confirm no wake arrives; arm from a `READ`-only capability and
  confirm `InsufficientRights`; let the owning domain end with a deadline armed and confirm nothing
  is signalled afterwards.
- **No fuzz target**, and the security section says why.

## Unresolved questions

1. **Is a minimum deadline enforced, and by what argument?** A floor stops the tightest re-arm loop
   and is also a limit on what the system can express. Deferred until something needs a short timer,
   because a number chosen now would be chosen without a caller.
2. **What resolution is promised?** This RFC promises only "not before the deadline", which is the
   half correctness depends on.

   **Measured at step 2, and the number was bad: a deadline armed for 20 ms fired after 142–173 ms.**
   Expiry runs on the timer interrupt, and arming from a system call does not re-program the
   hardware, so a deadline waits for a tick that was going to happen anyway. Folding the soonest
   armed deadline into the tickless re-arm decision was necessary and not sufficient — `rearm` itself
   only runs *on* a tick.

   **Measured properly at step 4, and the shape is worse than one number could show.** Sixteen
   samples at each of five durations, on a four-processor QEMU machine, run twice — during bring-up
   and again with the services up (`make iso CMDLINE=timers=measure`):

   ```
     0.100 ms deadline: late by 282.503 / 328.029 / 372.759 ms (min/median/max), 16 samples
     1.000 ms deadline: late by 279.949 / 325.155 / 367.769 ms
     5.000 ms deadline: late by 277.159 / 324.757 / 361.815 ms
    20.000 ms deadline: late by 263.203 / 306.999 / 347.603 ms
   100.000 ms deadline: late by 181.407 / 226.033 / 268.388 ms
   ```

   **The lateness is not a cost, it is the deadline being ignored.** Read down the column: as the
   deadline grows by 100 ms the lateness falls by 102 ms. The form is `lateness ≈ C − d`, with `C`
   around 330 ms — which is to say the **wake instant is the same instant whatever the deadline
   was**. A program asking for 0.1 ms and a program asking for 100 ms are woken together.

   `C` is then no mystery. Over the 26 seconds of the measurement the timer was armed for a computed
   deadline **zero** times: every interrupt on the machine was an idle CPU's `IDLE_BACKSTOP_MS`
   one-second backstop, four of them staggered, giving one tick somewhere every 250–330 ms. The
   promise this RFC can honestly make today is therefore **"not before the deadline, and before the
   backstop"** — one second, not one anything-else.

   Step 2's fold of `earliest_deadline` into `rearm` is weaker than "not sufficient": in this regime
   it never runs. `on_tick` expires the deadline before calling `rearm`, so by the time `rearm` asks
   what is armed, the answer is nothing.

   Closing the gap means the `ARM` path re-programming this processor's timer when the new deadline
   is sooner than what it is armed for. That is a small change in an interrupt-adjacent path, and it
   is exactly the workload `M4-10b`'s wheel is waiting for. **Step 4's measurement is what justifies
   it**, and the justification is not the median: it is that the deadline currently has no effect on
   the wake at all.

   **Done, 2026-08-14.** `time::arm_no_later_than` brings this CPU's next interrupt forward when the
   deadline just armed beats what it was going to fire for, and the `ARM` system call calls it. The
   same measurement, three runs:

   ```
     0.100 ms deadline: late by 0.032 / 0.065 / 0.089 ms (min/median/max), 16 samples
     1.000 ms deadline: late by 0.064 / 0.087 / 0.133 ms
     5.000 ms deadline: late by 0.097 / 0.134 / 0.183 ms
    20.000 ms deadline: late by 0.100 / 0.143 / 0.184 ms
   100.000 ms deadline: late by 0.114 / 0.150 / 0.192 ms
   ```

   **`C − d` is gone**, which is the result rather than the medians: the lateness now *grows* with
   the deadline instead of shrinking by exactly what the deadline gained, so the wake instant is the
   deadline's rather than the machine's. About **2,000× better at the median**, and the worst sample
   across three runs is 0.819 ms against a previous median of a third of a second.

   **It only ever moves the interrupt earlier.** Programming the one-shot counter restarts it, so
   arming for a *later* deadline would push out a tick already due — a slice that never ends, or an
   idle CPU's backstop deferred by a program asking to be woken next week. The CPU records what it is
   armed for and declines when it is already soon enough; a boot exercises both branches, and says
   so.

   **What this promises is still not a bound.** The residual is interrupt delivery and the rounding
   of a TSC deadline into APIC counts, and neither is guaranteed. The promise remains "not before the
   deadline"; what has changed is that "not long after it" is now true rather than hoped for, and a
   boot gate fails if a 20 ms deadline is more than 25 ms late.

   **Question 1 gets sharper because of this.** A floor on deadlines mattered little while arming did
   nothing to the hardware; now a program can ask this processor's timer to fire as soon as it likes,
   as often as it likes. It is still bounded to that processor, and it is still the spin this system
   already permits — but the fuse is shorter, and the argument for deferring is now weaker than it
   was.
3. **Does a timer survive being handed on?** A notification capability can be derived and passed;
   whether an armed deadline is a property of the object or of the granting is not decided, and
   nothing needs it yet.

## Implementation plan

Each step leaves the tree green.

1. **The deadline table and its arithmetic**, host-tested: arm, replace, disarm, expire, refuse when
   full. No kernel wiring.
2. **`Invoke(ARM)` and `Invoke(DISARM)`**, the rights check, and expiry signalled from where the
   timer interrupt already runs. The QEMU test that a wake arrives after the deadline and not before.
3. **`bin/dhcp` stops counting loop iterations** and waits on a deadline instead. The first real
   caller, and the one that shows the difference: its patience becomes a duration in the source
   rather than a number tuned by experiment.
4. **The measurement** — wake delay at several durations, as a distribution, recorded in TRACKER.
   Done 2026-08-14, gated behind `timers=measure` on the command line because it costs the best part
   of a minute and answers a question that is asked once. It found that the deadline does not affect
   the wake instant at all; see unresolved question 2.

Steps 1 and 2 are the mechanism. Step 3 is the justification. Step 4 is what lets `M4-10b` be
designed against a workload rather than a guess.
