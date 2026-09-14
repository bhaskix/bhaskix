# RFC 0078: a watchdog that does not need the scheduler

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-09-14 — steps 1 and 2 built and watched both ways.** The check runs on the timer vector and a stall before `sched::start_all` now reports instead of timing out silently; with the check removed the same stall goes back to 0 report lines and a 120 s timeout. Step 3's permanent `bhaskix.fault=stall-early` is **not** built: the arming above was done by hand, so nothing re-verifies this on its own yet. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (`trap`, `console`) |
| **Milestone** | Phase 2 — core operating system |
| **Depends on** | [RFC 0019](0019-time-and-timers.md) (the timer), and `lib.rs`'s `bringup_watchdog`, which this does not replace |

---

## Summary

The bring-up watchdog is a thread, so it cannot watch the part of bring-up that
runs before there is a scheduler to run threads. That part contains the
scheduler self-tests, which is where this project's longest-running intermittent
lives. This proposes a second check that rides the timer interrupt instead: no
thread, no scheduler, armed from the moment interrupts are on.

## Motivation

**A machine that stops there says nothing at all.** On 2026-09-14 CI's
`boot (uefi, max)` printed

    wait queues    4 stations spawned at 7349 ms; watching for 2000 ms

and then nothing for 290 seconds, until the harness killed it. That is
specimen eighteen of the ring-station row in `TRACKER.md` §3 — a row with
eighteen specimens and no cause — and the silence was read first as a wedged
console, then as a lost wakeup, before being traced to something duller:
`continue_on_guarded_stack` calls `scheduling_self_test` at `lib.rs:541` and
spawns `bringup_watchdog` at `lib.rs:633`. There was no watchdog yet. Nothing
swallowed the report; nobody was there to write one.

**The existing watchdog already says this cannot be fixed by moving it.**
`lib.rs:606` bounds it twice and both bounds are real:

* *"Not before `sched::start_all`. It is a thread, and a thread spawned into a
  stopped scheduler is runnable and never chosen."*
* *"Not before `tickless_self_test`. That test measures how few interrupts idle
  CPUs take, and a watchdog asleep on a timer is an outstanding deadline on
  whichever CPU it sits on. It would be grading this watchdog rather than the
  kernel."*

The same comment names what is wanted: *"a real gap, and catching it needs a
mechanism that does not depend on the scheduler at all"*. It also records that
this is not only about the ring — *"including `demand paging`, where one stall
has been seen"*.

**A deadline inside the self-test is not the answer either**, which was the
first thing proposed and the first thing to fall over: a thread that is stuck is
not running, so it cannot check its own deadline.

## Design

**The check rides the timer interrupt.** `trap::handle_interrupt`'s
`apic::TIMER_VECTOR` arm already runs on every tick of every CPU, already
increments `TICKS`, and already calls `time::on_tick`. One more call there
compares `bringup_progress()` — the counter the existing watchdog reads, print
count plus bounded-wait count — against the tick it last changed on.

It needs no thread, so `start_all` does not bound it; it adds no outstanding
timer, so `tickless_self_test` does not bound it. It rides ticks that already
happen and is therefore free on an idle CPU, which is also its main limitation:
see Unresolved questions.

**On any CPU, not one.** A thread stuck with interrupts disabled takes no ticks
on its own CPU, so a check pinned to the stalled CPU would be as silent as no
check at all. The state is two atomics — the last progress value and the tick it
was seen at — and every CPU's tick compares them. Whichever CPU is still taking
interrupts does the reporting.

**It reports the way `panic::report` does.** The report path calls
`console::enter_fatal()` first, so output waits a bounded while for the console
lock and then writes through it. That matters more here than anywhere: a timer
interrupt can land on a CPU that is *inside* a `println!`, holding the console,
and an interrupt handler that blocks on a lock its own CPU holds is a hang, not
a report. `write_fatal`'s *"patience first, theft second"* is exactly the
contract needed, and a torn report on a machine that has already stopped is
worth more than a clean silence.

**It disarms itself.** The first report sets a flag and never reports again: a
stalled machine produces one report and not one per tick per CPU.

**It does not replace `bringup_watchdog`.** That thread prints a much fuller
picture — every thread, its state, what the fair pick compares — and can do so
because it runs in thread context where walking the scheduler's tables is safe.
This one prints a few atomics and says where to look. Two mechanisms, different
reach, and the cheap one covers the window the good one cannot.

## Alternatives considered

| | |
|---|---|
| **Move `bringup_watchdog` earlier** | Refused in the tree already, twice over: a thread in a stopped scheduler is never chosen, and a sleeping watchdog is an outstanding deadline the tickless test would then be grading. |
| **A deadline inside `scheduling_self_test`** | The stuck thread would have to run to report it. That is the thing that is not happening. |
| **Rely on the harness timeout** | It is what happens today: a 300-second wait and a log ending mid-sentence. It says a machine stopped and never says where, which is how specimen eighteen cost an afternoon on two wrong theories. |
| **Print from the NMI watchdog instead** | There is no NMI watchdog. Building one is a larger change and would want the same report path; if one is ever built this check should move onto it, because an NMI reaches a CPU with interrupts disabled and a timer does not. |

## Impact on existing design documents

* `docs/architecture.md` — the trap path gains a bounded comparison on the timer
  vector; worth a sentence where the timer's work is described.
* `lib.rs:606`'s comment names this gap and should point at this RFC once it is
  accepted, so the next reader finds the answer beside the problem.
* `TRACKER.md` §3 — the ring-station row records specimen eighteen and this gap.

## Security implications

None across a boundary. The check reads two atomics on a path that already runs,
and the report is a print. It is armed only until `BRINGUP_DONE`, so it is not a
mechanism a running system carries.

## Performance implications

Two atomic loads and a comparison on the timer vector, which already does four
atomic operations and a call. It is measurable only against a tick that does
nothing else, and the tick never does nothing else. To be confirmed by the
tickless numbers the boot already prints, which is a measurement this tree
already takes every boot.

## Testing plan

1. **A deliberate stall, injectable.** `bhaskix.fault=stall-early`, a fault that
   spins for ever before `sched::start_all`. This follows `gp-held`'s precedent
   exactly — that fault exists because *"the log stopped one line after the
   banner"* and the report's guarantee needed something that could falsify it.
   A watchdog whose whole claim is "a stall will not be silent" needs a stall.
2. The boot lanes assert that the fault produces the report, and that a healthy
   boot produces none.
3. The tickless numbers before and after, from the boot's own report.
4. **Armed against itself**: with the comparison removed, the injected stall
   must go back to being silent. A watchdog that cannot be shown failing is a
   watchdog nobody should trust, and this tree has spent a day proving that.

## Unresolved questions

1. **A CPU that takes no ticks at all.** If every CPU has interrupts disabled,
   nothing reports. That is a narrower hole than today's — today it is every
   stall before `start_all`, not just the interrupt-disabled ones — but it is a
   hole, and only an NMI closes it.
2. **What the deadline should be.** The thread watchdog uses 45 seconds of quiet.
   Bring-up before `start_all` is much shorter than the whole of bring-up, so a
   shorter deadline would report sooner; too short and a slow runner under load
   reports a stall that is not one. Proposed: the same 45 seconds, on the
   grounds that a wrong report is worse than a late one and nobody is waiting
   on those 45 seconds anyway.
3. Whether the report should also name the last line printed. It would help, and
   the console keeps a record; reading that record from an interrupt handler is
   a second lock and wants its own thought.

## Implementation plan

1. The two atomics and the comparison, called from the timer vector. Armed by
   removing the comparison.
2. `enter_fatal` and the report, with the one-shot flag.
3. `bhaskix.fault=stall-early` and its boot-lane gate, watched both ways.
4. `lib.rs:606`'s comment points here; `TRACKER.md` §7 and the ring-station row.
