# RFC 0024: Preemption on wake

| | |
|---|---|
| **Status** | **Closed without shipping, 2026-08-15** — built, measured, refuted by its own pre-stated target's instrument, and reverted. The record below is the deliverable. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (`sched`, `trap`) |
| **Milestone** | Phase 2 — the change wake-to-dispatch's numbers ask for, and the home M4-10b's slice-policy questions were waiting on |
| **Depends on** | [RFC 0019](0019-time-and-timers.md) (the tick this reasons about), [RFC 0023](0023-a-wake-for-a-connection.md) (the measurement that convicted the scheduler) |

---

## Summary

**A wake may end the running thread's slice.** Today, waking a thread on another CPU sends a
reschedule IPI and that CPU acts at once; waking a thread on the *same* CPU marks it ready and
nothing more — the woken thread waits until the runner blocks, yields, or the next timer tick
lands, a gap measured at **mean 414 µs and worst several seconds**. This RFC makes a wake that
ought to win request an immediate reschedule at the next safe point: the waker's own syscall
return, or the interrupt exit that delivered the wake. The policy is deliberately narrow — a
real-time thread always wins; a fair thread wins only if the runner has had a minimum grant — so
two threads trading wakes cannot ping-pong the CPU into doing nothing but switching.

## Motivation

**Two measurements, one owner.** RFC 0023 replaced a poll loop with a wake and the round-trip
median *rose* by about a millisecond; the wake-to-dispatch instrument then found the scheduler's
own ready-to-dispatched gap at mean 414 µs (IOMMU boot, 16,906 wakes) to ~1 ms (BIOS), worst
cases seconds long during bring-up. The mechanism is visible in the code: `wake_with` pokes a
*remote* CPU with `RESCHEDULE_VECTOR` — whose handler re-arms the tick and calls `preempt()` —
but on the local CPU it only marks the thread ready. With a 3 ms default slice
(`DEFAULT_SLICE_US`), a thread woken early in the runner's slice waits most of it.

**Every event-driven design this project has shipped pays this gap**: RFC 0010's notifications,
RFC 0019's deadlines, RFC 0023's connection wakes, and each IPC reply that unblocks a caller. The
gap is also why RFC 0023's honest verdict read "the wake path, not TCP, is the next thing worth
measuring" — this is that measurement acted on.

**What happens if we do nothing**: wakes stay tick-quantised, and every latency-sensitive design
on top of notifications inherits up to a slice of hidden latency.

## Design

### The hint

`wake_with` gains a verdict: after marking the thread ready on this CPU, it compares the woken
thread against the one currently running —

- an **rt** wake over a **fair** runner always warrants preemption;
- a **fair** wake warrants it only if the runner has already run at least `MIN_GRANT_US`
  (500 µs) of its slice *and* the woken thread's `vruntime` is not ahead of the runner's;
- nothing warrants preempting an **rt** runner except a lower-vruntime rt wake — the admission
  control that already bounds rt load keeps this rare.

A warranted wake sets the CPU's slice deadline to *now* — the same variable the tick already
honours, so no second mechanism decides scheduling — and raises a per-CPU **resched pending**
flag.

### The safe points

The flag is acted on where preemption is already legal:

- **Syscall return**: a waker in a system call (`SIGNAL`, `Reply`) checks the flag on its own
  exit path and calls `preempt()` before returning to user mode. The woken thread runs within
  microseconds of the wake, and the waker resumes at the fairness the vruntime accounting was
  already keeping.
- **Interrupt exit**: a wake performed inside an interrupt handler (a deadline expiring, a
  device's notification) is acted on by the existing tail of the interrupt path, which already
  calls `preempt()` for the timer — the flag extends the same call to the vectors that wake.

`preempt()` keeps every refusal it has: a CPU holding any lock is not descheduled, re-entry is
excluded, and a skipped preemption is retried at the next tick — the flag makes the *common* case
prompt without making any case less safe.

### What does not change

The tick, the slice length, vruntime accounting, the remote-wake IPI, and every blocking path.
A machine where no wake ever warrants preemption schedules exactly as today.

## The timer wheel, deferred again — this time with its trigger written down

M4-10b has waited since M4 for "a many-short-timers workload to have a shape". The workload
today is four timers on one connection table of two, plus one deadline per waiting client — the
per-CPU nearest-deadline re-arm (RFC 0019) walks a handful of entries and the walk has never
appeared in a measurement. A wheel bought now would be a data structure without a customer.
**The trigger**: when the connection table grows past the point where `arm_nearest`'s walk shows
up in the wake-to-dispatch or deadline-lateness lines this project already prints, the wheel gets
built against that number. Until then the honest slice-policy work lived here.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Preempt on every wake, no policy | Two threads trading wakes (a caller and its service) would switch on every message — the ping-pong costs more context switches than the latency it saves, and starves the runner of the grant fairness promised it. |
| Shorten the slice instead (3 ms → 500 µs) | Taxes every thread on every CPU to help the one being woken; quadruples tick work for compute-bound domains that never wake anyone. The gap is per-event, so the fix should be too. |
| A dedicated "wake vector" self-IPI | The syscall and interrupt exits are already safe points with `preempt()` reachable; a self-IPI adds a vector and an APIC round trip to arrive at the same call. |

## Impact on existing design documents

- [RFC 0023](0023-a-wake-for-a-connection.md): its implementation notes name the 1–3 ms and
  predict this RFC; the re-measurement here closes that loop.
- `TRACKER.md` M4-10b: the wheel's deferral gains a written trigger instead of an open wait.

## Security implications

None new: preemption decisions read scheduler state the tick already reads, at points the tick
already preempts. A domain cannot invoke preemption except by the wakes it was already able to
cause, and the `MIN_GRANT_US` floor bounds how often its wakes can displace anyone.

## Performance implications

The measured target, stated before the work: the wake-to-dispatch **mean must fall below 50 µs**
on the same boots that measured 414 µs, and RFC 0023's wake-driven round-trip median must come
back to at least polling parity. The cost to watch: total context switches per boot (printed
already) must not grow by more than the wakes that warranted preemption.

## Unresolved questions

1. **Is `MIN_GRANT_US = 500` right?** It is a guess bounded by two cliffs — too low ping-pongs,
   too high re-creates the gap. The instrument that measured the gap measures the choice; ship
   500, record the distribution, revisit with numbers.
2. **Should the woken thread inherit the remainder of the preempted slice** rather than starting
   a fresh one? Fresh-slice is simpler and what the tick does today; inheritance would bound the
   preemption tax on the runner. Deferred until the switch counts say the tax is real.

## Implementation plan

Each step leaves the tree green.

1. **The flag and the verdict**: `wake_with` computes warranted-ness, sets the slice deadline and
   the per-CPU flag; host tests for the policy table (rt over fair, the grant floor, vruntime
   order), each watched failing.
2. **The safe points**: syscall return and interrupt exit act on the flag through the existing
   `preempt()`. The gate is the instrument already in the boot report: wake-to-dispatch mean
   under 50 µs, watched red by disabling the flag.
3. **The re-measurement**: RFC 0023's distribution rerun, before/after in TRACKER, and the
   switch-count delta recorded beside it.

---

**Closure note, 2026-08-15.** Steps 1 and 2 were built — a per-CPU resched flag set by local
wakes, consumed by `preempt()`, acted on at the syscall-return and claimed-interrupt exits — and
step 3's measurement refuted the premise before the mechanism shipped, in two moves:

1. **The mean was the wrong statistic.** The wake-to-dispatch instrument gained a log₂ histogram,
   and the percentiles it revealed — **p50 54 µs, p99 218 µs** — showed the 414 µs "mean" was a
   handful of seconds-long bring-up outliers spread across sixteen thousand fast wakes. One
   four-second wake alone contributes ~240 µs of mean.
2. **The mechanism changed nothing.** With the flag disabled the percentiles are identical:
   p50 54 µs, p99 218 µs. The common wakers already hand over promptly — a service that signals
   returns to its receive and blocks within microseconds, and every interrupt-context wake exits
   through arms that already preempt. There was no gap for the flag to close.

So the scheduler is **exonerated**, this document's motivation dissolves, and the mechanism was
reverted rather than shipped as reassurance code — the same rule that keeps data structures from
being built without customers keeps preemption hooks from being kept without effects. What
survives: the percentile instrument (now the boot line the gate demands), and a sharpened
question with its suspect list — RFC 0023's wake-driven round-trip median of 1.4–3.1 ms is *not*
scheduler latency, so it lives in the event pipeline between the wire and the wake: the protocol
service's own serve loop, its fallback deadline cadence, or slirp. Attributing it needs
per-stage timestamps, which is a future instrument, not this RFC.

The grant-floor policy table in the design above also did not survive contact with the code: this
scheduler is EEVDF — `pick_next` chooses by real-time priority then earliest virtual deadline,
with no slice protection to override — so the anti-ping-pong policy the table proposed already
exists as the deadline arithmetic. Kept as drafted for the record of what was believed before
measuring.
