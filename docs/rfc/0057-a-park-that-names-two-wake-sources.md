# RFC 0057: a park that names two wake sources

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-08-28** — proposed, built and accepted the same day. Built and gated. `two sources` on every boot lane proves both directions and the take-back; the typing lane proves the arm, by hanging without it, and shows the shape in use. **What this does not claim.** *(1)* Only `poll`/`select` naming the **console** use it; a socket still wakes nobody, which is RFC 0056's question and needs a notification the service signals. *(2)* The nucleus's own disarm has no lane that would catch its removal — the timed park's deadline usually fires by itself — so what proves the take-back is the self-test, on the primitive both paths use. *(3)* `clock_nanosleep` keeps the wake pool: it waits on a deadline alone and has no event to race |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel |
| **Milestone** | Phase 2 — Core Operating System (L1) |
| **Depends on** | [RFC 0054](0054-a-hosted-read-that-waits.md) (the parking reply), [RFC 0055](0055-a-poll-that-tells-the-truth.md) (`poll`'s timeouts) |

---

## Summary

A parking reply may name a **deadline** as well as a notification. The nucleus
arms the one against the other, so the caller wakes on whichever comes first,
and disarms on the way out. This removes the limit RFC 0055 accepted — that a
positive timeout waits its whole interval and never returns early — and is the
last of the three open questions RFCs 0054 to 0056 left behind.

## Motivation

**A thread here can wait for an event, or for a deadline, and not for either.**
`BLOCK_ON_RETRY` names a notification; `method::ARM` sets a timer that signals
one. Both exist and neither composes with the other from ring 3, because the
adapter must choose *one* notification to be parked on and can only arm the
notifications it holds `WRITE` on — which, deliberately, the console's is not.

**What that costs, exactly.** RFC 0055's `poll` with a positive timeout parks on
an armed wake slot and re-examines when it expires. A key pressed a millisecond
in is not noticed until the interval ends. For BusyBox's escape-sequence
disambiguation that is ~50ms of latency nobody sees; for a program that polls
standard input with a one-second timeout in a loop it is a shell that feels
broken. The RFC said so and priced it as *late, never early* — true, and worth
removing now that the rest is built.

## Design

### It already composes; nothing can say so

`notify::arm(id, deadline, badge)` makes the timer **signal that notification**.
So a thread parked on `N` with a deadline armed on `N` wakes on a real signal or
on the timer, whichever lands first, through the single-waiter path that already
exists. **No new waiting primitive is needed** — what is missing is a way for
the adapter to ask for it.

### The reply shape

| | |
|---|---|
| `reply::BLOCK_ON_UNTIL` = 9 | Park on the notification in `args[0]`, waking no later than the deadline in `args[1]`, and ask the same question again |

Retry semantics, as `BLOCK_ON_RETRY`: what wakes a poller is not its answer.

**The deadline rides in the reply's second word, which was already there.** The
adapter answers with `call(syscall::REPLY, 0, how, [value, 0, 0, 0])` and the
nucleus keeps `args[0]` alone; three words have been unused since the interface
existed. The alternative was packing a slot and a deadline into one word, which
would have spent a permanent piece of the deadline's range on a number that is
always below 128.

### The nucleus arms, and the adapter still cannot

**This is the whole reason it is a reply shape rather than a method.** The
adapter holds the console's notification with `READ` — RFC 0054 chose that so it
could park a hosted reader and could not invent a keystroke. `ARM` needs
`WRITE`. Letting the adapter arm the console would hand back exactly what was
withheld.

So the nucleus arms it, on behalf of a park it is already performing, bounded by
the same check: `may_park_on` refuses the console's notification unless the
calling domain holds the input grant, and that check runs first.

**And it disarms on waking.** A deadline left behind fires later and signals a
notification whose waiter is by then somebody else — a spurious wake for a
reader that finds nothing and parks again. `arm` replaces per notification and
`disarm` already exists; the discipline is *the arm and the disarm are one
statement*, which is what the gate below checks.

### What a refused arm means

`ARM` answers `Congested` when every deadline slot is taken. The park is then
**refused** and the caller told `EAGAIN`, rather than parked without its
deadline — which would be a wait that never ends for a caller that asked for a
bounded one. Counted beside the other park refusals.

## Alternatives considered

**Give the adapter `WRITE` on the console notification.** One line, and it
undoes RFC 0054's central narrowing: a program that can signal the keyboard's
notification can wake a reader that then finds nothing, repeatedly, which is a
denial of the console dressed as a timer.

**A second notification and a wait on either.** `notify::wait` takes one waiter
and waits on one notification; making it wait on two is a change to the
primitive every driver in the system uses, to serve one caller.

**Leave it.** The honest option, and what RFC 0055 did. It is being revisited
because the cost is now understood and the mechanism turned out to be one reply
shape rather than a new primitive.

## Impact on existing design documents

- **RFC 0055** unresolved question 3 and its stated limit *"a positive timeout
  waits at least as long as asked and never returns early"* are answered for any
  set naming the console.
- **RFC 0054** unresolved question 2 — a deadline a thread can park against — is
  the same question and is answered with it.
- **RFC 0056** unresolved question 1 is **not** answered: a socket becoming
  readable still wakes nobody, because the missing piece there is a
  notification the service signals, not a way to wait on two.

## Security implications

**No new authority for the adapter.** It gains no right on any notification; the
nucleus performs the arm as part of a park it was already performing, and only
where `may_park_on` allows the park at all.

**A spurious wake is the worst it can do.** An adapter naming a deadline on a
notification it may park on can wake that waiter early. The waiter is a hosted
thread of a domain the adapter already serves, and the wake sends it back
through its own question. Nothing else on the machine is reachable.

## Performance implications

One `arm` and one `disarm` per timed park, both table walks over a fixed number
of deadline slots. It replaces a park that *always* ran to the full timeout, so
the common case gets shorter rather than longer.

## Testing plan

1. **A boot self-test in both directions**: a thread parked with a notification
   and a far deadline is woken by the **signal**, and the deadline is disarmed
   behind it; a thread parked with a near deadline and no signal is woken by the
   **timer**. Watched red by removing the disarm and by removing the arm.
2. `armed_deadlines()` before and after, so "disarmed" is measured rather than
   asserted from the code's shape.
3. The typing lane still passes: BusyBox's timed polls are the first real
   caller, and a broken deadline would hang it at its prompt.

## What was found while building it

**A retried wait restarted its own deadline, and the nucleus's backstop is what
caught it.** `BLOCK_ON_UNTIL` asks the question again when it wakes, and the
first version computed a fresh deadline on every pass — so a caller that asked
to wait fifty milliseconds waited fifty milliseconds *per retry*. The loop is
bounded at sixteen retries with `EAGAIN` past it, and that bound is the only
reason this was a visible failure rather than a hang: BusyBox printed
`poll: Resource temporarily unavailable` and abandoned the line. The instant is
recorded on the first park now and consulted on every retry — **a wait that is
retried is still one wait**.

**A gate that measured other people's timers.** The self-test first compared
`notify::armed_deadlines()` before and after, which is a global that every other
timed park on the machine moves; it failed for arithmetic that had nothing to do
with it. It asks `disarm` about *that* notification now, which is the local fact
and a stronger one: the deadline whose signal lost the race is still armed and
must be taken back, and the one that won cleared itself.

**A counter that measured intent.** `PARKED_UNTIL` was incremented after the arm
rather than inside its success, so a mutation that skipped the arm entirely
still reported parks with deadlines. Moving it inside the `Ok` arm does not fix
that either — measured, not assumed — because a mutation that keeps the arm and
removes the call still counts. What the counter honestly says is that the shape
was *used*; what proves the arm is the typing lane, which hangs without it. The
comment at the counter says so rather than claiming more.

**And an assertion placed before the line it read.** The lane's check on
`input park` sat before the `exit` that causes it to be printed. It passed once
and failed the next run.

## Unresolved questions

1. **Nothing else uses it yet.** `clock_nanosleep` waits on a deadline alone and
   has no event to race, so it keeps the wake pool it has; a pipe reader has an
   event and no timeout. The second caller will be `poll` on a pipe with a
   timeout, when something asks.

## Implementation plan

1. `ask_adapter_*` keeps the reply's second word.
2. `reply::BLOCK_ON_UNTIL`, armed and disarmed around the existing wait.
3. `bin/linuxd` answers it for a timed `poll`/`select` naming the console.
4. The self-test, both directions, and the mutations.
