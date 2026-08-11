# RFC 0010: Notifications, and how an interrupt reaches a thread

| | |
|---|---|
| **Status** | ✅ **Accepted 2026-08-04.** Resolves **NF1**. With RFC 0009, completes RFC 0008's answer to **A3**. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (`cap`, `notify`, `syscall`, `trap`) |
| **Milestone** | Phase 2 — required before a user-mode driver, and before any service that must not block its callers |
| **Depends on** | [RFC 0008](0008-syscall-and-ipc-shape.md) (which promises this), [RFC 0009](0009-shared-memory.md) (the other half of the same answer), [security.md](../security.md) §2 |

---

> **Accepted 2026-08-04 by the project lead.**
>
> **What acceptance locks in**, beyond the object itself: **at most one waiter,
> refused rather than queued.** That is the decision this RFC says is most
> likely to be argued with, and it is the divergence from seL4 — which queues
> waiters — that everything else here rests on. It is what keeps the signal
> path lock-free, and a lock-free signal path is what lets an interrupt handler
> call it. Adding a queue later means adding a `try_lock` with a deferred-wake
> fallback, which is machinery M6-04 already built; it is a change with a
> known shape rather than a corner painted into.
>
> Unresolved questions 1, 3 and 4 stay open. Question 2 was already answered by
> [RFC 0011](0011-irq-handler.md) existing.
>
> One correction made at acceptance: the impact section cited
> `driver-model.md` §5 where it meant §2. A wrong cross-reference is not part
> of an argument, so it is fixed rather than preserved.
>
> The argument below is now immutable, per the document ownership table in
> `TRACKER.md`. A change of mind is a new RFC that supersedes this one.

---

## Summary

A new object kind, **`Notification`**: one word of pending bits, at most one
waiter, and two operations — **signal**, which never blocks and may be called
from an interrupt handler, and **wait**, which blocks until the word is
non-zero and then takes it.

The bits come from the **badge** on the capability that signalled, so a
receiver learns *which* of its senders woke it without trusting any of them.
Signals coalesce: two before a wait are one wake. That is what makes this a
fixed-size object rather than a queue, which is what
[RFC 0008](0008-syscall-and-ipc-shape.md) refused to put in the nucleus.

Together with [RFC 0009](0009-shared-memory.md) this completes RFC 0008's
answer to **A3**: *synchronous rendezvous is the primitive, and async is built
above it from shared memory plus a notification capability.*

---

## Motivation

**1. There is no way to wake a thread that is not already talking to you.**
Every wake-up in Bhaskix today is either a reply to a `Call` the waiter made,
or a kernel-internal wake with no capability behind it. A service cannot say
"something happened" to a domain that is not currently asking; it can only
answer.

**2. A driver in a domain cannot receive an interrupt.** M6-06's `virtio-blk`
driver polls its used ring with a bounded spin, and TRACKER records why: the
kernel has no object that means "wake this thread when that line fires". The
poll costs a CPU for the duration of every request. On an emulator that is
tens of microseconds; on real hardware with a real disk it is milliseconds of
a processor doing nothing.

**3. A shared-memory ring has no doorbell.** RFC 0009 gives two domains a
buffer. Without a notification, the reader either spins on it or the writer
must fall back to a synchronous `Call` — at which point the shared buffer has
bought nothing but a larger message.

**What happens if we do nothing.** Every driver polls, every service is
synchronous, and the first one that cannot be either grows a special case in
the nucleus.

---

## Design

### The object

```rust
pub struct Notification {
    /// Badge bits signalled and not yet taken. Atomic: the signal path runs
    /// in interrupt context and must not take a lock.
    pending: AtomicU64,
    /// The one thread blocked in `wait`, or zero.
    waiter: AtomicU32,
    /// Bumped on destruction, so a stale capability cannot name a reused slot.
    generation: u32,
    live: bool,
}
```

Fixed size, allocated from a bounded arena exactly as endpoints are (M5-05),
and charged to the creating domain's capability quota. **Nothing here
allocates per signal**, which is the property that makes it safe to signal
from an interrupt handler and the reason it is not a queue.

### Two operations, and no new syscall

RFC 0008 fixes the syscall set at six kinds and says adding a seventh should
feel like an architectural change. It is not needed:

| Operation | How it is expressed | Blocks? |
|---|---|---|
| **Signal** | `Invoke(notification, SIGNAL)` | Never |
| **Wait** | `Recv(notification)` | Until the word is non-zero |
| **Poll** | `Invoke(notification, POLL)` | Never; returns and clears the word |

`Recv` today means "block until a message arrives on an endpoint". Extending
it to accept a notification capability is the same sentence with a different
object, and it returns the badge word where a message would have returned its
first register. `Signal` is an `Invoke` because `Invoke` is the kind that
means "do a thing and come straight back".

**Poll matters more than it looks.** A service draining a shared-memory ring
must be able to ask "is there more?" without committing to sleep, or it will
sleep holding work it has already been told about.

### The badge is a bitmask, and that is a deliberate reinterpretation

`security.md` §2 rule 4: the badge is set by the granter and the holder can
neither read nor alter it. For an endpoint, a badge identifies a caller. For a
notification, **the badge is OR-ed into the pending word**, so it identifies a
*source*.

That gives a receiver the shape everyone wants and nobody has to build: one
notification, up to 64 distinguishable senders, one wait, and a word saying
which of them fired. It is `select` without a table, and the identification is
trustworthy because the sender did not choose its own badge.

**The limit is real and is stated here rather than discovered:** 64 bits. A
65th sender must either alias onto an existing bit — deliberately, if the
receiver treats a group as one source — or get its own notification. Aliasing
is a choice the *granter* makes when it sets the badge, which is the right
place for it.

A badge of zero is refused at derivation for a notification capability. A
signal that sets no bits is a wake that says nothing, and a receiver cannot
tell it from a spurious one.

### Signalling, including from an interrupt handler

```
signal(capability):
    bits = badge of the capability          ← the kernel's, not the caller's
    pending |= bits                          (atomic, release)
    waiter = load(waiter)                    (acquire)
    if waiter != 0:
        wake_from_interrupt(waiter)
```

Two properties this depends on, both of which already exist:

- **`sched::wake_from_interrupt`** (M6-04) takes no blocking lock and records
  what it could not deliver for the next timer tick. It was written because
  `time::on_tick` waking a sleeper with a blocking runqueue lock was a
  one-CPU deadlock waiting for a timer to expire in a window a few
  instructions wide.
- **The mark-blocked-then-check order** in `wait`, which is the rule M4-09
  established, M5-05 relearned, and `input.rs` states in full. A waiter marks
  itself blocked, *then* reads the word, so a signal that arrives in between
  is found by the read rather than lost.

`wait` is therefore:

```
wait(capability):
    if waiter is already set → refuse (Congested)
    store this thread in waiter
    loop:
        mark_blocked()
        word = pending.swap(0)               ← take it all, atomically
        if word != 0:
            cancel_block(); clear waiter; return word
        block_self()
```

The `swap` is what makes coalescing correct: the waiter takes every bit
signalled since it last looked, in one operation, so no signal is dropped and
none is delivered twice.

### One waiter, refused rather than queued

A second `Recv` on the same notification is refused with `Congested`. This is
the design decision most likely to be argued with, so the reasoning in full:

- **Every use here has one waiter.** A driver thread waiting on its device; a
  service's event loop waiting on its ring. Two threads waiting on one
  notification want one of them to get the word, which is a work-queue, which
  is a thing to build *above* this out of a notification and an endpoint.
- **It makes the signal path lock-free**, which is what lets an interrupt
  handler call it. A waiter *list* needs a lock, and a lock taken from an ISR
  must be `try_lock`, and a `try_lock` that fails on a wake is a lost wakeup —
  the exact bug this project has now hit twice.
- **It is the same shape `input.rs` already proved.** One reader recorded in
  an atomic, woken from the serial interrupt, with the ordering argument
  written down. Notifications generalise that pattern to an object anyone can
  hold a capability to, rather than a static private to the console.

seL4 queues waiters. If a workload turns up that needs it, the queue goes in
and the signal path grows a `try_lock` with a deferred-wake fallback — which
is machinery M6-04 already built.

### Destruction and revocation

Revoking the last capability destroys the object. A thread blocked in `wait`
must not be left blocked on something that no longer exists:

```
destroy(notification):
    live = false; generation += 1
    waiter = swap(waiter, 0)
    if waiter != 0: wake(waiter)             ← it will find live == false and return an error
```

This is what `ipc::destroy` already does for endpoints, down to the "stranded
on teardown" count the boot gate asserts. The same accounting should appear
here, for the same reason: a thread that was woken by a teardown is a fact
worth counting, because the alternative to counting it is discovering it.

### Interrupt delivery needs a second object, and this RFC does not define it

Signalling a notification is *how* an interrupt reaches a thread. It is not
*who may receive one*. Giving a domain an interrupt line is giving it a
hardware resource, and that needs an object naming the line — seL4 calls it an
`IRQHandler`, with methods to bind a notification to it and to acknowledge.

That is deliberately out of scope here, because it is tangled with questions
this RFC has no opinion on: who allocates a vector, how an MSI-X entry is
programmed, and what happens when two domains claim the same line. Those are
device-resource questions and belong with the driver framework.

**What this RFC commits to** is that the delivery half is ready: the kernel's
own handler can signal a notification from interrupt context, safely, today's
scheduler included. `input.rs` would be the first thing rewritten on it, and
the second would be `virtio-blk`, which would stop polling.

### Concurrency

| Path | Locks taken | Context |
|---|---|---|
| `signal` | none (two atomics + `wake_from_interrupt`) | thread or interrupt |
| `wait` | the notification arena, to resolve; released before blocking | thread only |
| `destroy` | the arena, then a runqueue via `wake` | thread only |

The arena lock sits with the endpoint table's rank — inside the capability
arena, outside the runqueues — because a `Recv` resolves its capability before
it blocks, exactly as IPC does.

### Failure behaviour

| Situation | Answer |
|---|---|
| A second waiter | `Congested`; the first keeps the notification |
| Signal with no waiter | The bits accumulate; nothing blocks, nothing is lost |
| Signal on a revoked capability | `Revoked`, before the object is touched |
| Wait on a destroyed notification | Woken and returned an error, not left blocked |
| Badge of zero at derivation | Refused: a signal that sets no bits says nothing |
| 65th sender | The granter chooses an alias or a second notification; the kernel does not choose for it |
| Arena full | `QuotaExceeded` at create, as endpoints already do |

---

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **A seventh syscall, `Wait`** | RFC 0008 fixes the set at six and says a seventh should feel architectural. `Recv` on a notification is the same sentence with a different object. | Never for this; the shape fits. |
| **A counting semaphore instead of a bitset** | A count that saturates is a lie and one that wraps is worse, and neither tells the receiver *what* happened. Coalescing is the property that bounds the object's size. | A workload needed to know how many events occurred rather than that events occurred — at which point the count belongs in the shared-memory ring, where it can be as wide as it likes. |
| **Deliver interrupts as IPC messages to an endpoint** | A send from an interrupt handler must either block, which is impossible there, or queue, which is the unbounded nucleus buffer RFC 0008 refused. | Never. This is the same argument as A3, arriving from the hardware side. |
| **POSIX-style signals** — an asynchronous callback onto a thread's stack | Reentrancy on a stack the thread was using, a handler that must be async-signal-safe, and authority that arrives without a capability. Decades of evidence that this is hard to use correctly. | Never natively. It is a Linux personality's problem, per RFC 0005. |
| **Queue the waiters, as seL4 does** | Needs a lock in the signal path; a lock in the signal path must be `try_lock` because of interrupts; a failed `try_lock` on a wake is a lost wakeup. Every use here has one waiter. | A workload genuinely wants many threads waiting on one source — then the queue lands on M6-04's deferred-wake machinery. |
| **Keep polling** (the status quo) | Costs a CPU per outstanding request and cannot scale past one device. It is also the honest current answer, which is why this is Phase 2 and not now. | — |
| **Fold this into RFC 0009** | A notification is useful with no shared memory at all — an interrupt is the obvious case — and the two share no invariants. One RFC would have to argue two threat models. | If review finds the two are decided together in practice, merging costs nothing. |

---

## Impact on existing design documents

**[architecture.md](../architecture.md) §3** describes the nucleus's objects.
`Notification` joins them, and `ObjectKind::Notification` is already declared
in `cap.rs` and unused — this RFC is what gives it meaning.

**[driver-model.md](../driver-model.md) §2** assumes a driver in a domain can
be woken by its device. That assumption has been unfunded since it was
written; this is half the funding, and the `IRQHandler` object is the other
half.

**[RFC 0008](0008-syscall-and-ipc-shape.md)** is completed rather than
contradicted: its §A3 answer named shared memory *and* a notification
capability, and after this and RFC 0009 both exist.

**No document becomes wrong.** This is a promise being kept, not a design
being changed — which is worth noting because it is the first RFC in this
series that can say so.

---

## Security implications

**New authority.** The ability to wake a thread. That is small but not
nothing: an unbounded ability to wake a thread is an ability to keep it off
the idle path and burn its `ResourceEnvelope`'s CPU share. Two things bound
it — signals coalesce, so a sender that signals in a loop produces one wake
per wait rather than one per signal; and the waiter's own scheduling class
decides what that wake costs it.

**What becomes reachable without a capability.** Nothing. Signalling needs a
capability; waiting needs a capability; the badge is the kernel's.

**Identification without trust.** The badge is granter-set, so a receiver can
attribute a wake-up to a sender that cannot lie about which it is. This is the
same mechanism M5-05 uses to let a service tell its callers apart, applied to
events.

**New parser for untrusted input?** None. A signal carries no payload — the
payload is in the shared memory RFC 0009 describes, and it is the receiver's
business to validate what it reads there, under that RFC's double-fetch rules.

**A denial-of-service that is *not* closed by this design, stated plainly:** a
domain holding a signal capability can wake a receiver whenever it likes. If
the receiver's work per wake-up is not bounded by its own policy, that is a
loop the sender controls. The kernel bounds the *wake*, not what the receiver
does about it. That is the correct division and it is worth writing in
`docs/security.md` when the code lands.

---

## Performance implications

**Faster:** the block driver stops burning a CPU per request. The console
input path stops needing a private static and a hand-written wake.

**Slower:** nothing measurably. A signal is two atomics and a possible wake;
the wake is the cost, and it is the cost of the wake that already happens.

**What will be measured:**

| Measurement | Today |
|---|---|
| CPU cycles spent inside `virtio::read` waiting for the device | the whole request |
| Wakes delivered per 1 000 signals when the receiver is slow | n/a — no signal path exists |
| Time from `signal` in an ISR to the waiter running, p50 and p99.9 | n/a |

The last one is the number that matters, and it is the same measurement
`docs/scheduler.md` §4 already defines for RT wake-up latency — so the gate
exists and only needs pointing at a new source.

---

## Testing plan

**On the host:**

- The badge-to-bits arithmetic, and that a zero badge is refused.
- Coalescing: any sequence of signals between two waits yields exactly the OR
  of their badges, once. Exhaustive over small sequences.
- The state machine: signal-then-wait, wait-then-signal, signal-signal-wait,
  wait with the word already set, and the second-waiter refusal.
- Destruction with a waiter recorded.

**In QEMU:**

- Two threads: one signals, one waits, a fixed number of times, with the
  counts asserted rather than sampled.
- **Signal from an interrupt handler**, which is the whole point — and the
  serial interrupt is already the right source. Rewriting `input.rs` on a
  notification is the test.
- No lost wake-ups under load: the ring test M4-09 uses, with a notification
  in place of the wait queue, asserting the same "a lost wakeup stops the
  ring rather than slowing it" property.
- A waiter woken by destruction returns an error rather than staying blocked,
  and the stranded count says so.

**Negative tests** (each must fail the gate when introduced):

- Signal that wakes before publishing the bits → the waiter looks, finds
  nothing, and sleeps with work pending.
- `wait` that checks before marking blocked → a lost wake-up under load.
- A `swap` replaced by a read-then-clear → a signal between the two is lost.

**Fuzz target:** none, and the *Security implications* section says why.

---

## Unresolved questions

1. **Bound notifications.** seL4 lets a thread wait on an endpoint and a
   notification at once, which is how a service handles requests and events in
   one loop. Without it, a service needs two threads. Proposal: leave it out,
   and revisit when a service has both — because the mechanism is genuinely
   intricate and the need is not yet demonstrated.

   **Still open, and the trigger has fired.** `bin/blkd` has both: it receives
   on an endpoint and waits on the notification its device signals. It needed
   **one** thread, not the two this question predicts, and the reason is
   structural rather than lucky — the wait happens *inside* handling a request,
   because the device event it waits for is the completion of the work that
   request asked for. Nothing arrives unsolicited.

   So the case that would settle this is narrower than "a service has both": it
   is a service that must answer callers *while* something it did not ask for
   may arrive. A network driver is the obvious first one, which puts this
   question in front of whoever writes the networking RFC.
2. ~~**The `IRQHandler` object** — who may claim an interrupt line, how a
   vector is allocated, and what acknowledgement looks like.~~ **Answered:**
   [RFC 0011](0011-irq-handler.md), which uses this object as its delivery
   mechanism and adds the one thing this RFC's interrupt discussion did not
   mention — the source must be *masked* before it is signalled.
3. **A timeout on `wait`.** RFC 0008 already records that `Recv` needs one
   eventually, or a service bug becomes a caller hang. The same applies here
   and the answer should be the same answer, whatever it turns out to be.
4. **Whether 64 bits is the right width.** It is the natural one on this
   architecture and nothing here needs more. Recorded so that the day
   something does, the aliasing rule is found rather than rediscovered.

---

## Implementation plan

Each step leaves the tree green.

1. **The object and its arena.** Create, destroy, revoke; `ObjectKind::
   Notification` given meaning; quota charged. Host tests for the arena and
   the state machine.
2. **`Invoke(SIGNAL)` and `Recv` on a notification.** The lock-free signal
   path, the mark-blocked-then-check wait, the second-waiter refusal. The
   two-thread QEMU test.
3. **`Invoke(POLL)`**, and the drain-then-block pattern in a service.
4. **Signal from an interrupt handler**, proved by rewriting `input.rs`'s
   private reader on it. This is the step that retires a hand-written
   special case in favour of a general object, which is the point of the
   whole exercise.
5. **Destruction while a waiter is blocked**, with the stranded count and its
   gate.
6. **A ring plus a doorbell** — RFC 0009's shared memory with a notification
   on top, in `abi`, as the async channel RFC 0008 promised. No kernel change.

Steps 1–3 are the object. Step 4 is the justification. Step 6 is the reason
RFC 0008 said any of this.
