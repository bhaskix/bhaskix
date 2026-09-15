# RFC 0081: a thread belongs to an incarnation, not a slot

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-09-15.** Written after the same defect was fixed three times in one day at three different doors, each fix correct and none of them the cause. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (`sched`, `domain`) |
| **Depends on** | [RFC 0017](0017-process-management.md) (the domain lifecycle), and it is the general form of the repairs made under [RFC 0079](0079-a-signal-a-process-may-send-another.md) |

---

## Summary

A thread records which domain it belongs to as a **slot index**. A domain slot
is reused, and a thread outlives the domain it belonged to — so between a
domain ending and its last thread stopping, that thread carries a number which
now names somebody else. Every guard that asks *"does this domain have a
thread"* by that number gets a wrong answer during the window, and each has
been repaired separately. This proposes carrying the domain's **generation**
beside the slot, so the question has a right answer instead of a series of
exceptions.

## Motivation

**Three defects in one day, at three doors, from one cause.**

| where | what it did | how it was found |
|---|---|---|
| `START` (`syscall::start_program`) | refused to start a program in a domain that was fresh and empty | measured: `bin/sup` failed one boot in five, and a print at the refusal read `domain 14 has 0 thread(s)` — the count that refused it was already back to zero by the next instruction |
| `Domain::has_threads` | refused the Linux personality tag on a domain created three lines earlier | two sightings in `TRACKER.md` §3, filed 2026-09-02 and 2026-09-13, whose own message named the mechanism |
| `START`, again | would have *allowed* a second program into a domain that already had one | read from the source: it used the `try_lock` counter, which reads a queue it cannot take as empty |

The first two are the same window in two places. Each was fixed by teaching the
guard to skip a thread that cannot run again — `Thread::dying` for a domain
that was destroyed, `Thread::departing` for one whose thread is on its way out
— and **both fixes are correct and neither is the cause**.

**The cause is that the question is asked of the wrong identity.** `Thread`
carries `domain: u32`, a slot index. `Domain` already carries
`generation: u32`, bumped when the slot is reused. The two are never compared.

**And the adapter already solved this, one ring out.** `bhaskix-personality`'s
process table looks a record up by `by_domain(domain, generation)` and says why
in its own comment: *"a domain id is reused, and a record found by id alone
would answer for whoever holds the slot now"*. Ring 3 carries the incarnation;
the nucleus does not.

**What happens if we do nothing** is what happened today: the next guard that
asks the question by slot id gets the same wrong answer, and is repaired
separately. Two flags now cover the two windows anybody has looked at. A third
window needs a third flag, and nothing says how many there are — which is the
shape of a fix that is not one.

## Design

**A thread records the incarnation it was spawned into.** `Thread` gains
`domain_generation: u32` beside `domain`, taken from the domain at spawn, and
the predicate that decides whether a thread belongs to a domain compares both.

```text
  fn belongs_to(thread, domain, generation) -> bool
      thread.domain == domain && thread.domain_generation == generation
```

**Which callers change, and which deliberately do not.** The distinction this
tree already draws — and which today's repairs turn on — is between guards that
*decide* and counters that *wait*.

| caller | asks | identity it needs |
|---|---|---|
| `start_program`, `Domain::has_threads` | *may I start a program / change a tag here* | the **incarnation**: somebody else's thread is not this domain's |
| `wait_for_probe_threads`, the socket-reclaim gate | *is this slot's queue clear yet* | the **slot**: the point is precisely to wait for the previous incarnation |
| `domain::create_under`'s `DOMAIN_LIVE_THREADS` | *is this slot free to hand out* | the **slot**, for the same reason |

So this narrows the identity where a decision is made and leaves it alone where
the wait is the purpose. The two flags added on 2026-09-15 become redundant for
the guards and are **kept** — see *Alternatives*.

**Concurrency.** Nothing new is locked: the generation is read once at spawn,
under the domain table lock already held there, and compared inside the
runqueue scans that already take a runqueue lock. No new rank, no new order.
`Rank::Domains` is 6 and `Rank::SchedRunqueue` is 10, and this adds no path
that takes them in the other order.

**Failure behaviour.** A thread spawned before domains exist keeps
`domain == u32::MAX`, which no domain matches, exactly as now. A generation
that wraps is a `u32` counting slot reuses; at the observed rate of domain
churn this is not reachable in the life of a machine, and the failure if it
were is a false *match* — the same wrong answer we have today, not a worse one.

**`unsafe`**: none. This is a field and a comparison.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Keep adding a flag per window** — `dying`, `departing`, and the next one | It is what was done today, twice, and it works. But each flag closes a window somebody found, and nothing bounds how many there are: the guard is right only about the cases already suffered. A generation makes the question correct rather than the exceptions complete | The generation turns out to cost more than it saves — but note the flags are being *kept* either way, because `dying` is read by the scheduler for reasons unrelated to this |
| **Refuse to reuse a slot until its threads are gone** (`domain::create_under`) | Tried before this RFC and recorded in the socket-reclaim gate's own comment: it gives the successor a *different* slot, which stops the `FORGET` message and breaks the mechanism that gate exists to test. It also makes domain creation fail for a reason the caller cannot act on | The reclaim gate stops depending on slot reuse, which would need RFC 0058's message to be sent on something other than reuse |
| **Clear `thread.domain` at departure**, so the thread belongs to nobody | This was the first instinct while fixing the second window and it is wrong: `wait_for_probe_threads` and the socket-reclaim gate wait for a *slot's* threads to leave the queue, and would be told "clear" while the thread was still on it. It answers the deciding question by breaking the waiting one | Never: the two questions are different and one field cannot answer both |
| **Make `DomainId` carry the generation** | Larger and mostly elsewhere: `DomainId` crosses the capability arena, the ABI's domain ids, and every `from_u32` in the tree. The identity that is wrong here is the *thread's* record of its domain, which is one field in one struct | The same confusion turns up on capabilities naming domains, rather than on threads |
| **Do nothing and keep repairing at each door** | Each repair is cheap and correct; the cost is that the next one is found the way the last three were, which was a boot failing one time in five and a day of reading | — |

## Impact on existing design documents

* `TRACKER.md` §3 — two rows (`refused the Linux tag with HasThreads`, 2026-09-02
  and 2026-09-13) name this mechanism. Their two windows are shut for the
  guards; this would make the shutting general rather than enumerated.
* `docs/rfc/0017` — the lifecycle's statement of what a domain's threads *are*
  is where the slot/incarnation distinction belongs.
* `sched::first_thread_in_domain`'s doc comment enumerates the two windows and
  would state the rule instead.
* Nothing in `docs/architecture.md` changes: a domain is still a domain, and
  this is how a thread names one.

## Security implications

**No new authority, and nothing reachable without a capability that was not
before.** A thread's domain field is an *identifier*, never authority — what a
thread may do is what its domain's CSpace holds, which this does not touch.

**It narrows one thing that is currently wide**, and that is the point: a guard
that refuses a domain because of a stranger's thread is failing safe, but a
guard that *allows* something because of one would not be. `START`'s check is
the second kind — it is what stops two programs sharing an address space — and
today it is right only because the two flags cover the windows that have been
found. Making the identity correct removes the reliance on that enumeration.

No parser, no untrusted input, no fuzz target.

## Performance implications

**One `u32` per thread and one comparison per scanned thread.** The scans are
not on a hot path: they run at `START`, at a personality change, and in test
waits. The spawn-time read is one field under a lock already held.

What to measure: nothing needs a benchmark. The claim is that a comparison
added to a loop that already dereferences the thread is unmeasurable, and if
that is wrong the boot report's existing scheduler timings would show it.

## Testing plan

**Host, and this is the half that matters.** The predicate is pure —
`could_still_run` is already host-tested with a `Thread` fixture, and this adds
the generation to the same tests: a thread of the same slot and a *different*
generation must not count, and one of the same slot and the same generation
must. Armed by dropping the generation comparison.

**QEMU** for the live half, and the honest note is that neither existing gate
arms this: `bin/sup`'s seventh refusal (a second `START` on a running child)
and the bystander's tag refusal both hold the *rule*, and both pass whether the
identity is a slot or an incarnation, because neither is contended. What a boot
can show is that nothing regressed.

**What cannot be tested directly** is the window itself: it needs a domain slot
reused while a thread of its predecessor is still queued, which is a race
nobody has been able to force. Both sightings behind the §3 rows arrived from
CI, and four immediate re-runs found 0 of 4. This is therefore a fix argued
from the source and held by host tests, and it should be said that way rather
than claimed to be gated.

**Real hardware**: nothing specific. This is scheduler bookkeeping.

## Unresolved questions

1. **Whether the two flags should go once this lands.** They would be redundant
   *for these guards* and are not redundant elsewhere: `dying` is read on the
   return-to-ring-3 path and by `mark_domain_dying`, which is unrelated to slot
   identity. Proposed: keep both, and remove only their use inside
   `could_still_run`, leaving one predicate that reads the generation.
2. **Whether `DOMAIN_LIVE_THREADS` should be per incarnation too.** It is the
   counter that frees the slot, so it is slot-shaped by definition — but its own
   note says a slot handed out in the wrong window *"gets a stranger's departure
   counted against it"*, which is the same confusion in the other direction and
   is not addressed here.
3. **Whether the ring-station row is a third instance.** That defect ends with a
   thread `Blocked` whose wake was delivered, and slot reuse is not obviously in
   it — but it is the largest open scheduler defect and this RFC should not
   claim it without evidence. Recorded so the next specimen can be read with
   this in hand.

## Implementation plan

1. `Thread::domain_generation`, set at spawn from the domain's own generation;
   `u32::MAX`-domained kernel threads unaffected. Host tests for the predicate,
   armed.
2. `could_still_run` compares both, and the `dying`/`departing` clauses come out
   of it — question 1 above decided first, not after.
3. `sched::first_thread_in_domain`'s comment and `TRACKER.md` §3's two rows
   state the rule rather than the enumeration.
4. `docs/rfc/0017` gains the sentence distinguishing a slot from an incarnation.
