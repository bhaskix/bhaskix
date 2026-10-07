# RFC 0085: A futex sleeper comes back for its answer

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-10-04 by the project lead.** Drafted 2026-09-29 — **both steps built and gated, each armed red.** A woken futex sleeper comes back to the adapter for its answer, its wake slot is no longer given back before it has taken the wake, and a signal sent to a futex sleeper is delivered when it wakes — RFC 0083's fourth limit, closed. ~~The acceptance call is the project lead's.~~ |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | userspace (`bin/linuxd`) |
| **Milestone** | Phase 2 — the Linux personality ([RFC 0005](0005-linux-abi-compatibility.md)) |
| **Depends on** | [RFC 0032](0032-a-supervisor-interface.md) step 10 (the futex in ring 3), [RFC 0083](0083-a-signal-a-process-can-catch.md) (its fourth limit) |

---

## Summary

A hosted thread parked in `futex(WAIT)` is resumed by the nucleus itself when
it is woken: the adapter answers the park `REPLY_BLOCK_ON`, the one reply kind
whose wake completes the call without asking the adapter again. This RFC has
the futex park answer `REPLY_BLOCK_ON_RETRY` instead, like every other park
`bin/linuxd` makes, so a woken sleeper comes back to the adapter for its
answer. Two defects close with it: the futex wake's wake slot is no longer
given back before its sleeper has taken the wake, and a signal raised at a
futex sleeper is delivered when it wakes rather than at its next call.

## Motivation

**The wake-slot defect.** On 2026-09-29 the pipe and `wait4` wakes were found
releasing a parked caller's wake slot the moment they signalled it, before the
caller had taken the wake; the next park anywhere is handed the lowest free
slot, and either it is refused as a second waiter or it takes the first
caller's wake and leaves it waiting on a slot nobody will signal again. Both
outcomes were observed (`TRACKER.md` §3). The fix was to let the parked caller
own its slot until it comes back.

`answer_futex`'s `WAKE` has the same shape — it signals a sleeper's slot and
clears its record at once — and that fix cannot reach it, because **a futex
sleeper never comes back**. `REPLY_BLOCK_ON` tells the nucleus to answer 0
when the wait returns, so there is no moment at which the adapter learns the
sleeper has left its wait. Not observed; found by auditing every slot release.

**RFC 0083's fourth limit.** *"A futex wake resumes without an adapter reply"*,
and delivery rides out on a reply, so a signal pending for a futex sleeper is
not delivered at that boundary. The RFC names `answer_futex` as
`REPLY_BLOCK_ON`'s only caller. A park that comes back is a reply.

## Design

**The park.** `WAIT` claims a slot as today, and answers `REPLY_BLOCK_ON_RETRY`
naming it. The slot is recorded in `bin/linuxd`'s `HELD` table as a `Futex`
park of the calling thread — the same table, keyed by domain **and thread**,
that the pipe and `wait4` fixes use.

**The wake.** `WAKE` signals each sleeper it chooses and **marks** its record
woken rather than freeing it. A woken record keeps its slot and is no longer a
match for another `WAKE` on the same word, so a sleeper is counted once.

**The return.** A woken sleeper re-asks with the same `futex(WAIT)`. The
adapter recognises it by the `Futex` entry `HELD` has for that thread — a
thread that is parked cannot make another call — and:

| its record | the answer |
|---|---|
| woken by a `WAKE` | **0**, and the slot is given back |
| not woken, and the word still holds `expected` | park again, on the **same** slot |
| not woken, and the word has changed | `EAGAIN`, and the slot is given back |

A thread woken by a *signal* (`wake_parked`) is the second or third row, and
if its signal is pending the adapter's existing delivery arm turns the re-park
into a delivery with `EINTR` — Linux's answer for a futex interrupted by a
handler — and gives the slot back. That is the fourth limit closed.

**Spurious wakes** are the second row, which is what Linux permits a futex to
do. The nucleus's retry loop is bounded at sixteen turns; a sleeper woken
spuriously more often than that is answered `EAGAIN`, which a futex caller
already has to handle.

**Unchanged.** The nucleus: `REPLY_BLOCK_ON_RETRY` is a path every other park
already takes. `REPLY_BLOCK_ON` loses its only caller and is kept, documented
as unused, rather than removed in the same change.

## Alternatives considered

- **Keep `REPLY_BLOCK_ON` and free the slot later** — on the next `WAKE`, or on
  a timer. There is no event that says the sleeper has left its wait, and a
  guess is the defect this is about.
- **One notification per sleeping thread**, never shared. The pool is sixteen
  slots on purpose; a per-thread notification is a resource per hosted thread
  and a larger change than the defect.

## Security implications

None new. The retry passes through the same adapter checks as the first ask;
a re-park reads the word through the same `Domain` capability.

## Performance implications

One adapter round trip per woken futex sleeper, which every pipe reader and
`wait4` already pays. A contended lock in a hosted program is where it would
show, and the boot measures hosted call costs already.

## Testing plan

- **The existing gates are the regression net**: the clone test (a parent
  sleeps in a futex, its child sets the word and wakes it, and the parent comes
  back), the sixteen hosted threads parked on adapter-named notifications, and
  `futex wakes: none of 16 notifications was left holding bits nobody took`.
- **A count of sleepers answered on their return**, printed every boot: at
  least one on every boot (the clone test's parent), and gated — without it,
  the retry path could be dead and the old one still answering.
- **The fourth limit**: a probe act that signals a thread parked in a futex and
  requires its handler to run. Step 2, below.

## Unresolved questions

1. **`FUTEX_WAIT` with a timeout.** `plan_futex` does not take one today; when
   it does, it is `park_until`'s shape, not this one's.

## Implementation plan

1. ✅ `bin/linuxd`: the park answers `REPLY_BLOCK_ON_RETRY` and holds its slot;
   `WAKE` marks; the return is answered from the table above; a count of
   sleepers answered on their return, published and gated. **Counted on the
   nucleus's side** — a futex answered with a value on a retry — rather than by
   the adapter, whose report record is full and which should not be the only
   witness to its own fix. First boot: `futex return 1`. Armed by switching
   the park back to `REPLY_BLOCK_ON`: 0, and the gate failed.
2. ✅ The fourth limit: a hosted probe act that signals a futex sleeper and
   requires its handler; RFC 0083's fourth limit is then marked closed. The
   killer probe's fourth child, with the same handshake as the other three:
   its handler exits 88, gated on its own line. Armed by answering the park
   `REPLY_BLOCK_ON` again: exit 96, the futex back with nothing delivered.
3. `TRACKER.md`, `docs/progress.md`, and RFC 0083's fourth-limit section, in
   the same commits.
