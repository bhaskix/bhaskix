# RFC 0070: a badge that can never ring is refused where it is committed

| | |
|---|---|
| **Status** | Draft |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (`notify`, `irq`, `syscall`) |
| **Milestone** | Phase 2 — core operating system |
| **Depends on** | [RFC 0010](0010-notifications.md), [RFC 0019](0019-time-and-timers.md), [RFC 0057](0057-a-park-that-names-two-wake-sources.md) |

---

## Summary

`notify::signal` refuses a badge of zero, because a signal that sets no bits is
a wake that says nothing. Two operations *commit* to signalling later — arming
a deadline, and binding an interrupt — and neither checks the badge it is given.
Both answer `Ok`, and the refusal then happens inside a timer interrupt or an
interrupt handler, where there is nobody to return it to and the answer is
discarded. This RFC moves the refusal to the moment of commitment, where a
caller still exists to be told.

## Motivation

RFC 0010 settled this once already, and settled it correctly. Its original rule
— *"a badge of zero is refused at derivation for a notification capability"* —
is struck through in that document, corrected in place on 2026-08-13 when step 2
was built: refusing at derivation *"is too broad and stops the machine booting"*,
because most notification capabilities are held in order to **wait** — the
supervisor's is `derive(root, ALL, 0)` — and *"a waiter has no use for a badge"*.
The reason for the rule is about senders and *"does not reach a capability that
will never signal"*. So the refusal went to `SIGNAL`, *"the only moment the
distinction is real"*, and `cap.rs` carries the same reasoning beside the code.

That reasoning has one gap, and it is a gap rather than an error. "Derivation"
and "signalling" are not the only two moments. Between them sits a third: when a
caller **commits** the kernel to signalling later. There the sender/waiter
distinction *is* real — a program arming a deadline is declaring itself a sender
— and, unlike inside `signal`, there is still a caller to answer.

Today both committing paths accept a badge they will not be able to use:

| path | badge comes from | answer today |
|---|---|---|
| `notify::arm` (`ARM`, `syscall.rs:1319`) | the capability's own badge, `resolved.badge` | `Ok` |
| `irq::bind` (`BIND`, `syscall.rs:1190`) | `frame.arg1`, a raw caller argument | `Ok` |

And the three places that discover the problem all discard it, because all three
run where no caller is waiting for an answer:

    kernel/src/irq.rs:820      an interrupt signalling its driver
    kernel/src/time.rs:409     a deadline expiring
    kernel/src/domain.rs:1271  a domain's death reaching its supervisor

The consequence is the worst shape a wake can have: the program is told its
deadline is armed, the timer fires on schedule, and nothing wakes. The kernel
already knows this. `syscall.rs` hard-codes `WAKE_BADGE = 1` for the deadlines
the nucleus arms for itself, and says why beside it — *"One bit, and not zero
[…] a badge of zero sets nothing and the waiter is never woken. A timer that
fired and woke nobody is the hardest kind of missing wake to see."* The nucleus
protects itself from this by construction. A program arming its own deadline
gets no such protection, and no error either.

**The capability shape is in the tree, and ring 3 holds it.** Two badge-zero
notification capabilities carry `WRITE`:

* `lib.rs:18383` — the supervisor's, `derive(root, ALL, 0)`, exactly the
  derivation `cap.rs` names
* `lib.rs:18881` — the shell's writable half, `derive(root, WRITE, 0)`,
  installed at cspace **slot 7** of a ring-3 domain

`ARM` requires `Rights::WRITE` and then passes `resolved.badge`, so either would
be accepted.

**This is a trap, not a live defect, and the difference is stated rather than
blurred.** Nothing arms on such a capability today: every in-kernel arm site
passes an explicit non-zero badge (`BY_TIMER`, `BADGE`, `WAKE_BADGE`); the shell
holds slot 7 as `SIGNAL_WRITE_ONLY` and never signals or arms on it at all — its
only use is a `PEEK` in the `caps` listing; and `user/sup` does not arm either. Measured on three boots after instrumenting `signal`, both refusal
counters read zero. What argues for fixing it anyway is the cost asymmetry: the
check is two lines and the failure it prevents is a program that sleeps forever
with every gate green and no line in the report to explain it.

**How large the discard is.** Forcing the deadline path to signal a zero badge
made the new counter read **10 for a badge that rings nobody** on one boot — ten
real expiries per boot pass through a site that cannot report a refusal.

## Design

Three changes, each justified separately, because they are not the same case.

**1. `notify::arm` refuses a zero badge**, returning `NotifyError::EmptyBadge`.
This does not contradict `cap.rs`: its exemption is explicitly for capabilities
*"that will never signal"*, and a deadline will signal. Holding a badge-zero
capability stays legal; committing it to a future wake does not.

**2. The `BIND` syscall refuses a zero badge**, answering `Status::WrongObject`.
A different case, and a simpler one: that badge is `frame.arg1`, a raw argument
rather than a capability's badge, so no exemption is in play. The identical check
already guards `notify_on_end` twenty-seven hundred lines away in the same file,
with the same reason beside it and the same status. This is that check on the
path that was missing it.

**3. The counters stay.** Landed already as instrumentation: `wake refused N for
a badge that rings nobody, M for a notification that was already gone`. After
this RFC the first should be unreachable through `arm` and `bind`, which makes a
non-zero value a report of a path nobody has thought about yet.

`domain.rs`'s death notice keeps its discard: the badge there is checked at
`notify_on_end`, and a `Gone` at teardown means the supervisor exited first,
which is ordinary.

## Alternatives considered

**Enforce RFC 0010 at derivation.** Tried, in effect, and recorded in `cap.rs`:
it stops the machine booting, because waiters hold badge-zero capabilities and
have every right to.

**Give `arm` a default badge of 1 when it is passed zero.** Rejected: it invents
authority the caller did not ask for, and the ABI is explicit that *"a badge may
not be invented: it must be the one the capability already"* carries. A refusal
tells the truth; a substitution hides it.

**Leave it and rely on the counters.** Rejected on asymmetry. The counter says
afterwards that a wake was lost; the refusal stops the caller from being told a
deadline is armed when it is not.

## Impact on existing design documents

* `docs/rfc/0010-notifications.md` — **no correction needed, and that is worth
  saying.** Its derivation-time rule was already struck through and explained in
  place on 2026-08-13, and `cap.rs` repeats the reasoning at the code. This RFC
  does not overturn that; it adds the moment RFC 0010's correction did not
  consider — commitment — and should be linked from it as a follow-on.
* `docs/security.md` — no boundary changes. A domain could only ever silence its
  own wakes.
* `TRACKER.md` §7.

## Security implications

None that cross a domain boundary: a badge of zero silences only wakes to the
notification the caller already holds. The change is diagnosability, not
containment — it converts a permanent silent failure into an immediate error.

## Performance implications

Two comparisons against zero, one per `arm` and one per `BIND`. Neither is on a
hot path; `arm` already resolves a capability and walks the deadline table.

## Testing plan

1. Host tests on `notify::arm` for the zero badge, refused, and a non-zero badge
   still armed.
2. A boot probe that arms a deadline on the shell's slot-7 capability and
   asserts the syscall now refuses it. **This probe must be shown failing
   against the tree as it is** — it is the reproducer for the trap, and if it
   cannot fail before the fix it is not testing the fix.
3. The `wake refused` line stays zero across the boot lanes, as measured.

## Unresolved questions

Whether `bind` should refuse a zero badge in the kernel-internal `irq::bind`
too, or only at the syscall boundary. In-tree callers pass constants (1, 2, 4,
1), so the check would never fire; putting it in `bind` guards a future caller,
putting it at the syscall keeps the kernel's own paths free of a check that
cannot fail. Proposed: the syscall, and a debug assertion in `bind`.

## Implementation plan

1. `notify::arm` refuses, with host tests. Gate: the tests.
2. The `BIND` syscall refuses, matching `notify_on_end`.
3. The boot probe from the testing plan, armed both ways.
4. `TRACKER.md` §7, and RFC 0010's correction recorded.
