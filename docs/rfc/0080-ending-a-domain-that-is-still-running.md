# RFC 0080: ending a domain that is still running

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-09-15 — built and gated, with one refusal implemented and not gated, which is said below rather than glossed.** A supervisor ends a child that spins in ring 3 making no system call, and the gate asserts it reported `Killed` rather than that the call returned `Ok`. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (`syscall`, `domain`) |
| **Milestone** | Phase 2 — core operating system |
| **Depends on** | [RFC 0017](0017-process-management.md) (the domain lifecycle), and needed by [RFC 0079](0079-a-signal-a-process-may-send-another.md) |

---

## Summary

A domain ends when its last thread exits. Nothing in ring 3 can end one that is
still running — not the supervisor that created it, not the holder of its
capability. This adds one method that does, on the capability that already
names the domain.

## Motivation

**`TRACKER.md` says this exists and it does not.** The PM1 row reads *"Create,
grant, start, kill, reap — each an operation on a capability, none a new syscall
kind"*. Four of those five are operations on a capability. `kill` is not, and
the row is corrected as of 2026-09-15. What the syscall layer accepts on a
`Domain` is `BIND`, `INFO` and `RELEASE`; `RELEASE` is `domain::reap` and
refuses while the domain is live, and `DELETE` empties a capability slot and
leaves the object alone.

**[RFC 0079](0079-a-signal-a-process-may-send-another.md) is blocked on it.** A
hosted `kill(2)` has a rule for who may signal whom — `may_signal`, built and
armed — and nothing to enforce it with. A `kill` that recorded an exit and woke
the parent's `wait4` while the target kept running would not be a signal; it
would be a lie told to the parent.

**And a supervisor that cannot stop what it started is not a supervisor.** RFC
0017's model says so in its own list. Today a child that will not exit runs
until the machine does.

## Design

**One method, `method::END = 74`, on a `Domain` capability.** It maps to
`domain::destroy`, which already exists and is already used on the kernel's own
paths — `spawn` calls it when a creation fails part-way.

**The capability is the authority, which is the whole model.** Holding a
`Domain` capability already means holding the right to grant into it, start a
program in it, and reap it. Ending it is not a larger power than starting it,
and a check beyond "the caller holds this capability" would be inventing a
second authority system beside the one RFC 0008 settled.

**What it promises is already written.** `domain::destroy`'s contract is that
*"the revocation completes before this returns — `docs/security.md` §2 rule 3 —
so a destroyed domain's grants are dead everywhere, not scheduled for
cleanup"*. That is the property that makes this safe to expose: a caller that
has been told the domain is gone cannot then find one of its grants still live.

**It does not reap.** `END` ends; `RELEASE` collects. Keeping them apart is
what lets a parent read the ending — `INFO` answers `Ending` — before the slot
is recycled, which is exactly what `wait4` needs on the hosted side.

**Ending an already-ended domain answers `Ok`**, not an error. The caller's
intent is that the domain not be running, and it is not. An error there would
make every caller write the same race-handling around it.

## Alternatives considered

| | |
|---|---|
| **Let `DELETE` on a domain capability end the domain** | Overloads a method whose meaning is "drop this capability" with one that destroys an object. Two holders would then mean two different things by the same call, and a holder tidying its slots would kill a domain by accident. |
| **A new syscall kind** | RFC 0008 fixes the set at six and this is an operation on a capability, which is what `Invoke` is for. |
| **Let only the creator end it** | The kernel would have to record a creator, which it does not, and it would make a granted capability weaker than the one it was derived from for no stated reason. |
| **Leave it to RFC 0079 and let the adapter do something else** | There is nothing else it can do: cooperative delivery cannot implement `SIGKILL`, and that was weighed and refused there. |

## Impact on existing design documents

* `TRACKER.md` PM1 — already corrected to say `kill` is in the model and not in
  the ABI; when this lands it becomes true and the strike-through comes off.
* `docs/rfc/0017` — the lifecycle gains the operation its own list names.
* `docs/security.md` §2 — the revocation rule is the one this relies on, and
  should be cited from here rather than restated.
* `docs/rfc/0079` — unblocked, and its Security section should then say that
  the adapter holds this power over every hosted process.

## Security implications

**This grants nothing new to a holder.** A `Domain` capability already carries
the right to place a program in the domain and start it. A holder that wanted
it stopped could already achieve it by starting a program that exits; what it
could not do is stop a program already running, which is the gap.

**It widens what a compromised holder can do**, and that is worth stating
plainly: `bin/sup` and, after RFC 0079, `bin/linuxd` would be able to end the
domains they created. For the adapter that is the point; `security.md` T11
prices what a compromise of it costs and should gain a line.

**The revocation is the dangerous part and it is not new.** `domain::destroy`
already runs on kernel paths; this changes who can ask, not what happens.

## Performance implications

None on any existing path. The method is not on a hot path, and `destroy`'s
cost is what it already is where the kernel calls it.

## Testing plan

1. A supervisor spawns a child that loops for ever, ends it with `END`, and
   reaps it. The gate is that the child **stopped** — a counter it increments
   stops moving — and not merely that `END` answered `Ok`. Armed by dropping
   the `END`, which must leave the counter moving and the reap refusing.
2. ~~`INFO` after `END` and before `RELEASE` answers `Killed`.~~ **Done.** The
   gate asserts `reason 3`, and arming `destroy` to record `Ending::Exited`
   turns it red reading `reason 1` — so the number is what separates *it
   ended* from *it was ended*.
3. ~~`END` on an already-ended domain answers `Ok`.~~ **Done.** The supervisor
   ends its child twice and the gate requires the second to be accepted; making
   that arm error turns it red.
4. **`END` on a domain capability naming the caller's own domain is refused,
   and that refusal is not gated.** It is implemented — the arm compares the
   target against the caller and answers `WrongObject` — but **no program in
   this system holds a capability to its own domain**, so nothing in ring 3 can
   attempt it. Gating it means granting one to `bin/sup` for the purpose, which
   is what `bin/shell`'s capability self-test does for every other refusal it
   asserts, and is the cheapest way to close this. Stated here rather than left
   for a reader to assume the refusal is tested because the others are.
5. Host tests for `domain::destroy`'s existing contract are already there; this
   adds none, because it adds no mechanism.

## Unresolved questions

1. ~~**A domain whose threads hold kernel locks.**~~ **Answered from the source,
   2026-09-15, and the design is already there.** `domain::end` calls
   `sched::mark_domain_dying`, which takes every runqueue lock in turn —
   blocking rather than `try_lock`, because *"skipping a contended queue loses
   a thread, and a lost thread is a domain that reports itself destroyed while
   part of it is still running"* — marks each of the domain's threads `dying`,
   and wakes the blocked ones so they can notice.

   A thread is then stopped at a **safe point**, not where it stands.
   `syscall.rs` states why: killing it the moment its domain died *"would
   instead catch it mid-derivation or half-way through a rendezvous, and free
   the stack it was standing on"*. The two safe points are the return from a
   system call and an interrupt returning to ring 3, and the second bounds the
   first: a ring 3 thread that is not making system calls *"is caught within a
   tick"*.

   And a dying thread may not sleep. `sched` asserts it: *"a thread told to
   stop must not go to sleep: sleeping is the one state with no next safe
   point"*.

   **So the answer this RFC needed is that ending a domain with threads on
   other CPUs is bounded by one timer tick**, and the invariant that makes it
   safe is already written and already tested. What this RFC exposes is a
   caller for a mechanism that is finished, which is a much smaller claim than
   the one it started with — and it means the gate in the testing plan should
   allow a tick before asserting the counter has stopped, rather than reading
   it immediately and calling a scheduling delay a failure.
2. **Whether a domain may end itself** by invoking `END` on a capability to
   itself. `Exit` already exists for that and is the honest way; this should
   probably refuse, and the refusal wants a test.
3. **What a hosted process's `wait4` reports** when the adapter ends a domain
   this way is RFC 0079's question, not this one, but the two want reading
   together.

## Implementation plan

1. `method::END = 74` in the ABI, with the `Domain` arm in `syscall.rs` calling
   `domain::destroy`. The refusals first, because they are the cheap half.
2. The supervisor gate: spawn a looping child, end it, assert it stopped.
   Watched red by dropping the `END`.
3. `INFO`-after-`END` and the already-ended case, each armed.
4. ~~Question 1 answered in writing before this is accepted, not after.~~ Done before any code, and it removed the RFC's largest unknown rather than confirming it.
5. `TRACKER.md` PM1 and §7, `docs/rfc/0017`, `docs/security.md` T11.
