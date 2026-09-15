# RFC 0079: a signal a process may send another

| | |
|---|---|
| **Status** | 🔨 **Draft — steps 1 and 2's prerequisite built 2026-09-15; the syscall itself is next.** `may_signal` is in `bhaskix-personality` with three armed tests. The block is gone: [RFC 0080](0080-ending-a-domain-that-is-still-running.md) gave the nucleus `END`, and the adapter now **keeps a domain capability per forked process and gives it back**, gated both ways. What is left is `kill(2)` calling the two. See *What retaining a capability actually took*. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | libc (`bin/linuxd`) |
| **Milestone** | Phase 2 — Linux personality (L1) |
| **Depends on** | [RFC 0033](0033-what-a-hosted-process-is.md) (the process record), [RFC 0031](0031-linux-compatibility-as-an-adapter.md) (compatibility is an adapter, and Linux UID 0 is not Bhaskix authority) |

---

## Summary

`kill(2)` does not exist in this adapter. A hosted shell can start a child and
wait for it and cannot stop it. This adds `kill(pid, sig)` for the signals that
need no handler, and — because the question is authority rather than syscall
numbers — states which processes a hosted process may signal and why.

## Motivation

**A shell notices this immediately.** `docs/roadmap.md`'s L1 row says what is
left is *"breadth, not shape: terminal `ioctl`s, `getdents`, `stat`, ~~a
writable path~~, and the signal gaps a shell notices"*. This is the first of
those gaps: without `kill` there is no `^C`, no `kill %1`, no way to end a
child that is not going to end itself.

What exists today is narrower than it looks. `tgkill` is handled for exactly
one case — a thread signalling **itself** with `SIGABRT`, `SIGKILL` or
`SIGSEGV`, which becomes an exit — and `rt_sigaction` records a handler for the
one fault-handling demonstration RFC 0033 built. `rt_sigprocmask` answers `OK`
and does nothing. Signal number 62, `kill`, is not in the table at all.

## The authority question, which is the whole of this RFC

Linux answers "may A signal B?" with uids: same real or effective uid, or
privilege. **That answer is unavailable here and refusing it is the point.**
RFC 0031 is explicit that Linux UID 0 is not Bhaskix authority, so a rule
phrased in uids would either be a lie or would invent an authority this system
does not have.

Two candidate rules, and the reason for the one chosen:

| rule | what it grants | why not / why |
|---|---|---|
| **Any hosted process may signal any other** | Everything in the adapter | The adapter holds every hosted process's authority; this makes a compromise of any one of them a compromise of all of them's *lifetime*. `security.md` T11 already prices what the adapter holds, and this would widen it for nothing a shell needs. |
| **A process may signal its own descendants and its own process group** | What job control is | Chosen. It is the shape the process record already has — `Process` carries `ppid` and `pgid`, and `wait4` already understands `WaitFor::Group` — so the rule is a property of a tree this adapter already maintains rather than a new table. |

**The rule, stated so it can be tested:** `kill(pid, sig)` succeeds when the
target is the caller, a descendant of the caller, or a member of the caller's
process group. Anything else is `ESRCH` — *not* `EPERM`. A hosted process
should not learn that a pid it may not touch exists, and Linux's own
`kill(pid, 0)` probe is the usual way that is discovered.

## Design

**Which signals.** `SIGKILL` and `SIGTERM` to begin with, plus `sig == 0` as
the existence-and-permission probe that changes nothing. Both fatal signals end
the target's domain and record `Exit::Signalled`, which `wait4` already reports
and which `tgkill`'s existing path already constructs — so the parent's side of
this needs no new code.

**`SIGTERM` is fatal here, and that is a limitation rather than a decision.**
On Linux it is catchable, and catching it is how a program cleans up. This
adapter records handlers but does not deliver them, so a `SIGTERM` that claims
to be catchable would be a lie; ending on it is honest and matches what a
default-disposition process does. Delivering to a handler is named in
Unresolved questions and is a separate RFC's worth of work.

**`kill(-pgid, sig)`** follows from the rule without new mechanism: a negative
pid names the caller's own group, which it may always signal.

**Not `kill(-1, sig)`.** "Every process you may signal" is exactly the breadth
the authority rule refuses, and no shell needs it to run a job.

## Alternatives considered

| | |
|---|---|
| **Give the adapter a capability per hosted domain and check *that* instead of the tree** | Written here first as *"it already holds one"*, which is false — see *Security implications*. It holds none, and it will have to hold one for `kill` to work at all. But holding one is not a rule: the adapter would hold a capability to **every** hosted domain, so a check against it is `true` for every pair and documents a boundary that does not exist. The tree is still the rule; the capability is only the means. |
| **Map Linux uids onto something** | RFC 0031 refuses this, and rightly: it would be the first thing in the adapter that invented authority rather than translating it. |
| **`EPERM` for a pid outside the rule** | Tells a caller that a process it may not signal exists. `ESRCH` is both the safer answer and the one Linux gives for a pid that is gone. |

## Impact on existing design documents

* `docs/roadmap.md` L1 — the first of the named signal gaps closes; the row
  should say which remain.
* `docs/security.md` T11 — the adapter's reach grows by "may end a hosted
  process's domain on another's request, within the tree". Worth a sentence,
  because T11 prices what a compromise of the adapter costs.
* `docs/rfc/0033` — the process record gains a use for `ppid` beyond `wait4`.

## Security implications

**The adapter does not hold the authority this RFC assumed it held**, and that
is the largest thing found while drafting it. The first version of this section
said `kill` would be "the adapter exercising authority it already holds on a
caller's behalf, which is what every other hosted syscall does". It is not.

`adapter::CHILD` is **one slot**, documented as *"where an `execve` holds the
domain it is building, one at a time"*, and `answer_fork` does
`method::DELETE` on it as soon as the child is built. The adapter therefore
holds **no capability naming a running hosted process's domain**, and in a
system whose whole claim is that there is no ambient authority, that means it
cannot end one. A `kill` implemented today could record an exit and wake the
parent's `wait4` while the target kept running — which is not a signal, it is
a lie told to the parent.

**So step 2 is blocked on a decision this RFC has to make rather than assume.**
Three ways out, none free:

| | |
|---|---|
| **The adapter retains a domain capability per hosted process** | Honest and simple, and it widens what `security.md` T11 prices: a compromise of the adapter would gain the power to end every hosted process, where today it gains their files and descriptors. It also costs a capability slot per process, against a fixed table. |
| **Cooperative delivery: the target notices a pending signal at its next syscall** | Costs the adapter nothing and cannot implement `SIGKILL`, which must be immediate and uncatchable. A process spinning without syscalls would ignore it for ever, which is a worse lie than not having `kill`. |
| **The nucleus lets a domain's creator end it without holding a capability** | Ambient authority by another name, and refused on the same grounds RFC 0031 refuses Linux UID 0. |

**The first is the only honest one**, and it should be argued for what it costs
rather than slipped in: the adapter would keep, for each hosted process, a
capability it needs only to kill. **Chosen 2026-09-15.**

### And a capability is necessary without being sufficient

Retaining one gives the adapter something to name. It does not give it anything
to *do*, and that was found only by going to build it.

**Ring 3 cannot end a running domain.** The whole domain method set the syscall
layer accepts is `BIND`, `INFO` and `RELEASE`. `RELEASE` is `domain::reap`,
which refuses while `domain.live` — it collects a domain that has already
ended. `DELETE` empties a capability slot and leaves the object alone;
`cap::remove` is `self.slots.get_mut(index)?.take()`. `domain::destroy` exists
and is what would be wanted, and its only callers are kernel-internal — in
`spawn`, as the cleanup path when creation fails.

So step 2 needs a **new nucleus operation**: a method on a `Domain` capability
that ends a live domain. `domain::destroy` already promises what makes that
safe — *"the revocation completes before this returns … a destroyed domain's
grants are dead everywhere, not scheduled for cleanup"* — so this is exposing
an existing, careful primitive rather than writing a new one. It is still a new
authority in the nucleus and wants its own argument: what it means for a domain
whose threads are running on other CPUs, and whether a caller holding the
capability is sufficient or a further check belongs there.

Until that exists, `may_signal` is a rule with nothing to enforce it, and step 2
cannot be written honestly. Specified as [RFC 0080](0080-ending-a-domain-that-is-still-running.md), which carries the argument for exposing `domain::destroy` and the three questions it opens — chiefly what ending a domain means when its threads are running on other CPUs, which `spawn`'s failure path never has to face.

**What does not change.** The boundary is still the process tree, checked in
the adapter by `may_signal`, and a hosted process still cannot reach another's
domain directly. The new exposure, if the first option is taken, is that a
compromised *adapter* can end hosted processes — which a compromise of the
adapter arguably implies anyway, and which T11 should say out loud rather than
leave to a reader.

## What retaining a capability actually took

Built 2026-09-15, and written here because three of the four things it took
were not visible from the design.

**A pool, allocated the other way from the files.** `adapter::DOMAIN_FLOOR` is
`FILE_TOP + 1` and `DOMAIN_COUNT` is 32, allocated **upward** where the file
slots are allocated downward from the top, so the two pools grow apart rather
than into each other. 32 is `MAX_PROCESSES`, asserted in the nucleus beside the
ABI assertions rather than left as two numbers that happen to match.

**Derived, not moved, and the difference is the whole of it.** `answer_fork`
builds the child in `adapter::CHILD`, which is one slot reused by the next
fork. The capability that survives is a `DERIVE` of it carrying every right the
parent holds — a derived capability may not gain what its parent lacks, and
`rights` has no `ALL`, so they are named. `DELETE` on `CHILD` afterwards empties
that slot and leaves the derived one alone; the cascading destruction is
`REVOKE`, a different method.

**A failed derive must give the slot back, and `filter` does not.** The first
version read `claim_domain_slot().filter(|slot| derive_succeeded)`, which drops
the `Some` and leaves the slot marked held with nothing in it — a fork whose
derive failed would cost a slot for the rest of the boot. **Found by arming the
gate rather than by review**: forcing the derive to fail printed `2 held, peak
2` where it should have shown nothing kept. It is `and_then` with an explicit
release now, and the peak is counted where a capability is really held rather
than where a slot is reserved, so the arming reads `peak 0` as it should.

**And a process can end without the adapter being told.** `note_exit` releases
the slot for a process that calls `exit_group` or takes a fatal fault, and the
`FORGET` message catches one killed from outside — but `FORGET` arrives when the
domain slot is *reused*, which may be never. A hosted thread calling plain
`exit(2)` reaches neither, and the fork probe's child does exactly that: the
tail of `FORK_PROBE_CODE` is `mov eax, 60; syscall`. The adapter cannot answer
that call by recording a process exit, because `clone` exists and the thread
ending need not be the last one — recording an exit there would wake a parent's
`wait4` for a process still running, which is the lie this RFC exists to refuse.

**So it asks instead of being told.** The kept capability names the domain, and
`INFO` on a domain answers `0` while it lives and its `Ending` afterwards, so
`reclaim_domain_slots` sweeps every held slot and releases the ones whose
process has gone. It runs before each claim, which means no fork can ever fail
for want of a slot belonging to a process that has ended. A slot is therefore
returned **at once** for a process that exits the ways the adapter sees, and **by
the next fork** otherwise — the same shape of bound RFC 0058 states for sockets,
and stated here rather than rounded to "released".

**Cost**: one `unsafe` line, the accessor for the slot table, taking
`bin/linuxd`'s exact budget from 117 to 118. The capabilities themselves cost
none — they are derived, held and deleted through invocations, and nothing is
dereferenced.

**Containment must be asserted, not assumed.** Two boot gates below assert a
refusal rather than a permission, for the reason RFC 0060's write path does: a
containment test that passes on absence tests nothing.

## Performance implications

A pid lookup in the process table on a path that is not hot, and a domain
ending that already exists. Nothing to measure.

## Testing plan

1. A hosted probe forks a child, kills it with `SIGTERM`, and `wait4` reports
   `Signalled` with the right number. Armed by dropping the signal.
2. The same with `SIGKILL`.
3. **Containment, and it is the gate that matters**: a hosted process attempts
   `kill` on a pid outside its tree — the pid of another probe — and must get
   `ESRCH`, with the target still alive afterwards. Armed by removing the tree
   check, which must turn it red and leave the target dead.
4. `kill(pid, 0)` answers `OK` for a pid in the tree and `ESRCH` for one
   outside, changing nothing either way.
5. ~~Host tests in `bhaskix-personality` for the rule itself — caller,
   descendant, group member, stranger — armed one at a time.~~ **Done.**
6. ~~A capability is kept while a hosted process lives and given back after.~~
   **Done.** The boot report carries both numbers, because neither proves the
   other: `0 of 32 kept now` alone cannot tell *released properly* from *never
   kept*, which is how it was first read while the kernel's reader was
   truncating the record to six words and the count was always zero whatever
   the adapter wrote.

## Unresolved questions

1. **Delivering a signal to a handler that `rt_sigaction` recorded.** That is
   the difference between `SIGTERM` being fatal here and being catchable, and
   it needs a way to run a hosted process's handler on a stack it owns —
   which RFC 0033's fault path does for `SIGSEGV` and which would have to
   become general. Separate RFC.
2. **`SIGSTOP`/`SIGCONT`.** A shell's job control wants them; a domain has no
   stopped state today, so they would be invented rather than translated.
3. **Whether a descendant's descendant counts.** The rule says "descendant",
   and the record has `ppid`, so the walk is upward and bounded by the tree's
   depth. Proposed: yes, and bounded by a depth limit so a cycle — which the
   record should make impossible and which nothing currently asserts — cannot
   hang the adapter.

## Implementation plan

1. ~~The rule, in `bhaskix-personality`, as a pure function over the process
   table: `may_signal(caller, target) -> bool`. Host tests, armed.~~ **Done
   2026-09-15**, three tests, each armed.
2. ~~The adapter retains a domain capability per hosted process, and gives it
   back.~~ **Done 2026-09-15** — see *What retaining a capability actually
   took*. One boot gate, both halves armed: forcing the derive to fail reads
   `peak 0`, and removing the releases reads `2 held, peak 2`.
3. `kill(2)` in `bin/linuxd`, calling `may_signal` and then `method::END` on the
   kept capability, for `SIGKILL`, `SIGTERM` and `0`.
4. The probe and the three boot gates, each watched red.
5. ~~`security.md` T11~~ **done 2026-09-15** — the note prices the widening at
   "a compromised adapter can end every hosted process". `roadmap.md` L1 and
   `TRACKER.md` §7 when the syscall lands.
