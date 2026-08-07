# RFC 0017: Process management — a domain that can be created, killed, and reaped

| | |
|---|---|
| **Status** | 📝 **Draft.** |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | `kernel/domain`, `kernel/sched`, `kernel/trap`, `kernel/ipc`, ABI, a supervisor |
| **Milestone** | Phase 2 in [roadmap.md](../roadmap.md) — closes the *process management* bullet, and M5's unmet exit criterion |
| **Depends on** | [RFC 0008](0008-syscall-and-ipc-shape.md) (six syscall kinds), [RFC 0009](0009-shared-memory.md) (revocation), [RFC 0010](0010-notifications.md) (how death is reported), [RFC 0011](0011-irq-handler.md) (the control-object shape), [RFC 0013](0013-service-framework.md) (whose question 1 this answers) |

---

## Summary

This system has domains, and it cannot make one, stop one, or find out that one died.

Every domain in the tree is created by boot code — all twenty-one calls to `domain::create` are in
`kernel/src/lib.rs`, so the set of programs that can ever run is fixed when the kernel is compiled.
`destroy` releases a domain's memory, its interrupt handlers and its capabilities, and leaves its
threads running. And a fault in ring 3 does not kill the program; it halts the processor the
program was on, permanently, and leaks everything the program held.

That last one is not a design position, it is a leftover. `trap.rs` still says *"Every exception is
fatal at M2 — there is no memory manager to service a fault and no scheduler to kill a task."* Both
of those have existed since M3 and M4.

This RFC proposes the smallest set of mechanisms that make a domain a thing with a lifetime:
**create, start, kill, reap** — each an operation on a capability, none of them a new syscall kind.
It deliberately does **not** propose `fork`, a pid, or signals, and §*Alternatives* argues why each
of those is the wrong shape for this system rather than merely unfashionable.

---

## Motivation

Four things are broken or missing, and they are separate problems that share one solution.

### A fault in ring 3 costs a processor and leaks a domain

Demonstrated, not inferred. A temporary `crashme` command was added to the user-mode shell, writing
through a null pointer from ring 3:

```
bhaskix$ crashme

==================================================================
  EXCEPTION: page fault (#PF)
==================================================================
  vector 0x0e   from USER mode
  error code 0x0000000000000006
  faulting address 0x0000000000000000   (cr2)
    page not present while writing in user mode
    address is in the first page: this is a null pointer dereference

  thread 36 (usershell) expects space 0xf5c0000, cr3 holds 0xf5c0000
  ...
  Halting. Every exception is fatal at M2 -- there is no memory
  manager to service a fault and no scheduler to kill a task.
```

The diagnostic itself is good and this RFC keeps all of it. What is wrong is the last line, and it
is worth being exact about *how* wrong, because the first version of this section overstated it.

`halt_forever` is `loop { disable_interrupts(); halt(); }` — **it halts the CPU it runs on, not the
machine.** Measured afterwards, by putting a deliberate ring 3 fault into the boot sequence on a
four-processor machine: the boot carried on and every later gate printed. So what a fault in ring 3
actually costs is:

- **The processor, permanently.** It halts with interrupts disabled, so no timer and no IPI can ever
  wake it. On a one-CPU machine that is the whole machine, which is why the gate for this runs on
  one CPU. On four, it is a quarter of them per faulting program.
- **The domain, leaked.** `destroy` is never called: the capabilities stay live, the memory stays
  charged against an envelope nobody will release, and the domain occupies a slot in a table with
  32 of them.
- **The thread, never stopped.** It is still `Running`, on a processor that will never run anything
  again.

That is a denial of service rather than an instant kill, and it is still unacceptable: an
unprivileged program holding no capabilities can consume a processor and a domain slot, permanently,
by dereferencing a null pointer. Four of them end the machine.

The reason it *looked* like an instant kill is that the program used to demonstrate it was the
shell, which is the only thing producing output — so "nothing printed afterwards" and "the machine
stopped" are indistinguishable from the console. They are not the same, and this RFC says so rather
than keeping the more dramatic claim.

**This is [roadmap.md](../roadmap.md)'s M5 exit criterion**, which reads: *"a user-mode program runs,
invokes capabilities, is denied what it does not hold, and **is killed cleanly when it faults**."*
M5 is recorded as `COMPLETE`. The first three clauses are gated; the fourth has never been true and
has never been tested — all six faults in `tests/qemu/fault-test.sh` are injected from kernel mode,
so no test in this project has ever faulted from ring 3. TRACKER should say so, and this RFC's step
1 is what closes it.

### Nothing can create a domain

`domain::create` takes a `&'static str`, which is by itself a statement that the caller is compiled
into the kernel. There is no capability meaning *"may create a domain"*, so there is no way for a
program to start another program, and the service framework's placement table is the only thing that
decides what runs.

RFC 0013 stopped exactly here, and said so: it *"does not propose a general supervisor, an init
system, or a restart policy… Restart policy is a separate argument with its own failure modes, and
putting it here would make this RFC about that."* This is that separate argument.

### Threads are counted, not owned

`kernel/src/domain.rs` documents this against itself:

> **Threads are counted, not owned.** Destroying a domain does not yet stop its threads; it releases
> its accounting and revokes its authority. A thread that outlives its domain holds no capabilities,
> which contains it, but it still runs.

Containment by capability is real and it is not sufficient. A thread with no capabilities still
holds a kernel stack, still occupies a runqueue slot, still consumes CPU that the envelope has
stopped accounting for, and — most awkwardly — may be *inside a system call* when its domain is
destroyed, holding a lock that the rest of the kernel is waiting on.

### A caller whose service died waits for ever

RFC 0013's unresolved question 1, verbatim:

> Today an endpoint whose holder has gone leaves the caller blocked for ever… the fix needs a
> mechanism that does not exist: an endpoint that reports when the capability reaching it is
> revoked.

This is the same problem as the three above: nothing happens when a domain ends, because ending is
not an event. Once it is, the blocked caller is woken as part of it.

---

## Design

### The shape: create, grant, start — never fork

A new domain is made in three explicit steps, and there is no operation that means *"another one of
me"*:

1. **Create.** A holder of a `DomainControl` capability asks for a `Domain`. It comes back empty: no
   threads, no capabilities, no address space, an envelope no larger than the creator's own.
2. **Grant.** The creator transfers exactly the capabilities the child should have, one at a time,
   using the `GRANT` that already exists. This is the only way authority enters a domain.
3. **Start.** The creator names an entry point and a stack, and the domain gets its first thread.

The child's authority is therefore the sum of deliberate acts, each of which is a capability
operation that already has rules and tests. Nothing is inherited, because there is no mechanism by
which anything could be.

`DomainControl` → `Domain` is the same shape this project has used twice already: `IrqControl` hands
out `IrqHandler` ([RFC 0011](0011-irq-handler.md)), `IommuControl` hands out `DmaWindow`
([RFC 0012](0012-iommu.md)). Using a third shape here would be a reason to re-examine the first two.

### The process tree is the capability tree

There is no pid, no parent pointer and no process group. **Whoever holds a `Domain` capability is
that domain's parent**, and a domain may have several parents in the sense that several holders can
act on it — which is not a defect, it is what a capability means.

The tree already exists and is already transitive. `domain::create` documents its own root
capability as *"the root of everything it will ever be granted, which is what makes destruction
total: revoking it revokes the whole derived subtree, in every other domain's CSpace, before
`destroy` returns."* A child domain's capability is derived from its creator's, so killing a parent
already kills every descendant, through machinery that is built and negative-tested.

This is the whole answer to "process trees" in the roadmap bullet. It costs one line of new
structure: none.

### Death, and the four ways it happens

A domain ends for exactly four reasons, and the distinction is recorded because a supervisor's
restart policy is a different decision for each:

| Reason | Cause |
|---|---|
| `Exited` | Its last thread called the exit syscall |
| `Faulted` | A thread took an exception in ring 3 |
| `Killed` | A holder of its `Domain` capability said so |
| `Envelope` | It asked for a resource its envelope refuses, on a path that cannot return an error |

`Faulted` keeps the entire diagnostic that exists today. It stops calling `halt_forever` and starts
killing one domain, and the report gains the one fact it currently cannot state: *which domain this
was, and that the rest of the machine is still running.*

### Killing a thread that is inside the kernel

This is the hard part of the RFC and the reason for the step order in the implementation plan.

A thread cannot be deleted at an arbitrary moment. It may hold a runqueue lock, be halfway through a
capability derivation, or be blocked in an IPC rendezvous another thread is about to complete.
Freeing its stack at that point corrupts whatever it was doing to a data structure the rest of the
kernel shares.

**A dying thread is therefore marked, not deleted.** `Dying` is a state, and the thread stops at the
next point where it holds nothing:

- **Returning to user mode.** Checked in the syscall and interrupt exit paths, where by construction
  no kernel lock is held.
- **Blocking.** A thread about to sleep on an endpoint or a notification dies instead.
- **Already blocked.** Woken with `Status::Revoked` rather than its expected reply, and dies on the
  way out — which is also the fix for the blocked-caller problem below.

A thread spinning in ring 3 dies at the next timer interrupt, so the bound is one tick. A thread
spinning *in the kernel* does not die at all, and this RFC does not pretend otherwise: that is a
kernel bug, and the honest response is that the machine has one, not a preemption mechanism that
papers over it.

### A caller whose service died

When a domain ends, every thread blocked on an endpoint that domain was serving is woken with
`Status::Revoked`. This answers RFC 0013's question 1, and it falls out of death being an event
rather than needing the "endpoint that reports revocation" that RFC 0013 could not find — the
endpoint does not need to report anything, because the domain's death already walks the structures
that name it.

The caller sees a call that failed. It does not see *why*, beyond "the thing you called is gone",
and that is deliberate: a status that distinguished "crashed" from "was killed" would let any client
of a service infer things about a domain it does not hold a capability to.

### Reaping, without a new mechanism

A `Domain` capability can have a **`Notification` bound to it** ([RFC 0010](0010-notifications.md)),
signalled once when the domain ends. The holder waits on the notification it already knows how to
wait on; `INFO` on the `Domain` capability then returns the state and the reason from the table
above.

No new blocking primitive, no wait queue, no `SIGCHLD`. A supervisor is then an ordinary program:
hold the `Domain` capabilities, wait on the notifications, ask what happened, decide.

**Reaping is what releases the slot.** A domain that has ended but not been reaped keeps its entry
in the table and its exit reason, or the answer to "what happened to it" would be a race against
whoever asked. A domain whose last capability is deleted is reaped automatically, because at that
point nobody can ask.

### The envelope has to cover children

`MAX_DOMAINS` is 32. A domain that can create domains can exhaust that table, and every other domain
on the machine then cannot start anything — which is `security.md` §1 **T10**, the threat the
`ResourceEnvelope` exists to answer, reopened by the feature this RFC adds.

So the envelope gains a **child-domain count**, charged to the creator when a domain is created and
released when it is reaped. Charged to the *creator*, not the child, because the resource being
protected is the shared table and the creator is who consumes it.

`domain.rs` already states the rule this must follow: the envelope *"refuses. It does not warn, it
does not reclaim, and it does not succeed and notify."*

### What a domain is named

`create` takes a `&'static str` today, which cannot come from user memory. A domain created at
runtime gets a fixed-size inline name copied from the caller, truncated rather than refused — a
name is a diagnostic aid, and failing to start a program because its name is long would be a worse
outcome than a short name in a report.

---

## Alternatives considered

| Alternative | Why not |
|---|---|
| **`fork`** | It duplicates an address space *and, by implication, a capability space*. The child gets everything the parent had because of what it is rather than because anyone granted it, which is ambient authority arriving through the back door of a system built to refuse it. It also forces an answer to what happens to every capability with a side effect, and every answer is arbitrary. Create-grant-start expresses the same intent in three steps that are each already checkable |
| **`posix_spawn`-shaped single call** | One call that creates, populates and starts is simpler to use and impossible to check: the grant step is where the interesting refusals live, and folding it into creation means a failure part-way leaves a domain that half-exists. The three steps are separable precisely because the middle one can fail |
| **Signals** | A POSIX signal is an asynchronous interrupt delivered to a process named by an integer, with ambient authority to send it, running a handler on a borrowed stack under async-signal-safety rules that most programs get wrong. The two things signals are actually used for are covered: "stop" is `KILL` on a capability you hold, and "something happened" is a `Notification` the domain holds. Neither needs re-entrancy |
| **Kill immediately, wherever the thread is** | Corrupts any structure the thread was modifying. The `Dying` state costs a check on two paths that are already the exit paths |
| **A supervisor in the kernel** | Restart policy is policy — how many times, how fast, what counts as failure. `ai-native.md` §0's rule that the kernel decides and the model advises applies to any policy, not just AI: the kernel provides create, kill and reap, and a program decides what to do with them |
| **Reference-counted automatic reaping only** | Loses the exit reason, which is the one piece of information a supervisor needs. Kept as the *fallback* when the last capability goes away, since at that point nobody can ask |

---

## Impact on existing design documents

- **[roadmap.md](../roadmap.md)** — closes the *process management* bullet. Its **M5 exit criterion
  is currently unmet**, and this RFC's step 1 is what meets it. That should be recorded in TRACKER
  rather than quietly fixed, because M5 is marked `COMPLETE`.
- **[architecture.md](../architecture.md) §4** — domains gain a lifetime. The document describes
  what a domain *is* and says nothing about how one begins or ends.
- **[security.md](../security.md) §1 T10** — the envelope extends to child domains. Without that,
  this RFC reopens the threat.
- **[scheduler.md](../scheduler.md)** — a `Dying` thread state, and what the scheduler does with one.
- **[RFC 0013](0013-service-framework.md)** — its unresolved question 1 is answered here.
- **`kernel/src/domain.rs`** — the "What is not here" list loses *"threads are counted, not owned"*.
- **`kernel/src/trap.rs`** — the comment claiming every exception is fatal *"at M2"* stops being
  true, three milestones after it stopped being a reasonable thing to say.

---

## Security implications

**This RFC hands out the ability to start programs, and that is a real increase in what a compromised
domain can do.** Three things bound it:

1. **A child is never stronger than its creator.** It starts empty, and every capability it gets is
   one the creator held and chose to pass. This is the existing `GRANT` rule and needs nothing new.
2. **The envelope covers children**, so "start programs until the table is full" is a refusal rather
   than a denial of service against every other domain.
3. **`DomainControl` is not ambient.** A domain that was not given it cannot create anything, and
   the shell — the most exposed program in the tree — should not be given it.

The one genuinely new exposure is **the exit reason**, which tells a holder something about a
program it did not run. That is why the reason is available only through the `Domain` capability and
never through the endpoint: a client learns that its call failed and nothing more.

**A supervisor is a high-value target** in a way nothing in this system currently is, because it
holds `Domain` capabilities for everything it started. That argues for it being small, and for it
being one of the first programs written against the "no `unsafe`" discipline the user programs
already follow.

---

## Performance implications

Creating a domain is not on any hot path and is not optimised. What must not regress:

- **The syscall exit path** gains one check of a per-thread flag. It is a predictable branch on a
  path that already touches that cache line.
- **Killing a domain** walks its threads, its endpoints' wait queues, and its capability subtree.
  The subtree walk already exists in `destroy`. This is bounded by what the domain holds, and it
  happens with the domain already unable to run.
- **`Dying` costs nothing when nothing is dying**, which is the common case by an enormous margin.

---

## Testing plan

Every gate below must be watched failing before it counts, per this project's rule that a check
nobody has seen fail is not a check. The negative test is named with each.

| Gate | Negative test |
|---|---|
| A ring-3 fault kills its domain and the machine keeps running: the shell faults, the console and filesystem services still answer, and a second shell can be started | Restore `halt_forever` on the user-mode path — the machine stops and every later gate fails |
| The fault report names the domain that died and says the machine survived | Remove the name — the report is the one that exists today, which cannot distinguish two programs at the same address |
| A killed domain leaks nothing: create and kill 1000 domains, free-frame count returns exactly to baseline | The M3 frame-leak harness, reused. Leak one stack per kill and the count drifts by 1000 |
| A domain killed while its thread is **inside a syscall** dies at the boundary: the thread stops, and the lock it held is free | Kill at the fault point instead of marking `Dying` — the next acquirer of that lock hangs |
| A caller blocked on a killed service is woken with `Status::Revoked` | Skip the wake — the caller blocks for ever, which is today's behaviour and RFC 0013's question 1 |
| The envelope refuses a child that would exceed the creator's budget | Remove the charge — a domain creates until `MAX_DOMAINS` is gone and no other domain can start |
| Reaping distinguishes `Exited` from `Faulted` from `Killed` | Report one reason for all three — the gate passes on the count and fails on the reason, which is why it asserts the reason |
| A domain whose last capability is deleted is reaped without anyone waiting | Drop the fallback — the table fills with domains nobody can ask about |

The first gate is the one that matters, and it is worth stating what it proves: **an unprivileged
program can no longer stop this machine.**

---

## Unresolved questions

1. **What kills a domain whose thread is spinning in the kernel?** Nothing here does, and the
   position taken is that such a thread is a kernel bug rather than a case to be handled. If
   experience says otherwise the answer is probably a watchdog, which is its own RFC.
2. **Does the shell get `DomainControl`?** It would let `elf` start a program in its own domain,
   which is the obvious next demonstration and also hands the most exposed program in the tree the
   ability to make more. Deferred to the step that needs it.
3. **What restarts a service that died?** Not this RFC — the same boundary RFC 0013 drew, for the
   same reason. This provides the mechanisms a restart policy would be written against.
4. **Should `MAX_DOMAINS` stay fixed at 32?** It is fixed so that creating a domain cannot fail for
   want of heap during memory pressure, which is a good reason. Whether 32 is the right number is
   a separate question from whether the limit should be static.

---

## Implementation plan

Six steps. **Step 1 is worth doing alone** and does not depend on the rest — it closes a documented,
currently-false exit criterion, and it is the difference between a program crashing and a machine
crashing.

1. **A ring-3 fault kills its domain, not the machine.** The `Faulted` reason, the report keeping
   everything it says today plus the domain's identity, and the machine continuing. Needs step 2's
   thread ownership only for the threads of the domain that died, which is the narrow case.
2. ~~**Threads are owned.**~~ ✅ **Done**, except for the stacks — see below. `destroy` marks every
   thread of the domain and wakes the sleeping ones; each stops at its next safe point.

   **A flag, not a fifth `State`.** A dying thread is still `Ready`, `Running` or `Blocked` — it has
   not stopped yet, and everything reasoning about runnability, load and eviction must keep seeing it
   as what it is. A `State` variant would have to be handled by all of them, and the ones that forgot
   would be the interesting bugs. Host-tested: marking a thread dying does not change the load figure.

   **Two safe points, and they are not equally provable.** The gate runs a domain with three threads
   in ring 3 — one that faults, one that spins making no system call, one that does nothing but
   `yield` — and asserts all three are gone. Deleting the interrupt-return check is caught
   immediately and names the survivor: `spinner`, which has no other door. Deleting the
   syscall-return check is **caught by nothing**, because a thread returning from a system call
   returns to user mode, where the interrupt check catches it a tick later. That check is kept for
   promptness and because step 3 needs it, and the code says so rather than implying it is gated.

   **Sleeping is refused rather than interrupted.** A dying thread is not marked `Blocked`, because
   sleeping is the one state with no next safe point. This is also why waking the already-blocked
   ones is the whole mechanism rather than a courtesy — and it is most of step 3 arriving early.

   **Not done: kernel stacks.** `reap_finished` frees a thread's slot and leaves its stack, because
   there is no allocator for stack slots. That is older and larger than this step, and it is recorded
   as outstanding rather than folded in here.
3. ~~**A blocked caller is woken when its server dies.**~~ ✅ **Done.** RFC 0013's question 1, open
   since M7, and it was **not** small — step 2 turned out to have a hole that only this step's test
   could see.

   **The hole.** `take_message_or_block` writes `State::Blocked` directly rather than going through
   `mark_blocked`, so it never learned step 2's rule. A dying thread asleep on an endpoint was woken,
   found nothing, and blocked again — for ever. Step 2 therefore stopped every thread *except the
   ones asleep in IPC*, which is most of the interesting ones, and its gate could not see it because
   none of its three threads ever blocked. Watched failing: with the check removed, the domain's
   server survives its own domain's destruction.

   **The obligation is what dies, not the endpoint.** A caller blocked in `Call` cannot work this out
   for itself: the endpoint is still there, the capability is still good, and something else may
   serve it tomorrow. So `exit` takes the dying thread's `reply_to` and tells that caller directly.
   The status is **`Revoked`** and not "no such endpoint", because a caller that believed the latter
   would throw away a capability that is still perfectly valid — watched failing by reporting the
   endpoint gone instead, which fails that check and only that one.

   This is also where the syscall-return safe point earns its keep: the woken caller is *in the
   kernel*, and the call it returns from is where it finds out.
4. **`DomainControl`, and creating a domain from ring 3.** The control object, the inline name, and
   the envelope charging children to their creator — the last of which is not optional, because
   without it this step reopens T10.
5. **Starting a program.** Entry point, stack, and the first thread; the ELF loader reachable from a
   domain rather than only from boot code.
6. **Reaping.** The notification bound to a `Domain` capability, `INFO` returning state and reason,
   the slot released on reap, and the fallback when the last capability goes away.

A supervisor program is deliberately **not** in this list. When steps 1–6 are done, one can be
written entirely in userspace, and that is the test of whether these are the right mechanisms.
