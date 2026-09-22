# RFC 0083: a signal a process can catch

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-09-19 — built and gated.** A hosted process catches `SIGTERM`: one it sends itself, one sent to a child parked in a sleep, and one sent to a child parked on a pipe. Three assertions, each armed red. **Step 7 (2026-09-21) closes question 2**: a handler runs with its own signal blocked and is not entered on top of itself. The limit this design has is named below and printed on every boot. |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | userspace (`bin/linuxd`), `bhaskix-personality` |
| **Milestone** | Phase 2 — the Linux personality |
| **Depends on** | [RFC 0079](0079-a-signal-a-process-may-send-another.md) (who may signal whom), [RFC 0033](0033-what-a-hosted-process-is.md) (the fault path this generalises), [RFC 0032](0032-a-supervisor-interface.md) (the register frame and the resume) |

---

## Summary

`rt_sigaction` records a handler and nothing runs it for a signal that arrives
from a `kill`, so `SIGTERM` ends a hosted process whatever it installed. This
delivers it: the process is redirected into its handler on the way out of a
call, on the same mechanism the fault path has used for `SIGSEGV` since
2026-08-20.

## Motivation

**RFC 0079 named this, and named it as the next thing.** Its unresolved
question 1:

> **Delivering a signal to a handler that `rt_sigaction` recorded.** That is the
> difference between `SIGTERM` being fatal here and being catchable, and it
> needs a way to run a hosted process's handler on a stack it owns — which
> RFC 0033's fault path does for `SIGSEGV` and which would have to become
> general. Separate RFC.

And it was explicit that the current behaviour is *honest* rather than right:
*"this adapter records handlers but does not deliver them, so a `SIGTERM` that
claims to be catchable would be a lie, and ending on it is what a
default-disposition process does."* This makes it true instead of honest.

**It is the gap a shell notices.** Catching `SIGTERM` is how a program cleans
up — removes its temporary file, restores the terminal, kills its own children
— and it is the difference between `^C` at a hosted shell and pulling its
power. `docs/roadmap.md`'s L1 row lists it as one of two remaining signal gaps.

## Design

### The delivery mechanism already existed and had one caller

`deliver()` in `bin/linuxd` builds a frame on the faulting process's own stack,
copies it out, edits the register image — `rdi` = signal, `rsi` = siginfo,
`rdx` = ucontext, `rip` = handler, `rsp` = frame — and resumes. It was
`SIGSEGV`-shaped. Generalising it is a change of arguments: `deliver_signal`
takes the number and `si_addr`, and the fault path becomes one of its two
callers. The existing `linux signal` gate proves the refactor, unchanged.

### A pending set, as arithmetic

`personality::signal::Dispositions` gains a 64-bit pending mask beside the
handlers it already holds. A bitmask and not a queue, because a standard signal
is a *condition*: two `SIGTERM`s before the process next enters the adapter are
one delivery, which is what Linux does and what a mask can honestly promise.

Two refusals are the design:

- **`SIGKILL` is never pending.** A process that could catch it could refuse to
  be ended, and who may end a hosted process is RFC 0079's whole subject.
- **A signal with no handler is never pending.** Its default disposition is to
  end the process, which is what happens today. Making it pending would turn a
  signal that *does* something into one that is remembered and never acted on —
  this change may make a fatal signal catchable, never a fatal signal silent.

### Delivery happens at a call or a fault, and nowhere else

There is no way to redirect a running ring-3 thread: the nucleus presents a
thread's registers only when it traps. So delivery rides out on the boundary
the process is already at, in two shapes:

- **A call that finished.** The call is completed first, its result stashed,
  and `REPLY_NEED_FRAME` asks for the register image; the frame is built, the
  result written into the **saved `rax`**, and `REPLY_RESTORE` resumes into the
  handler. Completing first is what makes this need no restart logic: the
  program's call really did happen, and `rt_sigreturn` hands back its answer.
- **A call that is about to park.** Interrupted instead, with `EINTR` — which
  is what `EINTR` *is*. Without this a process blocked on a pipe could never be
  signalled: the `kill` wakes it, the call is re-asked, nothing has arrived, and
  it parks again with the signal still pending, for ever, having burned the
  wake.

### `kill` routes rather than ends

A catchable signal whose target has a handler is raised and the target is
woken; everything else ends the target exactly as before, so RFC 0079's gates
are untouched. The wake matters because the target is parked on a notification
**this adapter named** when it answered `REPLY_BLOCK_ON*` — so the adapter is
the only thing that knows which one, and the slot is recorded at the single
site every reply passes through.

### A forked child inherits its parent's handlers

Linux does this and this adapter did not: dispositions are kept per *domain*
and a fork makes a new one, so a child woke with none. It inherits them now —
and **not** the pending set, because a signal waiting for the parent was sent
to the parent.

This began as a probe problem and is a real fix. A child that installed its own
handler after forking could be killed before it got there: one boot showed a
death by signal 15 and the next an uncaught return. Inheritance removes the
window rather than narrowing it.

## The limit, stated and printed

**A process that makes no calls and takes no faults never receives the
signal.** Linux delivers at any kernel entry, including a timer tick; this
delivers at the next call or fault. Every shell utility calls something; a
compute loop does not.

It is not left as a sentence. The boot prints `raised`, `delivered` and
`unbuilt`, and **`raised` minus `delivered` is exactly the number of signals
waiting on a process that has not come back**. A count of zero on every boot is
what says the limit is not being hit; a count that grows is what would say it
is.

**The trigger for closing it**, rather than an opinion: if that difference is
ever non-zero on a boot that is not deliberately spinning, the nucleus-side
delivery becomes worth its cost. That is a generic "this domain has a
personality event pending" flag checked on return to ring 3 — on the hottest
path in the system, and phrased so it does not put Linux knowledge back in the
nucleus, which RFC 0031 gates at 0. A separate RFC.

## A second limit, found by the gate

**A signal cannot be delivered to a forked child that has no mapped stack.**
The frame is built below the target's `rsp`, and a fork starts its child on the
*parent's* `rsp` while copying only the regions the personality recorded —
which are what `mmap` answered, not the program's original stack. So the
child's `rsp` points at memory its own address space does not have, and the
delivery's copy fails.

Found rather than reasoned: the adapter counted one frame it could not build,
which is why that counter exists. The probe gives its children a stack that was
mapped before the fork. **The general fix belongs to `fork`, not to signals** —
a child should be given a stack in its own address space — and is recorded here
as the next thing that path owes.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| Deliver on return to ring 3, in the nucleus | Matches Linux's delivery point and removes the spinner limit, at the cost of a check on the hottest path in the system and a new crossing, phrased generically or it undoes RFC 0031's zero | The `raised` − `delivered` difference is ever non-zero outside a deliberate spinner |
| Deliver *before* running the call, and restart it afterwards | Needs `SA_RESTART` and `EINTR` semantics for every call, and re-running is only safe for the ones that can be repeated. A much larger piece of work, and the wrong one to do first | A call ever needs to be interrupted before it takes effect, which a signal at a boundary does not |
| Queue signals rather than mask them | Promises an arrival count nothing here can keep, and Linux does not keep it either for standard signals | Real-time signals (`SIGRTMIN`+) are ever wanted, which do queue |
| Let the target poll for pending signals | Puts the mechanism in the program rather than under it, so a program that does not poll cannot be signalled — which is the limit above, made permanent | — |

## Impact on existing design documents

**[roadmap.md](roadmap.md)**, the L1 row: *"What remains of the signals is
**delivery to a handler** — `rt_sigaction` records one and nothing runs it, so
`SIGTERM` is fatal here rather than catchable"*. Half of that sentence changes
with this code; `SIGSTOP`/`SIGCONT` remain.

**[security.md](security.md)** is unaffected: no new authority. Who may signal
whom is unchanged and is still RFC 0079's process-tree rule.

## Security implications

**No new authority, and one refusal made structural.** `raise` will not make
`SIGKILL` pending whatever a process installs, so the authority to end a hosted
process stays exactly where RFC 0079 put it. A handler runs in the target's own
domain, on its own stack, holding what it already held.

`bin/linuxd`'s `unsafe` budget rises 118 → 121, for the three counters written
into the report page — declared, justified in the manifest, and exact, so it
cannot drift. The rest of the change spends none: the pending set is arithmetic
in a crate that forbids `unsafe`, and the stash and parked-slot table are
atomics chosen over a `static mut` for that reason.

No parser, no untrusted input, so no fuzz target is owed.

## Performance implications

One load and a comparison on the way out of every hosted call — the pending
check — and the frame round trip only when something is actually pending. The
adapter's own answer path is what RFC 0005 step 10 prices, and that figure is
on the boot report to compare against.

## Testing plan

**Host** — the pending set, which needs no machine: `SIGKILL` never pending, no
handler never pending, signal zero and a signal past the table refused rather
than aliased, twice-before-a-delivery is one delivery, lowest number first, a
handler removed after the raise is not delivered to, and a stale bit does not
block the one behind it.

**QEMU** — three acts on the existing hosted-kill probe, which is already the
witness for `kill`:

1. **A signal a process sends itself**, handled on the way out of that very
   `kill`. No wake and no park: the target is inside the adapter making the
   call.
2. **A child parked in `nanosleep`**, woken by the `kill`. Its call *completes*
   when woken, so it is delivered on the finished-call arm.
3. **A child parked on a pipe nobody writes to**, whose `read` **re-parks**
   when woken, so it is delivered on the about-to-park arm. Act 2 does not
   reach this path, which is how the arm was found to be untested.

Each child's handler exits 88, so the parent collects an ordinary **exit** where
a child with no handler shows a death by signal 15. That difference is the
assertion, and it is what the same probe read before this change.

**Armed**, all three: `kill` not routing to a handler, a child inheriting
nothing, and the about-to-park arm disabled — the last of which leaves the pipe
child parked for ever and collected as nothing, which is exactly what it
predicts.

## Unresolved questions

1. **`SIGSTOP`/`SIGCONT`.** RFC 0079's question 2, untouched: a domain has no
   stopped state, so they would be invented rather than translated.
2. ~~**`sa_mask` during delivery.** Recorded and returned; not enforced. A
   handler that is signalled again while it runs will be re-entered, where
   Linux would have blocked the signal.~~ **Answered by step 7, 2026-09-21.**
   A handler runs with its own signal and everything its `sa_mask` names
   blocked, and `rt_sigreturn` puts the previous set back. The set travels in
   the frame's own `uc_sigmask`, at the offset Linux puts it — which is where
   this frame already ended, so it cost eight bytes and no second arithmetic.
   Nesting therefore unwinds by construction, and a handler that edits
   `uc_sigmask` is obeyed. `SIGKILL` is masked out of any blocked set, for the
   reason it cannot be caught.
3. **`SA_RESTART`.** Accepted and recorded; nothing restarts. A call
   interrupted by a delivery answers `EINTR` whatever the flag says, which is
   correct for a flag that is not implemented and wrong for one that claims to
   be.
4. **A forked child's stack**, above. It belongs to `fork`, and it is larger
   than the note above suggests — established 2026-09-21 rather than assumed:

   - `execve` maps the program's segments *and* its stack with `map_at_eager`
     and never calls `remember_mapping`, so `fork` does not copy either.
   - A **kernel-started** hosted program's whole layout — code, buffer and
     stack — is mapped by `run_bell_program` in the kernel, which `bin/linuxd`
     never sees at all.

   So `fork` copies what the adapter *remembers*, which is only what `mmap`
   answered. That is why a forked child cannot run its parent's code and why
   the probe's children are given a page to stand on.

   **Priced on 2026-09-22, and the price corrects what this entry first said.**
   It said recording `execve`'s regions would "cost more than it is worth"
   because every BusyBox `fork` would copy 2.1 MB. That is true of the
   *supervisor* path and is not a general objection, which is the opposite of
   how it was written.

   The boot measures both sides. A page through `COPY_OUT` costs **213,404
   cycles warm** (1,447,268 the first time, two crossings per page, because
   the scratch is smaller than a page); the kernel moves a page through the
   direct map in **140**. That is a factor of **1,524**.

   | | bytes | pages | through `COPY_OUT` | in the kernel |
   |---|---|---|---|---|
   | a fork today | 8,192 | 2 | 426,808 | 280 |
   | the `execve` stack | 65,536 | 16 | 3,414,464 | 2,240 |
   | `bin/hosted` | 85,512 | 21 | 4,481,484 | 2,940 |
   | BusyBox | 2,172,376 | 531 | 113,317,524 | 74,340 |

   **So copying the whole of BusyBox in the kernel costs 74,340 cycles —
   under a sixth of what copying today's 8 KiB through `COPY_OUT` costs.** The
   expensive thing is not the megabytes; it is the crossing. A supervisor that
   copies an address space a kilobyte at a time is the wrong mechanism at any
   size, and the copy-on-write this entry reached for is not needed to make
   the cost acceptable — it is needed only if the copying stays in ring 3.

   That settles the shape: **the fix belongs in the kernel**, which already
   moves these pages for every `execve`, and a `fork` that asks it to copy a
   domain's address space is a nucleus change and its own RFC. What this entry
   got right is that recording `execve`'s regions and copying them through the
   adapter is not the way; what it got wrong is the reason.

   **Answered on 2026-09-23 by
   [RFC 0084](0084-a-fork-the-kernel-copies.md)**, which is where this entry
   now continues. `COPY_SPACE` on a `Domain` capability copies the address
   space in the kernel, `bin/linuxd`'s `fork` calls it, and the hosted fork
   gate's byte count went from 8,192 to 16,384 — the four frames the probe's
   parent held, two of which the adapter has never seen. A forked child gets
   its parent's code and its parent's stack. The page a probe's child is
   handed to stand on is no longer necessary, and the probes that hand one are
   kept because they still prove what they proved.

## Implementation plan

1. ✅ **The pending set** — `personality::signal`, host-tested, inert.
2. ✅ **`deliver()` generalised** into `deliver_signal`, its only caller still
   the fault path, proved by the existing `SIGSEGV` gate.
3. ✅ **Delivery at a call boundary** — the stash, `REPLY_NEED_FRAME`, the
   saved-`rax` write, `REPLY_RESTORE`, and the about-to-park arm.
4. ✅ **`kill` routes** and wakes a parked target; a forked child inherits.
5. ✅ **The counters, the gate and the arming.**
6. ✅ **The documents.**
7. ✅ **A handler that is not re-entered** (2026-09-21) — the blocked set, the
   frame's `uc_sigmask`, and `rt_sigreturn` restoring it. Closes question 2.

   **The gate turns on one number, and it is not the obvious one.** The
   probe's handler signals *itself* on its first entry. Without a blocked set
   the delivery for that signal lands on the way out of the `kill` and the
   handler is entered on top of itself; with one, the `kill` returns, the run
   finishes, and the still-pending signal is delivered on the way out of
   `rt_sigreturn`. **Both give two runs** — only the *depth* differs, 2
   against 1, and a gate that counted runs would have passed on both. Armed,
   and the armed run reads depth 2.

   It also caught a mistake of its own making: the step-6 assertion
   `handler_runs == 1` was left in place beside the new `== 2`, so the
   condition was unsatisfiable for one boot. A contradiction is a better
   failure than a wrong pass, and it is why the two clauses are now one.
