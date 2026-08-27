# RFC 0052: a line that waits for its newline

| | |
|---|---|
| **Status** | ✅ **ACCEPTED 2026-08-27** — proposed, built and accepted the same day, and the last of three console changes that began with a hosted program's `execed pid 3` arriving as `e`, a kernel report, then `xeced pid 3`. The console service holds each caller's partial line, keyed by the badge the kernel stamps and the caller cannot choose, and puts it in one `PUT_RUN` on a newline, on a full buffer, or **when that caller reads** — the last being what keeps a prompt visible, since a shell writes `bhaskix$ ` with no newline and then waits. It is also the argument for the service being the right place: **the nucleus cannot see `console::READ`**, so it could not have done this correctly, which is a stronger reason than the one RFC 0050 gave for refusing to buffer there. **What acceptance does not claim.** *(1)* **It has not run on the SR550**; that boot predates it, and sixteen processors is where console contention is worst. *(2)* **Bytes can be held and invisible**: a caller that writes a partial line and then neither newlines, nor fills its buffer, nor reads keeps those bytes held — bounded at `4 × 256`, and the console can be one partial line behind per caller. *(3)* **Ordering between callers changes** — a caller that finishes its line appears before one that has not — which is the cost every line-buffered terminal pays and is the point. *(4)* A **fifth** concurrent caller is not buffered at all and writes straight through, degraded to RFC 0050's behaviour rather than refused, and **it is not counted**; that is unresolved question 2. *(5)* A kernel line can still land *between* a program's lines. Nothing in the service can prevent that, and it was never the fault: the fault was a kernel line landing **inside** one |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | userspace |
| **Milestone** | Phase 2 — Core Operating System |
| **Depends on** | [RFC 0013](0013-relocatable-services.md) (the service and its placements), [RFC 0050](0050-a-console-line-that-arrives-whole.md) (`PUT_RUN`, which this flushes through) |

---

## Summary

The console service holds each caller's partial line and puts it in one
`PUT_RUN` when a newline arrives, the buffer fills, or that caller reads.

## Motivation

**RFC 0050 shrank the window and did not close it.** A hosted program's `write`
is one invocation now, but a *native* program reaches the console through the
service, one 16-byte `Chunk` per message. A line longer than sixteen bytes is
several messages, and a kernel line printed on another CPU can land between two
of them. `bin/sup`'s output has been seen split exactly there:

    sup: starting ch    services       9 entries listed, ...

**Buffering is policy, and this is where policy goes.** RFC 0050 rejected
line-buffering *inside the nucleus* on the grounds that `PUT`'s own comment gives
— *"deciding that an escape sequence must not reach it is policy, and policy is
what was moved out"*. The console service is a ring 3 program in the domain
placement. Holding a line is exactly the kind of decision it should be making.

## Design

**State, keyed by badge.** `Console::State` becomes a small table of partial
lines. The key is `Request::badge`, which the kernel stamps from the capability
used and which the caller cannot choose — so two domains writing at once cannot
be spliced into each other's lines, which is the failure this must not introduce
while fixing another.

**Three flush points, and the third is the one that matters.**

1. **A newline.** The bytes up to and including it go out in one `PUT_RUN`.
2. **A full buffer.** `LINE_BYTES` is 256, matching `MAX_CONSOLE_RUN`, so a flush
   is always one invocation. A program writing without newlines gets its output
   in 256-byte pieces rather than never.
3. **That caller reading.** `console::READ` flushes the reader's own buffer
   first. **Without this the shell disappears**: it writes `bhaskix$ ` — no
   newline — and then waits for a key, so a buffer that only flushed on newlines
   would swallow every prompt on the machine. This is what makes the change a
   terminal discipline rather than a buffer, and it is the part most likely to be
   got wrong.

**A caller with no slot is not buffered.** The table is fixed at four. A fifth
caller writes straight through, one `PUT_RUN` per chunk, exactly as today —
degraded to RFC 0050's behaviour rather than refused or dropped.

**The filtering does not move.** Bytes are filtered on the way *into* the buffer,
by the same substitution and in the same place, so a program still cannot put an
escape sequence on the kernel's console and cannot get one there by splitting it
across two writes.

## Alternatives considered

**Flush on every write, as today.** That is RFC 0050, and it leaves the gaps
between chunks.

**Buffer in the nucleus.** Rejected by RFC 0050 and still rejected: policy in the
nucleus, and the nucleus cannot see `console::READ` — the flush point that keeps
prompts working is a *service protocol* event.

**Buffer in each program.** Correct for programs that do it and useless for
programs that do not, which is every program that exists today. A `write` that
arrives whole should arrive whole.

## Impact on existing design documents

RFC 0050's unresolved question 2 said a whole-line fix "wants its own RFC and its
own gates". This is it.

## Security implications

**No new authority and no new reachability.** The service already receives these
bytes and already puts them; it now puts them later and together.

**One new failure mode, stated rather than discovered.** A caller that writes a
partial line and then neither writes a newline, nor fills the buffer, nor reads,
leaves those bytes held until it does one of the three. They are not lost, and
they are not visible either. The bound on how much can be held is
`4 × 256` bytes, and the console the operator is looking at can be up to one
partial line behind per caller.

**Ordering between callers changes.** A holds a partial line, B writes a whole
one; B's appears first. That is the cost every line-buffered terminal pays, and
it is the point: each line is whole, and lines are no longer interleaved *within*
themselves.

## Performance implications

Fewer invocations, not more: a 100-byte line was seven `PUT_RUN`s and becomes
one. The service does one copy into its buffer that it did not do before.

## Testing plan

1. **Host tests** on the discipline itself: bytes with no newline are held; a
   newline flushes exactly up to and including it; a second caller's line does
   not join the first's; a full buffer flushes; a read flushes the reader's own
   buffer and not another's. Each watched red.
2. **The shell lanes**, which are the prompt test: the user-mode shell must still
   print `bhaskix$ ` and answer typed commands. If flush-on-read is wrong, every
   shell lane hangs at a prompt nobody can see — a failure that cannot be missed.
3. `make test`, every lane and both placements.

## Unresolved questions

1. **Should the kernel's own printing flush the buffers too?** A kernel line
   between two of a program's lines is fine; a kernel line *while* a program has
   a partial line held is the ordering change above. Nothing can be done about it
   from inside the service, which cannot see the kernel print.
2. **Four slots, and what happens at five.** Falling back to unbuffered is safe
   and silent. It should probably be counted.

## Implementation plan

1. `Lines` state in the console service, keyed by badge, with the three flush
   points. ✅ **Done 2026-08-27.**
2. Host tests, watched red. ✅ **Done** — five, and three mutations each caught
   by the right test: flushing on every write fails the holding test, the
   two-callers test *and* the prompt test; removing the flush-on-read fails
   **only** the prompt test; ignoring the badge fails the two-callers test and
   the prompt test.
3. Both placements build unchanged — the state is the service's, not the
   placement's. ✅ **Done.**

**And a flake this work introduced and then removed.** The first version of these
tests failed once and passed on the re-run: `PUT` and `TYPED` are process-wide
and cargo runs tests in parallel, so a test that clears `PUT` and asserts on it
races every other test that writes to it. The tests that existed *before* had the
same hazard and had simply not been caught by it, which is how a race waits. A
module-wide guard now serialises them, in the shape `notify`'s test module
already used — and adding it carelessly deadlocked the suite, because the guard
went in twice in one test and the lock is not reentrant. Fifteen consecutive
clean runs afterwards.
