# RFC 0063: releasing what a reused domain left behind

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-09-01 — steps 1–3 implemented, found wrong, and reverted the same day.** The rule below is necessary and **not sufficient**: it selects the right *records* and says nothing about whether their *handles* are still theirs. See "What the first attempt got wrong" |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | libc / userspace (`bin/linuxd`) |
| **Milestone** | Phase 2 — Linux personality (L1) |
| **Depends on** | [RFC 0033](0033-what-a-hosted-process-is.md), [RFC 0058](0058-what-a-service-learns-without-being-called.md) |

---

## Summary

A hosted process that dies holding a socket can leave the port bound for the
rest of the boot. The path that exists to release it — `FORGET`, which arrives
when the domain's slot is reused — **cannot find the record holding the socket**,
and fabricates an empty one instead of failing.

## The defect

`release_sockets_of` opens with `process_for(domain)`. `process_for` is a
**get-or-create**: when `by_domain(domain, generation)` misses it calls `admit`,
installs standard descriptors, and returns a fresh empty record. The loop then
walks its zero descriptors, releases nothing, and returns as though it had
worked.

On the `FORGET` path the miss is **guaranteed rather than occasional**:

```rust
pub fn by_domain(&self, domain: u32, generation: u32) -> Option<&Process> {
    self.slots.iter().flatten()
        .find(|p| p.domain == domain && p.generation == generation && p.state == State::Live)
}
```

Two filters, and the caller's own comment defeats both: *"this arrives when the
slot is reused"* — so the generation has already advanced, and the old record is
a `Zombie` or gone. `note_exit` escapes only by an accident of ordering, running
*before* `processes.ended` while the record is still `Live`.

**Measured, on the specimen that eliminated the other two hypotheses.** A
failing boot reads `socket reclaim FAILED: held true, reaped true, same slot
true, bound again false (fd 1, bind 1), forgets 1` beside `socket close every
close landed; the worst needed 1 of 4 attempts, and no FORGET was refused`. The
close landed, nothing was refused, nothing needed retrying — and the port stayed
held, because nothing was ever released.

## Why this is an RFC and not an edit

The obvious fix — find the record by domain id alone — is the bug the table was
built to prevent. `by_domain`'s own comment says it:

> *"a domain id is reused, and a record found by id alone would answer for
> whoever holds the slot now."*

And that failure has happened here before. The comment beside `release_socket_slot`
records a *live* program losing its network because a dead one was cleaned up
twice, found when this function gained its second caller. **Releasing too
broadly is worse than releasing too little**: too little leaks a port until
reboot, too much takes a port from a program that is using it.

So the question this RFC answers is not *how* to find the record. It is **which
records a `FORGET` is entitled to release for**, stated precisely enough that
the answer cannot drift.

## The rule

A `FORGET` for domain *d* releases the sockets of every record that names *d*
**and cannot belong to its current occupant**:

* `p.domain == d`, and
* `p.generation != incarnation()[d]` — a strictly older incarnation.

The current generation is excluded whatever its state, which is what makes this
safe: a `Live` record of the current generation is the new occupant and is
untouched, and a `Zombie` of the current generation still belongs to it and its
parent may yet `wait4` it.

**Older generations cannot have a living owner.** The domain was destroyed
before the slot could be reused — that destruction is what `FORGET` announces —
so any record naming *d* at an older generation describes a program that no
longer exists, whatever its `state` says.

## Steps

**Step 1 — the accessor, in the crate that can test it.**
`Processes::stale_for_domain(d, current) -> impl Iterator<Item = &mut Process>`
in `personality/src/process.rs`, yielding records matching *d* at generations
other than `current`, in either state. Host tests: a live current-generation
record is never yielded; a zombie of the current generation is never yielded; an
older live record is; an older zombie is; and a table with no match yields
nothing rather than admitting one.

**Step 2 — `release_sockets_of` stops creating records.** It takes the
generation as an argument and uses a lookup, never `process_for`. Its two
callers differ and that difference becomes explicit: `note_exit` passes the
record's own generation (its process is still live), `FORGET` passes
`incarnation()[d]` and releases the stale set.

**Step 3 — the descriptor is cleared through the same record**, not through a
second `process_for` call, which is the other place today's code can conjure a
record mid-loop.

**Step 4 — the gate keeps its shape and gains a number.** The reclaim gate
already prints `held / reaped / same slot / bound again`; it gains the count of
stale records a `FORGET` released for, so a boot that releases nothing says
whether it found nothing or had nothing to find — the distinction this defect
spent weeks on the wrong side of.

## What the first attempt got wrong

**Implemented on 2026-09-01, and it made the defect deterministic: 4 boots of 4
failed where it had been intermittent.** Reverted. What went wrong is worth more
than the attempt.

Steps 1–3 went in as written. `stale_for_domain` was added with four host tests
and both directions armed red — a domain-id-only filter correctly fails
`the_current_incarnation_is_never_stale`, which is the danger this document opens
by naming. `release_sockets_of` stopped fabricating records. `FORGET` released
the stale set. All of that is right.

**And it still closed sockets belonging to live programs**, which is exactly the
failure the section above warns about. The rule reasons about *which records* are
stale. It says nothing about whether a stale record's **handles** are still its
own:

```rust
if entry.kind == Kind::Socket
    && entry.handle != u64::MAX
    && process.descriptors.holders(entry.handle) == 1
```

`holders` counts entries *within one descriptor table* that name the same handle
(`personality/src/file.rs`). It cannot see that the slot behind that handle was
released long ago and handed to somebody else — and on the `FORGET` path that is
the likely case, because the record has been dead long enough for its domain slot
to be reused. Releasing on the strength of a number in a dead record closes
whatever holds that slot **now**.

So: selecting the right records is necessary and not sufficient. A handle read
out of a stale record is a *claim*, not a fact, and this RFC treated it as a
fact.

**What a working step 2 needs**, and it is a question for the slot allocator
rather than the process table: a handle must carry, or be checkable against,
something that says which incarnation it was issued to — a generation on the
slot, or an owner recorded beside it. Then a stale record's handle is released
only when the slot still agrees it belongs to that incarnation, and a reallocated
slot is left alone. Until that exists, **any implementation of the rule below is
unsafe**, however carefully it picks its records — which is why this section sits
above the steps rather than after them.

The two host tests from the attempt are worth keeping when it is retried; they
were correct and they passed. They simply tested the half of the problem this
document had thought about.

## What this does not do

- It does not release *files*. That asymmetry is deliberate and already
  recorded: a file's slot is per-open, from a pool of thirty-two, and a leak
  there costs a slot rather than a scarce service resource.
- It does not close the window RFC 0058 names: a socket held by a domain that is
  killed and **never replaced** stays held, because nothing reuses the slot and
  no `FORGET` is ever sent. That bound is stated there rather than rounded to
  "fixed", and this RFC does not widen it.
- It does not make `process_for` a lookup. That function's get-or-create is
  correct for the syscall paths, where a hosted process meeting the adapter for
  the first time must get a record. What was wrong was calling it from a release
  path, where creating one is never the right answer.
