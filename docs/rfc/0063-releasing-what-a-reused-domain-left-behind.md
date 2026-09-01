# RFC 0063: releasing what a reused domain left behind

| | |
|---|---|
| **Status** | 🔍 **Open — reopened 2026-09-01, hours after being closed, because the cause given for closing it was false.** The page was never stale: `map_anonymous` zeroes every frame it allocates. See "The closure was wrong" |
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

**What a working step 2 needs — and this tree has already solved the same
problem one field over.** `claim_socket_slot` carries no identity at all:

```rust
let index = held.iter().position(|taken| !*taken)?;   // a bool per slot
held[index] = true;
Some(SOCKET_SLOT + index as u64)
```

A handle is `SOCKET_SLOT + index`, so **two sockets in the same slot at
different times have the identical handle**. Nor can the handle be widened to
carry a generation: it *is* a CSpace slot number, passed to `INVOKE`.

So the generation must sit **beside** the handle — which is exactly what
`Entry::inode` already does, and its own comment says why:

> *"Kept beside the handle rather than derived from it. The handle is a
> capability slot, taken from a small pool and reused: two files opened one
> after the other routinely land in the same slot, so a `st_ino` derived from
> it would report them as the same file."*

`inode` exists because a handle is not an identity. Socket ownership needs the
same answer: a per-slot counter bumped on every `claim_socket_slot`, and the
value recorded in the `Entry` when the socket is opened. A stale record's handle
is then released only when the slot's counter still matches what the record was
issued — and a reallocated slot is left alone, because its counter has moved.

**And a second attempt, with that identity built, broke it too.** On 2026-09-01
`SOCKET_OWNER` was added — a `(domain, generation)` per slot, stamped where a
slot is claimed, cleared where it is released — and the stale release was gated
on it: release only where the slot still agrees it was issued to this domain at
this generation. The reclaim gate then failed **4 boots of 4**, against a
control on the same tree that passed **4 of 4**. Reverted.

So the identity was necessary and still not sufficient, and this document should
stop predicting what will be. **Two implementations, two deterministic
regressions, from a defect that is intermittent when left alone** — which is
itself the strongest evidence about it: whatever holds that port is not simply a
record nobody released, or releasing it correctly would help. The second attempt
released *more* and the port stayed held (`bound again false`, `bind -98`,
`forgets 2`), which is the opposite of what the model predicts.

**What the next attempt should establish before writing any code**: where the
port is actually held. Every hypothesis so far has been about the adapter's
bookkeeping — which record, which handle, which generation — and two corrections
to that bookkeeping have made the machine worse rather than better. The port
lives in `bin/ipd`, and no instrument in this investigation has yet asked *it*
what it thinks it is holding and for whom. That is the question, and it is one
service call away.

Until then, **any implementation of the rule below is unsafe**, however
carefully it picks its records — which is why this section sits above the steps
rather than after them.

The two host tests from the attempt are worth keeping when it is retried; they
were correct and they passed. They simply tested the half of the problem this
document had thought about.

## What the service itself says it is holding (2026-09-01)

The previous section ended by recommending that somebody ask `bin/ipd` what it thinks it holds,
since every hypothesis so far had been about the *adapter's* bookkeeping and two corrections to that
made the machine deterministically worse. That has now been done — and the first attempt at it was
wrong in a way worth recording, because it produced a confident reading and a conclusion drawn from
nothing.

**The first instrument reported a field it had itself destroyed.** It wrote its packed ports into
the report page at word 9 with `write_volatile`, on the stated reasoning that word nine was "past
the eight `report` writes". `report` writes twenty-three. Word 9 is `DELIVERED` and word 10 is `WHY`
— the delivery count, the last refusal reason, the frame size and the ethertype that the kernel's
`ipd after` line prints. Nothing went red, because the values coincided: `DELIVERED` was 2, and a
single socket bound on port 2 packs to exactly 2. The line `ipd holds slot 0 port 2` was the
delivery count showing through the word that had been overwritten, on every boot, whether or not
the instrument ever ran.

**So the conclusion drawn from it is withdrawn.** This section previously said that the reading was
identical on a failing boot and a passing one, and that the service therefore was not sitting on an
extra port at report time. That was a statement about `DELIVERED`, not about any socket, and it is
not evidence for or against anything. The hypothesis it claimed to eliminate is open again.

This is the second time in this RFC that a correction to bookkeeping has been worse than the
bookkeeping, and the same lesson as the console tear closed the same day: a value that looks
plausible is not a measurement, and the comment beside the report array — *"RFC 0029's first draft
took the zeros for spares and its v6 words were silently overwritten"* — had already written this
mistake down before it was made again.

**What is there now.** Three words appended past the v6 pair at 21 and 22, carried by both
`report` and `refresh` the way every other counter in that program reaches the kernel, costing no
`unsafe` at all — so the raise to 159 that the first version needed is reverted to 156 the same day.
They cover **all six** slots, not four: an instrument that watches four of six cannot see a leak in
the other two, and this defect has already cost two fixes aimed at the wrong place. A healthy boot
now reads:

    ipd sockets    none bound  | reuse 1,1,1,1,1,1

which is already worth having: at boot-report time the service holds nothing, and every slot has
been bound and released exactly once. A failing boot that shows a port still bound puts the leak in
the service; one that shows the same table with a lower generation says the slot was never given
back. Both are distinguishable now, and neither was before.

**The first real specimen, taken the same day.** A `make test` run failed the reclaim gate with the
corrected instrument in, and it reads:

    socket reclaim FAILED: held true, reaped true, same slot true, bound again false (fd 1, bind 1), forgets 1
    ipd sockets    none bound  | reuse 1,1,1,1,1,1

which is **character for character** what a passing boot reads. So the service ends a failing boot
holding nothing, with every slot bound and released exactly once — the same as a healthy one. The
port is given back. Whatever `bound again false` means, it is not a port stranded in the service's
table for the rest of the boot.

That is the same sentence this section withdrew an hour earlier, and it is worth being explicit
about why it may be asserted now and could not be then: then it was a reading of `DELIVERED` through
a word the instrument had overwritten, and now it is a reading of the six slots the service actually
holds. The conclusion is the same; only one of the two was evidence.

**The limit, stated so it is not over-read.** It samples once, at the boot report — after the
failure, after the release, after everything. It says the port is not leaked *for the rest of the
boot*. It does **not** say the port was free at the moment the rebind was refused, and that moment
is the one the defect lives in. A generation of 1 on every slot on both boots says only that each
slot was closed once by the end.

## The descriptor number, which nobody had compared (2026-09-01)

The reclaim gate prints `(fd {}, bind {})` and has printed it since the defect was filed, but the
two values had never been compared against a healthy run — because a healthy run does not print
them. Forcing the failure branch on a boot where the reclaim *works* gives the baseline, and it does
not match:

| | fd | bind | the adapter's own record |
|---|---|---|---|
| healthy | **3** | 0 | `3 at stage -130 (the adapter thinks it bound port 7781)` |
| the failing specimen | **1** | 1 | not captured — the gate did not read it |

**A socket that lands on descriptor 1 is a process with no stdio.** Descriptor 3 is the first free
number in a record that has 0, 1 and 2 already filled; descriptor 1 is the second free number in a
record that has nothing at all. So on the failing boot the taker was talking to an *empty*
descriptor table.

That is not a new mechanism — it is one this investigation has already written down and not
followed. `process_for` is not a lookup: **it admits a fresh empty record when none matches
`(domain, generation)`**, which was recorded earlier in this hunt as "a silent path neither counter
catches, and the one to instrument next if a specimen shows both at zero". A fresh record explains
the descriptor number directly, and it would explain the reclaim failing while every counter reports
success: `release_sockets_of` walking a record that was created moments ago releases nothing and
says so honestly.

What it does **not** yet explain is `bind 1`. `answer_bind` returns `Answer::ok(0)` or
`Answer::error(-errno)`; it cannot return a positive 1, so either the value the taker stored is not
an `answer_bind` result, or it did not come from the syscall the gate believes it made. That is the
one loose end here, and it is named rather than smoothed over.

**The gate now reads the adapter's record on failure**, which it never did although two other gates
do. On a refused bind `answer_bind` writes the errno, `STAGE_NOT_BOUND` and *the service's own
refusal word* packed with the port; the gate was printing a bare `bind {n}` and leaving the reason
on the floor. The new line was armed by forcing the failure branch, so its decode is proven before
the specimen it exists for arrives — twelve boots after adding it produced no failure, which is
consistent with the rate this defect has always had.

## Asking `process_for` what it does, on every boot (2026-09-01)

`process_for` has been named a suspect in this hunt twice — once when it was written down as "not a
lookup: it admits a fresh empty record when none matches `(domain, generation)`", and again when the
descriptor number pointed at a table with no stdio. Both times the next step was "instrument it",
and both times the instrument was never built, so the suspicion stayed a sentence.

It is built now, in the layout module both rings share rather than at an address one of them guessed:
`report::PROCESS_AT`, four words — records admitted, records found, the last domain admitted for,
and how many descriptors that record held. The layout's own compile-time assertion that every record
ends before the scratch was updated to cover it, so the new record cannot silently walk into the
staging area the way `FAULT_LOG_OFFSET` once did.

A healthy boot reads:

    process records 31 admitted, 146 found; last admitted for domain 18 holding 3 descriptor(s)

**Printed on every boot, not only a failing one**, which is the correction this hunt keeps having to
make: the descriptor number in the paragraph above had been printed for a week and was unreadable
because there was nothing to compare it against.

**Three is the number that matters.** A freshly admitted record has the three standard descriptors
installed, so the first socket opened through it lands on descriptor 3 — which is what a healthy
taker gets. The failing specimen got descriptor 1, meaning a table holding one descriptor at slot 0.
`install_standard` installs three unconditionally, so if a failing boot reads `holding 3` then the
descriptor number did not come from a fresh record and that hypothesis is dead; if it reads
`holding 1` the admission itself is wrong. Either answer closes a branch, which is more than any
instrument in this RFC has managed so far.

## Whose bind was it (2026-09-01)

The gate reports the taker's `bind` answering **1**. `answer_bind` returns `Answer::ok(0)` or
`Answer::error(-errno)`, so a positive one is not an answer it can give — which has been recorded
here as a loose end for a day without anything able to pursue it.

The richest specimen so far sharpened it into a contradiction. On a boot where the reclaim failed:

    socket reclaim FAILED: ... bound again false (fd 1, bind 1), forgets 1
    the adapter last recorded: 3 at stage -130 (the adapter thinks it bound port 7781)

Stage −130 is `STAGE_SOCKET`, which `answer_bind` writes only when a bind **succeeded** — descriptor
3, port 7781. So the adapter's own record says its last bind worked, while the gate says the taker's
bind answered 1 on descriptor 1. Both cannot describe the same call, and nothing could say whether
they did, because the record does not carry **whose** bind it was.

`report::BIND_AT` carries that now: the asking domain and the outcome, written on **both** paths.
Two words, which is exactly what was left in the report page before the scratch — the layout's
compile-time assertion covers them. A domain absent from that record did not reach `answer_bind`.

The healthy baseline, taken by forcing the failure branch on a boot where the reclaim works:

    bound again true (fd 3, bind 0), forgets 2
    last bind: domain 18, errno 0, port 7781, service word 0
    the adapter last recorded: 3 at stage -130 (the adapter thinks it bound port 7781)

The taker is domain 18, and the two records agree. On a failing boot they will either name the same
domain — in which case the record *is* the taker's and a bind that returned 1 came out of a function
that cannot return 1 — or a different one, in which case the taker's call never arrived and every
instrument aimed at `answer_bind` has been watching the wrong thing. Both answers close something,
which is more than this RFC has managed since it was opened.

**So the next instrument samples at the failure rather than after it.** `bin/ipd` knows when it
refuses a bind; latching the whole table at that instant would show what was held *then*, which is
the question. That is a service-side change of a few lines and no new capability, and it is the
first thing to try before any further correction to the adapter.

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


---

## What it was said to be, and was not (2026-09-01)

**Nothing in this RFC was needed, and the two attempted fixes made the machine worse because they
were correcting bookkeeping that was already correct.**

The bind record added this morning gave the decisive specimen. On a boot where the reclaim gate
failed:

    socket reclaim FAILED: ... bound again false (fd 1, bind 1), forgets 1
    last bind: domain 18, errno 0, port 7781, service word 0
    the adapter last recorded: 3 at stage -130 (the adapter thinks it bound port 7781)

and on a boot where it passed, taken by forcing the failure branch:

    bound again true (fd 3, bind 0), forgets 2
    last bind: domain 18, errno 0, port 7781, service word 0
    the adapter last recorded: 3 at stage -130 (the adapter thinks it bound port 7781)

**The adapter's two records are identical.** It bound port 7781 for domain 18 on descriptor 3, and
said so, on the failing boot as on the passing one. So the `fd 1, bind 1` the gate reported never
came from the adapter at all — and a taker that got descriptor 3 and a successful bind would have
written `(3, 1)` into its report page.

`run_bell_program` maps the probe's report page and **never clears it**. The kernel then waits for
the second word to become non-zero before reading the pair. A recycled frame arriving with anything
in that word satisfies the wait *before the program has run*, and the gate reads whatever the frame
last held. That is the whole defect, and it is intermittent for the obvious reason: it depends on
what was in the frame.

The page is zeroed now, before the peer address that is written into the same page.

**Proven rather than argued.** Poisoning the page with the specimen's own values — `1` and `2` —
reproduces the failure character for character and deterministically:

    socket reclaim FAILED: held true, reaped true, same slot true, bound again false (fd 1, bind 1), forgets 1

Twelve consecutive boots of the lane are green with the page zeroed.

**Why three days of instruments found nothing.** Every one of them was aimed at `bin/linuxd` or
`bin/ipd` — which process record, which handle, which generation, which port, which slot. All of them
reported the adapter and the service behaving correctly, and all of them were right. The two
corrections attempted on that basis regressed the machine 4/4 against a 4/4-passing control, which
should have been read as evidence sooner than it was: a fix that makes a correct mechanism worse is a
fix aimed at the wrong mechanism.

**This is not only this gate's problem.** Four probes go through `run_bell_program` and every one of
them reports through a page that was never cleared. Any gate waiting on a word there could read a
recycled frame; the zeroing fixes all of them at once, and other intermittents in §3 should be
re-examined against it rather than assumed unrelated.

The rule this RFC proposed is withdrawn. `Process::exec_into`, `release_sockets_of` and
`process_for` are unchanged, and the instruments added along the way stay: `ipd sockets`, `process
records`, the adapter's bind record and its file record all print on every boot or on every failure,
and between them they are what made this answerable.


---

## The closure was wrong (2026-09-01, the same day)

**The section above is retracted.** It claimed the probe's report page arrived holding stale bytes
from a recycled frame, and that a non-zero word there satisfied the kernel's wait before the program
ran. The page is not stale. `AddressSpace::map_anonymous` allocates every present page and zeroes it
unconditionally — *"Zero on allocation, never on free"*, `docs/memory.md` §2 — and the probe's buffer
page is mapped through exactly that call. There is no window in which it holds anything.

**How a wrong answer got this far.** The poison test looked conclusive and was not. Writing `1` and
`2` into the page reproduces the failure line character for character, which proves those values are
*sufficient* to produce it — it says nothing about whether they were ever *there*. That is a
sufficient condition mistaken for a necessary one, and the twelve green boots that followed are
consistent with an intermittent that fires about once in twenty simply not firing. Neither
measurement was evidence for the claim, and the claim was written as settled.

The zeroing is reverted rather than kept as defensive tidiness: it duplicated a policy the memory
manager already states and implements, which is the second derivation this project keeps paying for,
and its justification comment and unsafe-budget raise both cited a cause that does not exist.

**What is actually known**, and this part survives:

- The gate reads `fd 1, bind 1` from the taker on a failing boot.
- `bin/linuxd`'s bind record and file record are **identical on a failing and a passing boot** —
  `domain 18, errno 0, port 7781` and `3 at stage -130`. The adapter bound the port correctly both
  times, so `fd 1, bind 1` is not an answer it gave.
- The probe's page is zeroed before the program runs, so those values were *written by something*.
- `answers[1] == 2` means a writer put 2 there, and the taker writes `bind + 1`.

So the open question is sharper than before and differently shaped: not "why did the adapter answer
wrongly" — it did not — but **who wrote `(1, 2)` into a page that starts zeroed**. Domain numbers are
reused, so `domain 18` on the failing boot may be the *leaker's* bind rather than the taker's, which
would mean the taker's call never reached `answer_bind` at all. Distinguishing those needs the record
to carry a boot-unique identity rather than a domain number, and that is the next instrument.
