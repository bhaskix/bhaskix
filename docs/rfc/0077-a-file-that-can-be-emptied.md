# RFC 0077: a file that can be emptied

| | |
|---|---|
| **Status** | 🔨 **Draft 2026-09-13 — all six steps built, and parked on a branch rather than landed.** The feature works and its five checks all pass on the `iommu` lane, each watched red. **It is not accepted, because `make test` is red with it**: RFC 0059's adapter file-slot gate reports one slot held that should have come back, on 7 boots of 8, against 0 of 8 without this change. The cause is **not established** — see *What blocks acceptance* below. A status line that said ACCEPTED while the suite was red would be the one thing this project's documents are not allowed to do |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | fs / libc |
| **Milestone** | Phase 2 — Linux personality (L1) |
| **Depends on** | [RFC 0060](0060-a-writable-path-for-a-hosted-process.md) (the writable directory), [RFC 0065](0065-the-block-the-format-already-had.md) (the indirect block, and freeing it) |

---

## Summary

A file can be set back to zero bytes. `dir::TRUNCATE` is one new method on the
filesystem service, gated by the same writable badge as every other method that
changes something, and `Volume::truncate` frees a file's blocks without removing
its directory entry. A hosted Linux process gets `O_TRUNC` on an existing file
and `ftruncate(2)` to zero, so `echo x > file` means what it says.

## Motivation

**`echo x > file` over a longer file leaves the old tail**, silently. That is
the state of the tree as of 2026-09-13, and it is the bad kind of wrong: the
shell reports success, the file is the length it used to be, and the difference
shows up whenever somebody reads it back.

[RFC 0060](0060-a-writable-path-for-a-hosted-process.md) refused `ftruncate`
with a written trigger — *"a program actually needs it, likely as soon as a
real shell redirects onto an existing file"* — and its Design section noted
that `O_TRUNC` on **create** is free because a created file is empty. That is
true and it is half the cases. RFC 0060 closed the other half into existence:
a hosted shell can now redirect, so the trigger is met by the change that made
it reachable.

Nothing else in the system can empty a file either. `bin/shell`'s `pkg` writes
only ever create; the kernel's own formatter writes whole volumes. So this is
missing capability rather than a Linux-compatibility wart, and `pkg` will want
it the first time a package is reinstalled over a shorter one.

## Design

### The freeing already exists, and that decides the shape

`Volume::remove` frees a file's contents today, and does it correctly: the
direct blocks, then the blocks the indirect table names, then the table. That
loop is RFC 0065's — a delete that stopped at the direct blocks leaked up to
1,025 blocks per file, and the fix is armed by a test that fails against the
code as it was.

**Truncation is that loop without removing the directory entry.** So the
proposal is not new arithmetic; it is extracting the freeing into
`Volume::free_contents` and calling it from two places. Writing a second copy
would be two implementations of one invariant that must agree, and this tree
has already paid for that shape more than once.

```rust
/// Frees every block a file holds, direct and indirect, and the table.
fn free_contents(&mut self, file: &Inode) -> Result<(), FsError>;

/// Sets `index` back to zero bytes, keeping the inode and its generation.
pub fn truncate(&mut self, index: u32) -> Result<(), FsError>;
```

`truncate` stages the freed bitmap and an inode with `size: 0`,
`direct: [0; 10]`, `indirect: 0` — and **the same `kind`, `links` and
`generation`**. The generation is the load-bearing one: it is what a stale
capability is checked against, so a truncate that bumped it would revoke every
handle to a file whose contents merely went away.

### The method

| | |
|---|---|
| `dir::TRUNCATE` | **10** — the next free number; 1–9 are taken |
| Arguments | none; the handle names the file |
| Reply | `args[0]` outcome, and nothing else |
| Badge | **writable only**, through `refused_read_only`, as `WRITE_FROM` and `REMOVE_AT` are |
| Refusals | `GONE` for a wrong generation or a file that is not one; `REFUSED` for anything the volume returns |

**A directory is refused.** `Volume::truncate` checks `kind == Kind::File`, so
emptying a directory is not spelled "truncate" — `REMOVE_AT` already refuses a
non-empty directory and that is the only removal a directory has.

**No length argument, and that is a narrowing rather than an oversight.**
Linux's `ftruncate` takes a length and can *extend* a file as well as shorten
it. Extending means a sparse file, which this format has no representation for,
and shortening to a non-zero length means freeing a suffix and keeping a
prefix — real work in the block arithmetic for no caller that exists. `O_TRUNC`
and `ftruncate(fd, 0)` are what a shell needs, so those are what this answers,
and `ftruncate` to any other length is refused with `EINVAL` rather than
rounded to zero.

### What the adapter does with it

`open_writable` already computes `plan.truncate` and throws it away — the same
shape as `plan.writable` before RFC 0060 step 3. When the plan says truncate and
the name already existed, the adapter calls `TRUNCATE` on the handle it was just
given, before the descriptor reaches the process. On the create path there is
nothing to do, because a created file is empty.

`ftruncate(2)` becomes a descriptor lookup, the same `entry.writable` check
`write` makes, and the same call — the reason it is in scope here rather than
deferred is that it is those three lines once the method exists.

### Failure behaviour

A truncate that reaches the service and fails leaves the file as it was: the
freeing is staged inside one transaction and committed at the end, which is
`Volume`'s existing discipline and the reason the journal exists. A truncate
that fails *during* an `open` fails the open, rather than handing back a
descriptor to a file that is neither its old length nor empty.

No `unsafe`, in any of the three programs. The bytes never move; only the
bitmap and one inode do.

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **`REMOVE_AT` then `CREATE_AT` in the adapter** | Ten lines, no protocol change, and it lies: the file gets a **new inode**, so anything holding a second descriptor is silently pointing at a dead one. Invisible to a shell and wrong for everything else, which is the worst combination — it would be found by a program that deserved better. It also cannot express `ftruncate`, which has no name to re-create | Never for this. If an adapter-only stopgap were ever needed it would be a stated lie with a trigger, not a fix |
| **Refuse `O_TRUNC` with `EOPNOTSUPP`** | Honest, four lines, and it breaks `echo x > existing_file` outright at the hosted shell. Worse for L1 than the silent tail it replaces, because the silent tail at least lets a shell run | The truncate method were somehow blocked, and a loud failure were better than a quiet wrong answer while it was |
| **A length argument on `TRUNCATE`** | Extending needs sparse files, which this format cannot represent; shortening to a non-zero length is suffix arithmetic for no caller. Both are speculative generality in a shared protocol | A program needs `ftruncate(fd, n)` for non-zero `n` — a database preallocating a file is the obvious one, and that is L3 |
| **Truncate as a flag on `OPEN_AT`** | Fewer round trips, and it puts a *mutation* on the method every read path uses. `OPEN_AT` is reachable from the read-only root; a flag there would mean the badge check moves inside a method that does not otherwise need one, and one day somebody would pass the flag from a read path | The round trip were measured to matter, which it is not: a truncate happens once per open, against a journal commit that dominates it |

## Impact on existing design documents

* **[RFC 0060](0060-a-writable-path-for-a-hosted-process.md)** unresolved
  question 5 is answered by this RFC and must say so. Its Alternatives row
  refusing `ftruncate` becomes a row this RFC supersedes, with the trigger
  recorded as met rather than the row deleted.
* **`docs/roadmap.md`** L1 row names the `O_TRUNC` gap; it closes.
* **`TRACKER.md`** §7, and §4's libc row.
* **`docs/security.md`** T11: no new authority. The adapter already holds the
  writable directory, and this is a method on a handle derived from it — worth
  one sentence saying exactly that, because the note enumerates what a
  compromise reaches and "it can also empty files under `/tmp`" is within what
  "create, fill, remove" already says.

## Security implications

**No new authority.** `TRUNCATE` is gated by `dir::WRITABLE`, a badge only the
kernel mints, on a handle the adapter already holds. A program that could not
write a file cannot empty one; a program that could write it could already
overwrite every byte, so emptying is strictly less than it had.

**No new parser.** The method takes no arguments — not even a name — so there
is no untrusted input and no fuzz target is owed. That is a deliberate property
of putting the file in the handle rather than in a `Chunk`.

**One thing worth stating plainly**: truncation is the first operation that
destroys data a hosted process did not write in the same call. `REMOVE_AT`
already does, so this is not a new class, and both are confined to the one
writable directory by the same capability.

## Performance implications

A truncate is one journal transaction: a bitmap run and one inode. It should
cost about what a `create` costs, which the boot report already prices at
3.8–4.4 ms a block for the staging write and 3.4–8.3 ms for a format block.
**What to measure on the boot that first does it**: the truncate against a
`create` on the same volume, so the two are comparable rather than one asserted
to be like the other.

An `open` with `O_TRUNC` on an existing file costs one extra round trip. That is
once per open and against a journal commit, so it is not expected to show; if it
does, the number goes here.

## Testing plan

* **Host** — `Volume::truncate` is pure filesystem arithmetic and is where the
  weight goes: a file with only direct blocks, one with an indirect table
  (which is what RFC 0065 taught us to check), the free-block count returning
  to exactly its pre-write value, the generation surviving, a directory
  refused, and a truncate of an already-empty file being a no-op rather than an
  error. Each armed by breaking the rule it guards.
* **QEMU** — the gate that matters, and it must be the one a 48-byte line
  cannot fake: a hosted program writes a **long** body, closes, reopens with
  `O_TRUNC`, writes a **short** one, closes, reopens read-only and reads. The
  assertion is that what comes back is the short body **and nothing after it** —
  the old tail is what a broken truncate leaves, so the gate must read past the
  short body's end and require silence there.
* **Armed both ways** — a truncate that frees nothing must fail the gate, and a
  truncate through a **read-only** handle must be refused, which is the
  containment arm and the more important one.
* **Real hardware** — not reachable, for the reason every filesystem gate is
  not: the SR550 has no disk this project's driver accepts.

## Unresolved questions

1. **Does `pkg` want this?** A package reinstalled over a shorter one has the
   same bug this RFC fixes, and `bin/shell` holds a writable `/pkg`. Not in
   scope here because no `pkg` test has produced it, and adding a caller
   without a failing case is how a method grows a second user that nobody
   measures. Whoever hits it should point at this RFC rather than write a
   second mechanism.
2. **Should `truncate` free the blocks or keep them for the next write?** Freeing
   is simpler and is what this proposes. A file rewritten to the same length
   pays for allocation twice, which nothing has measured and which a page cache
   partly hides. Left open, with the trigger being a measurement rather than an
   intuition.
3. **`O_TRUNC` on a file opened read-only** is `EINVAL` on Linux and would be
   here too, by `plan_openat`'s existing access-mode arithmetic. Worth a host
   test; not worth a design decision.

## What blocks acceptance — 2026-09-13

**`make test` is red with this change and the reason is unresolved.** Everything below is
measured; the explanation is not.

| measurement | result |
|---|---|
| `HEAD` (40dff2e), unmodified | **0 of 8** boots leak |
| this branch | **7 of 8** boots leak |
| `HEAD` plus five extra plain opens | 0 of 6 — so it is **not traffic volume** |
| probe phases reordered | 5 of 6 — so it is **not phase ordering** |
| the probe quiescent at sample time (short spin) | 3 of 3 leak |
| which slot | index 2 (slot 125), exactly one, read off a held-slot bitmask |
| claims against releases | claims **equal**; one **release** missing |
| `holders()` miscounting? | **no** — the not-last counter is 0 on every boot |

So: one slot, one missing release, not a bad holder count, not volume, not ordering.

**And one result that fits none of it.** A *long* spin added after everything the probe does
makes the count read clean 3 of 3 — while the log shows the report sampled at line ~531 and the
spin beginning at ~536. A change after the measurement cannot alter the measurement. Either the
log's order is not the time order, or the probe's *exit* is involved, or the instrument is
wrong. That contradiction is the reason this is parked rather than pushed through: the next
person should start by timestamping the sample rather than trusting log position, which is
exactly what stopped being trustworthy here.

**What is not in doubt**: the feature itself. `Volume::truncate`, the service method, the
adapter paths and all five checks behave as specified, and four of the five were watched failing
against the rule each guards. The block is the slot accounting around it, not the emptying.

**Bisected as far as it goes**: removing the whole `ftruncate` phase from the probe is clean
(4 of 4), as is removing the truncate phase (4 of 4); within the phase no single call owns it —
dropping the `EINVAL` probe still leaks 3 of 4, dropping the reopen-and-read still leaks 1 of 4,
and open-and-close alone is clean 3 of 3. That pattern is monotonic in how much the phase does,
which is what made volume the obvious suspect — and the attribution test above refuted it.

## Implementation plan

**Every step below is built and its checks pass; none of it is landed.** The ticks are about
the code, not about the tree — see *What blocks acceptance* above.


1. ✅ **Done.** `Volume::free_contents` extracted from `Volume::remove`, with
   `remove` calling it and its existing tests unchanged. **Arming proved the
   sharing**: breaking the extracted function fails *both* truncate's test and
   `remove`'s, which is the property that made extracting it worth more than
   writing it twice.
2. ✅ **Done.** `Volume::truncate` and four host tests: identity kept (kind,
   links and **generation**), the indirect table's blocks counted back out of
   the allocator, an empty file costing nothing, and a directory refused.

   **The leak test was wrong first, and arming is what said so.** Its first
   version wrote and truncated twenty times and asserted the volume did not run
   dry — which passes against the leak, because twenty rounds strand forty
   blocks and a 256-block volume absorbs that. It asks the allocator for the two
   specific blocks back now, as `remove`'s own test does.
3. ✅ **Done.** `dir::TRUNCATE` = 10 in `abi`, and the arm in `bin/fsd` behind
   `refused_read_only`, beside every other method that changes something.
4. ✅ **Done.** `open_writable` honours `plan.truncate` on an existing file —
   and zeroes the `Entry`'s size, because `OPEN_AT` answered the length the file
   had a moment earlier and believing it would make the first `read` ask for
   bytes that are gone. `ftruncate(2)` on a writable descriptor, non-zero length
   refused with `EINVAL`, and the probe exercises **both** paths: a constant
   declared and never called is how an untested call ships.
5. ✅ **Done.** The boot gate — long body, `O_TRUNC`, short body, read back
   **128 bytes**, and require the read to stop at 5. Armed both ways, and both
   print the same sentence from opposite causes: the adapter ignoring `O_TRUNC`
   as it did before this RFC, and the service truncating nothing —
   `hosted trunc read back 64 bytes, wanted 5 -- the old body is still there`.
6. ✅ **Done.** RFC 0060's question 5 and its superseded Alternatives row,
   `docs/roadmap.md`'s L1 row, and `TRACKER.md`. `docs/security.md` T11 needs
   no change and that is checked rather than assumed: this adds no authority,
   only a method on a handle derived from the writable directory the adapter
   already held.
