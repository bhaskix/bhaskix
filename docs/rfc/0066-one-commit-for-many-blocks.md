# RFC 0066: one commit for many blocks

| | |
|---|---|
| **Status** | ✅ **Accepted 2026-09-01 — implemented and measured on a booted machine: 16.7 ms a block became 3.8–4.4, and BusyBox's projected cost fell from about 8.9 s to about 2.1 s** |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | filesystem (`fs`) |
| **Milestone** | Phase 2 — Linux personality (L1) |
| **Depends on** | [RFC 0015](0015-a-filesystem-that-survives-a-crash.md), [RFC 0065](0065-the-block-the-format-already-had.md) |

---

## Summary

`Volume::write` is one journal transaction per 4 KiB block, and this kernel's own boot report prices
that at **14–47 ms a block**. A file's data blocks are never staged — only its inode and bitmap are —
so one transaction can cover as many data blocks as the caller has, and the metadata cost does not
grow with them. This adds that path beside the existing one.

## Motivation

RFC 0064 and RFC 0065 removed the two limits that stopped a hosted `execve` of BusyBox: the loader's
staging window and the filesystem's ten-direct-block file limit. What stops it now is time, and the
number is measured rather than estimated — the boot report says

    hosted stage   76992 bytes in 19 block(s), 317 ms; 16707 us per block

so BusyBox's 531 blocks would add **7.5 to 25 seconds** to a boot, on a lane that has already timed
out once at 120 s. That is the whole of the remaining distance.

**The cost is per transaction, not per byte.** Each `write` does: copy the metadata into the journal,
flush, write and flush the commit block, write the metadata to its homes, flush, clear the commit.
That is four device flushes and a handful of writes to move one block of data. Doing it 531 times to
store one program is paying the durability price 531 times for a change that is, from the
filesystem's point of view, one change.

## Design

`Volume::write_run(index, offset, data)` writes whole blocks in **one** transaction and answers how
many bytes went.

**Why the metadata does not grow with the data.** RFC 0015 does not journal data: a data block is
written straight to its home *before* the commit, so that a block an inode claims can never be a
block still holding somebody else's bytes. Only the inode and the free-block bitmap are staged. A run
of blocks touches one inode and — because a bitmap block covers 32,768 blocks — almost always one
bitmap block, plus at most one indirect table. `stage` already returns the existing slot for a home
it has seen, so those are **three** of the eight a transaction may hold, whatever the run's length.

**Allocation in one pass.** `free_block` scans from the start of the data area for each call, which
is quadratic over a run and, worse, hands out the same number twice inside a transaction because the
bitmap it reads is the cached one and `stage_bitmap` edits a journalled copy — RFC 0065 met that and
worked around it for two blocks. `free_blocks` collects what a run needs in a single scan, which
removes both.

**The bound.** A run is refused if it would need more than the eight staged blocks, and the caller is
told how many bytes went so it can continue with a second call. Partial success is honest here in a
way it is not inside a transaction: each call is atomic, and a caller looping over calls is a caller
making several changes, which is what it is.

**What does not change.** `Volume::write` keeps its shape and its comment: *"a write spanning blocks
would be several transactions, and several transactions is several acknowledgements, so saying so is
more honest than looping here and implying one."* That is a good reason for the API it has. It is not
a reason there cannot be a second one beside it that spans blocks *and says so*.

## Alternatives considered

**Make `write` itself span blocks.** Rejected: it would change what an existing caller's single
acknowledgement means, and the shell's package install depends on that meaning.

**Batch at the caller.** The kernel's staging loop could hold a buffer and write once — but the
transaction boundary is the filesystem's to own, and a caller assembling one would be reimplementing
the journal's contract outside it.

**Skip the journal for a file being created.** Tempting and wrong: a crash mid-write would leave an
inode claiming blocks the bitmap does not, which is exactly the corruption RFC 0015 exists to
prevent.

## Impact on existing design documents

- `docs/roadmap.md`'s L1 row, which names this as the next limit.
- RFC 0065, whose `free_block_excluding` this subsumes for runs — it stays for the single-block path.
- `TRACKER.md` §7.

## Security implications

None new. A run allocates the same blocks the same way and checks each against the superblock exactly
as the single-block path does. A caller can consume free space faster, which the free-block allocator
already bounds and which was never rate-limited.

## Performance implications

The point of the change. One transaction rather than N: four device flushes total instead of 4N, with
the data writes unchanged at one per block. The boot report already prices the current path, so the
new one can be compared against a number this tree has rather than a claim.

## Testing plan

1. Host tests in `fs`: a run lands and reads back through a reader that never saw the cache; the
   blocks it allocated are distinct; a run needing more than eight staged blocks is refused rather
   than half-written; a run that crosses from direct blocks into the indirect table works.
2. Armed: the distinctness test fails against a naive loop of `free_block`.
3. The kernel's staging loop uses it, and the boot report's `hosted stage` line prices the result
   against the 14–47 ms per block it reports today.

## Unresolved questions

Whether the cache's eight frames become the next bound once the transaction stops being one. Writing
a long run evicts continuously, and each eviction is a device write — which is one write per block
either way, so it should not, but "should not" is what the measurement in step 3 is for.

## Implementation plan

1. `free_blocks`, collecting a run in one scan, with host tests.
2. `write_run`, with host tests, armed.
3. The kernel's staging loop uses it; the boot report shows the difference.


---

## What it measured (2026-09-01)

The kernel's staging of `bin/hosted` is the same write before and after, so the boot report compares
the two paths directly:

| | per block | 19 blocks | BusyBox's 531 blocks |
|---|---|---|---|
| `write` in a loop | 14,037–46,715 µs | 266–887 ms | 7.5–25 s |
| `write_run` | 3,811–4,421 µs | 72–84 ms | **2.0–2.3 s** |

Between **3.5× and 10×**, depending on how loaded the host is — and the spread narrows, which is
what paying a fixed cost once instead of N times looks like.

**Two things the implementation got wrong first, both caught by the tests written to prove it.**

The table was allocated by a *second* scan, which returns a block the run has already chosen —
nothing is marked used until the commit — so the first draft detected the collision and answered
`Full`. That is a refusal invented by the allocator rather than by the filesystem being full. The
table comes out of the same scan now, taken from the end so that a short scan shortens the run
instead of losing the table.

And `a_run_allocates_distinct_blocks` was armed by replacing `free_blocks` with a naive loop of
`free_block` — the way the single-block path allocates — and it fails, as does the read-back test.
That is the whole reason `free_blocks` exists, and now the reason is checked rather than asserted.

## What is still true

`Volume::write` is unchanged, keeps its one-transaction-per-block meaning, and keeps its comment.
`write_run` refuses an unaligned offset and falls back to it for anything shorter than a block, so
the tail of a file is written the way it always was. The cache's eight frames did **not** become the
next bound, which was this RFC's unresolved question: the measurement above answers it.
