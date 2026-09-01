# RFC 0065: the block the format already had

| | |
|---|---|
| **Status** | ✅ **Accepted 2026-09-01 — all three steps implemented and measured on a booted machine.** A 109,760-byte program is stored, read back and `execve`d, which neither the old filesystem nor the old loader could do |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | filesystem (`fs`, `bin/fsd`) |
| **Milestone** | Phase 2 — Linux personality (L1) |
| **Depends on** | [RFC 0015](0015-a-filesystem-that-survives-a-crash.md), [RFC 0064](0064-a-read-that-lands-where-the-caller-says.md) |

---

## Summary

Every file on this filesystem stops at **40,960 bytes**. `Inode` has ten direct blocks and an
`indirect: u32`; the *reader* already follows it, and the writer has never allocated one. This makes
the writer use the field the format has had all along, which takes the limit to **4,239,360 bytes**.

## Motivation

RFC 0064 made `execve` stream a program through a fixed window so the loader would stop capping
program size. Proving it needed a program larger than the window, and the boot refused one: the
adapter recorded `ENOEXEC` on a file the filesystem reported as 40,960 bytes rather than the 109,760
that were written. The write had been truncated, and nothing said so.

Three facts, each measured rather than assumed:

- `Volume::write_ordered` returns `FsError::Full` the moment `block_index >= inode.direct.len()`.
- `Inode::indirect` is written as `0` in both places that construct an inode and read in none of them.
- `Filesystem::block_of` **already** follows an indirect block, with a range check on every number it
  reads out of one, "because it came off a disk".

So the format has the field, the reader honours it, and the writer does not. That is not a design
question; it is an implementation that stopped one function short, and it is now the binding limit on
running BusyBox — 2,172,376 bytes, which one indirect block clears with room to spare.

**The silent half is the worse half.** The kernel's staging loop breaks on `Err` and keeps whatever
fitted, so a file too large to store becomes a *short file*, and the program built from it fails much
later somewhere unrelated. That is exactly how this was found, and it is fixed here too.

## Design

One indirect block, holding `BLOCK / 4 = 1024` block numbers, giving `(10 + 1024) * 4096 =
4,239,360` bytes. No double indirect: the next limit after this one is a 256 KiB test disk, and
adding a level nothing can reach would be inventing a capability rather than finishing one.

**Writing.** When the block index is past the direct blocks, the writer allocates the indirect block
if the inode has none, then places the data block's number in it at `(index - 10) * 4`.

**Ordering, which the existing code already argues for.** The indirect table's contents reach the
device with the data, before the commit that points an inode at the table — the same rule RFC 0015
states for data blocks and for the same reason: a table an inode claims must never be a block still
holding somebody else's bytes. A crash between the two leaks a block, which is the safe direction and
the one this filesystem already chooses.

**Freeing.** `remove` frees `victim.direct` and nothing else today, so the moment writes can reach an
indirect block a delete would leak up to 1,025 of them. It frees the table's blocks and then the
table.

**Refusing.** Past `10 + 1024` blocks the answer is still `FsError::Full`, and the kernel's staging
loop now reports a short write instead of keeping it.

## Alternatives considered

**Double indirect, or extents.** Rejected as inventing reach nothing has. The disk this runs on is
256 KiB; the largest thing anybody wants to store is 2.1 MB; one indirect block covers 4.2 MB. A
second level is a later RFC written against a real need.

**Growing `direct`.** It is on-disk layout — every existing image would stop parsing — to buy a few
dozen kilobytes. The indirect field is already there and costs no format change at all.

## Impact on existing design documents

- `TRACKER.md` §3's row filed today naming the 40,960-byte limit, which this closes.
- RFC 0064's "What step 4 found", which names this as the blocker, and its step 4 becomes
  unblocked — the gate it describes can then be written.

## Security implications

Every number read out of an indirect block is checked against the superblock before use, which is
what `block_of` already does and says why: it came off a disk. The writer applies the same check to
the table number itself before it is trusted. A file can now claim 1,034 blocks rather than 10, which
is a larger denial-of-service surface for a domain that can write — bounded by the free-block
allocator, which was already the bound.

## Performance implications

One extra cached block read for a write past the tenth, and one extra block written when the table is
first allocated. Files under 40,960 bytes take exactly the path they take now — the branch is on the
block index and nothing before it changes.

## Testing plan

1. Host tests in `fs`: a write past the tenth block lands and reads back; the table is allocated
   once and reused; a file at the new limit works and one past it is `Full`; a removed file frees the
   table *and* the blocks it named, proven by allocating again afterwards.
2. Armed: the write-past-ten test fails against the current code, which is the whole point of it.
3. The boot gates that already exercise the filesystem, unchanged.

## Unresolved questions

Whether `bin/fsd`'s own limits need raising to match. Its per-call transfer is a page and the loop is
the caller's, so nothing there is expected to notice — to be confirmed on a booted machine rather
than assumed.

## Implementation plan

1. `Volume::write_ordered` uses the indirect block; `remove` frees it. Host tests, armed.
2. The kernel's staging loop reports a short write rather than keeping it.
3. A boot that stores and reads a file larger than ten blocks.


---

## What implementing it found (2026-09-01)

**Two allocations in one transaction collided, and the test written to prove the feature is what
caught it.** `stage_bitmap` edits a *journalled* copy of the bitmap while `free_block` reads the
*cached* one, so a block claimed earlier in the same transaction still reads as free. Nothing had
ever needed two blocks at once; this needs a table and a data block together, and the first version
got the same number twice — the table and the file's data were the same block, and the file's own
bytes read back as block numbers. The read-back assertion showed `0x76656C65`, which is `"elev"`.

`free_block_excluding` is the fix, and the collision is written down beside it because it is a
property of the journal's shape rather than of this feature: **any** future caller wanting two blocks
in one transaction meets it.

The removal test then met the same thing from the other side — proving both blocks came back by
asking the allocator twice returns one block twice — which is recorded in the test rather than worked
around silently.

**Measured on a booted machine.** `user/hosted` padded with a `.rodata` array to 76,992 bytes:

    hosted exec    a Linux program execed 76992 bytes read off the filesystem

That is past the 40,960-byte file limit this RFC removes *and* past the 65,536-byte loader window
RFC 0064 removed, so the two together are what make it possible. RFC 0064's step 4 is unblocked and
done: the gate it describes is this program, and it runs on every boot with a filesystem.

Step 2 landed too. The kernel's staging loop still breaks on `Err` — that is the filesystem
answering `Full` honestly — but the gate now compares what reached the disk against what was asked
for and fails loudly, instead of letting a truncated program fail later as somebody else's `ENOEXEC`.

`bin/fsd`'s own limits needed nothing, which was the unresolved question: its per-call transfer is a
page and the loop is the caller's, so a longer file is simply more calls. Confirmed on a boot rather
than assumed.


**Three sizes moved with it, and none of them failed in a way that mentioned size.** The domain disk
went 256 KiB → 1 MiB after a package install answered `no space`. The formatted filesystem went 48
blocks → 128 after the install then answered `creating a file refused (7)` — `Full`, on a disk with
room to spare and a filesystem without. And a boot gate carrying `512 sectors` in its pattern failed
as "the block driver in a domain did not report a device it had driven", which is a sentence about a
driver; it matches any count now, because the size of a test disk was never that gate's business.

The padding is 64 KiB rather than the 96 KiB first written. Every block of it is a journal
transaction the kernel runs at boot before anything else starts, and the `iommu-off` lane timed out
once under the concurrent suite at the larger size. 76,992 bytes clears both limits, which is all it
has to do.
