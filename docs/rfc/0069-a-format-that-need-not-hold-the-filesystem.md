# RFC 0069: a format that need not hold the filesystem

| | |
|---|---|
| **Status** | ✅ **All three steps landed 2026-09-04.** The filesystem is now the disk's size, the format writes 13 blocks instead of 128, and 2,172,376 bytes of BusyBox are on it. See "Steps 2 and 3" |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | fs (`bhaskix_fs::format`) / kernel |
| **Milestone** | Phase 2 — Linux personality, application milestone **L1** |
| **Depends on** | [RFC 0015](0015-a-filesystem-with-a-journal.md), [RFC 0065](0065-the-block-the-format-already-had.md), [RFC 0068](0068-a-disk-that-can-hold-busybox.md) |

---

## Summary

`format` takes a byte slice and derives the filesystem's size from its length. The image *is* the
filesystem, so declaring a larger one means holding all of it in kernel memory and writing all of it
to the device. Separating the two — a buffer that holds the metadata, an argument that declares the
size — makes a 540-block filesystem cost **53,248 bytes and 13 block writes** instead of 2,211,840
bytes and 540, and shrinks the kernel while doing it.

## Motivation

RFC 0068 set out to give a hosted BusyBox somewhere to live and found the binding limit was not the
disk but the formatted filesystem: a fixed 128 blocks, laid out in `JOURNAL_IMAGE`, a
`[u8; 128 * BLOCK]` static. Its flag reports the consequence exactly —
`busybox disk FAILED: 364544 of 2172376 bytes reached the disk`, which is the 89 blocks left of 128.

Growing that the obvious way costs a 2.2 MiB kernel static, paid in `.bss` on every boot whether or
not anything is staged, and about 260 ms of formatting on every boot that formats. Both follow from
one line:

```rust
pub fn format(bytes: &mut [u8], inodes: u64) -> Result<Superblock, FsError> {
    let blocks = (bytes.len() / BLOCK) as u64;
```

**A format does not need to write a filesystem's data blocks.** It writes a superblock, a bitmap, an
inode table and a journal. Data blocks are marked free in the bitmap, and nothing reads one before it
has been allocated and written — which is why `mkfs` does not zero a disk either.

## Design

```rust
pub fn format_sized(bytes: &mut [u8], inodes: u64, blocks: u64) -> Result<Superblock, FsError>
```

`blocks` declares the filesystem; `bytes` holds what the format actually lays out. The existing
`format(bytes, inodes)` becomes `format_sized(bytes, inodes, bytes.len() / BLOCK)` and keeps its
behaviour exactly, so every current caller and every host test is unaffected.

**What `bytes` must hold** is the metadata prefix — superblock, bitmap, inode table, journal — which
the function already computes:

```rust
let bitmap_blocks = blocks.div_ceil(BLOCK as u64 * 8).max(1);
let inode_blocks  = (inodes * INODE as u64).div_ceil(BLOCK as u64).max(1);
let journal_start = 1 + bitmap_blocks + inode_blocks;
```

Too small a buffer is `FsError::OutOfRange`, as too small an image is today. The one new rule is
that `blocks` must be at least what the prefix occupies plus one data block, which is the same bound
`format` already enforces against `bytes.len()`.

**What the caller writes** is `bytes.len() / BLOCK` blocks, not `blocks`. That is the whole saving,
and it is the caller's loop rather than this function's business — the kernel's format loop already
takes its count from a variable.

### What it costs, for the 540 blocks BusyBox needs

With this filesystem's own constants — `BLOCK` 4096, `INODE` 64, `JOURNAL_BLOCKS` 9, 128 inodes:

| | whole image | metadata only |
|---|---|---|
| kernel buffer | 2,211,840 bytes | **53,248** |
| blocks written at format | 540 | **13** |

Thirteen blocks at the 477 us a block the format runs at since RFC 0067 is about **6 ms**, against
260. And 52 KiB is *less* than the 512 KiB `JOURNAL_IMAGE` occupies today, so the kernel gets
smaller.

## Alternatives considered

**Grow `JOURNAL_IMAGE` to 2.2 MiB.** The obvious move, and what RFC 0068 assumed. Rejected on the
numbers above: it spends four times the memory to write forty times the blocks, for a filesystem
whose data blocks are then immediately marked free.

**Format on the device, without an image at all.** Cleaner in principle and a much larger change:
`format` is pure, host-tested against a byte slice, and fuzzed at 123,501 executions as
`fs_image.rs`. Keeping it pure and letting the caller decide what to write preserves all of that.

**Leave the filesystem at 128 blocks and give BusyBox its own.** A second filesystem is a second
mount, a second journal and a second thing to get wrong, to avoid one argument.

## Impact on existing design documents

* `docs/rfc/0068` — its "the format is bounded" note and its two new cost numbers are superseded by
  this; that RFC already records the arithmetic and points here.
* `docs/rfc/0015` — the journal's layout is unchanged; only who decides `blocks` moves.

## Security implications

None. A filesystem whose data blocks were never written contains whatever the device held, and the
bitmap says they are free — the same position every allocated-but-unwritten block is in today, and
the same one `mkfs` leaves. Nothing reads a free block: `Volume::read` resolves through an inode,
and an inode names only blocks the allocator has given it.

Worth stating plainly because it is the one place this change touches confidentiality: this change
introduces no new exposure, because a block is zeroed when it is **allocated**. The write path
clears a block on the `fresh` arm — the one taken when the block has just been claimed from the
bitmap — before the writer's own bytes land in it, so a block reaching a file carries nothing of
whatever held it before, whether that was another file or the image the format never wrote.

> **This paragraph originally argued the same conclusion from a false premise, and the correction
> stays here rather than only in the changelog.** It read: *"a block freed by `remove` and
> reallocated is already handed out without zeroing, so this introduces no new exposure — but it
> does make the first allocation of a block after a format share that property, where before a
> format had zeroed it. If that is not acceptable the answer is to zero on allocation, which is a
> separate decision and priced separately."* Zero-on-allocation was not a decision waiting to be
> made; it was already the behaviour, and had been. The claim was reasoned from `remove` — which
> genuinely does not clear the blocks it frees — without reading the path that hands one out. The
> conclusion survives and is stronger than stated; the reasoning did not.
>
> Both halves are now asserted by `a_data_block_is_zeroed_when_it_is_allocated_not_when_it_is_freed`
> (`fs/src/volume.rs`), and `docs/security.md` states the property beside the matching one for
> memory frames.

## Performance implications

The table above. No path that does not format is affected, and the format itself gets faster on
every lane.

## Testing plan

1. The existing host tests, unchanged, through the `format` wrapper — this is what says the
   behaviour is preserved.
2. New host tests: a filesystem declared larger than its buffer mounts, allocates, and reports the
   declared size; a buffer too small for the prefix is refused; the declared size being smaller than
   the prefix is refused.
3. The fuzz target `fs_image.rs` keeps running against `format`, and gains the sized variant.
4. A boot where the kernel formats a filesystem larger than `JOURNAL_IMAGE` and writes only the
   prefix, with `disk format` reporting the smaller count.

## Unresolved questions

* Whether the kernel should then declare a filesystem sized from the *disk* rather than a constant.
  RFC 0068's flag wants 540 blocks; the disk holds 1024. Sizing from the device is the obvious next
  step and is deliberately not decided here.

## Implementation plan

1. `format_sized`, with `format` delegating to it. Host tests as above.
2. The kernel's two callers pass a declared size; the format loop's count comes from the buffer.
3. RFC 0068's flag stages BusyBox into a filesystem that can hold it, and its `busybox disk` line
   stops being a measurement of the limit and becomes a demonstration.


---

## Step 1, landed (2026-09-04)

`format_sized(bytes, inodes, blocks)` is in, and `format` is `format_sized(bytes, inodes,
bytes.len() / BLOCK)` — so the whole existing suite exercises the new function through the old
name, which is what says the behaviour is preserved rather than a comment claiming it.

Four host tests, each watched red:

* a filesystem of **540 blocks laid out in a 13-block buffer**, which is the case this RFC exists
  for, asserting both that the superblock declares 540 and that the prefix fits what was written;
* a buffer too small for the metadata is **refused, not truncated** — half an inode table mounts and
  then loses files;
* a declared size too small for its own layout is refused, at both ends;
* `format` and `format_sized` over the same buffer produce **byte-identical images**.

The one thing worth noting from writing it: `if (bytes.len() / BLOCK) as u64 < superblock.data_start`
does not parse — `as u64 <` is read as the start of generic arguments. It needs the cast
parenthesised, and the compiler says so clearly enough that this is a footnote rather than a
finding.


## Steps 2 and 3, landed (2026-09-04)

The kernel's disk format now declares a filesystem the size of the device and writes only its
metadata:

```
fs domain      mounted the disk through the block service: 8192 sectors, 1024 blocks
disk format    13 block(s) written in 5 ms
```

Against 128 blocks in 36 to 93 ms before. **Raising the ceiling eightfold made the format about
twelve times faster**, which is the shape this RFC argued for: the cost was never the filesystem's
size, it was writing a filesystem's worth of blocks that nothing was going to read.

And RFC 0068's flag now says what it was built to say:

```
busybox disk   2172376 bytes of BusyBox staged onto the filesystem in 1567 ms,
               so a hosted execve has a real shell to resolve
```

All 2,172,376 bytes, on a passing boot, in 1.567 seconds — inside the 2.1 to 3.4 seconds RFC 0068
predicted after the staging variance was fixed.

**What this does not claim.** BusyBox is *on the filesystem the adapter's directory capability
resolves through*. Whether a hosted `execve` of it returns a running shell is untested here: nothing
in the tree yet execs it, and RFC 0068's step 3 gate — a hosted `sh` running one command — is not
written. The number that stopped it is gone; the demonstration is the next piece of work.

The unresolved question above is answered by step 2 rather than left open: the filesystem is sized
from the device, `(sectors / 8)`, because the alternative is a constant that has now been wrong
twice.
