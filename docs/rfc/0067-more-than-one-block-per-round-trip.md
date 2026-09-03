# RFC 0067: more than one block per round trip

| | |
|---|---|
| **Status** | 🔨 **Steps 1 and 2 landed 2026-09-02, inert and verified. Step 3 attempted and reverted the same day: a run of blocks needs one buffer the *device* sees as contiguous, which this RFC did not account for.** See "What step 3 found" |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | block (`bin/blkd`, `bhaskix_abi::block_ring`) / kernel |
| **Milestone** | Phase 2 — Linux personality (L1) |
| **Depends on** | [RFC 0016](0016-a-block-service-in-its-own-domain.md), [RFC 0066](0066-one-commit-for-many-blocks.md) |

---

## Summary

Every 4 KiB block this system writes costs one round trip to `bin/blkd`, and that round trip — not
the journal — is what dominates the disk. The boot report prices it. The service's ring already
parameterises by sector count; what is one block is the *payload area* and the objects on either side
of it.

## Motivation

The kernel now prices both halves of what a boot pays for the disk:

    disk format    128 block(s) written in 947 ms; 7403 us per block
    hosted stage   76992 bytes in 19 block(s), 96 ms; 5087 us per block

Across boots the format is **437–1,061 ms** and the staging **72–137 ms**. The per-block costs
overlap — 3.4–8.3 ms for a *raw* device write against 3.8–5.1 ms for a *journalled* one — which is
the finding that motivates this: RFC 0066 removed the transaction and the cost barely moved, because
a round trip to another domain dominates both.

And it is the standing obstacle to the milestone. A filesystem large enough for BusyBox is about 600
blocks, so the format alone would be **2–5 seconds** of every boot.

## What is already in place

Established by reading, 2026-09-02:

- `block::WRITE` takes a sector **count** in `args[1]`.
- `bin/blkd` clamps it to `ring::SECTORS = 8` — not because the protocol says so, but because the
  payload area runs from `DATA` at `0x2800` to `REPORT` at `0x3800`: exactly one 4 KiB block.
- The virtio descriptor is already `(count * 512) as u32`, and `DRAIN`/`FILL` already take a length.
  Neither hard-codes a block.
- The layout has **one owner** since this morning — `bhaskix_abi::block_ring`, with compile-time
  assertions that the payload ends before the report and the report is inside the object. It was
  derived twice until then, and this RFC's first step is what would have broken that.

So the service side needs a bigger payload area and a larger `SECTORS`, and nothing else.

## Design

**Three parts, and each is useless alone — which is why this is written down rather than started.**

1. **The ring grows.** `DATA` keeps its offset, `SECTORS` rises to 64 (32 KiB), `REPORT` moves past
   the payload, and `PAGES` rises to cover it. The assertions already added check both. The kernel's
   `shared::create` for the rings takes `block_ring::PAGES` rather than a literal 4.

2. **The caller's object grows.** The disk-journal domain's object is one frame
   (`shared::create(owner, FRAME_SIZE)`), and `DiskStore` addresses `frames[0]` alone. A caller that
   wants to hand over 32 KiB needs an object that large, and its frames are **not contiguous** — so
   the copy into it is per frame, and `DISK_FRAME` becomes a slice rather than one address.

3. **A caller asks for more than one block.** `fs::Store::write` is one block by contract and should
   stay that way. The kernel's disk *format* loop is the caller worth changing: it already holds the
   whole image in memory and writes it block by block, and it is the larger half of the cost.

## Alternatives considered

**Raise `SECTORS` alone.** Gains nothing: every caller asks for eight, so the clamp never binds.
Worth stating because it is the tempting one-line version.

**Batch inside `DiskStore::write`.** It cannot: the `Store` contract hands it one block and the next
block may not be adjacent.

**Skip the service for the format.** The kernel writing the device directly would be faster and would
undo RFC 0016's whole point: the driver is in a domain, and the kernel reaching past it is the
architecture this project does not have.

## Impact on existing design documents

- `docs/roadmap.md`'s L1 row, which names this as what stands between here and BusyBox on the disk.
- `TRACKER.md` §7's measurements of 2026-09-02, which this is the follow-through for.

## Security implications

A larger payload area is more memory the block service and its caller share, and it is the same
memory with the same rights — the object is created by the kernel and named by slot, and neither side
gains a reach it did not have. The device sees a longer descriptor, which is what a longer transfer
is.

## Performance implications

The point. At 64 sectors the format's 128 calls become 16, and if the per-call cost is dominated by
the round trip rather than the bytes — which the overlap above says it is — that is close to an 8×
cut on the larger half of the disk's boot cost. **Predicted, not measured**, and the measurement is
step 3's gate.

## Testing plan

1. The existing block-service gates, unchanged: they assert what a sector read and written contains,
   and a larger payload must not change either.
2. The `disk format` line the boot already prints, before and after, on the same host.
3. A write of more than one block read back through a reader that never saw the cache — the shape
   RFC 0065's tests already use.
4. Armed: shrink `SECTORS` back to 8 with the callers batching, and the service must refuse or
   short-write rather than silently truncate.

## Unresolved questions

Whether the staging write should follow. It goes through `Volume::write_run`, which is journalled and
whose blocks are allocated together but need not be adjacent — so it would need a scatter list rather
than a longer transfer, which is a larger question than this.

## Implementation plan

1. The ring grows; nothing else changes and every gate stays green.
2. The caller's object grows and `DiskStore` addresses it per frame.
3. The format loop asks for a run, and the boot report says what it cost.


---

## What step 3 found (2026-09-02)

Steps 1 and 2 landed and are inert by design: the ring carries 64 sectors, the caller's object holds
eight pages, and nothing asks for more than eight sectors yet. Both were verified by a boot that
behaves exactly as before.

**Step 3 was written, failed, bisected, and reverted.** The format loop copied eight blocks into the
object's eight frames and issued one `block::WRITE` for 64 sectors. The boot then failed at
`disk journal FAILED at stage 3` — the image on the disk would not mount.

The bisect is the useful part: **with the run forced to one block the new code path works**, so the
copy, the IPC shape and the reply check are all right, and it is the multi-block case alone that
fails. That leaves the payload.

**What this RFC did not account for — WITHDRAWN 2026-09-03, it was wrong.** The explanation
written here on the day was that `bin/blkd` describes the payload as *one* virtio descriptor, so a
sixty-four-sector transfer would span eight pages of a shared object whose frames need not be
adjacent, and that batching therefore needed a descriptor chain or a physically contiguous payload
area. It was recorded as unchecked. It has now been checked, and every part of it is false.

* **The device already sees the object contiguously.** `iommu::map_memory` allocates one contiguous
  device-address range and places each frame at its own offset inside it, and says why in its own
  comment: *"the object's frames need not be contiguous in physical memory, and the device needs
  them contiguous in its address space — which is most of what an IOMMU is for."* Physical
  adjacency is exactly what the window makes irrelevant.
* **The ring layout already fits sixty-four sectors**, and says so at compile time:
  `assert!(DATA + SECTORS * 512 <= REPORT)` holds with no slack — `0x2800 + 0x8000 == 0xa800`.
* **The object is already big enough.** Step 1 made the kernel size it from
  `block_ring::PAGES`, twelve frames, rather than the literal four it used before.

So there is no descriptor chain to write and no contiguity problem to solve. **Step 3's failure is
unexplained again**, and this section is left saying that rather than carrying a mechanism that
reads like an answer. What remains true and measured is the bisect — one block works, eight do not
— and everything it eliminates: the copy, the IPC shape and the reply check are all correct.

The next diagnosis has to start from the parts this never examined: the sector number computed for
a batched request, and what `bin/fsd`'s journal expects of a write that covers eight blocks at once.

The measurement that motivated the RFC is unchanged: the format is the larger half of the disk's
boot cost, at 3.4–8.3 ms a block, and 128 blocks of it.
