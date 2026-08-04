# RFC 0009: Shared memory, and the objects that name it

| | |
|---|---|
| **Status** | **Draft — for discussion.** |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | kernel (`cap`, `vm`, `syscall`), mm |
| **Milestone** | Phase 2 — required before user-mode drivers or any bulk data path |
| **Depends on** | [RFC 0008](0008-syscall-and-ipc-shape.md) (which promises this), [security.md](../security.md) §2, [memory.md](../memory.md) §3 and §5 |

---

## Summary

A new object kind, **`Memory`**: a kernel-owned set of frames that a
capability can name, that a domain can map into its own address space with
rights no wider than the capability carries, and that unmaps from *every*
address space that mapped it before a `revoke` returns.

This is the piece [RFC 0008](0008-syscall-and-ipc-shape.md) named and did not
build. That RFC fixed a message at four registers and said in two places that
anything larger "travels as a capability to shared memory". There is no such
capability, so today anything larger travels sixteen bytes at a time.

---

## Motivation

Three separate problems, one missing object.

**1. Bulk data moves at sixteen bytes per round trip.** M6-05's user-mode
shell reaches the console and the filesystem through IPC, and a message is
four registers of which two carry bytes. Printing its `help` output is a few
dozen context switches. Reading a file is one round trip per sixteen bytes.
The design is correct and the throughput is a placeholder.

**2. Async IPC has no substrate.** RFC 0008 rejected buffered channels in the
nucleus, on the grounds that every answer to "whose memory is the buffer"
is either a denial of service or synchronous behaviour with extra steps. The
answer it gave instead was: build async above shared memory plus a
notification capability. Neither half exists, so `Call`/`Recv` is currently
the only shape any service can have.

**3. A user-mode driver cannot be given a DMA buffer.** [memory.md](../memory.md)
§5 says a driver receives a capability "naming exactly the frames it may map".
M6-06's `virtio-blk` driver instead allocates frames from the kernel's own
allocator and hands their physical addresses to a device. That is fine for an
in-nucleus driver and is exactly the thing that cannot be handed outward — a
domain cannot be given "these frames, and only these" because there is no
object that means it.

**What happens if we do nothing.** Every service keeps the shape the shell
has: correct, capability-scoped, and slow enough that no measurement of it
means anything. The first workload that needs throughput gets a special case
in the nucleus, and the special case becomes the interface.

---

## Design

### The object

```rust
/// Physical memory a capability can name.
pub struct Memory {
    frames: FrameList,       // ordered; index i is the i-th page of the object
    length: u64,             // bytes; a multiple of FRAME_SIZE
    owner: DomainId,         // whose envelope paid for the frames
    attributes: Attributes,  // device-visible, contiguous
    mappings: MappingList,   // every (address space, address) that has it
    generation: u32,         // matches the capability arena's reuse counter
}
```

It is created by a domain, out of its own `ResourceEnvelope`:

| Method on a `Memory` capability | Effect |
|---|---|
| `MAP(address, rights)` | Map into the **caller's own** address space |
| `UNMAP(address)` | Remove that mapping |
| `INFO` | Length, and the rights this capability carries |

Creation is a method on a **`Domain`** capability, not a free-standing
syscall, because creating one spends the domain's memory quota and RFC 0008
fixes the syscall set at six. Destruction is revocation: the last capability
going away destroys the object.

### Why an object, and not a capability per frame

A capability per frame is the smaller change: `ObjectKind::Frame` is already
declared. It is also sixteen CSpace slots to share sixty-four kilobytes, and
sixteen `MAP` calls to place it, each of which can fail separately — leaving a
partially mapped buffer nobody named. One object with a length is one
allocation, one map, one failure mode, and one thing to revoke.

`ObjectKind::Frame` and `ObjectKind::Untyped` are declared and unused. This
RFC proposes **deleting `Untyped`** and keeping `Frame` for the one case that
genuinely wants a single page (a device register window). See *Unresolved
questions* — the untyped-memory model is a fork in the road, not a detail.

### Mapping into your own address space, and nobody else's

`MAP` places the object in the **caller's** address space. There is no method
that maps into another domain's, and the absence is the design: sharing
happens by handing over a *capability*, which the existing `grant` path
already does (M5-07, an `Invoke` method on a `Domain` capability). A service
that could map into a caller's address space would be a service that could
write to its callers.

So the sharing sequence is:

1. **A** creates a `Memory` object; the frames are charged to A's envelope.
2. **A** derives a capability to it with reduced rights — `READ` only, say —
   and `grant`s it into B's CSpace.
3. **B** maps it wherever it likes in its own address space.
4. Both now address the same frames. Neither can widen what it holds, because
   derivation is monotone (`security.md` §2 rule 2).

### Rights are the existing rights

`cap::Rights` already has `READ`, `WRITE`, `EXECUTE`, `GRANT`, `REVOKE`,
`DERIVE`. A `MAP` request is refused unless the capability carries the rights
it asks for, and the resulting page-table entry is exactly those rights.

**`EXECUTE` on shared memory is refused outright**, and not only for W^X.
Revocation unmaps while the other side is running: a receiver whose *data*
vanishes takes a fault it can be written to survive, and a receiver whose
*code* vanishes takes a fault at an instruction that no longer exists. Shared
executable memory is a way to make a domain's control flow depend on another
domain's timing, and there is no workload here that needs it.

### Revocation is the hard part, and the whole point

`security.md` §2 rule 3: *revoke invalidates every capability derived from it,
transitively, before returning.* For a `Memory` capability that means the
mappings must be gone too — a revoked capability whose pages are still mapped
is not revoked, it is renamed.

```
revoke(memory capability)
  → for each mapping recorded on the object:
      remove the region from that address space
      invalidate the page-table entries
      shoot down the TLB on every CPU that may have loaded that address space
  → then destroy the derivation subtree, as revocation already does
  → return
```

The pieces this needs, and their state today:

| Piece | Exists? |
|---|---|
| Cross-CPU TLB shootdown, acknowledged by every CPU | ✅ M3, `tlb::SHOOTDOWN_VECTOR` |
| A region map per address space, with removal | ✅ M3, `RangeMap` / `VmRegion` |
| Transitive capability revocation | ✅ M5-01, `Arena::destroy_subtree` |
| A **reverse map** from object to its mappings | ❌ new |

The reverse map is a bounded array on the object — `MAX_MAPPINGS`, proposed as
8. A ninth `MAP` is refused. That bound is not a limitation to apologise for:
an unbounded list is an allocation inside a path that must complete during
revocation, and revocation must not be able to fail.

**Ordering.** The mappings go first, then the capabilities. The reverse order
would leave a window in which the capability is dead and the memory is still
mapped — which is precisely the delay fuse rule 3 exists to forbid.

### Accounting

The **creator's** envelope is charged for the frames, for the life of the
object, no matter who else maps it. Sharing does not double-charge and does
not transfer the charge.

The consequence has to be stated because it is the interesting one: **a shared
region does not outlive the domain that created it.** Destroying a domain
destroys its objects, which unmaps them everywhere, which is a receiver taking
a fault. A receiver that wants memory to outlive its provider must own it
itself and grant the *provider* access — which is the correct shape for a
buffer pool anyway, and worth saying out loud so that nobody discovers it by
having a service die.

Page tables built by `MAP` are charged to the **mapper**, because they are in
the mapper's address space and go away with it.

### Concurrency

| Lock | Rank | Notes |
|---|---|---|
| The memory-object arena | between `Domains` and `Capabilities` | Taken by create, map, unmap, revoke |
| An address space's region map | existing | Taken *inside* the object arena, during revocation |

Revocation takes the object arena and then a region map, so nothing may take
them the other way round. `MAP` therefore resolves the capability, releases
the arena, and *then* touches its own address space — the pattern M5-05 used
for IPC, and for the same reason.

Nothing here runs in interrupt context. A TLB shootdown is *sent* from
revocation and handled in interrupt context on other CPUs, which is what M3
already does.

### Failure behaviour

| Situation | Answer |
|---|---|
| Out of frames at create | `QuotaExceeded` or `OutOfMemory`; no partial object |
| Out of page tables at map | The whole mapping is undone; the address space is unchanged |
| Ninth mapping | Refused, `SlotUnavailable` |
| Revocation while another CPU is mid-access | The access faults after the shootdown completes; that is the contract |
| Domain destroyed while its object is mapped elsewhere | Object destroyed, mappings removed, receivers fault |
| Two CPUs mapping the same object at once | Serialised by the arena lock; both succeed or the second is refused for want of a slot |

### Where `unsafe` is needed

Page-table manipulation and TLB invalidation, both of which already exist in
`mm` and `arch`. The object bookkeeping is safe code. **The kernel never
dereferences a shared page** — it maps it and lets the MMU do the rest. That
is worth stating, because it is the property this design keeps and a
`copy_from_user`-style interface would give up.

---

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Bigger messages** — 16 or 32 registers instead of 4 | Moves the wall, does not remove it. A file is not 256 bytes either, and every register added is saved and restored on every call including the ones that carry nothing. | Measurement showed the bulk paths are all small-but-more-than-four — i.e. the wall is in the wrong place rather than present. |
| **Kernel-copied buffers** — sender passes a pointer, kernel copies into the receiver | Reintroduces exactly what the current design does not have: the kernel dereferencing an address a caller chose, on that caller's behalf, which is the confused-deputy surface `copy_from_user` exists to police. It is also a copy, which shared memory is not. | Never for bulk. Possibly for small, bounded, one-shot transfers where the copy is cheaper than a map. |
| **A capability per frame** | Sixteen slots and sixteen fallible calls to share 64 KiB. | Only if the object turns out to need per-page rights, which no workload here has asked for. |
| **Grant by address range** — donate pages out of the sender's own address space | Ties the object to the sender's layout, and makes "who is charged" a question about a range rather than about an object. Revocation would have to reason about ranges that have since been split. | Never; this is the seL4 `Untyped`-retype question in disguise, and the object form answers it more simply. |
| **Lazy revocation** — mark dead, unmap on next fault | Violates `security.md` §2 rule 3 in the letter and the spirit. The whole value of immediate revocation is that "after `revoke` returns" is a statement you can build on. | Never. This is the rule the security model rests on. |
| **Buffered channels in the nucleus** | Already rejected by RFC 0008 §A3, for reasons this RFC does not change. | As RFC 0008 says: if measurement shows shared memory plus notification cannot reach the throughput a real workload needs. |
| **Do nothing until a workload demands it** | Defensible, and the reason this is Phase 2 rather than now. The cost of waiting is that the first workload to need it will get a special case, and special cases in a nucleus become the interface. | This is the status quo; the RFC exists so the decision is made once rather than under pressure. |

---

## Impact on existing design documents

**[memory.md](../memory.md) §3** describes `Backing` as anonymous, direct, or
reserved. A fourth arrives:

> ```rust
> pub enum Backing {
>     Anonymous,
>     Direct { physical: u64 },
>     Reserved,
>     Shared { object: MemoryId },   // new
> }
> ```

with the invariant that **tearing down an address space must not free a shared
region's frames** — they belong to the object. The frame-leak gate is what
will catch this being wrong, and it should be pointed at exactly this case.

**[memory.md](../memory.md) §5** says every DMA-capable device is behind the
IOMMU and a driver receives "a `DmaCapability` naming exactly the frames it
may map". This RFC provides the object that capability would name, and does
**not** provide the IOMMU. Until that exists, a device-visible `Memory` object
may be held only by in-nucleus code; handing one to a domain would be handing
it the machine while telling it otherwise. That restriction belongs in the
code, not in a comment.

**[architecture.md](../architecture.md) §2** says a service should be able to
run in the nucleus or in its own domain with the same interface. Today's
services move bytes in registers, which is placement-independent by accident.
Once bulk paths use shared memory, the two placements differ in what they map,
and the both-placements CI job becomes the thing that keeps the claim honest.

**RFC 0008** is not contradicted — it is completed. Its §A3 answer ("async is
built above rendezvous from shared memory plus a notification capability")
becomes buildable.

---

## Security implications

**New authority.** Yes: the ability to make another domain's memory readable
or writable by this one. That is the point, and it is why the object is
capability-named, monotone in rights, and revocable.

**What becomes reachable without a capability.** Nothing. A `MAP` needs a
`Memory` capability; obtaining one needs a `grant`, which needs a `Domain`
capability with `WRITE`.

**A property that is deliberately kept.** The kernel still never dereferences
an address a caller chose. Sharing is done by the MMU, not by the kernel
reading on someone's behalf — so the entire class of bug that
`copy_from_user` exists to contain stays out of the tree.

**A property that is deliberately given up, and what replaces it.** Two
domains now share mutable memory, so anything a receiver reads from a shared
region can change between two reads of it — the double-fetch bug, which is a
real and recurring source of kernel vulnerabilities elsewhere. The rules:

1. **Copy out before validating.** A value validated in shared memory and then
   used from shared memory has been validated twice and used once, and the two
   need not be the same value.
2. **Prefer read-only in the direction that matters.** A service handed a
   request buffer should map it `READ` and copy what it needs.
3. This belongs in `docs/coding-style.md` as a rule with the reason attached,
   at the same time as the code lands.

**New parser for untrusted input?** No. Offsets and lengths arrive in
registers and are range-checked against the object's length; there is no
structure being parsed, so there is no new fuzz target. The *contents* of a
shared region are untrusted input to whoever reads them, which is rule 1
above, not a parser.

**Denial of service.** Bounded by the envelope (frames) and by
`MAX_MAPPINGS`. A domain cannot make another domain's revocation slow, because
the work revocation does is bounded by that same number.

---

## Performance implications

**Faster:** any path that moves more than a few dozen bytes. The console
service's `write` is the obvious first measurement — today it is one round
trip per sixteen bytes, and two context switches per round trip.

**Slower:** revocation, which now walks mappings and shoots down TLBs across
CPUs. Also the first touch of a mapping, by a page-table walk that was not
there before.

**What will be measured**, before and after, on the same machine:

| Measurement | Today's baseline |
|---|---|
| Bytes per second through the console service's write path | 16 bytes per round trip |
| Round trips to `cat` a 4 KiB file | 256 |
| Time to revoke a capability with *n* mappings, n = 0..8 | n/a — the path does not exist |
| Frames free before and after a create/map/unmap/destroy cycle | must be identical |

A performance claim without a benchmark is a hypothesis, and the current
sixteen-byte number is the only honest baseline this project has.

---

## Testing plan

**On the host** — the majority, and deliberately:

- Rights arithmetic for `MAP`: for every pair of (capability rights, requested
  rights), the request is granted exactly when it is a subset. Exhaustive over
  64×64, as M5-01's derivation test already is.
- The mapping list: adding, removing, filling, and the ninth refusal.
- Offset and length checking against the object's length, including the
  arithmetic that overflows.
- A model of revocation: given a set of mappings, the walk visits each exactly
  once and leaves the list empty.

**In QEMU:**

- Two domains map one object; one writes, the other reads it back. That is the
  whole feature in one test.
- The revocation test: B maps, B reads successfully, A revokes, B's next read
  faults — and the fault is B's problem rather than the machine's.
- The frame-leak gate across create/map/unmap/destroy, and across destroying a
  domain whose object is mapped by another.
- A shootdown count: revocation of a mapping live on another CPU must show a
  shootdown acknowledged by that CPU.

**On real hardware:** nothing specific beyond what M1-17 already needs.

**Fuzz target:** none, and the *Security implications* section says why. This
is a case where "none" is the true answer rather than the convenient one.

---

## Unresolved questions

1. **Untyped memory: in or out?** seL4 makes all kernel memory come from
   `Untyped` capabilities that userspace retypes, which makes kernel memory
   accounting exact and the API considerably larger. This RFC proposes a
   simpler model — objects allocated from a domain's envelope — and deleting
   the unused `Untyped` kind. That is a fork in the road and the one question
   here that is genuinely architectural. **Decided by: the project owner,
   before implementation starts.**
2. **Must a `Memory` object be physically contiguous?** DMA wants it;
   general sharing does not. Proposal: an attribute set at creation, with
   contiguous allocation allowed to fail. Deferred until the IOMMU RFC.
3. **Notification capabilities** — the other half of RFC 0008's async answer.
   Same RFC, or its own? Proposal: its own, because a notification is useful
   without shared memory and the two have no shared invariants.
4. **`MAX_MAPPINGS = 8`** is a guess. It should be the number that makes the
   revocation walk's worst case acceptable, which is a measurement nobody has
   taken.
5. **May a mapping be resized or moved?** Proposal: no. Unmap and map again.

---

## Implementation plan

Each step is a PR that leaves the tree green.

1. **The object and its arena.** Create and destroy on a `Domain` capability;
   frames charged to the envelope; no mapping yet. Host tests for the arena
   and the accounting; a QEMU test for the frame-leak gate across
   create/destroy.
2. **`Backing::Shared` and `MAP`/`UNMAP` into the caller's own space.** W^X;
   `EXECUTE` refused. The teardown invariant — a destroyed address space does
   not free shared frames — with the leak gate pointed at it.
3. **The reverse map and revocation.** The mapping list, the bound, the walk,
   the shootdown. The QEMU test where B faults after A revokes.
4. **Transfer.** A `Memory` capability crossing a `grant`, so two domains can
   genuinely share. This is where the feature becomes usable and where the
   two-domain test lands.
5. **A channel in `abi`.** A ring buffer layout over a shared region, with the
   double-fetch rules written into the code that reads it. No kernel change.
6. **Move the bulk paths.** The console service's `write` and the filesystem
   service's `read` gain a shared-memory path, keeping the register path for
   short transfers. Measure both against the table above.
7. **Device-visible objects** — gated on the IOMMU, and therefore on a
   separate RFC. Until then, the attribute exists and only in-nucleus code may
   hold an object that carries it.

Steps 1–4 are the RFC. Steps 5–6 are what make it worth having. Step 7 is a
different argument with a different threat model, and putting it here would
make this RFC about the IOMMU.
